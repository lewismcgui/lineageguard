"""Deterministic schema change extraction for dbt manifests and ALTER TABLE SQL.

The parser deliberately supports a small, auditable surface.  It never guesses a
rename from names or positions alone: a dbt rename is inferred only when the
removed and added outputs have one unique, identical compiled-SQL expression.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from lineageguard.models import ChangeType, ConfidenceLevel, SchemaChange, SchemaChangeType

ManifestInput = Mapping[str, Any] | str | Path


class ChangeParseError(ValueError):
    """Raised when input cannot be parsed into trustworthy schema changes."""


class UnsupportedChangeError(ChangeParseError):
    """Raised when input is valid but outside the deliberately narrow grammar."""


@dataclass(frozen=True, slots=True)
class _Projection:
    fingerprint: str | None
    ordinal: int
    direct_cast_type: str | None


@dataclass(frozen=True, slots=True)
class _ColumnState:
    name: str
    data_type: str | None
    data_type_from_projection: bool
    nullable: bool | None
    projection: _Projection | None


@dataclass(frozen=True, slots=True)
class _ManifestNode:
    relation: str
    columns: Mapping[str, _ColumnState]


class ChangeParser:
    """Facade for the two supported, deterministic change sources."""

    def compare_dbt_manifests(
        self,
        before: ManifestInput,
        after: ManifestInput,
        *,
        dialect: str | None = None,
        source_path: str | None = None,
    ) -> tuple[SchemaChange, ...]:
        """Compare dbt manifests and return normalized column changes."""
        return compare_dbt_manifests(
            before,
            after,
            dialect=dialect,
            source_path=source_path,
        )

    def parse_alter_table(
        self,
        sql: str,
        *,
        dialect: str = "postgres",
        source_path: str = "<sql>",
    ) -> tuple[SchemaChange, ...]:
        """Parse the allowlisted ALTER TABLE subset."""
        return parse_alter_table(sql, dialect=dialect, source_path=source_path)


def compare_dbt_manifests(
    before: ManifestInput,
    after: ManifestInput,
    *,
    dialect: str | None = None,
    source_path: str | None = None,
) -> tuple[SchemaChange, ...]:
    """Extract a normalized column delta from two dbt ``manifest.json`` files.

    Nodes are matched by their physical ``relation_name`` rather than dbt's
    unique ID.  Newly introduced relations are ignored because they cannot
    break an existing relation.  Removed or renamed relations are rejected:
    representing a table removal as a series of column removals would be
    misleading and unsafe.
    """

    before_manifest, before_label = _load_manifest(before, "before manifest")
    after_manifest, after_label = _load_manifest(after, "after manifest")
    selected_dialect = _select_manifest_dialect(before_manifest, after_manifest, dialect)
    before_nodes = _manifest_nodes(before_manifest, selected_dialect, before_label)
    after_nodes = _manifest_nodes(after_manifest, selected_dialect, after_label)

    removed_relations = sorted(set(before_nodes).difference(after_nodes))
    if removed_relations:
        joined = ", ".join(removed_relations)
        raise UnsupportedChangeError(
            f"Relation removal or rename is unsupported; missing after manifest: {joined}"
        )

    provenance = source_path or after_label
    changes: list[SchemaChange] = []
    for relation in sorted(set(before_nodes).intersection(after_nodes)):
        changes.extend(
            _compare_relation(
                before_nodes[relation],
                after_nodes[relation],
                source_path=provenance,
            )
        )
    return tuple(sorted(changes, key=_change_sort_key))


# Friendly name for callers that treat every input as a parse operation.
parse_dbt_manifest_changes = compare_dbt_manifests


def parse_alter_table(
    sql: str,
    *,
    dialect: str = "postgres",
    source_path: str = "<sql>",
) -> tuple[SchemaChange, ...]:
    """Parse a narrow ALTER TABLE grammar with sqlglot's AST.

    Supported actions are ADD COLUMN (type plus optional NULL/NOT NULL), DROP
    COLUMN, RENAME COLUMN, ALTER COLUMN TYPE without USING/COLLATE, and SET or
    DROP NOT NULL.  Any other AST node or modifier is rejected rather than
    partially interpreted.
    """

    if not sql.strip():
        raise ChangeParseError("ALTER TABLE SQL must not be empty")
    try:
        statements = sqlglot.parse(sql, read=dialect)
    except (ParseError, TokenError, ValueError) as exc:
        raise ChangeParseError(f"Invalid {dialect} SQL: {exc}") from exc
    if not statements:
        raise ChangeParseError("ALTER TABLE SQL did not contain a statement")

    changes: list[SchemaChange] = []
    for statement in statements:
        if not isinstance(statement, exp.Alter) or statement.args.get("kind") != "TABLE":
            raise UnsupportedChangeError("Only ALTER TABLE statements are supported")
        table = statement.this
        if not isinstance(table, exp.Table):
            raise UnsupportedChangeError("ALTER TABLE target must be a concrete table")
        relation = _relation_from_table(table, dialect)
        actions = statement.args.get("actions")
        if not isinstance(actions, Sequence) or not actions:
            raise UnsupportedChangeError("ALTER TABLE must contain a supported column action")
        for action in actions:
            changes.extend(
                _changes_from_alter_action(
                    relation,
                    action,
                    dialect=dialect,
                    source_path=source_path,
                )
            )
    return tuple(sorted(changes, key=_change_sort_key))


def _changes_from_alter_action(
    relation: str,
    action: exp.Expression,
    *,
    dialect: str,
    source_path: str,
) -> tuple[SchemaChange, ...]:
    evidence_refs = (f"sqlglot:{type(action).__name__}",)

    if isinstance(action, exp.RenameColumn):
        old_column = _column_expression_name(action.this)
        new_column = _column_expression_name(action.args.get("to"))
        return (
            _schema_change(
                change_type=ChangeType.RENAME_COLUMN,
                relation=relation,
                old_column=old_column,
                new_column=new_column,
                source_path=source_path,
                evidence_refs=evidence_refs,
            ),
        )

    if isinstance(action, exp.ColumnDef):
        data_type = action.args.get("kind")
        if not isinstance(data_type, exp.DataType):
            raise UnsupportedChangeError("ADD COLUMN requires an explicit data type")
        nullable = True
        for constraint in action.args.get("constraints") or ():
            if not isinstance(constraint, exp.ColumnConstraint):
                raise UnsupportedChangeError("Unsupported ADD COLUMN constraint")
            kind = constraint.args.get("kind")
            if not isinstance(kind, exp.NotNullColumnConstraint):
                raise UnsupportedChangeError(
                    f"Unsupported ADD COLUMN constraint: {type(kind).__name__}"
                )
            nullable = bool(kind.args.get("allow_null", False))
        return (
            _schema_change(
                change_type=ChangeType.ADD_COLUMN,
                relation=relation,
                new_column=_identifier_name(action.this),
                new_type=_render_type(data_type),
                new_nullable=nullable,
                source_path=source_path,
                evidence_refs=evidence_refs,
            ),
        )

    if isinstance(action, exp.Drop):
        if str(action.args.get("kind", "")).upper() != "COLUMN":
            raise UnsupportedChangeError("Only DROP COLUMN is supported")
        if action.args.get("cascade") or action.args.get("purge"):
            raise UnsupportedChangeError("DROP COLUMN CASCADE/PURGE is unsupported")
        return (
            _schema_change(
                change_type=ChangeType.DROP_COLUMN,
                relation=relation,
                old_column=_column_expression_name(action.this),
                source_path=source_path,
                evidence_refs=evidence_refs,
            ),
        )

    if isinstance(action, exp.AlterColumn):
        if action.args.get("default") is not None:
            raise UnsupportedChangeError("ALTER COLUMN DEFAULT is unsupported")
        if action.args.get("using") or action.args.get("collate"):
            raise UnsupportedChangeError("ALTER COLUMN USING/COLLATE is unsupported")
        column = _identifier_name(action.this)
        results: list[SchemaChange] = []
        data_type = action.args.get("dtype")
        if data_type is not None:
            if not isinstance(data_type, exp.DataType):
                raise UnsupportedChangeError("ALTER COLUMN TYPE must contain a data type")
            results.append(
                _schema_change(
                    change_type=ChangeType.TYPE_CHANGE,
                    relation=relation,
                    old_column=column,
                    new_column=column,
                    old_type="UNKNOWN",
                    new_type=_render_type(data_type),
                    source_path=source_path,
                    evidence_refs=evidence_refs,
                )
            )
        if "allow_null" in action.args:
            results.append(
                _schema_change(
                    change_type=ChangeType.NULLABILITY_CHANGE,
                    relation=relation,
                    old_column=column,
                    new_column=column,
                    old_nullable=not bool(action.args["allow_null"]),
                    new_nullable=bool(action.args["allow_null"]),
                    source_path=source_path,
                    evidence_refs=evidence_refs,
                )
            )
        if not results:
            raise UnsupportedChangeError("Unsupported ALTER COLUMN action")
        return tuple(results)

    raise UnsupportedChangeError(f"Unsupported ALTER TABLE action: {type(action).__name__}")


def _compare_relation(
    before: _ManifestNode,
    after: _ManifestNode,
    *,
    source_path: str,
) -> list[SchemaChange]:
    before_names = set(before.columns)
    after_names = set(after.columns)
    removed = before_names.difference(after_names)
    added = after_names.difference(before_names)
    renames = _infer_renames(before.columns, after.columns, removed, added)
    renamed_old = set(renames)
    renamed_new = set(renames.values())
    changes: list[SchemaChange] = []

    for old_name, new_name in sorted(renames.items()):
        old = before.columns[old_name]
        new = after.columns[new_name]
        fingerprint = old.projection.fingerprint if old.projection else None
        rename_evidence = ["dbt:column-set:removed-and-added"]
        if fingerprint:
            digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:16]
            rename_evidence.append(f"dbt:compiled-expression:{digest}")
        changes.append(
            _schema_change(
                change_type=ChangeType.RENAME_COLUMN,
                relation=before.relation,
                old_column=old.name,
                new_column=new.name,
                old_type=old.data_type,
                new_type=new.data_type,
                old_nullable=old.nullable,
                new_nullable=new.nullable,
                source_path=source_path,
                evidence_refs=tuple(rename_evidence),
            )
        )
        changes.extend(_attribute_changes(before.relation, old, new, source_path))

    for name in sorted(removed.difference(renamed_old)):
        old = before.columns[name]
        changes.append(
            _schema_change(
                change_type=ChangeType.DROP_COLUMN,
                relation=before.relation,
                old_column=old.name,
                old_type=old.data_type,
                old_nullable=old.nullable,
                source_path=source_path,
                evidence_refs=("dbt:column-removed",),
            )
        )

    for name in sorted(added.difference(renamed_new)):
        new = after.columns[name]
        changes.append(
            _schema_change(
                change_type=ChangeType.ADD_COLUMN,
                relation=after.relation,
                new_column=new.name,
                new_type=new.data_type,
                new_nullable=new.nullable,
                source_path=source_path,
                evidence_refs=("dbt:column-added",),
            )
        )

    for name in sorted(before_names.intersection(after_names)):
        changes.extend(
            _attribute_changes(
                before.relation,
                before.columns[name],
                after.columns[name],
                source_path,
            )
        )
    return changes


def _attribute_changes(
    relation: str,
    old: _ColumnState,
    new: _ColumnState,
    source_path: str,
) -> list[SchemaChange]:
    changes: list[SchemaChange] = []
    old_projection = old.projection
    new_projection = new.projection
    projection_unverified_or_changed = (old_projection is None) != (new_projection is None) or (
        old_projection is not None
        and new_projection is not None
        and (
            old_projection.fingerprint is None
            or new_projection.fingerprint is None
            or old_projection.fingerprint != new_projection.fingerprint
        )
    )
    if projection_unverified_or_changed and (old.data_type is None or new.data_type is None):
        raise UnsupportedChangeError(
            "Retained compiled projection changed without trustworthy output type evidence: "
            f"{relation}.{old.name}"
        )
    if old.data_type is not None and new.data_type is not None and old.data_type != new.data_type:
        evidence_ref = (
            "dbt:compiled-direct-cast-type-changed"
            if old.data_type_from_projection or new.data_type_from_projection
            else "dbt:data-type-changed"
        )
        changes.append(
            _schema_change(
                change_type=ChangeType.TYPE_CHANGE,
                relation=relation,
                old_column=old.name,
                new_column=new.name,
                old_type=old.data_type,
                new_type=new.data_type,
                source_path=source_path,
                evidence_refs=(evidence_ref,),
            )
        )
    if old.nullable is not None and new.nullable is not None and old.nullable != new.nullable:
        changes.append(
            _schema_change(
                change_type=ChangeType.NULLABILITY_CHANGE,
                relation=relation,
                old_column=old.name,
                new_column=new.name,
                old_nullable=old.nullable,
                new_nullable=new.nullable,
                source_path=source_path,
                evidence_refs=("dbt:nullability-changed",),
            )
        )
    return changes


def _infer_renames(
    before: Mapping[str, _ColumnState],
    after: Mapping[str, _ColumnState],
    removed: set[str],
    added: set[str],
) -> dict[str, str]:
    """Return only mutually unique expression matches.

    If two removed or added outputs share an expression, all edges in that
    ambiguous component remain ordinary drops/adds.  No edit distance, ordinal,
    or type-only heuristic is used.
    """

    old_candidates: dict[str, list[str]] = defaultdict(list)
    new_candidates: dict[str, list[str]] = defaultdict(list)
    for old_name in sorted(removed):
        old_projection = before[old_name].projection
        if old_projection is None or old_projection.fingerprint is None:
            continue
        for new_name in sorted(added):
            new_projection = after[new_name].projection
            if new_projection is None or new_projection.fingerprint is None:
                continue
            if old_projection.fingerprint == new_projection.fingerprint:
                old_candidates[old_name].append(new_name)
                new_candidates[new_name].append(old_name)

    inferred: dict[str, str] = {}
    for old_name in sorted(old_candidates):
        candidates = old_candidates[old_name]
        if len(candidates) != 1:
            continue
        new_name = candidates[0]
        if len(new_candidates[new_name]) == 1:
            inferred[old_name] = new_name
    return inferred


def _load_manifest(source: ManifestInput, description: str) -> tuple[Mapping[str, Any], str]:
    if isinstance(source, Mapping):
        manifest = source
        label = f"<{description}>"
    else:
        path = Path(source)
        label = str(path)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ChangeParseError(f"Cannot read {description} at {path}: {exc}") from exc
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ChangeParseError(f"Invalid JSON in {description} at {path}: {exc}") from exc
        if not isinstance(loaded, Mapping):
            raise ChangeParseError(f"{description} must be a JSON object")
        manifest = loaded
    if not isinstance(manifest.get("nodes"), Mapping):
        raise ChangeParseError(f"{description} must contain a nodes object")
    return manifest, label


def _select_manifest_dialect(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    explicit: str | None,
) -> str:
    adapters: set[str] = set()
    for manifest in (before, after):
        metadata = manifest.get("metadata")
        if isinstance(metadata, Mapping):
            adapter = metadata.get("adapter_type")
            if isinstance(adapter, str) and adapter:
                normalized = adapter.casefold()
                adapters.add({"postgresql": "postgres"}.get(normalized, normalized))
    if len(adapters) > 1:
        raise ChangeParseError(f"Manifest adapter types differ: {', '.join(sorted(adapters))}")
    if explicit:
        normalized_explicit = explicit.casefold()
        normalized_explicit = {"postgresql": "postgres"}.get(
            normalized_explicit, normalized_explicit
        )
        if adapters and normalized_explicit not in adapters:
            raise ChangeParseError(
                "Explicit dialect does not match manifest adapter type: "
                f"{normalized_explicit} vs {next(iter(adapters))}"
            )
        return normalized_explicit
    return next(iter(adapters), "postgres")


def _manifest_nodes(
    manifest: Mapping[str, Any], dialect: str, source_label: str
) -> dict[str, _ManifestNode]:
    raw_nodes = manifest["nodes"]
    assert isinstance(raw_nodes, Mapping)  # validated by _load_manifest
    result: dict[str, _ManifestNode] = {}
    for unique_id in sorted(raw_nodes, key=str):
        raw = raw_nodes[unique_id]
        if not isinstance(raw, Mapping):
            raise ChangeParseError(f"Node {unique_id!s} in {source_label} must be an object")
        resource_type = raw.get("resource_type")
        if resource_type not in {"model", "seed", "snapshot"}:
            continue
        relation = _node_relation(raw, dialect, str(unique_id))
        if relation in result:
            raise ChangeParseError(f"Duplicate dbt relation {relation!r} in {source_label}")
        result[relation] = _ManifestNode(
            relation=relation,
            columns=_node_columns(raw, dialect, str(unique_id)),
        )
    return result


def _node_relation(node: Mapping[str, Any], dialect: str, unique_id: str) -> str:
    relation_name = node.get("relation_name")
    if not isinstance(relation_name, str) or not relation_name.strip():
        parts: list[str] = []
        for key in ("database", "schema"):
            value = node.get(key)
            if isinstance(value, str) and value:
                parts.append(value)
        terminal = node.get("alias") or node.get("identifier") or node.get("name")
        if isinstance(terminal, str) and terminal:
            parts.append(terminal)
        relation_name = ".".join(parts)
    if not relation_name:
        raise ChangeParseError(f"dbt node {unique_id} has no usable relation name")
    try:
        table = sqlglot.parse_one(relation_name, read=dialect, into=exp.Table)
    except (ParseError, TokenError, ValueError) as exc:
        raise ChangeParseError(
            f"dbt node {unique_id} has invalid relation_name {relation_name!r}: {exc}"
        ) from exc
    return _relation_from_table(table, dialect)


def _node_columns(node: Mapping[str, Any], dialect: str, unique_id: str) -> dict[str, _ColumnState]:
    projections = _compiled_projections(node, dialect)
    raw_columns = node.get("columns")
    if raw_columns is None:
        raw_columns = {}
    if not isinstance(raw_columns, Mapping):
        raise ChangeParseError(f"dbt node {unique_id} columns must be an object")
    columns: dict[str, _ColumnState] = {}
    for raw_key in sorted(raw_columns, key=str):
        metadata = raw_columns[raw_key]
        if not isinstance(metadata, Mapping):
            raise ChangeParseError(
                f"dbt node {unique_id} column {raw_key!s} metadata must be an object"
            )
        declared_name = metadata.get("name", raw_key)
        if not isinstance(declared_name, str) or not declared_name:
            raise ChangeParseError(f"dbt node {unique_id} has an invalid column name")
        quote = metadata.get("quote")
        if quote is not None and not isinstance(quote, bool):
            raise ChangeParseError(f"dbt node {unique_id} has an invalid column quote flag")
        name = _canonical_manifest_column(declared_name, quoted=quote is True)
        if name in columns:
            raise ChangeParseError(f"dbt node {unique_id} declares duplicate column {name!r}")
        raw_type = metadata.get("data_type")
        declared_type = _canonical_type(raw_type, dialect) if isinstance(raw_type, str) else None
        projection = projections.get(name)
        projected_type = projection.direct_cast_type if projection is not None else None
        if (
            declared_type is not None
            and projected_type is not None
            and declared_type != projected_type
        ):
            raise ChangeParseError(
                f"dbt node {unique_id} column {name!r} has conflicting declared "
                "and compiled output types"
            )
        columns[name] = _ColumnState(
            name=name,
            data_type=declared_type if declared_type is not None else projected_type,
            data_type_from_projection=declared_type is None and projected_type is not None,
            nullable=_manifest_nullable(metadata),
            projection=projection,
        )
    for name, projection in projections.items():
        columns.setdefault(
            name,
            _ColumnState(
                name=name,
                data_type=projection.direct_cast_type,
                data_type_from_projection=projection.direct_cast_type is not None,
                nullable=None,
                projection=projection,
            ),
        )
    return columns


def _compiled_projections(node: Mapping[str, Any], dialect: str) -> dict[str, _Projection]:
    compiled = node.get("compiled_code") or node.get("compiled_sql")
    if not isinstance(compiled, str) or not compiled.strip():
        return {}
    try:
        query = sqlglot.parse_one(compiled, read=dialect)
    except (ParseError, TokenError, ValueError):
        return {}
    if not isinstance(query, exp.Select):
        return {}

    candidates: dict[str, list[_Projection]] = defaultdict(list)
    for ordinal, expression in enumerate(query.expressions):
        if isinstance(expression, exp.Alias):
            output = expression.args.get("alias")
            source = expression.this
        elif isinstance(expression, exp.Column) and not expression.is_star:
            output = expression.this
            source = expression
        else:
            continue
        if not isinstance(output, exp.Identifier) or not output.name:
            continue
        name = _identifier_name(output)
        try:
            fingerprint = source.sql(dialect=dialect, normalize=True, pretty=False)
        except (ValueError, TypeError):
            fingerprint = None
        direct_cast = source
        while isinstance(direct_cast, exp.Paren):
            direct_cast = direct_cast.this
        direct_cast_type = None
        if isinstance(direct_cast, exp.Cast):
            cast_type = direct_cast.args.get("to")
            if isinstance(cast_type, exp.DataType):
                direct_cast_type = _render_type(cast_type)
        candidates[name].append(
            _Projection(
                fingerprint=fingerprint,
                ordinal=ordinal,
                direct_cast_type=direct_cast_type,
            )
        )

    # Duplicate output aliases are not safe rename evidence.
    return {name: values[0] for name, values in candidates.items() if len(values) == 1}


def _manifest_nullable(metadata: Mapping[str, Any]) -> bool | None:
    nullable = metadata.get("nullable")
    if isinstance(nullable, bool):
        return nullable
    not_null = metadata.get("not_null")
    if isinstance(not_null, bool):
        return not not_null
    constraints = metadata.get("constraints")
    if not isinstance(constraints, Sequence) or isinstance(constraints, (str, bytes)):
        return None
    for constraint in constraints:
        kind: Any = constraint.get("type") if isinstance(constraint, Mapping) else constraint
        if isinstance(kind, str) and kind.casefold().replace(" ", "_") == "not_null":
            return False
    return None


def _canonical_type(raw_type: str, dialect: str) -> str:
    stripped = raw_type.strip()
    if not stripped:
        raise ChangeParseError("Column data_type must not be empty")
    try:
        parsed = sqlglot.parse_one(stripped, read=dialect, into=exp.DataType)
    except (ParseError, TokenError, ValueError):
        return " ".join(stripped.split()).upper()
    return _render_type(parsed)


def _render_type(data_type: exp.DataType) -> str:
    """Render a canonical type without dialect rewrites that discard detail."""
    return data_type.sql(normalize=True, pretty=False).upper()


def _relation_from_table(table: exp.Table, dialect: str) -> str:
    parts: list[str] = []
    for part in table.parts:
        if not isinstance(part, exp.Identifier):
            raise ChangeParseError("Relation contains an unsupported identifier")
        try:
            parts.append(part.sql(dialect=dialect, normalize=True, pretty=False))
        except (TypeError, ValueError) as exc:
            raise ChangeParseError("Relation contains an unsupported identifier") from exc
    if not parts:
        raise ChangeParseError("Relation must not be empty")
    return ".".join(parts)


def _identifier_name(value: Any) -> str:
    if not isinstance(value, exp.Identifier):
        raise UnsupportedChangeError("Column name must be a plain identifier")
    name = value.name
    if value.args.get("quoted"):
        return '"' + name.replace('"', '""') + '"'
    return name.casefold()


def _column_expression_name(value: Any) -> str:
    if not isinstance(value, exp.Column) or value.table:
        raise UnsupportedChangeError("Column name must be an unqualified identifier")
    identifier = value.this
    return _identifier_name(identifier)


def _canonical_manifest_column(name: str, *, quoted: bool = False) -> str:
    stripped = name.strip()
    if not stripped:
        raise ChangeParseError("Column name must not be empty")
    return '"' + stripped.replace('"', '""') + '"' if quoted else stripped.casefold()


def _schema_change(
    *,
    change_type: SchemaChangeType,
    relation: str,
    source_path: str,
    evidence_refs: tuple[str, ...],
    old_column: str | None = None,
    new_column: str | None = None,
    old_type: str | None = None,
    new_type: str | None = None,
    old_nullable: bool | None = None,
    new_nullable: bool | None = None,
) -> SchemaChange:
    """Construct one high-confidence parser fact with fully typed arguments."""
    return SchemaChange(
        change_type=change_type,
        relation=relation,
        old_column=old_column,
        new_column=new_column,
        old_type=old_type,
        new_type=new_type,
        old_nullable=old_nullable,
        new_nullable=new_nullable,
        source_path=source_path,
        confidence=ConfidenceLevel.HIGH,
        evidence_refs=evidence_refs,
    )


def _change_sort_key(change: SchemaChange) -> tuple[str, int, str, str]:
    order = {
        ChangeType.RENAME_COLUMN: 0,
        ChangeType.DROP_COLUMN: 1,
        ChangeType.ADD_COLUMN: 2,
        ChangeType.TYPE_CHANGE: 3,
        ChangeType.NULLABILITY_CHANGE: 4,
    }
    return (
        change.relation,
        order.get(change.change_type, 99),
        change.old_column or "",
        change.new_column or "",
    )


__all__ = [
    "ChangeParseError",
    "ChangeParser",
    "ManifestInput",
    "UnsupportedChangeError",
    "compare_dbt_manifests",
    "parse_alter_table",
    "parse_dbt_manifest_changes",
]
