"""Bounded, deterministic remediation generation.

This module only creates in-memory artifacts.  It does not write files, invoke
dbt, or run generated SQL.  Applying and testing a returned bundle is a later,
explicit temporary-copy verification step.
"""

from __future__ import annotations

import difflib
import hashlib
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any

import sqlglot
import yaml
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from lineageguard.models import ChangeType, SchemaChange


class RemediationError(ValueError):
    """Base class for deterministic remediation rejection."""


class UnsupportedRemediationError(RemediationError):
    """Raised when no bounded remediation template covers a change."""


class AmbiguousRemediationError(RemediationError):
    """Raised when more than one change or target could be remediated."""


class UnsafePathError(RemediationError):
    """Raised when an artifact target is outside the exact path allowlist."""


@dataclass(frozen=True, slots=True)
class GeneratedArtifact:
    """One proposed file state, retained entirely in memory."""

    path: str
    content: str
    previous_content: str | None
    purpose: str

    @property
    def sha256(self) -> str:
        """Digest used by the later evidence ledger."""
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()

    @property
    def unified_diff(self) -> str:
        """Return a deterministic, reviewable unified diff."""
        before = "" if self.previous_content is None else self.previous_content
        return "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                self.content.splitlines(keepends=True),
                fromfile=f"a/{self.path}" if self.previous_content is not None else "/dev/null",
                tofile=f"b/{self.path}",
                lineterm="\n",
            )
        )


@dataclass(frozen=True, slots=True)
class RemediationBundle:
    """The complete proposed compatibility bridge for one proven rename."""

    change_id: str
    artifacts: tuple[GeneratedArtifact, ...]

    def __post_init__(self) -> None:
        paths = [artifact.path for artifact in self.artifacts]
        if len(paths) != len(set(paths)):
            raise AmbiguousRemediationError("A remediation bundle cannot target a path twice")

    @property
    def by_path(self) -> Mapping[str, GeneratedArtifact]:
        """Read-only path lookup for callers and report renderers."""
        return MappingProxyType({artifact.path: artifact for artifact in self.artifacts})

    @property
    def unified_diff(self) -> str:
        """Concatenate artifact diffs in stable path order."""
        return "".join(artifact.unified_diff for artifact in self.artifacts)


class RemediationGenerator:
    """Generate the allowlisted dbt rename bridge used by the demo.

    The allowlist is exact, not glob based.  A caller must name the model,
    schema, and new singular-test paths up front.
    """

    def __init__(
        self,
        allowlisted_paths: Iterable[str | PurePosixPath],
        *,
        dialect: str = "duckdb",
    ) -> None:
        normalized = frozenset(_safe_relative_path(path) for path in allowlisted_paths)
        if not normalized:
            raise UnsafePathError("At least one output path must be allowlisted")
        self._allowlisted_paths = normalized
        self._dialect = dialect

    @property
    def allowlisted_paths(self) -> frozenset[str]:
        """Exact immutable output allowlist."""
        return self._allowlisted_paths

    def generate(
        self,
        changes: SchemaChange | Sequence[SchemaChange],
        *,
        model_path: str | PurePosixPath,
        model_sql: str,
        schema_path: str | PurePosixPath,
        schema_yaml: str,
        test_path: str | PurePosixPath,
        model_name: str | None = None,
        existing_test_sql: str | None = None,
    ) -> RemediationBundle:
        """Return a three-file dbt remediation bundle without applying it."""

        selected = (changes,) if isinstance(changes, SchemaChange) else tuple(changes)
        if len(selected) != 1:
            raise AmbiguousRemediationError(
                f"Exactly one schema change is required, received {len(selected)}"
            )
        change = selected[0]
        if change.change_type != ChangeType.RENAME_COLUMN:
            raise UnsupportedRemediationError(
                f"No bounded remediation for {change.change_type.value}"
            )
        if not change.old_column or not change.new_column:
            raise UnsupportedRemediationError("Rename remediation requires old and new columns")
        if change.old_column == change.new_column:
            raise UnsupportedRemediationError("Rename columns must be different")

        old_column = _safe_identifier(change.old_column, "old column")
        new_column = _safe_identifier(change.new_column, "new column")
        resolved_model_name = model_name or change.relation.rsplit(".", 1)[-1]
        resolved_model_name = _safe_identifier(resolved_model_name, "dbt model")

        normalized_model_path = self._allowed(model_path)
        normalized_schema_path = self._allowed(schema_path)
        normalized_test_path = self._allowed(test_path)
        if len({normalized_model_path, normalized_schema_path, normalized_test_path}) != 3:
            raise AmbiguousRemediationError("Model, schema, and test paths must be distinct")
        if existing_test_sql is not None:
            raise UnsupportedRemediationError(
                "Refusing to overwrite an existing singular test artifact"
            )

        patched_model = _add_compatibility_projection(
            model_sql,
            old_column=old_column,
            new_column=new_column,
            dialect=self._dialect,
        )
        patched_schema = _add_deprecation_metadata(
            schema_yaml,
            model_name=resolved_model_name,
            old_column=old_column,
            new_column=new_column,
            change_id=change.id,
        )
        equality_test = _equality_test(
            model_name=resolved_model_name,
            old_column=old_column,
            new_column=new_column,
            change_id=change.id,
        )

        artifacts = (
            GeneratedArtifact(
                path=normalized_model_path,
                content=patched_model,
                previous_content=model_sql,
                purpose="compatibility alias",
            ),
            GeneratedArtifact(
                path=normalized_schema_path,
                content=patched_schema,
                previous_content=schema_yaml,
                purpose="deprecated column metadata",
            ),
            GeneratedArtifact(
                path=normalized_test_path,
                content=equality_test,
                previous_content=None,
                purpose="compatibility equality test",
            ),
        )
        return RemediationBundle(
            change_id=change.id,
            artifacts=tuple(sorted(artifacts, key=lambda artifact: artifact.path)),
        )

    def _allowed(self, path: str | PurePosixPath) -> str:
        normalized = _safe_relative_path(path)
        if normalized not in self._allowlisted_paths:
            raise UnsafePathError(f"Output path is not allowlisted: {normalized}")
        return normalized


def generate_rename_remediation(
    change: SchemaChange,
    *,
    allowlisted_paths: Iterable[str | PurePosixPath],
    model_path: str | PurePosixPath,
    model_sql: str,
    schema_path: str | PurePosixPath,
    schema_yaml: str,
    test_path: str | PurePosixPath,
    model_name: str | None = None,
    dialect: str = "duckdb",
) -> RemediationBundle:
    """Functional convenience wrapper around :class:`RemediationGenerator`."""
    return RemediationGenerator(allowlisted_paths, dialect=dialect).generate(
        change,
        model_path=model_path,
        model_sql=model_sql,
        schema_path=schema_path,
        schema_yaml=schema_yaml,
        test_path=test_path,
        model_name=model_name,
    )


def _add_compatibility_projection(
    model_sql: str,
    *,
    old_column: str,
    new_column: str,
    dialect: str,
) -> str:
    if not model_sql.strip():
        raise UnsupportedRemediationError("dbt model SQL must not be empty")
    prefix, query_source = _split_leading_config(model_sql)
    masked_sql, replacements = _mask_dbt_relation_macros(query_source)
    try:
        query = sqlglot.parse_one(masked_sql, read=dialect)
    except (ParseError, TokenError, ValueError) as exc:
        raise UnsupportedRemediationError(f"dbt model SQL is not safely parseable: {exc}") from exc
    if not isinstance(query, exp.Select):
        raise UnsupportedRemediationError("Only a single top-level SELECT model can be patched")

    matching_new: list[exp.Expression] = []
    matching_old: list[exp.Expression] = []
    for expression in query.expressions:
        output_name = _output_name(expression)
        if output_name == new_column.casefold():
            matching_new.append(expression)
        if output_name == old_column.casefold():
            matching_old.append(expression)
    if matching_old:
        raise UnsupportedRemediationError(
            f"Model already exposes compatibility column {old_column!r}"
        )
    if len(matching_new) != 1:
        raise AmbiguousRemediationError(
            f"Expected exactly one projection for {new_column!r}, found {len(matching_new)}"
        )

    target = matching_new[0]
    target_identifier = target.args.get("alias") if isinstance(target, exp.Alias) else target.this
    if not isinstance(target_identifier, exp.Identifier) or target_identifier.args.get("quoted"):
        raise UnsupportedRemediationError(
            "Quoted output identifiers are outside the bounded remediation grammar"
        )
    source_expression = target.this if isinstance(target, exp.Alias) else target
    if not _is_safe_compatibility_expression(source_expression):
        raise UnsupportedRemediationError(
            "Compatibility aliases are limited to direct column projections or direct column casts"
        )
    compatibility = exp.alias_(source_expression.copy(), old_column, quoted=False)
    target_index = next(
        index for index, expression in enumerate(query.expressions) if expression is target
    )
    projections = list(query.expressions)
    projections[target_index] = compatibility
    projections.append(target.copy())
    query.set("expressions", projections)
    rendered = query.sql(dialect=dialect, pretty=True)
    for placeholder, original in replacements.items():
        if placeholder not in rendered:
            raise UnsupportedRemediationError("Could not safely restore a dbt relation macro")
        rendered = rendered.replace(placeholder, original)
    leading = prefix.rstrip()
    result = f"{leading}\n\n{rendered}" if leading else rendered
    return result.rstrip() + "\n"


def _is_safe_compatibility_expression(expression: exp.Expression) -> bool:
    """Allow only a column or a type cast applied directly to one column."""
    if isinstance(expression, exp.Column):
        return not expression.is_star
    if isinstance(expression, exp.Cast):
        source = expression.this
        return isinstance(source, exp.Column) and not source.is_star
    return False


def _split_leading_config(model_sql: str) -> tuple[str, str]:
    """Separate leading ``{{ config(...) }}`` blocks without evaluating Jinja."""
    cursor = 0
    end_of_prefix = 0
    while True:
        while cursor < len(model_sql) and model_sql[cursor].isspace():
            cursor += 1
        if not model_sql.startswith("{{", cursor):
            break
        close = model_sql.find("}}", cursor + 2)
        if close < 0:
            raise UnsupportedRemediationError("Unclosed leading dbt config block")
        body = model_sql[cursor + 2 : close].strip()
        if not body.startswith("config(") or not body.endswith(")"):
            break
        cursor = close + 2
        end_of_prefix = cursor
    return model_sql[:end_of_prefix], model_sql[end_of_prefix:]


def _mask_dbt_relation_macros(sql: str) -> tuple[str, Mapping[str, str]]:
    """Mask only ref/source macros, then let sqlglot validate the full query AST."""
    if "{%" in sql or "{#" in sql:
        raise UnsupportedRemediationError("dbt statement/comment blocks are unsupported")
    output: list[str] = []
    replacements: dict[str, str] = {}
    cursor = 0
    placeholder_index = 0
    while cursor < len(sql):
        start = sql.find("{{", cursor)
        if start < 0:
            output.append(sql[cursor:])
            break
        output.append(sql[cursor:start])
        close = sql.find("}}", start + 2)
        if close < 0:
            raise UnsupportedRemediationError("Unclosed dbt expression")
        original = sql[start : close + 2]
        body = sql[start + 2 : close].strip()
        if not ((body.startswith("ref(") or body.startswith("source(")) and body.endswith(")")):
            raise UnsupportedRemediationError(
                "Only dbt ref/source relation macros are supported in model SQL"
            )
        placeholder = f"__lineageguard_jinja_{placeholder_index:03d}__"
        while placeholder in sql:
            placeholder_index += 1
            placeholder = f"__lineageguard_jinja_{placeholder_index:03d}__"
        placeholder_index += 1
        replacements[placeholder] = original
        output.append(placeholder)
        cursor = close + 2
    return "".join(output), MappingProxyType(replacements)


def _output_name(expression: exp.Expression) -> str | None:
    if isinstance(expression, exp.Alias):
        return expression.alias.casefold()
    if isinstance(expression, exp.Column) and not expression.is_star:
        return expression.name.casefold()
    return None


def _add_deprecation_metadata(
    schema_yaml: str,
    *,
    model_name: str,
    old_column: str,
    new_column: str,
    change_id: str,
) -> str:
    try:
        document = yaml.safe_load(schema_yaml)
    except yaml.YAMLError as exc:
        raise UnsupportedRemediationError(f"Invalid dbt schema YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise UnsupportedRemediationError("dbt schema YAML must be a mapping")
    raw_models = document.get("models")
    if not isinstance(raw_models, list):
        raise UnsupportedRemediationError("dbt schema YAML must contain a models list")
    matches = [
        model for model in raw_models if isinstance(model, dict) and model.get("name") == model_name
    ]
    if len(matches) != 1:
        raise AmbiguousRemediationError(
            f"Expected exactly one schema model named {model_name!r}, found {len(matches)}"
        )
    model = matches[0]
    columns = model.get("columns")
    if not isinstance(columns, list):
        raise UnsupportedRemediationError(
            f"Schema model {model_name!r} must declare a columns list"
        )
    old_matches = [column for column in columns if _yaml_column_name(column) == old_column]
    new_indexes = [
        index for index, column in enumerate(columns) if _yaml_column_name(column) == new_column
    ]
    if old_matches:
        raise UnsupportedRemediationError(
            f"Schema metadata already declares compatibility column {old_column!r}"
        )
    if len(new_indexes) != 1:
        raise AmbiguousRemediationError(
            f"Expected exactly one schema column {new_column!r}, found {len(new_indexes)}"
        )
    new_column_definition = columns[new_indexes[0]]
    if not isinstance(new_column_definition, Mapping):
        raise UnsupportedRemediationError("Replacement column metadata must be a mapping")
    deprecation: dict[str, Any] = {
        "name": old_column,
        "description": f"Deprecated compatibility alias. Use `{new_column}` instead.",
        "meta": {
            "lineageguard": {
                "deprecated": True,
                "replacement": new_column,
                "change_id": change_id,
            }
        },
    }
    replacement_data_type = new_column_definition.get("data_type")
    if isinstance(replacement_data_type, str) and replacement_data_type.strip():
        deprecation["data_type"] = replacement_data_type
    for preserved_key in ("constraints", "data_tests"):
        preserved_value = new_column_definition.get(preserved_key)
        if isinstance(preserved_value, list):
            deprecation[preserved_key] = deepcopy(preserved_value)
    replacement_index = new_indexes[0]
    columns[replacement_index] = deprecation
    columns.append(new_column_definition)
    return yaml.safe_dump(
        document,
        sort_keys=False,
        allow_unicode=False,
        default_flow_style=False,
        width=100,
    )


def _yaml_column_name(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    name = value.get("name")
    return name if isinstance(name, str) else None


def _equality_test(
    *,
    model_name: str,
    old_column: str,
    new_column: str,
    change_id: str,
) -> str:
    return (
        "-- Generated by LineageGuard; no code was executed during generation.\n"
        f"-- Change: {change_id}\n"
        "with compatibility_check as (\n"
        "    select\n"
        f"        {old_column},\n"
        f"        {new_column}\n"
        f"    from {{{{ ref('{model_name}') }}}}\n"
        ")\n"
        "select *\n"
        "from compatibility_check\n"
        f"where {old_column} is distinct from {new_column}\n"
    )


def _safe_relative_path(path: str | PurePosixPath) -> str:
    raw = str(path)
    if not raw or "\\" in raw:
        raise UnsafePathError(f"Output path is not a safe POSIX relative path: {raw!r}")
    parsed = PurePosixPath(raw)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise UnsafePathError(f"Output path is not a safe POSIX relative path: {raw!r}")
    normalized = parsed.as_posix()
    if normalized != raw:
        raise UnsafePathError(f"Output path is not normalized: {raw!r}")
    return normalized


def _safe_identifier(value: str, description: str) -> str:
    if not value or value[0].isdigit():
        raise UnsupportedRemediationError(f"Unsafe {description} identifier: {value!r}")
    if not all(
        character.isascii() and (character.isalnum() or character == "_") for character in value
    ):
        raise UnsupportedRemediationError(f"Unsafe {description} identifier: {value!r}")
    return value


__all__ = [
    "AmbiguousRemediationError",
    "GeneratedArtifact",
    "RemediationBundle",
    "RemediationError",
    "RemediationGenerator",
    "UnsafePathError",
    "UnsupportedRemediationError",
    "generate_rename_remediation",
]
