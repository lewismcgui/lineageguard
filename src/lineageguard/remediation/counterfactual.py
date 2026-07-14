"""Fail-closed counterfactual comparison for a tested remediation."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from lineageguard.changes import ChangeParseError, compare_dbt_manifests
from lineageguard.models import SchemaChange, SchemaChangeType
from lineageguard.remediation.verifier import (
    ManifestSnapshot,
    VerificationResult,
    VerificationStatus,
)


class CounterfactualError(RuntimeError):
    """Verified evidence cannot prove the requested compatibility outcome."""


class CounterfactualCondition(StrEnum):
    """Tell the caller whether a residual schema delta still needs scoring."""

    NO_RESIDUAL_CHANGES = "NO_RESIDUAL_CHANGES"
    RESIDUAL_CHANGES = "RESIDUAL_CHANGES"


@dataclass(frozen=True, slots=True)
class CounterfactualResult:
    """Deterministic proof and residual input for the next scoring step."""

    original_change_id: str
    original_interface_preserved: bool
    residual_changes: tuple[SchemaChange, ...]
    rescore_condition: CounterfactualCondition
    before_manifest_sha256: str
    patched_manifest_sha256: str
    preserved_expression_fingerprint: str
    preserved_contract_sha256: str
    preserved_query_context_sha256: str
    evidence_digest: str

    @property
    def requires_rescore(self) -> bool:
        """Return whether callers should score the residual change tuple."""

        return self.rescore_condition is CounterfactualCondition.RESIDUAL_CHANGES


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _load_snapshot(snapshot: ManifestSnapshot | None, description: str) -> Mapping[str, Any]:
    if snapshot is None:
        raise CounterfactualError(f"{description} manifest evidence is missing")
    try:
        loaded = json.loads(snapshot.summary_json)
    except (json.JSONDecodeError, TypeError) as exc:
        raise CounterfactualError(f"{description} manifest evidence is invalid") from exc
    if (
        not isinstance(loaded, Mapping)
        or loaded.get("summary_version") != 3
        or not isinstance(loaded.get("nodes"), Mapping)
    ):
        raise CounterfactualError(f"{description} manifest evidence is invalid")

    canonical = _canonical_json(loaded)
    actual_sha256 = hashlib.sha256(canonical.encode()).hexdigest()
    if canonical != snapshot.summary_json or not hmac.compare_digest(
        actual_sha256, snapshot.sha256
    ):
        raise CounterfactualError(f"{description} manifest evidence drifted")
    return loaded


def _same_identifier(left: str | None, right: str | None) -> bool:
    return left is not None and right is not None and left.casefold() == right.casefold()


def _same_type(left: str | None, right: str | None) -> bool:
    return (
        left is not None
        and right is not None
        and "".join(left.split()).casefold() == "".join(right.split()).casefold()
    )


def _relation_key(value: str, dialect: str) -> tuple[str, ...]:
    try:
        table = exp.to_table(value, dialect=dialect)
    except (ParseError, TokenError, TypeError, ValueError) as exc:
        raise CounterfactualError("counterfactual relation evidence is invalid") from exc
    parts = tuple(part.name.casefold() for part in table.parts if part.name)
    if not parts:
        raise CounterfactualError("counterfactual relation evidence is invalid")
    return parts


def _relation_identity(node: Mapping[str, Any], dialect: str) -> tuple[tuple[str, bool], ...]:
    value = _node_relation(node)
    if value is None:
        raise CounterfactualError("counterfactual relation evidence is invalid")
    try:
        table = exp.to_table(value, dialect=dialect)
    except (ParseError, TokenError, TypeError, ValueError) as exc:
        raise CounterfactualError("counterfactual relation evidence is invalid") from exc
    identity: list[tuple[str, bool]] = []
    for part in table.parts:
        if not isinstance(part, exp.Identifier) or not part.name:
            raise CounterfactualError("counterfactual relation evidence is invalid")
        quoted = part.args.get("quoted") is True
        identity.append((part.name if quoted else part.name.casefold(), quoted))
    if not identity:
        raise CounterfactualError("counterfactual relation evidence is invalid")
    return tuple(identity)


def _node_relation(node: Mapping[str, Any]) -> str | None:
    relation_name = node.get("relation_name")
    if isinstance(relation_name, str) and relation_name.strip():
        return relation_name
    identifier = node.get("alias") or node.get("identifier") or node.get("name")
    if not isinstance(identifier, str) or not identifier:
        return None
    parts = [
        value
        for value in (node.get("database"), node.get("schema"), identifier)
        if isinstance(value, str) and value
    ]
    return ".".join(parts)


def _relation_node(manifest: Mapping[str, Any], relation: str, dialect: str) -> Mapping[str, Any]:
    nodes = manifest.get("nodes")
    if not isinstance(nodes, Mapping):
        raise CounterfactualError("counterfactual manifest evidence is invalid")
    relation_key = _relation_key(relation, dialect)
    matches: list[Mapping[str, Any]] = []
    for raw_node in nodes.values():
        if not isinstance(raw_node, Mapping):
            continue
        node_relation = _node_relation(raw_node)
        if node_relation is not None and _relation_key(node_relation, dialect) == relation_key:
            matches.append(raw_node)
    if len(matches) != 1:
        raise CounterfactualError("counterfactual relation evidence is missing or ambiguous")
    return matches[0]


def _identifier_key(identifier: exp.Identifier) -> str:
    quoted = identifier.args.get("quoted") is True
    name = identifier.name if quoted else identifier.name.casefold()
    return f"{'q' if quoted else 'u'}:{name}"


def _key_matches_column(key: str, column: str) -> bool:
    prefix, separator, name = key.partition(":")
    if not separator:
        return False
    return name == column if prefix == "q" else prefix == "u" and name == column.casefold()


def _projection_sequence(node: Mapping[str, Any], dialect: str) -> tuple[tuple[str, str], ...]:
    compiled = node.get("compiled_code")
    if not isinstance(compiled, str):
        raise CounterfactualError("counterfactual projection evidence is invalid")
    try:
        query = sqlglot.parse_one(compiled, read=dialect)
    except (ParseError, TokenError, TypeError, ValueError) as exc:
        raise CounterfactualError("counterfactual projection evidence is invalid") from exc
    if not isinstance(query, exp.Select):
        raise CounterfactualError("counterfactual projection evidence is invalid")
    projections: list[tuple[str, str]] = []
    seen: set[str] = set()
    for projection in query.expressions:
        if not isinstance(projection, exp.Alias) or not projection.alias:
            raise CounterfactualError("counterfactual projection evidence is invalid")
        alias = projection.args.get("alias")
        if not isinstance(alias, exp.Identifier):
            raise CounterfactualError("counterfactual projection evidence is invalid")
        token = projection.this
        if (
            not isinstance(token, exp.Literal)
            or not token.is_string
            or not isinstance(token.this, str)
            or not token.this.startswith("expression:")
        ):
            raise CounterfactualError("counterfactual projection evidence is invalid")
        key = _identifier_key(alias)
        if key in seen:
            raise CounterfactualError("counterfactual projection evidence is ambiguous")
        seen.add(key)
        projections.append((key, token.this))
    if not projections:
        raise CounterfactualError("counterfactual projection evidence is invalid")
    return tuple(projections)


def _projection_map(node: Mapping[str, Any], dialect: str) -> dict[str, str]:
    return dict(_projection_sequence(node, dialect))


def _column_contract_map(node: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    columns = node.get("columns")
    if not isinstance(columns, Mapping):
        raise CounterfactualError("counterfactual contract evidence is invalid")
    contracts: dict[str, Mapping[str, Any]] = {}
    for name, contract in columns.items():
        if not isinstance(name, str) or not isinstance(contract, Mapping):
            raise CounterfactualError("counterfactual contract evidence is invalid")
        quoted = contract.get("quote") is True
        key = f"{'q' if quoted else 'u'}:{name if quoted else name.casefold()}"
        if key in contracts:
            raise CounterfactualError("counterfactual contract evidence is ambiguous")
        contracts[key] = contract
    return contracts


def _query_context_fingerprint(node: Mapping[str, Any]) -> str:
    value = node.get("query_context_sha256")
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise CounterfactualError("counterfactual query context evidence is invalid")
    return value


def _model_config_fingerprint(node: Mapping[str, Any]) -> str:
    value = node.get("config_sha256")
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise CounterfactualError("counterfactual model configuration evidence is invalid")
    return value


def _model_constraints_fingerprint(node: Mapping[str, Any]) -> str:
    value = node.get("model_constraints_sha256")
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise CounterfactualError("counterfactual model constraint evidence is invalid")
    return value


def _model_test_fingerprints(node: Mapping[str, Any]) -> frozenset[str]:
    if node.get("model_test_evidence_complete") is not True:
        raise CounterfactualError("compiled model test evidence is incomplete")
    values = node.get("model_test_sha256")
    if not isinstance(values, list) or any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in values
    ):
        raise CounterfactualError("counterfactual model test evidence is invalid")
    if values != sorted(set(values)):
        raise CounterfactualError("counterfactual model test evidence is ambiguous")
    return frozenset(values)


def _projection_fingerprint(
    manifest: Mapping[str, Any], relation: str, column: str, dialect: str
) -> str:
    matches = [
        token
        for key, token in _projection_map(
            _relation_node(manifest, relation, dialect), dialect
        ).items()
        if _key_matches_column(key, column)
    ]
    if len(matches) != 1:
        raise CounterfactualError(
            f"counterfactual projection evidence for {column!r} is missing or ambiguous"
        )
    return matches[0]


def _column_contract(
    manifest: Mapping[str, Any], relation: str, column: str, dialect: str
) -> Mapping[str, Any]:
    matches = [
        contract
        for key, contract in _column_contract_map(
            _relation_node(manifest, relation, dialect)
        ).items()
        if _key_matches_column(key, column)
    ]
    if len(matches) != 1:
        raise CounterfactualError(
            f"counterfactual contract evidence for {column!r} is missing or ambiguous"
        )
    contract = matches[0]
    if contract.get("data_test_evidence_complete") is False:
        raise CounterfactualError(f"compiled column test evidence for {column!r} is incomplete")
    return contract


def _without_column(values: Mapping[str, Any], column: str, *, description: str) -> dict[str, Any]:
    matches = [key for key in values if _key_matches_column(key, column)]
    if len(matches) != 1:
        raise CounterfactualError(f"{description} evidence for {column!r} is missing or ambiguous")
    result = dict(values)
    result.pop(matches[0])
    return result


def _manifest_adapter(manifest: Mapping[str, Any], description: str) -> str:
    metadata = manifest.get("metadata")
    adapter = metadata.get("adapter_type") if isinstance(metadata, Mapping) else None
    if not isinstance(adapter, str) or not adapter:
        raise CounterfactualError(f"{description} adapter evidence is missing")
    normalized = adapter.casefold()
    return {"postgresql": "postgres"}.get(normalized, normalized)


def _preserved_interface_changes(
    residual_changes: tuple[SchemaChange, ...], original_change: SchemaChange
) -> tuple[SchemaChange, ...]:
    return tuple(
        change
        for change in residual_changes
        if change.relation == original_change.relation
        and (
            _same_identifier(change.old_column, original_change.old_column)
            or _same_identifier(change.new_column, original_change.old_column)
        )
    )


def _intended_additions(
    residual_changes: tuple[SchemaChange, ...], original_change: SchemaChange
) -> tuple[SchemaChange, ...]:
    return tuple(
        change
        for change in residual_changes
        if change.change_type is SchemaChangeType.ADD_COLUMN
        and change.relation == original_change.relation
        and _same_identifier(change.new_column, original_change.new_column)
    )


def _validate_intended_addition(addition: SchemaChange, original_change: SchemaChange) -> None:
    if original_change.new_type is not None and (
        addition.new_type is None or not _same_type(addition.new_type, original_change.new_type)
    ):
        raise CounterfactualError("patched manifest changed the intended replacement type")
    if (
        original_change.new_nullable is not None
        and addition.new_nullable is not original_change.new_nullable
    ):
        raise CounterfactualError("patched manifest changed the intended replacement nullability")


def verify_remediation_counterfactual(
    before_manifest: ManifestSnapshot,
    verification: VerificationResult,
    original_change: SchemaChange,
    *,
    proposed_manifest: ManifestSnapshot | None = None,
    dialect: str | None = None,
) -> CounterfactualResult:
    """Prove a tested rename bridge preserves the old interface.

    The existing dbt manifest comparator is the sole source of residual schema
    facts. A successful result proves that the baseline column remains
    unchanged and the intended replacement column is still present as an
    additive change. The tested manifest must also preserve the proposed
    manifest's complete replacement contract and projection; this binds the
    proof to the caller-supplied PR snapshot rather than merely trusting the
    project directory used by the verifier. Anything missing, drifted,
    ambiguous, or unsupported raises :class:`CounterfactualError` rather than
    producing a safe condition.
    """

    if verification.status is not VerificationStatus.TESTED:
        raise CounterfactualError("successful remediation verification is required")
    if original_change.change_type is not SchemaChangeType.RENAME_COLUMN:
        raise CounterfactualError("counterfactual verification supports rename remediation only")
    if original_change.old_column is None or original_change.new_column is None:
        raise CounterfactualError("rename remediation is missing its column interface")

    before = _load_snapshot(before_manifest, "before")
    if proposed_manifest is None:
        raise CounterfactualError("proposed manifest evidence is missing")
    proposed = _load_snapshot(proposed_manifest, "proposed")
    patched_manifest = verification.patched_manifest
    if patched_manifest is None:
        raise CounterfactualError("patched manifest evidence is missing")
    patched = _load_snapshot(patched_manifest, "patched")
    before_adapter = _manifest_adapter(before, "before")
    proposed_adapter = _manifest_adapter(proposed, "proposed")
    patched_adapter = _manifest_adapter(patched, "patched")
    if before_adapter != proposed_adapter or before_adapter != patched_adapter:
        raise CounterfactualError("counterfactual manifest adapter types differ")
    if dialect is not None:
        requested_adapter = {"postgresql": "postgres"}.get(dialect.casefold(), dialect.casefold())
        if requested_adapter != before_adapter:
            raise CounterfactualError("requested dialect does not match manifest adapter evidence")
    comparison_dialect = before_adapter

    before_node = _relation_node(before, original_change.relation, comparison_dialect)
    proposed_node = _relation_node(proposed, original_change.relation, comparison_dialect)
    patched_node = _relation_node(patched, original_change.relation, comparison_dialect)
    relation_identity = _relation_identity(before_node, comparison_dialect)
    if relation_identity != _relation_identity(patched_node, comparison_dialect):
        raise CounterfactualError("patched manifest changed the physical relation identity")
    baseline_query_context = _query_context_fingerprint(before_node)
    proposed_query_context = _query_context_fingerprint(proposed_node)
    patched_query_context = _query_context_fingerprint(patched_node)
    if not hmac.compare_digest(baseline_query_context, patched_query_context):
        raise CounterfactualError("patched manifest changed the preserved query context")
    baseline_model_config = _model_config_fingerprint(before_node)
    proposed_model_config = _model_config_fingerprint(proposed_node)
    patched_model_config = _model_config_fingerprint(patched_node)
    if not hmac.compare_digest(baseline_model_config, patched_model_config):
        raise CounterfactualError("patched manifest changed the model configuration")
    baseline_model_constraints = _model_constraints_fingerprint(before_node)
    proposed_model_constraints = _model_constraints_fingerprint(proposed_node)
    patched_model_constraints = _model_constraints_fingerprint(patched_node)
    if not hmac.compare_digest(baseline_model_constraints, patched_model_constraints):
        raise CounterfactualError("patched manifest changed model-level constraints")
    baseline_model_tests = _model_test_fingerprints(before_node)
    proposed_model_tests = _model_test_fingerprints(proposed_node)
    patched_model_tests = _model_test_fingerprints(patched_node)
    if not baseline_model_tests.issubset(patched_model_tests):
        raise CounterfactualError("patched manifest removed or changed a model-level test")

    baseline_contract = _column_contract(
        before,
        original_change.relation,
        original_change.old_column,
        comparison_dialect,
    )
    patched_old_contract = _column_contract(
        patched,
        original_change.relation,
        original_change.old_column,
        comparison_dialect,
    )
    if not hmac.compare_digest(
        _canonical_json(baseline_contract), _canonical_json(patched_old_contract)
    ):
        raise CounterfactualError("patched manifest changed the preserved column contract")
    baseline_contracts = _column_contract_map(before_node)
    proposed_contracts = _column_contract_map(proposed_node)
    patched_contracts = _column_contract_map(patched_node)
    replacement_contract_keys = [
        key for key in patched_contracts if _key_matches_column(key, original_change.new_column)
    ]
    if len(replacement_contract_keys) != 1:
        raise CounterfactualError("patched manifest replacement contract is missing")
    patched_without_replacement = dict(patched_contracts)
    patched_without_replacement.pop(replacement_contract_keys[0])
    if not hmac.compare_digest(
        _canonical_json(baseline_contracts), _canonical_json(patched_without_replacement)
    ):
        raise CounterfactualError("patched manifest changed a non-target column contract")

    baseline_expression = _projection_fingerprint(
        before,
        original_change.relation,
        original_change.old_column,
        comparison_dialect,
    )
    patched_old_expression = _projection_fingerprint(
        patched,
        original_change.relation,
        original_change.old_column,
        comparison_dialect,
    )
    patched_new_expression = _projection_fingerprint(
        patched,
        original_change.relation,
        original_change.new_column,
        comparison_dialect,
    )
    proposed_new_expression = _projection_fingerprint(
        proposed,
        original_change.relation,
        original_change.new_column,
        comparison_dialect,
    )
    if not hmac.compare_digest(baseline_expression, patched_old_expression):
        raise CounterfactualError("patched manifest changed the preserved column expression")
    if not hmac.compare_digest(patched_old_expression, patched_new_expression):
        raise CounterfactualError(
            "patched manifest replacement expression does not match the bridge"
        )
    baseline_projection_sequence = _projection_sequence(before_node, comparison_dialect)
    patched_projection_sequence = _projection_sequence(patched_node, comparison_dialect)
    replacement_projection_indexes = [
        index
        for index, (key, _token) in enumerate(patched_projection_sequence)
        if _key_matches_column(key, original_change.new_column)
    ]
    if len(replacement_projection_indexes) != 1:
        raise CounterfactualError("patched manifest replacement projection is missing")
    replacement_index = replacement_projection_indexes[0]
    if (
        replacement_index != len(patched_projection_sequence) - 1
        or patched_projection_sequence[:-1] != baseline_projection_sequence
    ):
        raise CounterfactualError(
            "patched manifest changed non-target projection order or identity"
        )
    try:
        residual_changes = compare_dbt_manifests(
            before,
            patched,
            dialect=comparison_dialect,
            source_path="<verified-counterfactual>",
        )
    except ChangeParseError as exc:
        raise CounterfactualError(f"counterfactual manifest comparison failed: {exc}") from exc

    if _preserved_interface_changes(residual_changes, original_change):
        raise CounterfactualError("patched manifest does not preserve the original interface")
    intended_additions = _intended_additions(residual_changes, original_change)
    if len(intended_additions) != 1:
        raise CounterfactualError(
            "patched manifest does not expose exactly one intended replacement column"
        )
    _validate_intended_addition(intended_additions[0], original_change)

    # Bind the tested project back to the supplied PR snapshot only after the
    # original-interface proof above has produced its most specific failure.
    if relation_identity != _relation_identity(proposed_node, comparison_dialect):
        raise CounterfactualError("proposed manifest changed the physical relation identity")
    if not hmac.compare_digest(proposed_query_context, patched_query_context):
        raise CounterfactualError("patched manifest does not preserve the proposed query context")
    if not hmac.compare_digest(proposed_model_config, patched_model_config):
        raise CounterfactualError(
            "patched manifest does not preserve the proposed model configuration"
        )
    if not hmac.compare_digest(proposed_model_constraints, patched_model_constraints):
        raise CounterfactualError(
            "patched manifest does not preserve the proposed model-level constraints"
        )
    if not proposed_model_tests.issubset(patched_model_tests):
        raise CounterfactualError("patched manifest removed a proposed model-level test")

    patched_without_compatibility = _without_column(
        patched_contracts,
        original_change.old_column,
        description="patched compatibility contract",
    )
    if not hmac.compare_digest(
        _canonical_json(proposed_contracts), _canonical_json(patched_without_compatibility)
    ):
        raise CounterfactualError(
            "patched manifest does not preserve the proposed column contracts"
        )
    if not hmac.compare_digest(proposed_new_expression, patched_new_expression):
        raise CounterfactualError(
            "patched manifest does not preserve the proposed replacement expression"
        )
    proposed_projection_sequence = _projection_sequence(proposed_node, comparison_dialect)
    baseline_old_index = next(
        index
        for index, (key, _token) in enumerate(baseline_projection_sequence)
        if _key_matches_column(key, original_change.old_column)
    )
    proposed_new_projection = next(
        projection
        for projection in proposed_projection_sequence
        if _key_matches_column(projection[0], original_change.new_column)
    )
    expected_proposed_sequence = list(baseline_projection_sequence)
    expected_proposed_sequence[baseline_old_index] = proposed_new_projection
    if proposed_projection_sequence != tuple(expected_proposed_sequence):
        raise CounterfactualError(
            "proposed manifest changed non-target projection order or identity"
        )

    # A valid rename bridge necessarily leaves the intended new column as an
    # additive residual relative to the baseline manifest.
    condition = CounterfactualCondition.RESIDUAL_CHANGES
    preserved_contract_payload = {
        "column": baseline_contract,
        "model_config_sha256": baseline_model_config,
        "model_constraints_sha256": baseline_model_constraints,
        "model_test_sha256": sorted(baseline_model_tests),
    }
    preserved_contract_sha256 = hashlib.sha256(
        _canonical_json(preserved_contract_payload).encode()
    ).hexdigest()
    evidence_payload = {
        "before_manifest_sha256": before_manifest.sha256,
        "condition": condition.value,
        "original_change_id": original_change.id,
        "original_interface_preserved": True,
        "patched_manifest_sha256": patched_manifest.sha256,
        "proposed_manifest_sha256": proposed_manifest.sha256,
        "preserved_contract_sha256": preserved_contract_sha256,
        "preserved_expression_fingerprint": baseline_expression,
        "preserved_query_context_sha256": baseline_query_context,
        "residual_changes": [
            change.model_dump(mode="json", exclude={"evidence"}) for change in residual_changes
        ],
        "verification_evidence_digest": verification.evidence_digest,
    }
    return CounterfactualResult(
        original_change_id=original_change.id,
        original_interface_preserved=True,
        residual_changes=residual_changes,
        rescore_condition=condition,
        before_manifest_sha256=before_manifest.sha256,
        patched_manifest_sha256=patched_manifest.sha256,
        preserved_expression_fingerprint=baseline_expression,
        preserved_contract_sha256=preserved_contract_sha256,
        preserved_query_context_sha256=baseline_query_context,
        evidence_digest=hashlib.sha256(_canonical_json(evidence_payload).encode()).hexdigest(),
    )


__all__ = [
    "CounterfactualCondition",
    "CounterfactualError",
    "CounterfactualResult",
    "verify_remediation_counterfactual",
]
