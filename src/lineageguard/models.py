"""Typed domain models shared by LineageGuard's deterministic core.

The models in this module deliberately distinguish an observed negative fact
(for example, an asset with no owner) from absent evidence.  ``None`` means the
fact was not established; an empty tuple means the source explicitly reported
that no values exist.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from itertools import pairwise
from pathlib import PurePosixPath
from typing import Annotated, Any, Self

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class DomainModel(BaseModel):
    """Strict, immutable base for values used in risk decisions."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class SchemaChangeType(StrEnum):
    """Normalized change types, including the policy's specific classes.

    Parsers may emit one of the five generic forms.  A parser that has already
    established compatibility can emit a policy-specific form instead.
    """

    ADD_COLUMN = "add_column"
    DROP_COLUMN = "drop_column"
    RENAME_COLUMN = "rename_column"
    TYPE_CHANGE = "type_change"
    NULLABILITY_CHANGE = "nullability_change"

    INCOMPATIBLE_TYPE = "incompatible_type"
    WIDENING_TYPE = "widening_type"
    NULLABLE_TO_REQUIRED = "nullable_to_required"
    ADD_REQUIRED_COLUMN = "add_required_column"
    ADD_NULLABLE_COLUMN = "add_nullable_column"

    @classmethod
    def _missing_(cls, value: object) -> Self | None:
        if not isinstance(value, str):
            return None
        aliases = {
            "add": cls.ADD_COLUMN,
            "drop": cls.DROP_COLUMN,
            "rename": cls.RENAME_COLUMN,
            "type": cls.TYPE_CHANGE,
            "nullability": cls.NULLABILITY_CHANGE,
        }
        return aliases.get(value.strip().lower())


# Short alias for call sites that do not need the longer schema-oriented name.
ChangeType = SchemaChangeType


class ConfidenceLevel(StrEnum):
    """Confidence in a parsed fact, not overall evidence coverage."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EvidenceStatus(StrEnum):
    """Completeness state for evidence used by the deterministic decision."""

    COMPLETE = "complete"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    TRUNCATED = "truncated"
    STALE = "stale"
    UNAVAILABLE = "unavailable"
    ERROR = "error"

    @property
    def is_complete(self) -> bool:
        """Return whether this status can support a PASS decision."""

        return self is EvidenceStatus.COMPLETE


class EvidenceKind(StrEnum):
    """Kinds of catalog and change evidence LineageGuard may record."""

    SCHEMA_CHANGE = "schema_change"
    CATALOG = "catalog"
    LINEAGE = "lineage"
    TRAVERSAL = "traversal"
    OWNERSHIP = "ownership"
    ASSERTION = "assertion"
    CRITICALITY = "criticality"
    ASSET_TYPE = "asset_type"
    SENSITIVITY = "sensitivity"
    USAGE = "usage"
    OTHER = "other"


class EvidenceRecord(DomainModel):
    """A source-provided evidence reference; never synthesized by the scorer."""

    id: NonEmptyStr
    kind: EvidenceKind
    status: EvidenceStatus
    source: NonEmptyStr | None = None
    detail: str | None = None
    observed_at: datetime | None = None
    critical: bool = False

    @field_validator("detail")
    @classmethod
    def normalize_detail(cls, value: str | None) -> str | None:
        """Treat whitespace-only details as absent."""

        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class EvidenceState(DomainModel):
    """Coverage of the five critical inputs required for a safe PASS.

    Defaults are intentionally fail-closed.  Callers must explicitly report a
    complete catalog read, lineage traversal, owner enrichment, and assertion
    enrichment; merely omitting those checks cannot produce PASS.
    """

    catalog: EvidenceStatus = EvidenceStatus.MISSING
    lineage: EvidenceStatus = EvidenceStatus.MISSING
    traversal: EvidenceStatus = EvidenceStatus.MISSING
    ownership: EvidenceStatus = EvidenceStatus.MISSING
    assertions: EvidenceStatus = EvidenceStatus.MISSING
    records: tuple[EvidenceRecord, ...] = ()

    @field_validator("records")
    @classmethod
    def sort_records(cls, records: tuple[EvidenceRecord, ...]) -> tuple[EvidenceRecord, ...]:
        """Canonicalize records and reject conflicting duplicate references."""

        ordered = sorted(records, key=lambda item: item.id)
        for previous, current in pairwise(ordered):
            if previous.id == current.id:
                raise ValueError(f"duplicate evidence id: {current.id}")
        return tuple(ordered)

    @classmethod
    def complete(cls, *, records: tuple[EvidenceRecord, ...] = ()) -> Self:
        """Build explicitly complete coverage for verified callers and tests."""

        return cls(
            catalog=EvidenceStatus.COMPLETE,
            lineage=EvidenceStatus.COMPLETE,
            traversal=EvidenceStatus.COMPLETE,
            ownership=EvidenceStatus.COMPLETE,
            assertions=EvidenceStatus.COMPLETE,
            records=records,
        )

    @property
    def incomplete_critical_evidence(self) -> tuple[tuple[str, EvidenceStatus], ...]:
        """Return non-complete critical checks in stable field order."""

        checks = (
            ("catalog", self.catalog),
            ("lineage", self.lineage),
            ("traversal", self.traversal),
            ("ownership", self.ownership),
            ("assertions", self.assertions),
        )
        return tuple((name, status) for name, status in checks if not status.is_complete)


class SchemaChange(DomainModel):
    """A normalized proposed schema change with a reproducible identifier."""

    id: str = ""
    change_type: SchemaChangeType
    relation: NonEmptyStr = Field(
        validation_alias=AliasChoices("relation", "dataset", "dataset_urn")
    )
    old_column: NonEmptyStr | None = None
    new_column: NonEmptyStr | None = None
    old_type: NonEmptyStr | None = None
    new_type: NonEmptyStr | None = None
    old_nullable: bool | None = None
    new_nullable: bool | None = None
    source_path: NonEmptyStr | None = None
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    evidence_refs: tuple[NonEmptyStr, ...] = ()
    evidence: tuple[EvidenceRecord, ...] = ()

    @field_validator("source_path")
    @classmethod
    def normalize_source_path(cls, value: str | None) -> str | None:
        """Normalize path separators without requiring the file to exist."""

        if value is None:
            return None
        return str(PurePosixPath(value.replace("\\", "/")))

    @field_validator("evidence_refs")
    @classmethod
    def sort_evidence_refs(cls, refs: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(refs)))

    @field_validator("evidence")
    @classmethod
    def sort_evidence(cls, records: tuple[EvidenceRecord, ...]) -> tuple[EvidenceRecord, ...]:
        ordered = sorted(records, key=lambda item: item.id)
        for previous, current in pairwise(ordered):
            if previous.id == current.id:
                raise ValueError(f"duplicate evidence id: {current.id}")
        return tuple(ordered)

    @model_validator(mode="after")
    def validate_shape_and_id(self) -> Self:
        """Validate type-specific fields and derive an ID from semantic content."""

        column_types = {
            SchemaChangeType.ADD_COLUMN,
            SchemaChangeType.ADD_REQUIRED_COLUMN,
            SchemaChangeType.ADD_NULLABLE_COLUMN,
        }
        if self.change_type in column_types and self.new_column is None:
            raise ValueError(f"{self.change_type.value} requires new_column")
        if self.change_type is SchemaChangeType.DROP_COLUMN and self.old_column is None:
            raise ValueError("drop_column requires old_column")
        if self.change_type is SchemaChangeType.RENAME_COLUMN:
            if self.old_column is None or self.new_column is None:
                raise ValueError("rename_column requires old_column and new_column")
            if self.old_column == self.new_column:
                raise ValueError("rename_column requires distinct column names")

        type_changes = {
            SchemaChangeType.TYPE_CHANGE,
            SchemaChangeType.INCOMPATIBLE_TYPE,
            SchemaChangeType.WIDENING_TYPE,
        }
        if self.change_type in type_changes:
            if self.old_type is None or self.new_type is None:
                raise ValueError(f"{self.change_type.value} requires old_type and new_type")
            if self.old_type.casefold() == self.new_type.casefold():
                raise ValueError(f"{self.change_type.value} requires distinct types")

        nullability_changes = {
            SchemaChangeType.NULLABILITY_CHANGE,
            SchemaChangeType.NULLABLE_TO_REQUIRED,
        }
        if self.change_type in nullability_changes:
            if self.old_nullable is None or self.new_nullable is None:
                raise ValueError(f"{self.change_type.value} requires old_nullable and new_nullable")
            if self.old_nullable is self.new_nullable:
                raise ValueError(f"{self.change_type.value} requires a changed nullability")
        if self.change_type is SchemaChangeType.NULLABLE_TO_REQUIRED and not (
            self.old_nullable and self.new_nullable is False
        ):
            raise ValueError("nullable_to_required requires true -> false nullability")

        normalized_id = self.id.strip()
        if not normalized_id:
            identity: dict[str, Any] = {
                "change_type": self.change_type.value,
                "relation": self.relation,
                "old_column": self.old_column,
                "new_column": self.new_column,
                "old_type": self.old_type,
                "new_type": self.new_type,
                "old_nullable": self.old_nullable,
                "new_nullable": self.new_nullable,
                "source_path": self.source_path,
            }
            encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
            normalized_id = f"change-{hashlib.sha256(encoded).hexdigest()[:16]}"
        object.__setattr__(self, "id", normalized_id)
        return self

    @property
    def severity_key(self) -> str:
        """Map a generic parser change to one exact risk-policy severity key.

        Unknown type compatibility and requiredness are treated conservatively;
        this never turns missing detail into a lower risk category.
        """

        direct = {
            SchemaChangeType.DROP_COLUMN: "drop_column",
            SchemaChangeType.RENAME_COLUMN: "rename_column",
            SchemaChangeType.INCOMPATIBLE_TYPE: "incompatible_type",
            SchemaChangeType.WIDENING_TYPE: "widening_type",
            SchemaChangeType.NULLABLE_TO_REQUIRED: "nullable_to_required",
            SchemaChangeType.ADD_REQUIRED_COLUMN: "add_required_column",
            SchemaChangeType.ADD_NULLABLE_COLUMN: "add_nullable_column",
        }
        if self.change_type in direct:
            return direct[self.change_type]
        if self.change_type is SchemaChangeType.TYPE_CHANGE:
            return "incompatible_type"
        if self.change_type is SchemaChangeType.ADD_COLUMN:
            return "add_nullable_column" if self.new_nullable is True else "add_required_column"
        if self.change_type is SchemaChangeType.NULLABILITY_CHANGE:
            if self.old_nullable and self.new_nullable is False:
                return "nullable_to_required"
            return "widening_type"
        raise AssertionError(f"unhandled schema change type: {self.change_type}")

    @property
    def all_evidence_refs(self) -> tuple[str, ...]:
        """Return only source references supplied with this change."""

        return tuple(sorted({*self.evidence_refs, *(record.id for record in self.evidence)}))


class AssetType(StrEnum):
    """Downstream DataHub asset categories relevant to risk scoring."""

    DATASET = "dataset"
    DASHBOARD = "dashboard"
    CHART = "chart"
    DATA_JOB = "data_job"
    DATA_FLOW = "data_flow"
    ASSERTION = "assertion"
    OTHER = "other"


class ImpactedAsset(DomainModel):
    """An observed downstream asset and its source-backed risk facts."""

    urn: NonEmptyStr
    asset_type: AssetType
    name: NonEmptyStr | None = None
    hop_count: int = Field(ge=1)
    owners: tuple[NonEmptyStr, ...] | None = None
    assertion_urns: tuple[NonEmptyStr, ...] | None = None
    critical_asset: bool | None = None
    sensitive_data: bool | None = None
    direct_column_lineage: bool | None = None
    recent_query_usage_score: int | None = Field(
        default=None,
        ge=0,
        validation_alias=AliasChoices("recent_query_usage_score", "recent_query_usage"),
    )
    evidence_refs: tuple[NonEmptyStr, ...] = ()
    evidence: tuple[EvidenceRecord, ...] = ()

    @field_validator("owners", "assertion_urns")
    @classmethod
    def sort_optional_values(cls, values: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if values is None:
            return None
        return tuple(sorted(set(values)))

    @field_validator("evidence_refs")
    @classmethod
    def sort_asset_evidence_refs(cls, refs: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(refs)))

    @field_validator("evidence")
    @classmethod
    def sort_asset_evidence(cls, records: tuple[EvidenceRecord, ...]) -> tuple[EvidenceRecord, ...]:
        ordered = sorted(records, key=lambda item: item.id)
        for previous, current in pairwise(ordered):
            if previous.id == current.id:
                raise ValueError(f"duplicate evidence id: {current.id}")
        return tuple(ordered)

    @property
    def all_evidence_refs(self) -> tuple[str, ...]:
        """Return only references supplied by the caller, in stable order."""

        return tuple(sorted({*self.evidence_refs, *(record.id for record in self.evidence)}))


class RiskDecision(StrEnum):
    """Final PR gate decision."""

    PASS = "PASS"  # noqa: S105 - decision label, not a credential
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


# Compatibility alias for callers that prefer the shorter term.
Decision = RiskDecision


class RiskCategory(StrEnum):
    """Policy contribution categories."""

    SEVERITY = "severity"
    SIGNAL = "signal"
    HOP_PENALTY = "hop_penalty"
    BREADTH = "breadth"
    CLAMP = "clamp"


class RiskContribution(DomainModel):
    """One auditable, evidence-linked component of a computed score."""

    category: RiskCategory
    key: NonEmptyStr
    points: int
    asset_urn: NonEmptyStr | None = None
    change_id: NonEmptyStr | None = None
    evidence_refs: tuple[NonEmptyStr, ...] = ()
    explanation: NonEmptyStr

    @field_validator("evidence_refs")
    @classmethod
    def sort_contribution_refs(cls, refs: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(refs)))


class AssetRisk(DomainModel):
    """Transparent score for one impacted asset before breadth is added."""

    asset_urn: NonEmptyStr
    hop_count: int = Field(ge=1)
    score: int = Field(ge=0, le=100)
    contributions: tuple[RiskContribution, ...]


class DecisionOverride(DomainModel):
    """Explicit minimum decision caused by insufficient critical evidence."""

    minimum_decision: RiskDecision = RiskDecision.REVIEW
    reason_codes: tuple[NonEmptyStr, ...]

    @field_validator("reason_codes")
    @classmethod
    def normalize_reason_codes(cls, reasons: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(reasons)))
        if not normalized:
            raise ValueError("decision override requires at least one reason")
        return normalized


class RiskAssessment(DomainModel):
    """Complete deterministic result, including numeric and confidence decisions."""

    policy_version: NonEmptyStr
    score: int = Field(ge=0, le=100)
    score_decision: RiskDecision
    decision: RiskDecision
    score_basis_asset_urn: NonEmptyStr | None = None
    asset_risks: tuple[AssetRisk, ...]
    contributions: tuple[RiskContribution, ...]
    evidence_state: EvidenceState
    decision_override: DecisionOverride | None = None
    change_ids: tuple[NonEmptyStr, ...]
    impacted_asset_urns: tuple[NonEmptyStr, ...]

    @field_validator("change_ids", "impacted_asset_urns")
    @classmethod
    def sort_identifiers(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(values)))


__all__ = [
    "AssetRisk",
    "AssetType",
    "ChangeType",
    "ConfidenceLevel",
    "Decision",
    "DecisionOverride",
    "DomainModel",
    "EvidenceKind",
    "EvidenceRecord",
    "EvidenceState",
    "EvidenceStatus",
    "ImpactedAsset",
    "RiskAssessment",
    "RiskCategory",
    "RiskContribution",
    "RiskDecision",
    "SchemaChange",
    "SchemaChangeType",
]
