"""Serializable evidence contract for one LineageGuard agent run."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum

from pydantic import model_validator

from lineageguard.models import (
    DomainModel,
    EvidenceState,
    ImpactedAsset,
    RiskAssessment,
    SchemaChange,
)


class RunStatus(StrEnum):
    """Whether every requested stage produced conclusive evidence."""

    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"


class GateDecision(StrEnum):
    """The PR-facing decision after any tested remediation."""

    PASS = "PASS"  # noqa: S105 - decision label, not a credential
    PASS_WITH_REMEDIATION = "PASS_WITH_REMEDIATION"  # noqa: S105
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class RemediationStatus(StrEnum):
    """Lifecycle of the bounded remediation attempt."""

    NOT_NEEDED = "NOT_NEEDED"
    UNSUPPORTED = "UNSUPPORTED"
    GENERATED = "GENERATED"
    TESTED = "TESTED"
    TEST_FAILED = "TEST_FAILED"
    VERIFICATION_ERROR = "VERIFICATION_ERROR"


class WritebackState(StrEnum):
    """Durability state of the DataHub change passport."""

    NOT_REQUESTED = "NOT_REQUESTED"
    VERIFIED = "VERIFIED"
    WRITEBACK_PENDING = "WRITEBACK_PENDING"


class AnalyzedInputState(StrEnum):
    """How the exact manifest bytes used by the analysis reached LineageGuard."""

    SUPPLIED_MANIFESTS = "SUPPLIED_MANIFESTS"
    GENERATED_IN_PROCESS = "GENERATED_IN_PROCESS"


class InputEvidence(DomainModel):
    """Content-addressed inputs, without machine-specific absolute paths.

    ``commit_sha`` identifies only a clean source tree. It does not claim that
    generated or caller-supplied manifests were committed; their state and
    exact bytes are recorded independently.
    """

    before_manifest: str
    before_manifest_sha256: str
    after_manifest: str
    after_manifest_sha256: str
    project: str
    commit_sha: str
    model_path: str = ""
    schema_path: str = ""
    test_path: str = ""
    selector: str = ""
    dialect: str | None = None
    writeback_requested: bool = False
    analyzed_input_state: AnalyzedInputState | None = None
    preflight_evidence_digest: str | None = None
    policy_sha256: str | None = None


class ContextEvidence(DomainModel):
    """Merged DataHub evidence used by the score."""

    source_urns: tuple[str, ...]
    impacted_assets: tuple[ImpactedAsset, ...]
    evidence_state: EvidenceState
    response_digests: tuple[str, ...]
    reason_codes: tuple[str, ...]


class ArtifactEvidence(DomainModel):
    """One generated remediation artifact."""

    path: str
    purpose: str
    sha256: str
    unified_diff: str


class CommandEvidence(DomainModel):
    """One allowlisted verification command and its result."""

    command: tuple[str, ...]
    exit_code: int
    duration_ms: int
    output_digest: str
    output_tail: str


class VerificationEvidence(DomainModel):
    """Reproducible result of the isolated dbt verification plan."""

    status: str
    commands: tuple[CommandEvidence, ...] = ()
    artifact_digests: tuple[tuple[str, str], ...] = ()
    evidence_digest: str | None = None
    patched_manifest_sha256: str | None = None
    patched_manifest_summary: str | None = None
    run_results_digest: str | None = None
    verified_node_ids: tuple[str, ...] = ()
    failure_reason: str | None = None


class RemediationEvidence(DomainModel):
    """Generated patch, test proof, and counterfactual delta."""

    status: RemediationStatus
    reason: str | None = None
    artifacts: tuple[ArtifactEvidence, ...] = ()
    unified_diff: str = ""
    verification: VerificationEvidence | None = None
    counterfactual_verified: bool = False
    interface_preserved: bool = False
    counterfactual_condition: str | None = None
    counterfactual_evidence_digest: str | None = None
    baseline_manifest_sha256: str | None = None
    baseline_manifest_summary: str | None = None
    preserved_expression_fingerprint: str | None = None
    preserved_contract_sha256: str | None = None
    preserved_query_context_sha256: str | None = None
    residual_changes: tuple[SchemaChange, ...] = ()
    residual_risk: RiskAssessment | None = None


class WritebackEvidence(DomainModel):
    """MCP mutation and readback proof, or an explicit pending state."""

    state: WritebackState
    document_urn: str | None = None
    mutation_digests: tuple[str, ...] = ()
    readback_digests: tuple[str, ...] = ()
    reason: str | None = None


class MCPTraceEvidence(DomainModel):
    """Secret-free evidence for one official MCP tool call."""

    tool: str
    argument_digest: str
    result_digest: str | None
    duration_ms: int
    success: bool
    attempt: int


class RunResult(DomainModel):
    """Stable JSON contract consumed by reports and the local review UI."""

    schema_version: str = "1.0"
    run_id: str
    created_at: datetime
    status: RunStatus
    final_decision: GateDecision
    inputs: InputEvidence
    changes: tuple[SchemaChange, ...]
    context: ContextEvidence
    initial_risk: RiskAssessment
    remediation: RemediationEvidence
    evidence_hash: str
    artifact_hash: str | None = None
    writeback: WritebackEvidence
    mcp_trace: tuple[MCPTraceEvidence, ...] = ()

    @model_validator(mode="after")
    def _validate_contract_version(self) -> RunResult:
        if self.schema_version == "1.0":
            if self.inputs.analyzed_input_state is not None:
                raise ValueError("schema 1.0 cannot claim analyzed-input provenance")
            return self
        if self.schema_version == "1.1":
            if self.inputs.analyzed_input_state is None:
                raise ValueError("schema 1.1 requires analyzed-input provenance")
            return self
        raise ValueError("unsupported run schema version")


def run_result_payload(
    result: RunResult, *, include_artifact_hash: bool = True
) -> dict[str, object]:
    """Serialize one run without adding unhashed fields to a legacy v1.0 artifact."""

    payload = result.model_dump(mode="json")
    if not include_artifact_hash:
        payload.pop("artifact_hash", None)
    if result.schema_version == "1.0":
        inputs = payload.get("inputs")
        if isinstance(inputs, dict):
            inputs.pop("analyzed_input_state", None)
    return payload


def calculate_artifact_hash(result: RunResult) -> str:
    """Calculate the canonical integrity seal for a typed run artifact."""

    payload = run_result_payload(result, include_artifact_hash=False)
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "AnalyzedInputState",
    "ArtifactEvidence",
    "CommandEvidence",
    "ContextEvidence",
    "GateDecision",
    "InputEvidence",
    "MCPTraceEvidence",
    "RemediationEvidence",
    "RemediationStatus",
    "RunResult",
    "RunStatus",
    "VerificationEvidence",
    "WritebackEvidence",
    "WritebackState",
    "calculate_artifact_hash",
    "run_result_payload",
]
