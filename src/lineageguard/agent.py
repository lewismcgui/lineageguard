"""Application-layer orchestration for the closed-loop LineageGuard agent."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from lineageguard.changes import ChangeParseError, compare_dbt_manifests
from lineageguard.datahub.context import ContextCollection
from lineageguard.datahub.mcp_client import MCPClientError, MCPTraceEvent
from lineageguard.datahub.writeback import (
    ChangePassport,
    WritebackResult,
)
from lineageguard.models import (
    AssetType,
    EvidenceKind,
    EvidenceRecord,
    EvidenceState,
    EvidenceStatus,
    ImpactedAsset,
    RiskAssessment,
    RiskDecision,
    SchemaChange,
    SchemaChangeType,
)
from lineageguard.remediation import (
    CounterfactualError,
    ManifestSnapshot,
    RemediationError,
    RemediationGenerator,
    RemediationVerifier,
    VerificationError,
    VerificationResult,
    VerificationStatus,
    snapshot_dbt_manifest,
    verify_remediation_counterfactual,
)
from lineageguard.reporting import render_passport_markdown
from lineageguard.risk import RiskEngine
from lineageguard.run_models import (
    AnalyzedInputState,
    ArtifactEvidence,
    CommandEvidence,
    ContextEvidence,
    GateDecision,
    InputEvidence,
    MCPTraceEvidence,
    RemediationEvidence,
    RemediationStatus,
    RunResult,
    RunStatus,
    VerificationEvidence,
    WritebackEvidence,
    WritebackState,
    calculate_artifact_hash,
)


class AgentInputError(ValueError):
    """The requested analysis cannot be performed without guessing."""


class ContextCollector(Protocol):
    async def collect(self, change: SchemaChange) -> ContextCollection: ...


class WritebackClient(Protocol):
    async def persist(self, passport: ChangePassport) -> WritebackResult: ...


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    """Exact files and bounded remediation targets for one PR analysis."""

    before_manifest: Path
    after_manifest: Path
    project_dir: Path
    model_path: str
    schema_path: str
    test_path: str
    model_name: str
    selector: str
    source_commit_sha: str = "WORKTREE"
    analyzed_input_state: AnalyzedInputState = AnalyzedInputState.SUPPLIED_MANIFESTS
    dialect: str | None = None
    preflight_evidence_digest: str | None = None


@dataclass(frozen=True, slots=True)
class _CapturedManifest:
    data: Mapping[str, object]
    sha256: str
    snapshot: ManifestSnapshot


_STATUS_RANK = {
    EvidenceStatus.COMPLETE: 0,
    EvidenceStatus.MISSING: 1,
    EvidenceStatus.TRUNCATED: 2,
    EvidenceStatus.AMBIGUOUS: 3,
    EvidenceStatus.STALE: 4,
    EvidenceStatus.UNAVAILABLE: 5,
    EvidenceStatus.ERROR: 6,
}

_ASSET_RISK_RANK = {
    AssetType.OTHER: 0,
    AssetType.DATASET: 1,
    AssetType.DATA_FLOW: 2,
    AssetType.DATA_JOB: 3,
    AssetType.CHART: 4,
    AssetType.DASHBOARD: 5,
    AssetType.ASSERTION: 6,
}

_ASSET_FACT_CONFLICTS = (
    ("asset_type", EvidenceKind.ASSET_TYPE, "catalog"),
    ("hop_count", EvidenceKind.TRAVERSAL, "traversal"),
    ("owners", EvidenceKind.OWNERSHIP, "ownership"),
    ("assertion_urns", EvidenceKind.ASSERTION, "assertions"),
    ("critical_asset", EvidenceKind.CRITICALITY, "catalog"),
    ("sensitive_data", EvidenceKind.SENSITIVITY, "catalog"),
    ("direct_column_lineage", EvidenceKind.LINEAGE, "lineage"),
    ("recent_query_usage_score", EvidenceKind.USAGE, "catalog"),
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise AgentInputError(f"Cannot read required input: {path.name}") from exc
    return digest.hexdigest()


def _capture_manifest(path: Path) -> _CapturedManifest:
    try:
        raw = path.read_bytes()
        loaded = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AgentInputError(f"Cannot capture dbt manifest: {path.name}") from exc
    if not isinstance(loaded, Mapping) or not isinstance(loaded.get("nodes"), Mapping):
        raise AgentInputError(f"Invalid dbt manifest shape: {path.name}")
    snapshot = snapshot_dbt_manifest(loaded)
    return _CapturedManifest(
        data=loaded,
        sha256=hashlib.sha256(raw).hexdigest(),
        snapshot=snapshot,
    )


def _portable_label(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _project_file(root: Path, relative_path: str, *, must_exist: bool = True) -> Path:
    candidate = root / relative_path
    if candidate.is_symlink():
        raise AgentInputError(f"Refusing symlinked project target: {relative_path}")
    try:
        resolved = candidate.resolve(strict=must_exist)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        message = f"Project target is missing or escapes the project: {relative_path}"
        raise AgentInputError(message) from exc
    if must_exist and not resolved.is_file():
        raise AgentInputError(f"Project target is not a file: {relative_path}")
    return resolved


def _worst_status(values: Sequence[EvidenceStatus]) -> EvidenceStatus:
    return max(values, key=_STATUS_RANK.__getitem__)


def _merge_optional_values(
    left: tuple[str, ...] | None, right: tuple[str, ...] | None
) -> tuple[str, ...] | None:
    if left is None or right is None:
        return None
    return tuple(sorted({*left, *right}))


def _merge_signal(left: bool | None, right: bool | None) -> bool | None:
    if left is True or right is True:
        return True
    if left is None or right is None:
        return None
    return False


def _merge_assets(left: ImpactedAsset, right: ImpactedAsset) -> ImpactedAsset:
    asset_type = max((left.asset_type, right.asset_type), key=_ASSET_RISK_RANK.__getitem__)
    names = sorted(value for value in (left.name, right.name) if value is not None)
    records = {record.id: record for record in (*left.evidence, *right.evidence)}
    usage_values = [
        value
        for value in (left.recent_query_usage_score, right.recent_query_usage_score)
        if value is not None
    ]
    return ImpactedAsset(
        urn=left.urn,
        asset_type=asset_type,
        name=names[0] if names else None,
        hop_count=min(left.hop_count, right.hop_count),
        owners=_merge_optional_values(left.owners, right.owners),
        assertion_urns=_merge_optional_values(left.assertion_urns, right.assertion_urns),
        critical_asset=_merge_signal(left.critical_asset, right.critical_asset),
        sensitive_data=_merge_signal(left.sensitive_data, right.sensitive_data),
        direct_column_lineage=_merge_signal(
            left.direct_column_lineage, right.direct_column_lineage
        ),
        recent_query_usage_score=max(usage_values) if usage_values else None,
        evidence_refs=tuple(sorted({*left.evidence_refs, *right.evidence_refs})),
        evidence=tuple(records[key] for key in sorted(records)),
    )


def merge_context_collections(collections: Sequence[ContextCollection]) -> ContextEvidence:
    """Merge per-change catalog reads conservatively and deterministically."""

    if not collections:
        raise AgentInputError("At least one DataHub context collection is required")

    assets: dict[str, ImpactedAsset] = {}
    records: dict[str, EvidenceRecord] = {}
    reasons: set[str] = set()
    conflict_ids: set[str] = set()
    ambiguous_state_fields: set[str] = set()
    for collection in collections:
        reasons.update(collection.reason_codes)
        for asset in collection.impacted_assets:
            existing = assets.get(asset.urn)
            if existing is None:
                assets[asset.urn] = asset
            else:
                if existing != asset:
                    reasons.add(
                        "context.asset_merged."
                        + hashlib.sha256(asset.urn.encode()).hexdigest()[:12]
                    )
                asset_digest = hashlib.sha256(asset.urn.encode()).hexdigest()[:12]
                for field, kind, state_field in _ASSET_FACT_CONFLICTS:
                    if getattr(existing, field) == getattr(asset, field):
                        continue
                    ambiguous_state_fields.add(state_field)
                    reason = f"context.asset_fact_conflict.{field}.{asset_digest}"
                    reasons.add(reason)
                    record = EvidenceRecord(
                        id=reason,
                        kind=kind,
                        status=EvidenceStatus.AMBIGUOUS,
                        source="LineageGuard context merge",
                        detail=(
                            "Conflicting values were returned for one impacted asset "
                            f"field: {field}."
                        ),
                        critical=True,
                    )
                    records[record.id] = record
                assets[asset.urn] = _merge_assets(existing, asset)
        for record in collection.evidence_state.records:
            existing_record = records.get(record.id)
            if existing_record is not None and existing_record != record:
                conflict_ids.add(record.id)
                reasons.add("context.evidence_record_conflict")
                continue
            records[record.id] = record

    for record_id in sorted(conflict_ids):
        digest = hashlib.sha256(record_id.encode()).hexdigest()[:16]
        conflict = EvidenceRecord(
            id=f"merge-conflict:{digest}",
            kind=EvidenceKind.OTHER,
            status=EvidenceStatus.ERROR,
            source="LineageGuard context merge",
            detail="Conflicting evidence records shared an identifier.",
            critical=True,
        )
        records[conflict.id] = conflict

    states = [collection.evidence_state for collection in collections]

    def merged_status(field: str) -> EvidenceStatus:
        values = [getattr(state, field) for state in states]
        if field in ambiguous_state_fields:
            values.append(EvidenceStatus.AMBIGUOUS)
        return _worst_status(values)

    return ContextEvidence(
        source_urns=tuple(
            sorted(
                {
                    collection.source_urn
                    for collection in collections
                    if collection.source_urn is not None
                }
            )
        ),
        impacted_assets=tuple(assets[urn] for urn in sorted(assets)),
        evidence_state=EvidenceState(
            catalog=merged_status("catalog"),
            lineage=merged_status("lineage"),
            traversal=merged_status("traversal"),
            ownership=merged_status("ownership"),
            assertions=merged_status("assertions"),
            records=tuple(records[key] for key in sorted(records)),
        ),
        response_digests=tuple(
            sorted({digest for collection in collections for digest in collection.response_digests})
        ),
        reason_codes=tuple(sorted(reasons)),
    )


def _verification_evidence(result: VerificationResult) -> VerificationEvidence:
    return VerificationEvidence(
        status=result.status.value,
        commands=tuple(
            CommandEvidence(
                command=command.command,
                exit_code=command.exit_code,
                duration_ms=command.duration_ms,
                output_digest=command.output_digest,
                output_tail=command.output[-4_000:],
            )
            for command in result.commands
        ),
        artifact_digests=result.artifact_digests,
        evidence_digest=result.evidence_digest,
        patched_manifest_sha256=(
            result.patched_manifest.sha256 if result.patched_manifest is not None else None
        ),
        patched_manifest_summary=(
            result.patched_manifest.summary_json if result.patched_manifest is not None else None
        ),
        run_results_digest=result.run_results_digest,
        verified_node_ids=result.verified_node_ids,
        failure_reason=result.failure_reason,
    )


def _gate_decision(initial: RiskAssessment, remediation: RemediationEvidence) -> GateDecision:
    if (
        initial.decision_override is None
        and remediation.status is RemediationStatus.TESTED
        and remediation.counterfactual_verified
        and remediation.interface_preserved
    ):
        residual = remediation.residual_risk
        no_residual = remediation.counterfactual_condition == "NO_RESIDUAL_CHANGES"
        if (residual is not None and residual.decision is RiskDecision.PASS) or (
            residual is None and no_residual
        ):
            return GateDecision.PASS_WITH_REMEDIATION
    return GateDecision(initial.decision.value)


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


class LineageGuardAgent:
    """Run schema analysis, DataHub context, tested repair, and durable writeback."""

    def __init__(
        self,
        *,
        collector: ContextCollector,
        risk_engine: RiskEngine,
        verifier: RemediationVerifier,
        writer: WritebackClient | None = None,
        trace_provider: Callable[[], Sequence[MCPTraceEvent]] | None = None,
    ) -> None:
        self.collector = collector
        self.risk_engine = risk_engine
        self.verifier = verifier
        self.writer = writer
        self.trace_provider = trace_provider

    async def analyze(self, request: AnalysisRequest, *, writeback: bool = False) -> RunResult:
        try:
            project = request.project_dir.resolve(strict=True)
            before = request.before_manifest.resolve(strict=True)
            after = request.after_manifest.resolve(strict=True)
        except OSError as exc:
            raise AgentInputError("A required project or manifest path is missing") from exc
        if not project.is_dir():
            raise AgentInputError("project_dir must be a dbt project directory")
        try:
            captured_before = _capture_manifest(before)
            captured_after = _capture_manifest(after)
        except VerificationError as exc:
            raise AgentInputError(str(exc)) from exc
        try:
            changes = compare_dbt_manifests(
                captured_before.data,
                captured_after.data,
                dialect=request.dialect,
                source_path=_portable_label(after, project),
            )
        except ChangeParseError as exc:
            raise AgentInputError(str(exc)) from exc
        if not changes:
            raise AgentInputError("The manifests contain no supported schema changes")

        contexts: list[ContextCollection] = []
        for change in changes:
            contexts.append(await self.collector.collect(change))
        context = merge_context_collections(contexts)
        initial = self.risk_engine.assess(changes, context.impacted_assets, context.evidence_state)

        remediation = await self._remediate(
            request,
            project,
            changes,
            context,
            captured_before.snapshot,
            captured_after.snapshot,
        )
        if (
            _sha256_file(before) != captured_before.sha256
            or _sha256_file(after) != captured_after.sha256
        ):
            raise AgentInputError("A dbt manifest drifted during analysis")
        final_decision = _gate_decision(initial, remediation)
        inputs = InputEvidence(
            before_manifest=_portable_label(before, project),
            before_manifest_sha256=captured_before.sha256,
            after_manifest=_portable_label(after, project),
            after_manifest_sha256=captured_after.sha256,
            project=project.name,
            commit_sha=request.source_commit_sha,
            model_path=request.model_path,
            schema_path=request.schema_path,
            test_path=request.test_path,
            selector=request.selector,
            dialect=request.dialect,
            writeback_requested=writeback,
            analyzed_input_state=request.analyzed_input_state,
            preflight_evidence_digest=request.preflight_evidence_digest,
            policy_sha256=_canonical_digest(self.risk_engine.policy.model_dump(mode="json")),
        )
        evidence_hash = _canonical_digest(
            {
                "inputs": inputs.model_dump(mode="json"),
                "changes": [change.model_dump(mode="json") for change in changes],
                "context": context.model_dump(mode="json"),
                "initial_risk": initial.model_dump(mode="json"),
                "remediation": remediation.model_dump(mode="json"),
                "final_decision": final_decision.value,
            }
        )
        run_id = "lg-" + evidence_hash[:16]
        writeback_evidence = WritebackEvidence(
            state=(WritebackState.WRITEBACK_PENDING if writeback else WritebackState.NOT_REQUESTED),
            reason="writeback_not_attempted" if writeback else None,
        )
        created_at = datetime.now(UTC)
        result = RunResult(
            schema_version="1.1",
            run_id=run_id,
            created_at=created_at,
            status=self._run_status(initial.decision_override is not None, remediation, None),
            final_decision=final_decision,
            inputs=inputs,
            changes=changes,
            context=context,
            initial_risk=initial,
            remediation=remediation,
            evidence_hash=evidence_hash,
            writeback=writeback_evidence,
            mcp_trace=self._trace(),
        )

        if writeback:
            result = await self._writeback(result)
        result = result.model_copy(update={"mcp_trace": self._trace()})
        artifact_hash = calculate_artifact_hash(result)
        return result.model_copy(update={"artifact_hash": artifact_hash})

    async def _remediate(
        self,
        request: AnalysisRequest,
        project: Path,
        changes: tuple[SchemaChange, ...],
        context: ContextEvidence,
        baseline_snapshot: ManifestSnapshot,
        proposed_snapshot: ManifestSnapshot,
    ) -> RemediationEvidence:
        if len(changes) != 1 or changes[0].change_type is not SchemaChangeType.RENAME_COLUMN:
            return RemediationEvidence(
                status=RemediationStatus.UNSUPPORTED,
                reason="Bounded automatic remediation currently requires one proven column rename.",
            )

        change = changes[0]
        try:
            generator = RemediationGenerator(
                {request.model_path, request.schema_path, request.test_path},
                dialect=request.dialect or "duckdb",
            )
            model = _project_file(project, request.model_path)
            schema = _project_file(project, request.schema_path)
            test = _project_file(project, request.test_path, must_exist=False)
            model_sql = model.read_text(encoding="utf-8")
            schema_yaml = schema.read_text(encoding="utf-8")
            existing_test = "already exists" if test.exists() else None
            bundle = generator.generate(
                change,
                model_path=request.model_path,
                model_sql=model_sql,
                schema_path=request.schema_path,
                schema_yaml=schema_yaml,
                test_path=request.test_path,
                model_name=request.model_name,
                existing_test_sql=existing_test,
            )
        except RemediationError as exc:
            return RemediationEvidence(
                status=RemediationStatus.UNSUPPORTED,
                reason=str(exc),
            )
        except (OSError, UnicodeError) as exc:
            return RemediationEvidence(
                status=RemediationStatus.VERIFICATION_ERROR,
                reason=f"Cannot read remediation target: {type(exc).__name__}",
            )

        artifacts = tuple(
            ArtifactEvidence(
                path=artifact.path,
                purpose=artifact.purpose,
                sha256=artifact.sha256,
                unified_diff=artifact.unified_diff,
            )
            for artifact in bundle.artifacts
        )
        try:
            verification = await asyncio.to_thread(
                self.verifier.verify, project, bundle, selector=request.selector
            )
        except VerificationError as exc:
            return RemediationEvidence(
                status=RemediationStatus.VERIFICATION_ERROR,
                reason=str(exc),
                artifacts=artifacts,
                unified_diff=bundle.unified_diff,
            )
        verification_evidence = _verification_evidence(verification)
        status_map = {
            VerificationStatus.TESTED: RemediationStatus.TESTED,
            VerificationStatus.TEST_FAILED: RemediationStatus.TEST_FAILED,
            VerificationStatus.VERIFICATION_ERROR: RemediationStatus.VERIFICATION_ERROR,
        }
        if verification.status is not VerificationStatus.TESTED:
            return RemediationEvidence(
                status=status_map[verification.status],
                reason=verification.failure_reason,
                artifacts=artifacts,
                unified_diff=bundle.unified_diff,
                verification=verification_evidence,
            )

        try:
            counterfactual = verify_remediation_counterfactual(
                baseline_snapshot,
                verification,
                change,
                proposed_manifest=proposed_snapshot,
                dialect=request.dialect,
            )
        except (CounterfactualError, VerificationError) as exc:
            return RemediationEvidence(
                status=RemediationStatus.VERIFICATION_ERROR,
                reason=str(exc),
                artifacts=artifacts,
                unified_diff=bundle.unified_diff,
                verification=verification_evidence,
            )

        residual_risk = (
            self.risk_engine.assess(
                counterfactual.residual_changes,
                (),
                context.evidence_state,
            )
            if counterfactual.requires_rescore
            else None
        )
        return RemediationEvidence(
            status=RemediationStatus.TESTED,
            reason="Compatibility bridge passed the isolated dbt seed, parse, and build plan.",
            artifacts=artifacts,
            unified_diff=bundle.unified_diff,
            verification=verification_evidence,
            counterfactual_verified=True,
            interface_preserved=counterfactual.original_interface_preserved,
            counterfactual_condition=counterfactual.rescore_condition.value,
            counterfactual_evidence_digest=counterfactual.evidence_digest,
            baseline_manifest_sha256=baseline_snapshot.sha256,
            baseline_manifest_summary=baseline_snapshot.summary_json,
            preserved_expression_fingerprint=counterfactual.preserved_expression_fingerprint,
            preserved_contract_sha256=counterfactual.preserved_contract_sha256,
            preserved_query_context_sha256=counterfactual.preserved_query_context_sha256,
            residual_changes=counterfactual.residual_changes,
            residual_risk=residual_risk,
        )

    async def _writeback(self, result: RunResult) -> RunResult:
        if self.writer is None:
            evidence = WritebackEvidence(
                state=WritebackState.WRITEBACK_PENDING,
                reason="writeback_client_unavailable",
            )
            return result.model_copy(
                update={
                    "status": RunStatus.INCOMPLETE,
                    "writeback": evidence,
                }
            )
        if len(result.context.source_urns) != 1:
            evidence = WritebackEvidence(
                state=WritebackState.WRITEBACK_PENDING,
                reason="writeback_requires_one_resolved_source_urn",
            )
            return result.model_copy(
                update={
                    "status": RunStatus.INCOMPLETE,
                    "writeback": evidence,
                }
            )

        passport = ChangePassport(
            run_id=result.run_id,
            source_urn=result.context.source_urns[0],
            original_risk=result.initial_risk.score,
            residual_risk=(
                result.remediation.residual_risk.score
                if result.remediation.residual_risk is not None
                else result.initial_risk.score
            ),
            decision=result.final_decision.value,
            remediation_status=result.remediation.status.value,
            evidence_hash=result.evidence_hash,
            commit_sha=result.inputs.commit_sha,
            markdown=render_passport_markdown(result),
        )
        try:
            written = await self.writer.persist(passport)
        except MCPClientError:
            evidence = WritebackEvidence(
                state=WritebackState.WRITEBACK_PENDING,
                reason="MCPClientError",
            )
        else:
            evidence = WritebackEvidence(
                state=WritebackState(written.status.value),
                document_urn=written.document_urn,
                mutation_digests=written.mutation_digests,
                readback_digests=written.readback_digests,
                reason=written.reason,
            )
        status = self._run_status(
            result.initial_risk.decision_override is not None,
            result.remediation,
            evidence,
        )
        return result.model_copy(update={"status": status, "writeback": evidence})

    def _trace(self) -> tuple[MCPTraceEvidence, ...]:
        if self.trace_provider is None:
            return ()
        return tuple(
            MCPTraceEvidence(
                tool=event.tool,
                argument_digest=event.argument_digest,
                result_digest=event.result_digest,
                duration_ms=event.duration_ms,
                success=event.success,
                attempt=event.attempt,
            )
            for event in self.trace_provider()
        )

    @staticmethod
    def _run_status(
        initial_override: bool,
        remediation: RemediationEvidence,
        writeback: WritebackEvidence | None,
    ) -> RunStatus:
        residual_override = (
            remediation.residual_risk is not None
            and remediation.residual_risk.decision_override is not None
        )
        verification_error = remediation.status is RemediationStatus.VERIFICATION_ERROR
        writeback_pending = (
            writeback is not None and writeback.state is WritebackState.WRITEBACK_PENDING
        )
        if initial_override or residual_override or verification_error or writeback_pending:
            return RunStatus.INCOMPLETE
        return RunStatus.COMPLETE


__all__ = [
    "AgentInputError",
    "AnalysisRequest",
    "LineageGuardAgent",
    "merge_context_collections",
]
