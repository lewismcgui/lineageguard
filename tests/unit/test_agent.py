from __future__ import annotations

import json
from pathlib import Path

import pytest

from lineageguard.agent import (
    AgentInputError,
    AnalysisRequest,
    LineageGuardAgent,
    _gate_decision,
    merge_context_collections,
)
from lineageguard.datahub.context import ContextCollection
from lineageguard.datahub.writeback import (
    ChangePassport,
    WritebackResult,
    WritebackStatus,
)
from lineageguard.models import (
    AssetType,
    EvidenceKind,
    EvidenceState,
    EvidenceStatus,
    ImpactedAsset,
    RiskDecision,
    SchemaChange,
    SchemaChangeType,
)
from lineageguard.remediation import (
    VerificationResult,
    VerificationStatus,
    snapshot_dbt_manifest,
)
from lineageguard.risk import RiskEngine
from lineageguard.run_models import (
    AnalyzedInputState,
    GateDecision,
    RemediationEvidence,
    RemediationStatus,
    RunStatus,
    WritebackState,
)

ROOT = Path(__file__).resolve().parents[2]
SOURCE_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,analytics.orders,PROD)"
DASHBOARD_URN = "urn:li:dashboard:(looker,revenue)"


def _manifest(column: str, *, compatibility: bool = False) -> dict[str, object]:
    expression = "cast(order_total as decimal(12, 2))"
    columns: dict[str, object] = {
        column: {
            "name": column,
            "data_type": "decimal(12, 2)",
            "constraints": [{"type": "not_null"}],
        }
    }
    projections = [f"{expression} as {column}"]
    if compatibility:
        replacement = columns[column]
        preserved = {
            "name": "order_total",
            "data_type": "decimal(12, 2)",
            "constraints": [{"type": "not_null"}],
        }
        columns = {"order_total": preserved, column: replacement}
        projections = [f"{expression} as order_total", f"{expression} as {column}"]
    return {
        "metadata": {"adapter_type": "duckdb"},
        "nodes": {
            "model.acme.orders": {
                "resource_type": "model",
                "name": "orders",
                "relation_name": '"analytics"."orders"',
                "columns": columns,
                "compiled_code": "select " + ", ".join(projections) + " from raw.orders",  # noqa: S608 - static synthetic manifest
            }
        },
    }


def _write_manifest(path: Path, manifest: dict[str, object]) -> None:
    path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")


def _project(tmp_path: Path) -> tuple[Path, Path, Path]:
    project = tmp_path / "proposed"
    (project / "models").mkdir(parents=True)
    (project / "tests").mkdir()
    (project / "dbt_project.yml").write_text("name: acme\n", encoding="utf-8")
    (project / "models/orders.sql").write_text(
        "select cast(order_total as decimal(12, 2)) as gross_amount from raw.orders\n",
        encoding="utf-8",
    )
    (project / "models/schema.yml").write_text(
        """version: 2
models:
  - name: orders
    columns:
      - name: gross_amount
        data_type: decimal(12, 2)
        constraints:
          - type: not_null
""",
        encoding="utf-8",
    )
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _write_manifest(before, _manifest("order_total"))
    _write_manifest(after, _manifest("gross_amount"))
    return project, before, after


class FakeCollector:
    def __init__(self, state: EvidenceState | None = None) -> None:
        self.state = state or EvidenceState.complete()
        self.changes = []

    async def collect(self, change):
        self.changes.append(change)
        asset = ImpactedAsset(
            urn=DASHBOARD_URN,
            asset_type=AssetType.DASHBOARD,
            name="Executive Revenue",
            hop_count=2,
            owners=("urn:li:corpuser:finance",),
            assertion_urns=("urn:li:assertion:order-total",),
            critical_asset=True,
            sensitive_data=False,
            direct_column_lineage=True,
        )
        return ContextCollection(
            source_urn=SOURCE_URN,
            impacted_assets=(asset,),
            evidence_state=self.state,
            response_digests=("a" * 64,),
            reason_codes=(),
        )


class FakeVerifier:
    def __init__(self) -> None:
        self.calls = []

    def verify(self, project_dir, bundle, *, selector):
        self.calls.append((project_dir, bundle, selector))
        snapshot = snapshot_dbt_manifest(_manifest("gross_amount", compatibility=True))
        return VerificationResult(
            status=VerificationStatus.TESTED,
            commands=(),
            artifact_digests=tuple(
                (artifact.path, artifact.sha256) for artifact in bundle.artifacts
            ),
            evidence_digest="b" * 64,
            patched_manifest=snapshot,
        )


class FakeWriter:
    def __init__(self) -> None:
        self.passports: list[ChangePassport] = []

    async def persist(self, passport: ChangePassport) -> WritebackResult:
        self.passports.append(passport)
        return WritebackResult(
            status=WritebackStatus.VERIFIED,
            document_urn="urn:li:document:lineageguard-test",
            mutation_digests=("c" * 64,),
            readback_digests=("d" * 64,),
        )


def _request(project: Path, before: Path, after: Path) -> AnalysisRequest:
    return AnalysisRequest(
        before_manifest=before,
        after_manifest=after,
        project_dir=project,
        model_path="models/orders.sql",
        schema_path="models/schema.yml",
        test_path="tests/order_total_matches_gross_amount.sql",
        model_name="orders",
        selector="orders+",
        source_commit_sha="abc123",
        dialect="duckdb",
    )


def _agent(collector, verifier, writer=None) -> LineageGuardAgent:
    return LineageGuardAgent(
        collector=collector,
        risk_engine=RiskEngine.from_policy_file(ROOT / "config/risk-policy.yaml"),
        verifier=verifier,
        writer=writer,
    )


@pytest.mark.asyncio
async def test_runs_closed_loop_to_tested_residual_pass_and_verified_writeback(
    tmp_path: Path,
) -> None:
    project, before, after = _project(tmp_path)
    collector = FakeCollector()
    verifier = FakeVerifier()
    writer = FakeWriter()
    agent = _agent(collector, verifier, writer)

    result = await agent.analyze(_request(project, before, after), writeback=True)

    assert result.initial_risk.decision.value == "BLOCK"
    assert result.remediation.residual_risk is not None
    assert result.remediation.residual_risk.score == 12
    assert result.remediation.residual_risk.decision.value == "PASS"
    assert result.remediation.interface_preserved is True
    assert result.final_decision is GateDecision.PASS_WITH_REMEDIATION
    assert result.writeback.state is WritebackState.VERIFIED
    assert result.status is RunStatus.COMPLETE
    assert result.schema_version == "1.1"
    assert result.inputs.commit_sha == "abc123"
    assert result.inputs.analyzed_input_state is AnalyzedInputState.SUPPLIED_MANIFESTS
    assert writer.passports[0].decision == "PASS_WITH_REMEDIATION"
    assert writer.passports[0].document_urn is None
    assert result.evidence_hash in writer.passports[0].markdown
    assert result.run_id == f"lg-{result.evidence_hash[:16]}"
    assert result.artifact_hash is not None
    assert len(result.artifact_hash) == 64
    assert not (project / "tests/order_total_matches_gross_amount.sql").exists()


def test_gate_requires_tested_status_even_when_counterfactual_flags_are_true() -> None:
    state = EvidenceState.complete()
    change = SchemaChange(
        change_type=SchemaChangeType.RENAME_COLUMN,
        relation="analytics.orders",
        old_column="order_total",
        new_column="gross_amount",
        old_type="DECIMAL(12, 2)",
        new_type="DECIMAL(12, 2)",
    )
    initial = RiskEngine.from_policy_file(ROOT / "config/risk-policy.yaml").assess(
        (change,), (), state
    )
    remediation = RemediationEvidence(
        status=RemediationStatus.GENERATED,
        counterfactual_verified=True,
        interface_preserved=True,
        counterfactual_condition="NO_RESIDUAL_CHANGES",
    )

    assert _gate_decision(initial, remediation) is GateDecision.REVIEW


@pytest.mark.asyncio
async def test_read_only_run_is_deterministic_and_does_not_call_writer(tmp_path: Path) -> None:
    project, before, after = _project(tmp_path)
    writer = FakeWriter()
    agent = _agent(FakeCollector(), FakeVerifier(), writer)
    request = _request(project, before, after)

    first = await agent.analyze(request)
    second = await agent.analyze(request)

    assert first.run_id == second.run_id
    assert first.evidence_hash == second.evidence_hash
    assert first.writeback.state is WritebackState.NOT_REQUESTED
    assert writer.passports == []


@pytest.mark.asyncio
async def test_manifest_drift_during_context_collection_fails_closed(tmp_path: Path) -> None:
    project, before, after = _project(tmp_path)

    class MutatingCollector(FakeCollector):
        async def collect(self, change):
            _write_manifest(after, _manifest("unexpected_column"))
            return await super().collect(change)

    with pytest.raises(AgentInputError, match="manifest drifted"):
        await _agent(MutatingCollector(), FakeVerifier()).analyze(_request(project, before, after))


@pytest.mark.asyncio
async def test_untyped_compiled_cast_change_cannot_become_a_false_pass(tmp_path: Path) -> None:
    project, before, after = _project(tmp_path)
    before_manifest = _manifest("order_total")
    after_manifest = _manifest("order_total")
    before_node = next(iter(before_manifest["nodes"].values()))  # type: ignore[union-attr]
    after_node = next(iter(after_manifest["nodes"].values()))  # type: ignore[union-attr]
    before_node["columns"]["order_total"].pop("data_type")  # type: ignore[index]
    after_node["columns"]["order_total"].pop("data_type")  # type: ignore[index]
    before_node["compiled_code"] = (  # type: ignore[index]
        "select cast(order_total as integer) as order_total from raw.orders"
    )
    after_node["compiled_code"] = (  # type: ignore[index]
        "select cast(order_total as varchar) as order_total from raw.orders"
    )
    _write_manifest(before, before_manifest)
    _write_manifest(after, after_manifest)
    verifier = FakeVerifier()

    result = await _agent(FakeCollector(), verifier).analyze(_request(project, before, after))

    assert [change.change_type for change in result.changes] == [SchemaChangeType.TYPE_CHANGE]
    assert result.final_decision is not GateDecision.PASS
    assert result.initial_risk.decision_override is not None
    assert verifier.calls == []


@pytest.mark.asyncio
async def test_proposed_replacement_contract_is_bound_to_tested_manifest(tmp_path: Path) -> None:
    project, before, after = _project(tmp_path)
    proposed = _manifest("gross_amount")
    proposed_node = next(iter(proposed["nodes"].values()))  # type: ignore[union-attr]
    proposed_node["columns"]["gross_amount"]["constraints"].append(  # type: ignore[index]
        {"type": "unique"}
    )
    _write_manifest(after, proposed)

    result = await _agent(FakeCollector(), FakeVerifier()).analyze(_request(project, before, after))

    assert result.remediation.status is RemediationStatus.VERIFICATION_ERROR
    assert result.remediation.reason is not None
    assert "proposed column contracts" in result.remediation.reason
    assert result.final_decision is GateDecision.BLOCK
    assert result.status is RunStatus.INCOMPLETE


@pytest.mark.asyncio
async def test_incomplete_catalog_evidence_can_never_produce_complete_run(tmp_path: Path) -> None:
    project, before, after = _project(tmp_path)
    state = EvidenceState(
        catalog=EvidenceStatus.COMPLETE,
        lineage=EvidenceStatus.TRUNCATED,
        traversal=EvidenceStatus.TRUNCATED,
        ownership=EvidenceStatus.COMPLETE,
        assertions=EvidenceStatus.COMPLETE,
    )

    result = await _agent(FakeCollector(state), FakeVerifier()).analyze(
        _request(project, before, after)
    )

    assert result.status is RunStatus.INCOMPLETE
    assert result.initial_risk.decision_override is not None
    assert result.remediation.residual_risk is not None
    assert result.remediation.residual_risk.decision.value == "REVIEW"
    assert result.final_decision is GateDecision.BLOCK


def test_context_merge_uses_conservative_asset_facts() -> None:
    first = ContextCollection(
        source_urn=SOURCE_URN,
        impacted_assets=(
            ImpactedAsset(
                urn=DASHBOARD_URN,
                asset_type=AssetType.DATASET,
                hop_count=3,
                owners=("urn:li:corpuser:analytics",),
                assertion_urns=(),
                critical_asset=False,
                sensitive_data=False,
                direct_column_lineage=False,
                recent_query_usage_score=1,
            ),
        ),
        evidence_state=EvidenceState.complete(),
        response_digests=("1",),
        reason_codes=(),
    )
    second = ContextCollection(
        source_urn=SOURCE_URN,
        impacted_assets=(
            ImpactedAsset(
                urn=DASHBOARD_URN,
                asset_type=AssetType.DASHBOARD,
                hop_count=1,
                owners=None,
                assertion_urns=("urn:li:assertion:a",),
                critical_asset=True,
                sensitive_data=None,
                direct_column_lineage=True,
                recent_query_usage_score=2,
            ),
        ),
        evidence_state=EvidenceState.complete(),
        response_digests=("2",),
        reason_codes=(),
    )

    merged = merge_context_collections((first, second))
    asset = merged.impacted_assets[0]

    assert asset.asset_type is AssetType.DASHBOARD
    assert asset.hop_count == 1
    assert asset.owners is None
    assert asset.critical_asset is True
    assert asset.direct_column_lineage is True
    assert any(reason.startswith("context.asset_merged") for reason in merged.reason_codes)
    assert merged.evidence_state.catalog is EvidenceStatus.AMBIGUOUS
    assert merged.evidence_state.lineage is EvidenceStatus.AMBIGUOUS
    assert merged.evidence_state.ownership is EvidenceStatus.AMBIGUOUS
    assert merged.evidence_state.assertions is EvidenceStatus.AMBIGUOUS
    conflict_records = tuple(
        record
        for record in merged.evidence_state.records
        if record.id.startswith("context.asset_fact_conflict")
    )
    assert len(conflict_records) == 8
    assert all(
        record.critical and record.status is EvidenceStatus.AMBIGUOUS for record in conflict_records
    )

    low_risk_change = SchemaChange(
        change_type=SchemaChangeType.ADD_COLUMN,
        relation="analytics.orders",
        new_column="safe_addition",
        new_type="INTEGER",
        new_nullable=True,
    )
    assessment = RiskEngine.from_policy_file(ROOT / "config/risk-policy.yaml").assess(
        (low_risk_change,), merged.impacted_assets, merged.evidence_state
    )
    assert assessment.decision is not RiskDecision.PASS
    assert assessment.decision_override is not None


def test_asset_type_and_hop_conflicts_force_review_even_when_score_would_pass() -> None:
    def collection(asset_type: AssetType, hop_count: int, digest: str) -> ContextCollection:
        return ContextCollection(
            source_urn=SOURCE_URN,
            impacted_assets=(
                ImpactedAsset(
                    urn=DASHBOARD_URN,
                    asset_type=asset_type,
                    hop_count=hop_count,
                    owners=("urn:li:corpuser:analytics",),
                    assertion_urns=(),
                    critical_asset=False,
                    sensitive_data=False,
                    direct_column_lineage=False,
                    recent_query_usage_score=0,
                ),
            ),
            evidence_state=EvidenceState.complete(),
            response_digests=(digest,),
            reason_codes=(),
        )

    merged = merge_context_collections(
        (
            collection(AssetType.OTHER, 3, "first"),
            collection(AssetType.DATASET, 1, "second"),
        )
    )
    change = SchemaChange(
        change_type=SchemaChangeType.ADD_COLUMN,
        relation="analytics.orders",
        new_column="safe_addition",
        new_type="INTEGER",
        new_nullable=True,
    )
    assessment = RiskEngine.from_policy_file(ROOT / "config/risk-policy.yaml").assess(
        (change,), merged.impacted_assets, merged.evidence_state
    )

    assert merged.evidence_state.catalog is EvidenceStatus.AMBIGUOUS
    assert merged.evidence_state.traversal is EvidenceStatus.AMBIGUOUS
    assert {
        record.kind
        for record in merged.evidence_state.records
        if record.id.startswith("context.asset_fact_conflict")
    } == {EvidenceKind.ASSET_TYPE, EvidenceKind.TRAVERSAL}
    assert assessment.score_decision is RiskDecision.PASS
    assert assessment.decision is RiskDecision.REVIEW
    assert assessment.decision_override is not None
