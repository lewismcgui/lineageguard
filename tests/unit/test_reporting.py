from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from lineageguard.models import (
    AssetType,
    EvidenceState,
    ImpactedAsset,
    SchemaChange,
    SchemaChangeType,
)
from lineageguard.reporting import (
    render_html,
    render_markdown,
    render_passport_markdown,
    write_reports,
)
from lineageguard.risk import assess_risk, load_policy
from lineageguard.run_models import (
    AnalyzedInputState,
    ArtifactEvidence,
    CommandEvidence,
    ContextEvidence,
    GateDecision,
    InputEvidence,
    RemediationEvidence,
    RemediationStatus,
    RunResult,
    RunStatus,
    VerificationEvidence,
    WritebackEvidence,
    WritebackState,
    calculate_artifact_hash,
)

ROOT = Path(__file__).resolve().parents[2]


def _result() -> RunResult:
    change = SchemaChange(
        change_type=SchemaChangeType.RENAME_COLUMN,
        relation="analytics.<orders>",
        old_column="order_total",
        new_column="gross_amount",
        old_type="DECIMAL(12, 2)",
        new_type="DECIMAL(12, 2)",
    )
    asset = ImpactedAsset(
        urn="urn:li:dashboard:(looker,revenue)",
        asset_type=AssetType.DASHBOARD,
        name="Revenue | Monday",
        hop_count=2,
        owners=("urn:li:corpuser:finance",),
        assertion_urns=(),
        critical_asset=True,
        sensitive_data=False,
        direct_column_lineage=False,
    )
    state = EvidenceState.complete()
    policy = load_policy(ROOT / "config/risk-policy.yaml")
    initial = assess_risk((change,), (asset,), state, policy)
    residual_change = SchemaChange(
        change_type=SchemaChangeType.ADD_COLUMN,
        relation=change.relation,
        new_column="gross_amount",
        new_type="DECIMAL(12, 2)",
        new_nullable=True,
    )
    residual = assess_risk((residual_change,), (), state, policy)
    result = RunResult(
        schema_version="1.1",
        run_id="lg-test123456",
        created_at=datetime(2026, 7, 12, tzinfo=UTC),
        status=RunStatus.COMPLETE,
        final_decision=GateDecision.PASS_WITH_REMEDIATION,
        inputs=InputEvidence(
            before_manifest="baseline/manifest.json",
            before_manifest_sha256="a" * 64,
            after_manifest="proposed/manifest.json",
            after_manifest_sha256="b" * 64,
            project="proposed",
            commit_sha="abc123",
            analyzed_input_state=AnalyzedInputState.GENERATED_IN_PROCESS,
        ),
        changes=(change,),
        context=ContextEvidence(
            source_urns=("urn:li:dataset:(urn:li:dataPlatform:duckdb,orders,PROD)",),
            impacted_assets=(asset,),
            evidence_state=state,
            response_digests=("c" * 64,),
            reason_codes=(),
        ),
        initial_risk=initial,
        remediation=RemediationEvidence(
            status=RemediationStatus.TESTED,
            artifacts=(
                ArtifactEvidence(
                    path="models/orders.sql",
                    purpose="compatibility alias",
                    sha256="d" * 64,
                    unified_diff="--- a/models/orders.sql\n+++ b/models/orders.sql\n",
                ),
            ),
            unified_diff="--- a/models/orders.sql\n+++ b/models/orders.sql\n",
            counterfactual_verified=True,
            interface_preserved=True,
            residual_changes=(residual_change,),
            residual_risk=residual,
        ),
        evidence_hash="e" * 64,
        writeback=WritebackEvidence(state=WritebackState.NOT_REQUESTED),
    )
    return result.model_copy(update={"artifact_hash": calculate_artifact_hash(result)})


def test_markdown_contains_decision_blast_radius_and_patch() -> None:
    result = _result()
    remediation = result.remediation.model_copy(
        update={
            "verification": VerificationEvidence(
                status="TESTED",
                evidence_digest="9" * 64,
                commands=(
                    CommandEvidence(
                        command=("dbt", "build"),
                        exit_code=0,
                        duration_ms=42,
                        output_digest="8" * 64,
                        output_tail="PASS",
                    ),
                ),
            )
        }
    )
    result = result.model_copy(update={"remediation": remediation})
    report = render_markdown(result)

    assert "PASS_WITH_REMEDIATION" in report
    assert "Revenue \\| Monday" in report
    assert "```diff" in report
    assert "Writeback was not requested" in report
    assert f"**Final artifact hash:** `{result.artifact_hash}`" in report
    assert "**Source commit:** `abc123`" in report
    assert "**Analyzed inputs:** `GENERATED_IN_PROCESS`" in report
    assert "dbt build" in report
    assert "42 ms" in report


def test_html_escapes_catalog_text_and_has_before_after_rail() -> None:
    report = render_html(_result())

    assert "analytics.&amp;lt;orders&amp;gt;" in report
    assert "analytics.<orders>" not in report
    assert "BEFORE&nbsp;" in report
    assert "AFTER&nbsp;" in report
    assert "<script" not in report


def test_datahub_passport_is_neutral_about_the_later_readback_outcome() -> None:
    passport = render_passport_markdown(_result())

    assert "**DataHub writeback:**" not in passport
    assert "independent MCP readback outcome" in passport
    assert "Source commit: `abc123`" in passport
    assert "Analyzed inputs: `GENERATED_IN_PROCESS`" in passport
    assert "Writeback was not requested" not in passport


def test_writes_immutable_run_reports_and_atomic_latest_snapshot(tmp_path: Path) -> None:
    result = _result()
    paths = write_reports(result, tmp_path / "runs")

    assert paths.json.is_file()
    assert paths.markdown.is_file()
    assert paths.html.is_file()
    assert paths.latest_json.read_bytes() == paths.json.read_bytes()
    assert paths.run_directory.name == f"{result.run_id}-{result.artifact_hash[:12]}"
    assert stat.S_IMODE(paths.run_directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.json.stat().st_mode) == 0o600
    assert stat.S_IMODE(paths.latest_json.stat().st_mode) == 0o600
    payload = json.loads(paths.json.read_text(encoding="utf-8"))
    assert payload["run_id"] == result.run_id
    assert payload["final_decision"] == "PASS_WITH_REMEDIATION"


def test_report_writer_rejects_symlinked_output_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "runs"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="symbolic link"):
        write_reports(_result(), link)


def test_report_writer_rejects_unsafe_run_id_path_escape(tmp_path: Path) -> None:
    result = _result().model_copy(update={"run_id": "../../escape"})

    with pytest.raises(ValueError, match="run ID"):
        write_reports(result, tmp_path / "runs")

    assert not (tmp_path / "escape").exists()


def test_report_writer_is_idempotent_but_rejects_tampered_immutable_run(
    tmp_path: Path,
) -> None:
    result = _result()
    first = write_reports(result, tmp_path / "runs")
    second = write_reports(result, tmp_path / "runs")
    assert second.run_directory == first.run_directory

    first.markdown.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        write_reports(result, tmp_path / "runs")


def test_report_writer_rejects_precreated_symlink_run_directory(tmp_path: Path) -> None:
    result = _result()
    assert result.artifact_hash is not None
    root = tmp_path / "runs"
    root.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (root / f"lg-test123456-{result.artifact_hash[:12]}").symlink_to(
        target, target_is_directory=True
    )

    with pytest.raises(ValueError, match="owner-controlled"):
        write_reports(result, root)


def test_report_writer_rejects_a_drifted_artifact_seal(tmp_path: Path) -> None:
    result = _result().model_copy(update={"evidence_hash": "0" * 64})

    with pytest.raises(ValueError, match="artifact hash"):
        write_reports(result, tmp_path / "runs")


def test_report_writer_rejects_symlinked_immutable_artifact(tmp_path: Path) -> None:
    result = _result()
    paths = write_reports(result, tmp_path / "runs")
    target = tmp_path / "outside.md"
    target.write_text("outside\n", encoding="utf-8")
    paths.markdown.unlink()
    paths.markdown.symlink_to(target)

    with pytest.raises(ValueError, match="symbolic link"):
        write_reports(result, tmp_path / "runs")


def test_markdown_neutralizes_active_metadata_and_uses_a_longer_diff_fence() -> None:
    result = _result()
    hostile_asset = result.context.impacted_assets[0].model_copy(
        update={"name": '<img src="https://example.invalid/x"> ![x](https://example.invalid/y)'}
    )
    context = result.context.model_copy(update={"impacted_assets": (hostile_asset,)})
    remediation = result.remediation.model_copy(
        update={
            "reason": "<script>alert(1)</script> ![reason](https://example.invalid/r)",
            "unified_diff": "--- a/file\n+++ b/file\n```evil\n+unsafe\n",
        }
    )

    report = render_markdown(
        result.model_copy(update={"context": context, "remediation": remediation})
    )

    assert "<img" not in report
    assert "<script" not in report
    assert "![x](" not in report
    assert "````diff" in report
    assert "\n````\n" in report
