from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from lineageguard.agent import AnalysisRequest
from lineageguard.cli import REPOSITORY_ROOT, run_analysis
from lineageguard.config import Settings
from lineageguard.datahub.demo_seed import seed_demo
from lineageguard.demo import prepare_demo_projects
from lineageguard.run_models import GateDecision, RunStatus, WritebackState


@pytest.mark.datahub
@pytest.mark.asyncio
async def test_live_core_mcp_writeback_and_readback(tmp_path: Path) -> None:
    """Required retained smoke proof for a running pinned local DataHub stack."""

    settings = Settings(project_root=REPOSITORY_ROOT, mcp_mutations=True)
    assert seed_demo(settings) > 0
    executable = shutil.which("dbt") or "dbt"
    preparation = prepare_demo_projects(
        REPOSITORY_ROOT / "demo/acme_dbt",
        tmp_path / "prepared",
        dbt_executable=executable,
    )
    request = AnalysisRequest(
        before_manifest=preparation.before_manifest,
        after_manifest=preparation.after_manifest,
        project_dir=preparation.proposed_project,
        model_path="models/staging/stg_orders.sql",
        schema_path="models/staging/schema.yml",
        test_path="tests/lineageguard_order_total_matches_gross_amount.sql",
        model_name="stg_orders",
        selector="stg_orders+",
        source_commit_sha="LIVE-DATAHUB-SMOKE",
        dialect="duckdb",
    )

    result, reports = await run_analysis(
        request,
        settings=settings,
        policy_path=REPOSITORY_ROOT / "config/risk-policy.yaml",
        output_root=tmp_path / "runs",
        writeback=True,
    )

    assert result.final_decision is GateDecision.PASS_WITH_REMEDIATION
    assert result.status is RunStatus.COMPLETE
    assert result.writeback.state is WritebackState.VERIFIED
    assert result.writeback.document_urn is not None
    assert result.writeback.mutation_digests
    assert result.writeback.readback_digests
    assert result.artifact_hash is not None
    assert reports.json.is_file()
    assert reports.latest_json.read_bytes() == reports.json.read_bytes()
