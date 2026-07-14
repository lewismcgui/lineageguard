from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from lineageguard.changes import compare_dbt_manifests
from lineageguard.models import SchemaChangeType
from lineageguard.remediation import (
    CounterfactualCondition,
    RemediationGenerator,
    RemediationVerifier,
    VerificationStatus,
    snapshot_dbt_manifest,
    verify_remediation_counterfactual,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEMO_PROJECT = REPOSITORY_ROOT / "demo" / "acme_dbt"
MODEL_PATH = "models/staging/stg_orders.sql"
SCHEMA_PATH = "models/staging/schema.yml"
TEST_PATH = "tests/lineageguard_order_total_matches_gross_amount.sql"


def _copy_demo(destination: Path) -> Path:
    return shutil.copytree(
        DEMO_PROJECT,
        destination,
        ignore=shutil.ignore_patterns("target", "logs", "*.duckdb", "__pycache__"),
    )


def _compile_manifest(project: Path, executable: str) -> Path:
    allowed_environment = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "VIRTUAL_ENV")
    environment = {key: os.environ[key] for key in allowed_environment if key in os.environ}
    environment["DBT_SEND_ANONYMOUS_USAGE_STATS"] = "false"
    completed = subprocess.run(  # noqa: S603 - test invokes the resolved dbt executable only
        (
            executable,
            "compile",
            "--project-dir",
            ".",
            "--profiles-dir",
            ".",
            "--select",
            "stg_orders+",
            "--no-use-colors",
        ),
        cwd=project,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
    )
    diagnostic = f"{completed.stdout}\n{completed.stderr}"
    assert completed.returncode == 0, diagnostic
    manifest = project / "target" / "manifest.json"
    assert manifest.is_file()
    return manifest


@pytest.mark.integration
def test_generated_rename_bridge_repair_is_actually_dbt_tested(tmp_path: Path) -> None:
    executable = shutil.which("dbt")
    assert executable is not None

    baseline = _copy_demo(tmp_path / "baseline")
    baseline_manifest_path = _compile_manifest(baseline, executable)
    before_snapshot = snapshot_dbt_manifest(baseline_manifest_path)

    project = _copy_demo(tmp_path / "proposed")
    shutil.copytree(project / "scenario/proposed/models", project / "models", dirs_exist_ok=True)
    proposed_manifest_path = _compile_manifest(project, executable)
    proposed_snapshot = snapshot_dbt_manifest(proposed_manifest_path)

    proposed_changes = compare_dbt_manifests(
        baseline_manifest_path,
        proposed_manifest_path,
        source_path="<proposed-demo-manifest>",
    )
    assert len(proposed_changes) == 1
    change = proposed_changes[0]
    assert change.change_type is SchemaChangeType.RENAME_COLUMN
    assert (change.old_column, change.new_column) == ("order_total", "gross_amount")
    assert (change.old_nullable, change.new_nullable) == (False, False)

    bundle = RemediationGenerator({MODEL_PATH, SCHEMA_PATH, TEST_PATH}).generate(
        change,
        model_path=MODEL_PATH,
        model_sql=(project / MODEL_PATH).read_text(encoding="utf-8"),
        schema_path=SCHEMA_PATH,
        schema_yaml=(project / SCHEMA_PATH).read_text(encoding="utf-8"),
        test_path=TEST_PATH,
        model_name="stg_orders",
    )

    result = RemediationVerifier(dbt_executable=executable).verify(
        project, bundle, selector="stg_orders+"
    )

    diagnostic = "\n".join(command.output for command in result.commands)
    assert result.status is VerificationStatus.TESTED, f"{result.failure_reason}\n{diagnostic}"
    assert [command.command[1] for command in result.commands] == ["seed", "parse", "build"]
    assert all(command.exit_code == 0 for command in result.commands)
    assert result.patched_manifest is not None
    assert len(result.patched_manifest.sha256) == 64
    assert str(tmp_path) not in result.patched_manifest.summary_json
    assert "DBT_ENV" not in result.patched_manifest.summary_json
    assert not (project / TEST_PATH).exists(), "verification must not alter the PR workspace"
    assert (
        "CAST(order_total AS DECIMAL(12, 2)) AS order_total" in bundle.by_path[MODEL_PATH].content
    )
    assert len(result.evidence_digest) == 64

    counterfactual = verify_remediation_counterfactual(
        before_snapshot,
        result,
        change,
        proposed_manifest=proposed_snapshot,
    )
    assert counterfactual.original_interface_preserved is True
    assert counterfactual.rescore_condition is CounterfactualCondition.RESIDUAL_CHANGES
    assert counterfactual.requires_rescore is True
    assert len(counterfactual.evidence_digest) == 64
    assert counterfactual.patched_manifest_sha256 == result.patched_manifest.sha256
    assert len(counterfactual.residual_changes) == 1
    residual = counterfactual.residual_changes[0]
    assert residual.change_type is SchemaChangeType.ADD_COLUMN
    assert residual.relation == change.relation
    assert residual.new_column == "gross_amount"
    assert residual.new_type == "DECIMAL(12, 2)"
    assert residual.new_nullable is False
    assert residual.severity_key == "add_required_column"
