from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEMO_PROJECT = REPOSITORY_ROOT / "demo" / "acme_dbt"
DBT_TIMEOUT_SECONDS = 90


def _dbt_executable() -> Path:
    executable = shutil.which("dbt")
    if executable is not None:
        return Path(executable).resolve()

    adjacent_to_python = Path(sys.executable).with_name("dbt")
    if adjacent_to_python.is_file():
        return adjacent_to_python.resolve()

    raise AssertionError("dbt is unavailable; install the repository's demo dependencies")


def _copy_demo(destination: Path) -> Path:
    project = shutil.copytree(
        DEMO_PROJECT,
        destination,
        ignore=shutil.ignore_patterns("target", "dbt_packages", "logs", "__pycache__"),
    )
    assert not any(path.name == ".git" for path in project.rglob(".git"))
    return project


def _run_dbt(project: Path, command: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(
        {
            "DBT_LOG_PATH": str(project / "target/logs"),
            "DBT_PROFILES_DIR": str(project),
            "DBT_SEND_ANONYMOUS_USAGE_STATS": "false",
        }
    )
    try:
        return subprocess.run(  # noqa: S603
            [_dbt_executable(), command, "--profiles-dir", str(project)],
            cwd=project,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=DBT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"dbt {command} exceeded the {DBT_TIMEOUT_SECONDS}-second timeout")


def _output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stdout}\n{result.stderr}"


def _assert_success(result: subprocess.CompletedProcess[str], command: str) -> None:
    assert result.returncode == 0, f"dbt {command} failed:\n{_output(result)}"


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict)
    return value


@pytest.mark.integration
def test_demo_baseline_is_green_and_proposed_rename_breaks_contract(tmp_path: Path) -> None:
    baseline = _copy_demo(tmp_path / "baseline")

    baseline_seed = _run_dbt(baseline, "seed")
    _assert_success(baseline_seed, "seed")
    baseline_build = _run_dbt(baseline, "build")
    _assert_success(baseline_build, "build")
    assert (baseline / "target/acme_commerce.duckdb").is_file()
    assert not (baseline / "logs").exists()
    assert not (baseline / "dbt_packages").exists()

    manifest = _load_json(baseline / "target" / "manifest.json")
    nodes = manifest["nodes"]
    staging_id = "model.acme_commerce.stg_orders"
    mart_id = "model.acme_commerce.fct_daily_revenue"
    assert "order_total" in nodes[staging_id]["columns"]
    assert staging_id in nodes[mart_id]["depends_on"]["nodes"]
    assert any(
        node["resource_type"] == "test" and node.get("attached_node") == staging_id
        for node in nodes.values()
    )
    exposure = manifest["exposures"]["exposure.acme_commerce.executive_revenue_overview"]
    assert mart_id in exposure["depends_on"]["nodes"]
    assert exposure["owner"]["email"] == "finance-analytics@example.invalid"

    proposed = _copy_demo(tmp_path / "proposed")
    shutil.copytree(
        proposed / "scenario/proposed/models",
        proposed / "models",
        dirs_exist_ok=True,
    )

    proposed_seed = _run_dbt(proposed, "seed")
    _assert_success(proposed_seed, "seed")
    proposed_build = _run_dbt(proposed, "build")
    assert proposed_build.returncode != 0, "the intentionally breaking proposal unexpectedly passed"

    proposed_manifest = _load_json(proposed / "target" / "manifest.json")
    proposed_columns = proposed_manifest["nodes"][staging_id]["columns"]
    assert "gross_amount" in proposed_columns
    assert "order_total" not in proposed_columns

    run_results = _load_json(proposed / "target" / "run_results.json")
    results = {result["unique_id"]: result for result in run_results["results"]}
    assertion_id = "test.acme_commerce.assert_completed_orders_have_positive_totals"
    assert results[staging_id]["status"] == "success"
    assert results[assertion_id]["status"] == "error"
    assert results[mart_id]["status"] == "skipped"

    downstream_error = str(results[assertion_id]["message"]).lower()
    assert "order_total" in downstream_error
    assert "gross_amount" in downstream_error
