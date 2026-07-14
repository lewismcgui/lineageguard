from __future__ import annotations

import json
import stat
import subprocess
from pathlib import Path

import pytest

from lineageguard.demo import (
    DemoPreparation,
    DemoPreparationError,
    prepare_demo_projects,
    write_demo_preflight,
)


def _preflight_input(tmp_path: Path) -> DemoPreparation:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text('{"before":true}', encoding="utf-8")
    after.write_text('{"after":true}', encoding="utf-8")
    return DemoPreparation(
        baseline_project=tmp_path,
        proposed_project=tmp_path,
        before_manifest=before,
        after_manifest=after,
        commands=(),
        evidence_digest="a" * 64,
    )


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    (source / "models").mkdir(parents=True)
    (source / "scenario/proposed/models").mkdir(parents=True)
    (source / "dbt_project.yml").write_text("name: demo\n", encoding="utf-8")
    (source / "models/orders.sql").write_text("select order_total\n", encoding="utf-8")
    (source / "scenario/proposed/models/orders.sql").write_text(
        "select order_total as gross_amount\n", encoding="utf-8"
    )
    return source


def _manifest(project: str) -> dict[str, object]:
    column = "order_total" if project == "baseline" else "gross_amount"
    return {
        "metadata": {"adapter_type": "duckdb"},
        "nodes": {
            "model.demo.orders": {
                "resource_type": "model",
                "relation_name": '"analytics"."orders"',
                "columns": {column: {"name": column}},
            }
        },
    }


def _write_demo_run_results(cwd: Path, *, proposed_failed: bool) -> None:
    statuses: list[dict[str, object]] = [
        {"unique_id": "model.demo.stg_orders", "status": "success"},
        {
            "unique_id": "model.demo.fct_daily_revenue",
            "status": "skipped" if proposed_failed else "success",
        },
    ]
    if proposed_failed:
        statuses.append(
            {
                "unique_id": "test.demo.assert_completed_orders_have_positive_totals",
                "status": "error",
                "message": "Binder Error: order_total is missing",
            }
        )
    (cwd / "target/run_results.json").write_text(
        json.dumps({"results": statuses}), encoding="utf-8"
    )


def test_prepares_green_baseline_expected_breakage_and_manifest_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATAHUB_GMS_TOKEN", "must-not-enter-dbt")
    resolved_dbt = tmp_path / "bin/dbt"
    calls: list[tuple[str, str]] = []

    def runner(command, *, cwd, env, timeout_seconds):
        assert timeout_seconds == 30
        assert "DATAHUB_GMS_TOKEN" not in env
        action = command[1]
        calls.append((cwd.name, action))
        (cwd / "target").mkdir(exist_ok=True)
        (cwd / "target/manifest.json").write_text(json.dumps(_manifest(cwd.name)), encoding="utf-8")
        if cwd.name == "proposed" and action == "build":
            _write_demo_run_results(cwd, proposed_failed=True)
            return subprocess.CompletedProcess(
                command,
                1,
                stdout="Binder Error: order_total missing downstream",
                stderr="",
            )
        if cwd.name == "baseline" and action == "build":
            _write_demo_run_results(cwd, proposed_failed=False)
        return subprocess.CompletedProcess(command, 0, stdout="PASS", stderr="")

    preparation = prepare_demo_projects(
        _source(tmp_path),
        tmp_path / "workspace",
        dbt_executable=str(resolved_dbt),
        timeout_seconds=30,
        runner=runner,
    )

    assert calls == [
        ("baseline", "build"),
        ("proposed", "compile"),
        ("proposed", "build"),
        ("proposed", "compile"),
    ]
    assert [command.exit_code for command in preparation.commands] == [0, 0, 1, 0]
    assert all(command.command[0] == "dbt" for command in preparation.commands)
    assert all(str(resolved_dbt) not in command.command for command in preparation.commands)
    assert preparation.commands[0].run_results_digest is not None
    assert preparation.commands[2].run_results_digest is not None
    assert len(preparation.evidence_digest) == 64
    assert preparation.before_manifest.is_file()
    assert preparation.after_manifest.is_file()
    assert "gross_amount" in (preparation.proposed_project / "models/orders.sql").read_text(
        encoding="utf-8"
    )

    destination = tmp_path / "reports/demo-preflight.json"
    write_demo_preflight(preparation, destination)
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["evidence_digest"] == preparation.evidence_digest
    assert len(payload["commands"]) == 4
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_demo_preflight_rejects_symlinked_file_and_parent(tmp_path: Path) -> None:
    preparation = _preflight_input(tmp_path)
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    target = report_dir / "target.json"
    target.write_text("preserve", encoding="utf-8")
    destination = report_dir / "demo-preflight.json"
    destination.symlink_to(target)

    with pytest.raises(DemoPreparationError, match="must not be a symbolic link"):
        write_demo_preflight(preparation, destination)
    assert target.read_text(encoding="utf-8") == "preserve"

    destination.unlink()
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "linked-reports").symlink_to(outside, target_is_directory=True)
    with pytest.raises(DemoPreparationError, match="parent must not be a symbolic link"):
        write_demo_preflight(preparation, tmp_path / "linked-reports/preflight.json")
    assert not (outside / "preflight.json").exists()


def test_demo_preflight_rejects_group_writable_parent(tmp_path: Path) -> None:
    preparation = _preflight_input(tmp_path)
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o770)

    with pytest.raises(DemoPreparationError, match="owner-controlled"):
        write_demo_preflight(preparation, parent / "preflight.json")


def test_rejects_non_dbt_executable_and_nonempty_workspace(tmp_path: Path) -> None:
    source = _source(tmp_path)
    with pytest.raises(DemoPreparationError, match="only the dbt"):
        prepare_demo_projects(source, tmp_path / "workspace", dbt_executable="bash")

    workspace = tmp_path / "nonempty"
    workspace.mkdir()
    (workspace / "owned.txt").write_text("preserve", encoding="utf-8")
    with pytest.raises(DemoPreparationError, match="must be empty"):
        prepare_demo_projects(source, workspace)
    assert (workspace / "owned.txt").read_text(encoding="utf-8") == "preserve"


def test_rejects_copyable_source_symlink_before_dbt_runs(tmp_path: Path) -> None:
    source = _source(tmp_path)
    outside = tmp_path / "ignored-outside.sql"
    outside.write_text("{% macro hidden() %}uncommitted{% endmacro %}\n", encoding="utf-8")
    link = source / "macros/hidden.sql"
    link.parent.mkdir()
    link.symlink_to(outside)
    calls: list[tuple[str, ...]] = []

    def runner(command, *, cwd, env, timeout_seconds):
        del cwd, env, timeout_seconds
        calls.append(command)
        raise AssertionError("dbt must not run for a symlinked source project")

    with pytest.raises(DemoPreparationError, match="must not contain symbolic links"):
        prepare_demo_projects(source, tmp_path / "workspace", runner=runner)

    assert calls == []
    assert not (tmp_path / "workspace").exists()


def test_unexpected_proposed_failure_fails_closed(tmp_path: Path) -> None:
    def runner(command, *, cwd, env, timeout_seconds):
        del env, timeout_seconds
        (cwd / "target").mkdir(exist_ok=True)
        (cwd / "target/manifest.json").write_text(json.dumps(_manifest(cwd.name)), encoding="utf-8")
        code = 1 if cwd.name == "proposed" and command[1] == "build" else 0
        if command[1] == "build":
            _write_demo_run_results(cwd, proposed_failed=code == 1)
        return subprocess.CompletedProcess(command, code, stdout="network timeout", stderr="")

    with pytest.raises(DemoPreparationError, match="unexpected reason"):
        prepare_demo_projects(_source(tmp_path), tmp_path / "workspace", runner=runner)
