from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from lineageguard.remediation import (
    GeneratedArtifact,
    RemediationBundle,
    RemediationVerifier,
    VerificationError,
    VerificationStatus,
    snapshot_dbt_manifest,
)

_SECRET_SENTINEL = "credential-must-not-escape"


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "dbt_project"
    (project / "models").mkdir(parents=True)
    (project / "tests").mkdir()
    (project / "models" / "orders.sql").write_text(
        "select gross_amount from source\n", encoding="utf-8"
    )
    (project / "dbt_project.yml").write_text("name: demo\n", encoding="utf-8")
    return project


def _bundle() -> RemediationBundle:
    return RemediationBundle(
        change_id="change-one",
        artifacts=(
            GeneratedArtifact(
                path="models/orders.sql",
                content="select gross_amount, gross_amount as order_total from source\n",
                previous_content="select gross_amount from source\n",
                purpose="compatibility alias",
            ),
            GeneratedArtifact(
                path="tests/compat.sql",
                content="select 1 where false\n",
                previous_content=None,
                purpose="equality test",
            ),
        ),
    )


def _write_patched_manifest(workspace: Path, *, relation_name: str = "analytics.orders") -> None:
    manifest = {
        "metadata": {
            "adapter_type": "duckdb",
            "env": {"DBT_ENV_CUSTOM_ENV_SECRET": _SECRET_SENTINEL},
            "temporary_project": str(workspace),
        },
        "nodes": {
            "model.demo.orders": {
                "resource_type": "model",
                "relation_name": relation_name,
                "columns": {
                    "gross_amount": {
                        "name": "gross_amount",
                        "data_type": "decimal(12, 2)",
                        "constraints": [
                            {"type": "not_null", "expression": _SECRET_SENTINEL},
                            {"type": _SECRET_SENTINEL},
                            _SECRET_SENTINEL,
                        ],
                    },
                    "order_total": {
                        "name": "order_total",
                        "data_type": "decimal(12, 2)",
                    },
                },
                "config": {"password": _SECRET_SENTINEL, "path": str(workspace)},
                "compiled_code": (
                    "select 'credential-must-not-escape' as gross_amount, "
                    "'credential-must-not-escape' as order_total from raw.orders"
                ),
            }
        },
    }
    target = workspace / "target"
    target.mkdir(exist_ok=True)
    (target / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    _write_run_results(workspace)


def _write_run_results(
    workspace: Path,
    *,
    include_model: bool = True,
    include_compatibility_test: bool = True,
    compatibility_unique_id: str = "test.demo.compat",
) -> None:
    results = []
    if include_model:
        results.append({"unique_id": "model.demo.orders", "status": "success"})
    if include_compatibility_test:
        results.append({"unique_id": compatibility_unique_id, "status": "pass"})
    target = workspace / "target"
    target.mkdir(exist_ok=True)
    (target / "run_results.json").write_text(json.dumps({"results": results}), encoding="utf-8")


def test_green_plan_runs_only_fixed_dbt_commands_in_isolated_copy(tmp_path: Path) -> None:
    source = _project(tmp_path)
    resolved_dbt = tmp_path / "bin/dbt"
    calls: list[tuple[tuple[str, ...], Path, dict[str, str]]] = []

    def runner(command, *, cwd, env, timeout_seconds):
        calls.append((command, cwd, dict(env)))
        assert timeout_seconds == 10
        assert (cwd / "tests" / "compat.sql").is_file()
        assert (cwd / "models" / "orders.sql").read_text(encoding="utf-8").count("order_total") == 1
        if command[1] == "build":
            _write_patched_manifest(cwd)
        return subprocess.CompletedProcess(command, 0, stdout="PASS", stderr="")

    result = RemediationVerifier(
        dbt_executable=str(resolved_dbt), timeout_seconds=10, runner=runner
    ).verify(source, _bundle(), selector="orders+")
    assert result.status is VerificationStatus.TESTED
    assert [call[0][1] for call in calls] == ["seed", "parse", "build"]
    assert all(call[0][0] == str(resolved_dbt) for call in calls)
    assert all(command.command[0] == "dbt" for command in result.commands)
    assert all(str(resolved_dbt) not in command.command for command in result.commands)
    assert all("DATAHUB_GMS_TOKEN" not in call[2] for call in calls)
    assert not (source / "tests" / "compat.sql").exists()
    assert len(result.evidence_digest) == 64
    assert result.patched_manifest is not None
    assert result.run_results_digest is not None
    assert result.verified_node_ids == ("model.demo.orders", "test.demo.compat")
    assert len(result.patched_manifest.sha256) == 64
    assert _SECRET_SENTINEL not in result.patched_manifest.summary_json
    assert not any(str(call[1]) in result.patched_manifest.summary_json for call in calls)
    assert "gross_amount" in result.patched_manifest.summary_json
    summary = json.loads(result.patched_manifest.summary_json)
    node = next(iter(summary["nodes"].values()))
    constraints = node["columns"]["gross_amount"]["constraints"]
    assert [constraint["type"] for constraint in constraints] == ["not_null", "other", "other"]
    assert all(len(constraint["sha256"]) == 64 for constraint in constraints)


def test_manifest_snapshot_is_canonical_and_deterministic() -> None:
    first_manifest = {
        "metadata": {"adapter_type": "postgresql", "env": {"SECRET": _SECRET_SENTINEL}},
        "nodes": {
            "test.demo.ignored": {"resource_type": "test", "raw_code": _SECRET_SENTINEL},
            "model.demo.orders": {
                "resource_type": "model",
                "database": "warehouse",
                "schema": "analytics",
                "alias": "orders",
                "columns": {"id": {"name": "id", "data_type": "bigint"}},
                "compiled_sql": "select id from raw.orders",
            },
        },
    }
    reversed_manifest = {
        "nodes": dict(reversed(tuple(first_manifest["nodes"].items()))),
        "metadata": first_manifest["metadata"],
    }

    first = snapshot_dbt_manifest(first_manifest)
    second = snapshot_dbt_manifest(reversed_manifest)

    assert first == second
    assert len(first.sha256) == 64
    assert _SECRET_SENTINEL not in first.summary_json
    summary = json.loads(first.summary_json)
    assert summary["summary_version"] == 3
    assert summary["metadata"] == {"adapter_type": "postgres"}
    assert tuple(summary["nodes"]) == ("node.000000",)
    node = summary["nodes"]["node.000000"]
    assert node["database"] == "warehouse"
    assert "compiled_code" in node
    assert len(node["query_context_sha256"]) == 64


def test_manifest_snapshot_rejects_missing_or_untrustworthy_shapes(tmp_path: Path) -> None:
    with pytest.raises(VerificationError, match="missing or unreadable"):
        snapshot_dbt_manifest(tmp_path / "missing.json")

    invalid_json = tmp_path / "manifest.json"
    invalid_json.write_text("not-json", encoding="utf-8")
    with pytest.raises(VerificationError, match="not valid JSON"):
        snapshot_dbt_manifest(invalid_json)

    invalid_json.write_text("[]", encoding="utf-8")
    with pytest.raises(VerificationError, match="JSON object"):
        snapshot_dbt_manifest(invalid_json)

    invalid_sources = (
        {"nodes": []},
        {"nodes": {"model.demo.orders": []}},
        {"nodes": {"model.demo.orders": {"resource_type": "model", "columns": []}}},
        {
            "nodes": {
                "model.demo.orders": {
                    "resource_type": "model",
                    "columns": {1: {"name": "id"}},
                }
            }
        },
        {
            "nodes": {
                "model.demo.orders": {
                    "resource_type": "model",
                    "columns": {"id": []},
                }
            }
        },
        {"metadata": {"adapter_type": "not an adapter/path"}, "nodes": {}},
    )
    for source in invalid_sources:
        with pytest.raises(VerificationError):
            snapshot_dbt_manifest(source)


def test_failed_command_stops_plan_and_is_not_labelled_tested(tmp_path: Path) -> None:
    source = _project(tmp_path)
    commands: list[str] = []

    def runner(command, *, cwd, env, timeout_seconds):
        commands.append(command[1])
        return subprocess.CompletedProcess(
            command, 1 if command[1] == "parse" else 0, stdout="", stderr="compile failed"
        )

    result = RemediationVerifier(runner=runner).verify(source, _bundle(), selector="orders+")
    assert result.status is VerificationStatus.TEST_FAILED
    assert result.failure_reason == "parse exited 1"
    assert commands == ["seed", "parse"]
    assert result.patched_manifest is None


def test_drifted_input_fails_before_any_command(tmp_path: Path) -> None:
    source = _project(tmp_path)
    (source / "models" / "orders.sql").write_text("changed behind agent\n", encoding="utf-8")
    called = False

    def runner(command, *, cwd, env, timeout_seconds):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = RemediationVerifier(runner=runner).verify(source, _bundle(), selector="orders+")
    assert result.status is VerificationStatus.VERIFICATION_ERROR
    assert "drifted" in (result.failure_reason or "")
    assert called is False


def test_successful_commands_without_a_manifest_fail_closed(tmp_path: Path) -> None:
    source = _project(tmp_path)

    def runner(command, *, cwd, env, timeout_seconds):
        return subprocess.CompletedProcess(command, 0, stdout="PASS", stderr="")

    result = RemediationVerifier(runner=runner).verify(source, _bundle(), selector="orders+")

    assert result.status is VerificationStatus.VERIFICATION_ERROR
    assert result.failure_reason == "dbt run results are missing or invalid"
    assert result.patched_manifest is None


def test_invalid_manifest_after_successful_commands_fails_closed(tmp_path: Path) -> None:
    source = _project(tmp_path)

    def runner(command, *, cwd, env, timeout_seconds):
        if command[1] == "build":
            target = cwd / "target"
            target.mkdir(exist_ok=True)
            (target / "manifest.json").write_text("not-json", encoding="utf-8")
            _write_run_results(cwd)
        return subprocess.CompletedProcess(command, 0, stdout="PASS", stderr="")

    result = RemediationVerifier(runner=runner).verify(source, _bundle(), selector="orders+")

    assert result.status is VerificationStatus.VERIFICATION_ERROR
    assert result.failure_reason == "dbt manifest is not valid JSON"
    assert result.patched_manifest is None


def test_runner_error_and_temporary_path_manifest_are_not_exposed(tmp_path: Path) -> None:
    source = _project(tmp_path)

    def failing_runner(command, *, cwd, env, timeout_seconds):
        raise OSError("runner unavailable")

    failed = RemediationVerifier(runner=failing_runner).verify(
        source, _bundle(), selector="orders+"
    )
    assert failed.status is VerificationStatus.VERIFICATION_ERROR
    assert failed.failure_reason == "OSError"
    assert failed.patched_manifest is None

    def path_runner(command, *, cwd, env, timeout_seconds):
        if command[1] == "build":
            _write_patched_manifest(cwd, relation_name=str(cwd))
        return subprocess.CompletedProcess(command, 0, stdout="PASS", stderr="")

    unsafe = RemediationVerifier(runner=path_runner).verify(source, _bundle(), selector="orders+")
    assert unsafe.status is VerificationStatus.VERIFICATION_ERROR
    assert unsafe.failure_reason == "verified dbt manifest contains a temporary path"
    assert unsafe.patched_manifest is None


@pytest.mark.parametrize("selector", ["", "orders", "orders;rm", "orders $(id)", "../orders"])
def test_unsafe_selector_is_rejected(selector: str, tmp_path: Path) -> None:
    with pytest.raises(VerificationError, match="Unsafe dbt selector"):
        RemediationVerifier().verify(_project(tmp_path), _bundle(), selector=selector)


def test_green_build_for_wrong_model_selector_fails_closed(tmp_path: Path) -> None:
    source = _project(tmp_path)

    def runner(command, *, cwd, env, timeout_seconds):
        if command[1] == "build":
            _write_patched_manifest(cwd)
        return subprocess.CompletedProcess(command, 0, stdout="PASS", stderr="")

    result = RemediationVerifier(runner=runner).verify(
        source, _bundle(), selector="unrelated_model+"
    )

    assert result.status is VerificationStatus.VERIFICATION_ERROR
    assert result.failure_reason == "dbt did not verify the remediated model"
    assert result.patched_manifest is None


def test_green_build_without_generated_compatibility_test_fails_closed(tmp_path: Path) -> None:
    source = _project(tmp_path)

    def runner(command, *, cwd, env, timeout_seconds):
        if command[1] == "build":
            _write_patched_manifest(cwd)
            _write_run_results(cwd, include_compatibility_test=False)
        return subprocess.CompletedProcess(command, 0, stdout="PASS", stderr="")

    result = RemediationVerifier(runner=runner).verify(source, _bundle(), selector="orders+")

    assert result.status is VerificationStatus.VERIFICATION_ERROR
    assert result.failure_reason == "dbt did not verify the generated compatibility test"


def test_similarly_named_unrelated_test_cannot_substitute_for_generated_test(
    tmp_path: Path,
) -> None:
    source = _project(tmp_path)

    def runner(command, *, cwd, env, timeout_seconds):
        if command[1] == "build":
            _write_patched_manifest(cwd)
            _write_run_results(cwd, compatibility_unique_id="test.demo.incompatible")
        return subprocess.CompletedProcess(command, 0, stdout="PASS", stderr="")

    result = RemediationVerifier(runner=runner).verify(source, _bundle(), selector="orders+")

    assert result.status is VerificationStatus.VERIFICATION_ERROR
    assert result.failure_reason == "dbt did not verify the generated compatibility test"


def test_non_dbt_executable_is_rejected() -> None:
    with pytest.raises(VerificationError, match="only permits"):
        RemediationVerifier(dbt_executable="bash")


def test_verifier_rejects_symlinks_anywhere_in_project(tmp_path: Path) -> None:
    source = _project(tmp_path)
    target = tmp_path / "outside.sql"
    target.write_text("select 1\n", encoding="utf-8")
    (source / "models" / "linked.sql").symlink_to(target)

    with pytest.raises(VerificationError, match="must not contain symlinks"):
        RemediationVerifier().verify(source, _bundle(), selector="orders+")
