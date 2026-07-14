from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from lineageguard.cli import _asset_root, _is_passing, _source_commit_sha
from lineageguard.run_models import (
    GateDecision,
    RunResult,
    RunStatus,
    WritebackState,
)


def _result(
    decision: GateDecision,
    status: RunStatus,
    writeback: WritebackState,
) -> RunResult:
    return cast(
        RunResult,
        SimpleNamespace(
            final_decision=decision,
            status=status,
            writeback=SimpleNamespace(state=writeback),
        ),
    )


@pytest.mark.parametrize("decision", [GateDecision.PASS, GateDecision.PASS_WITH_REMEDIATION])
def test_complete_pass_is_accepted_without_required_writeback(decision: GateDecision) -> None:
    result = _result(decision, RunStatus.COMPLETE, WritebackState.NOT_REQUESTED)

    assert _is_passing(result, require_writeback=False) is True


def test_incomplete_run_can_never_be_reported_as_passing() -> None:
    result = _result(
        GateDecision.PASS_WITH_REMEDIATION,
        RunStatus.INCOMPLETE,
        WritebackState.VERIFIED,
    )

    assert _is_passing(result, require_writeback=True) is False


def test_demo_style_gate_requires_verified_writeback() -> None:
    pending = _result(
        GateDecision.PASS_WITH_REMEDIATION,
        RunStatus.COMPLETE,
        WritebackState.WRITEBACK_PENDING,
    )
    verified = _result(
        GateDecision.PASS_WITH_REMEDIATION,
        RunStatus.COMPLETE,
        WritebackState.VERIFIED,
    )

    assert _is_passing(pending, require_writeback=True) is False
    assert _is_passing(verified, require_writeback=True) is True


def test_asset_root_prefers_checkout_then_wheel_bundle(tmp_path) -> None:
    source = tmp_path / "checkout"
    package = tmp_path / "lineageguard"

    assert _asset_root(source, package) == package / "bundled"
    (source / "demo/acme_dbt").mkdir(parents=True)
    assert _asset_root(source, package) == source


def _git(cwd: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git is required for commit provenance tests")
    return subprocess.run(  # noqa: S603 - isolated fixture repository; no shell
        (executable, "-C", str(cwd), *arguments),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )


def _provenance_repository(
    tmp_path: Path,
) -> tuple[Path, tuple[str, str], str]:
    repository = tmp_path / "repository"
    project = repository / "project"
    (project / "models").mkdir(parents=True)
    (project / "tests").mkdir()
    (repository / ".gitignore").write_text(
        "project/target/\nproject/logs/\nproject/*.duckdb\n"
        "project/ignored-inputs/\nproject/ignored-source.sql\n",
        encoding="utf-8",
    )
    (project / "models/orders.sql").write_text("select 1 as order_id\n", encoding="utf-8")
    (project / "models/schema.yml").write_text("version: 2\n", encoding="utf-8")

    _git(repository, "init", "--quiet")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=LineageGuard tests",
        "-c",
        "user.email=lineageguard@example.invalid",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "core.hooksPath=/dev/null",
        "commit",
        "--quiet",
        "-m",
        "provenance fixture",
    )
    head = _git(repository, "rev-parse", "HEAD").stdout.strip()
    return project, ("models/orders.sql", "models/schema.yml"), head


def test_source_commit_accepts_clean_inputs_before_generated_test_exists(tmp_path: Path) -> None:
    project, source_paths, head = _provenance_repository(tmp_path)
    generated_test = "tests/lineageguard_orders_compatibility.sql"

    assert not (project / generated_test).exists()
    assert (
        _source_commit_sha(
            project,
            source_paths=source_paths,
            generated_paths=(generated_test,),
        )
        == head
    )


def test_source_commit_accepts_project_at_repository_root(tmp_path: Path) -> None:
    project, source_paths, head = _provenance_repository(tmp_path)
    repository = project.parent

    assert (
        _source_commit_sha(
            repository,
            source_paths=tuple(f"project/{path}" for path in source_paths),
            generated_paths=("project/tests/lineageguard_orders_compatibility.sql",),
        )
        == head
    )


def test_source_commit_allows_only_ignored_outputs_excluded_from_copy(tmp_path: Path) -> None:
    project, source_paths, head = _provenance_repository(tmp_path)
    (project / "target").mkdir()
    (project / "target/manifest.json").write_text("{}\n", encoding="utf-8")
    (project / "logs").mkdir()
    (project / "logs/dbt.log").write_text("local output\n", encoding="utf-8")
    (project / "local.duckdb").write_bytes(b"local output")
    outside = tmp_path / "outside-output"
    outside.write_text("not copied\n", encoding="utf-8")
    (project / "target/ignored-link").symlink_to(outside)

    assert (
        _source_commit_sha(
            project,
            source_paths=source_paths,
            generated_paths=("tests/lineageguard_orders_compatibility.sql",),
        )
        == head
    )


def test_source_commit_rejects_ignored_input_that_verifier_would_copy(tmp_path: Path) -> None:
    project, source_paths, _head = _provenance_repository(tmp_path)
    ignored = project / "ignored-inputs/macro.sql"
    ignored.parent.mkdir()
    ignored.write_text("{% macro hidden() %}select 2{% endmacro %}\n", encoding="utf-8")

    assert (
        _source_commit_sha(
            project,
            source_paths=source_paths,
            generated_paths=("tests/lineageguard_orders_compatibility.sql",),
        )
        == "WORKTREE"
    )


def test_source_commit_rejects_dirty_tracked_input(tmp_path: Path) -> None:
    project, source_paths, _head = _provenance_repository(tmp_path)
    (project / source_paths[0]).write_text("select 2 as order_id\n", encoding="utf-8")

    assert _source_commit_sha(project, source_paths=source_paths) == "WORKTREE"


@pytest.mark.parametrize("index_flag", ["--assume-unchanged", "--skip-worktree"])
def test_source_commit_rejects_index_flags_that_hide_dirty_bytes(
    tmp_path: Path, index_flag: str
) -> None:
    project, source_paths, _head = _provenance_repository(tmp_path)
    repository = project.parent
    hidden = f"project/{source_paths[0]}"
    _git(repository, "update-index", index_flag, hidden)
    (project / source_paths[0]).write_text("select 999 as hidden_change\n", encoding="utf-8")

    assert _git(repository, "status", "--porcelain=v1").stdout == ""
    assert _source_commit_sha(project, source_paths=source_paths) == "WORKTREE"


def test_source_commit_rejects_source_path_escape(tmp_path: Path) -> None:
    project, source_paths, _head = _provenance_repository(tmp_path)

    assert (
        _source_commit_sha(
            project,
            source_paths=("../outside.sql", source_paths[1]),
        )
        == "WORKTREE"
    )


def test_source_commit_rejects_generated_path_escape(tmp_path: Path) -> None:
    project, source_paths, _head = _provenance_repository(tmp_path)

    assert (
        _source_commit_sha(
            project,
            source_paths=source_paths,
            generated_paths=("../outside.sql",),
        )
        == "WORKTREE"
    )


def test_source_commit_fails_closed_for_malformed_source_path(tmp_path: Path) -> None:
    project, source_paths, _head = _provenance_repository(tmp_path)

    assert (
        _source_commit_sha(
            project,
            source_paths=("models/orders\0.sql", source_paths[1]),
        )
        == "WORKTREE"
    )


@pytest.mark.parametrize(
    ("source_paths", "generated_paths"),
    [
        ((), ()),
        (("models/orders.sql",), ("models/orders.sql",)),
    ],
)
def test_source_commit_rejects_empty_or_duplicate_path_sets(
    tmp_path: Path,
    source_paths: tuple[str, ...],
    generated_paths: tuple[str, ...],
) -> None:
    project, _paths, _head = _provenance_repository(tmp_path)

    assert (
        _source_commit_sha(
            project,
            source_paths=source_paths,
            generated_paths=generated_paths,
        )
        == "WORKTREE"
    )


def test_source_commit_fails_closed_without_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, source_paths, _head = _provenance_repository(tmp_path)
    monkeypatch.setattr("lineageguard.cli.shutil.which", lambda _name: None)

    assert _source_commit_sha(project, source_paths=source_paths) == "WORKTREE"


def test_source_commit_rejects_non_directory_or_non_repository_project(tmp_path: Path) -> None:
    project_file = tmp_path / "project-file"
    project_file.write_text("not a project\n", encoding="utf-8")
    plain_directory = tmp_path / "plain-project"
    plain_directory.mkdir()
    (plain_directory / "model.sql").write_text("select 1\n", encoding="utf-8")

    assert _source_commit_sha(project_file, source_paths=("model.sql",)) == "WORKTREE"
    assert _source_commit_sha(plain_directory, source_paths=("model.sql",)) == "WORKTREE"


def test_source_commit_rejects_directory_or_ignored_source_file(tmp_path: Path) -> None:
    project, source_paths, _head = _provenance_repository(tmp_path)
    ignored = project / "ignored-source.sql"
    ignored.write_text("select 2\n", encoding="utf-8")

    assert _source_commit_sha(project, source_paths=("models",)) == "WORKTREE"
    assert _source_commit_sha(project, source_paths=(*source_paths, ignored.name)) == "WORKTREE"


def test_source_commit_rejects_symlinked_generated_destination(tmp_path: Path) -> None:
    project, source_paths, _head = _provenance_repository(tmp_path)
    outside = tmp_path / "outside.sql"
    outside.write_text("select 2\n", encoding="utf-8")
    generated = project / "tests/generated.sql"
    generated.symlink_to(outside)

    assert (
        _source_commit_sha(
            project,
            source_paths=source_paths,
            generated_paths=("tests/generated.sql",),
        )
        == "WORKTREE"
    )


def test_source_commit_rejects_tracked_symlink_to_ignored_outside_bytes(tmp_path: Path) -> None:
    project, source_paths, _head = _provenance_repository(tmp_path)
    repository = project.parent
    ignore = repository / ".gitignore"
    ignore.write_text(ignore.read_text(encoding="utf-8") + "outside-input.sql\n", encoding="utf-8")
    outside = repository / "outside-input.sql"
    outside.write_text("{% macro hidden() %}uncommitted{% endmacro %}\n", encoding="utf-8")
    link = project / "macros/hidden.sql"
    link.parent.mkdir()
    link.symlink_to(outside)
    _git(repository, "add", ".gitignore", "project/macros/hidden.sql")
    _git(
        repository,
        "-c",
        "user.name=LineageGuard tests",
        "-c",
        "user.email=lineageguard@example.invalid",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "core.hooksPath=/dev/null",
        "commit",
        "--quiet",
        "-m",
        "tracked project symlink",
    )

    assert _git(repository, "status", "--porcelain=v1").stdout == ""
    assert _source_commit_sha(project, source_paths=source_paths) == "WORKTREE"


def test_source_commit_rejects_generated_destination_through_escaped_parent(
    tmp_path: Path,
) -> None:
    project, source_paths, _head = _provenance_repository(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (project / "generated").symlink_to(outside, target_is_directory=True)

    assert (
        _source_commit_sha(
            project,
            source_paths=source_paths,
            generated_paths=("generated/nested/test.sql",),
        )
        == "WORKTREE"
    )
