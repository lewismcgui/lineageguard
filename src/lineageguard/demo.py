"""Prepare the real dbt/DuckDB before-and-after scenario used by the local demo."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol


class DemoPreparationError(RuntimeError):
    """The checked-in demo did not establish its promised baseline or breakage."""


@dataclass(frozen=True, slots=True)
class DemoCommand:
    """Secret-free proof for one fixed dbt preparation command."""

    project: str
    command: tuple[str, ...]
    exit_code: int
    expected_exit: str
    duration_ms: int
    output_digest: str
    output_tail: str
    run_results_digest: str | None = None


@dataclass(frozen=True, slots=True)
class DemoPreparation:
    """Temporary projects and retained manifest evidence for the agent run."""

    baseline_project: Path
    proposed_project: Path
    before_manifest: Path
    after_manifest: Path
    commands: tuple[DemoCommand, ...]
    evidence_digest: str


class CommandRunner(Protocol):
    def __call__(
        self,
        command: tuple[str, ...],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
    ) -> subprocess.CompletedProcess[str]: ...


def _runner(
    command: tuple[str, ...],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - command is built from a fixed dbt allowlist
        command,
        cwd=cwd,
        env=dict(env),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
        shell=False,
    )


def _safe_environment() -> dict[str, str]:
    allowed = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "VIRTUAL_ENV")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment["DBT_SEND_ANONYMOUS_USAGE_STATS"] = "false"
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _private_demo_destination(path: Path) -> Path:
    """Validate a private output path without resolving through symlinks."""

    expanded = path.expanduser()
    if ".." in expanded.parts:
        raise DemoPreparationError("Demo preflight path must not contain parent traversal")
    anchor = None if expanded.is_absolute() else Path.cwd()
    destination = expanded if anchor is None else anchor / expanded
    chain = tuple(reversed((destination.parent, *destination.parent.parents)))
    if anchor is not None:
        try:
            chain = chain[chain.index(anchor) :]
        except ValueError as exc:
            raise DemoPreparationError(
                "Demo preflight path must stay below the project root"
            ) from exc

    current_uid = os.getuid() if hasattr(os, "getuid") else None
    for directory in chain:
        try:
            metadata = directory.lstat()
        except FileNotFoundError:
            try:
                directory.mkdir(mode=0o700)
                metadata = directory.lstat()
            except FileExistsError:
                metadata = directory.lstat()
            except OSError as exc:
                raise DemoPreparationError("Demo preflight directory is unavailable") from exc
        except OSError as exc:
            raise DemoPreparationError("Demo preflight directory is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise DemoPreparationError("Demo preflight parent must not be a symbolic link")
        if not stat.S_ISDIR(metadata.st_mode):
            raise DemoPreparationError("Demo preflight parent must be a directory")
        if current_uid is None:
            continue
        mode = stat.S_IMODE(metadata.st_mode)
        controlled = metadata.st_uid == current_uid and not mode & 0o022
        safe_system_ancestor = (
            anchor is None
            and metadata.st_uid == 0
            and (not mode & 0o022 or bool(mode & stat.S_ISVTX))
        )
        if not controlled and not safe_system_ancestor:
            raise DemoPreparationError("Demo preflight parent must be owner-controlled")

    parent_metadata = destination.parent.lstat()
    if current_uid is not None and (
        parent_metadata.st_uid != current_uid or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise DemoPreparationError("Demo preflight file parent must be owner-controlled")
    if destination.is_symlink():
        raise DemoPreparationError("Demo preflight path must not be a symbolic link")
    if destination.exists():
        metadata = destination.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise DemoPreparationError("Demo preflight path must be a regular file")
        if current_uid is not None and metadata.st_uid != current_uid:
            raise DemoPreparationError("Demo preflight file must be owned by the current user")
    return destination


def _dbt_command(executable: str, action: str) -> tuple[str, ...]:
    if action not in {"build", "compile"}:
        raise DemoPreparationError(f"Unsupported demo dbt action: {action}")
    return (
        executable,
        action,
        "--project-dir",
        ".",
        "--profiles-dir",
        ".",
        "--no-use-colors",
    )


def _excluded_from_demo_copy(path: Path) -> bool:
    return any(
        part in {".git", "__pycache__", "logs", "target"} or part.endswith(".duckdb")
        for part in path.parts
    )


def _has_copyable_symlink(project: Path) -> bool:
    return any(
        path.is_symlink() and not _excluded_from_demo_copy(path.relative_to(project))
        for path in project.rglob("*")
    )


def _run_results(path: Path) -> tuple[bytes, tuple[tuple[str, str, str], ...]]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DemoPreparationError("dbt run results are missing or invalid") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise DemoPreparationError("dbt run results are missing or invalid")
    statuses: list[tuple[str, str, str]] = []
    for item in payload["results"]:
        if not isinstance(item, dict):
            continue
        unique_id = item.get("unique_id")
        status = item.get("status")
        if isinstance(unique_id, str) and isinstance(status, str):
            message = item.get("message")
            statuses.append(
                (
                    unique_id,
                    status.casefold(),
                    message if isinstance(message, str) else "",
                )
            )
    return raw, tuple(statuses)


def _validate_build_results(project: Path, *, expected_success: bool) -> str:
    raw, statuses = _run_results(project / "target/run_results.json")
    if expected_success:
        if not statuses or any(status in {"error", "fail", "failed"} for _, status, _ in statuses):
            raise DemoPreparationError("The baseline dbt run results are not fully successful")
    else:
        staging_ok = any(
            unique_id.startswith("model.")
            and unique_id.endswith(".stg_orders")
            and status == "success"
            for unique_id, status, _ in statuses
        )
        contract_test_failed = any(
            unique_id.endswith(".assert_completed_orders_have_positive_totals")
            and status in {"error", "fail", "failed"}
            and "order_total" in message.casefold()
            for unique_id, status, message in statuses
        )
        downstream_blocked = any(
            unique_id.startswith("model.")
            and unique_id.endswith(".fct_daily_revenue")
            and status in {"error", "fail", "failed", "skipped"}
            for unique_id, status, _ in statuses
        )
        if not staging_ok or not contract_test_failed or not downstream_blocked:
            raise DemoPreparationError(
                "The proposed build did not prove the expected downstream interface break"
            )
    return hashlib.sha256(raw).hexdigest()


def _run(
    project: Path,
    command: tuple[str, ...],
    *,
    expected_success: bool,
    runner: CommandRunner,
    timeout_seconds: float,
) -> DemoCommand:
    recorded_command = (Path(command[0]).name, *command[1:])
    started = time.monotonic()
    try:
        completed = runner(
            command,
            cwd=project,
            env=_safe_environment(),
            timeout_seconds=timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DemoPreparationError(
            f"Demo command could not run: {command[1]} ({type(exc).__name__})"
        ) from exc
    output = f"{completed.stdout}\n{completed.stderr}".strip()
    succeeded = completed.returncode == 0
    if succeeded is not expected_success:
        expectation = "succeed" if expected_success else "fail on the unremediated PR"
        raise DemoPreparationError(
            f"Expected {project.name} dbt {command[1]} to {expectation}; "
            f"exit={completed.returncode}"
        )
    if not expected_success and "order_total" not in output.casefold():
        raise DemoPreparationError(
            "The proposed dbt build failed for an unexpected reason, not the renamed column"
        )
    run_results_digest = (
        _validate_build_results(project, expected_success=expected_success)
        if command[1] == "build"
        else None
    )
    return DemoCommand(
        project=project.name,
        command=recorded_command,
        exit_code=completed.returncode,
        expected_exit="zero" if expected_success else "nonzero_breaking_pr",
        duration_ms=round((time.monotonic() - started) * 1000),
        output_digest=hashlib.sha256(output.encode()).hexdigest(),
        output_tail=output[-4_000:],
        run_results_digest=run_results_digest,
    )


def prepare_demo_projects(
    source_project: Path,
    workspace: Path,
    *,
    dbt_executable: str = "dbt",
    timeout_seconds: float = 120.0,
    runner: CommandRunner = _runner,
) -> DemoPreparation:
    """Build a green baseline and prove the checked-in proposed rename is broken."""

    executable = Path(dbt_executable)
    if executable.name != "dbt":
        raise DemoPreparationError("The demo permits only the dbt executable")
    if not 1 <= timeout_seconds <= 600:
        raise DemoPreparationError("timeout_seconds must be between 1 and 600")
    if source_project.is_symlink():
        raise DemoPreparationError("Demo source project must not be a symbolic link")
    source = source_project.resolve(strict=True)
    if _has_copyable_symlink(source):
        raise DemoPreparationError("Demo source project must not contain symbolic links")
    destination = workspace.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise DemoPreparationError("Demo workspace must be empty")
    destination.mkdir(parents=True, exist_ok=True)
    baseline = shutil.copytree(
        source,
        destination / "baseline",
        ignore=shutil.ignore_patterns("target", "logs", "*.duckdb", ".git", "__pycache__"),
    )
    proposed = shutil.copytree(
        source,
        destination / "proposed",
        ignore=shutil.ignore_patterns("target", "logs", "*.duckdb", ".git", "__pycache__"),
    )
    overlay = proposed / "scenario" / "proposed" / "models"
    if not overlay.is_dir():
        raise DemoPreparationError("Proposed dbt scenario overlay is missing")
    shutil.copytree(overlay, proposed / "models", dirs_exist_ok=True)

    commands = [
        _run(
            baseline,
            _dbt_command(dbt_executable, "build"),
            expected_success=True,
            runner=runner,
            timeout_seconds=timeout_seconds,
        ),
        _run(
            proposed,
            _dbt_command(dbt_executable, "compile"),
            expected_success=True,
            runner=runner,
            timeout_seconds=timeout_seconds,
        ),
        _run(
            proposed,
            _dbt_command(dbt_executable, "build"),
            expected_success=False,
            runner=runner,
            timeout_seconds=timeout_seconds,
        ),
        _run(
            proposed,
            _dbt_command(dbt_executable, "compile"),
            expected_success=True,
            runner=runner,
            timeout_seconds=timeout_seconds,
        ),
    ]
    before_source = baseline / "target" / "manifest.json"
    after_source = proposed / "target" / "manifest.json"
    if not before_source.is_file() or not after_source.is_file():
        raise DemoPreparationError("dbt did not produce both required manifests")
    before_manifest = destination / "baseline-manifest.json"
    after_manifest = destination / "proposed-manifest.json"
    shutil.copy2(before_source, before_manifest)
    shutil.copy2(after_source, after_manifest)
    evidence_digest = _digest(
        {
            "before_sha256": hashlib.sha256(before_manifest.read_bytes()).hexdigest(),
            "after_sha256": hashlib.sha256(after_manifest.read_bytes()).hexdigest(),
            "commands": [asdict(command) for command in commands],
        }
    )
    return DemoPreparation(
        baseline_project=baseline,
        proposed_project=proposed,
        before_manifest=before_manifest,
        after_manifest=after_manifest,
        commands=tuple(commands),
        evidence_digest=evidence_digest,
    )


def write_demo_preflight(preparation: DemoPreparation, destination: Path) -> None:
    """Retain preparation proof beside the final agent report."""

    payload = {
        "schema_version": "1.0",
        "evidence_digest": preparation.evidence_digest,
        "commands": [asdict(command) for command in preparation.commands],
        "before_manifest_sha256": hashlib.sha256(
            preparation.before_manifest.read_bytes()
        ).hexdigest(),
        "after_manifest_sha256": hashlib.sha256(
            preparation.after_manifest.read_bytes()
        ).hexdigest(),
    }
    destination = _private_demo_destination(destination)
    encoded = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if destination.is_symlink():
            raise DemoPreparationError("Demo preflight path must not be a symbolic link")
        os.replace(temporary, destination)
        temporary = None
        directory_descriptor = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except DemoPreparationError:
        raise
    except OSError as exc:
        raise DemoPreparationError("Demo preflight file could not be stored safely") from exc
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    metadata = destination.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise DemoPreparationError("Demo preflight file is not private")


__all__ = [
    "DemoCommand",
    "DemoPreparation",
    "DemoPreparationError",
    "prepare_demo_projects",
    "write_demo_preflight",
]
