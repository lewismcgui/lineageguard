"""Command-line entry point for LineageGuard."""

from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from lineageguard import __version__
from lineageguard.agent import AgentInputError, AnalysisRequest, LineageGuardAgent
from lineageguard.config import Settings
from lineageguard.datahub.context import DataHubContextCollector
from lineageguard.datahub.graphql import DataHubGraphQLClient
from lineageguard.datahub.mcp_client import DataHubMCPClient, MCPClientError
from lineageguard.datahub.writeback import (
    DOCUMENT_PROJECTION_READBACK_ATTEMPTS,
    DOCUMENT_PROJECTION_RETRY_DELAY_SECONDS,
    DataHubWriteback,
)
from lineageguard.demo import DemoPreparationError, prepare_demo_projects, write_demo_preflight
from lineageguard.remediation import RemediationVerifier
from lineageguard.reporting import ReportPaths, write_reports
from lineageguard.risk import RiskEngine, RiskPolicyError
from lineageguard.run_models import (
    AnalyzedInputState,
    GateDecision,
    RunResult,
    RunStatus,
    WritebackState,
)

app = typer.Typer(
    name="lineageguard",
    help="Prevent breaking data changes with DataHub-grounded evidence and tested fixes.",
    no_args_is_help=True,
)
console = Console()


def _asset_root(source_root: Path, package_root: Path) -> Path:
    """Prefer checkout assets, then fall back to wheel-bundled demo resources."""

    return source_root if (source_root / "demo/acme_dbt").is_dir() else package_root / "bundled"


REPOSITORY_ROOT = _asset_root(Path(__file__).resolve().parents[2], Path(__file__).resolve().parent)


@app.callback()
def main() -> None:
    """LineageGuard PR Agent."""


@app.command()
def version() -> None:
    """Print the installed LineageGuard version."""
    console.print(__version__)


def _run_git(git: str, cwd: Path, *arguments: str) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(  # noqa: S603 - fixed executable; arguments are never a shell command
            (git, "-C", str(cwd), *arguments),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            shell=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _excluded_from_verification_copy(path: Path) -> bool:
    """Match paths the isolated dbt project copy deliberately omits."""

    return any(
        part in {".git", "logs", "target"} or part.endswith(".duckdb") for part in path.parts
    )


def _has_copyable_symlink(project: Path) -> bool:
    """Return whether the dbt copier could dereference a project symlink."""

    return any(
        path.is_symlink() and not _excluded_from_verification_copy(path.relative_to(project))
        for path in project.rglob("*")
    )


def _source_commit_sha(
    project: Path,
    *,
    source_paths: Sequence[str],
    generated_paths: Sequence[str] = (),
) -> str:
    """Return HEAD only when it honestly identifies the copied source tree.

    Manifest bytes are bound separately by their report hashes. Output paths
    may be absent, but must remain inside the project. Git-ignored files that
    the verifier would copy make source provenance unverifiable and therefore
    fail closed to ``WORKTREE``.
    """

    if not source_paths or len((*source_paths, *generated_paths)) != len(
        set((*source_paths, *generated_paths))
    ):
        return "WORKTREE"
    git = shutil.which("git")
    if git is None:
        return "WORKTREE"
    try:
        if project.is_symlink():
            return "WORKTREE"
        resolved_project = project.resolve(strict=True)
        if not resolved_project.is_dir() or _has_copyable_symlink(resolved_project):
            return "WORKTREE"
        resolved_sources: list[Path] = []
        for project_path in source_paths:
            relative = Path(project_path)
            if relative.is_absolute() or ".." in relative.parts:
                return "WORKTREE"
            resolved = (resolved_project / relative).resolve(strict=True)
            if not resolved.is_relative_to(resolved_project) or not resolved.is_file():
                return "WORKTREE"
            resolved_sources.append(resolved)
        for project_path in generated_paths:
            relative = Path(project_path)
            if relative.is_absolute() or ".." in relative.parts:
                return "WORKTREE"
            candidate = resolved_project / relative
            if candidate.is_symlink():
                return "WORKTREE"
            existing = candidate if candidate.exists() else candidate.parent
            while not existing.exists() and existing != resolved_project:
                existing = existing.parent
            resolved_parent = existing.resolve(strict=True)
            if not resolved_parent.is_relative_to(resolved_project):
                return "WORKTREE"
    except (OSError, RuntimeError, ValueError):
        return "WORKTREE"

    top_level = _run_git(git, resolved_project, "rev-parse", "--show-toplevel")
    if top_level is None or top_level.returncode != 0:
        return "WORKTREE"
    top_level_lines = top_level.stdout.splitlines()
    if len(top_level_lines) != 1:
        return "WORKTREE"
    try:
        repository = Path(top_level_lines[0]).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return "WORKTREE"
    if not repository.is_dir() or not resolved_project.is_relative_to(repository):
        return "WORKTREE"
    if any(not path.is_relative_to(repository) for path in resolved_sources):
        return "WORKTREE"

    head = _run_git(git, repository, "rev-parse", "--verify", "HEAD^{commit}")
    if head is None or head.returncode != 0:
        return "WORKTREE"
    value = head.stdout.strip()
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None:
        return "WORKTREE"

    index_flags = _run_git(git, repository, "ls-files", "-v", "-z")
    if index_flags is None or index_flags.returncode != 0:
        return "WORKTREE"
    index_entries = [entry for entry in index_flags.stdout.split("\0") if entry]
    if not index_entries or any(not entry.startswith("H ") for entry in index_entries):
        # Lower-case tags denote assume-unchanged entries; ``S`` denotes
        # skip-worktree. Either can hide bytes that dbt would execute from the
        # normal status and diff checks below, so reject all nonstandard flags.
        return "WORKTREE"

    status = _run_git(
        git,
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=normal",
        "--ignore-submodules=none",
    )
    if status is None or status.returncode != 0 or status.stdout:
        return "WORKTREE"

    literal_pathspecs = tuple(
        f":(top,literal){path.relative_to(repository).as_posix()}" for path in resolved_sources
    )
    tracked = _run_git(
        git,
        repository,
        "ls-files",
        "--error-unmatch",
        "--stage",
        "--",
        *literal_pathspecs,
    )
    if tracked is None or tracked.returncode != 0 or not tracked.stdout:
        return "WORKTREE"

    unchanged = _run_git(
        git,
        repository,
        "diff",
        "--no-ext-diff",
        "--quiet",
        value,
        "--",
        *literal_pathspecs,
    )
    if unchanged is None or unchanged.returncode != 0:
        return "WORKTREE"

    project_pathspec = (
        f":(top,literal){resolved_project.relative_to(repository).as_posix()}"
        if resolved_project != repository
        else ":(top)"
    )
    ignored = _run_git(
        git,
        repository,
        "ls-files",
        "-z",
        "--others",
        "--ignored",
        "--exclude-standard",
        "--",
        project_pathspec,
    )
    if ignored is None or ignored.returncode != 0:
        return "WORKTREE"
    for raw_path in ignored.stdout.split("\0"):
        if not raw_path:
            continue
        try:
            relative_to_project = (repository / raw_path).relative_to(resolved_project)
        except ValueError:
            return "WORKTREE"
        if not _excluded_from_verification_copy(relative_to_project):
            return "WORKTREE"
    return value


async def run_analysis(
    request: AnalysisRequest,
    *,
    settings: Settings,
    policy_path: Path,
    output_root: Path,
    writeback: bool,
) -> tuple[RunResult, ReportPaths]:
    """Connect to the official MCP server and retain all local run artifacts."""

    executable = shutil.which("dbt") or "dbt"
    async with DataHubMCPClient(settings) as mcp:
        collector = DataHubContextCollector(mcp, DataHubGraphQLClient(settings))
        agent = LineageGuardAgent(
            collector=collector,
            risk_engine=RiskEngine.from_policy_file(policy_path),
            verifier=RemediationVerifier(dbt_executable=executable),
            writer=(
                DataHubWriteback(
                    mcp,
                    document_index_path=output_root / "document-index",
                    readback_attempts=DOCUMENT_PROJECTION_READBACK_ATTEMPTS,
                    readback_retry_delay_seconds=DOCUMENT_PROJECTION_RETRY_DELAY_SECONDS,
                )
                if writeback
                else None
            ),
            trace_provider=lambda: mcp.trace,
        )
        result = await agent.analyze(request, writeback=writeback)
    return result, write_reports(result, output_root)


def _print_result(result: RunResult, paths: ReportPaths) -> None:
    residual = result.remediation.residual_risk
    table = Table(title=f"LineageGuard {result.run_id}", show_header=False)
    table.add_column("Field", style="dim")
    table.add_column("Value")
    table.add_row("Run status", result.status.value)
    table.add_row("Decision", result.final_decision.value)
    table.add_row("Initial risk", f"{result.initial_risk.score}/100")
    table.add_row("Residual risk", f"{residual.score}/100" if residual else "not established")
    table.add_row("Remediation", result.remediation.status.value)
    table.add_row("DataHub writeback", result.writeback.state.value)
    table.add_row("Report", str(paths.html))
    console.print(table)


def _is_passing(result: RunResult, *, require_writeback: bool) -> bool:
    decision_passes = result.final_decision in {
        GateDecision.PASS,
        GateDecision.PASS_WITH_REMEDIATION,
    }
    writeback_passes = not require_writeback or result.writeback.state is WritebackState.VERIFIED
    return decision_passes and result.status is RunStatus.COMPLETE and writeback_passes


@app.command()
def analyze(
    before_manifest: Annotated[
        Path,
        typer.Option("--before-manifest", exists=True, file_okay=True, dir_okay=False),
    ],
    after_manifest: Annotated[
        Path,
        typer.Option("--after-manifest", exists=True, file_okay=True, dir_okay=False),
    ],
    project_dir: Annotated[
        Path,
        typer.Option("--project-dir", exists=True, file_okay=False, dir_okay=True),
    ],
    model_path: Annotated[str, typer.Option("--model-path")],
    schema_path: Annotated[str, typer.Option("--schema-path")],
    test_path: Annotated[str, typer.Option("--test-path")],
    model_name: Annotated[str, typer.Option("--model-name")],
    selector: Annotated[str, typer.Option("--selector")],
    policy: Annotated[Path, typer.Option("--policy")] = REPOSITORY_ROOT / "config/risk-policy.yaml",
    output: Annotated[Path, typer.Option("--output")] = Path(".lineageguard/runs"),
    dialect: Annotated[str, typer.Option("--dialect")] = "duckdb",
    writeback: Annotated[
        bool,
        typer.Option(
            "--writeback/--no-writeback",
            help="Persist and read back the decision in the connected local DataHub.",
        ),
    ] = False,
    fail_on_nonpass: Annotated[
        bool,
        typer.Option(
            "--fail-on-nonpass/--no-fail-on-nonpass",
            help="Exit 2 unless the final decision is PASS or PASS_WITH_REMEDIATION.",
        ),
    ] = False,
) -> None:
    """Analyze two dbt manifests using live DataHub MCP context."""

    resolved_project = project_dir.resolve()
    request = AnalysisRequest(
        before_manifest=before_manifest,
        after_manifest=after_manifest,
        project_dir=resolved_project,
        model_path=model_path,
        schema_path=schema_path,
        test_path=test_path,
        model_name=model_name,
        selector=selector,
        source_commit_sha=_source_commit_sha(
            resolved_project,
            source_paths=(model_path, schema_path),
            generated_paths=(test_path,),
        ),
        analyzed_input_state=AnalyzedInputState.SUPPLIED_MANIFESTS,
        dialect=dialect,
    )
    settings = Settings(project_root=Path.cwd(), mcp_mutations=writeback)
    try:
        result, paths = asyncio.run(
            run_analysis(
                request,
                settings=settings,
                policy_path=policy,
                output_root=output,
                writeback=writeback,
            )
        )
    except (AgentInputError, MCPClientError, RiskPolicyError, ValueError) as exc:
        console.print(f"[red]Analysis failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    _print_result(result, paths)
    passing = _is_passing(result, require_writeback=writeback)
    if fail_on_nonpass and not passing:
        raise typer.Exit(code=2)


@app.command()
def demo(
    output: Annotated[Path, typer.Option("--output")] = Path(".lineageguard/runs"),
    writeback: Annotated[
        bool,
        typer.Option(
            "--writeback/--no-writeback",
            help="Persist and read back the synthetic decision through DataHub MCP.",
        ),
    ] = False,
    seed_datahub: Annotated[
        bool,
        typer.Option(
            "--seed-datahub/--no-seed-datahub",
            help="Idempotently seed the synthetic Acme graph before analysis.",
        ),
    ] = False,
) -> None:
    """Run the checked-in Acme scenario against a live local DataHub."""

    settings = Settings(
        project_root=Path.cwd().resolve(),
        mcp_mutations=writeback,
    )
    executable = shutil.which("dbt") or "dbt"
    demo_source = REPOSITORY_ROOT / "demo/acme_dbt"
    source_commit_sha = _source_commit_sha(
        demo_source,
        source_paths=(
            "dbt_project.yml",
            "profiles.yml",
            "models/staging/stg_orders.sql",
            "models/staging/schema.yml",
            "scenario/proposed/models/staging/stg_orders.sql",
            "scenario/proposed/models/staging/schema.yml",
        ),
        generated_paths=("tests/lineageguard_order_total_matches_gross_amount.sql",),
    )
    try:
        with tempfile.TemporaryDirectory(prefix="lineageguard-demo-") as temporary:
            preparation = prepare_demo_projects(
                demo_source,
                Path(temporary),
                dbt_executable=executable,
            )
            write_demo_preflight(preparation, output / "demo-preflight-latest.json")
            if seed_datahub:
                try:
                    from lineageguard.datahub.demo_seed import seed_demo

                    proposal_count = seed_demo(settings)
                except ImportError as exc:
                    console.print(
                        "[red]DataHub seed unavailable:[/red] install the 'datahub' extra."
                    )
                    raise typer.Exit(code=1) from exc
                except Exception as exc:
                    console.print(
                        "[red]DataHub seed failed:[/red] "
                        f"{type(exc).__name__}; no credential was displayed."
                    )
                    raise typer.Exit(code=1) from exc
                console.print(f"Seeded {proposal_count} deterministic DataHub proposals.")

            request = AnalysisRequest(
                before_manifest=preparation.before_manifest,
                after_manifest=preparation.after_manifest,
                project_dir=preparation.proposed_project,
                model_path="models/staging/stg_orders.sql",
                schema_path="models/staging/schema.yml",
                test_path="tests/lineageguard_order_total_matches_gross_amount.sql",
                model_name="stg_orders",
                selector="stg_orders+",
                source_commit_sha=source_commit_sha,
                analyzed_input_state=AnalyzedInputState.GENERATED_IN_PROCESS,
                dialect="duckdb",
                preflight_evidence_digest=preparation.evidence_digest,
            )
            result, paths = asyncio.run(
                run_analysis(
                    request,
                    settings=settings,
                    policy_path=REPOSITORY_ROOT / "config/risk-policy.yaml",
                    output_root=output,
                    writeback=writeback,
                )
            )
            write_demo_preflight(preparation, paths.run_directory / "demo-preflight.json")
    except DemoPreparationError as exc:
        console.print(f"[red]Demo preparation failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except (AgentInputError, MCPClientError, RiskPolicyError, ValueError) as exc:
        console.print(f"[red]Demo analysis failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    _print_result(result, paths)
    if not _is_passing(result, require_writeback=True):
        console.print(
            "[red]Demo incomplete:[/red] a passing decision and verified DataHub "
            "readback are required."
        )
        raise typer.Exit(code=2)


@app.command()
def serve(
    port: Annotated[
        int,
        typer.Option("--port", min=1024, max=65535, help="Local review UI port."),
    ] = 8765,
) -> None:
    """Serve the latest local report on the loopback interface only."""

    console.print(f"Review UI: http://127.0.0.1:{port}")
    uvicorn.run(
        "lineageguard.review_ui.app:app",
        host="127.0.0.1",
        port=port,
        reload=False,
        log_level="warning",
    )


if __name__ == "__main__":
    app()
