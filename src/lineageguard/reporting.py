"""Deterministic JSON, Markdown, and self-contained HTML run reports."""

from __future__ import annotations

import html
import json
import os
import re
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from lineageguard.run_models import RunResult, calculate_artifact_hash, run_result_payload


@dataclass(frozen=True, slots=True)
class ReportPaths:
    """Files retained for a completed analysis run."""

    run_directory: Path
    json: Path
    markdown: Path
    html: Path
    latest_json: Path


_REPORT_TOKEN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_ARTIFACT_HASH = re.compile(r"^[0-9a-f]{64}$")


def _safe_cell(value: object) -> str:
    text = html.escape(str(value), quote=True).replace("\n", " ").replace("\r", " ")
    text = text.replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "!", "|"):
        text = text.replace(character, f"\\{character}")
    return text


def _diff_fence(value: str) -> str:
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", value)), default=0)
    return "`" * max(3, longest + 1)


def _input_state_label(result: RunResult) -> str:
    state = result.inputs.analyzed_input_state
    return state.value if state is not None else "LEGACY_UNRECORDED"


def render_markdown(result: RunResult) -> str:
    """Render the evidence ledger as a reviewable change passport."""

    residual = result.remediation.residual_risk
    residual_score = str(residual.score) if residual is not None else "not established"
    lines = [
        f"# LineageGuard change passport {_safe_cell(result.run_id)}",
        "",
        f"**Run status:** `{result.status.value}`  ",
        f"**Decision:** `{result.final_decision.value}`  ",
        f"**Initial risk:** {result.initial_risk.score}/100 "
        f"(`{result.initial_risk.decision.value}`)  ",
        f"**Residual risk:** {residual_score}  ",
        f"**Remediation:** `{result.remediation.status.value}`  ",
        f"**DataHub writeback:** `{result.writeback.state.value}`  ",
        f"**Source commit:** `{_safe_cell(result.inputs.commit_sha)}`  ",
        f"**Analyzed inputs:** `{_input_state_label(result)}`  ",
        f"**Decision evidence hash:** `{result.evidence_hash}`",
        f"**Final artifact hash:** `{result.artifact_hash or 'not sealed'}`",
        "",
        "## Proposed schema change",
        "",
        "| Relation | Change | Existing | Proposed |",
        "| --- | --- | --- | --- |",
    ]
    for change in result.changes:
        existing = change.old_column or change.old_type or "-"
        proposed = change.new_column or change.new_type or "-"
        lines.append(
            "| "
            + " | ".join(
                _safe_cell(value)
                for value in (change.relation, change.change_type.value, existing, proposed)
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## DataHub blast radius",
            "",
            "| Asset | Type | Hops | Owners | Assertions |",
            "| --- | --- | ---: | --- | ---: |",
        ]
    )
    for asset in result.context.impacted_assets:
        owners = ", ".join(asset.owners or ()) if asset.owners is not None else "not established"
        assertions = (
            str(len(asset.assertion_urns))
            if asset.assertion_urns is not None
            else "not established"
        )
        lines.append(
            "| "
            + " | ".join(
                _safe_cell(value)
                for value in (
                    asset.name or asset.urn,
                    asset.asset_type.value,
                    asset.hop_count,
                    owners or "none recorded",
                    assertions,
                )
            )
            + " |"
        )
    if not result.context.impacted_assets:
        lines.append("| No downstream assets established | - | - | - | - |")

    lines.extend(
        [
            "",
            "## Tested remediation",
            "",
            _safe_cell(
                result.remediation.reason or "A bounded compatibility bridge was generated."
            ),
            "",
        ]
    )
    verification = result.remediation.verification
    if verification is not None:
        lines.extend(
            [
                f"Verification status: `{verification.status}`",
                "",
                "| Command | Exit | Duration | Output digest |",
                "| --- | ---: | ---: | --- |",
            ]
        )
        for command in verification.commands:
            lines.append(
                "| "
                + " | ".join(
                    _safe_cell(value)
                    for value in (
                        " ".join(command.command),
                        command.exit_code,
                        f"{command.duration_ms} ms",
                        command.output_digest,
                    )
                )
                + " |"
            )
        lines.append("")

    if result.remediation.unified_diff:
        fence = _diff_fence(result.remediation.unified_diff)
        lines.extend(
            [
                f"{fence}diff",
                result.remediation.unified_diff.rstrip(),
                fence,
                "",
            ]
        )

    lines.extend(
        [
            "## Counterfactual decision",
            "",
            "Original interface preserved: "
            f"`{str(result.remediation.interface_preserved).lower()}`  ",
            "Counterfactual verified: "
            f"`{str(result.remediation.counterfactual_verified).lower()}`  ",
            f"Residual decision: `{residual.decision.value if residual else 'not established'}`",
            "",
            "## Evidence coverage",
            "",
            f"- Catalog: `{result.context.evidence_state.catalog.value}`",
            f"- Lineage: `{result.context.evidence_state.lineage.value}`",
            f"- Traversal: `{result.context.evidence_state.traversal.value}`",
            f"- Ownership: `{result.context.evidence_state.ownership.value}`",
            f"- Assertions: `{result.context.evidence_state.assertions.value}`",
        ]
    )
    if result.context.reason_codes:
        lines.extend(["", "Reason codes:"])
        lines.extend(f"- `{reason}`" for reason in result.context.reason_codes)

    lines.extend(["", "## DataHub durability", ""])
    if result.writeback.state.value == "VERIFIED":
        lines.append(
            "The change passport was written through the official MCP server and read back "
            "from DataHub."
        )
    elif result.writeback.state.value == "NOT_REQUESTED":
        lines.append("Writeback was not requested for this run.")
    else:
        lines.append("Writeback is pending and must not be represented as durable DataHub state.")
    if result.writeback.document_urn:
        lines.extend(["", f"Document URN: {_safe_cell(result.writeback.document_urn)}"])
    return "\n".join(lines).rstrip() + "\n"


def render_passport_markdown(result: RunResult) -> str:
    """Render a small injection-resistant identity document for DataHub."""

    residual = result.remediation.residual_risk
    verification = result.remediation.verification
    lines = [
        "# LineageGuard change passport",
        "",
        f"Run ID: `{result.run_id}`  ",
        f"Decision: `{result.final_decision.value}`  ",
        f"Initial risk: `{result.initial_risk.score}`  ",
        f"Residual risk: `{residual.score if residual is not None else 'NOT_ESTABLISHED'}`  ",
        f"Remediation: `{result.remediation.status.value}`  ",
        f"Source commit: `{result.inputs.commit_sha}`  ",
        f"Analyzed inputs: `{_input_state_label(result)}`  ",
        f"Counterfactual verified: `{str(result.remediation.counterfactual_verified).lower()}`  ",
        f"Decision evidence hash: `{result.evidence_hash}`  ",
        "Verifier evidence hash: "
        f"`{verification.evidence_digest if verification is not None else 'NOT_ESTABLISHED'}`",
        "",
        "This document records bounded decision identity before durability readback. "
        "Machine-readable structured properties and the local sealed artifact carry "
        "the independent MCP readback outcome.",
    ]
    return "\n".join(lines).rstrip() + "\n"


def render_html(result: RunResult) -> str:
    """Render a portable report with no scripts, remote assets, or network calls."""

    markdown = render_markdown(result)
    escaped = html.escape(markdown)
    decision = html.escape(result.final_decision.value)
    score = result.initial_risk.score
    residual = result.remediation.residual_risk
    residual_score = residual.score if residual is not None else "?"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LineageGuard {html.escape(result.run_id)}</title>
  <style>
    :root {{ color-scheme: dark; --ink:#101416; --paper:#f1eadb; --risk:#ff6b35;
      --verified:#2ed3c6; --muted:#9da7a6; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--ink); color:var(--paper);
      font:15px/1.55 "IBM Plex Mono","Aptos Mono",ui-monospace,monospace; }}
    main {{ width:min(1120px,calc(100% - 32px)); margin:32px auto 64px; }}
    header {{ display:grid; grid-template-columns:1fr auto; gap:24px; align-items:end;
      border-block:1px solid #4b5352; padding:24px 0; }}
    .kicker {{ color:var(--muted); text-transform:uppercase; font-size:12px; }}
    h1 {{ margin:4px 0 0; font:700 clamp(28px,5vw,58px)/.95 Georgia,serif; }}
    .decision {{ border:1px solid var(--risk); padding:10px 14px; color:var(--risk); }}
    .rail {{ display:grid; grid-template-columns:1fr auto 1fr; align-items:center; gap:14px;
      margin:28px 0; }}
    .score {{ border-top:6px solid var(--risk); padding-top:10px; font-size:24px; }}
    .score.after {{ border-color:var(--verified); text-align:right; }}
    .arrow {{ color:var(--muted); }}
    pre {{ white-space:pre-wrap; overflow-wrap:anywhere; background:#171c1e;
      border:1px solid #343b3d;
      padding:20px; border-radius:2px; }}
    @media (max-width:680px) {{ header {{ grid-template-columns:1fr; }}
      .rail {{ grid-template-columns:1fr; }}
      .arrow {{ transform:rotate(90deg); text-align:center; }}
      .score.after {{ text-align:left; }} }}
  </style>
</head>
<body><main>
  <header><div><div class="kicker">Evidence-led change passport</div>
    <h1>LineageGuard</h1></div><div class="decision">{decision}</div></header>
  <section class="rail" aria-label="Risk before and after remediation">
    <div class="score">BEFORE&nbsp; {score}/100</div><div class="arrow">-&gt;</div>
    <div class="score after">AFTER&nbsp; {residual_score}/100</div>
  </section>
  <pre>{escaped}</pre>
</main></body></html>
"""


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.replace(temporary, path)
        path.chmod(0o600)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def _reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    for component in (absolute, *absolute.parents):
        if component.is_symlink():
            raise ValueError("report output path must not contain a symbolic link")


def _verify_existing_run(run_directory: Path, expected: dict[str, str]) -> None:
    if run_directory.is_symlink() or not run_directory.is_dir():
        raise ValueError("report run directory is not an owner-controlled directory")
    metadata = run_directory.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("report run directory is not owner-only")
    for name, content in expected.items():
        path = run_directory / name
        if path.is_symlink():
            raise ValueError("immutable report artifact is a symbolic link")
        try:
            file_metadata = path.stat()
            observed = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ValueError("immutable report artifact is missing or unreadable") from exc
        if (
            not stat.S_ISREG(file_metadata.st_mode)
            or file_metadata.st_uid != os.getuid()
            or stat.S_IMODE(file_metadata.st_mode) != 0o600
            or observed != content
        ):
            raise ValueError("immutable report artifact does not match this sealed run")


def write_reports(result: RunResult, output_root: Path) -> ReportPaths:
    """Write immutable per-run artifacts plus an atomic latest JSON snapshot."""

    expanded_root = output_root.expanduser()
    _reject_symlink_components(expanded_root)
    if _REPORT_TOKEN.fullmatch(result.run_id) is None:
        raise ValueError("report run ID is unsafe for a local path")
    if (
        result.artifact_hash is None
        or _ARTIFACT_HASH.fullmatch(result.artifact_hash) is None
        or result.artifact_hash != calculate_artifact_hash(result)
    ):
        raise ValueError("report artifact hash is invalid")
    expanded_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = expanded_root.resolve(strict=True)
    root.chmod(0o700)
    attempt_seal = result.artifact_hash[:12]
    run_directory = root / f"{result.run_id}-{attempt_seal}"
    json_path = run_directory / "report.json"
    markdown_path = run_directory / "report.md"
    html_path = run_directory / "report.html"
    latest_json = root / "latest.json"
    payload = (
        json.dumps(run_result_payload(result), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    )
    expected = {
        "report.json": payload,
        "report.md": render_markdown(result),
        "report.html": render_html(result),
    }
    try:
        run_directory.mkdir(parents=False, exist_ok=False, mode=0o700)
    except FileExistsError:
        _verify_existing_run(run_directory, expected)
    else:
        run_directory.chmod(0o700)
        _atomic_write(json_path, expected["report.json"])
        _atomic_write(markdown_path, expected["report.md"])
        _atomic_write(html_path, expected["report.html"])
    _atomic_write(latest_json, payload)
    return ReportPaths(
        run_directory=run_directory,
        json=json_path,
        markdown=markdown_path,
        html=html_path,
        latest_json=latest_json,
    )


__all__ = [
    "ReportPaths",
    "render_html",
    "render_markdown",
    "render_passport_markdown",
    "write_reports",
]
