"""Apply generated artifacts in an isolated copy and run allowlisted dbt checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, cast

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from lineageguard.changes import ManifestInput
from lineageguard.remediation.generator import RemediationBundle

_MODEL_DOWNSTREAM_SELECTOR = re.compile(r"^(?P<model>[A-Za-z_][A-Za-z0-9_]*)\+$")
_SAFE_ADAPTER_TYPE = re.compile(r"^[A-Za-z0-9_+-]+$")
_MAX_CAPTURE_CHARS = 12_000


class VerificationStatus(StrEnum):
    TESTED = "TESTED"
    TEST_FAILED = "TEST_FAILED"
    VERIFICATION_ERROR = "VERIFICATION_ERROR"


class VerificationError(RuntimeError):
    """A remediation could not be applied or verified safely."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    command: tuple[str, ...]
    exit_code: int
    duration_ms: int
    output: str
    output_digest: str


@dataclass(frozen=True, slots=True)
class ManifestSnapshot:
    """Immutable, comparator-ready summary of one dbt manifest.

    The summary deliberately excludes dbt environment/configuration data and
    raw SQL. Projection expressions are represented only by SHA-256 tokens so
    rename evidence remains comparable without retaining SQL literals.
    """

    summary_json: str
    sha256: str


@dataclass(frozen=True, slots=True)
class VerificationResult:
    status: VerificationStatus
    commands: tuple[CommandResult, ...]
    artifact_digests: tuple[tuple[str, str], ...]
    evidence_digest: str
    failure_reason: str | None = None
    patched_manifest: ManifestSnapshot | None = None
    run_results_digest: str | None = None
    verified_node_ids: tuple[str, ...] = ()


class CommandRunner(Protocol):
    def __call__(
        self,
        command: tuple[str, ...],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
    ) -> subprocess.CompletedProcess[str]: ...


def _subprocess_runner(
    command: tuple[str, ...],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
) -> subprocess.CompletedProcess[str]:
    def tail(stream: Any) -> str:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - _MAX_CAPTURE_CHARS))
        return cast(bytes, stream.read()).decode("utf-8", errors="replace")

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        completed = subprocess.run(  # noqa: S603 - fixed internal argv, no shell
            command,
            cwd=cwd,
            env=dict(env),
            stdout=stdout,
            stderr=stderr,
            text=False,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
        return subprocess.CompletedProcess(
            command,
            completed.returncode,
            stdout=tail(stdout),
            stderr=tail(stderr),
        )


def _safe_environment() -> dict[str, str]:
    allowed = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "VIRTUAL_ENV")
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env["DBT_SEND_ANONYMOUS_USAGE_STATS"] = "false"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _read_manifest(source: ManifestInput) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        manifest = source
    else:
        try:
            raw = Path(source).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise VerificationError("dbt manifest is missing or unreadable") from exc
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise VerificationError("dbt manifest is not valid JSON") from exc
        if not isinstance(loaded, Mapping):
            raise VerificationError("dbt manifest must be a JSON object")
        manifest = loaded
    if not isinstance(manifest.get("nodes"), Mapping):
        raise VerificationError("dbt manifest must contain a nodes object")
    return manifest


def _manifest_dialect(manifest: Mapping[str, Any]) -> str:
    metadata = manifest.get("metadata")
    adapter = metadata.get("adapter_type") if isinstance(metadata, Mapping) else None
    if not isinstance(adapter, str) or not adapter.strip():
        return "postgres"
    normalized = adapter.strip().casefold()
    if not _SAFE_ADAPTER_TYPE.fullmatch(normalized):
        raise VerificationError("dbt manifest adapter type is invalid")
    return {"postgresql": "postgres"}.get(normalized, normalized)


def _projection_summary(node: Mapping[str, Any], dialect: str) -> str | None:
    """Render only output names and hashed expression identities as safe SQL."""

    compiled = node.get("compiled_code") or node.get("compiled_sql")
    if not isinstance(compiled, str) or not compiled.strip():
        return None
    try:
        query = sqlglot.parse_one(compiled, read=dialect)
    except (ParseError, TokenError, TypeError, ValueError):
        return None
    if not isinstance(query, exp.Select):
        return None

    projections: list[exp.Expression] = []
    for ordinal, expression in enumerate(query.expressions):
        if isinstance(expression, exp.Alias):
            output_identifier = expression.args.get("alias")
            if not isinstance(output_identifier, exp.Identifier):
                return None
            output = output_identifier.name
            quoted = output_identifier.args.get("quoted") is True
            source = expression.this
        elif isinstance(expression, exp.Column) and not expression.is_star:
            output_identifier = expression.this
            if not isinstance(output_identifier, exp.Identifier):
                return None
            output = output_identifier.name
            quoted = output_identifier.args.get("quoted") is True
            source = expression
        else:
            return None
        if not output:
            return None
        try:
            fingerprint = source.sql(dialect=dialect, normalize=True, pretty=False)
        except (TypeError, ValueError):
            # Preserve the output column but make a rename match impossible.
            token = f"unavailable:{ordinal}:{output.casefold()}"
        else:
            token = f"expression:{hashlib.sha256(fingerprint.encode()).hexdigest()}"
        projections.append(
            cast(exp.Expression, exp.alias_(exp.Literal.string(token), output, quoted=quoted))
        )

    if not projections:
        return None
    try:
        return exp.select(*projections).sql(dialect=dialect, pretty=False)
    except (TypeError, ValueError):
        return None


def _query_context_sha256(node: Mapping[str, Any], dialect: str) -> str | None:
    """Hash every top-level query clause except the projection list."""

    compiled = node.get("compiled_code") or node.get("compiled_sql")
    if not isinstance(compiled, str) or not compiled.strip():
        return None
    try:
        query = sqlglot.parse_one(compiled, read=dialect)
    except (ParseError, TokenError, TypeError, ValueError):
        return None
    if not isinstance(query, exp.Select):
        return None
    context = query.copy()
    context.set("expressions", [exp.Literal.number(1)])
    try:
        rendered = context.sql(
            dialect=dialect,
            normalize=True,
            pretty=False,
            comments=False,
        )
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(rendered.encode()).hexdigest()


def _safe_constraints(value: object) -> list[dict[str, str]] | None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return None
    constraints: list[dict[str, str]] = []
    for constraint in value:
        kind = constraint.get("type") if isinstance(constraint, Mapping) else constraint
        if not isinstance(kind, str) or not kind.strip():
            raise VerificationError("dbt manifest column constraint has no usable type")
        try:
            canonical = json.dumps(
                constraint,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode()
        except (TypeError, ValueError) as exc:
            raise VerificationError("dbt manifest column constraint is not JSON") from exc
        normalized_kind = kind.casefold().replace(" ", "_")
        safe_kind = (
            normalized_kind
            if normalized_kind
            in {"not_null", "unique", "primary_key", "foreign_key", "check", "custom"}
            else "other"
        )
        constraints.append(
            {
                "type": safe_kind,
                "sha256": hashlib.sha256(canonical).hexdigest(),
            }
        )
    return sorted(constraints, key=lambda item: (item["type"], item["sha256"]))


def _safe_columns(value: object) -> dict[str, dict[str, object]]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise VerificationError("dbt manifest node columns must be an object")
    columns: dict[str, dict[str, object]] = {}
    for raw_key in sorted(value, key=str):
        if not isinstance(raw_key, str):
            raise VerificationError("dbt manifest column keys must be strings")
        raw_column = value[raw_key]
        if not isinstance(raw_column, Mapping):
            raise VerificationError("dbt manifest column metadata must be an object")
        column: dict[str, object] = {}
        for field in ("name", "data_type"):
            item = raw_column.get(field)
            if isinstance(item, str):
                column[field] = item
        for field in ("nullable", "not_null"):
            item = raw_column.get(field)
            if isinstance(item, bool):
                column[field] = item
        quote = raw_column.get("quote")
        if quote is not None and not isinstance(quote, bool):
            raise VerificationError("dbt manifest column quote flag must be boolean")
        column["quote"] = quote is True
        constraints = _safe_constraints(raw_column.get("constraints"))
        if constraints is not None:
            column["constraints"] = constraints
        columns[raw_key] = column
    return columns


def _column_test_signature(node: Mapping[str, Any]) -> str | None:
    metadata = node.get("test_metadata")
    name = metadata.get("name") if isinstance(metadata, Mapping) else node.get("name")
    kwargs = metadata.get("kwargs") if isinstance(metadata, Mapping) else None
    safe_kwargs = (
        {str(key): value for key, value in kwargs.items() if key not in {"model", "column_name"}}
        if isinstance(kwargs, Mapping)
        else {}
    )
    config = node.get("config")
    safe_config = (
        {
            key: config[key]
            for key in (
                "severity",
                "where",
                "warn_if",
                "error_if",
                "fail_calc",
                "limit",
                "store_failures",
                "store_failures_as",
            )
            if key in config
        }
        if isinstance(config, Mapping)
        else {}
    )
    compiled = node.get("compiled_code") or node.get("compiled_sql")
    if not isinstance(compiled, str) or not compiled.strip():
        return None
    payload = {
        "compiled_sha256": hashlib.sha256(compiled.encode()).hexdigest(),
        "config": safe_config,
        "kwargs": safe_kwargs,
        "name_sha256": hashlib.sha256(str(name).encode()).hexdigest(),
    }
    try:
        return hashlib.sha256(_canonical_json(payload).encode()).hexdigest()
    except (TypeError, ValueError) as exc:
        raise VerificationError("dbt column test metadata is not JSON") from exc


def _safe_manifest_summary(manifest: Mapping[str, Any]) -> dict[str, object]:
    raw_nodes = manifest["nodes"]
    if not isinstance(raw_nodes, Mapping):  # retained for direct defensive use
        raise VerificationError("dbt manifest must contain a nodes object")
    dialect = _manifest_dialect(manifest)
    safe_metadata = {"adapter_type": dialect}

    summarized_by_unique_id: dict[str, dict[str, object]] = {}
    for unique_id in sorted(raw_nodes, key=str):
        raw_node = raw_nodes[unique_id]
        if not isinstance(raw_node, Mapping):
            raise VerificationError("dbt manifest nodes must be objects")
        resource_type = raw_node.get("resource_type")
        if resource_type not in {"model", "seed", "snapshot"}:
            continue
        node: dict[str, object] = {
            "resource_type": resource_type,
            "columns": _safe_columns(raw_node.get("columns")),
            "model_test_evidence_complete": True,
            "model_test_sha256": [],
        }
        raw_config = raw_node.get("config")
        if raw_config is None:
            safe_node_config: Mapping[str, Any] = {}
        elif not isinstance(raw_config, Mapping):
            raise VerificationError("dbt manifest node config must be an object")
        else:
            safe_node_config = raw_config
        try:
            node["config_sha256"] = hashlib.sha256(
                _canonical_json(safe_node_config).encode()
            ).hexdigest()
            node["model_constraints_sha256"] = hashlib.sha256(
                _canonical_json(
                    {
                        "constraints": raw_node.get("constraints"),
                        "primary_key": raw_node.get("primary_key"),
                    }
                ).encode()
            ).hexdigest()
        except (TypeError, ValueError) as exc:
            raise VerificationError("dbt manifest interface metadata is not JSON") from exc
        relation_name = raw_node.get("relation_name")
        if isinstance(relation_name, str) and relation_name.strip():
            node["relation_name"] = relation_name
        else:
            for field in ("database", "schema", "alias", "identifier", "name"):
                value = raw_node.get(field)
                if isinstance(value, str):
                    node[field] = value
        projection_summary = _projection_summary(raw_node, dialect)
        if projection_summary is not None:
            node["compiled_code"] = projection_summary
        query_context_sha256 = _query_context_sha256(raw_node, dialect)
        if query_context_sha256 is not None:
            node["query_context_sha256"] = query_context_sha256
        summarized_by_unique_id[str(unique_id)] = node

    for unique_id in sorted(raw_nodes, key=str):
        raw_test = raw_nodes[unique_id]
        if not isinstance(raw_test, Mapping) or raw_test.get("resource_type") != "test":
            continue
        attached_node = raw_test.get("attached_node")
        column_name = raw_test.get("column_name")
        depends_on = raw_test.get("depends_on")
        dependency_nodes = depends_on.get("nodes") if isinstance(depends_on, Mapping) else ()
        if not isinstance(dependency_nodes, Sequence) or isinstance(dependency_nodes, (str, bytes)):
            raise VerificationError("dbt test dependency metadata is invalid")
        dependencies = {
            dependency for dependency in dependency_nodes if isinstance(dependency, str)
        }
        if len(dependencies) != len(dependency_nodes):
            raise VerificationError("dbt test dependency metadata is invalid")
        if isinstance(attached_node, str):
            dependencies.add(attached_node)
        signature = _column_test_signature(raw_test)
        is_column_test = isinstance(attached_node, str) and isinstance(column_name, str)
        if not is_column_test:
            for dependency in dependencies:
                summarized_dependency = summarized_by_unique_id.get(dependency)
                if summarized_dependency is None:
                    continue
                model_signatures = summarized_dependency.get("model_test_sha256")
                if not isinstance(model_signatures, list):
                    raise VerificationError("dbt model test summary is invalid")
                if signature is None:
                    summarized_dependency["model_test_evidence_complete"] = False
                else:
                    model_signatures.append(signature)

        if not isinstance(attached_node, str) or not isinstance(column_name, str):
            continue
        summarized = summarized_by_unique_id.get(attached_node)
        columns = summarized.get("columns") if summarized is not None else None
        if not isinstance(columns, dict):
            continue
        matching_key = next(
            (
                key
                for key in columns
                if isinstance(key, str) and key.casefold() == column_name.casefold()
            ),
            None,
        )
        if matching_key is None:
            raise VerificationError("dbt column test points to a missing column")
        contract = columns[matching_key]
        if not isinstance(contract, dict):  # retained for defensive direct calls
            raise VerificationError("dbt column contract summary is invalid")
        signatures = contract.setdefault("data_test_sha256", [])
        if not isinstance(signatures, list):  # retained for defensive direct calls
            raise VerificationError("dbt column test summary is invalid")
        if signature is None:
            contract["data_test_evidence_complete"] = False
        else:
            contract.setdefault("data_test_evidence_complete", True)
            signatures.append(signature)

    summarized_nodes = list(summarized_by_unique_id.values())
    for node in summarized_nodes:
        model_signatures = node.get("model_test_sha256")
        if isinstance(model_signatures, list):
            node["model_test_sha256"] = sorted(set(model_signatures))
        columns = node.get("columns")
        if not isinstance(columns, dict):
            continue
        for contract in columns.values():
            if isinstance(contract, dict) and isinstance(contract.get("data_test_sha256"), list):
                contract["data_test_sha256"] = sorted(contract["data_test_sha256"])

    # dbt unique IDs are unnecessary for the physical-relation comparator and
    # may contain package-local detail, so replace them with stable local keys.
    summarized_nodes.sort(key=_canonical_json)
    nodes = {f"node.{index:06d}": node for index, node in enumerate(summarized_nodes)}
    return {"summary_version": 3, "metadata": safe_metadata, "nodes": nodes}


def snapshot_dbt_manifest(source: ManifestInput) -> ManifestSnapshot:
    """Create a canonical safe manifest summary suitable for later comparison."""

    summary_json = _canonical_json(_safe_manifest_summary(_read_manifest(source)))
    return ManifestSnapshot(
        summary_json=summary_json,
        sha256=hashlib.sha256(summary_json.encode()).hexdigest(),
    )


def _verified_run_results(
    path: Path,
    *,
    model_name: str,
    compatibility_test_names: tuple[str, ...],
) -> tuple[str, tuple[str, ...]]:
    try:
        raw = path.read_bytes()
        loaded = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError("dbt run results are missing or invalid") from exc
    if not isinstance(loaded, Mapping) or not isinstance(loaded.get("results"), list):
        raise VerificationError("dbt run results are missing or invalid")

    successful: set[str] = set()
    for item in loaded["results"]:
        if not isinstance(item, Mapping):
            continue
        unique_id = item.get("unique_id")
        status = item.get("status")
        if (
            isinstance(unique_id, str)
            and isinstance(status, str)
            and status.casefold() in {"pass", "success"}
        ):
            successful.add(unique_id)

    model_matches = {
        unique_id
        for unique_id in successful
        if unique_id.startswith("model.") and unique_id.rsplit(".", 1)[-1] == model_name
    }
    if len(model_matches) != 1:
        raise VerificationError("dbt did not verify the remediated model")
    for test_name in compatibility_test_names:
        matches = {
            unique_id
            for unique_id in successful
            if unique_id.startswith("test.")
            and len(unique_id.split(".")) >= 3
            and unique_id.split(".")[2] == test_name
        }
        if len(matches) != 1:
            raise VerificationError("dbt did not verify the generated compatibility test")

    return hashlib.sha256(raw).hexdigest(), tuple(sorted(successful))


def _apply_bundle(workspace: Path, bundle: RemediationBundle) -> None:
    root = workspace.resolve(strict=True)
    for artifact in bundle.artifacts:
        target = root / artifact.path
        if target.is_symlink():
            raise VerificationError(f"Refusing to write through symlink: {artifact.path}")
        resolved_parent = target.parent.resolve(strict=True)
        try:
            resolved_parent.relative_to(root)
        except ValueError as exc:
            raise VerificationError(
                f"Artifact escapes verification workspace: {artifact.path}"
            ) from exc
        if artifact.previous_content is None:
            if target.exists():
                raise VerificationError(
                    f"Generated artifact would overwrite a file: {artifact.path}"
                )
        else:
            if not target.is_file():
                raise VerificationError(f"Remediation target is missing: {artifact.path}")
            current = target.read_text(encoding="utf-8")
            if current != artifact.previous_content:
                raise VerificationError(f"Remediation target drifted: {artifact.path}")
        target.write_text(artifact.content, encoding="utf-8")


class RemediationVerifier:
    """Run a fixed dbt seed/parse/build plan without evaluating metadata text."""

    def __init__(
        self,
        *,
        dbt_executable: str = "dbt",
        timeout_seconds: float = 90.0,
        runner: CommandRunner = _subprocess_runner,
    ) -> None:
        executable_name = Path(dbt_executable).name
        if executable_name != "dbt":
            raise VerificationError("The verifier only permits the dbt executable")
        if timeout_seconds <= 0 or timeout_seconds > 600:
            raise VerificationError("timeout_seconds must be between 0 and 600")
        self.dbt_executable = dbt_executable
        self.timeout_seconds = timeout_seconds
        self.runner = runner

    def verify(
        self,
        project_dir: Path,
        bundle: RemediationBundle,
        *,
        selector: str,
    ) -> VerificationResult:
        selector_match = _MODEL_DOWNSTREAM_SELECTOR.fullmatch(selector)
        if selector_match is None:
            raise VerificationError(f"Unsafe dbt selector: {selector!r}; expected exactly <model>+")
        model_name = selector_match.group("model")
        source = project_dir.resolve(strict=True)
        if not source.is_dir():
            raise VerificationError("dbt project path must be a directory")
        if any(path.is_symlink() for path in source.rglob("*")):
            raise VerificationError("dbt verification project must not contain symlinks")

        artifact_digests = tuple(
            sorted((artifact.path, artifact.sha256) for artifact in bundle.artifacts)
        )
        results: list[CommandResult] = []
        failure_reason: str | None = None
        status = VerificationStatus.TESTED
        patched_manifest: ManifestSnapshot | None = None
        run_results_digest: str | None = None
        verified_node_ids: tuple[str, ...] = ()
        compatibility_test_names = tuple(
            Path(artifact.path).stem
            for artifact in bundle.artifacts
            if Path(artifact.path).parts[0] == "tests"
            and Path(artifact.path).suffix == ".sql"
            and artifact.previous_content is None
        )
        if not compatibility_test_names:
            raise VerificationError("The remediation bundle has no compatibility equality test")

        with tempfile.TemporaryDirectory(prefix="lineageguard-verify-") as temporary:
            workspace = Path(temporary) / "project"
            shutil.copytree(
                source,
                workspace,
                ignore=shutil.ignore_patterns("target", "logs", "*.duckdb", ".git"),
            )
            try:
                _apply_bundle(workspace, bundle)
            except (OSError, UnicodeError, VerificationError) as exc:
                status = VerificationStatus.VERIFICATION_ERROR
                failure_reason = str(exc)
            else:
                commands = (
                    (
                        self.dbt_executable,
                        "seed",
                        "--project-dir",
                        ".",
                        "--profiles-dir",
                        ".",
                        "--no-use-colors",
                    ),
                    (
                        self.dbt_executable,
                        "parse",
                        "--project-dir",
                        ".",
                        "--profiles-dir",
                        ".",
                        "--no-use-colors",
                    ),
                    (
                        self.dbt_executable,
                        "build",
                        "--project-dir",
                        ".",
                        "--profiles-dir",
                        ".",
                        "--select",
                        selector,
                        "--no-use-colors",
                    ),
                )
                for command in commands:
                    recorded_command = (Path(command[0]).name, *command[1:])
                    started = time.monotonic()
                    try:
                        completed = self.runner(
                            command,
                            cwd=workspace,
                            env=_safe_environment(),
                            timeout_seconds=self.timeout_seconds,
                        )
                    except (OSError, subprocess.SubprocessError) as exc:
                        status = VerificationStatus.VERIFICATION_ERROR
                        failure_reason = type(exc).__name__
                        break
                    output = f"{completed.stdout}\n{completed.stderr}".strip()
                    result = CommandResult(
                        command=recorded_command,
                        exit_code=completed.returncode,
                        duration_ms=round((time.monotonic() - started) * 1000),
                        output=output[-_MAX_CAPTURE_CHARS:],
                        output_digest=hashlib.sha256(output.encode()).hexdigest(),
                    )
                    results.append(result)
                    if completed.returncode != 0:
                        status = VerificationStatus.TEST_FAILED
                        failure_reason = f"{command[1]} exited {completed.returncode}"
                        break

                if status is VerificationStatus.TESTED:
                    try:
                        run_results_digest, verified_node_ids = _verified_run_results(
                            workspace / "target" / "run_results.json",
                            model_name=model_name,
                            compatibility_test_names=compatibility_test_names,
                        )
                        patched_manifest = snapshot_dbt_manifest(
                            workspace / "target" / "manifest.json"
                        )
                    except VerificationError as exc:
                        status = VerificationStatus.VERIFICATION_ERROR
                        failure_reason = str(exc)
                    else:
                        # The summary should never retain the ephemeral copy's
                        # location, even if a dbt adapter emits path-like data.
                        if str(workspace) in patched_manifest.summary_json:
                            patched_manifest = None
                            status = VerificationStatus.VERIFICATION_ERROR
                            failure_reason = "verified dbt manifest contains a temporary path"

        evidence_digest = _canonical_digest(
            {
                "status": status.value,
                "commands": [
                    {
                        "command": result.command,
                        "exit_code": result.exit_code,
                        "output_digest": result.output_digest,
                    }
                    for result in results
                ],
                "artifacts": artifact_digests,
                "failure_reason": failure_reason,
                "patched_manifest_sha256": (
                    patched_manifest.sha256 if patched_manifest is not None else None
                ),
                "run_results_digest": run_results_digest,
                "verified_node_ids": verified_node_ids,
            }
        )
        return VerificationResult(
            status=status,
            commands=tuple(results),
            artifact_digests=artifact_digests,
            evidence_digest=evidence_digest,
            failure_reason=failure_reason,
            patched_manifest=patched_manifest,
            run_results_digest=run_results_digest,
            verified_node_ids=verified_node_ids,
        )
