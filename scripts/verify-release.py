#!/usr/bin/env python3
"""Fail a release archive that leaks local build state or misses demo assets."""

from __future__ import annotations

import argparse
import hashlib
import re
import tarfile
import zipfile
from pathlib import PurePosixPath


def _unsafe_path(name: str) -> bool:
    path = PurePosixPath(name)
    lowered = {part.casefold() for part in path.parts}
    return (
        path.is_absolute()
        or "\\" in name
        or ".." in path.parts
        or bool(lowered.intersection({"target", "logs", ".lineageguard", "__pycache__"}))
        or bool(lowered.intersection({".env", "datahub-token", "document-index"}))
        or path.suffix.casefold() in {".duckdb", ".sqlite", ".pyc"}
    )


_LOCAL_PATH_PATTERNS = (
    re.compile(rb"/Users/[A-Za-z0-9._-]+/"),
    re.compile(rb"/home/[A-Za-z0-9._-]+/"),
    re.compile(rb"[A-Za-z]:\\\\Users\\\\[A-Za-z0-9._-]+\\\\"),
)
_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bsk-proj-[A-Za-z0-9_-]{16,}"),
    re.compile(rb"\bghp_[A-Za-z0-9]{20,}"),
    re.compile(rb"\b(?:datahub[_-]?pat|dhpat)[_-][A-Za-z0-9_-]{20,}\b", re.IGNORECASE),
    re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(rb"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)
_AUTHORIZATION_VALUE = re.compile(
    rb"\bauthorization\b[^\r\n]{0,32}\bbearer[ \t]+([A-Za-z0-9._~+/=-]{16,})",
    re.IGNORECASE,
)
_NAMED_SECRET_VALUE = re.compile(
    rb"\b(?:[A-Za-z0-9]+[_-])*(?:token|password|api[_-]?key|client[_-]?secret|"
    rb"(?:aws[_-])?secret[_-]?access[_-]?key)\b[\"']?[ \t]*[:=][ \t]*"
    rb"(?:[rubf]{0,2}[\"'])?"
    rb"([A-Za-z0-9_~+/=-]{20,})",
    re.IGNORECASE,
)
_EMAIL_ADDRESS = re.compile(
    rb"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})@"
    rb"([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.[A-Za-z]{2,63})\b",
    re.IGNORECASE,
)
_PLACEHOLDER_MARKERS = (
    b"changeme",
    b"dummy",
    b"example",
    b"generated",
    b"local",
    b"placeholder",
    b"redacted",
    b"replace",
    b"sample",
    b"test",
)
_ROLE_EMAIL_LOCALS = frozenset(
    {b"admin", b"contact", b"info", b"no-reply", b"noreply", b"privacy", b"security", b"support"}
)
_RESERVED_EMAIL_DOMAINS = (b"example.com", b"example.net", b"example.org")
_RESERVED_EMAIL_SUFFIXES = (b".example", b".invalid", b".localhost", b".test")
_CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([^\r\n]+)$")
_EVIDENCE_CHECKSUM_PATHS = frozenset(
    {
        "demo-preflight.json",
        "report.html",
        "report.json",
        "report.md",
        "screenshots/datahub-decision-state.png",
        "screenshots/datahub-lineage.png",
        "screenshots/datahub-writeback-verified.png",
        "screenshots/report-overview.png",
    }
)
_DEMO_RELATIVE_FILES = frozenset(
    {
        ".gitignore",
        "README.md",
        "dbt_project.yml",
        "models/marts/fct_daily_revenue.sql",
        "models/marts/schema.yml",
        "models/staging/schema.yml",
        "models/staging/stg_orders.sql",
        "profiles.yml",
        "scenario/proposed/models/staging/schema.yml",
        "scenario/proposed/models/staging/stg_orders.sql",
        "seeds/orders.csv",
        "seeds/schema.yml",
        "tests/assert_completed_orders_have_positive_totals.sql",
        "tests/assert_daily_revenue_reconciles.sql",
    }
)
_SDIST_REQUIRED_SUFFIXES = frozenset(
    {
        "LICENSE",
        "Makefile",
        "README.md",
        "config/risk-policy.yaml",
        "config/structured-properties.yaml",
        "deploy/Dockerfile",
        "docs/demo-runbook.md",
        "examples/generated/README.md",
        "examples/generated/SHA256SUMS",
        "examples/generated/demo-preflight.json",
        "examples/generated/report.html",
        "examples/generated/report.json",
        "examples/generated/report.md",
        "examples/generated/screenshots/datahub-decision-state.png",
        "examples/generated/screenshots/datahub-lineage.png",
        "examples/generated/screenshots/datahub-writeback-verified.png",
        "examples/generated/screenshots/report-overview.png",
        "pyproject.toml",
        "scripts/create-local-token.py",
        "scripts/datahub-preflight.sh",
        "scripts/datahub-quickstart.py",
        "scripts/datahub-up.sh",
        "scripts/demo.sh",
        "scripts/seed-datahub-demo.py",
        "scripts/verify-release.py",
        "src/lineageguard/cli.py",
        "src/lineageguard/review_ui/app.py",
        "src/lineageguard/review_ui/static/index.html",
        "src/lineageguard/review_ui/static/review.css",
        "src/lineageguard/review_ui/static/review.js",
        "uv.lock",
    }
    | {f"demo/acme_dbt/{path}" for path in _DEMO_RELATIVE_FILES}
)
_WHEEL_REQUIRED_PATHS = frozenset(
    {
        "lineageguard/__init__.py",
        "lineageguard/cli.py",
        "lineageguard/bundled/config/risk-policy.yaml",
        "lineageguard/bundled/config/structured-properties.yaml",
        "lineageguard/review_ui/app.py",
        "lineageguard/review_ui/static/index.html",
        "lineageguard/review_ui/static/review.css",
        "lineageguard/review_ui/static/review.js",
    }
    | {f"lineageguard/bundled/demo/acme_dbt/{path}" for path in _DEMO_RELATIVE_FILES}
)
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _unsafe_content(data: bytes) -> str | None:
    if any(pattern.search(data) for pattern in _LOCAL_PATH_PATTERNS):
        return "a local absolute path"
    if any(pattern.search(data) for pattern in _SECRET_PATTERNS):
        return "credential-shaped content"
    for pattern in (_AUTHORIZATION_VALUE, _NAMED_SECRET_VALUE):
        for match in pattern.finditer(data):
            candidate = match.group(1).lower()
            if not any(marker in candidate for marker in _PLACEHOLDER_MARKERS):
                return "credential-shaped content"
    for match in _EMAIL_ADDRESS.finditer(data):
        local_part = match.group(1).lower()
        domain = match.group(2).lower()
        reserved = (
            domain in _RESERVED_EMAIL_DOMAINS
            or any(domain.endswith(b"." + value) for value in _RESERVED_EMAIL_DOMAINS)
            or any(domain.endswith(suffix) for suffix in _RESERVED_EMAIL_SUFFIXES)
        )
        if not reserved and local_part not in _ROLE_EMAIL_LOCALS:
            return "a personal email-shaped address"
    return None


def _matching_member(names: set[str], suffix: str) -> str:
    matches = sorted(name for name in names if name == suffix or name.endswith(f"/{suffix}"))
    if len(matches) != 1:
        raise SystemExit(f"sdist does not contain exactly one {suffix}: {matches}")
    return matches[0]


def _read_tar_member(archive: tarfile.TarFile, name: str) -> bytes:
    stream = archive.extractfile(name)
    if stream is None:
        raise SystemExit(f"sdist member is not a readable file: {name}")
    return stream.read()


def _verify_evidence_checksums(archive: tarfile.TarFile, names: set[str]) -> None:
    manifest_name = _matching_member(names, "examples/generated/SHA256SUMS")
    try:
        manifest = _read_tar_member(archive, manifest_name).decode("ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit("evidence checksum manifest is not ASCII") from exc

    checksums: dict[str, str] = {}
    for line in manifest.splitlines():
        match = _CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise SystemExit(f"invalid evidence checksum line: {line!r}")
        digest, relative_path = match.groups()
        if relative_path in checksums:
            raise SystemExit(f"duplicate evidence checksum path: {relative_path}")
        checksums[relative_path] = digest

    listed_paths = set(checksums)
    if listed_paths != _EVIDENCE_CHECKSUM_PATHS:
        missing = sorted(_EVIDENCE_CHECKSUM_PATHS - listed_paths)
        unexpected = sorted(listed_paths - _EVIDENCE_CHECKSUM_PATHS)
        raise SystemExit(
            f"evidence checksum coverage mismatch; missing={missing}, unexpected={unexpected}"
        )

    for relative_path, expected_digest in checksums.items():
        member_name = _matching_member(names, f"examples/generated/{relative_path}")
        data = _read_tar_member(archive, member_name)
        if relative_path.endswith(".png") and not data.startswith(_PNG_SIGNATURE):
            raise SystemExit(f"evidence screenshot is not PNG data: {relative_path}")
        actual_digest = hashlib.sha256(data).hexdigest()
        if actual_digest != expected_digest:
            raise SystemExit(
                f"evidence checksum mismatch for {relative_path}: "
                f"expected {expected_digest}, got {actual_digest}"
            )


def verify_sdist(path: str) -> None:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        unsafe = [
            member.name
            for member in members
            if _unsafe_path(member.name) or member.issym() or member.islnk() or member.isdev()
        ]
        if unsafe:
            raise SystemExit(f"sdist contains unsafe build state: {unsafe[:5]}")
        names = {member.name for member in members}
        missing = sorted(
            suffix
            for suffix in _SDIST_REQUIRED_SUFFIXES
            if not any(name == suffix or name.endswith(f"/{suffix}") for name in names)
        )
        if missing:
            raise SystemExit(f"sdist is missing required release assets: {missing}")
        for member in members:
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            if stream is None:
                continue
            problem = _unsafe_content(stream.read())
            if problem is not None:
                raise SystemExit(f"sdist contains {problem}: {member.name}")
        _verify_evidence_checksums(archive, names)


def verify_wheel(path: str) -> None:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        unsafe = [name for name in names if _unsafe_path(name)]
        if unsafe:
            raise SystemExit(f"wheel contains unsafe build state: {unsafe[:5]}")
        missing = sorted(_WHEEL_REQUIRED_PATHS - names)
        if missing:
            raise SystemExit(f"wheel is missing required runtime assets: {missing}")
        for name in names:
            if name.endswith("/"):
                continue
            problem = _unsafe_content(archive.read(name))
            if problem is not None:
                raise SystemExit(f"wheel contains {problem}: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdist", required=True)
    parser.add_argument("--wheel", required=True)
    args = parser.parse_args()
    verify_sdist(args.sdist)
    verify_wheel(args.wheel)
    print("Release archives contain the required assets and no local build state.")


if __name__ == "__main__":
    main()
