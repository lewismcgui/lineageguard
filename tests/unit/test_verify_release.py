from __future__ import annotations

import hashlib
import io
import runpy
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

SCRIPT = Path(__file__).parents[2] / "scripts/verify-release.py"
SCRIPT_GLOBALS = runpy.run_path(str(SCRIPT))
_unsafe_content = cast(Callable[[bytes], str | None], SCRIPT_GLOBALS["_unsafe_content"])
_verify_evidence_checksums = cast(
    Callable[[tarfile.TarFile, set[str]], None],
    SCRIPT_GLOBALS["_verify_evidence_checksums"],
)
_EVIDENCE_CHECKSUM_PATHS = cast(frozenset[str], SCRIPT_GLOBALS["_EVIDENCE_CHECKSUM_PATHS"])
_SDIST_REQUIRED_SUFFIXES = cast(frozenset[str], SCRIPT_GLOBALS["_SDIST_REQUIRED_SUFFIXES"])
_WHEEL_REQUIRED_PATHS = cast(frozenset[str], SCRIPT_GLOBALS["_WHEEL_REQUIRED_PATHS"])


def test_release_verifier_requires_every_retained_evidence_file() -> None:
    assert {
        "demo-preflight.json",
        "report.html",
        "report.json",
        "report.md",
        "screenshots/datahub-decision-state.png",
        "screenshots/datahub-lineage.png",
        "screenshots/datahub-writeback-verified.png",
        "screenshots/report-overview.png",
    } == _EVIDENCE_CHECKSUM_PATHS


def test_release_verifier_requires_runnable_sdist_and_complete_wheel_assets() -> None:
    assert {
        "Makefile",
        "pyproject.toml",
        "scripts/create-local-token.py",
        "scripts/datahub-preflight.sh",
        "scripts/datahub-quickstart.py",
        "scripts/datahub-up.sh",
        "scripts/demo.sh",
        "scripts/seed-datahub-demo.py",
        "src/lineageguard/cli.py",
        "src/lineageguard/review_ui/static/index.html",
        "src/lineageguard/review_ui/static/review.css",
        "src/lineageguard/review_ui/static/review.js",
    }.issubset(_SDIST_REQUIRED_SUFFIXES)
    assert {
        "lineageguard/cli.py",
        "lineageguard/review_ui/static/index.html",
        "lineageguard/review_ui/static/review.css",
        "lineageguard/review_ui/static/review.js",
        "lineageguard/bundled/demo/acme_dbt/models/marts/fct_daily_revenue.sql",
        "lineageguard/bundled/demo/acme_dbt/scenario/proposed/models/staging/schema.yml",
        "lineageguard/bundled/demo/acme_dbt/seeds/orders.csv",
        "lineageguard/bundled/demo/acme_dbt/tests/assert_daily_revenue_reconciles.sql",
    }.issubset(_WHEEL_REQUIRED_PATHS)


def _evidence_archive(*, omitted_path: str | None = None) -> io.BytesIO:
    payloads = {
        path: (b"\x89PNG\r\n\x1a\nfixture" if path.endswith(".png") else b"fixture")
        for path in _EVIDENCE_CHECKSUM_PATHS
    }
    manifest = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {path}\n" for path, data in sorted(payloads.items())
    ).encode("ascii")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for path, data in {"SHA256SUMS": manifest, **payloads}.items():
            if path == omitted_path:
                continue
            member = tarfile.TarInfo(f"package/examples/generated/{path}")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    stream.seek(0)
    return stream


def test_evidence_verifier_checks_archive_members_not_only_manifest_paths() -> None:
    stream = _evidence_archive(omitted_path="screenshots/datahub-decision-state.png")
    with tarfile.open(fileobj=stream, mode="r:gz") as archive:
        names = {member.name for member in archive.getmembers()}
        with pytest.raises(SystemExit, match="does not contain exactly one"):
            _verify_evidence_checksums(archive, names)


@pytest.mark.parametrize(
    "content",
    [
        b"eyJ" + b"a" * 24 + b"." + b"b" * 24 + b"." + b"c" * 24,
        b"datahub_" + b"pat_" + b"Ab9_" * 8,
        b"AK" + b"IA" + b"A1B2C3D4E5F6G7H8",
        b"Authorization: Bearer " + b"Ab9._-" * 6,
        b'access_token="' + b"Zx9_" * 8 + b'"',
        b'SERVICE_TOKEN="' + b"Q7x_" * 8 + b'"',
        b'aws_secret_access_key="' + b"aB9/" * 10 + b'"',
    ],
)
def test_release_scanner_rejects_extended_credential_shapes(content: bytes) -> None:
    assert _unsafe_content(content) == "credential-shaped content"


def test_release_scanner_rejects_personal_email_addresses() -> None:
    content = b"lewis" + b"@" + b"personalmail.co.uk"

    assert _unsafe_content(content) == "a personal email-shaped address"


@pytest.mark.parametrize(
    "content",
    [
        b"finance-analytics@example.invalid",
        b"user@subdomain.example.com",
        b"security@real-company.io",
        b"https://user:pass@datahub.example.com",
        b"Authorization: Bearer ${DATAHUB_GMS_TOKEN}",
        b'token = "generated-local-value"',
        b'api_key = "replace-with-a-real-key"',
    ],
)
def test_release_scanner_allows_reserved_addresses_and_obvious_placeholders(
    content: bytes,
) -> None:
    assert _unsafe_content(content) is None
