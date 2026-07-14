"""FastAPI serving layer for the local LineageGuard change flight recorder."""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import stat
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Final

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from lineageguard.run_models import RunResult, calculate_artifact_hash, run_result_payload

DEFAULT_RUN_ARTIFACT: Final = Path(".lineageguard/runs/latest.json")
MAX_RUN_ARTIFACT_BYTES: Final = 5 * 1024 * 1024
STATIC_DIRECTORY: Final = Path(__file__).with_name("static")

_SECURITY_HEADERS: Final = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "base-uri 'none'; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}
_ARTIFACT_HASH: Final = re.compile(r"^[0-9a-f]{64}$")
_DNS_LABEL: Final = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _api_error(status_code: int, status: str, message: str) -> JSONResponse:
    """Build a stable, detail-safe API error payload."""

    return JSONResponse(
        status_code=status_code,
        content={"status": status, "message": message},
    )


def _reject_nonstandard_number(value: str) -> None:
    """Reject NaN and infinities, which are not valid JSON values."""

    raise ValueError(f"non-standard JSON number: {value}")


def _read_artifact(path: Path) -> object:
    """Read a bounded UTF-8 JSON artifact without changing it."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise IsADirectoryError("run artifact must be a regular file")
        if metadata.st_size > MAX_RUN_ARTIFACT_BYTES:
            raise OverflowError("run artifact exceeds the local review limit")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(MAX_RUN_ARTIFACT_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > MAX_RUN_ARTIFACT_BYTES:
        raise OverflowError("run artifact exceeds the local review limit")
    return json.loads(raw.decode("utf-8"), parse_constant=_reject_nonstandard_number)


def _validated_artifact(payload: object) -> dict[str, object]:
    """Validate the typed run contract and its non-signing integrity seal."""

    try:
        result = RunResult.model_validate(payload)
    except ValidationError as exc:
        raise ValueError("run artifact schema is invalid") from exc
    observed = result.artifact_hash
    if (
        result.schema_version not in {"1.0", "1.1"}
        or not isinstance(observed, str)
        or _ARTIFACT_HASH.fullmatch(observed) is None
        or not hmac.compare_digest(observed, calculate_artifact_hash(result))
    ):
        raise ValueError("run artifact seal is invalid")
    return run_result_payload(result)


def _allowed_hosts() -> list[str]:
    configured = os.environ.get("LINEAGEGUARD_ALLOWED_HOSTS", "")
    hosts = [host.strip() for host in configured.split(",") if host.strip()]
    if len(hosts) > 10:
        raise ValueError("LINEAGEGUARD_ALLOWED_HOSTS permits at most 10 exact hosts")

    validated: list[str] = []
    for host in hosts:
        if "*" in host or len(host) > 253:
            raise ValueError("LINEAGEGUARD_ALLOWED_HOSTS requires exact safe host names")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            labels = host.split(".")
            if not labels or any(_DNS_LABEL.fullmatch(label) is None for label in labels):
                raise ValueError("LINEAGEGUARD_ALLOWED_HOSTS contains an unsafe host") from None
            normalized = host.casefold()
        else:
            if address.version != 4:
                raise ValueError("LINEAGEGUARD_ALLOWED_HOSTS permits exact IPv4 hosts only")
            normalized = str(address)
        if normalized not in validated:
            validated.append(normalized)
    return ["127.0.0.1", "localhost", "testserver", *validated]


def create_app(run_artifact: Path | None = None) -> FastAPI:
    """Create a read-only local review app bound to one latest-run path."""

    configured_artifact = os.environ.get("LINEAGEGUARD_RUN_ARTIFACT")
    artifact_path = (
        Path(configured_artifact)
        if run_artifact is None and configured_artifact
        else Path.cwd() / DEFAULT_RUN_ARTIFACT
        if run_artifact is None
        else run_artifact
    )
    application = FastAPI(
        title="LineageGuard change flight recorder",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.run_artifact = artifact_path
    application.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=_allowed_hosts(),
    )
    application.mount(
        "/assets",
        StaticFiles(directory=STATIC_DIRECTORY),
        name="review-ui-assets",
    )

    @application.middleware("http")
    async def add_review_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    @application.get("/", include_in_schema=False)
    @application.get("/review", include_in_schema=False)
    def review_page() -> FileResponse:
        return FileResponse(STATIC_DIRECTORY / "index.html", media_type="text/html")

    @application.get("/healthz", include_in_schema=False)
    def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/api/runs/latest", include_in_schema=False)
    def latest_run() -> JSONResponse:
        try:
            payload = _validated_artifact(_read_artifact(application.state.run_artifact))
        except FileNotFoundError:
            return _api_error(
                404,
                "empty",
                "No local LineageGuard run has been recorded yet.",
            )
        except OverflowError:
            return _api_error(
                413,
                "error",
                "The latest run artifact is too large to review safely.",
            )
        except (IsADirectoryError, OSError):
            return _api_error(
                500,
                "error",
                "The latest run artifact could not be read.",
            )
        except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError):
            return _api_error(
                422,
                "error",
                "The latest run artifact is not a valid sealed LineageGuard run.",
            )
        return JSONResponse(content={"status": "ready", "run": payload})

    return application


app = create_app()

__all__ = [
    "DEFAULT_RUN_ARTIFACT",
    "MAX_RUN_ARTIFACT_BYTES",
    "app",
    "create_app",
]
