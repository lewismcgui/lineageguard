"""Local-only DataHub access-token bootstrap helpers."""

from __future__ import annotations

import base64
import binascii
import fcntl
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import httpx

CREATE_TOKEN_MUTATION = """
mutation CreateLineageGuardToken($input: CreateAccessTokenInput!) {
  createAccessToken(input: $input) {
    accessToken
  }
}
""".strip()
REVOKE_TOKEN_MUTATION = """
mutation RevokeLineageGuardToken($tokenId: String!) {
  revokeAccessToken(tokenId: $tokenId)
}
""".strip()
AUTH_PROBE_PATH = (
    "/aspects/urn%3Ali%3AdataPlatform%3Alineageguard-token-check?aspect=dataPlatformKey&version=0"
)
_AUTH_CONTROL_VALUE = "lineageguard-control-token-not-a-jwt"
_TOKEN_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


class TokenBootstrapError(RuntimeError):
    """A local DataHub token could not be generated or stored safely."""


class TokenEnsureStatus(StrEnum):
    """Outcome of ensuring a usable private local token."""

    CREATED = "CREATED"
    REUSED = "REUSED"
    REUSED_UNVERIFIABLE = "REUSED_UNVERIFIABLE"
    REPLACED = "REPLACED"


class TokenValidationStatus(StrEnum):
    """Whether GMS proved a bearer, rejected it, or did not enforce auth."""

    VALID = "VALID"
    INVALID = "INVALID"
    AUTH_DISABLED_OR_UNVERIFIABLE = "AUTH_DISABLED_OR_UNVERIFIABLE"


@dataclass(frozen=True, slots=True)
class TokenEnsureResult:
    status: TokenEnsureStatus
    path: Path


def _login(
    client: httpx.Client,
    frontend_url: str,
    *,
    username: str,
    password: str,
) -> None:
    if not username or not password:
        raise TokenBootstrapError("Local DataHub login credentials are required")
    login_endpoint = _loopback_endpoint(frontend_url, "/logIn", service="frontend")
    login_response = client.post(
        login_endpoint,
        json={"username": username, "password": password},
    )
    if login_response.status_code != 200:
        raise TokenBootstrapError("DataHub rejected the local login")
    if not client.cookies:
        raise TokenBootstrapError("DataHub local login returned no session")


def _loopback_endpoint(base_url: str, path: str, *, service: str) -> str:
    """Build a local HTTP endpoint without accepting URL-borne credentials."""

    try:
        parsed = httpx.URL(base_url)
    except (httpx.InvalidURL, TypeError, ValueError) as exc:
        raise TokenBootstrapError(f"Local DataHub {service} URL is invalid") from exc
    if parsed.scheme not in {"http", "https"}:
        raise TokenBootstrapError(f"Local DataHub {service} URL must use HTTP or HTTPS")
    if parsed.host not in {"localhost", "127.0.0.1", "::1"}:
        raise TokenBootstrapError(f"Local DataHub {service} URL must use loopback")
    if parsed.username or parsed.password:
        raise TokenBootstrapError(f"Local DataHub {service} URL must not contain credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise TokenBootstrapError(
            f"Local DataHub {service} URL must not contain a path, query, or fragment"
        )
    return f"{str(parsed).rstrip('/')}/{path.lstrip('/')}"


def create_local_token(
    frontend_url: str,
    *,
    username: str,
    password: str,
    timeout_seconds: float = 15.0,
) -> str:
    """Create a one-month PAT through an authenticated local frontend session."""

    graphql_endpoint = _loopback_endpoint(frontend_url, "/api/v2/graphql", service="frontend")
    try:
        with httpx.Client(
            timeout=timeout_seconds,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            _login(client, frontend_url, username=username, password=password)
            response = client.post(
                graphql_endpoint,
                json={
                    "query": CREATE_TOKEN_MUTATION,
                    "variables": {
                        "input": {
                            "type": "PERSONAL",
                            "actorUrn": f"urn:li:corpuser:{username}",
                            "duration": "ONE_MONTH",
                            "name": "LineageGuard local MCP",
                            "description": "Local hackathon development token",
                        }
                    },
                },
            )
        if response.status_code != 200:
            raise TokenBootstrapError("DataHub token request failed")
        payload = response.json()
    except TokenBootstrapError:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise TokenBootstrapError("DataHub token request failed") from exc

    if not isinstance(payload, Mapping):
        raise TokenBootstrapError("DataHub returned no access token")
    if payload.get("errors"):
        raise TokenBootstrapError("DataHub rejected the local token request")
    try:
        token = payload["data"]["createAccessToken"]["accessToken"]
    except (KeyError, TypeError) as exc:
        raise TokenBootstrapError("DataHub returned no access token") from exc
    if not isinstance(token, str) or not token:
        raise TokenBootstrapError("DataHub returned an invalid access token")
    return token


def token_revocation_id(token: str) -> str | None:
    """Read the non-secret DataHub registry ID carried by an issued PAT JWT."""

    parts = token.split(".")
    if len(parts) != 3:
        return None
    encoded_payload = parts[1]
    try:
        raw = base64.urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4))
        payload = json.loads(raw)
    except (binascii.Error, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, Mapping):
        return None
    token_id = payload.get("jti")
    if not isinstance(token_id, str) or _TOKEN_ID.fullmatch(token_id) is None:
        return None
    return token_id


def revoke_local_token(
    frontend_url: str,
    token_id: str,
    *,
    username: str,
    password: str,
    timeout_seconds: float = 15.0,
) -> None:
    """Revoke one exact local PAT through an authenticated frontend session."""

    if _TOKEN_ID.fullmatch(token_id) is None:
        raise TokenBootstrapError("DataHub token revocation ID is invalid")
    graphql_endpoint = _loopback_endpoint(frontend_url, "/api/v2/graphql", service="frontend")
    try:
        with httpx.Client(
            timeout=timeout_seconds,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            _login(client, frontend_url, username=username, password=password)
            response = client.post(
                graphql_endpoint,
                json={
                    "query": REVOKE_TOKEN_MUTATION,
                    "variables": {"tokenId": token_id},
                },
            )
        if response.status_code != 200:
            raise TokenBootstrapError("DataHub token revocation request failed")
        payload = response.json()
    except TokenBootstrapError:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise TokenBootstrapError("DataHub token revocation request failed") from exc

    if (
        not isinstance(payload, Mapping)
        or payload.get("errors")
        or not isinstance(payload.get("data"), Mapping)
        or payload["data"].get("revokeAccessToken") is not True
    ):
        raise TokenBootstrapError("DataHub did not confirm token revocation")


def _token_destination(path: Path) -> Path:
    expanded = path.expanduser()
    if ".." in expanded.parts:
        raise TokenBootstrapError("Token path must not contain parent traversal")
    if expanded.is_absolute():
        destination = expanded
        anchor = None
    else:
        anchor = Path.cwd()
        destination = anchor / expanded

    chain = tuple(reversed((destination.parent, *destination.parent.parents)))
    if anchor is not None:
        try:
            chain = chain[chain.index(anchor) :]
        except ValueError as exc:
            raise TokenBootstrapError("Token path must stay below the project root") from exc

    current_uid = os.getuid() if hasattr(os, "getuid") else None
    for directory in chain:
        try:
            metadata = directory.lstat()
        except FileNotFoundError:
            try:
                directory.mkdir(mode=0o700)
                metadata = directory.lstat()
            except OSError as exc:
                raise TokenBootstrapError("Token directory is unavailable") from exc
        except OSError as exc:
            raise TokenBootstrapError("Token directory is unavailable") from exc

        if stat.S_ISLNK(metadata.st_mode):
            raise TokenBootstrapError("Token path parent must not be a symbolic link")
        if not stat.S_ISDIR(metadata.st_mode):
            raise TokenBootstrapError("Token path parent must be an owner-controlled directory")
        if current_uid is None:
            continue

        mode = stat.S_IMODE(metadata.st_mode)
        if anchor is not None:
            controlled = metadata.st_uid == current_uid and not mode & 0o022
        else:
            controlled = (metadata.st_uid == current_uid and not mode & 0o022) or (
                metadata.st_uid == 0 and (not mode & 0o022 or bool(mode & stat.S_ISVTX))
            )
        if not controlled:
            raise TokenBootstrapError("Token path parent must be an owner-controlled directory")

    if current_uid is not None:
        parent_metadata = destination.parent.lstat()
        if parent_metadata.st_uid != current_uid or stat.S_IMODE(parent_metadata.st_mode) & 0o022:
            raise TokenBootstrapError("Token file parent must be controlled by the current user")
    if destination.is_symlink():
        raise TokenBootstrapError("Token path must not be a symbolic link")
    return destination


@contextmanager
def token_bootstrap_lock(path: Path) -> Iterator[Path]:
    """Serialize token lifecycle changes through a persistent private lock file."""

    destination = _token_destination(path)
    lock_path = destination.with_name(f".{destination.name}.bootstrap.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(lock_path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise TokenBootstrapError("Token bootstrap lock must be a regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise TokenBootstrapError("Token bootstrap lock permissions must be 0600")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise TokenBootstrapError("Token bootstrap lock must be owned by the current user")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except TokenBootstrapError:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        raise TokenBootstrapError("Token bootstrap lock is unavailable") from exc

    try:
        yield destination
    finally:
        with suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        with suppress(OSError):
            os.close(descriptor)


def preflight_private_token(path: Path, *, overwrite: bool = False) -> Path:
    """Prove the private destination is available before minting a remote PAT."""

    destination = _token_destination(path)
    if destination.exists():
        metadata = destination.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise TokenBootstrapError("Token path must be a regular file")
        if not overwrite:
            raise TokenBootstrapError(f"Token file already exists: {destination}")

    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.preflight.", dir=destination.parent
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
    except OSError as exc:
        raise TokenBootstrapError("Token destination is not writable") from exc
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination


def read_private_token(path: Path) -> str:
    """Read a regular owner-only token file without exposing its value."""

    destination = _token_destination(path)
    if destination.is_symlink():
        raise TokenBootstrapError("Token path must not be a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(destination, flags)
    except OSError as exc:
        raise TokenBootstrapError("Token file is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise TokenBootstrapError("Token path must be a regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise TokenBootstrapError("Token file permissions must be 0600")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise TokenBootstrapError("Token file must be owned by the current user")
        if metadata.st_size > 8192:
            raise TokenBootstrapError("Token file is too large")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(8193)
        token = raw.decode("utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise TokenBootstrapError("Token file is unreadable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > 8192:
        raise TokenBootstrapError("Token file is too large")
    if not token:
        raise TokenBootstrapError("Token file is empty")
    return token


def validate_local_token(
    gms_url: str,
    token: str,
    *,
    timeout_seconds: float = 10.0,
) -> TokenValidationStatus:
    """Prove a bearer by comparing it with a deliberately invalid control.

    Transient failures and unexpected services raise so callers preserve the
    existing credential rather than rotating it speculatively. If GMS accepts
    both bearers, authentication is disabled or the probe is not authoritative.
    """

    config_endpoint = _loopback_endpoint(gms_url, "/config", service="GMS")
    probe_endpoint = _loopback_endpoint(gms_url, AUTH_PROBE_PATH, service="GMS")
    try:
        with httpx.Client(timeout=timeout_seconds, trust_env=False) as client:
            response = client.get(
                config_endpoint,
                headers={"Authorization": f"Bearer {token}"},
            )
            if response.status_code == 401:
                return TokenValidationStatus.INVALID
            if response.status_code != 200:
                raise TokenBootstrapError("DataHub token validation returned an unexpected status")
            try:
                payload: Any = response.json()
            except ValueError:
                raise TokenBootstrapError(
                    "DataHub token validation returned invalid JSON"
                ) from None
            if not isinstance(payload, dict) or payload.get("noCode") != "true":
                raise TokenBootstrapError("DataHub token validation reached an unexpected service")

            response = client.get(
                probe_endpoint,
                headers={"Authorization": f"Bearer {token}"},
            )
            if response.status_code == 401:
                return TokenValidationStatus.INVALID
            if response.status_code not in {200, 404}:
                raise TokenBootstrapError("DataHub token validation returned an unexpected status")
            control_response = client.get(
                probe_endpoint,
                headers={"Authorization": f"Bearer {_AUTH_CONTROL_VALUE}"},
            )
    except httpx.HTTPError:
        raise TokenBootstrapError("DataHub token validation could not reach GMS") from None
    if control_response.status_code == 401:
        return TokenValidationStatus.VALID
    if control_response.status_code in {200, 404}:
        return TokenValidationStatus.AUTH_DISABLED_OR_UNVERIFIABLE
    raise TokenBootstrapError("DataHub token validation returned an unexpected status")


def _store_minted_token(
    destination: Path,
    token: str,
    *,
    frontend_url: str,
    username: str,
    password: str,
    overwrite: bool,
) -> None:
    """Store a new PAT, revoking it if durable storage cannot complete."""

    try:
        write_private_token(destination, token, overwrite=overwrite)
    except BaseException as storage_error:
        token_id = token_revocation_id(token)
        if token_id is None:
            raise TokenBootstrapError(
                "Token storage failed and the new PAT requires manual revocation"
            ) from storage_error
        try:
            revoke_local_token(
                frontend_url,
                token_id,
                username=username,
                password=password,
            )
        except TokenBootstrapError as revocation_error:
            raise TokenBootstrapError(
                "Token storage failed and new PAT revocation could not be confirmed"
            ) from revocation_error
        if not isinstance(storage_error, Exception):
            raise
        raise TokenBootstrapError(
            "Token storage failed; the newly minted PAT was revoked"
        ) from storage_error


def _mint_and_store(
    destination: Path,
    frontend_url: str,
    *,
    credential_provider: Callable[[], tuple[str, str]],
    overwrite: bool,
) -> None:
    preflight_private_token(destination, overwrite=overwrite)
    username, password = credential_provider()
    token = create_local_token(frontend_url, username=username, password=password)
    _store_minted_token(
        destination,
        token,
        frontend_url=frontend_url,
        username=username,
        password=password,
        overwrite=overwrite,
    )


def create_private_local_token(
    path: Path,
    frontend_url: str,
    *,
    credential_provider: Callable[[], tuple[str, str]],
) -> TokenEnsureResult:
    """Create one new private token without racing another bootstrap process."""

    with token_bootstrap_lock(path) as destination:
        _mint_and_store(
            destination,
            frontend_url,
            credential_provider=credential_provider,
            overwrite=False,
        )
    return TokenEnsureResult(TokenEnsureStatus.CREATED, destination)


def ensure_local_token(
    path: Path,
    gms_url: str,
    frontend_url: str,
    *,
    credential_provider: Callable[[], tuple[str, str]],
    force: bool = False,
) -> TokenEnsureResult:
    """Create, reuse, or definitively replace a local DataHub token."""

    # Validate the always-used GMS destination even when no token exists yet;
    # otherwise a local frontend token could be forwarded to a configured
    # remote service by the caller after bootstrap returns.
    _loopback_endpoint(gms_url, "/config", service="GMS")
    with token_bootstrap_lock(path) as destination:
        if not destination.exists():
            _mint_and_store(
                destination,
                frontend_url,
                credential_provider=credential_provider,
                overwrite=False,
            )
            return TokenEnsureResult(TokenEnsureStatus.CREATED, destination)

        current = read_private_token(destination)
        validation = validate_local_token(gms_url, current)
        if validation is TokenValidationStatus.VALID:
            if force:
                raise TokenBootstrapError(
                    "Refusing to force-replace a valid PAT; revoke it explicitly first"
                )
            return TokenEnsureResult(TokenEnsureStatus.REUSED, destination)
        if validation is TokenValidationStatus.AUTH_DISABLED_OR_UNVERIFIABLE:
            if force:
                raise TokenBootstrapError(
                    "Refusing to force-replace a PAT while authentication is unverifiable"
                )
            return TokenEnsureResult(TokenEnsureStatus.REUSED_UNVERIFIABLE, destination)

        _mint_and_store(
            destination,
            frontend_url,
            credential_provider=credential_provider,
            overwrite=True,
        )
        return TokenEnsureResult(TokenEnsureStatus.REPLACED, destination)


def write_private_token(path: Path, token: str, *, overwrite: bool = False) -> None:
    """Atomically store a token with owner-only permissions."""
    if not token:
        raise TokenBootstrapError("Refusing to store an empty token")
    destination = _token_destination(path)
    if destination.exists() and not overwrite:
        raise TokenBootstrapError(f"Token file already exists: {destination}")
    if destination.exists():
        metadata = destination.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise TokenBootstrapError("Token path must be a regular file")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(token)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        directory_descriptor = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
