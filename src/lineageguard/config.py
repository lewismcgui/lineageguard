"""Validated runtime configuration with secret-safe diagnostics."""

from __future__ import annotations

import os
import shlex
import stat
import sys
from pathlib import Path
from typing import Annotated

from pydantic import AliasChoices, Field, HttpUrl, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _default_mcp_command() -> str:
    executable = Path(sys.executable)
    candidates = (
        executable.parent / "mcp-server-datahub",
        executable.resolve().parent / "mcp-server-datahub",
    )
    return next(
        (str(candidate) for candidate in candidates if candidate.is_file()), "mcp-server-datahub"
    )


def _token_parent_chain(path: Path, *, anchor: Path | None) -> tuple[Path, ...]:
    """Return the lexical parent chain without resolving symbolic links."""
    chain = tuple(reversed((path.parent, *path.parent.parents)))
    if anchor is None:
        return chain
    try:
        start = chain.index(anchor)
    except ValueError as exc:
        raise ValueError("DataHub token path must stay below the project root") from exc
    return chain[start:]


def _validate_token_parents(path: Path, *, anchor: Path | None) -> None:
    """Reject parent links and directories another account could replace."""
    current_uid = os.getuid() if hasattr(os, "getuid") else None
    for directory in _token_parent_chain(path, anchor=anchor):
        try:
            metadata = directory.lstat()
        except FileNotFoundError:
            # A missing parent means the token file is absent. Deeper parents
            # cannot exist without this component, so the eventual open will
            # safely return the normal missing-token result.
            return
        except OSError as exc:
            raise ValueError(f"DataHub token directory is unavailable: {directory}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"DataHub token path parent must not be a symbolic link: {directory}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(
                f"DataHub token path parent must be an owner-controlled directory: {directory}"
            )
        if current_uid is None:
            continue

        mode = stat.S_IMODE(metadata.st_mode)
        if anchor is not None:
            controlled = metadata.st_uid == current_uid and not mode & 0o022
        else:
            # Absolute token paths retain support for root-owned system
            # prefixes. A sticky root-owned directory such as /private/tmp is
            # safe as an ancestor, but the token's immediate parent is checked
            # below and must be controlled by the current user.
            controlled = (metadata.st_uid == current_uid and not mode & 0o022) or (
                metadata.st_uid == 0 and (not mode & 0o022 or bool(mode & stat.S_ISVTX))
            )
        if not controlled:
            raise ValueError(
                f"DataHub token path parent must be an owner-controlled directory: {directory}"
            )

    if current_uid is not None:
        try:
            parent_metadata = path.parent.lstat()
        except FileNotFoundError:
            return
        if parent_metadata.st_uid != current_uid or stat.S_IMODE(parent_metadata.st_mode) & 0o022:
            raise ValueError(
                f"DataHub token file parent must be controlled by the current user: {path.parent}"
            )


class Settings(BaseSettings):
    """LineageGuard settings loaded from explicit values and environment variables."""

    model_config = SettingsConfigDict(
        env_file=None,
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    datahub_gms_url: HttpUrl = Field(
        default=HttpUrl("http://127.0.0.1:8080"),
        validation_alias=AliasChoices("DATAHUB_GMS_URL", "LINEAGEGUARD_DATAHUB_GMS_URL"),
    )
    datahub_gms_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("DATAHUB_GMS_TOKEN", "LINEAGEGUARD_DATAHUB_GMS_TOKEN"),
    )
    datahub_gms_token_file: Path | None = Field(
        default=Path(".lineageguard/datahub-token"),
        validation_alias=AliasChoices(
            "DATAHUB_GMS_TOKEN_FILE", "LINEAGEGUARD_DATAHUB_GMS_TOKEN_FILE"
        ),
    )
    datahub_frontend_url: HttpUrl = Field(
        default=HttpUrl("http://127.0.0.1:9002"),
        validation_alias=AliasChoices("DATAHUB_FRONTEND_URL", "LINEAGEGUARD_DATAHUB_FRONTEND_URL"),
    )
    mcp_command: str = Field(
        default_factory=_default_mcp_command, validation_alias="LINEAGEGUARD_MCP_COMMAND"
    )
    mcp_args: Annotated[tuple[str, ...], NoDecode] = Field(
        default=(), validation_alias="LINEAGEGUARD_MCP_ARGS"
    )
    mcp_timeout_seconds: float = Field(
        default=30.0, gt=0, le=300, validation_alias="LINEAGEGUARD_MCP_TIMEOUT_SECONDS"
    )
    mcp_mutations: bool = Field(default=False, validation_alias="LINEAGEGUARD_MCP_MUTATIONS")
    mcp_max_read_attempts: int = Field(
        default=3, ge=1, le=5, validation_alias="LINEAGEGUARD_MCP_MAX_READ_ATTEMPTS"
    )
    project_root: Path = Field(
        default_factory=lambda: Path.cwd(), validation_alias="LINEAGEGUARD_PROJECT_ROOT"
    )

    @field_validator("datahub_gms_token", mode="before")
    @classmethod
    def blank_token_is_absent(cls, value: object) -> object:
        """Let a blank optional environment variable fall through to the token file."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("datahub_gms_url", "datahub_frontend_url")
    @classmethod
    def datahub_urls_reject_user_information(cls, value: HttpUrl) -> HttpUrl:
        if value.username is not None or value.password is not None:
            raise ValueError("DataHub URL must not contain user information")
        return value

    @field_validator("datahub_gms_url")
    @classmethod
    def remote_gms_requires_https(cls, value: HttpUrl) -> HttpUrl:
        if value.host not in {"localhost", "127.0.0.1", "::1"} and value.scheme != "https":
            raise ValueError("Non-loopback DataHub GMS URLs must use HTTPS")
        return value

    @field_validator("mcp_args", mode="before")
    @classmethod
    def parse_mcp_args(cls, value: object) -> object:
        """Parse shell-like args without ever invoking a shell."""
        if isinstance(value, str):
            return tuple(shlex.split(value))
        return value

    def mcp_environment(self) -> dict[str, str]:
        """Build the official server environment while preserving executable lookup."""
        allowed = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "VIRTUAL_ENV")
        env = {key: os.environ[key] for key in allowed if key in os.environ}
        env["DATAHUB_GMS_URL"] = str(self.datahub_gms_url).rstrip("/")
        token = self.resolve_datahub_token()
        if token is not None:
            env["DATAHUB_GMS_TOKEN"] = token
        else:
            env.pop("DATAHUB_GMS_TOKEN", None)
        # LineageGuard performs immediate semantic readback. The SDK default,
        # SYNC_PRIMARY, can return before search-backed document projections
        # converge; SYNC_WAIT makes the official server wait for both stores.
        env["DATAHUB_EMIT_MODE"] = "SYNC_WAIT"
        env["TOOLS_IS_MUTATION_ENABLED"] = "true" if self.mcp_mutations else "false"
        env["TOOLS_IS_USER_ENABLED"] = "false"
        return env

    def resolve_datahub_token(self) -> str | None:
        """Resolve a token from env or a private file without logging its contents."""
        if self.datahub_gms_token is not None:
            return self.datahub_gms_token.get_secret_value()
        if self.datahub_gms_token_file is None:
            return None
        configured_path = self.datahub_gms_token_file.expanduser()
        if ".." in configured_path.parts:
            raise ValueError("DataHub token path must not contain parent traversal")
        if configured_path.is_absolute():
            path = configured_path
            anchor = None
        else:
            anchor = self.project_root.expanduser()
            if not anchor.is_absolute():
                anchor = Path.cwd() / anchor
            if ".." in anchor.parts:
                raise ValueError("DataHub project root must not contain parent traversal")
            path = anchor / configured_path
        _validate_token_parents(path, anchor=anchor)
        if path.is_symlink():
            raise ValueError(f"DataHub token file must not be a symbolic link: {path}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ValueError(f"DataHub token file is unavailable: {path}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"DataHub token path must be a regular file: {path}")
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ValueError(f"DataHub token file permissions must be 0600: {path}")
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise ValueError(f"DataHub token file must be owned by the current user: {path}")
            if metadata.st_size > 8192:
                raise ValueError(f"DataHub token file is too large: {path}")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                raw = stream.read(8193)
            token = raw.decode("utf-8").strip()
        except (OSError, UnicodeError) as exc:
            raise ValueError(f"DataHub token file is unreadable: {path}") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(raw) > 8192:
            raise ValueError(f"DataHub token file is too large: {path}")
        if not token:
            raise ValueError(f"DataHub token file is empty: {path}")
        return token

    def safe_summary(self) -> dict[str, object]:
        """Return configuration suitable for logs and generated evidence."""
        return {
            "datahub_gms_url": str(self.datahub_gms_url).rstrip("/"),
            "datahub_frontend_url": str(self.datahub_frontend_url).rstrip("/"),
            "has_datahub_token": self.datahub_gms_token is not None
            or self.datahub_gms_token_file is not None,
            "datahub_token_source": (
                "environment"
                if self.datahub_gms_token is not None
                else "file"
                if self.datahub_gms_token_file is not None
                else "missing"
            ),
            "mcp_command": self.mcp_command,
            "mcp_arg_count": len(self.mcp_args),
            "mcp_timeout_seconds": self.mcp_timeout_seconds,
            "mcp_mutations": self.mcp_mutations,
        }
