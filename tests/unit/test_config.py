from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from lineageguard.config import Settings, _default_mcp_command


def test_default_mcp_command_prefers_the_active_virtual_environment() -> None:
    command = Path(_default_mcp_command())

    assert command.name == "mcp-server-datahub"
    assert command.is_file()
    assert command.parent == Path(sys.executable).parent


def test_settings_parse_mcp_args_without_shell(monkeypatch) -> None:
    monkeypatch.setenv("LINEAGEGUARD_MCP_ARGS", 'mcp-server-datahub@0.6.0 --flag "two words"')
    settings = Settings(_env_file=None)
    assert settings.mcp_args == ("mcp-server-datahub@0.6.0", "--flag", "two words")


def test_safe_summary_never_exposes_token(monkeypatch) -> None:
    monkeypatch.setenv("DATAHUB_GMS_TOKEN", "super-secret-token")
    monkeypatch.setenv("LINEAGEGUARD_MCP_ARGS", "--token argument-secret --verbose")
    settings = Settings(_env_file=None)
    summary = settings.safe_summary()
    assert summary["has_datahub_token"] is True
    assert "super-secret-token" not in repr(summary)
    assert "super-secret-token" not in repr(settings)
    assert "argument-secret" not in repr(summary)
    assert summary["mcp_arg_count"] == 3


def test_mcp_environment_sets_explicit_mutation_mode(monkeypatch) -> None:
    expected = "unit-test-value"
    monkeypatch.setenv("DATAHUB_GMS_TOKEN", expected)
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-reach-subprocess")
    settings = Settings(_env_file=None, mcp_mutations=True)
    environment = settings.mcp_environment()
    assert environment["TOOLS_IS_MUTATION_ENABLED"] == "true"
    assert environment["DATAHUB_EMIT_MODE"] == "SYNC_WAIT"
    assert environment["DATAHUB_GMS_TOKEN"] == expected
    assert "UNRELATED_SECRET" not in environment


def test_token_file_requires_owner_only_permissions(tmp_path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("generated-local-value\n", encoding="utf-8")
    os.chmod(token_file, 0o644)
    settings = Settings(_env_file=None, datahub_gms_token_file=token_file)
    with pytest.raises(ValueError, match="0600"):
        settings.resolve_datahub_token()

    os.chmod(token_file, 0o600)
    assert settings.resolve_datahub_token() == "generated-local-value"


def test_token_file_rejects_symlinks_and_non_files(tmp_path) -> None:
    target = tmp_path / "target"
    target.write_text("generated-local-value\n", encoding="utf-8")
    os.chmod(target, 0o600)
    link = tmp_path / "token"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="symbolic link"):
        Settings(_env_file=None, datahub_gms_token_file=link).resolve_datahub_token()

    with pytest.raises(ValueError, match="regular file"):
        Settings(_env_file=None, datahub_gms_token_file=tmp_path).resolve_datahub_token()


def test_token_file_rejects_symlinked_parent_escape(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    token_file = outside / "datahub-token"
    token_file.write_text("outside-token\n", encoding="utf-8")
    os.chmod(token_file, 0o600)
    (project / ".lineageguard").symlink_to(outside, target_is_directory=True)

    settings = Settings(
        _env_file=None,
        project_root=project,
        datahub_gms_token_file=".lineageguard/datahub-token",
    )

    with pytest.raises(ValueError, match="parent must not be a symbolic link"):
        settings.resolve_datahub_token()


def test_missing_private_token_parent_is_an_absent_token(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    settings = Settings(
        _env_file=None,
        project_root=project,
        datahub_gms_token_file=".lineageguard/datahub-token",
    )

    assert settings.resolve_datahub_token() is None


def test_token_parent_component_must_be_a_directory(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".lineageguard").write_text("not a directory\n", encoding="utf-8")
    settings = Settings(
        _env_file=None,
        project_root=project,
        datahub_gms_token_file=".lineageguard/datahub-token",
    )

    with pytest.raises(ValueError, match="owner-controlled directory"):
        settings.resolve_datahub_token()


def test_token_file_rejects_writable_parent_directory(tmp_path) -> None:
    token_parent = tmp_path / "tokens"
    token_parent.mkdir()
    token_file = token_parent / "datahub-token"
    token_file.write_text("unsafe-parent-token\n", encoding="utf-8")
    os.chmod(token_file, 0o600)
    os.chmod(token_parent, 0o777)  # noqa: S103 - intentional unsafe fixture

    with pytest.raises(ValueError, match="owner-controlled directory"):
        Settings(_env_file=None, datahub_gms_token_file=token_file).resolve_datahub_token()


def test_blank_environment_token_falls_through_to_private_file(tmp_path, monkeypatch) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("file-token\n", encoding="utf-8")
    os.chmod(token_file, 0o600)
    monkeypatch.setenv("DATAHUB_GMS_TOKEN", "   ")

    settings = Settings(_env_file=None, datahub_gms_token_file=token_file)

    assert settings.resolve_datahub_token() == "file-token"


def test_settings_do_not_auto_load_untrusted_cwd_dotenv(tmp_path, monkeypatch) -> None:
    (tmp_path / ".env").write_text(
        "DATAHUB_GMS_TOKEN=from-untrusted-file\nLINEAGEGUARD_MCP_COMMAND=./malicious\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    settings = Settings()

    assert settings.datahub_gms_token is None
    assert settings.mcp_command != "./malicious"


def test_remote_gms_requires_https_and_rejects_url_credentials() -> None:
    with pytest.raises(ValueError, match="must use HTTPS"):
        Settings(_env_file=None, datahub_gms_url="http://datahub.example.com")
    with pytest.raises(ValueError, match="must not contain user information"):
        Settings(_env_file=None, datahub_gms_url="https://user:pass@datahub.example.com")
    with pytest.raises(ValueError, match="must not contain user information"):
        Settings(
            _env_file=None,
            datahub_frontend_url="https://user:pass@datahub.example.com",
        )

    assert str(
        Settings(_env_file=None, datahub_gms_url="https://datahub.example.com").datahub_gms_url
    ).startswith("https://")
