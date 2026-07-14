from __future__ import annotations

import base64
import json
import runpy
import stat
import sys
from pathlib import Path

import httpx
import pytest
import respx

import lineageguard.datahub.token as token_module
from lineageguard.datahub.token import (
    AUTH_PROBE_PATH,
    TokenBootstrapError,
    TokenEnsureStatus,
    TokenValidationStatus,
    create_local_token,
    ensure_local_token,
    preflight_private_token,
    read_private_token,
    validate_local_token,
    write_private_token,
)

TOKEN_VALIDATION_PROBE_URL = f"http://localhost:8080{AUTH_PROBE_PATH}"


def _jwt(token_id: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"jti": token_id}).encode()).rstrip(b"=")
    return f"header.{payload.decode()}.signature"


@respx.mock
def test_create_local_token_uses_authenticated_frontend_session() -> None:
    login = respx.post("http://localhost:9002/logIn").mock(
        return_value=httpx.Response(
            200,
            headers={"Set-Cookie": "PLAY_SESSION=local-session; Path=/; HttpOnly"},
        )
    )
    graphql = respx.post("http://localhost:9002/api/v2/graphql").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"createAccessToken": {"accessToken": "generated-local-value"}}},
        )
    )
    assert (
        create_local_token(
            "http://localhost:9002",
            username="datahub",
            password="local-login-value",
        )
        == "generated-local-value"
    )

    login_body = json.loads(login.calls[0].request.content)
    assert login_body == {"username": "datahub", "password": "local-login-value"}
    request = graphql.calls[0].request
    assert request.headers["cookie"] == "PLAY_SESSION=local-session"
    assert "x-datahub-actor" not in request.headers
    assert "authorization" not in request.headers
    variables = json.loads(request.content)["variables"]
    assert variables["input"]["actorUrn"] == "urn:li:corpuser:datahub"


@pytest.mark.parametrize("status_code", [302, 401, 403, 500])
@respx.mock
def test_create_local_token_hides_login_failure_details(status_code: int) -> None:
    login_value = "must-never-appear"
    respx.post("http://localhost:9002/logIn").mock(
        return_value=httpx.Response(status_code, text=f"rejected {login_value}")
    )

    with pytest.raises(TokenBootstrapError, match="rejected the local login") as caught:
        create_local_token(
            "http://localhost:9002",
            username="datahub",
            password=login_value,
        )

    assert login_value not in str(caught.value)


@respx.mock
def test_create_local_token_requires_a_session_cookie() -> None:
    respx.post("http://localhost:9002/logIn").mock(return_value=httpx.Response(200))

    with pytest.raises(TokenBootstrapError, match="returned no session"):
        create_local_token(
            "http://localhost:9002",
            username="datahub",
            password="local-login-value",
        )


@respx.mock
def test_create_local_token_hides_graphql_error_details() -> None:
    respx.post("http://localhost:9002/logIn").mock(
        return_value=httpx.Response(
            200,
            headers={"Set-Cookie": "PLAY_SESSION=local-session; Path=/; HttpOnly"},
        )
    )
    respx.post("http://localhost:9002/api/v2/graphql").mock(
        return_value=httpx.Response(200, json={"errors": [{"message": "internal details"}]})
    )
    with pytest.raises(TokenBootstrapError, match="rejected") as caught:
        create_local_token(
            "http://localhost:9002",
            username="datahub",
            password="local-login-value",
        )
    assert "internal details" not in str(caught.value)


def test_write_private_token_is_owner_only_and_no_overwrite(tmp_path) -> None:
    destination = tmp_path / "credential"
    write_private_token(destination, "generated-local-value")
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert destination.read_text(encoding="utf-8") == "generated-local-value\n"
    with pytest.raises(TokenBootstrapError, match="already exists"):
        write_private_token(destination, "replacement")


def test_write_private_token_does_not_close_a_transferred_descriptor_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "credential"
    captured: dict[str, int] = {}
    explicitly_closed: list[int] = []
    real_mkstemp = token_module.tempfile.mkstemp
    real_close = token_module.os.close

    def tracked_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        descriptor, name = real_mkstemp(*args, **kwargs)
        captured["descriptor"] = descriptor
        return descriptor, name

    def tracked_close(descriptor: int) -> None:
        explicitly_closed.append(descriptor)
        real_close(descriptor)

    def fail_replace(source: object, destination_path: object) -> None:
        del source, destination_path
        raise OSError("simulated replace failure")

    monkeypatch.setattr(token_module.tempfile, "mkstemp", tracked_mkstemp)
    monkeypatch.setattr(token_module.os, "close", tracked_close)
    monkeypatch.setattr(token_module.os, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        write_private_token(destination, "generated-local-value")

    assert captured["descriptor"] not in explicitly_closed
    assert not destination.exists()


def test_token_cli_refuses_existing_output_before_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "credential"
    write_private_token(destination, "existing-token")
    script = Path(__file__).parents[2] / "scripts/create-local-token.py"
    monkeypatch.setattr(sys, "argv", [str(script), "--output", str(destination)])
    monkeypatch.setenv("DATAHUB_LOCAL_PASSWORD", "must-not-be-used")

    with pytest.raises(SystemExit, match="already exists"):
        runpy.run_path(str(script), run_name="__main__")

    assert read_private_token(destination) == "existing-token"


def test_preflight_private_token_rejects_unwritable_destination(tmp_path: Path) -> None:
    parent = tmp_path / "tokens"
    parent.mkdir(mode=0o700)
    parent.chmod(0o500)
    try:
        with pytest.raises(TokenBootstrapError, match="not writable"):
            preflight_private_token(parent / "credential")
    finally:
        parent.chmod(0o700)


@respx.mock
def test_ensure_reuses_a_valid_private_token(tmp_path: Path) -> None:
    destination = tmp_path / "credential"
    write_private_token(destination, "existing-token")
    route = respx.get("http://localhost:8080/config").mock(
        return_value=httpx.Response(200, json={"noCode": "true"})
    )
    probe = respx.get(TOKEN_VALIDATION_PROBE_URL).mock(
        side_effect=[httpx.Response(404), httpx.Response(401)]
    )

    result = ensure_local_token(
        destination,
        "http://localhost:8080",
        "http://localhost:9002",
        credential_provider=lambda: pytest.fail("credentials must not be requested"),
    )

    assert result.status is TokenEnsureStatus.REUSED
    assert read_private_token(destination) == "existing-token"
    assert route.calls[0].request.headers["Authorization"] == "Bearer existing-token"
    assert probe.calls[0].request.headers["Authorization"] == "Bearer existing-token"
    assert probe.calls[1].request.headers["Authorization"].endswith("not-a-jwt")


@respx.mock
def test_ensure_marks_reuse_unverifiable_when_gms_accepts_nonsense_bearers(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "credential"
    write_private_token(destination, "arbitrary-existing-value")
    respx.get("http://localhost:8080/config").mock(
        return_value=httpx.Response(200, json={"noCode": "true"})
    )
    probe = respx.get(TOKEN_VALIDATION_PROBE_URL).mock(return_value=httpx.Response(404))

    result = ensure_local_token(
        destination,
        "http://localhost:8080",
        "http://localhost:9002",
        credential_provider=lambda: pytest.fail("credentials must not be requested"),
    )

    assert result.status is TokenEnsureStatus.REUSED_UNVERIFIABLE
    assert read_private_token(destination) == "arbitrary-existing-value"
    assert len(probe.calls) == 2


@respx.mock
def test_force_refuses_to_orphan_a_valid_pat(tmp_path: Path) -> None:
    destination = tmp_path / "credential"
    write_private_token(destination, _jwt("existing-id"))
    respx.get("http://localhost:8080/config").mock(
        return_value=httpx.Response(200, json={"noCode": "true"})
    )
    respx.get(TOKEN_VALIDATION_PROBE_URL).mock(
        side_effect=[httpx.Response(404), httpx.Response(401)]
    )

    with pytest.raises(TokenBootstrapError, match="force-replace a valid PAT"):
        ensure_local_token(
            destination,
            "http://localhost:8080",
            "http://localhost:9002",
            credential_provider=lambda: pytest.fail("credentials must not be requested"),
            force=True,
        )

    assert read_private_token(destination) == _jwt("existing-id")


@respx.mock
def test_ensure_replaces_only_a_definitively_rejected_token(tmp_path: Path) -> None:
    destination = tmp_path / "credential"
    write_private_token(destination, "expired-token")
    respx.get("http://localhost:8080/config").mock(
        return_value=httpx.Response(200, json={"noCode": "true"})
    )
    respx.get(TOKEN_VALIDATION_PROBE_URL).mock(return_value=httpx.Response(401))
    respx.post("http://localhost:9002/logIn").mock(
        return_value=httpx.Response(
            200,
            headers={"Set-Cookie": "PLAY_SESSION=local-session; Path=/; HttpOnly"},
        )
    )
    respx.post("http://localhost:9002/api/v2/graphql").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"createAccessToken": {"accessToken": "replacement-token"}}},
        )
    )

    result = ensure_local_token(
        destination,
        "http://localhost:8080",
        "http://localhost:9002",
        credential_provider=lambda: ("datahub", "local-login-value"),
    )

    assert result.status is TokenEnsureStatus.REPLACED
    assert read_private_token(destination) == "replacement-token"


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(403), "unexpected status"),
        (httpx.Response(500), "unexpected status"),
        (httpx.Response(200, text="not-json"), "invalid JSON"),
        (httpx.Response(200, json={"service": "frontend"}), "unexpected service"),
    ],
)
@respx.mock
def test_ensure_preserves_token_on_uncertain_validation(
    tmp_path: Path, response: httpx.Response, message: str
) -> None:
    destination = tmp_path / "credential"
    write_private_token(destination, "keep-me")
    respx.get("http://localhost:8080/config").mock(return_value=response)

    with pytest.raises(TokenBootstrapError, match=message):
        ensure_local_token(
            destination,
            "http://localhost:8080",
            "http://localhost:9002",
            credential_provider=lambda: pytest.fail("credentials must not be requested"),
        )

    assert read_private_token(destination) == "keep-me"


@respx.mock
def test_ensure_preserves_token_when_auth_probe_is_forbidden(tmp_path: Path) -> None:
    destination = tmp_path / "credential"
    write_private_token(destination, "keep-me")
    respx.get("http://localhost:8080/config").mock(
        return_value=httpx.Response(200, json={"noCode": "true"})
    )
    respx.get(TOKEN_VALIDATION_PROBE_URL).mock(return_value=httpx.Response(403))

    with pytest.raises(TokenBootstrapError, match="unexpected status"):
        ensure_local_token(
            destination,
            "http://localhost:8080",
            "http://localhost:9002",
            credential_provider=lambda: pytest.fail("credentials must not be requested"),
        )

    assert read_private_token(destination) == "keep-me"


@respx.mock
def test_ensure_creates_missing_token_with_owner_only_permissions(tmp_path: Path) -> None:
    destination = tmp_path / "credential"
    respx.post("http://localhost:9002/logIn").mock(
        return_value=httpx.Response(
            200,
            headers={"Set-Cookie": "PLAY_SESSION=local-session; Path=/; HttpOnly"},
        )
    )
    respx.post("http://localhost:9002/api/v2/graphql").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"createAccessToken": {"accessToken": "new-token"}}},
        )
    )

    result = ensure_local_token(
        destination,
        "http://localhost:8080",
        "http://localhost:9002",
        credential_provider=lambda: ("datahub", "local-login-value"),
    )

    assert result.status is TokenEnsureStatus.CREATED
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert read_private_token(destination) == "new-token"
    lock = destination.with_name(f".{destination.name}.bootstrap.lock")
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600


@respx.mock
def test_new_pat_is_revoked_if_private_storage_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "credential"
    created = _jwt("new-token-id")
    login = respx.post("http://localhost:9002/logIn").mock(
        return_value=httpx.Response(
            200,
            headers={"Set-Cookie": "PLAY_SESSION=local-session; Path=/; HttpOnly"},
        )
    )
    graphql = respx.post("http://localhost:9002/api/v2/graphql").mock(
        side_effect=[
            httpx.Response(200, json={"data": {"createAccessToken": {"accessToken": created}}}),
            httpx.Response(200, json={"data": {"revokeAccessToken": True}}),
        ]
    )

    def fail_storage(path: Path, token: str, *, overwrite: bool = False) -> None:
        del path, token, overwrite
        raise OSError("simulated disk failure")

    monkeypatch.setattr(token_module, "write_private_token", fail_storage)
    with pytest.raises(TokenBootstrapError, match="newly minted PAT was revoked"):
        ensure_local_token(
            destination,
            "http://localhost:8080",
            "http://localhost:9002",
            credential_provider=lambda: ("datahub", "local-login-value"),
        )

    assert not destination.exists()
    assert len(login.calls) == 2
    revoke_body = json.loads(graphql.calls[1].request.content)
    assert revoke_body["variables"] == {"tokenId": "new-token-id"}


@respx.mock
def test_new_pat_is_revoked_before_storage_interrupt_is_reraised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "credential"
    created = _jwt("interrupted-token-id")
    login = respx.post("http://localhost:9002/logIn").mock(
        return_value=httpx.Response(
            200,
            headers={"Set-Cookie": "PLAY_SESSION=local-session; Path=/; HttpOnly"},
        )
    )
    graphql = respx.post("http://localhost:9002/api/v2/graphql").mock(
        side_effect=[
            httpx.Response(200, json={"data": {"createAccessToken": {"accessToken": created}}}),
            httpx.Response(200, json={"data": {"revokeAccessToken": True}}),
        ]
    )

    def interrupt_storage(path: Path, token: str, *, overwrite: bool = False) -> None:
        del path, token, overwrite
        raise KeyboardInterrupt

    monkeypatch.setattr(token_module, "write_private_token", interrupt_storage)
    with pytest.raises(KeyboardInterrupt):
        ensure_local_token(
            destination,
            "http://localhost:8080",
            "http://localhost:9002",
            credential_provider=lambda: ("datahub", "local-login-value"),
        )

    assert not destination.exists()
    assert len(login.calls) == 2
    revoke_body = json.loads(graphql.calls[1].request.content)
    assert revoke_body["variables"] == {"tokenId": "interrupted-token-id"}


def test_storage_failure_without_pat_registry_id_requires_manual_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_storage(path: Path, token: str, *, overwrite: bool = False) -> None:
        del path, token, overwrite
        raise OSError("simulated disk failure")

    monkeypatch.setattr(token_module, "write_private_token", fail_storage)
    with pytest.raises(TokenBootstrapError, match="requires manual revocation"):
        token_module._store_minted_token(
            tmp_path / "credential",
            "opaque-token-without-registry-id",
            frontend_url="http://localhost:9002",
            username="datahub",
            password="local-login-value",
            overwrite=False,
        )


def test_storage_failure_reports_unconfirmed_pat_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_storage(path: Path, token: str, *, overwrite: bool = False) -> None:
        del path, token, overwrite
        raise OSError("simulated disk failure")

    def fail_revocation(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TokenBootstrapError("simulated revocation failure")

    monkeypatch.setattr(token_module, "write_private_token", fail_storage)
    monkeypatch.setattr(token_module, "revoke_local_token", fail_revocation)
    with pytest.raises(TokenBootstrapError, match="revocation could not be confirmed"):
        token_module._store_minted_token(
            tmp_path / "credential",
            _jwt("unconfirmed-token-id"),
            frontend_url="http://localhost:9002",
            username="datahub",
            password="local-login-value",
            overwrite=False,
        )


@respx.mock
def test_validate_token_returns_explicit_statuses() -> None:
    config = respx.get("http://localhost:8080/config").mock(
        return_value=httpx.Response(200, json={"noCode": "true"})
    )
    probe = respx.get(TOKEN_VALIDATION_PROBE_URL).mock(
        side_effect=[
            httpx.Response(404),
            httpx.Response(401),
            httpx.Response(401),
            httpx.Response(404),
            httpx.Response(404),
        ]
    )

    assert validate_local_token("http://localhost:8080", "valid") is TokenValidationStatus.VALID
    assert validate_local_token("http://localhost:8080", "invalid") is TokenValidationStatus.INVALID
    assert (
        validate_local_token("http://localhost:8080", "unknown")
        is TokenValidationStatus.AUTH_DISABLED_OR_UNVERIFIABLE
    )
    assert len(config.calls) == 3
    assert len(probe.calls) == 5


def test_token_reader_rejects_bad_permissions_and_symlinks(tmp_path: Path) -> None:
    destination = tmp_path / "credential"
    destination.write_text("unsafe-token\n", encoding="utf-8")
    destination.chmod(0o644)
    with pytest.raises(TokenBootstrapError, match="0600"):
        read_private_token(destination)

    destination.unlink()
    target = tmp_path / "target"
    write_private_token(target, "target-token")
    destination.symlink_to(target)
    with pytest.raises(TokenBootstrapError, match="symbolic link"):
        read_private_token(destination)


def test_token_helpers_reject_symlinked_parent_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_token = outside / "datahub-token"
    write_private_token(outside_token, "outside-token")
    (project / ".lineageguard").symlink_to(outside, target_is_directory=True)
    monkeypatch.chdir(project)

    with pytest.raises(TokenBootstrapError, match="parent must not be a symbolic link"):
        read_private_token(Path(".lineageguard/datahub-token"))
    with pytest.raises(TokenBootstrapError, match="parent must not be a symbolic link"):
        write_private_token(Path(".lineageguard/new-token"), "must-not-escape")

    assert not (outside / "new-token").exists()


def test_token_writer_rejects_writable_parent_directory(tmp_path: Path) -> None:
    token_parent = tmp_path / "tokens"
    token_parent.mkdir()
    token_parent.chmod(0o777)

    with pytest.raises(TokenBootstrapError, match="owner-controlled directory"):
        write_private_token(token_parent / "datahub-token", "must-not-be-written")

    assert not (token_parent / "datahub-token").exists()


@respx.mock
def test_network_error_does_not_replace_existing_token(tmp_path: Path) -> None:
    destination = tmp_path / "credential"
    write_private_token(destination, "keep-me")
    respx.get("http://localhost:8080/config").mock(side_effect=httpx.ConnectError("offline"))

    with pytest.raises(TokenBootstrapError, match="could not reach"):
        ensure_local_token(
            destination,
            "http://localhost:8080",
            "http://localhost:9002",
            credential_provider=lambda: pytest.fail("credentials must not be requested"),
        )

    assert read_private_token(destination) == "keep-me"


@respx.mock
def test_validate_token_never_exposes_secret_in_failure(tmp_path: Path) -> None:
    del tmp_path
    secret = "must-never-appear"
    respx.get("http://localhost:8080/config").mock(side_effect=httpx.ConnectError("offline"))

    with pytest.raises(TokenBootstrapError) as caught:
        validate_local_token("http://localhost:8080", secret)

    assert secret not in str(caught.value)


def test_local_token_helpers_reject_remote_gms_urls() -> None:
    with pytest.raises(TokenBootstrapError, match="loopback"):
        create_local_token(
            "https://datahub.example.com",
            username="datahub",
            password="local-login-value",
        )
    with pytest.raises(TokenBootstrapError, match="loopback"):
        validate_local_token("https://datahub.example.com", "secret")


def test_missing_token_rejects_remote_gms_before_requesting_credentials(tmp_path: Path) -> None:
    with pytest.raises(TokenBootstrapError, match="GMS URL must use loopback"):
        ensure_local_token(
            tmp_path / "credential",
            "https://datahub.example.com",
            "http://localhost:9002",
            credential_provider=lambda: pytest.fail("credentials must not be requested"),
        )


@pytest.mark.parametrize(
    "frontend_url",
    [
        "http://user:pass@localhost:9002",
        "file://localhost/tmp/datahub",
        "http://localhost:9002?target=remote",
        "http://localhost:9002#fragment",
        "http://localhost:9002/unexpected",
    ],
)
def test_create_local_token_rejects_unsafe_local_frontend_urls(frontend_url: str) -> None:
    with pytest.raises(TokenBootstrapError):
        create_local_token(
            frontend_url,
            username="datahub",
            password="local-login-value",
        )


def test_create_local_token_wraps_invalid_frontend_urls() -> None:
    with pytest.raises(TokenBootstrapError, match="frontend URL is invalid"):
        create_local_token(
            "http://localhost:bad",
            username="datahub",
            password="local-login-value",
        )
