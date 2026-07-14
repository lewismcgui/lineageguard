from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import respx
import yaml

from lineageguard.datahub.quickstart import (
    EXPECTED_CLEANUP_IMAGES,
    EXPECTED_RUNNING_IMAGES,
    EXPECTED_RUNNING_PORTS,
    PUBLISHED_TARGETS,
    QUICKSTART_NETWORK_NAME,
    QUICKSTART_OWNER_LABEL,
    QUICKSTART_OWNER_VALUE,
    QUICKSTART_PROJECT_NAME,
    QuickstartNotRunning,
    QuickstartSecurityError,
    harden_quickstart_compose,
    non_loopback_bindings,
    prepare_loopback_compose,
    stop_running_datahub,
    validate_loopback_compose,
    validate_running_datahub_bindings,
    verify_local_docker_endpoint,
    verify_running_datahub_bindings,
    verify_startup_project_ownership,
)


def _source_compose() -> bytes:
    payload = {
        "name": QUICKSTART_PROJECT_NAME,
        "services": {
            f"service-{target}": {
                "image": "example.invalid/datahub:test",
                "labels": {QUICKSTART_OWNER_LABEL: QUICKSTART_OWNER_VALUE},
                "networks": {"default": None},
                "ports": [
                    {
                        "mode": "ingress",
                        "target": target,
                        "published": str(target),
                        "protocol": "tcp",
                    }
                ],
            }
            for target in PUBLISHED_TARGETS
        },
        "networks": {
            "default": {
                "name": QUICKSTART_NETWORK_NAME,
                "labels": {QUICKSTART_OWNER_LABEL: QUICKSTART_OWNER_VALUE},
            }
        },
    }
    return yaml.safe_dump(payload, sort_keys=False).encode()


def test_harden_quickstart_compose_binds_every_published_port_to_loopback() -> None:
    source = _source_compose()
    source_payload = yaml.safe_load(source)
    for service in source_payload["services"].values():
        service.pop("labels")
    source = yaml.safe_dump(source_payload, sort_keys=False).encode()
    result = harden_quickstart_compose(
        source,
        expected_sha256=hashlib.sha256(source).hexdigest(),
    )
    validate_loopback_compose(result)
    payload = yaml.safe_load(result)
    assert {
        port["host_ip"] for service in payload["services"].values() for port in service["ports"]
    } == {"127.0.0.1"}
    assert {
        port["published"] for service in payload["services"].values() for port in service["ports"]
    } == PUBLISHED_TARGETS
    assert {
        service["labels"][QUICKSTART_OWNER_LABEL] for service in payload["services"].values()
    } == {QUICKSTART_OWNER_VALUE}
    assert payload["name"] == QUICKSTART_PROJECT_NAME
    assert payload["networks"] == {
        "default": {
            "name": QUICKSTART_NETWORK_NAME,
            "labels": {QUICKSTART_OWNER_LABEL: QUICKSTART_OWNER_VALUE},
        }
    }
    assert {tuple(service["networks"]) for service in payload["services"].values()} == {
        ("default",)
    }


def test_harden_removes_every_user_home_bind_and_preserves_named_volumes() -> None:
    payload = yaml.safe_load(_source_compose())
    service = payload["services"]["service-8080"]
    service["volumes"] = [
        {
            "type": "bind",
            "source": "${HOME}/.aws",
            "target": "/opt/datahub/.aws",
            "read_only": True,
        },
        "${HOME}/.datahub/plugins:/etc/datahub/plugins",
        {
            "type": "volume",
            "source": "lineageguard-data",
            "target": "/var/lib/datahub",
        },
    ]
    source = yaml.safe_dump(payload, sort_keys=False).encode()

    hardened = harden_quickstart_compose(
        source,
        expected_sha256=hashlib.sha256(source).hexdigest(),
    )
    hardened_payload = yaml.safe_load(hardened)

    assert hardened_payload["services"]["service-8080"]["volumes"] == [
        {
            "type": "volume",
            "source": "lineageguard-data",
            "target": "/var/lib/datahub",
        }
    ]
    validate_loopback_compose(hardened)


def test_validate_loopback_compose_rejects_user_home_bind() -> None:
    payload = yaml.safe_load(_source_compose())
    for service in payload["services"].values():
        service["ports"][0]["host_ip"] = "127.0.0.1"
    payload["services"]["service-8080"]["volumes"] = [
        {
            "type": "bind",
            "source": "${HOME}/.datahub/plugins",
            "target": "/etc/datahub/plugins",
        }
    ]

    with pytest.raises(QuickstartSecurityError, match="user home"):
        validate_loopback_compose(yaml.safe_dump(payload).encode())


def test_harden_quickstart_compose_rejects_changed_source() -> None:
    with pytest.raises(QuickstartSecurityError, match="checksum changed"):
        harden_quickstart_compose(_source_compose(), expected_sha256="0" * 64)


def test_validate_loopback_compose_rejects_any_wildcard_binding() -> None:
    source = _source_compose()
    payload = yaml.safe_load(source)
    payload["services"]["service-8080"]["ports"][0]["host_ip"] = "0.0.0.0"  # noqa: S104
    with pytest.raises(QuickstartSecurityError, match="beyond loopback"):
        validate_loopback_compose(yaml.safe_dump(payload).encode())


def test_validate_loopback_compose_rejects_missing_pinned_port() -> None:
    source = _source_compose()
    payload = yaml.safe_load(source)
    payload["services"].pop("service-9200")
    for service in payload["services"].values():
        service["ports"][0]["host_ip"] = "127.0.0.1"
    with pytest.raises(QuickstartSecurityError, match="does not match"):
        validate_loopback_compose(yaml.safe_dump(payload).encode())


def _canonical_validation_payload(service: object) -> bytes:
    return yaml.safe_dump(
        {
            "name": QUICKSTART_PROJECT_NAME,
            "services": {"broken": service},
            "networks": {
                "default": {
                    "name": QUICKSTART_NETWORK_NAME,
                    "labels": {QUICKSTART_OWNER_LABEL: QUICKSTART_OWNER_VALUE},
                }
            },
        }
    ).encode()


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"services: [", "invalid YAML"),
        (b"[]\n", "not a mapping"),
        (b"services: {}\n", "services are missing"),
        (_canonical_validation_payload([]), "service definition"),
        (
            _canonical_validation_payload({"network_mode": "host", "networks": {"default": None}}),
            "host networking",
        ),
        (
            _canonical_validation_payload({"networks": {"default": None}, "ports": {}}),
            "ports are malformed",
        ),
        (
            _canonical_validation_payload({"networks": {"default": None}, "ports": ["8080:8080"]}),
            "short port mapping",
        ),
    ],
)
def test_validate_loopback_compose_rejects_malformed_shapes(data: bytes, message: str) -> None:
    with pytest.raises(QuickstartSecurityError, match=message):
        validate_loopback_compose(data)


def test_validate_loopback_compose_rejects_oversized_input() -> None:
    with pytest.raises(QuickstartSecurityError, match="unexpectedly large"):
        validate_loopback_compose(b"x" * (1024 * 1024 + 1))


def test_harden_rejects_malformed_service_and_ports() -> None:
    for payload, message in [
        ({"services": {"bad": []}}, "service definition"),
        ({"services": {"bad": {"volumes": {}}}}, "volumes are malformed"),
        ({"services": {"bad": {"ports": {}}}}, "ports are malformed"),
        ({"services": {"bad": {"ports": ["8080:8080"]}}}, "short port mapping"),
    ]:
        source = yaml.safe_dump(payload).encode()
        with pytest.raises(QuickstartSecurityError, match=message):
            harden_quickstart_compose(
                source,
                expected_sha256=hashlib.sha256(source).hexdigest(),
            )


def test_validate_and_harden_reject_invalid_or_changed_port_sets() -> None:
    payload = yaml.safe_load(_source_compose())
    for service in payload["services"].values():
        service["ports"][0]["host_ip"] = "127.0.0.1"
    payload["services"]["service-8080"]["ports"][0]["target"] = True
    with pytest.raises(QuickstartSecurityError, match="target port is invalid"):
        validate_loopback_compose(yaml.safe_dump(payload).encode())

    payload = yaml.safe_load(_source_compose())
    for service in payload["services"].values():
        service["ports"][0]["host_ip"] = "127.0.0.1"
    payload["services"]["service-8080"]["ports"][0]["published"] = "invalid"
    with pytest.raises(QuickstartSecurityError, match="host port is invalid"):
        validate_loopback_compose(yaml.safe_dump(payload).encode())

    payload = yaml.safe_load(_source_compose())
    payload["services"]["service-8080"]["ports"][0].pop("published")
    source = yaml.safe_dump(payload).encode()
    with pytest.raises(QuickstartSecurityError, match="published-port set changed"):
        harden_quickstart_compose(
            source,
            expected_sha256=hashlib.sha256(source).hexdigest(),
        )


def test_non_loopback_bindings_reports_only_unsafe_container_ports() -> None:
    payload = [
        {
            "Name": "/datahub-gms",
            "NetworkSettings": {
                "Ports": {
                    "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}],
                    "4319/tcp": [
                        {"HostIp": "0.0.0.0", "HostPort": "4319"}  # noqa: S104
                    ],
                }
            },
        },
        {
            "Name": "/datahub-frontend",
            "NetworkSettings": {"Ports": {"9002/tcp": [{"HostIp": "::1", "HostPort": "9002"}]}},
        },
    ]
    assert non_loopback_bindings(payload) == ("datahub-gms:4319/tcp",)


def test_non_loopback_bindings_rejects_malformed_inspect_payload() -> None:
    with pytest.raises(QuickstartSecurityError, match="port bindings"):
        non_loopback_bindings([{"Name": "/datahub-gms", "NetworkSettings": {}}])


def test_non_loopback_bindings_rejects_invalid_top_level_and_container() -> None:
    with pytest.raises(QuickstartSecurityError, match="response is malformed"):
        non_loopback_bindings({})
    with pytest.raises(QuickstartSecurityError, match="container is malformed"):
        non_loopback_bindings(["container"])


def test_non_loopback_bindings_treats_invalid_ip_as_unsafe() -> None:
    payload = [
        {
            "Name": None,
            "NetworkSettings": {
                "Ports": {"8080/tcp": [{"HostIp": "not-an-ip", "HostPort": "8080"}]}
            },
        }
    ]
    assert non_loopback_bindings(payload) == ("unknown:8080/tcp",)


def _running_inspections() -> list[dict[str, object]]:
    inspections: list[dict[str, object]] = []
    for service, image in EXPECTED_RUNNING_IMAGES.items():
        published = {
            f"{target}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(target)}]
            for target in EXPECTED_RUNNING_PORTS[service]
        }
        inspections.append(
            {
                "Name": f"/{service}",
                "Config": {
                    "Image": image,
                    "Labels": {
                        "com.docker.compose.project": QUICKSTART_PROJECT_NAME,
                        "com.docker.compose.service": service,
                        QUICKSTART_OWNER_LABEL: QUICKSTART_OWNER_VALUE,
                    },
                },
                "HostConfig": {"NetworkMode": QUICKSTART_NETWORK_NAME},
                "State": {
                    "Running": True,
                    "Status": "running",
                    **(
                        {}
                        if service == "datahub-actions-quickstart"
                        else {"Health": {"Status": "healthy"}}
                    ),
                },
                "NetworkSettings": {
                    "Ports": published,
                    "Networks": {QUICKSTART_NETWORK_NAME: {}},
                },
            }
        )
    return inspections


def _cleanup_inspection(
    service: str = "datahub-gms-quickstart",
    image: str | None = None,
) -> list[dict[str, object]]:
    return [
        {
            "Config": {
                "Image": image or EXPECTED_CLEANUP_IMAGES[service],
                "Labels": {
                    "com.docker.compose.project": QUICKSTART_PROJECT_NAME,
                    "com.docker.compose.service": service,
                    QUICKSTART_OWNER_LABEL: QUICKSTART_OWNER_VALUE,
                },
            }
        }
    ]


def test_validate_running_bindings_accepts_exact_loopback_port_set() -> None:
    validate_running_datahub_bindings(_running_inspections())


def test_validate_running_bindings_rejects_missing_pinned_port() -> None:
    inspections = _running_inspections()
    inspections.pop()
    with pytest.raises(QuickstartSecurityError, match="live published-port set"):
        validate_running_datahub_bindings(inspections)


def test_validate_running_bindings_rejects_host_port_remap() -> None:
    inspections = _running_inspections()
    network = inspections[1]["NetworkSettings"]
    assert isinstance(network, dict)
    ports = network["Ports"]
    assert isinstance(ports, dict)
    binding = next(iter(ports.values()))
    assert isinstance(binding, list)
    binding[0]["HostPort"] = "12345"
    with pytest.raises(QuickstartSecurityError, match="host-port mapping"):
        validate_running_datahub_bindings(inspections)


def test_validate_running_bindings_rejects_wrong_service_port_ownership() -> None:
    inspections = _running_inspections()
    gms = next(
        item
        for item in inspections
        if item["Config"]["Labels"]["com.docker.compose.service"] == "datahub-gms-quickstart"
    )
    frontend = next(
        item
        for item in inspections
        if item["Config"]["Labels"]["com.docker.compose.service"] == "frontend-quickstart"
    )
    gms_ports = gms["NetworkSettings"]["Ports"]
    frontend_ports = frontend["NetworkSettings"]["Ports"]
    gms_ports["9002/tcp"] = frontend_ports.pop("9002/tcp")
    frontend_ports["8080/tcp"] = gms_ports.pop("8080/tcp")

    with pytest.raises(QuickstartSecurityError, match="port ownership"):
        validate_running_datahub_bindings(inspections)


def test_validate_running_bindings_rejects_unexpected_extra_published_port() -> None:
    inspections = _running_inspections()
    actions = next(
        item
        for item in inspections
        if item["Config"]["Labels"]["com.docker.compose.service"] == "datahub-actions-quickstart"
    )
    actions["NetworkSettings"]["Ports"]["7777/tcp"] = [{"HostIp": "127.0.0.1", "HostPort": "7777"}]

    with pytest.raises(QuickstartSecurityError, match="published-port set"):
        validate_running_datahub_bindings(inspections)


def test_validate_running_bindings_rejects_host_networking() -> None:
    inspections = _running_inspections()
    inspections[0]["HostConfig"] = {"NetworkMode": "host"}
    with pytest.raises(QuickstartSecurityError, match="network mode"):
        validate_running_datahub_bindings(inspections)


def test_validate_running_bindings_rejects_shared_or_extra_network() -> None:
    inspections = _running_inspections()
    network = inspections[0]["NetworkSettings"]["Networks"]
    network["datahub_network"] = {}
    with pytest.raises(QuickstartSecurityError, match="network set"):
        validate_running_datahub_bindings(inspections)


def test_validate_running_bindings_rejects_wildcard_ip() -> None:
    inspections = _running_inspections()
    network = inspections[1]["NetworkSettings"]
    assert isinstance(network, dict)
    ports = network["Ports"]
    assert isinstance(ports, dict)
    binding = next(iter(ports.values()))
    assert isinstance(binding, list)
    binding[0]["HostIp"] = "0.0.0.0"  # noqa: S104
    with pytest.raises(QuickstartSecurityError, match="beyond loopback"):
        validate_running_datahub_bindings(inspections)


def test_validate_running_bindings_rejects_empty_binding_list() -> None:
    inspections = _running_inspections()
    network = inspections[1]["NetworkSettings"]
    assert isinstance(network, dict)
    ports = network["Ports"]
    assert isinstance(ports, dict)
    ports[next(iter(ports))] = []
    with pytest.raises(QuickstartSecurityError, match="empty port binding"):
        validate_running_datahub_bindings(inspections)


def test_validate_running_bindings_rejects_wrong_service_image() -> None:
    inspections = _running_inspections()
    config = inspections[0]["Config"]
    assert isinstance(config, dict)
    config["Image"] = "attacker.invalid/replacement:latest"
    with pytest.raises(QuickstartSecurityError, match="service or image set"):
        validate_running_datahub_bindings(inspections)


def test_validate_running_bindings_rejects_stopped_or_unhealthy_service() -> None:
    inspections = _running_inspections()
    inspections[0]["State"] = {"Running": False, "Status": "exited"}
    with pytest.raises(QuickstartSecurityError, match="not running"):
        validate_running_datahub_bindings(inspections)

    inspections = _running_inspections()
    inspections[1]["State"] = {
        "Running": True,
        "Status": "running",
        "Health": {"Status": "unhealthy"},
    }
    with pytest.raises(QuickstartSecurityError, match="not healthy"):
        validate_running_datahub_bindings(inspections)

    inspections = _running_inspections()
    inspections[0]["State"] = {
        "Running": True,
        "Status": "running",
        "Health": {"Status": "starting"},
    }
    with pytest.raises(QuickstartSecurityError, match="health is not ready"):
        validate_running_datahub_bindings(inspections)


def test_validate_running_bindings_rejects_missing_identity_and_duplicate_service() -> None:
    inspections = _running_inspections()
    inspections[0].pop("HostConfig")
    with pytest.raises(QuickstartSecurityError, match="host config"):
        validate_running_datahub_bindings(inspections)

    inspections = _running_inspections()
    inspections[1]["Config"] = inspections[0]["Config"]
    with pytest.raises(QuickstartSecurityError, match="duplicate"):
        validate_running_datahub_bindings(inspections)

    inspections = _running_inspections()
    config = inspections[0]["Config"]
    assert isinstance(config, dict)
    labels = config["Labels"]
    assert isinstance(labels, dict)
    labels.pop(QUICKSTART_OWNER_LABEL)
    with pytest.raises(QuickstartSecurityError, match="service identity"):
        validate_running_datahub_bindings(inspections)


def test_validate_running_bindings_rejects_non_tcp_port() -> None:
    inspections = _running_inspections()
    network = inspections[1]["NetworkSettings"]
    assert isinstance(network, dict)
    ports = network["Ports"]
    assert isinstance(ports, dict)
    binding = ports.pop(next(iter(ports)))
    ports["3306/udp"] = binding
    with pytest.raises(QuickstartSecurityError, match="non-TCP"):
        validate_running_datahub_bindings(inspections)


@respx.mock
def test_prepare_binds_cached_output_to_checksum_pinned_source(tmp_path: Path) -> None:
    source = _source_compose()
    source_url = "https://example.invalid/datahub-compose.yml"
    route = respx.get(source_url).mock(return_value=httpx.Response(200, content=source))
    destination = tmp_path / "private" / "compose.yml"
    prepare_loopback_compose(
        destination,
        source_url=source_url,
        expected_sha256=hashlib.sha256(source).hexdigest(),
    )
    source_cache = destination.with_name("compose.yml.source")
    assert route.call_count == 1
    assert os.stat(destination).st_mode & 0o777 == 0o600
    assert os.stat(source_cache).st_mode & 0o777 == 0o600

    payload = yaml.safe_load(destination.read_bytes())
    payload["services"]["service-8080"]["image"] = "attacker.invalid/root:latest"
    destination.write_text(yaml.safe_dump(payload), encoding="utf-8")
    with pytest.raises(QuickstartSecurityError, match="checksum-pinned source"):
        prepare_loopback_compose(
            destination,
            source_url=source_url,
            expected_sha256=hashlib.sha256(source).hexdigest(),
        )
    assert route.call_count == 1


@respx.mock
def test_prepare_refresh_recovers_a_tampered_cached_output(tmp_path: Path) -> None:
    source = _source_compose()
    source_url = "https://example.invalid/datahub-compose.yml"
    route = respx.get(source_url).mock(return_value=httpx.Response(200, content=source))
    destination = tmp_path / "private" / "compose.yml"
    expected_sha256 = hashlib.sha256(source).hexdigest()
    prepare_loopback_compose(
        destination,
        source_url=source_url,
        expected_sha256=expected_sha256,
    )
    destination.write_bytes(b"tampered")
    prepare_loopback_compose(
        destination,
        refresh=True,
        source_url=source_url,
        expected_sha256=expected_sha256,
    )
    validate_loopback_compose(destination.read_bytes())
    assert route.call_count == 2


@respx.mock
def test_prepare_rejects_http_failure_and_transport_error(tmp_path: Path) -> None:
    source_url = "https://example.invalid/datahub-compose.yml"
    respx.get(source_url).mock(return_value=httpx.Response(503))
    with pytest.raises(QuickstartSecurityError, match="download failed"):
        prepare_loopback_compose(tmp_path / "one/compose.yml", source_url=source_url)

    respx.get(source_url).mock(side_effect=httpx.ConnectError("offline"))
    with pytest.raises(QuickstartSecurityError, match="could not be downloaded"):
        prepare_loopback_compose(tmp_path / "two/compose.yml", source_url=source_url)


def test_prepare_rejects_traversal_before_network() -> None:
    with pytest.raises(QuickstartSecurityError, match="traversal"):
        prepare_loopback_compose(Path("safe/../compose.yml"))


@respx.mock
def test_prepare_rejects_nonprivate_cached_file(tmp_path: Path) -> None:
    source = _source_compose()
    source_url = "https://example.invalid/datahub-compose.yml"
    respx.get(source_url).mock(return_value=httpx.Response(200, content=source))
    destination = tmp_path / "private" / "compose.yml"
    kwargs = {
        "source_url": source_url,
        "expected_sha256": hashlib.sha256(source).hexdigest(),
    }
    prepare_loopback_compose(destination, **kwargs)
    destination.chmod(0o644)
    with pytest.raises(QuickstartSecurityError, match="mode 0600"):
        prepare_loopback_compose(destination, **kwargs)


def _mock_docker(monkeypatch: pytest.MonkeyPatch, outputs: list[object]) -> None:
    monkeypatch.setattr(
        "lineageguard.datahub.quickstart.shutil.which",
        lambda name: "/usr/local/bin/docker" if name == "docker" else None,
    )

    def run(*args: object, **kwargs: object) -> object:
        del args, kwargs
        result = outputs.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr("lineageguard.datahub.quickstart.subprocess.run", run)


NETWORK_ID = "a" * 64


def _network_inspection(
    container_ids: list[str] | None = None,
    *,
    owner: str = QUICKSTART_OWNER_VALUE,
) -> list[dict[str, object]]:
    return [
        {
            "Id": NETWORK_ID,
            "Name": QUICKSTART_NETWORK_NAME,
            "Labels": {
                "com.docker.compose.project": QUICKSTART_PROJECT_NAME,
                "com.docker.compose.network": "default",
                QUICKSTART_OWNER_LABEL: owner,
            },
            "Containers": {
                identifier: {"Name": f"container-{index}"}
                for index, identifier in enumerate(container_ids or [])
            },
        }
    ]


def _network_outputs(container_ids: list[str] | None = None) -> list[SimpleNamespace]:
    return [
        SimpleNamespace(stdout=f"{NETWORK_ID}\n"),
        SimpleNamespace(stdout=json.dumps(_network_inspection(container_ids))),
    ]


def test_verify_local_docker_endpoint_accepts_only_unix_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    _mock_docker(
        monkeypatch,
        [SimpleNamespace(stdout="unix:///var/run/docker.sock\n")],
    )
    assert verify_local_docker_endpoint() == "unix:///var/run/docker.sock"


def test_verify_local_docker_endpoint_rejects_remote_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "tcp://remote.example:2376")
    _mock_docker(
        monkeypatch,
        [SimpleNamespace(stdout="unix:///var/run/docker.sock\n")],
    )
    with pytest.raises(QuickstartSecurityError, match="remote Docker"):
        verify_local_docker_endpoint()


def test_verify_local_docker_endpoint_rejects_missing_or_failed_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    _mock_docker(monkeypatch, [SimpleNamespace(stdout="")])
    with pytest.raises(QuickstartSecurityError, match="no endpoint"):
        verify_local_docker_endpoint()

    _mock_docker(
        monkeypatch,
        [subprocess.CalledProcessError(1, ["docker", "context", "inspect"])],
    )
    with pytest.raises(QuickstartSecurityError, match="could not be inspected"):
        verify_local_docker_endpoint()


def test_verify_local_docker_endpoint_rejects_missing_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("lineageguard.datahub.quickstart.shutil.which", lambda _name: None)
    with pytest.raises(QuickstartSecurityError, match="not installed"):
        verify_local_docker_endpoint()


def test_stop_running_datahub_proves_project_containers_stopped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_docker(
        monkeypatch,
        [
            SimpleNamespace(stdout="0123456789ab\n"),
            SimpleNamespace(stdout=json.dumps(_cleanup_inspection())),
            SimpleNamespace(stdout="0123456789ab\n"),
            SimpleNamespace(stdout=""),
        ],
    )
    assert stop_running_datahub() == 1


def test_stop_running_datahub_handles_empty_and_failed_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_docker(monkeypatch, [SimpleNamespace(stdout="")])
    assert stop_running_datahub() == 0

    _mock_docker(
        monkeypatch,
        [
            SimpleNamespace(stdout="0123456789ab\n"),
            SimpleNamespace(stdout=json.dumps(_cleanup_inspection())),
            subprocess.CalledProcessError(1, ["docker", "stop"]),
        ],
    )
    with pytest.raises(QuickstartSecurityError, match="could not be stopped"):
        stop_running_datahub()


def test_stop_running_datahub_rejects_remaining_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_docker(
        monkeypatch,
        [
            SimpleNamespace(stdout="0123456789ab\n"),
            SimpleNamespace(stdout=json.dumps(_cleanup_inspection())),
            SimpleNamespace(stdout="0123456789ab\n"),
            SimpleNamespace(stdout="0123456789ab\n"),
        ],
    )
    with pytest.raises(QuickstartSecurityError, match="remain running"):
        stop_running_datahub()


def test_stop_running_datahub_allows_pinned_partial_setup_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_docker(
        monkeypatch,
        [
            SimpleNamespace(stdout="0123456789ab\n"),
            SimpleNamespace(stdout=json.dumps(_cleanup_inspection("system-update-quickstart"))),
            SimpleNamespace(stdout="0123456789ab\n"),
            SimpleNamespace(stdout=""),
        ],
    )
    assert stop_running_datahub() == 1


@pytest.mark.parametrize(
    "inspection",
    [
        _cleanup_inspection("datahub-gms-quickstart", "attacker.invalid/gms:latest"),
        [
            {
                "Config": {
                    "Image": "acryldata/datahub-gms:v1.6.0",
                    "Labels": {
                        "com.docker.compose.project": QUICKSTART_PROJECT_NAME,
                        "com.docker.compose.service": "unrelated-service",
                        QUICKSTART_OWNER_LABEL: QUICKSTART_OWNER_VALUE,
                    },
                }
            }
        ],
        [
            {
                "Config": {
                    "Image": "acryldata/datahub-gms:v1.6.0",
                    "Labels": {
                        "com.docker.compose.project": QUICKSTART_PROJECT_NAME,
                        "com.docker.compose.service": "datahub-gms-quickstart",
                    },
                }
            }
        ],
    ],
)
def test_stop_running_datahub_refuses_unrecognized_project_container(
    monkeypatch: pytest.MonkeyPatch,
    inspection: list[dict[str, object]],
) -> None:
    _mock_docker(
        monkeypatch,
        [
            SimpleNamespace(stdout="0123456789ab\n"),
            SimpleNamespace(stdout=json.dumps(inspection)),
        ],
    )
    with pytest.raises(QuickstartSecurityError, match="refusing to stop"):
        stop_running_datahub()


def test_stop_running_datahub_refuses_an_inspection_count_race(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_docker(
        monkeypatch,
        [
            SimpleNamespace(stdout="0123456789ab\n"),
            SimpleNamespace(stdout="[]"),
        ],
    )
    with pytest.raises(QuickstartSecurityError, match="container set changed"):
        stop_running_datahub()


def test_startup_ownership_accepts_first_start_and_known_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_docker(monkeypatch, [SimpleNamespace(stdout=""), SimpleNamespace(stdout="")])
    assert verify_startup_project_ownership() == 0

    identifiers = ["0" * 63 + "1", "0" * 63 + "2"]
    known = [
        *_cleanup_inspection("datahub-gms-quickstart"),
        *_cleanup_inspection("system-update-quickstart"),
    ]
    _mock_docker(
        monkeypatch,
        [
            SimpleNamespace(stdout="\n".join(identifiers)),
            SimpleNamespace(stdout=json.dumps(known)),
            *_network_outputs(),
        ],
    )
    assert verify_startup_project_ownership() == 2


def test_startup_ownership_blocks_stopped_foreign_reserved_project_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foreign = _cleanup_inspection()
    labels = foreign[0]["Config"]["Labels"]
    assert isinstance(labels, dict)
    labels.pop(QUICKSTART_OWNER_LABEL)
    _mock_docker(
        monkeypatch,
        [
            SimpleNamespace(stdout="0123456789ab\n"),
            SimpleNamespace(stdout=json.dumps(foreign)),
        ],
    )

    with pytest.raises(QuickstartSecurityError, match="unrecognized"):
        verify_startup_project_ownership()


def test_startup_ownership_ignores_inherited_and_generic_project_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATAHUB_COMPOSE_PROJECT_NAME", "datahub")
    monkeypatch.setattr(
        "lineageguard.datahub.quickstart.shutil.which",
        lambda name: "/usr/local/bin/docker" if name == "docker" else None,
    )
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> SimpleNamespace:
        del kwargs
        commands.append(command)
        return SimpleNamespace(stdout="")

    monkeypatch.setattr("lineageguard.datahub.quickstart.subprocess.run", run)

    assert verify_startup_project_ownership() == 0
    assert commands == [
        [
            "/usr/local/bin/docker",
            "ps",
            "--no-trunc",
            "-a",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={QUICKSTART_PROJECT_NAME}",
        ],
        [
            "/usr/local/bin/docker",
            "network",
            "ls",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"name=^{QUICKSTART_NETWORK_NAME}$",
        ],
    ]


def test_datahub_up_forces_reserved_project_before_preflight_and_startup() -> None:
    script = (Path(__file__).parents[2] / "scripts" / "datahub-up.sh").read_text(encoding="utf-8")
    export = "export DATAHUB_COMPOSE_PROJECT_NAME=lineageguard-datahub"
    assert export in script
    assert script.index(export) < script.index("./scripts/datahub-preflight.sh")
    assert script.index("verify-startup") < script.index("uvx --from")


def test_preflight_uses_reserved_project_health_verifier() -> None:
    script = (Path(__file__).parents[2] / "scripts" / "datahub-preflight.sh").read_text(
        encoding="utf-8"
    )
    assert "datahub docker check" not in script
    assert "scripts/datahub-quickstart.py verify-running" in script
    assert script.index('if [ -n "${occupied_ports}" ]') < script.index(
        'if [ -z "${available_kib}" ]'
    )


def test_verify_running_datahub_bindings_inspects_complete_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identifiers = [f"{value:064x}" for value in range(1, 7)]
    _mock_docker(
        monkeypatch,
        [
            SimpleNamespace(stdout="\n".join(identifiers)),
            SimpleNamespace(stdout=json.dumps(_running_inspections())),
            *_network_outputs(identifiers),
        ],
    )
    assert verify_running_datahub_bindings() == 6


def test_verify_running_rejects_foreign_reserved_network_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identifiers = [f"{value:064x}" for value in range(1, 7)]
    foreign = "f" * 64
    _mock_docker(
        monkeypatch,
        [
            SimpleNamespace(stdout="\n".join(identifiers)),
            SimpleNamespace(stdout=json.dumps(_running_inspections())),
            *_network_outputs([*identifiers, foreign]),
        ],
    )

    with pytest.raises(QuickstartSecurityError, match="endpoint set"):
        verify_running_datahub_bindings()


def test_startup_rejects_foreign_or_unowned_reserved_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foreign = "f" * 64
    _mock_docker(
        monkeypatch,
        [SimpleNamespace(stdout=""), *_network_outputs([foreign])],
    )
    with pytest.raises(QuickstartSecurityError, match="foreign endpoint"):
        verify_startup_project_ownership()

    _mock_docker(
        monkeypatch,
        [
            SimpleNamespace(stdout=""),
            SimpleNamespace(stdout=f"{NETWORK_ID}\n"),
            SimpleNamespace(stdout=json.dumps(_network_inspection(owner="foreign"))),
        ],
    )
    with pytest.raises(QuickstartSecurityError, match="identity"):
        verify_startup_project_ownership()


def test_verify_running_datahub_bindings_rejects_stopped_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_docker(monkeypatch, [SimpleNamespace(stdout="")])
    with pytest.raises(QuickstartNotRunning, match="no running"):
        verify_running_datahub_bindings()


def test_verify_running_rejects_invalid_container_id_and_inspect_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_docker(monkeypatch, [SimpleNamespace(stdout="not-an-id\n")])
    with pytest.raises(QuickstartSecurityError, match="invalid container identifier"):
        verify_running_datahub_bindings()

    _mock_docker(
        monkeypatch,
        [SimpleNamespace(stdout="0123456789ab\n"), SimpleNamespace(stdout="not-json")],
    )
    with pytest.raises(QuickstartSecurityError, match="could not be inspected"):
        verify_running_datahub_bindings()


def test_verify_running_rejects_docker_listing_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_docker(
        monkeypatch,
        [subprocess.CalledProcessError(1, ["docker", "ps"])],
    )
    with pytest.raises(QuickstartSecurityError, match="could not be listed"):
        verify_running_datahub_bindings()
