"""Prepare and verify a loopback-only pinned DataHub quickstart."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

import httpx
import yaml

DATAHUB_QUICKSTART_URL: Final = (
    "https://raw.githubusercontent.com/datahub-project/datahub/v1.6.0/"
    "docker/quickstart/docker-compose.quickstart-profile.yml"
)
DATAHUB_QUICKSTART_SHA256: Final = (
    "ba39d779cd0e066553b5f4673384ece3d6a872e2245983525fc71e2ece1b5077"
)
LOOPBACK_HOST: Final = "127.0.0.1"
PUBLISHED_TARGETS: Final = frozenset({3306, 4319, 8080, 9002, 9092, 9200})
QUICKSTART_PROJECT_NAME: Final = "lineageguard-datahub"
QUICKSTART_NETWORK_NAME: Final = "lineageguard_datahub_network"
EXPECTED_RUNNING_IMAGES: Final = {
    "datahub-actions-quickstart": "acryldata/datahub-actions:v1.6.0-slim",
    "datahub-gms-quickstart": "acryldata/datahub-gms:v1.6.0",
    "frontend-quickstart": "acryldata/datahub-frontend-react:v1.6.0",
    "kafka-broker": "confluentinc/cp-kafka:8.0.0",
    "mysql": "mysql:8.2",
    "opensearch": "opensearchproject/opensearch:2.19.3",
}
EXPECTED_RUNNING_PORTS: Final = {
    "datahub-actions-quickstart": frozenset(),
    "datahub-gms-quickstart": frozenset({4319, 8080}),
    "frontend-quickstart": frozenset({9002}),
    "kafka-broker": frozenset({9092}),
    "mysql": frozenset({3306}),
    "opensearch": frozenset({9200}),
}
EXPECTED_HEALTHY_SERVICES: Final = frozenset(EXPECTED_RUNNING_IMAGES) - {
    "datahub-actions-quickstart"
}
EXPECTED_CLEANUP_IMAGES: Final = {
    **EXPECTED_RUNNING_IMAGES,
    "system-update-quickstart": "acryldata/datahub-upgrade:v1.6.0",
}
QUICKSTART_OWNER_LABEL: Final = "io.lineageguard.quickstart"
QUICKSTART_OWNER_VALUE: Final = "v1.6.0"
MAX_COMPOSE_BYTES: Final = 1024 * 1024


class QuickstartSecurityError(RuntimeError):
    """The local quickstart cannot be proven safe to launch or reuse."""


class QuickstartNotRunning(QuickstartSecurityError):
    """No running DataHub Compose project was found."""


def _port_number(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise QuickstartSecurityError(f"quickstart {field} port is invalid")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise QuickstartSecurityError(f"quickstart {field} port is invalid")


def _compose_mapping(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_COMPOSE_BYTES:
        raise QuickstartSecurityError("quickstart Compose file is unexpectedly large")
    try:
        payload = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        raise QuickstartSecurityError("quickstart Compose file is invalid YAML") from exc
    if not isinstance(payload, dict):
        raise QuickstartSecurityError("quickstart Compose file is not a mapping")
    services = payload.get("services")
    if not isinstance(services, dict) or not services:
        raise QuickstartSecurityError("quickstart Compose services are missing")
    return payload


def _uses_home_bind(mount: object) -> bool:
    if isinstance(mount, str):
        return "${HOME}" in mount
    if not isinstance(mount, Mapping) or mount.get("type") != "bind":
        return False
    source = mount.get("source")
    return isinstance(source, str) and "${HOME}" in source


def validate_loopback_compose(data: bytes) -> None:
    """Require every host-published port in the prepared file to bind to loopback."""

    payload = _compose_mapping(data)
    if payload.get("name") != QUICKSTART_PROJECT_NAME:
        raise QuickstartSecurityError("quickstart Compose project name does not match the pin")
    networks = payload.get("networks")
    if not isinstance(networks, Mapping) or set(networks) != {"default"}:
        raise QuickstartSecurityError("quickstart Compose network set does not match the pin")
    default_network = networks.get("default")
    if (
        not isinstance(default_network, Mapping)
        or default_network.get("name") != QUICKSTART_NETWORK_NAME
    ):
        raise QuickstartSecurityError("quickstart Compose network name does not match the pin")
    network_labels = default_network.get("labels")
    if (
        not isinstance(network_labels, Mapping)
        or network_labels.get(QUICKSTART_OWNER_LABEL) != QUICKSTART_OWNER_VALUE
    ):
        raise QuickstartSecurityError(
            "quickstart Compose network owner label does not match the pin"
        )
    services = payload["services"]
    observed: set[int] = set()
    for service_name, service in services.items():
        if not isinstance(service_name, str) or not isinstance(service, Mapping):
            raise QuickstartSecurityError("quickstart service definition is malformed")
        if service.get("network_mode") == "host":
            raise QuickstartSecurityError("quickstart host networking is forbidden")
        service_networks = service.get("networks")
        if not isinstance(service_networks, Mapping) or set(service_networks) != {"default"}:
            raise QuickstartSecurityError(
                f"quickstart service {service_name} network set does not match the pin"
            )
        volumes = service.get("volumes", [])
        if not isinstance(volumes, list):
            raise QuickstartSecurityError("quickstart service volumes are malformed")
        if any(_uses_home_bind(mount) for mount in volumes):
            raise QuickstartSecurityError(
                f"quickstart service {service_name} exposes the user home directory"
            )
        ports = service.get("ports", [])
        if not isinstance(ports, list):
            raise QuickstartSecurityError("quickstart service ports are malformed")
        for port in ports:
            if not isinstance(port, Mapping):
                raise QuickstartSecurityError("quickstart uses an unverified short port mapping")
            if "published" not in port:
                continue
            target = _port_number(port.get("target"), field="target")
            published = _port_number(port.get("published"), field="host")
            host_ip = port.get("host_ip")
            if host_ip != LOOPBACK_HOST or published != target:
                raise QuickstartSecurityError(
                    f"quickstart service {service_name} publishes {target} beyond loopback"
                )
            observed.add(target)
    if observed != set(PUBLISHED_TARGETS):
        raise QuickstartSecurityError("quickstart published-port set does not match the pin")


def harden_quickstart_compose(
    source: bytes,
    *,
    expected_sha256: str = DATAHUB_QUICKSTART_SHA256,
) -> bytes:
    """Verify the official source and force all published ports onto IPv4 loopback."""

    observed_sha256 = hashlib.sha256(source).hexdigest()
    if observed_sha256 != expected_sha256:
        raise QuickstartSecurityError("pinned DataHub quickstart checksum changed")
    payload = _compose_mapping(source)
    payload["name"] = QUICKSTART_PROJECT_NAME
    networks = payload.get("networks", {})
    if not isinstance(networks, dict):
        raise QuickstartSecurityError("quickstart Compose networks are malformed")
    default_network = networks.get("default", {})
    if not isinstance(default_network, dict):
        raise QuickstartSecurityError("quickstart default network is malformed")
    network_labels = default_network.get("labels", {})
    if not isinstance(network_labels, dict):
        raise QuickstartSecurityError("quickstart default network labels are malformed")
    network_labels[QUICKSTART_OWNER_LABEL] = QUICKSTART_OWNER_VALUE
    default_network["labels"] = network_labels
    default_network["name"] = QUICKSTART_NETWORK_NAME
    payload["networks"] = {"default": default_network}
    services = payload["services"]
    observed: set[int] = set()
    for service in services.values():
        if not isinstance(service, dict):
            raise QuickstartSecurityError("quickstart service definition is malformed")
        labels = service.get("labels", {})
        if not isinstance(labels, dict):
            raise QuickstartSecurityError("quickstart service labels are malformed")
        labels[QUICKSTART_OWNER_LABEL] = QUICKSTART_OWNER_VALUE
        service["labels"] = labels
        service["networks"] = {"default": None}
        volumes = service.get("volumes", [])
        if not isinstance(volumes, list):
            raise QuickstartSecurityError("quickstart service volumes are malformed")
        service["volumes"] = [mount for mount in volumes if not _uses_home_bind(mount)]
        ports = service.get("ports", [])
        if not isinstance(ports, list):
            raise QuickstartSecurityError("quickstart service ports are malformed")
        for port in ports:
            if not isinstance(port, dict):
                raise QuickstartSecurityError("quickstart uses an unverified short port mapping")
            if "published" not in port:
                continue
            target = _port_number(port.get("target"), field="target")
            port["host_ip"] = LOOPBACK_HOST
            port["published"] = target
            observed.add(target)
    if observed != set(PUBLISHED_TARGETS):
        raise QuickstartSecurityError("official quickstart published-port set changed")
    generated = (
        "# Generated from the checksum-pinned DataHub v1.6.0 quickstart.\n"
        "# Every published port is intentionally bound to 127.0.0.1.\n"
        + yaml.safe_dump(payload, sort_keys=False, width=120)
    ).encode("utf-8")
    validate_loopback_compose(generated)
    return generated


def _read_regular_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise QuickstartSecurityError(
            "prepared quickstart file could not be opened safely"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise QuickstartSecurityError("prepared quickstart file is not an owned regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise QuickstartSecurityError("prepared quickstart file must have mode 0600")
        if metadata.st_size > MAX_COMPOSE_BYTES:
            raise QuickstartSecurityError("prepared quickstart file is unexpectedly large")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            return handle.read(MAX_COMPOSE_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_metadata = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.getuid()
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
    ):
        raise QuickstartSecurityError(
            "prepared quickstart directory must be an owner-only directory"
        )
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise QuickstartSecurityError(
            "prepared quickstart file could not be stored safely"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()


def prepare_loopback_compose(
    output: Path,
    *,
    refresh: bool = False,
    timeout_seconds: float = 20.0,
    source_url: str = DATAHUB_QUICKSTART_URL,
    expected_sha256: str = DATAHUB_QUICKSTART_SHA256,
) -> Path:
    """Create or validate the private local loopback-only Compose file."""

    destination = output.expanduser()
    if ".." in destination.parts:
        raise QuickstartSecurityError("prepared quickstart path must not contain traversal")
    source_cache = destination.with_name(f"{destination.name}.source")
    source: bytes
    if source_cache.exists() and not refresh:
        source = _read_regular_file(source_cache)
    else:
        try:
            with httpx.Client(
                timeout=timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.get(source_url)
        except httpx.HTTPError as exc:
            raise QuickstartSecurityError(
                "official DataHub quickstart could not be downloaded"
            ) from exc
        if response.status_code != 200:
            raise QuickstartSecurityError("official DataHub quickstart download failed")
        source = response.content
        harden_quickstart_compose(source, expected_sha256=expected_sha256)
        _write_private_file(source_cache, source)
    generated = harden_quickstart_compose(source, expected_sha256=expected_sha256)
    if destination.exists() and not refresh:
        existing = _read_regular_file(destination)
        if existing != generated:
            raise QuickstartSecurityError(
                "prepared quickstart differs from the checksum-pinned source"
            )
    else:
        _write_private_file(destination, generated)
    validate_loopback_compose(_read_regular_file(destination))
    return destination


def non_loopback_bindings(inspections: object) -> tuple[str, ...]:
    """Return safe container/port labels for published bindings outside loopback."""

    if not isinstance(inspections, list):
        raise QuickstartSecurityError("Docker inspect response is malformed")
    violations: list[str] = []
    for container in inspections:
        if not isinstance(container, Mapping):
            raise QuickstartSecurityError("Docker inspect container is malformed")
        name = container.get("Name")
        safe_name = name.lstrip("/") if isinstance(name, str) else "unknown"
        network = container.get("NetworkSettings")
        ports = network.get("Ports") if isinstance(network, Mapping) else None
        if not isinstance(ports, Mapping):
            raise QuickstartSecurityError("Docker inspect port bindings are missing")
        for container_port, bindings in ports.items():
            if bindings is None:
                continue
            if not isinstance(container_port, str) or not isinstance(bindings, list):
                raise QuickstartSecurityError("Docker inspect port binding is malformed")
            for binding in bindings:
                host_ip = binding.get("HostIp") if isinstance(binding, Mapping) else None
                try:
                    loopback = (
                        isinstance(host_ip, str) and ipaddress.ip_address(host_ip).is_loopback
                    )
                except ValueError:
                    loopback = False
                if not loopback:
                    violations.append(f"{safe_name}:{container_port}")
    return tuple(sorted(set(violations)))


def validate_running_datahub_bindings(inspections: object) -> None:
    """Require the exact healthy project and its six pinned loopback ports."""

    violations = non_loopback_bindings(inspections)
    if violations:
        joined = ", ".join(violations)
        raise QuickstartSecurityError(f"DataHub ports are published beyond loopback: {joined}")
    if not isinstance(inspections, list):
        raise QuickstartSecurityError("Docker inspect response is malformed")
    observed: set[int] = set()
    observed_services: dict[str, str] = {}
    observed_service_ports: dict[str, set[int]] = {}
    for container in inspections:
        if not isinstance(container, Mapping):
            raise QuickstartSecurityError("Docker inspect container is malformed")
        host_config = container.get("HostConfig")
        if not isinstance(host_config, Mapping):
            raise QuickstartSecurityError("Docker inspect host config is missing")
        if host_config.get("NetworkMode") != QUICKSTART_NETWORK_NAME:
            raise QuickstartSecurityError("DataHub live network mode does not match the pin")
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, Mapping) else None
        image = config.get("Image") if isinstance(config, Mapping) else None
        service = labels.get("com.docker.compose.service") if isinstance(labels, Mapping) else None
        project = labels.get("com.docker.compose.project") if isinstance(labels, Mapping) else None
        owner = labels.get(QUICKSTART_OWNER_LABEL) if isinstance(labels, Mapping) else None
        if (
            not isinstance(service, str)
            or not isinstance(image, str)
            or project != QUICKSTART_PROJECT_NAME
            or owner != QUICKSTART_OWNER_VALUE
        ):
            raise QuickstartSecurityError("Docker inspect service identity is missing")
        if service in observed_services:
            raise QuickstartSecurityError("DataHub has duplicate running Compose services")
        state = container.get("State")
        if (
            not isinstance(state, Mapping)
            or state.get("Running") is not True
            or state.get("Status") != "running"
        ):
            raise QuickstartSecurityError("DataHub live service is not running")
        health = state.get("Health")
        if service in EXPECTED_HEALTHY_SERVICES:
            if not isinstance(health, Mapping) or health.get("Status") != "healthy":
                raise QuickstartSecurityError("DataHub live service is not healthy")
        elif health is not None and (
            not isinstance(health, Mapping) or health.get("Status") != "healthy"
        ):
            raise QuickstartSecurityError("DataHub live service health is not ready")
        observed_services[service] = image
        observed_service_ports[service] = set()
        network = container.get("NetworkSettings")
        ports = network.get("Ports") if isinstance(network, Mapping) else None
        attached_networks = network.get("Networks") if isinstance(network, Mapping) else None
        if not isinstance(ports, Mapping):
            raise QuickstartSecurityError("Docker inspect port bindings are missing")
        if not isinstance(attached_networks, Mapping) or set(attached_networks) != {
            QUICKSTART_NETWORK_NAME
        }:
            raise QuickstartSecurityError("DataHub live network set does not match the pin")
        for container_port, bindings in ports.items():
            if bindings is None:
                continue
            if not isinstance(container_port, str) or not isinstance(bindings, list):
                raise QuickstartSecurityError("Docker inspect port binding is malformed")
            if not bindings:
                raise QuickstartSecurityError("Docker inspect contains an empty port binding")
            target_text, separator, protocol = container_port.partition("/")
            if separator != "/" or protocol != "tcp":
                raise QuickstartSecurityError("DataHub published a non-TCP port")
            target = _port_number(target_text, field="target")
            for binding in bindings:
                host_port = binding.get("HostPort") if isinstance(binding, Mapping) else None
                if _port_number(host_port, field="host") != target:
                    raise QuickstartSecurityError(
                        "DataHub live host-port mapping does not match the pin"
                    )
            observed.add(target)
            observed_service_ports[service].add(target)
    if observed != set(PUBLISHED_TARGETS):
        raise QuickstartSecurityError("DataHub live published-port set does not match the pin")
    if observed_services != EXPECTED_RUNNING_IMAGES:
        raise QuickstartSecurityError("DataHub live service or image set does not match the pin")
    if observed_service_ports != EXPECTED_RUNNING_PORTS:
        raise QuickstartSecurityError("DataHub live service port ownership does not match the pin")


def _docker_executable() -> str:
    docker = shutil.which("docker")
    if docker is None:
        raise QuickstartSecurityError("Docker is not installed")
    return docker


def _project_identifiers(docker: str, *, include_stopped: bool = False) -> list[str]:
    command = [docker, "ps", "--no-trunc"]
    if include_stopped:
        command.append("-a")
    command.extend(
        [
            "-q",
            "--filter",
            f"label=com.docker.compose.project={QUICKSTART_PROJECT_NAME}",
        ]
    )
    try:
        listed = subprocess.run(  # noqa: S603 - executable path resolved locally
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise QuickstartSecurityError("running DataHub containers could not be listed") from exc
    identifiers = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    if any(re.fullmatch(r"[0-9a-f]{12,64}", identifier) is None for identifier in identifiers):
        raise QuickstartSecurityError("Docker returned an invalid container identifier")
    return identifiers


def _reserved_network(
    docker: str,
    *,
    allow_absent: bool,
) -> Mapping[str, Any] | None:
    """Load the one exact reserved network without trusting a partial name match."""

    try:
        listed = subprocess.run(  # noqa: S603 - fixed Docker metadata command
            [
                docker,
                "network",
                "ls",
                "--quiet",
                "--no-trunc",
                "--filter",
                f"name=^{QUICKSTART_NETWORK_NAME}$",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise QuickstartSecurityError("reserved DataHub network could not be listed") from exc
    identifiers = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    if not identifiers:
        if allow_absent:
            return None
        raise QuickstartSecurityError("reserved DataHub network is missing")
    if len(identifiers) != 1 or re.fullmatch(r"[0-9a-f]{64}", identifiers[0]) is None:
        raise QuickstartSecurityError("reserved DataHub network identity is invalid")
    network_id = identifiers[0]
    try:
        inspected = subprocess.run(  # noqa: S603 - validated Docker network identifier
            [docker, "network", "inspect", network_id],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        payload = json.loads(inspected.stdout)
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as exc:
        raise QuickstartSecurityError("reserved DataHub network could not be inspected") from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], Mapping):
        raise QuickstartSecurityError("reserved DataHub network inspection is malformed")
    network = payload[0]
    labels = network.get("Labels")
    if (
        network.get("Id") != network_id
        or network.get("Name") != QUICKSTART_NETWORK_NAME
        or not isinstance(labels, Mapping)
        or labels.get("com.docker.compose.project") != QUICKSTART_PROJECT_NAME
        or labels.get("com.docker.compose.network") != "default"
        or labels.get(QUICKSTART_OWNER_LABEL) != QUICKSTART_OWNER_VALUE
    ):
        raise QuickstartSecurityError("reserved DataHub network identity does not match the pin")
    return network


def _verify_reserved_network_membership(
    docker: str,
    container_ids: list[str],
    *,
    allow_absent: bool,
    require_exact: bool,
) -> None:
    """Reject foreign endpoints and, for a live stack, require exact membership."""

    network = _reserved_network(docker, allow_absent=allow_absent)
    if network is None:
        return
    raw_endpoints = network.get("Containers")
    if not isinstance(raw_endpoints, Mapping):
        raise QuickstartSecurityError("reserved DataHub network endpoints are malformed")
    endpoints: set[str] = set()
    for identifier, endpoint in raw_endpoints.items():
        if (
            not isinstance(identifier, str)
            or re.fullmatch(r"[0-9a-f]{64}", identifier) is None
            or not isinstance(endpoint, Mapping)
            or identifier in endpoints
        ):
            raise QuickstartSecurityError("reserved DataHub network endpoints are malformed")
        endpoints.add(identifier)
    expected = set(container_ids)
    if require_exact:
        if endpoints != expected:
            raise QuickstartSecurityError(
                "reserved DataHub network endpoint set does not match the running project"
            )
    elif not endpoints.issubset(expected):
        raise QuickstartSecurityError("reserved DataHub network contains a foreign endpoint")


def _inspect_project_containers(
    docker: str,
    identifiers: list[str],
    *,
    purpose: str,
) -> object:
    try:
        inspected = subprocess.run(  # noqa: S603 - container IDs are validated by the caller
            [docker, "inspect", *identifiers],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        return json.loads(inspected.stdout)
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as exc:
        raise QuickstartSecurityError(
            f"running DataHub containers could not be inspected before {purpose}"
        ) from exc


def _validate_cleanup_candidates(inspections: object, *, expected_count: int) -> None:
    """Prove cleanup targets belong to this pinned quickstart before stopping them."""

    if not isinstance(inspections, list) or len(inspections) != expected_count:
        raise QuickstartSecurityError(
            "refusing cleanup because the DataHub container set changed during inspection"
        )
    observed_services: set[str] = set()
    for container in inspections:
        config = container.get("Config") if isinstance(container, Mapping) else None
        labels = config.get("Labels") if isinstance(config, Mapping) else None
        image = config.get("Image") if isinstance(config, Mapping) else None
        project = labels.get("com.docker.compose.project") if isinstance(labels, Mapping) else None
        service = labels.get("com.docker.compose.service") if isinstance(labels, Mapping) else None
        owner = labels.get(QUICKSTART_OWNER_LABEL) if isinstance(labels, Mapping) else None
        if (
            project != QUICKSTART_PROJECT_NAME
            or owner != QUICKSTART_OWNER_VALUE
            or not isinstance(service, str)
            or EXPECTED_CLEANUP_IMAGES.get(service) != image
            or service in observed_services
        ):
            raise QuickstartSecurityError(
                "refusing to stop an unrecognized DataHub Compose container"
            )
        observed_services.add(service)


def verify_local_docker_endpoint() -> str:
    """Reject remote Docker daemons because loopback would not mean this host."""

    docker = _docker_executable()
    candidates: list[str] = []
    override = os.environ.get("DOCKER_HOST")
    if override:
        candidates.append(override)
    try:
        inspected = subprocess.run(  # noqa: S603 - fixed Docker metadata command
            [docker, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise QuickstartSecurityError("Docker context could not be inspected") from exc
    candidates.extend(line.strip() for line in inspected.stdout.splitlines() if line.strip())
    if not candidates:
        raise QuickstartSecurityError("Docker context has no endpoint")
    for endpoint in candidates:
        parsed = urlsplit(endpoint)
        if parsed.scheme != "unix" or not parsed.path.startswith("/"):
            raise QuickstartSecurityError("remote Docker contexts are not supported")
    return candidates[-1]


def stop_running_datahub() -> int:
    """Stop only this pinned DataHub quickstart's containers and prove it stopped."""

    docker = _docker_executable()
    identifiers = _project_identifiers(docker)
    if not identifiers:
        return 0
    inspections = _inspect_project_containers(docker, identifiers, purpose="cleanup")
    _validate_cleanup_candidates(inspections, expected_count=len(identifiers))
    try:
        subprocess.run(  # noqa: S603 - validated Docker container identifiers
            [docker, "stop", "--time", "20", *identifiers],
            check=True,
            capture_output=True,
            text=True,
            timeout=45,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise QuickstartSecurityError("DataHub containers could not be stopped") from exc
    if _project_identifiers(docker):
        raise QuickstartSecurityError("DataHub containers remain running after cleanup")
    return len(identifiers)


def verify_running_datahub_bindings() -> int:
    """Verify the reserved project is exact, healthy, and loopback-only."""

    docker = _docker_executable()
    identifiers = _project_identifiers(docker)
    if not identifiers:
        raise QuickstartNotRunning("no running DataHub quickstart containers were found")
    payload = _inspect_project_containers(docker, identifiers, purpose="verification")
    validate_running_datahub_bindings(payload)
    _verify_reserved_network_membership(
        docker,
        identifiers,
        allow_absent=False,
        require_exact=True,
    )
    return len(identifiers)


def verify_startup_project_ownership() -> int:
    """Refuse startup if the reserved Compose project contains foreign containers."""

    docker = _docker_executable()
    identifiers = _project_identifiers(docker, include_stopped=True)
    if identifiers:
        inspections = _inspect_project_containers(docker, identifiers, purpose="startup")
        _validate_cleanup_candidates(inspections, expected_count=len(identifiers))
    _verify_reserved_network_membership(
        docker,
        identifiers,
        allow_absent=True,
        require_exact=False,
    )
    return len(identifiers)


__all__ = [
    "DATAHUB_QUICKSTART_SHA256",
    "DATAHUB_QUICKSTART_URL",
    "EXPECTED_CLEANUP_IMAGES",
    "EXPECTED_RUNNING_IMAGES",
    "EXPECTED_RUNNING_PORTS",
    "LOOPBACK_HOST",
    "PUBLISHED_TARGETS",
    "QUICKSTART_NETWORK_NAME",
    "QUICKSTART_OWNER_LABEL",
    "QUICKSTART_OWNER_VALUE",
    "QUICKSTART_PROJECT_NAME",
    "QuickstartNotRunning",
    "QuickstartSecurityError",
    "harden_quickstart_compose",
    "non_loopback_bindings",
    "prepare_loopback_compose",
    "stop_running_datahub",
    "validate_loopback_compose",
    "validate_running_datahub_bindings",
    "verify_local_docker_endpoint",
    "verify_running_datahub_bindings",
    "verify_startup_project_ownership",
]
