#!/usr/bin/env bash
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "${root}"

required_kib=$((13 * 1024 * 1024))
available_kib=$(df -Pk "${PWD}" | awk 'NR == 2 {print $4}')

if ! command -v docker >/dev/null 2>&1; then
  echo "FAIL docker: Docker is not installed." >&2
  exit 2
fi

if ! docker info >/dev/null 2>&1; then
  echo "FAIL docker: Docker Desktop or the Docker daemon is not running." >&2
  exit 2
fi

resource_line=$(docker info --format '{{.NCPU}} {{.MemTotal}} {{.MemoryLimit}} {{.SwapLimit}}')
set -- ${resource_line}
if [ "$#" -ne 4 ]; then
  echo "FAIL resources: Docker returned an unexpected resource summary." >&2
  exit 2
fi
cpu_count=$1
memory_bytes=$2
memory_limits=$3
swap_limits=$4
case "${cpu_count}:${memory_bytes}" in
  *[!0-9:]*|:*|*:)
    echo "FAIL resources: Docker returned invalid CPU or memory values." >&2
    exit 2
    ;;
esac
if [ "${cpu_count}" -lt 2 ]; then
  echo "FAIL CPU: Docker has ${cpu_count}; DataHub requires at least 2." >&2
  exit 2
fi
required_memory_bytes=8000000000
if [ "${memory_bytes}" -lt "${required_memory_bytes}" ]; then
  memory_gb=$(awk -v bytes="${memory_bytes}" 'BEGIN {printf "%.1f", bytes / 1000 / 1000 / 1000}')
  echo "FAIL memory: Docker has ${memory_gb} GB; DataHub requires at least 8 GB." >&2
  exit 2
fi
if [ "${memory_limits}" != true ] || [ "${swap_limits}" != true ]; then
  echo "FAIL resources: Docker memory and swap-limit support are required." >&2
  exit 2
fi

case "$(uname -s)" in
  Linux)
    swap_kib=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)
    if [ -z "${swap_kib}" ] || [ "${swap_kib}" -lt $((2 * 1024 * 1024)) ]; then
      echo "FAIL swap: Linux has less than the documented 2 GiB swap allocation." >&2
      exit 2
    fi
    ;;
  Darwin)
    if ! sysctl -n vm.swapusage >/dev/null 2>&1; then
      echo "FAIL swap: macOS swap availability could not be verified." >&2
      exit 2
    fi
    echo "NOTE: macOS swap is dynamic; availability was verified, not a fixed 2 GiB allocation."
    ;;
  *)
    echo "FAIL swap: unsupported host; 2 GiB swap cannot be verified." >&2
    exit 2
    ;;
esac

if ! docker compose version >/dev/null 2>&1; then
  echo "FAIL compose: Docker Compose v2 is required." >&2
  exit 2
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "FAIL uv: install uv before running the local MCP server." >&2
  exit 2
fi

uv run python scripts/datahub-quickstart.py verify-local-endpoint

if ! command -v lsof >/dev/null 2>&1; then
  echo "FAIL lsof: install lsof so preflight can prove DataHub ports are free." >&2
  exit 2
fi

occupied_ports=""
for port in 3306 4319 8080 9002 9092 9200; do
  if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
    occupied_ports="${occupied_ports} ${port}"
  fi
done

if [ -n "${occupied_ports}" ]; then
  if uv run python scripts/datahub-quickstart.py verify-running >/dev/null; then
    echo "PASS: existing healthy DataHub quickstart detected."
    exit 0
  fi
  echo "FAIL port: TCP${occupied_ports} occupied without a healthy DataHub quickstart." >&2
  exit 2
fi

if [ -z "${available_kib}" ] || [ "${available_kib}" -lt "${required_kib}" ]; then
  available_gib=$(awk -v kib="${available_kib:-0}" 'BEGIN {printf "%.1f", kib / 1024 / 1024}')
  echo "FAIL host disk: ${available_gib} GiB free; DataHub documents approximately 13 GiB." >&2
  exit 2
fi

echo "PASS: local Docker resources and all six DataHub ports passed preflight."
