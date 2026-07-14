#!/usr/bin/env bash
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "${root}"
compose_file=.lineageguard/datahub/docker-compose.v1.6.0-loopback.yml
# The pinned verifier and the upstream DataHub CLI must always address the same
# reserved project, regardless of inherited shell configuration.
export DATAHUB_COMPOSE_PROJECT_NAME=lineageguard-datahub

local_password=${DATAHUB_LOCAL_PASSWORD-}
local_password_set=${DATAHUB_LOCAL_PASSWORD+x}
unset DATAHUB_LOCAL_PASSWORD

./scripts/datahub-preflight.sh

uv run python scripts/datahub-quickstart.py prepare --output "${compose_file}"
uv run python scripts/datahub-quickstart.py verify-startup

cleanup_failed_start() {
  if ! uv run python scripts/datahub-quickstart.py stop-running; then
    echo "FAIL cleanup: DataHub may still be running; inspect Docker immediately." >&2
    return 1
  fi
}

if ! uvx --from 'acryl-datahub==1.6.0.10' datahub docker quickstart \
    --version v1.6.0 \
    -f "${compose_file}"; then
  echo "FAIL startup: stopping all partial DataHub containers without deleting data." >&2
  cleanup_failed_start || exit 3
  exit 2
fi
if ! uv run python scripts/datahub-quickstart.py verify-running; then
  echo "FAIL security: stopping DataHub because its live configuration was not verified." >&2
  cleanup_failed_start || exit 3
  exit 2
fi
echo "Pinned DataHub v1.6.0 was reconciled and verified on loopback."

gms_url=${DATAHUB_GMS_URL:-http://127.0.0.1:8080}
frontend_url=${DATAHUB_FRONTEND_URL:-http://127.0.0.1:9002}
token_file=${DATAHUB_GMS_TOKEN_FILE:-${LINEAGEGUARD_DATAHUB_GMS_TOKEN_FILE:-.lineageguard/datahub-token}}
case "${token_file}" in
  "~/"*) token_file="${HOME}/${token_file:2}" ;;
esac

token_args=(
  scripts/create-local-token.py
  --ensure
  --gms-url "${gms_url}"
  --frontend-url "${frontend_url}"
  --output "${token_file}"
)
if [ "${local_password_set}" = x ]; then
  DATAHUB_LOCAL_PASSWORD="${local_password}" uv run python "${token_args[@]}"
else
  uv run python "${token_args[@]}"
fi
unset local_password local_password_set

IFS= read -r token < "${token_file}"
DATAHUB_GMS_TOKEN="${token}" DATAHUB_GMS_URL="${gms_url}" \
  uv run datahub properties upsert -f config/structured-properties.yaml
unset token

echo "DataHub Core and LineageGuard structured properties are ready locally."
