# Read-only review container

This is deployment preparation only. The image was built and security-smoke-
tested locally on 2026-07-14; no image has been published or deployed.

First make a separately reviewed, world-readable-in-container copy. Do not
mount the owner-only `0600` retained evidence file directly:

```bash
install -d -m 0755 artifacts/public
install -m 0444 .lineageguard/runs/latest.json artifacts/public/latest.json
```

Build after that synthetic artifact has passed human data review:

```bash
docker build -f deploy/Dockerfile -t lineageguard-review:local .
```

Run the local container smoke test with only the sanitized `latest.json`
mounted read-only. Port 8765 avoids DataHub GMS on 8080, and the loopback host
mapping keeps this command local:

```bash
docker run --rm -p 127.0.0.1:8765:8080 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop=ALL --security-opt=no-new-privileges \
  -e LINEAGEGUARD_ALLOWED_HOSTS=demo.example \
  -v "$PWD/artifacts/public/latest.json:/data/latest.json:ro" \
  lineageguard-review:local
```

A later public platform must supply its exact public host through
`LINEAGEGUARD_ALLOWED_HOSTS`; wildcards are rejected.

The health check reads the mounted artifact endpoint, so an absent, unreadable,
oversized, or invalid artifact does not report ready. Dependencies are selected
from `uv.lock`; the Python base is pinned to an exact multi-platform manifest
digest. Rebuild the application image and record its resulting digest before
publication.

Do not copy or mount a DataHub token, `.env`, local DuckDB file, non-synthetic
report, or document index. No public deployment is configured by this
repository.
