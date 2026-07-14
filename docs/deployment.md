# Deployment preparation

Development and verification are local. No public deployment is included.

`deploy/Dockerfile` is a checked-in, non-root, read-only-review container
recipe. It requires a sanitized synthetic `latest.json` mounted at runtime and
an explicit accepted public Host value. The installed application package still
contains the local CLI modules, but the container command exposes only the
read-only review app and must receive no DataHub credential. The image has not
been published or deployed. It was built and security-smoke-tested locally on
2026-07-14 with the sealed synthetic report.

## Recommended public-demo shape

Public hosting is optional: the hackathon overview permits the public repository
with clear setup instructions to serve as the Project URL. If a hosted surface
is added, the safest shape is a read-only review app containing only a
verified synthetic Acme report. DataHub Core, its token, and the MCP mutation
path should stay private. The public artifact does not need catalog access
after the recorded run is generated.

Preparation sequence for any public deployment:

1. run the full local demo and confirm MCP readback;
2. review `report.json`, `report.md`, `report.html`, and screenshots for secrets
   or non-synthetic identities;
3. make a separately reviewed `0444` copy of only the verified synthetic
   `latest.json`; the Docker build context excludes tests, docs, caches,
   instruction files, and local artifacts;
4. run the UI as an unprivileged process with `--read-only`, dropped
   capabilities, and only a small no-exec `/tmp` tmpfs;
5. expose only the HTTP review route and health check;
6. set a 5 MiB artifact ceiling and retain the current CSP/security
   headers; and
7. verify the public URL in a clean browser before including it in Devpost.

## Runtime command

The application entry point is:

```text
uvicorn lineageguard.review_ui.app:app
```

The checked-in `lineageguard serve` wrapper intentionally binds only to
`127.0.0.1`. A future container or hosting configuration would bind the same
read-only app to its platform-provided interface; the prepared container does
this with Uvicorn and `LINEAGEGUARD_ALLOWED_HOSTS`. It must not include a
DataHub token, `.env`, `.lineageguard/datahub-token`, the local DuckDB file, or
non-synthetic reports.

## Cost gate

Prefer the repository-only Project URL or a free hosting tier. The submission
does not require a paid domain, hosting, storage, or video service.

## Rollback

Because the public surface is immutable synthetic evidence, rollback is a
single previous image/artifact. The local DataHub environment remains the
source of truth for regeneration and is never reachable from the public app.
