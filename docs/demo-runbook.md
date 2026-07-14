# Local demo runbook

This runbook produces the evidence required for a real LineageGuard demo. It
must not be replaced by mocked MCP responses or a prewritten result JSON.

## 1. Host check

Start Docker Desktop or the Docker daemon, then run:

```bash
make datahub-preflight
```

Expected result:

```text
PASS: local Docker resources and all six DataHub ports passed preflight.
```

The check requires a local Unix-socket Docker context, Compose v2, `uv`, two
Docker CPUs, 8 GB Docker memory, swap support, and approximately 13 GiB free on
the host filesystem. On Linux it also requires at least 2 GiB configured swap;
macOS manages swap dynamically, so only availability can be established there.
Ports 3306, 4319, 8080, 9002, 9092, and 9200 must be free or belong to the exact
healthy pinned quickstart. The upstream startup check independently measures
free space inside the Docker daemon before launching Core.

## 2. Start pinned DataHub Core

```bash
make datahub-up
```

This checksum-verifies and hardens the official Compose source, reconciles
DataHub Core `v1.6.0`, proves the six live ports and exact service images, safely
ensures a private local token, and upserts the eight LineageGuard structured
properties. A failed partial launch is stopped without deleting its volumes.

On first token creation, the hidden prompt expects the official quickstart
password. The unchanged quickstart credentials are username `datahub`, password
`datahub`. Confirm that:

- `http://127.0.0.1:9002` opens;
- `.lineageguard/datahub-token` exists with mode `0600`; and
- no token value appears in terminal output.

The official local Core disables GMS bearer enforcement. Existing PATs are
therefore labelled `REUSED_UNVERIFIABLE`; that is an honest local limitation,
not a failed demo. Loopback-only exposure is the security boundary.

## 3. Run the real closed loop

```bash
make test-datahub
make demo
```

The live test retains an automated assertion that Core, the official MCP
server, mutation tools, and readback all agree before the presentation run.

The command performs all of the following in fresh temporary projects:

1. builds the green baseline;
2. compiles the proposed rename;
3. proves the unremediated downstream build fails on `order_total`;
4. emits the deterministic official-SDK DataHub seed plan;
5. starts the official MCP server over stdio and checks capabilities;
6. resolves the catalog baseline and traces downstream column lineage;
7. scores the initial change;
8. generates the compatibility bridge;
9. runs dbt seed, parse, and build in another isolated copy;
10. compares the verified compiled future against the baseline;
11. writes the change passport through MCP; and
12. reads the required state back through MCP.

The terminal result must show:

```text
Decision              PASS_WITH_REMEDIATION
Remediation           TESTED
DataHub writeback     VERIFIED
```

Do not record a final demo if writeback is `WRITEBACK_PENDING`.

## 4. Inspect the durable state

In DataHub, open the `stg_orders` dataset and verify:

- the downstream `fct_daily_revenue` lineage;
- the dbt job, chart, dashboard, owners, tags, and assertion in the graph;
- the `LineageGuard_PASS_WITH_REMEDIATION` tag;
- all eight `io.lineageguard.*` structured properties, including
  `writebackState=VERIFIED`; and
- the related LineageGuard decision document.

The values must match `.lineageguard/runs/latest.json`.

## 5. Review the report

```bash
make serve
```

Open `http://127.0.0.1:8765`. Capture screenshots only after confirming the UI
is reading the same verified run ID and evidence hash as DataHub.

The portable files are retained under:

```text
.lineageguard/runs/<run-id>-<artifact-hash-prefix>/report.json
.lineageguard/runs/<run-id>-<artifact-hash-prefix>/report.md
.lineageguard/runs/<run-id>-<artifact-hash-prefix>/report.html
.lineageguard/runs/<run-id>-<artifact-hash-prefix>/demo-preflight.json
.lineageguard/runs/latest.json
.lineageguard/runs/demo-preflight-latest.json
```

## Recovery

- If preflight reports Docker stopped, start Docker and rerun it.
- If a port is occupied by an unhealthy or unrelated service, repair or stop
  it; a healthy existing quickstart is accepted and reused.
- A definitively rejected token is replaced. A timeout, 5xx, invalid response,
  auth-disabled response, or unexpected service preserves the existing token.
- `--force` refuses to orphan a valid or unverifiable PAT; revoke it explicitly
  before intentional rotation.
- If MCP capability discovery fails, compare the pinned Core and MCP versions.
- If catalog resolution is stale, reseed the demo and inspect the physical
  relation name rather than weakening matching.
- If writeback is pending, inspect the secret-free MCP trace and retry the
  entire synthetic run. Do not relabel the existing result as verified.
