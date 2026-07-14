# Security and trust model

LineageGuard handles source code, catalog metadata, local credentials, and
generated SQL. Its default posture is fail closed: missing proof can produce a
report, but it cannot produce a safe final decision.

## Trust boundaries

### Manifest evidence, project source, and DataHub metadata

dbt manifests, URNs, owner names, tags, document text, and MCP responses are
untrusted data. They are parsed or displayed as text and never evaluated by
LineageGuard itself.

The dbt verifier necessarily asks dbt to compile and execute project SQL and
Jinja. A temporary copy, reduced environment, fixed command allowlist, and
symlink rejection are useful containment, but they are not an OS sandbox.
Version 0.1 therefore supports trusted or already-reviewed repositories only;
do not run it on hostile fork code without a separate no-network,
dropped-privilege CI/container boundary.

The review UI uses `textContent`, a restrictive content security policy, local
assets, and no inline script. The API reads at most 5 MiB and rejects invalid
UTF-8, non-standard JSON numbers, malformed JSON, and directories. Standalone
Markdown reports entity-escape prose/table values and choose a code fence
longer than any backtick run in an untrusted diff.

### Remediation generation

The automatic generator supports exactly one high-confidence column rename.
The target projection must be a direct column or a cast directly around one
column. Model, schema, and test destinations must match an exact allowlist of
safe relative paths. Absolute paths, traversal, alternate separators,
duplicates, existing test files, ambiguous projections, Jinja control blocks,
and arbitrary macros are rejected.

### Verification subprocess

Verification runs in a new temporary copy and never modifies the supplied PR
workspace. It rejects symlinked or drifting targets and executes only these
fixed commands with `shell=False`:

```text
dbt seed
dbt parse
dbt build --select <validated selector>
```

The environment is reduced to process essentials. DataHub tokens and other
application secrets are not passed into dbt. Each command has a timeout;
captured output is bounded and content-addressed.

### Counterfactual evidence

The verified `target/manifest.json` is converted into a canonical v3 snapshot.
Only adapter, quote-aware physical relation, a digest of full model
configuration, hashed column constraints and compiled attached-test semantics,
hashed model-level constraints, a set of compiled model/singular test
identities, an ordered quote-aware projection map, and a hash of every
non-projection query clause remain. Raw compiled SQL, raw dbt configuration,
environment detail, and temporary paths are excluded. Both snapshot content
and SHA-256 digest are checked before comparison. The bridge must keep the
legacy column at its exact ordinal and may append only the intended replacement
projection/contract and generated equality test; row-set clauses, baseline
tests, and every other projection/contract must match the baseline.

### DataHub credentials and mutations

The local DataHub launcher accepts only a Unix-socket Docker context. It
checksum-verifies the official v1.6.0 Compose source, retains that exact source
in an owner-only cache, and regenerates a canonical file with all six published
ports fixed to `127.0.0.1`. Every start reconciles from that file with orphan
removal. Before any login credential is used, live inspection must prove the
exact six service images, exact host/container ports, non-host networking, and
loopback bindings. A failed or unverifiable partial start is stopped without
deleting volumes, but only after every cleanup target matches the generated
LineageGuard owner label and the exact allowlist of quickstart service/image
pairs. The launcher reserves the `lineageguard-datahub` Compose project and
`lineageguard_datahub_network`; before startup it rejects any running or stopped
container already in that project unless its owner, service, and image match
the canonical file. A generic project named `datahub` is never selected for
verification or cleanup. User-home bind mounts from the upstream file are
removed; only named quickstart volumes remain.

Container registry manifests are not pinned by immutable digest. This is an
explicit residual supply-chain risk: the seven quickstart and setup images span
DataHub, Confluent, MySQL, and OpenSearch publishers, while the upstream DataHub
CLI is tag-oriented and can continue with a cached tag when a pull fails. A
2026-07-14 registry check found both `linux/amd64` and `linux/arm64` in every
current tag's multi-platform index, but those digest references were not put in
the release path without clean startup and lifecycle verification through the
pinned CLI on both architectures. Closing this residual requires a maintained
index-digest catalog, a fail-closed pull step, and cross-architecture quickstart
tests. Until then, run only on a trusted Docker host; the operator must abort if
the CLI reports a failed pull or live image identity verification fails.

The local quickstart token is stored at `.lineageguard/datahub-token` as a
regular current-user file with mode `0600`, ignored by Git, and never printed.
A blank token environment variable falls through to the private file rather
than overriding it. Non-loopback GMS URLs require HTTPS, and the synthetic seed
hard-rejects non-loopback targets.

Token creation and replacement are serialized by a persistent owner-only lock.
A private-file failure after minting triggers exact PAT revocation through the
authenticated frontend when the returned JWT supplies its registry ID. The
official quickstart disables GMS bearer enforcement, so validation compares the
candidate with a deliberately invalid control and records
`AUTH_DISABLED_OR_UNVERIFIABLE`; it never represents that response as proof of
valid authentication. `--force` refuses valid or unverifiable tokens rather
than orphaning them. A response lost before the token or registry ID reaches
the client remains an unavoidable remote-API ambiguity and requires operator
inspection.

The MCP server starts with mutations disabled for read-only analysis. The
`--writeback` flag enables the narrow allowlist for that process. MCP reads may
retry after transient failures; mutations are attempted once because retrying
an ambiguous mutation could duplicate or overwrite state.

The MCP child receives `DATAHUB_EMIT_MODE=SYNC_WAIT`; search-backed document
relations can still trail by an index refresh, so LineageGuard performs bounded
read-only retries and never replays a mutation. MCP 0.6.0 can cache a
document-free discovery result for 60 seconds; only an acknowledged
`save_document` unlocks a direct call to the already registered,
read-allowlisted `grep_documents` handler. No other unadvertised tool can cross
the capability gate.

Writeback uses eight exact-singleton structured properties, one mutually
exclusive decision tag, and one DataHub document. It first writes
`writebackState=PENDING` and the neutral document. OSS-compatible MCP readback
uses dataset `relatedDocuments` for the relationship and an anchored
`grep_documents` query for exact title/content. Only then are stale
LineageGuard decision tags removed and the current tag added. That exact tag is
read back while state remains `PENDING`; state is changed to `VERIFIED` only
afterward, and a final dataset/document readback proves the final state.

The returned document URN is stored in an ignored, owner-only per-run pointer
validated by run ID, evidence hash, schema version, ownership, and mode. A
nonblocking per-run file lock rejects concurrent local writers. An identical
already-verified retry proves the exact remote state and returns without any
mutation. A pending retry resumes against the same document, and a
missing pointer triggers an exhaustive exact-title search plus identity
readback so an acknowledged-late `save_document` can be recovered without a
duplicate. Missing, ambiguous, or corrupt evidence fails pending;
LineageGuard never invents or silently rebinds a document URN.

Before a first `save_document`, a durable `ATTEMPTED` journal is fsynced. If the
mutation response is lost and recovery search is unavailable or cannot prove
the exact document, a later process remains pending and never replays the save.

## Fail-closed cases

- ambiguous relation resolution;
- stale catalog column or type fingerprint;
- unavailable or truncated lineage;
- missing ownership or assertion enrichment;
- missing required MCP capability;
- unsupported or ambiguous source change;
- generated-target drift or symlink;
- dbt timeout, nonzero exit, or missing compiled manifest;
- counterfactual snapshot drift or lost compatibility interface; and
- mutation failure or readback mismatch.

These states never become `PASS_WITH_REMEDIATION`.

Local report directories are owner-only (`0700`) and files are `0600`. The
review server binds to loopback, rejects non-loopback Host headers by default,
validates the complete `RunResult` schema, and recomputes the artifact integrity
seal before returning a run. The seal detects accidental or post-write drift;
it is not a signature against an attacker who can rewrite both content and
hash.

Git provenance separates source identity from analyzed inputs. `HEAD` is
recorded only when the repository is clean, required source files are tracked
and unchanged, generated destinations stay inside the project, and no ignored
file that would enter the isolated dbt copy is present. Ignored `target`, `logs`,
`.git`, and DuckDB outputs are allowed only because the copier excludes them.
Otherwise the source identity is `WORKTREE`. Caller-supplied manifests are
labelled `SUPPLIED_MANIFESTS`; demo manifests compiled in the current process
are labelled `GENERATED_IN_PROCESS`. In both cases their exact bytes are bound
by independent SHA-256 values, so a source commit never claims that generated
manifest or equality-test output was itself committed.

## Dependency audit

The fully pinned all-extras dependency export was re-audited on 2026-07-14.
Updating `pytest` to 9.1.1 removed its previously reported advisory. One known
transitive advisory remains: `setuptools` 81.0.0 is affected by
[`PYSEC-2026-3447`](https://osv.dev/vulnerability/PYSEC-2026-3447), whose fixed
release is 83.0.0, while pinned `acryl-datahub` 1.6.0.10 requires
`setuptools<82.0.0`. LineageGuard does not override that incompatible upstream
constraint; its own package uses Hatchling, while the affected dependency is
retained for the local DataHub tooling. Re-audit and upgrade as soon as the
pinned DataHub release permits the fixed version.

## Publication boundary

Generated reports contain URNs, owner identities, diffs, and command output.
Only the synthetic Acme run is suitable for publication without a separate
data review. Credentials are excluded by construction, but a human should
still inspect every artifact before any repository, deployment, or video is
made public.
