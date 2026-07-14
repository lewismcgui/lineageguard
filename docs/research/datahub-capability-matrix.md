# Pinned DataHub capability matrix

Source-audited against the pinned DataHub Core `v1.6.0`, DataHub CLI/SDK
`acryl-datahub==1.6.0.10`, and official MCP server
`mcp-server-datahub==0.6.0`, then re-checked against the complete local
Core/MCP run on 2026-07-12.

| Capability | Interface | LineageGuard use | Fail-closed rule |
| --- | --- | --- | --- |
| Dataset resolution | MCP `search` | Exhaustive keyword search filtered to datasets | Stable `total`, `start`, complete pages, unique valid URNs |
| Catalog baseline | MCP `list_schema_fields` | Exact source column and native-type fingerprint | Returned URN must equal the resolved dataset and page totals must reconcile; missing, duplicate, or stale field/type blocks completion |
| Blast radius | MCP `get_lineage` | Downstream column lineage to three hops | GraphQL `total` is authoritative; malformed pages or totals above the pinned 100-result window mark traversal truncated |
| Owners/assets | MCP `get_entities` | Dataset, job, chart, dashboard, tags, and owners | Every returned identity and hop is validated; incomplete enrichment stays missing |
| Assertion definitions | Read-only DataHub GraphQL | Native Assertion definitions for source/downstream datasets | Narrow authenticated query with strict page/URN validation; no run events are seeded or scored |
| Decision state | MCP `add_structured_properties` | Scores, run/commit/evidence identity, remediation and two-phase writeback state | Initial state is `PENDING`; final state is `VERIFIED` only after readback |
| Decision tag | MCP `remove_tags`, `add_tags` | Exactly one mutually exclusive LineageGuard decision badge | Stale decision tags are removed only after pending-state readback succeeds |
| Passport | MCP `save_document` | Small neutral identity document related to the source dataset | Reuse only a returned, recovered, or locally indexed URN whose exact identity reads back |
| Durability proof | MCP `get_entities`, `grep_documents` | Dataset properties/tag/`relatedDocuments`, plus exact anchored document title/content | `SYNC_WAIT` plus bounded read-only projection retries; pending tag state reads back before `VERIFIED` |

At MCP startup, LineageGuard enumerates every tool page and refuses to continue
if required read tools are absent. Mutation tools are required at the moment of
use; there is no silent fallback to mocks or an alternate write path.

The pinned MCP document middleware caches a document-free `list_tools` result
for 60 seconds, but it filters discovery only: a newly created document can be
read immediately through the already-registered `grep_documents` handler.
After, and only after, an acknowledged `save_document`, LineageGuard permits
that one allowlisted hidden read while the cache expires. It also forces the
official SDK's supported `DATAHUB_EMIT_MODE=SYNC_WAIT`, because its default
`SYNC_PRIMARY` mode does not wait for the search projection used by document
readback. The relation can still trail by an index refresh, so LineageGuard
retries only the semantic reads and never replays a mutation. An already
`VERIFIED` exact retry is a read-only no-op.

`get_entities` returns at most the first ten related documents in this pinned
server. Its `count` is the requested page size rather than the hydrated list
length. LineageGuard bounds the list by both `count` and `total`, rejects
malformed or duplicate entries, and requires the exact passport URN/title. A
returned exact relation proves inclusion even when other search hits fail
hydration; if the passport is absent, LineageGuard fails pending instead of
claiming durability.

## Known MCP 0.6.0 lineage window

The pinned implementation sends `start=0` and `count=max_results` to
`searchAcrossLineage`, then applies the public `offset` to that already-limited
prefix. Its derived `hasMore` can therefore be false when the preserved GraphQL
`total` is greater than 100. LineageGuard treats that case as `TRUNCATED`; it
never claims an exhaustive blast radius from the first window.

Primary references:

- DataHub MCP guide: https://docs.datahub.com/docs/features/feature-guides/mcp
- Official MCP repository: https://github.com/acryldata/mcp-server-datahub
- Pinned MCP release: https://github.com/acryldata/mcp-server-datahub/releases/tag/v0.6.0
- DataHub Core release: https://github.com/datahub-project/datahub/releases/tag/v1.6.0
