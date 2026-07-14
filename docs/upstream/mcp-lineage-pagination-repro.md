# Upstream-ready note: MCP lineage offset is applied after a fixed window

Local analysis only. Nothing has been published or sent upstream.

Pinned component: `mcp-server-datahub==0.6.0`.

## Minimal reproduction

1. Use a dataset whose downstream `searchAcrossLineage.total` is greater than
   100.
2. Call `get_lineage(..., max_results=100, offset=0)`.
3. Observe `total > 100`, 100 results, but `hasMore=false`.
4. Call again with `offset=100`.
5. Observe zero results because the GraphQL request again used `start=0,
   count=100` and the tool sliced offset 100 from that prefix.

## Root cause and proposed upstream fix

`AssetLineageAPI.get_lineage` hardcodes GraphQL `start: 0`; the public tool then
applies `offset` locally. Pass the requested offset into GraphQL `start`, retain
the authoritative response `total`, and compute `hasMore` from
`start + returned < total`. Token-budget truncation should remain explicit and
pagination tests should cover totals above 100.

## Local mitigation

LineageGuard validates the preserved GraphQL total and fails traversal closed
when complete coverage exceeds the pinned window. This note is ready to turn
into an upstream issue or patch after separate maintainer review.
