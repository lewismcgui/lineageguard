# Lessons

- The official MCP server is part of the product, not an implementation detail: demo evidence must show real MCP reads and mutations against DataHub Core.
- The pinned DataHub quickstart and official MCP flow now pass locally; keep the 13 GB preflight because a healthy existing stack does not prove a clean host can start one.
- Stable MCP 0.6.0 can hide tools by GMS capability; list tools at startup and keep OSS-optional mutations or assertion reads out of silent assumptions.
- A compatibility alias must preserve declared constraints as well as SQL and type, or the residual manifest loses requiredness proof and correctly stays REVIEW.
- An evidence hash is not a cryptographic signature; UI and submission language must call it an evidence seal unless a real signing mechanism is added.
- Keep screenshots and generated examples pending until the UI reads a real MCP-readback-verified run; schema fixtures are visual-test data only.
- Pinned MCP 0.6.0 applies lineage offsets after a fixed GraphQL window; GraphQL `total` is authoritative and totals above 100 must fail traversal closed.
- Never synthesize or silently rebind a DataHub document URN. Lock per run, persist the returned URN with its evidence hash, recover ambiguous commits by exact MCP search/readback, and treat corrupt or ambiguous state as pending.
- FastMCP wraps non-object structured results under `result`, and OSS MCP strips Document fields from `get_entities`; normalize the advertised wrapper and prove documents with dataset `relatedDocuments` plus anchored `grep_documents`.
- MCP 0.6.0 caches a document-free tool list for 60 seconds and the SDK defaults to search-eventual `SYNC_PRIMARY`; after an acknowledged save, allow only hidden `grep_documents`, use `SYNC_WAIT`, and bound read-only projection retries without replaying mutations.
- Counterfactual proof must preserve physical order/quoting, full model config, model constraints, and compiled column plus singular tests; catalog schema fields must read back the exact requested dataset URN and page.
- DataHub Core v1.6.0 does not register `ownership` on Assertion entities even when the SDK validates it; keep assertion seed aspects to the live registry contract.
- MCP 0.6.0 may omit `searchResults` when document search reports `total=0`; accept only that exact empty shape and fail closed on other omissions.
- `RelatedDocumentsResult.count` is the requested page size, not returned length; bound the hydrated list by `min(total, count)` before proving an exact URN/title relation.
