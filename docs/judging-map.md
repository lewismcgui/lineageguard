# Judging map

The official five criteria are equally weighted. DataHub usage is the first
tie-break criterion, so each claim below should be visible in the final video
and backed by a retained artifact.

| Criterion | LineageGuard evidence | Demo moment |
| --- | --- | --- |
| Meaningful DataHub use | Official MCP schema search, column lineage, entity enrichment, two-phase structured-property/tag/document mutations, and entity-bound MCP readback; DataHub Assertion gap adapter | Show the heterogeneous graph, then the verified machine fields in DataHub and the local report |
| Technical execution | Deterministic policy, capability handshake, pagination, fail-closed evidence states, AST-bounded patching, isolated dbt build, sanitized manifest proof, 85%+ coverage | Show initial score contributions, three green verifier commands, and the residual manifest delta |
| Originality | Counterfactual remediation loop rather than impact reporting alone | Move from a high-risk BLOCK to a tested 12 PASS while preserving the old interface |
| Real-world usefulness | Stops a common contracted-column break and returns executable migration work with owners and affected assets | Open the generated SQL/YAML/test diff and owner-aware impact ledger |
| Submission quality | One-command synthetic demo, polished flight-recorder UI, architecture, runbook, timed script, Apache 2.0, project provenance | Keep the walkthrough below three minutes and end on readback-verified passport |

## Claims anchored to live proof

The retained local run establishes `COMPLETE`, initial risk `88` (`BLOCK`),
residual risk `12` (`PASS`), remediation `TESTED`, final
`PASS_WITH_REMEDIATION`, and DataHub writeback/readback `VERIFIED`. Use these
claims only with the matching sealed sample artifact and screenshots from the
clean source run. The report must show a source commit rather than `WORKTREE`,
`GENERATED_IN_PROCESS` for the demo manifests, and the matching manifest hashes.
Never relabel a pending, dirty-source, or mismatched run as final evidence.

## Differentiation from existing impact actions

Existing DataHub/dbt impact tooling can report downstream effects. LineageGuard
extends that pattern with a closed work loop:

```text
future schema -> context graph -> risk -> executable bridge -> real build
-> compiled future proof -> residual score -> durable passport
```

The final presentation should lead with this loop, not with generic automation
language.
