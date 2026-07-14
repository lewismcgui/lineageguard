# LineageGuard delivery plan

## Milestone 1: working local prototype by 2026-07-20

- [x] Create the project during the official submission period.
- [x] Freeze the architecture and demo scenario against current official docs.
- [x] Bootstrap the Python package, CLI, report UI, and test harness.
- [x] Parse SQL/dbt schema changes into a normalized change set.
- [x] Traverse a seeded catalog through the official DataHub MCP server.
- [x] Produce a deterministic, evidence-linked risk decision.
- [x] Generate a remediation patch and test it in an isolated demo workspace.
- [x] Write the decision and remediation status back through MCP mutations.
- [x] Read back the mutation from DataHub and save end-to-end evidence.

## Milestone 2: complete end-to-end version by 2026-07-27

- [x] Keep the provider boundary explicit: v0.1 accepts compiled before/after dbt
      manifests through a CI-friendly CLI; provider-specific webhook adapters
      are outside the frozen scope.
- [x] Implement owners, pipelines, dashboards, Assertion definitions, and column lineage.
- [x] Add retry, timeout, partial-evidence, and safe-failure behavior.
- [x] Keep deterministic evidence, generation, scoring, and writeback
      authoritative and cost-free.
- [x] Add a polished interactive report and downloadable artifacts.
- [x] Add CI configuration without publishing or enabling external services.

## Milestone 3: feature freeze and verification by 2026-08-03

- [x] Run live Core/MCP mutation read-back and retain the local evidence.
- [x] Re-run Ruff, formatting, strict mypy, offline unit, integration, and live
      DataHub gates against the current working tree.
- [x] Verify the documented quickstart from a clean local environment.
- [x] Audit verification claims against implementation and saved test evidence;
      record live outcomes only after independent MCP readback.
- [x] Confirm the compliant end-to-end demo is feasible on the local stack.

## Milestone 4: submission package ready by 2026-08-07

- [x] Finalize README, architecture diagram, screenshots, and verified sample outputs.
- [x] Draft Devpost copy and a timed demonstration script under 3 minutes.
- [x] Complete Apache-2.0, project-provenance, direct-dependency, and
      pre-existing-code audit.
- [x] Rebuild and checksum the audited local release archive from the final
      submission-package commit; the judge testing guide is ready.
- [x] List the remaining final publication and submission steps.

## Remaining verification work

The live evidence was rerun from a clean commit, sanitized sample artifacts and
screenshots are sealed, and both the existing-token quickstart and first-ever PAT
creation passed against live local DataHub. Token reuse was reported as
`REUSED_UNVERIFIABLE` because the official local Core disables bearer
enforcement. The first-run credential was entered
through a hidden local prompt, the owner-only token passed the live DataHub test,
and the temporary PAT and token file were then removed. The release was rebuilt
and checksummed from committed source. The audited public repository is
published at `https://github.com/lewismcgui/lineageguard`; remaining publication
and submission actions are tracked in `docs/submission-checklist.md`.

## Current submission-package pass

- [x] Record portable dbt command names without weakening resolved-binary execution.
- [x] Correct stale or overstated judge-facing claims.
- [x] Replace the technical-first dashboard with a plain-English decision summary
      and an expandable audit trail.
- [x] Replace showcase-style cards and invented control-room language with a
      compact operational change-review layout.
- [x] Replace the static workbench with a selectable decision fork contrasting
      the unpatched block path with the tested-patch projection and proof.
- [x] Commit and verify the dashboard implementation before generating public evidence.
- [x] Rerun the live demo from the clean code commit.
- [x] Add sealed sample artifacts from the verified clean run.
- [x] Add matching LineageGuard and DataHub screenshots.
- [x] Rebuild and verify the final release from a clean local clone.

## Adversarial hardening pass

- [x] Close parser, counterfactual-binding, context-merge, and writeback edge cases.
- [x] Bind every DataHub quickstart port to loopback and verify the live bindings.
- [x] Harden PAT lifecycle, private temporary files, Host validation, and release scanning.
- [x] Make the checked-in evidence preview and quickstart requirements obvious to judges.
- [x] Re-run every offline, package, container, dependency, and live DataHub gate.
- [x] Commit and rebuild the final local submission package without publishing it.
