# Verified example output

These files were retained from the synthetic Acme demonstration on 2026-07-14.
The run was executed from a clean source commit before these example files were
added in the later package commit. The recorded source identifier belongs to
the retained pre-publication history; this repository begins with the audited
publication snapshot.

- Run ID: `lg-3d10638807e88502`
- Source identifier: `746cab4f54a505130cf63ce42df144e18a1bdab0`
- Analyzed inputs: `GENERATED_IN_PROCESS`, with both manifest bytes bound by
  SHA-256
- Evidence hash: `3d10638807e88502181f687002ffbc79c3014a1b262a1e9bf716ad6229870e5f`
- Artifact hash: `6dabb578cd762433645d58ebf904c66f81a9625f246ddfe044783bed0ebb203b`
- Outcome: `COMPLETE`, `PASS_WITH_REMEDIATION`, remediation `TESTED`,
  DataHub writeback `VERIFIED`
- Risk: `88 BLOCK` before remediation, projected `12 PASS` after the tested
  compatibility patch

The dashboard's plain-English `PASS WITH PATCH` label presents the canonical
`PASS_WITH_REMEDIATION` decision recorded in the machine-readable report.

`demo-preflight.json` contains the baseline and expected failing proposal
checks. `report.json` is the authoritative machine-readable run;
`report.md` and `report.html` are equivalent portable summaries. The four
screenshots show the matching report, DataHub decision fields, verified
writeback state, and column lineage. `SHA256SUMS` seals all eight copied
evidence files.
Verify it from this directory with
`shasum -a 256 -c SHA256SUMS`.

![LineageGuard decision fork](screenshots/report-overview.png)

![DataHub decision properties](screenshots/datahub-decision-state.png)

![DataHub verified writeback](screenshots/datahub-writeback-verified.png)

![DataHub column lineage](screenshots/datahub-lineage.png)

The example is synthetic. It contains no DataHub token, login password,
personal identity, or local filesystem path. The generated patch was verified
in a temporary project copy; these files do not claim that it was applied to a
production project.

Follow the [demo runbook](../../docs/demo-runbook.md) to reproduce the run
locally.
