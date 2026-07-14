# Submission checklist

## Local evidence

- [x] Start Docker and pass `make datahub-preflight` against the final commit.
- [x] Preserve the existing owner-only token as `REUSED_UNVERIFIABLE` while
      local bearer enforcement is disabled, then prove the Core/MCP flow and
      upsert the eight structured properties without exposing credentials.
- [x] Exercise first-ever PAT creation from no existing token through the hidden
      local credential prompt, then revoke the temporary PAT and delete its
      owner-only token file.
- [x] Run `make test-datahub` against live Core and retain MCP
      mutation/readback evidence.
- [x] Run `make demo` and retain a `VERIFIED` MCP readback.
- [x] Audit the retained live claims against the sealed run.
- [x] Rerun the live evidence from a clean committed source tree.
- [x] Run `make check` and `make test-integration` against the final package
      tree.
- [x] Build the current wheel/sdist and install both in isolated Python 3.12
      and 3.13 environments.
- [x] Verify the README quickstart from a clean checkout.

## Submission package

- [x] Apache 2.0 license present.
- [x] Project creation date and pre-existing-work provenance documented.
- [x] Project provenance and pre-existing-work disclosure present.
- [x] Architecture and security model drafted.
- [x] Judge-oriented demo runbook drafted.
- [x] Timed demonstration script drafted below three minutes.
- [x] Devpost description drafted.
- [x] Add real DataHub and report UI screenshots from the final run.
- [x] Add sanitized verified generated artifacts from the final run.
- [x] Add final third-party license audit.
- [x] Build and security-smoke the read-only review container locally.
- [x] Rebuild the local release archive and checksum from the final package
      commit.
- [x] Freeze exact live metrics from the retained `VERIFIED` artifact.
- [x] Re-check official rules and the 2026-08-10 22:00 BST deadline.
- [x] Make Apache-2.0 visible in the public repository About section.
- [ ] Confirm the public demo video contains no unauthorized trademarks,
      copyrighted music, or other third-party material.
- [ ] Keep the working project available free of charge and without restriction
      through 2026-08-31 17:00 ET.
- [x] Confirm entrant/team wording: Lewis McGuire, sole entrant.
- [x] Confirm the entry is personal and is not being submitted on behalf of a
      company.
- [x] Confirm Lewis has authority to submit all included code, assets, and
      intellectual property.
- [x] Prepare publication history with neutral, non-identifying Git metadata.

## Final publication steps

- [ ] Register for the competition.
- [ ] Accept the competition terms.
- [x] Create or publish the public repository.
- [x] Push the audited `main` branch to the public remote.
- [ ] Deploy the review app publicly.
- [ ] Upload or publish the demonstration video.
- [ ] Spend money on hosting, domains, tools, or services.
- [ ] Contact DataHub, Devpost, judges, sponsors, or other third parties.
- [ ] Submit the final entry.

Update README and deployment status statements after any publication step so
they remain factual.
