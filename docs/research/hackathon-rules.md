# DataHub Agent Hackathon rules snapshot

Retrieved on 2026-07-13 from official DataHub and Devpost sources. Re-check
before final submission because the official rules state that terms may change.

## Build and submission window

- Registration and submission period: 2026-07-06 09:00 ET through
  2026-08-10 17:00 ET.
- This repository was created locally on 2026-07-12, inside that period.
- Only projects newly created during the submission period qualify. Standard
  frameworks, libraries, and templates are permitted; other pre-existing code
  or work must be disclosed.

## Required product shape

- A working software application must use the DataHub open-source platform
  together with at least one of the MCP Server, Agent Context Kit, DataHub
  Skills, or Analytics Agent.
- The planned combined categories are **Agents That Do Real Work** and
  **Metadata-Aware Code Generation & Development**.
- The final submission requires an accessible project, public Apache-2.0 code
  repository, English text description, and a public demonstration video under
  three minutes. The Project URL may be a live demo, hosted app, or the public
  repository with clear setup instructions. Generated sample artifacts are
  recommended.
- The working project must remain available free of charge and without
  restriction through the end of judging on 2026-08-31 at 17:00 ET.

## Judging priorities

The five primary criteria are meaningful DataHub use, technical execution,
originality, real-world usefulness, and submission quality. DataHub use is the
first tie-break criterion. Meaningful open-source contributions to DataHub are
an additional bonus criterion.

LineageGuard therefore treats DataHub as durable operational state: it reads
schemas, lineage, ownership, and governance through the official MCP server,
uses a narrow GraphQL gap adapter for Assertion definitions, then writes the
decision and remediation state back through MCP for the next person or agent.

## Sources

- Official rules: https://datahub.devpost.com/rules
- Official overview: https://datahub.devpost.com/
- Official resources: https://datahub.devpost.com/resources
- DataHub announcement: https://datahub.com/blog/build-with-datahub-agent-hackathon/
- DataHub MCP documentation: https://docs.datahub.com/docs/features/feature-guides/mcp
- Official MCP server: https://github.com/acryldata/mcp-server-datahub

## Researched implementation baseline

- DataHub Core server: `v1.6.0`.
- DataHub CLI: `acryl-datahub==1.6.0.10`.
- Official self-hosted MCP server: `mcp-server-datahub==0.6.0`.
- The official quickstart documents 2 CPUs, 8 GB RAM, 2 GB swap, and
  approximately 13 GB disk as a tested allocation.
- Stable OSS MCP write-back uses structured properties, tags, and documents.
  Capability discovery is still mandatory because tools may be hidden when the
  connected GMS version does not support them.
- DataHub Core can represent dbt tests and externally evaluated run results as
  Assertions. The version 0.1 demo seeds one Assertion definition and does not
  seed or score Assertion run events; it must not claim Core ran dbt checks.
