# Third-party components

This is the direct runtime and demo dependency inventory from the locked local
environment, re-audited on 2026-07-14 after the lock changed. The installed
transitive distribution metadata and bundled license files were also reviewed:
no AGPL, proprietary, or other incompatible dependency was found.
`text-unidecode` is offered under either GPL/GPLv2+ or the Artistic License;
LineageGuard uses the unmodified distribution under the Artistic License.
`caio` omits license metadata but its installed `COPYING` is Apache-2.0. Repeat
this audit if `uv.lock` changes again.

| Component | Locked version | License |
| --- | ---: | --- |
| DataHub CLI and SDK (`acryl-datahub`) | 1.6.0.10 | Apache-2.0 |
| Official DataHub MCP server (`mcp-server-datahub`) | 0.6.0 | Apache-2.0 |
| MCP Python SDK | 1.28.1 | MIT |
| AnyIO | 4.14.1 | MIT |
| FastAPI | 0.139.0 | MIT |
| HTTPX | 0.28.1 | BSD-3-Clause |
| Jinja2 | 3.1.6 | BSD-3-Clause |
| Pydantic | 2.13.4 | MIT |
| Pydantic Settings | 2.14.2 | MIT |
| PyYAML | 6.0.3 | MIT |
| Rich | 14.3.4 | MIT |
| SQLGlot | 30.8.0 | MIT |
| Typer | 0.26.8 | MIT |
| Uvicorn | 0.51.0 | BSD-3-Clause |
| dbt Core | 1.11.12 | Apache-2.0 |
| dbt DuckDB | 1.10.1 | Apache-2.0 |
| Hatchling (build backend) | 1.31.0 | MIT |
| uv (prepared container build tool) | 0.11.26 | Apache-2.0 OR MIT |

LineageGuard does not copy source code from these projects. They are installed
as normal package dependencies. Their license texts and notices remain
authoritative in their distributions and upstream repositories.
