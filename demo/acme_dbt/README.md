# Acme Commerce dbt demo

This self-contained dbt/DuckDB project models a small fictional commerce
dataset. All rows and identifiers were created for LineageGuard and are safe to
publish with the repository under Apache-2.0. No customer or company data is
included.

The baseline contract exposes `stg_orders.order_total`. The downstream
`fct_daily_revenue` model and two singular assertions depend on that contract.
Generic and singular dbt tests plus enforced contracts establish the local
failure and repair evidence. A separate deterministic official-SDK seed creates
the synthetic DataHub graph, owners, dashboard, and native Assertion definition.

## Run the green baseline offline

After the repository's Python/demo dependencies are installed, neither command
downloads packages or calls a service:

```bash
cd demo/acme_dbt
DBT_LOG_PATH=target/logs ../../.venv/bin/dbt seed --profiles-dir .
DBT_LOG_PATH=target/logs ../../.venv/bin/dbt build --profiles-dir .
```

The profile uses one DuckDB thread and disables telemetry, version checks, and
partial parsing. The DuckDB file, logs, compiled SQL, manifest, and run results
are all written below the ignored `target/` directory.

## Proposed breaking PR

`scenario/proposed/models/staging/stg_orders.sql` represents a proposed PR
version of the staging model, with its matching proposed contract in the same
scenario tree. The PR renames `order_total` to `gross_amount` but deliberately
leaves the downstream model and singular assertion unchanged. The proposed
manifest therefore contains the real column rename, while its build fails in
the first unchanged assertion with a binder error naming the removed column
and its replacement. dbt then skips `fct_daily_revenue`, proving that the
breaking assertion gates its downstream consumer.

The integration test copies the entire project to fresh temporary baseline and
proposed workspaces, applies the proposed source only in the latter, and checks
both outcomes with subprocess timeouts:

```bash
uv run pytest tests/integration/test_demo_dbt.py -m integration
```

The scenario contains no nested Git repository and never changes the green
baseline in place.
