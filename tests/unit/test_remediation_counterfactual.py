from __future__ import annotations

import hashlib
import json

import pytest

from lineageguard.models import SchemaChange, SchemaChangeType
from lineageguard.remediation import (
    CounterfactualCondition,
    CounterfactualError,
    ManifestSnapshot,
    VerificationResult,
    VerificationStatus,
    snapshot_dbt_manifest,
)
from lineageguard.remediation import (
    verify_remediation_counterfactual as _verify_remediation_counterfactual,
)


def _manifest(
    columns: dict[str, str],
    projections: tuple[tuple[str, str], ...],
    *,
    adapter: str = "duckdb",
    query_suffix: str = "from raw.orders",
) -> dict[str, object]:
    compiled = ", ".join(f"{expression} as {name}" for name, expression in projections)
    return {
        "metadata": {"adapter_type": adapter},
        "nodes": {
            "model.demo.orders": {
                "resource_type": "model",
                "relation_name": "analytics.orders",
                "columns": {
                    name: {"name": name, "data_type": data_type}
                    for name, data_type in columns.items()
                },
                "compiled_code": f"select {compiled} {query_suffix}",
            }
        },
    }


def _before_snapshot() -> ManifestSnapshot:
    return snapshot_dbt_manifest(
        _manifest(
            {"order_total": "decimal(12, 2)"},
            (("order_total", "cast(raw_total as decimal(12, 2))"),),
        )
    )


def _patched_snapshot(
    *,
    include_old: bool = True,
    include_new: bool = True,
    old_type: str = "decimal(12, 2)",
    new_type: str = "decimal(12, 2)",
    adapter: str = "duckdb",
) -> ManifestSnapshot:
    columns: dict[str, str] = {}
    projections: list[tuple[str, str]] = []
    expression = "cast(raw_total as decimal(12, 2))"
    if include_old:
        columns["order_total"] = old_type
        projections.append(("order_total", expression))
    if include_new:
        columns["gross_amount"] = new_type
        projections.append(("gross_amount", expression))
    return snapshot_dbt_manifest(_manifest(columns, tuple(projections), adapter=adapter))


def _proposed_snapshot(*, adapter: str = "duckdb") -> ManifestSnapshot:
    return snapshot_dbt_manifest(
        _manifest(
            {"gross_amount": "decimal(12, 2)"},
            (("gross_amount", "cast(raw_total as decimal(12, 2))"),),
            adapter=adapter,
        )
    )


def _rename(*, new_type: str = "DECIMAL(12, 2)", new_nullable: bool | None = None) -> SchemaChange:
    return SchemaChange(
        change_type=SchemaChangeType.RENAME_COLUMN,
        relation="analytics.orders",
        old_column="order_total",
        new_column="gross_amount",
        old_type="DECIMAL(12, 2)",
        new_type=new_type,
        new_nullable=new_nullable,
        source_path="target/proposed-manifest.json",
    )


def _add_column_test(manifest: dict[str, object], column: str, name: str) -> None:
    nodes = manifest["nodes"]  # type: ignore[index]
    nodes[f"test.demo.{name}_{column}"] = {  # type: ignore[index]
        "resource_type": "test",
        "attached_node": "model.demo.orders",
        "column_name": column,
        "name": f"{name}_orders_{column}",
        "test_metadata": {
            "name": name,
            "kwargs": {"model": "{{ get_where_subquery(ref('orders')) }}", "column_name": column},
        },
        "config": {"severity": "ERROR", "where": None},
        "compiled_code": f"select * from analytics.orders where {column} is null",  # noqa: S608 - synthetic static test SQL
    }


def _add_model_test(manifest: dict[str, object], name: str, compiled_code: str) -> None:
    nodes = manifest["nodes"]  # type: ignore[index]
    nodes[f"test.demo.{name}"] = {  # type: ignore[index]
        "resource_type": "test",
        "name": name,
        "depends_on": {"nodes": ["model.demo.orders"]},
        "config": {"severity": "ERROR"},
        "compiled_code": compiled_code,
    }


def _verification(
    snapshot: ManifestSnapshot | None,
    *,
    status: VerificationStatus = VerificationStatus.TESTED,
) -> VerificationResult:
    return VerificationResult(
        status=status,
        commands=(),
        artifact_digests=(),
        evidence_digest="a" * 64,
        patched_manifest=snapshot,
    )


def verify_remediation_counterfactual(
    before_manifest: ManifestSnapshot,
    verification: VerificationResult,
    original_change: SchemaChange,
    *,
    proposed_manifest: ManifestSnapshot | None = None,
    dialect: str | None = None,
):
    adapter = "duckdb"
    try:
        before_payload = json.loads(before_manifest.summary_json)
        adapter_value = before_payload.get("metadata", {}).get("adapter_type")
        if isinstance(adapter_value, str):
            adapter = adapter_value
    except (AttributeError, json.JSONDecodeError):
        pass
    return _verify_remediation_counterfactual(
        before_manifest,
        verification,
        original_change,
        proposed_manifest=proposed_manifest or _proposed_snapshot(adapter=adapter),
        dialect=dialect,
    )


def test_verified_bridge_becomes_an_additive_residual_for_rescoring() -> None:
    before = _before_snapshot()
    verification = _verification(_patched_snapshot())

    first = verify_remediation_counterfactual(before, verification, _rename())
    second = verify_remediation_counterfactual(before, verification, _rename())

    assert first == second
    assert first.original_interface_preserved is True
    assert first.rescore_condition is CounterfactualCondition.RESIDUAL_CHANGES
    assert first.requires_rescore is True
    assert first.before_manifest_sha256 == before.sha256
    assert first.patched_manifest_sha256 == verification.patched_manifest.sha256  # type: ignore[union-attr]
    assert len(first.evidence_digest) == 64
    assert len(first.preserved_query_context_sha256) == 64
    assert len(first.residual_changes) == 1
    residual = first.residual_changes[0]
    assert residual.change_type is SchemaChangeType.ADD_COLUMN
    assert residual.relation == "analytics.orders"
    assert residual.new_column == "gross_amount"
    assert residual.new_type == "DECIMAL(12, 2)"
    assert residual.source_path == "<verified-counterfactual>"
    assert residual.evidence_refs == ("dbt:column-added",)


def test_proposed_manifest_evidence_is_required() -> None:
    with pytest.raises(CounterfactualError, match="proposed manifest evidence is missing"):
        _verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(_patched_snapshot()),
            _rename(),
        )


def test_patched_manifest_must_preserve_proposed_replacement_contract() -> None:
    proposed = _manifest(
        {"gross_amount": "decimal(12, 2)"},
        (("gross_amount", "cast(raw_total as decimal(12, 2))"),),
    )
    proposed_node = proposed["nodes"]["model.demo.orders"]  # type: ignore[index]
    proposed_node["columns"]["gross_amount"]["constraints"] = [  # type: ignore[index]
        {"type": "unique"}
    ]

    with pytest.raises(CounterfactualError, match="proposed column contracts"):
        verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(_patched_snapshot()),
            _rename(),
            proposed_manifest=snapshot_dbt_manifest(proposed),
        )


def test_patched_manifest_must_preserve_proposed_replacement_projection() -> None:
    proposed = snapshot_dbt_manifest(
        _manifest(
            {"gross_amount": "decimal(12, 2)"},
            (("gross_amount", "cast(raw_tax as decimal(12, 2))"),),
        )
    )

    with pytest.raises(CounterfactualError, match="proposed replacement expression"):
        verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(_patched_snapshot()),
            _rename(),
            proposed_manifest=proposed,
        )


def test_patched_manifest_must_preserve_proposed_query_context() -> None:
    proposed = snapshot_dbt_manifest(
        _manifest(
            {"gross_amount": "decimal(12, 2)"},
            (("gross_amount", "cast(raw_total as decimal(12, 2))"),),
            query_suffix="from raw.orders where raw_total > 0",
        )
    )

    with pytest.raises(CounterfactualError, match="proposed query context"):
        verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(_patched_snapshot()),
            _rename(),
            proposed_manifest=proposed,
        )


def test_patched_manifest_must_preserve_proposed_relation_identity() -> None:
    proposed = _manifest(
        {"gross_amount": "decimal(12, 2)"},
        (("gross_amount", "cast(raw_total as decimal(12, 2))"),),
    )
    proposed_node = proposed["nodes"]["model.demo.orders"]  # type: ignore[index]
    proposed_node["relation_name"] = '"analytics"."orders"'  # type: ignore[index]

    with pytest.raises(CounterfactualError, match="proposed manifest changed the physical"):
        verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(_patched_snapshot()),
            _rename(),
            proposed_manifest=snapshot_dbt_manifest(proposed),
        )


def test_patched_manifest_must_preserve_proposed_model_configuration() -> None:
    proposed = _manifest(
        {"gross_amount": "decimal(12, 2)"},
        (("gross_amount", "cast(raw_total as decimal(12, 2))"),),
    )
    proposed_node = proposed["nodes"]["model.demo.orders"]  # type: ignore[index]
    proposed_node["config"] = {"materialized": "view"}  # type: ignore[index]

    with pytest.raises(CounterfactualError, match="proposed model configuration"):
        verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(_patched_snapshot()),
            _rename(),
            proposed_manifest=snapshot_dbt_manifest(proposed),
        )


def test_patched_manifest_must_preserve_proposed_model_constraints() -> None:
    proposed = _manifest(
        {"gross_amount": "decimal(12, 2)"},
        (("gross_amount", "cast(raw_total as decimal(12, 2))"),),
    )
    proposed_node = proposed["nodes"]["model.demo.orders"]  # type: ignore[index]
    proposed_node["constraints"] = [  # type: ignore[index]
        {"type": "unique", "columns": ["gross_amount"]}
    ]

    with pytest.raises(CounterfactualError, match="proposed model-level constraints"):
        verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(_patched_snapshot()),
            _rename(),
            proposed_manifest=snapshot_dbt_manifest(proposed),
        )


def test_patched_manifest_must_preserve_proposed_model_tests() -> None:
    proposed = _manifest(
        {"gross_amount": "decimal(12, 2)"},
        (("gross_amount", "cast(raw_total as decimal(12, 2))"),),
    )
    _add_model_test(
        proposed,
        "positive_gross_amount",
        "select * from analytics.orders where gross_amount <= 0",
    )

    with pytest.raises(CounterfactualError, match="proposed model-level test"):
        verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(_patched_snapshot()),
            _rename(),
            proposed_manifest=snapshot_dbt_manifest(proposed),
        )


def test_patched_manifest_must_preserve_complete_proposed_projection_set() -> None:
    proposed = snapshot_dbt_manifest(
        _manifest(
            {"gross_amount": "decimal(12, 2)"},
            (
                ("gross_amount", "cast(raw_total as decimal(12, 2))"),
                ("uncontracted_output", "raw_tax"),
            ),
        )
    )

    with pytest.raises(CounterfactualError, match=r"proposed.*projection"):
        verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(_patched_snapshot()),
            _rename(),
            proposed_manifest=proposed,
        )


def test_semantically_changed_preserved_expression_fails_closed() -> None:
    changed = snapshot_dbt_manifest(
        _manifest(
            {
                "order_total": "decimal(12, 2)",
                "gross_amount": "decimal(12, 2)",
            },
            (
                ("order_total", "cast(raw_tax as decimal(12, 2))"),
                ("gross_amount", "cast(raw_tax as decimal(12, 2))"),
            ),
        )
    )

    with pytest.raises(CounterfactualError, match="preserved column expression"):
        verify_remediation_counterfactual(_before_snapshot(), _verification(changed), _rename())


def test_replacement_expression_must_equal_the_preserved_bridge() -> None:
    mismatched = snapshot_dbt_manifest(
        _manifest(
            {
                "order_total": "decimal(12, 2)",
                "gross_amount": "decimal(12, 2)",
            },
            (
                ("order_total", "cast(raw_total as decimal(12, 2))"),
                ("gross_amount", "cast(raw_tax as decimal(12, 2))"),
            ),
        )
    )

    with pytest.raises(CounterfactualError, match="replacement expression"):
        verify_remediation_counterfactual(_before_snapshot(), _verification(mismatched), _rename())


def test_changed_row_set_query_context_fails_closed() -> None:
    changed = snapshot_dbt_manifest(
        _manifest(
            {
                "order_total": "decimal(12, 2)",
                "gross_amount": "decimal(12, 2)",
            },
            (
                ("order_total", "cast(raw_total as decimal(12, 2))"),
                ("gross_amount", "cast(raw_total as decimal(12, 2))"),
            ),
            query_suffix="from raw.orders where false",
        )
    )

    with pytest.raises(CounterfactualError, match="preserved query context"):
        verify_remediation_counterfactual(_before_snapshot(), _verification(changed), _rename())


def test_changed_physical_relation_quoting_fails_closed() -> None:
    before_manifest = _manifest(
        {"order_total": "integer"},
        (("order_total", "raw_total"),),
        adapter="snowflake",
    )
    patched_manifest = _manifest(
        {"order_total": "integer", "gross_amount": "integer"},
        (("order_total", "raw_total"), ("gross_amount", "raw_total")),
        adapter="snowflake",
    )
    before_manifest["nodes"]["model.demo.orders"]["relation_name"] = (  # type: ignore[index]
        'ANALYTICS."orders"'
    )
    patched_manifest["nodes"]["model.demo.orders"]["relation_name"] = (  # type: ignore[index]
        "ANALYTICS.orders"
    )
    change = SchemaChange(
        change_type=SchemaChangeType.RENAME_COLUMN,
        relation="ANALYTICS.orders",
        old_column="order_total",
        new_column="gross_amount",
        old_type="INTEGER",
        new_type="INTEGER",
    )

    with pytest.raises(CounterfactualError, match="physical relation identity"):
        verify_remediation_counterfactual(
            snapshot_dbt_manifest(before_manifest),
            _verification(snapshot_dbt_manifest(patched_manifest)),
            change,
        )


def test_changed_output_identifier_quoting_fails_closed() -> None:
    before_manifest = _manifest(
        {"order_total": "integer"},
        (("order_total", "raw_total"),),
        adapter="snowflake",
    )
    patched_manifest = _manifest(
        {"order_total": "integer", "gross_amount": "integer"},
        (("order_total", "raw_total"), ("gross_amount", "raw_total")),
        adapter="snowflake",
    )
    before_node = before_manifest["nodes"]["model.demo.orders"]  # type: ignore[index]
    patched_node = patched_manifest["nodes"]["model.demo.orders"]  # type: ignore[index]
    before_node["compiled_code"] = 'select raw_total as "order_total" from raw.orders'  # type: ignore[index]
    patched_node["compiled_code"] = (  # type: ignore[index]
        "select raw_total as order_total, raw_total as gross_amount from raw.orders"
    )

    with pytest.raises(CounterfactualError, match="projection order or identity"):
        verify_remediation_counterfactual(
            snapshot_dbt_manifest(before_manifest),
            _verification(snapshot_dbt_manifest(patched_manifest)),
            _rename(new_type="INTEGER"),
        )


def test_reordered_physical_projection_contract_fails_closed() -> None:
    before = snapshot_dbt_manifest(
        _manifest(
            {"order_id": "bigint", "order_total": "decimal(12, 2)"},
            (("order_id", "raw_id"), ("order_total", "raw_total")),
        )
    )
    patched = snapshot_dbt_manifest(
        _manifest(
            {
                "order_id": "bigint",
                "order_total": "decimal(12, 2)",
                "gross_amount": "decimal(12, 2)",
            },
            (
                ("gross_amount", "raw_total"),
                ("order_id", "raw_id"),
                ("order_total", "raw_total"),
            ),
        )
    )

    with pytest.raises(CounterfactualError, match="projection order or identity"):
        verify_remediation_counterfactual(before, _verification(patched), _rename())


def test_changed_unrelated_projection_fails_closed() -> None:
    before = snapshot_dbt_manifest(
        _manifest(
            {"order_total": "decimal(12, 2)", "order_id": "bigint"},
            (
                ("order_total", "cast(raw_total as decimal(12, 2))"),
                ("order_id", "raw_id"),
            ),
        )
    )
    patched = snapshot_dbt_manifest(
        _manifest(
            {
                "order_total": "decimal(12, 2)",
                "gross_amount": "decimal(12, 2)",
                "order_id": "bigint",
            },
            (
                ("order_total", "cast(raw_total as decimal(12, 2))"),
                ("gross_amount", "cast(raw_total as decimal(12, 2))"),
                ("order_id", "raw_id + 1"),
            ),
        )
    )

    with pytest.raises(CounterfactualError, match="non-target projection"):
        verify_remediation_counterfactual(before, _verification(patched), _rename())


def test_equivalent_type_whitespace_does_not_invalidate_the_bridge() -> None:
    result = verify_remediation_counterfactual(
        _before_snapshot(),
        _verification(_patched_snapshot()),
        _rename(new_type="decimal(12,2)"),
    )

    assert result.original_interface_preserved is True


@pytest.mark.parametrize(
    "verification,match",
    [
        (_verification(None), "patched manifest evidence is missing"),
        (
            _verification(_patched_snapshot(), status=VerificationStatus.TEST_FAILED),
            "successful remediation verification is required",
        ),
    ],
)
def test_missing_or_untested_patched_evidence_fails_closed(
    verification: VerificationResult, match: str
) -> None:
    with pytest.raises(CounterfactualError, match=match):
        verify_remediation_counterfactual(_before_snapshot(), verification, _rename())


@pytest.mark.parametrize("drift_before", [True, False])
def test_drifted_snapshot_digest_fails_closed(drift_before: bool) -> None:
    before = _before_snapshot()
    patched = _patched_snapshot()
    drifted = ManifestSnapshot(summary_json=before.summary_json, sha256="0" * 64)
    if drift_before:
        supplied_before = drifted
        verification = _verification(patched)
        match = "before manifest evidence drifted"
    else:
        supplied_before = before
        verification = _verification(
            ManifestSnapshot(summary_json=patched.summary_json, sha256="0" * 64)
        )
        match = "patched manifest evidence drifted"

    with pytest.raises(CounterfactualError, match=match):
        verify_remediation_counterfactual(supplied_before, verification, _rename())


def test_noncanonical_snapshot_content_is_treated_as_drift() -> None:
    before = _before_snapshot()
    pretty = json.dumps(json.loads(before.summary_json), indent=2)
    noncanonical = ManifestSnapshot(
        summary_json=pretty,
        sha256=hashlib.sha256(pretty.encode()).hexdigest(),
    )

    with pytest.raises(CounterfactualError, match="before manifest evidence drifted"):
        verify_remediation_counterfactual(
            noncanonical, _verification(_patched_snapshot()), _rename()
        )


def test_legacy_snapshot_summary_version_is_rejected() -> None:
    before = _before_snapshot()
    payload = json.loads(before.summary_json)
    payload["summary_version"] = 2
    legacy_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    legacy = ManifestSnapshot(
        summary_json=legacy_json,
        sha256=hashlib.sha256(legacy_json.encode()).hexdigest(),
    )

    with pytest.raises(CounterfactualError, match="evidence is invalid"):
        verify_remediation_counterfactual(legacy, _verification(_patched_snapshot()), _rename())


@pytest.mark.parametrize(
    "snapshot,match",
    [
        (ManifestSnapshot(summary_json="{", sha256="0" * 64), "evidence is invalid"),
        (
            ManifestSnapshot(
                summary_json='{"nodes":[]}',
                sha256=hashlib.sha256(b'{"nodes":[]}').hexdigest(),
            ),
            "evidence is invalid",
        ),
    ],
)
def test_invalid_snapshot_content_fails_closed(snapshot: ManifestSnapshot, match: str) -> None:
    with pytest.raises(CounterfactualError, match=match):
        verify_remediation_counterfactual(
            snapshot,
            _verification(_patched_snapshot()),
            _rename(),
        )


def test_adapter_mismatch_fails_as_an_untrusted_comparison() -> None:
    with pytest.raises(CounterfactualError, match="adapter types differ"):
        verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(_patched_snapshot(adapter="snowflake")),
            _rename(),
            dialect="duckdb",
        )


def test_missing_preserved_column_contract_metadata_fails_closed() -> None:
    manifest = _manifest(
        {
            "order_total": "decimal(12, 2)",
            "gross_amount": "decimal(12, 2)",
        },
        (
            ("order_total", "cast(raw_total as decimal(12, 2))"),
            ("gross_amount", "cast(raw_total as decimal(12, 2))"),
        ),
    )
    node = manifest["nodes"]["model.demo.orders"]  # type: ignore[index]
    node["columns"]["order_total"].pop("data_type")  # type: ignore[index]

    with pytest.raises(CounterfactualError, match="preserved column contract"):
        verify_remediation_counterfactual(
            _before_snapshot(), _verification(snapshot_dbt_manifest(manifest)), _rename()
        )


def test_disappearing_non_nullability_constraint_fails_closed() -> None:
    before_manifest = _manifest(
        {"order_total": "decimal(12, 2)"},
        (("order_total", "cast(raw_total as decimal(12, 2))"),),
    )
    before_node = before_manifest["nodes"]["model.demo.orders"]  # type: ignore[index]
    before_node["columns"]["order_total"]["constraints"] = [{"type": "unique"}]  # type: ignore[index]

    with pytest.raises(CounterfactualError, match="preserved column contract"):
        verify_remediation_counterfactual(
            snapshot_dbt_manifest(before_manifest),
            _verification(_patched_snapshot()),
            _rename(),
        )


def test_disappearing_column_data_test_fails_closed() -> None:
    before_manifest = _manifest(
        {"order_total": "decimal(12, 2)"},
        (("order_total", "cast(raw_total as decimal(12, 2))"),),
    )
    _add_column_test(before_manifest, "order_total", "unique")

    with pytest.raises(CounterfactualError, match="preserved column contract"):
        verify_remediation_counterfactual(
            snapshot_dbt_manifest(before_manifest),
            _verification(_patched_snapshot()),
            _rename(),
        )


def test_changed_model_contract_enforcement_fails_closed() -> None:
    before_manifest = _manifest(
        {"order_total": "decimal(12, 2)"},
        (("order_total", "cast(raw_total as decimal(12, 2))"),),
    )
    patched_manifest = _manifest(
        {
            "order_total": "decimal(12, 2)",
            "gross_amount": "decimal(12, 2)",
        },
        (
            ("order_total", "cast(raw_total as decimal(12, 2))"),
            ("gross_amount", "cast(raw_total as decimal(12, 2))"),
        ),
    )
    before_node = before_manifest["nodes"]["model.demo.orders"]  # type: ignore[index]
    patched_node = patched_manifest["nodes"]["model.demo.orders"]  # type: ignore[index]
    before_node["config"] = {"contract": {"enforced": True}}  # type: ignore[index]
    patched_node["config"] = {"contract": {"enforced": False}}  # type: ignore[index]

    with pytest.raises(CounterfactualError, match="model configuration"):
        verify_remediation_counterfactual(
            snapshot_dbt_manifest(before_manifest),
            _verification(snapshot_dbt_manifest(patched_manifest)),
            _rename(),
        )


def test_changed_materialization_configuration_fails_closed() -> None:
    before_manifest = _manifest(
        {"order_total": "decimal(12, 2)"},
        (("order_total", "cast(raw_total as decimal(12, 2))"),),
    )
    patched_manifest = _manifest(
        {
            "order_total": "decimal(12, 2)",
            "gross_amount": "decimal(12, 2)",
        },
        (
            ("order_total", "cast(raw_total as decimal(12, 2))"),
            ("gross_amount", "cast(raw_total as decimal(12, 2))"),
        ),
    )
    before_node = before_manifest["nodes"]["model.demo.orders"]  # type: ignore[index]
    patched_node = patched_manifest["nodes"]["model.demo.orders"]  # type: ignore[index]
    before_node["config"] = {  # type: ignore[index]
        "contract": {"enforced": True},
        "materialized": "table",
    }
    patched_node["config"] = {  # type: ignore[index]
        "contract": {"enforced": True},
        "materialized": "view",
    }

    with pytest.raises(CounterfactualError, match="model configuration"):
        verify_remediation_counterfactual(
            snapshot_dbt_manifest(before_manifest),
            _verification(snapshot_dbt_manifest(patched_manifest)),
            _rename(),
        )


def test_removed_model_level_primary_key_constraint_fails_closed() -> None:
    before_manifest = _manifest(
        {"order_total": "decimal(12, 2)"},
        (("order_total", "raw_total"),),
    )
    patched_manifest = _manifest(
        {
            "order_total": "decimal(12, 2)",
            "gross_amount": "decimal(12, 2)",
        },
        (
            ("order_total", "cast(raw_total as decimal(12, 2))"),
            ("gross_amount", "cast(raw_total as decimal(12, 2))"),
        ),
    )
    before_node = before_manifest["nodes"]["model.demo.orders"]  # type: ignore[index]
    before_node["constraints"] = [  # type: ignore[index]
        {"type": "primary_key", "columns": ["order_total"]}
    ]
    before_node["primary_key"] = ["order_total"]  # type: ignore[index]

    with pytest.raises(CounterfactualError, match="model-level constraints"):
        verify_remediation_counterfactual(
            snapshot_dbt_manifest(before_manifest),
            _verification(snapshot_dbt_manifest(patched_manifest)),
            _rename(),
        )


def test_removed_singular_model_test_fails_closed() -> None:
    before_manifest = _manifest(
        {"order_total": "decimal(12, 2)"},
        (("order_total", "raw_total"),),
    )
    patched_manifest = _manifest(
        {
            "order_total": "decimal(12, 2)",
            "gross_amount": "decimal(12, 2)",
        },
        (("order_total", "raw_total"), ("gross_amount", "raw_total")),
    )
    _add_model_test(
        before_manifest,
        "positive_order_total",
        "select * from analytics.orders where order_total <= 0",
    )

    with pytest.raises(CounterfactualError, match="model-level test"):
        verify_remediation_counterfactual(
            snapshot_dbt_manifest(before_manifest),
            _verification(snapshot_dbt_manifest(patched_manifest)),
            _rename(),
        )


def test_additional_verified_model_test_is_allowed() -> None:
    patched_manifest = _manifest(
        {
            "order_total": "decimal(12, 2)",
            "gross_amount": "decimal(12, 2)",
        },
        (
            ("order_total", "cast(raw_total as decimal(12, 2))"),
            ("gross_amount", "cast(raw_total as decimal(12, 2))"),
        ),
    )
    _add_model_test(
        patched_manifest,
        "compatibility_equality",
        "select * from analytics.orders where order_total != gross_amount",
    )

    result = verify_remediation_counterfactual(
        _before_snapshot(),
        _verification(snapshot_dbt_manifest(patched_manifest)),
        _rename(),
    )

    assert result.original_interface_preserved is True


def test_changed_compiled_column_test_semantics_fail_closed() -> None:
    before_manifest = _manifest(
        {"order_total": "decimal(12, 2)"},
        (("order_total", "cast(raw_total as decimal(12, 2))"),),
    )
    patched_manifest = _manifest(
        {
            "order_total": "decimal(12, 2)",
            "gross_amount": "decimal(12, 2)",
        },
        (
            ("order_total", "cast(raw_total as decimal(12, 2))"),
            ("gross_amount", "cast(raw_total as decimal(12, 2))"),
        ),
    )
    _add_column_test(before_manifest, "order_total", "positive")
    _add_column_test(patched_manifest, "order_total", "positive")
    patched_test = patched_manifest["nodes"]["test.demo.positive_order_total"]  # type: ignore[index]
    patched_test["compiled_code"] = "select 1 where false"  # type: ignore[index]

    with pytest.raises(CounterfactualError, match="preserved column contract"):
        verify_remediation_counterfactual(
            snapshot_dbt_manifest(before_manifest),
            _verification(snapshot_dbt_manifest(patched_manifest)),
            _rename(),
        )


def test_attached_column_test_without_compiled_sql_fails_counterfactual_closed() -> None:
    before_manifest = _manifest(
        {"order_total": "decimal(12, 2)"},
        (("order_total", "cast(raw_total as decimal(12, 2))"),),
    )
    patched_manifest = _manifest(
        {
            "order_total": "decimal(12, 2)",
            "gross_amount": "decimal(12, 2)",
        },
        (
            ("order_total", "cast(raw_total as decimal(12, 2))"),
            ("gross_amount", "cast(raw_total as decimal(12, 2))"),
        ),
    )
    _add_column_test(before_manifest, "order_total", "positive")
    _add_column_test(patched_manifest, "order_total", "positive")
    test_node = before_manifest["nodes"]["test.demo.positive_order_total"]  # type: ignore[index]
    test_node.pop("compiled_code")  # type: ignore[union-attr]

    with pytest.raises(CounterfactualError, match="compiled column test evidence"):
        verify_remediation_counterfactual(
            snapshot_dbt_manifest(before_manifest),
            _verification(snapshot_dbt_manifest(patched_manifest)),
            _rename(),
        )


def test_star_projection_has_no_safe_counterfactual_proof() -> None:
    before_manifest = _manifest(
        {"order_total": "decimal(12, 2)"},
        (("order_total", "cast(raw_total as decimal(12, 2))"),),
    )
    patched_manifest = _manifest(
        {
            "order_total": "decimal(12, 2)",
            "gross_amount": "decimal(12, 2)",
        },
        (
            ("order_total", "cast(raw_total as decimal(12, 2))"),
            ("gross_amount", "cast(raw_total as decimal(12, 2))"),
        ),
    )
    before_node = before_manifest["nodes"]["model.demo.orders"]  # type: ignore[index]
    patched_node = patched_manifest["nodes"]["model.demo.orders"]  # type: ignore[index]
    before_node["compiled_code"] = "select raw.*, raw_total as order_total from raw.orders"  # type: ignore[index]
    patched_node["compiled_code"] = (  # type: ignore[index]
        "select other.*, raw_total as order_total, raw_total as gross_amount from raw.orders"
    )

    with pytest.raises(CounterfactualError, match="projection evidence"):
        verify_remediation_counterfactual(
            snapshot_dbt_manifest(before_manifest),
            _verification(snapshot_dbt_manifest(patched_manifest)),
            _rename(),
        )


def test_missing_replacement_nullability_fails_closed_when_original_was_known() -> None:
    with pytest.raises(CounterfactualError, match="replacement nullability"):
        verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(_patched_snapshot()),
            _rename(new_nullable=False),
        )


@pytest.mark.parametrize(
    "patched,match",
    [
        (
            _patched_snapshot(include_old=False),
            "contract evidence",
        ),
        (
            _patched_snapshot(include_new=False),
            "replacement contract",
        ),
        (
            _patched_snapshot(old_type="bigint"),
            "preserved column contract",
        ),
        (
            _patched_snapshot(new_type="bigint"),
            "changed the intended replacement type",
        ),
    ],
)
def test_incomplete_or_changed_bridge_fails_closed(patched: ManifestSnapshot, match: str) -> None:
    with pytest.raises(CounterfactualError, match=match):
        verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(patched),
            _rename(),
        )


def test_non_rename_remediation_is_rejected() -> None:
    dropped = SchemaChange(
        change_type=SchemaChangeType.DROP_COLUMN,
        relation="analytics.orders",
        old_column="order_total",
    )

    with pytest.raises(CounterfactualError, match="supports rename remediation only"):
        verify_remediation_counterfactual(
            _before_snapshot(),
            _verification(_patched_snapshot()),
            dropped,
        )
