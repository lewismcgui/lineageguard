"""Tests for normalized, fail-closed change extraction."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lineageguard.changes import (
    ChangeParseError,
    ChangeParser,
    UnsupportedChangeError,
    compare_dbt_manifests,
    parse_alter_table,
)
from lineageguard.models import ChangeType, ConfidenceLevel

FIXTURES = Path(__file__).parents[1] / "fixtures" / "change_detection"


def test_manifest_comparison_extracts_normalized_demo_changes() -> None:
    changes = compare_dbt_manifests(
        FIXTURES / "manifest_before.json",
        FIXTURES / "manifest_after.json",
    )

    assert [change.change_type for change in changes] == [
        ChangeType.RENAME_COLUMN,
        ChangeType.DROP_COLUMN,
        ChangeType.ADD_COLUMN,
        ChangeType.TYPE_CHANGE,
        ChangeType.TYPE_CHANGE,
        ChangeType.NULLABILITY_CHANGE,
        ChangeType.NULLABILITY_CHANGE,
    ]
    assert all(change.relation == '"analytics"."orders"' for change in changes)
    assert all(change.confidence is ConfidenceLevel.HIGH for change in changes)

    rename = changes[0]
    assert (rename.old_column, rename.new_column) == ("order_total", "gross_amount")
    assert (rename.old_type, rename.new_type) == ("DECIMAL(12, 2)", "DECIMAL(18, 2)")
    assert (rename.old_nullable, rename.new_nullable) == (True, False)
    assert any(
        reference.startswith("dbt:compiled-expression:") for reference in rename.evidence_refs
    )

    assert (changes[1].old_column, changes[2].new_column) == ("legacy_code", "currency")
    assert (changes[2].new_type, changes[2].new_nullable) == ("TEXT", False)
    assert [
        (change.old_column, change.new_column, change.old_type, change.new_type)
        for change in changes[3:5]
    ] == [
        ("customer_note", "customer_note", "TEXT", "BIGINT"),
        ("order_total", "gross_amount", "DECIMAL(12, 2)", "DECIMAL(18, 2)"),
    ]
    assert [
        (change.old_column, change.new_column, change.old_nullable, change.new_nullable)
        for change in changes[5:]
    ] == [
        ("order_total", "gross_amount", True, False),
        ("status", "status", True, False),
    ]


def test_manifest_results_and_ids_are_deterministic() -> None:
    first = compare_dbt_manifests(
        FIXTURES / "manifest_before.json", FIXTURES / "manifest_after.json"
    )
    second = compare_dbt_manifests(
        FIXTURES / "manifest_before.json", FIXTURES / "manifest_after.json"
    )

    assert first == second
    assert [change.id for change in first] == [change.id for change in second]
    assert len({change.id for change in first}) == len(first)


def test_manifest_rename_inference_refuses_ambiguous_expression_matches() -> None:
    changes = compare_dbt_manifests(
        FIXTURES / "manifest_ambiguous_before.json",
        FIXTURES / "manifest_ambiguous_after.json",
    )

    assert [change.change_type for change in changes] == [
        ChangeType.DROP_COLUMN,
        ChangeType.DROP_COLUMN,
        ChangeType.ADD_COLUMN,
        ChangeType.ADD_COLUMN,
    ]
    assert not any(change.change_type is ChangeType.RENAME_COLUMN for change in changes)


def test_manifest_does_not_guess_rename_without_parseable_compiled_sql() -> None:
    before = _manifest(
        columns={"order_total": {"name": "order_total", "data_type": "decimal(12,2)"}},
        compiled="select from definitely invalid",
    )
    after = _manifest(
        columns={"gross_amount": {"name": "gross_amount", "data_type": "decimal(12,2)"}},
        compiled="select from definitely invalid",
    )

    changes = compare_dbt_manifests(before, after)

    assert [change.change_type for change in changes] == [
        ChangeType.DROP_COLUMN,
        ChangeType.ADD_COLUMN,
    ]


def test_manifest_ignores_a_new_relation_but_rejects_a_removed_relation() -> None:
    empty = {"metadata": {"adapter_type": "duckdb"}, "nodes": {}}
    populated = _manifest(
        columns={"id": {"name": "id", "data_type": "bigint"}},
        compiled="select id from raw.orders",
    )

    assert compare_dbt_manifests(empty, populated) == ()
    with pytest.raises(UnsupportedChangeError, match="Relation removal or rename"):
        compare_dbt_manifests(populated, empty)


def test_manifest_relation_quoting_is_part_of_physical_identity() -> None:
    before = _manifest(
        columns={"id": {"name": "id", "data_type": "bigint"}},
        compiled="select id from raw.orders",
    )
    after = _manifest(
        columns={"id": {"name": "id", "data_type": "bigint"}},
        compiled="select id from raw.orders",
    )
    before["metadata"] = {"adapter_type": "snowflake"}
    after["metadata"] = {"adapter_type": "snowflake"}
    before["nodes"]["model.lineageguard.orders"]["relation_name"] = (  # type: ignore[index]
        'ANALYTICS."orders"'
    )
    after["nodes"]["model.lineageguard.orders"]["relation_name"] = (  # type: ignore[index]
        "ANALYTICS.orders"
    )

    with pytest.raises(UnsupportedChangeError, match="Relation removal or rename"):
        compare_dbt_manifests(before, after)


def test_manifest_column_quoting_change_is_not_erased() -> None:
    before = _manifest(
        columns={
            "order_total": {
                "name": "order_total",
                "data_type": "integer",
                "quote": True,
            }
        },
        compiled='select raw_total as "order_total" from raw.orders',
    )
    after = _manifest(
        columns={"order_total": {"name": "order_total", "data_type": "integer"}},
        compiled="select raw_total as order_total from raw.orders",
    )

    changes = compare_dbt_manifests(before, after)

    assert len(changes) == 1
    assert changes[0].change_type is ChangeType.RENAME_COLUMN
    assert changes[0].old_column == '"order_total"'
    assert changes[0].new_column == "order_total"


def test_manifest_requires_json_object_nodes_and_unique_relations(tmp_path: Path) -> None:
    malformed = tmp_path / "manifest.json"
    malformed.write_text("not-json", encoding="utf-8")
    with pytest.raises(ChangeParseError, match="Invalid JSON"):
        compare_dbt_manifests(malformed, _manifest(columns={}, compiled="select 1 as id"))

    duplicate = _manifest(columns={}, compiled="select 1 as id")
    first_node = next(iter(duplicate["nodes"].values()))
    duplicate["nodes"]["model.lineageguard.second"] = dict(first_node)
    with pytest.raises(ChangeParseError, match="Duplicate dbt relation"):
        compare_dbt_manifests(duplicate, duplicate)

    missing = tmp_path / "missing.json"
    with pytest.raises(ChangeParseError, match="Cannot read"):
        compare_dbt_manifests(missing, duplicate)

    non_object = tmp_path / "list.json"
    non_object.write_text("[]", encoding="utf-8")
    with pytest.raises(ChangeParseError, match="must be a JSON object"):
        compare_dbt_manifests(non_object, duplicate)

    with pytest.raises(ChangeParseError, match="nodes object"):
        compare_dbt_manifests({"nodes": []}, duplicate)


def test_manifest_adapter_mismatch_fails_closed() -> None:
    before = _manifest(columns={}, compiled="select 1 as id")
    after = json.loads(json.dumps(before))
    after["metadata"]["adapter_type"] = "snowflake"

    with pytest.raises(ChangeParseError, match="adapter types differ"):
        compare_dbt_manifests(before, after)

    with pytest.raises(ChangeParseError, match="adapter types differ"):
        compare_dbt_manifests(before, after, dialect="duckdb")

    with pytest.raises(ChangeParseError, match="does not match"):
        compare_dbt_manifests(before, before, dialect="snowflake")


def test_manifest_relation_fallback_and_compiled_only_columns_are_supported() -> None:
    before = _manifest(columns={}, compiled="select raw_total from raw.orders")
    after = _manifest(columns={}, compiled="select raw_total as net_total from raw.orders")
    for manifest in (before, after):
        node = next(iter(manifest["nodes"].values()))
        assert isinstance(node, dict)
        node["relation_name"] = None
        node["database"] = "warehouse"
        node["schema"] = "analytics"
        node["alias"] = "orders"
    changes = compare_dbt_manifests(before, after, dialect="duckdb")

    assert len(changes) == 1
    assert changes[0].change_type is ChangeType.RENAME_COLUMN
    assert changes[0].relation == "warehouse.analytics.orders"
    assert (changes[0].old_column, changes[0].new_column) == ("raw_total", "net_total")


def test_manifest_infers_retained_type_change_only_from_direct_casts() -> None:
    before = _manifest(
        columns={"amount": {"name": "amount"}},
        compiled="select cast(raw_amount as integer) as amount from raw.orders",
    )
    after = _manifest(
        columns={"amount": {"name": "amount"}},
        compiled="select cast(raw_amount as varchar) as amount from raw.orders",
    )

    changes = compare_dbt_manifests(before, after)

    assert len(changes) == 1
    assert changes[0].change_type is ChangeType.TYPE_CHANGE
    assert (changes[0].old_type, changes[0].new_type) == ("INT", "TEXT")
    assert changes[0].evidence_refs == ("dbt:compiled-direct-cast-type-changed",)


def test_manifest_rejects_changed_retained_projection_without_type_proof() -> None:
    before = _manifest(
        columns={"amount": {"name": "amount"}},
        compiled="select raw_amount + 1 as amount from raw.orders",
    )
    after = _manifest(
        columns={"amount": {"name": "amount"}},
        compiled="select raw_amount / 2 as amount from raw.orders",
    )

    with pytest.raises(UnsupportedChangeError, match="without trustworthy output type"):
        compare_dbt_manifests(before, after)


def test_manifest_rejects_declared_type_that_hides_a_compiled_cast_change() -> None:
    before = _manifest(
        columns={"amount": {"name": "amount", "data_type": "integer"}},
        compiled="select cast(raw_amount as integer) as amount from raw.orders",
    )
    after = _manifest(
        columns={
            "amount": {"name": "amount", "data_type": "integer"},
            "region": {
                "name": "region",
                "data_type": "varchar",
                "nullable": True,
            },
        },
        compiled=(
            "select cast(raw_amount as varchar) as amount, "
            "cast(region as varchar) as region from raw.orders"
        ),
    )

    with pytest.raises(ChangeParseError, match="conflicting declared and compiled output types"):
        compare_dbt_manifests(before, after)


def test_manifest_parentheses_cannot_hide_a_compiled_cast_change() -> None:
    before = _manifest(
        columns={"amount": {"name": "amount", "data_type": "integer"}},
        compiled="select ((cast(raw_amount as integer))) as amount from raw.orders",
    )
    after = _manifest(
        columns={"amount": {"name": "amount", "data_type": "integer"}},
        compiled="select ((cast(raw_amount as varchar))) as amount from raw.orders",
    )

    with pytest.raises(ChangeParseError, match="conflicting declared and compiled output types"):
        compare_dbt_manifests(before, after)


def test_manifest_nested_expression_cast_is_not_treated_as_a_direct_output_cast() -> None:
    before = _manifest(
        columns={"amount": {"name": "amount"}},
        compiled=("select coalesce(cast(raw_amount as integer), 0) as amount from raw.orders"),
    )
    after = _manifest(
        columns={"amount": {"name": "amount"}},
        compiled=("select coalesce(cast(raw_amount as varchar), '0') as amount from raw.orders"),
    )

    with pytest.raises(UnsupportedChangeError, match="without trustworthy output type"):
        compare_dbt_manifests(before, after)


def test_manifest_nullability_supports_dbt_flags_and_constraint_objects() -> None:
    before = _manifest(
        columns={
            "status": {
                "name": "status",
                "data_type": "varchar",
                "not_null": False,
            }
        },
        compiled="select status from raw.orders",
    )
    after = _manifest(
        columns={
            "status": {
                "name": "status",
                "data_type": "varchar",
                "constraints": [{"type": "not null"}],
            }
        },
        compiled="select status from raw.orders",
    )

    changes = compare_dbt_manifests(before, after)

    assert len(changes) == 1
    assert changes[0].change_type is ChangeType.NULLABILITY_CHANGE
    assert (changes[0].old_nullable, changes[0].new_nullable) == (True, False)


@pytest.mark.parametrize(
    "node_update, match",
    [
        ({"relation_name": None, "name": None}, "no usable relation"),
        ({"relation_name": "not a valid relation !!!"}, "invalid relation_name"),
        ({"columns": []}, "columns must be an object"),
        ({"columns": {"id": []}}, "metadata must be an object"),
        ({"columns": {"id": {"name": ""}}}, "invalid column name"),
        (
            {"columns": {"first": {"name": "ID"}, "second": {"name": "id"}}},
            "duplicate column",
        ),
        ({"columns": {"id": {"name": "id", "data_type": " "}}}, "must not be empty"),
    ],
)
def test_manifest_rejects_untrustworthy_node_shapes(
    node_update: dict[str, object], match: str
) -> None:
    manifest = _manifest(columns={}, compiled="select id from raw.orders")
    node = next(iter(manifest["nodes"].values()))
    assert isinstance(node, dict)
    node.update(node_update)
    with pytest.raises(ChangeParseError, match=match):
        compare_dbt_manifests(manifest, manifest)


def test_alter_table_parser_supports_only_normalized_column_actions() -> None:
    changes = parse_alter_table(
        """
        ALTER TABLE analytics.orders RENAME COLUMN order_total TO gross_amount;
        ALTER TABLE analytics.orders ADD COLUMN currency VARCHAR(3) NOT NULL;
        ALTER TABLE analytics.orders DROP COLUMN legacy_code;
        ALTER TABLE analytics.orders ALTER COLUMN gross_amount TYPE DECIMAL(18, 2);
        ALTER TABLE analytics.orders ALTER COLUMN gross_amount SET NOT NULL;
        ALTER TABLE analytics.orders ALTER COLUMN note DROP NOT NULL;
        """,
        dialect="postgres",
        source_path="migrations/0042_orders.sql",
    )

    assert [change.change_type for change in changes] == [
        ChangeType.RENAME_COLUMN,
        ChangeType.DROP_COLUMN,
        ChangeType.ADD_COLUMN,
        ChangeType.TYPE_CHANGE,
        ChangeType.NULLABILITY_CHANGE,
        ChangeType.NULLABILITY_CHANGE,
    ]
    assert changes[0].old_column == "order_total"
    assert changes[0].new_column == "gross_amount"
    assert changes[2].new_type == "VARCHAR(3)"
    assert changes[2].new_nullable is False
    assert changes[3].old_type == "UNKNOWN"
    assert changes[3].new_type == "DECIMAL(18, 2)"
    assert (changes[4].old_nullable, changes[4].new_nullable) == (True, False)
    assert (changes[5].old_nullable, changes[5].new_nullable) == (False, True)
    assert all(change.source_path == "migrations/0042_orders.sql" for change in changes)
    assert all(
        reference.startswith("sqlglot:") for change in changes for reference in change.evidence_refs
    )


@pytest.mark.parametrize(
    "sql, match",
    [
        ("SELECT * FROM analytics.orders", "Only ALTER TABLE"),
        ("ALTER TABLE analytics.orders ADD CONSTRAINT valid CHECK (id > 0)", "Unsupported"),
        ("ALTER TABLE analytics.orders ADD COLUMN active BOOLEAN DEFAULT true", "constraint"),
        ("ALTER TABLE analytics.orders DROP COLUMN id CASCADE", "CASCADE"),
        ("ALTER TABLE analytics.orders ALTER COLUMN id SET DEFAULT 1", "DEFAULT"),
        ("ALTER TABLE analytics.orders ALTER COLUMN id DROP DEFAULT", "Unsupported ALTER COLUMN"),
        ("ALTER TABLE analytics.orders ALTER COLUMN id TYPE BIGINT USING id::bigint", "USING"),
        ("ALTER TABLE analytics.orders RENAME TO purchases", "Unsupported"),
    ],
)
def test_alter_table_parser_rejects_unsupported_ast_actions(sql: str, match: str) -> None:
    with pytest.raises(UnsupportedChangeError, match=match):
        parse_alter_table(sql)


def test_alter_table_parser_rejects_mixed_or_malformed_statements_atomically() -> None:
    with pytest.raises(UnsupportedChangeError, match="Only ALTER TABLE"):
        parse_alter_table("ALTER TABLE orders RENAME COLUMN old TO new; DROP TABLE audit_log")
    with pytest.raises(ChangeParseError):
        parse_alter_table("ALTER TABLE")
    with pytest.raises(ChangeParseError, match="must not be empty"):
        parse_alter_table("  \n")


def test_alter_table_preserves_quoted_names_and_explicit_nullable_addition() -> None:
    changes = parse_alter_table(
        'ALTER TABLE "Analytics"."Orders" ADD COLUMN "DisplayName" VARCHAR(40) NULL'
    )

    assert len(changes) == 1
    assert changes[0].relation == '"Analytics"."Orders"'
    assert changes[0].new_column == '"DisplayName"'
    assert changes[0].new_nullable is True


def test_change_parser_facade_delegates_both_inputs() -> None:
    parser = ChangeParser()
    sql_change = parser.parse_alter_table("ALTER TABLE orders DROP COLUMN legacy")
    manifest_changes = parser.compare_dbt_manifests(
        FIXTURES / "manifest_before.json", FIXTURES / "manifest_after.json"
    )

    assert sql_change[0].change_type is ChangeType.DROP_COLUMN
    assert manifest_changes[0].change_type is ChangeType.RENAME_COLUMN


def _manifest(*, columns: dict[str, dict[str, object]], compiled: str) -> dict[str, object]:
    return {
        "metadata": {"adapter_type": "duckdb"},
        "nodes": {
            "model.lineageguard.orders": {
                "resource_type": "model",
                "name": "orders",
                "relation_name": "analytics.orders",
                "columns": columns,
                "compiled_code": compiled,
            }
        },
    }
