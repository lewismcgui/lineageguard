"""Tests for deterministic, in-memory dbt remediation generation."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
import yaml

from lineageguard.models import SchemaChange
from lineageguard.remediation import (
    AmbiguousRemediationError,
    GeneratedArtifact,
    RemediationBundle,
    RemediationGenerator,
    UnsafePathError,
    UnsupportedRemediationError,
    generate_rename_remediation,
)

MODEL_PATH = "models/marts/orders.sql"
SCHEMA_PATH = "models/marts/schema.yml"
TEST_PATH = "tests/order_total_matches_gross_amount.sql"
ALLOWLIST = {MODEL_PATH, SCHEMA_PATH, TEST_PATH}
MODEL_SQL = """{{ config(materialized='table') }}

select
    order_id,
    gross_amount
from {{ ref('stg_orders') }}
"""
SCHEMA_YAML = """version: 2
models:
  - name: orders
    description: Curated orders.
    columns:
      - name: order_id
        data_type: bigint
      - name: gross_amount
        data_type: decimal(18, 2)
        constraints:
          - type: not_null
        data_tests:
          - not_null
"""


def test_demo_rename_generates_compatibility_metadata_and_equality_test(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    change = _rename()
    generator = RemediationGenerator(ALLOWLIST)

    bundle = generator.generate(
        change,
        model_path=MODEL_PATH,
        model_sql=MODEL_SQL,
        schema_path=SCHEMA_PATH,
        schema_yaml=SCHEMA_YAML,
        test_path=TEST_PATH,
    )

    assert list(tmp_path.iterdir()) == []  # generation performs no writes or execution
    assert bundle.change_id == change.id
    assert set(bundle.by_path) == ALLOWLIST

    patched_model = bundle.by_path[MODEL_PATH].content
    assert "gross_amount AS order_total" in patched_model
    assert "FROM {{ ref('stg_orders') }}" in patched_model
    projection_lines = [line.strip().rstrip(",") for line in patched_model.splitlines()]
    assert projection_lines.index("gross_amount AS order_total") < projection_lines.index(
        "gross_amount"
    )

    patched_schema = yaml.safe_load(bundle.by_path[SCHEMA_PATH].content)
    columns = patched_schema["models"][0]["columns"]
    assert [column["name"] for column in columns] == [
        "order_id",
        "order_total",
        "gross_amount",
    ]
    deprecated = next(column for column in columns if column["name"] == "order_total")
    assert deprecated["data_type"] == "decimal(18, 2)"
    assert deprecated["constraints"] == [{"type": "not_null"}]
    assert deprecated["data_tests"] == ["not_null"]
    assert deprecated["meta"]["lineageguard"] == {
        "deprecated": True,
        "replacement": "gross_amount",
        "change_id": change.id,
    }
    assert "Use `gross_amount` instead" in deprecated["description"]

    test_sql = bundle.by_path[TEST_PATH].content
    assert "from {{ ref('orders') }}" in test_sql
    assert "where order_total is distinct from gross_amount" in test_sql
    assert bundle.by_path[TEST_PATH].previous_content is None
    assert f"+++ b/{TEST_PATH}" in bundle.unified_diff


def test_generation_is_byte_for_byte_deterministic() -> None:
    generator = RemediationGenerator(reversed(sorted(ALLOWLIST)))
    arguments = {
        "model_path": MODEL_PATH,
        "model_sql": MODEL_SQL,
        "schema_path": SCHEMA_PATH,
        "schema_yaml": SCHEMA_YAML,
        "test_path": TEST_PATH,
    }

    first = generator.generate(_rename(), **arguments)
    second = generator.generate(_rename(), **arguments)

    assert first == second
    assert first.unified_diff == second.unified_diff
    assert [artifact.path for artifact in first.artifacts] == sorted(ALLOWLIST)
    assert [artifact.sha256 for artifact in first.artifacts] == [
        artifact.sha256 for artifact in second.artifacts
    ]


def test_direct_column_cast_can_be_preserved_as_compatibility_alias() -> None:
    bundle = RemediationGenerator(ALLOWLIST).generate(
        _rename(),
        model_path=MODEL_PATH,
        model_sql="select cast(order_total as decimal(12, 2)) as gross_amount from raw.orders\n",
        schema_path=SCHEMA_PATH,
        schema_yaml=SCHEMA_YAML,
        test_path=TEST_PATH,
    )
    patched = bundle.by_path[MODEL_PATH].content
    assert "CAST(order_total AS DECIMAL(12, 2)) AS gross_amount" in patched
    assert "CAST(order_total AS DECIMAL(12, 2)) AS order_total" in patched


@pytest.mark.parametrize(
    "path",
    [
        "/tmp/orders.sql",
        "../models/orders.sql",
        "models/../orders.sql",
        "models\\orders.sql",
        "",
    ],
)
def test_constructor_rejects_unsafe_allowlist_paths(path: str) -> None:
    with pytest.raises(UnsafePathError):
        RemediationGenerator([path])


def test_constructor_requires_a_path_and_exposes_an_immutable_allowlist() -> None:
    with pytest.raises(UnsafePathError, match="At least one"):
        RemediationGenerator([])
    generator = RemediationGenerator(ALLOWLIST)
    assert generator.allowlisted_paths == frozenset(ALLOWLIST)


def test_generator_rejects_a_non_allowlisted_target() -> None:
    generator = RemediationGenerator(ALLOWLIST)
    with pytest.raises(UnsafePathError, match="not allowlisted"):
        generator.generate(
            _rename(),
            model_path="models/not-orders.sql",
            model_sql=MODEL_SQL,
            schema_path=SCHEMA_PATH,
            schema_yaml=SCHEMA_YAML,
            test_path=TEST_PATH,
        )


def test_generator_requires_three_distinct_targets() -> None:
    generator = RemediationGenerator(ALLOWLIST)
    with pytest.raises(AmbiguousRemediationError, match="must be distinct"):
        generator.generate(
            _rename(),
            model_path=MODEL_PATH,
            model_sql=MODEL_SQL,
            schema_path=MODEL_PATH,
            schema_yaml=SCHEMA_YAML,
            test_path=TEST_PATH,
        )


def test_generator_rejects_multiple_or_unsupported_changes() -> None:
    generator = RemediationGenerator(ALLOWLIST)
    arguments = _arguments()
    with pytest.raises(AmbiguousRemediationError, match="Exactly one"):
        generator.generate([_rename(), _rename(relation="analytics.other_orders")], **arguments)
    with pytest.raises(AmbiguousRemediationError, match="Exactly one"):
        generator.generate([], **arguments)

    addition = SchemaChange(
        change_type="add",
        relation="analytics.orders",
        new_column="currency",
        new_nullable=True,
    )
    with pytest.raises(UnsupportedRemediationError, match="No bounded remediation"):
        generator.generate(addition, **arguments)


@pytest.mark.parametrize(
    "model_sql, error_type, match",
    [
        (
            "select gross_amount, order_total from raw.orders",
            UnsupportedRemediationError,
            "already exposes",
        ),
        ("select order_id from raw.orders", AmbiguousRemediationError, "found 0"),
        (
            "select gross_amount, order_total as gross_amount from raw.orders",
            AmbiguousRemediationError,
            "found 2",
        ),
        (
            "select price * quantity as gross_amount from raw.orders",
            UnsupportedRemediationError,
            "direct column projections",
        ),
        (
            'select gross_amount as "gross_amount" from raw.orders',
            UnsupportedRemediationError,
            "Quoted output identifiers",
        ),
        (
            "select gross_amount from raw.orders union all select gross_amount from raw.archive",
            UnsupportedRemediationError,
            "top-level SELECT",
        ),
        (
            "select {{ dangerous_macro() }} as gross_amount from raw.orders",
            UnsupportedRemediationError,
            "Only dbt ref/source",
        ),
        ("", UnsupportedRemediationError, "must not be empty"),
        ("select (", UnsupportedRemediationError, "not safely parseable"),
        (
            "{{ config(materialized='table') select gross_amount from raw.orders",
            UnsupportedRemediationError,
            "Unclosed leading",
        ),
        (
            "{% if execute %} select gross_amount from raw.orders {% endif %}",
            UnsupportedRemediationError,
            "statement/comment blocks",
        ),
        (
            "select gross_amount from {{ ref('orders') ",
            UnsupportedRemediationError,
            "Unclosed dbt expression",
        ),
    ],
)
def test_generator_rejects_ambiguous_or_unsupported_model_sql(
    model_sql: str, error_type: type[Exception], match: str
) -> None:
    generator = RemediationGenerator(ALLOWLIST)
    arguments = _arguments()
    arguments["model_sql"] = model_sql
    with pytest.raises(error_type, match=match):
        generator.generate(_rename(), **arguments)


@pytest.mark.parametrize(
    "schema_yaml, error_type, match",
    [
        ("- not-a-mapping", UnsupportedRemediationError, "must be a mapping"),
        ("version: 2", UnsupportedRemediationError, "models list"),
        (
            "version: 2\nmodels:\n  - name: other\n    columns: []\n",
            AmbiguousRemediationError,
            "found 0",
        ),
        (
            "version: 2\nmodels:\n  - name: orders\n    columns: []\n",
            AmbiguousRemediationError,
            "schema column.*found 0",
        ),
        (
            """version: 2
models:
  - name: orders
    columns:
      - name: gross_amount
      - name: order_total
""",
            UnsupportedRemediationError,
            "already declares",
        ),
        ("version: [", UnsupportedRemediationError, "Invalid dbt schema YAML"),
        (
            "version: 2\nmodels:\n  - name: orders\n    columns: not-a-list\n",
            UnsupportedRemediationError,
            "columns list",
        ),
    ],
)
def test_generator_rejects_ambiguous_or_unsupported_schema_yaml(
    schema_yaml: str, error_type: type[Exception], match: str
) -> None:
    generator = RemediationGenerator(ALLOWLIST)
    arguments = _arguments()
    arguments["schema_yaml"] = schema_yaml
    with pytest.raises(error_type, match=match):
        generator.generate(_rename(), **arguments)


def test_generator_refuses_to_overwrite_existing_test() -> None:
    generator = RemediationGenerator(ALLOWLIST)
    with pytest.raises(UnsupportedRemediationError, match="overwrite"):
        generator.generate(_rename(), existing_test_sql="select 1", **_arguments())


def test_generator_rejects_identifier_injection() -> None:
    unsafe = _rename(new_column="gross_amount; drop table orders")
    with pytest.raises(UnsupportedRemediationError, match="Unsafe new column"):
        RemediationGenerator(ALLOWLIST).generate(unsafe, **_arguments())

    unsafe_model = _rename(relation="analytics.123orders")
    with pytest.raises(UnsupportedRemediationError, match="Unsafe dbt model"):
        RemediationGenerator(ALLOWLIST).generate(unsafe_model, **_arguments())


def test_macro_placeholder_collision_is_avoided_deterministically() -> None:
    model_sql = "select __lineageguard_jinja_000__, gross_amount from {{ source('raw', 'orders') }}"
    arguments = _arguments()
    arguments["model_sql"] = model_sql

    bundle = RemediationGenerator(ALLOWLIST).generate(_rename(), **arguments)

    patched = bundle.by_path[MODEL_PATH].content
    assert "__lineageguard_jinja_000__" in patched
    assert "{{ source('raw', 'orders') }}" in patched
    assert "gross_amount AS order_total" in patched


def test_bundle_is_immutable_and_path_map_is_read_only() -> None:
    bundle = RemediationGenerator(ALLOWLIST).generate(_rename(), **_arguments())
    with pytest.raises(FrozenInstanceError):
        bundle.artifacts[0].content = "tampered"  # type: ignore[misc]
    with pytest.raises(TypeError):
        bundle.by_path[MODEL_PATH] = bundle.artifacts[0]  # type: ignore[index]


def test_bundle_rejects_duplicate_artifact_paths() -> None:
    artifact = GeneratedArtifact(
        path=MODEL_PATH,
        content="select 1\n",
        previous_content=None,
        purpose="test",
    )
    with pytest.raises(AmbiguousRemediationError, match="target a path twice"):
        RemediationBundle(change_id="change-demo", artifacts=(artifact, artifact))


def test_functional_wrapper_uses_the_same_bounded_generator() -> None:
    bundle = generate_rename_remediation(_rename(), allowlisted_paths=ALLOWLIST, **_arguments())
    assert "gross_amount AS order_total" in bundle.by_path[MODEL_PATH].content


def _rename(
    *,
    relation: str = "analytics.orders",
    old_column: str = "order_total",
    new_column: str = "gross_amount",
) -> SchemaChange:
    return SchemaChange(
        change_type="rename",
        relation=relation,
        old_column=old_column,
        new_column=new_column,
        source_path="target/manifest.json",
        evidence_refs=("dbt:compiled-expression:demo",),
    )


def _arguments() -> dict[str, str]:
    return {
        "model_path": MODEL_PATH,
        "model_sql": MODEL_SQL,
        "schema_path": SCHEMA_PATH,
        "schema_yaml": SCHEMA_YAML,
        "test_path": TEST_PATH,
    }
