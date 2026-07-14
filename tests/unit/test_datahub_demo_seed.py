from __future__ import annotations

import json
import os
from collections.abc import Sequence
from typing import Any

import pytest
from datahub.emitter.mcp import MetadataChangeProposalWrapper
from datahub.metadata.schema_classes import (
    AssertionInfoClass,
    AssertionStdAggregationClass,
    AssertionStdOperatorClass,
    ChartInfoClass,
    CorpGroupInfoClass,
    DashboardInfoClass,
    DataFlowInfoClass,
    DataJobInputOutputClass,
    DatasetAssertionScopeClass,
    GlobalTagsClass,
    OwnershipClass,
    SchemaMetadataClass,
    TagPropertiesClass,
    UpstreamLineageClass,
)

from lineageguard.config import Settings
from lineageguard.datahub import demo_seed
from lineageguard.datahub.demo_seed import (
    DEMO_SEED_TIMESTAMP_MS,
    DEMO_URNS,
    build_demo_mcps,
    emit_demo_metadata,
    seed_demo,
)


def _aspect(
    proposals: Sequence[MetadataChangeProposalWrapper],
    urn: str,
    aspect_type: type[Any],
) -> Any:
    matches = [
        proposal.aspect
        for proposal in proposals
        if proposal.entityUrn == urn and isinstance(proposal.aspect, aspect_type)
    ]
    assert len(matches) == 1
    return matches[0]


def _serialized(proposals: Sequence[MetadataChangeProposalWrapper]) -> list[str]:
    return [
        json.dumps(proposal.to_obj(simplified_structure=True), sort_keys=True)
        for proposal in proposals
    ]


def test_seed_plan_is_valid_deterministic_and_idempotent() -> None:
    first = build_demo_mcps()
    second = build_demo_mcps()

    assert len(first) == 60
    assert all(proposal.validate() for proposal in first)
    assert _serialized(first) == _serialized(second)
    assert {
        proposal.systemMetadata.lastObserved
        for proposal in first
        if proposal.systemMetadata is not None
    } == {DEMO_SEED_TIMESTAMP_MS}
    assert len({(proposal.entityUrn, proposal.aspectName) for proposal in first}) == len(first)
    assert {proposal.changeType for proposal in first} == {"UPSERT"}


def test_dataset_schemas_owners_tags_and_column_lineage_are_real_aspects() -> None:
    proposals = build_demo_mcps()
    expected_fields = {
        DEMO_URNS.raw_orders: [
            "order_id",
            "customer_id",
            "order_date",
            "status",
            "order_total",
            "currency",
        ],
        DEMO_URNS.staging_orders: [
            "order_id",
            "customer_id",
            "order_date",
            "status",
            "order_total",
            "currency",
        ],
        DEMO_URNS.daily_revenue: [
            "order_date",
            "currency",
            "order_count",
            "gross_revenue",
        ],
    }
    expected_owners = {
        DEMO_URNS.raw_orders: "urn:li:corpGroup:commerce_platform",
        DEMO_URNS.staging_orders: "urn:li:corpGroup:commerce_analytics",
        DEMO_URNS.daily_revenue: "urn:li:corpGroup:finance_analytics",
    }

    assert "acme_commerce.analytics_raw.orders" in DEMO_URNS.raw_orders
    assert "acme_commerce.analytics_staging.stg_orders" in DEMO_URNS.staging_orders
    assert "acme_commerce.analytics_marts.fct_daily_revenue" in DEMO_URNS.daily_revenue

    for urn, field_names in expected_fields.items():
        schema = _aspect(proposals, urn, SchemaMetadataClass)
        assert schema.platform == "urn:li:dataPlatform:duckdb"
        assert [field.fieldPath for field in schema.fields] == field_names
        assert len(schema.hash) == 64

        ownership = _aspect(proposals, urn, OwnershipClass)
        assert [owner.owner for owner in ownership.owners] == [expected_owners[urn]]

        tags = _aspect(proposals, urn, GlobalTagsClass)
        assert "urn:li:tag:lineageguard_demo" in [tag.tag for tag in tags.tags]

    staging_lineage = _aspect(proposals, DEMO_URNS.staging_orders, UpstreamLineageClass)
    assert [upstream.dataset for upstream in staging_lineage.upstreams] == [DEMO_URNS.raw_orders]
    assert len(staging_lineage.fineGrainedLineages or []) == 6

    mart_lineage = _aspect(proposals, DEMO_URNS.daily_revenue, UpstreamLineageClass)
    assert [upstream.dataset for upstream in mart_lineage.upstreams] == [DEMO_URNS.staging_orders]
    downstream_fields = {
        lineage.downstreams[0].rsplit(",", 1)[-1].removesuffix(")")
        for lineage in mart_lineage.fineGrainedLineages or []
        if lineage.downstreams
    }
    assert downstream_fields == {"order_date", "currency", "order_count", "gross_revenue"}


def test_flow_job_dashboard_chart_and_assertion_form_connected_graph() -> None:
    proposals = build_demo_mcps()

    flow = _aspect(proposals, DEMO_URNS.dbt_flow, DataFlowInfoClass)
    assert flow.project == "acme_commerce"
    assert DEMO_URNS.dbt_flow == "urn:li:dataFlow:(dbt,acme_commerce,PROD)"

    job_io = _aspect(proposals, DEMO_URNS.dbt_job, DataJobInputOutputClass)
    assert job_io.inputDatasets == [DEMO_URNS.staging_orders]
    assert job_io.outputDatasets == [DEMO_URNS.daily_revenue]

    chart = _aspect(proposals, DEMO_URNS.revenue_chart, ChartInfoClass)
    assert chart.inputs == [DEMO_URNS.daily_revenue]

    dashboard = _aspect(proposals, DEMO_URNS.revenue_dashboard, DashboardInfoClass)
    assert dashboard.charts == [DEMO_URNS.revenue_chart]
    assert dashboard.datasets == [DEMO_URNS.daily_revenue]

    assertion = _aspect(proposals, DEMO_URNS.revenue_assertion, AssertionInfoClass)
    assert assertion.datasetAssertion is not None
    assert assertion.datasetAssertion.dataset == DEMO_URNS.daily_revenue
    assert assertion.datasetAssertion.scope == DatasetAssertionScopeClass.DATASET_COLUMN
    assert assertion.datasetAssertion.operator == AssertionStdOperatorClass.NOT_NULL
    assert assertion.datasetAssertion.aggregation == AssertionStdAggregationClass.IDENTITY
    assert assertion.datasetAssertion.fields == [
        f"urn:li:schemaField:({DEMO_URNS.daily_revenue},gross_revenue)"
    ]
    assert {
        proposal.aspectName
        for proposal in proposals
        if proposal.entityUrn == DEMO_URNS.revenue_assertion
    } == {"status", "assertionInfo", "globalTags"}


def test_referenced_owner_groups_and_tags_are_materialized() -> None:
    proposals = build_demo_mcps()
    group_urns = {
        proposal.entityUrn
        for proposal in proposals
        if isinstance(proposal.aspect, CorpGroupInfoClass)
    }
    tag_urns = {
        proposal.entityUrn
        for proposal in proposals
        if isinstance(proposal.aspect, TagPropertiesClass)
    }

    assert group_urns == {
        "urn:li:corpGroup:commerce_platform",
        "urn:li:corpGroup:commerce_analytics",
        "urn:li:corpGroup:finance_analytics",
    }
    assert tag_urns == {
        "urn:li:tag:lineageguard_demo",
        "urn:li:tag:synthetic_data",
        "urn:li:tag:business_critical",
        "urn:li:tag:internal",
        "urn:li:tag:LineageGuard_PASS",
        "urn:li:tag:LineageGuard_PASS_WITH_REMEDIATION",
        "urn:li:tag:LineageGuard_REVIEW",
        "urn:li:tag:LineageGuard_BLOCK",
    }


class RecordingEmitter:
    def __init__(self) -> None:
        self.items: list[MetadataChangeProposalWrapper] = []

    def emit(self, item: MetadataChangeProposalWrapper, callback: object = None) -> None:
        self.items.append(item)

    def flush(self) -> None:
        return None


def test_offline_emitter_receives_the_complete_sdk_plan() -> None:
    emitter = RecordingEmitter()
    count = emit_demo_metadata(emitter)

    assert count == 60
    assert _serialized(emitter.items) == _serialized(build_demo_mcps())


def test_seed_uses_private_token_file_without_printing_it(
    tmp_path: Any, monkeypatch: Any, capsys: Any
) -> None:
    secret = "unit-test-secret-that-must-not-be-printed"
    token_file = tmp_path / "datahub-token"
    token_file.write_text(secret, encoding="utf-8")
    os.chmod(token_file, 0o600)
    captured: dict[str, Any] = {}

    class FakeRestEmitter(RecordingEmitter):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__()
            captured.update(kwargs)

        def close(self) -> None:
            captured["closed"] = True

    monkeypatch.setattr(demo_seed, "DataHubRestEmitter", FakeRestEmitter)
    settings = Settings(
        _env_file=None,
        project_root=tmp_path,
        datahub_gms_token_file=token_file,
    )

    assert seed_demo(settings) == 60
    assert captured["token"] == secret
    assert captured["default_emit_mode"].value == "SYNC_WAIT"
    assert captured["closed"] is True
    output = capsys.readouterr()
    assert secret not in output.out
    assert secret not in output.err


def test_demo_seed_rejects_non_loopback_catalog_before_emitter_creation(tmp_path) -> None:
    settings = Settings(
        _env_file=None,
        project_root=tmp_path,
        datahub_gms_url="https://datahub.example.com",
        datahub_gms_token="unit-token",
    )

    with pytest.raises(ValueError, match="restricted to loopback"):
        seed_demo(settings)
