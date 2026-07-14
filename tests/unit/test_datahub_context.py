from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from lineageguard.datahub.context import DataHubContextCollector, _find_first_string
from lineageguard.datahub.graphql import AssertionPage
from lineageguard.datahub.mcp_client import MCPToolResponse
from lineageguard.models import EvidenceStatus, RiskDecision, SchemaChange, SchemaChangeType
from lineageguard.risk import RiskEngine

SOURCE = "urn:li:dataset:(urn:li:dataPlatform:duckdb,analytics.stg_orders,PROD)"
MODEL = "urn:li:dataset:(urn:li:dataPlatform:duckdb,analytics.fct_daily_revenue,PROD)"
DASHBOARD = "urn:li:dashboard:(looker,executive_revenue)"
DATA_JOB = "urn:li:dataJob:(urn:li:dataFlow:(dbt,acme,PROD),build_revenue)"


def _response(tool: str, data: Any, digest: str) -> MCPToolResponse:
    return MCPToolResponse(tool=tool, data=data, text="", digest=digest)


def _schema_page(fields: list[dict[str, Any]], *, urn: str = SOURCE) -> dict[str, Any]:
    return {
        "urn": urn,
        "fields": fields,
        "totalFields": len(fields),
        "returned": len(fields),
        "remainingCount": 0,
        "matchingCount": len(fields),
        "offset": 0,
    }


class FakeMCP:
    def __init__(self, *, ambiguous: bool = False, truncated: bool = False) -> None:
        self.ambiguous = ambiguous
        self.truncated = truncated
        self.calls: list[tuple[str, Mapping[str, Any] | None]] = []

    async def call_read(
        self, tool: str, arguments: Mapping[str, Any] | None = None
    ) -> MCPToolResponse:
        self.calls.append((tool, arguments))
        if tool == "search":
            urns = [SOURCE]
            if self.ambiguous:
                urns.append(
                    "urn:li:dataset:(urn:li:dataPlatform:snowflake,analytics.stg_orders,PROD)"
                )
            return _response(
                tool,
                {
                    "searchResults": [{"entity": {"urn": urn}} for urn in urns],
                    "total": len(urns),
                    "start": 0,
                    "count": len(urns),
                },
                "search1",
            )
        if tool == "list_schema_fields":
            return _response(
                tool,
                _schema_page([{"fieldPath": "order_total", "nativeDataType": "DECIMAL"}]),
                "schema1",
            )
        if tool == "get_lineage":
            total = 3 if self.truncated else 2
            return _response(
                tool,
                {
                    "downstreams": {
                        "searchResults": [
                            {
                                "entity": {"urn": MODEL},
                                "degree": 1,
                                "lineageColumns": ["gross_revenue"],
                            },
                            {"entity": {"urn": DASHBOARD}, "degree": 2},
                        ],
                        "total": total,
                        "offset": 0,
                        "returned": 2,
                        "hasMore": self.truncated,
                    }
                },
                "lineage1",
            )
        if tool == "get_entities":
            return _response(
                tool,
                [
                    {
                        "urn": MODEL,
                        "properties": {"name": "fct_daily_revenue"},
                        "ownership": {"owners": [{"owner": {"urn": "urn:li:corpuser:analytics"}}]},
                    },
                    {
                        "urn": DASHBOARD,
                        "properties": {"name": "Executive Revenue"},
                        "ownership": {"owners": [{"owner": {"urn": "urn:li:corpuser:finance"}}]},
                        "globalTags": {"tags": [{"tag": {"urn": "urn:li:tag:Critical"}}]},
                    },
                ],
                "entities1",
            )
        raise AssertionError(f"unexpected tool {tool}")


class FakeGraphQL:
    def get_dataset_assertions(
        self, dataset_urn: str, *, start: int = 0, count: int = 100
    ) -> AssertionPage:
        del count
        assertions: tuple[dict[str, Any], ...] = ()
        if dataset_urn == SOURCE and start == 0:
            assertions = (
                {
                    "urn": "urn:li:assertion:not-null-order-total",
                    "info": {"description": "order_total contract"},
                },
            )
        return AssertionPage(
            assertions=assertions,
            total=len(assertions),
            start=start,
            count=len(assertions),
            digest=f"assertions-{len(assertions)}-{dataset_urn[-8:]}",
        )


def _change(relation: str = "analytics.stg_orders") -> SchemaChange:
    return SchemaChange(
        change_type=SchemaChangeType.RENAME_COLUMN,
        relation=relation,
        old_column="order_total",
        new_column="gross_amount",
        old_type="DECIMAL",
        new_type="DECIMAL",
    )


@pytest.mark.asyncio
async def test_collects_mcp_lineage_owners_dashboard_and_assertion() -> None:
    mcp = FakeMCP()
    context = await DataHubContextCollector(mcp, FakeGraphQL()).collect(_change())
    assert context.source_urn == SOURCE
    assert context.evidence_state == context.evidence_state.complete(
        records=context.evidence_state.records
    )
    assets = {asset.urn: asset for asset in context.impacted_assets}
    assert assets[MODEL].direct_column_lineage is True
    assert assets[MODEL].owners == ("urn:li:corpuser:analytics",)
    assert "mcp-lineage:lineage1" in assets[MODEL].evidence_refs
    assert "mcp-lineage:search1" not in assets[MODEL].evidence_refs
    assert assets[DASHBOARD].critical_asset is True
    assertion = assets["urn:li:assertion:not-null-order-total"]
    assert assertion.assertion_urns == ("urn:li:assertion:not-null-order-total",)
    assert assertion.owners is None
    assert assertion.critical_asset is None
    assert assertion.direct_column_lineage is None
    assert [call[0] for call in mcp.calls] == [
        "search",
        "list_schema_fields",
        "get_lineage",
        "get_entities",
    ]


@pytest.mark.asyncio
async def test_entity_enrichment_uses_only_exact_top_level_entities() -> None:
    class NestedIdentityMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_entities":
                assert isinstance(response.data, list)
                model = response.data[0]
                assert isinstance(model, dict)
                model["nested_partial_reference"] = {
                    "urn": MODEL,
                    "ownership": {"owners": []},
                }
            return response

    context = await DataHubContextCollector(NestedIdentityMCP(), FakeGraphQL()).collect(_change())
    assets = {asset.urn: asset for asset in context.impacted_assets}

    assert context.evidence_state.ownership is EvidenceStatus.COMPLETE
    assert assets[MODEL].owners == ("urn:li:corpuser:analytics",)


@pytest.mark.parametrize(
    "malformation",
    ["duplicate", "unrequested", "ownership", "tags", "error"],
)
@pytest.mark.asyncio
async def test_entity_enrichment_rejects_unbound_or_malformed_pages(malformation: str) -> None:
    class MalformedEntityMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool != "get_entities":
                return response
            assert isinstance(response.data, list)
            first = response.data[0]
            assert isinstance(first, dict)
            if malformation == "duplicate":
                response.data.append(dict(first))
            elif malformation == "unrequested":
                response.data.append({"urn": "urn:li:dataset:unrequested"})
            elif malformation == "ownership":
                first["ownership"] = "not-an-ownership-aspect"
            elif malformation == "tags":
                first["globalTags"] = {"tags": [{"tag": {"urn": 123}}]}
            else:
                first["error"] = "partial failure"
            return response

    context = await DataHubContextCollector(MalformedEntityMCP(), FakeGraphQL()).collect(_change())

    assert context.evidence_state.ownership is EvidenceStatus.UNAVAILABLE
    assert "ownership.enrichment_unavailable" in context.reason_codes
    assert MODEL not in {asset.urn for asset in context.impacted_assets}


@pytest.mark.asyncio
async def test_direct_dataset_urn_resolves_without_search() -> None:
    mcp = FakeMCP()

    context = await DataHubContextCollector(mcp, FakeGraphQL()).collect(_change(SOURCE))

    assert context.source_urn == SOURCE
    assert context.evidence_state.catalog is EvidenceStatus.COMPLETE
    assert "search" not in [call[0] for call in mcp.calls]


@pytest.mark.asyncio
async def test_downstream_assertions_attach_to_the_dataset_without_fabricated_facts() -> None:
    class DownstreamGraphQL(FakeGraphQL):
        def get_dataset_assertions(
            self, dataset_urn: str, *, start: int = 0, count: int = 100
        ) -> AssertionPage:
            if dataset_urn == MODEL and start == 0:
                assertion = {
                    "urn": "urn:li:assertion:daily-revenue-not-null",
                    "info": {
                        "description": "gross_revenue contract",
                        "datasetAssertion": {"fields": [{"path": "GROSS_REVENUE"}]},
                    },
                }
                unrelated = {
                    "urn": "urn:li:assertion:daily-revenue-date-not-null",
                    "info": {
                        "description": "order_date contract",
                        "datasetAssertion": {"fields": [{"path": "order_date"}]},
                    },
                }
                return AssertionPage(
                    assertions=(assertion, unrelated),
                    total=2,
                    start=0,
                    count=2,
                    digest="downstream-assertion",
                )
            return super().get_dataset_assertions(dataset_urn, start=start, count=count)

    context = await DataHubContextCollector(FakeMCP(), DownstreamGraphQL()).collect(_change())
    assets = {asset.urn: asset for asset in context.impacted_assets}

    assert assets[MODEL].assertion_urns == ("urn:li:assertion:daily-revenue-not-null",)
    assert "urn:li:assertion:daily-revenue-not-null" not in assets
    assert "urn:li:assertion:daily-revenue-date-not-null" not in assets[MODEL].assertion_urns


@pytest.mark.asyncio
async def test_field_assertion_is_retained_ambiguously_without_column_lineage() -> None:
    assertion_urn = "urn:li:assertion:downstream-field-contract"

    class TableLevelLineageMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_lineage":
                del response.data["downstreams"]["searchResults"][0]["lineageColumns"]
            return response

    class FieldAssertionGraphQL(FakeGraphQL):
        def get_dataset_assertions(
            self, dataset_urn: str, *, start: int = 0, count: int = 100
        ) -> AssertionPage:
            if dataset_urn == MODEL and start == 0:
                return AssertionPage(
                    assertions=(
                        {
                            "urn": assertion_urn,
                            "info": {
                                "datasetAssertion": {
                                    "fields": [{"path": "unknown_from_table_lineage"}]
                                }
                            },
                        },
                    ),
                    total=1,
                    start=0,
                    count=1,
                    digest="field-assertion-with-table-lineage",
                )
            return super().get_dataset_assertions(dataset_urn, start=start, count=count)

    context = await DataHubContextCollector(
        TableLevelLineageMCP(), FieldAssertionGraphQL()
    ).collect(_change())
    assets = {asset.urn: asset for asset in context.impacted_assets}

    assert assets[MODEL].assertion_urns == (assertion_urn,)
    assert context.evidence_state.assertions is EvidenceStatus.AMBIGUOUS
    assert "assertions.column_lineage_unknown" in context.reason_codes


@pytest.mark.asyncio
async def test_ambiguous_relation_fails_closed_before_lineage() -> None:
    mcp = FakeMCP(ambiguous=True)
    context = await DataHubContextCollector(mcp, FakeGraphQL()).collect(_change())
    assert context.source_urn is None
    assert context.evidence_state.catalog is EvidenceStatus.AMBIGUOUS
    assert context.impacted_assets == ()
    assert [call[0] for call in mcp.calls] == ["search"]


@pytest.mark.asyncio
async def test_catalog_search_paginates_before_declaring_unique() -> None:
    backup = "urn:li:dataset:(urn:li:dataPlatform:snowflake,analytics.stg_orders,PROD)"

    class PaginatedMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool != "search":
                return await super().call_read(tool, arguments)
            self.calls.append((tool, arguments))
            start = int((arguments or {}).get("offset", 0))
            urn = SOURCE if start == 0 else backup
            return _response(
                tool,
                {
                    "searchResults": [{"entity": {"urn": urn}}],
                    "total": 2,
                    "start": start,
                    "count": 1,
                },
                f"search-{start}",
            )

    context = await DataHubContextCollector(PaginatedMCP(), FakeGraphQL()).collect(_change())

    assert context.source_urn is None
    assert context.evidence_state.catalog is EvidenceStatus.AMBIGUOUS


@pytest.mark.asyncio
async def test_catalog_search_never_promotes_a_nested_dataset_urn() -> None:
    class NestedURNMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool != "search":
                return await super().call_read(tool, arguments)
            self.calls.append((tool, arguments))
            return _response(
                tool,
                {
                    "searchResults": [
                        {
                            "entity": {"urn": "urn:li:dashboard:wrong"},
                            "matchedField": {"value": SOURCE},
                        }
                    ],
                    "total": 1,
                    "start": 0,
                },
                "nested-dataset-urn",
            )

    context = await DataHubContextCollector(NestedURNMCP(), FakeGraphQL()).collect(_change())

    assert context.source_urn is None
    assert context.evidence_state.catalog is EvidenceStatus.UNAVAILABLE
    assert "catalog.search_unavailable" in context.reason_codes


@pytest.mark.asyncio
async def test_absent_add_column_is_a_complete_baseline_and_can_pass() -> None:
    class AbsentColumnMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "list_schema_fields":
                self.calls.append((tool, arguments))
                return _response(tool, _schema_page([]), "schema-absent")
            if tool == "get_lineage":
                self.calls.append((tool, arguments))
                return _response(
                    tool,
                    {
                        "downstreams": {
                            "searchResults": [],
                            "total": 0,
                            "offset": 0,
                            "returned": 0,
                            "hasMore": False,
                        }
                    },
                    "lineage-empty",
                )
            return await super().call_read(tool, arguments)

    class NoAssertionsGraphQL(FakeGraphQL):
        def get_dataset_assertions(
            self, dataset_urn: str, *, start: int = 0, count: int = 100
        ) -> AssertionPage:
            del dataset_urn, count
            return AssertionPage(
                assertions=(),
                total=0,
                start=start,
                count=0,
                digest="assertions-empty",
            )

    addition = SchemaChange(
        change_type=SchemaChangeType.ADD_COLUMN,
        relation="analytics.stg_orders",
        new_column="region",
        new_type="VARCHAR",
        new_nullable=True,
    )
    context = await DataHubContextCollector(AbsentColumnMCP(), NoAssertionsGraphQL()).collect(
        addition
    )

    assert context.source_urn == SOURCE
    assert context.evidence_state.catalog is EvidenceStatus.COMPLETE
    assert context.evidence_state == context.evidence_state.complete(
        records=context.evidence_state.records
    )
    assert not any(reason.startswith("catalog.column_") for reason in context.reason_codes)

    policy_path = Path(__file__).parents[2] / "config" / "risk-policy.yaml"
    assessment = RiskEngine.from_policy_file(policy_path).assess(
        [addition], context.impacted_assets, context.evidence_state
    )
    assert assessment.decision is RiskDecision.PASS


@pytest.mark.parametrize(
    ("change_type", "new_nullable"),
    [
        (SchemaChangeType.ADD_COLUMN, True),
        (SchemaChangeType.ADD_NULLABLE_COLUMN, True),
        (SchemaChangeType.ADD_REQUIRED_COLUMN, False),
    ],
)
@pytest.mark.asyncio
async def test_existing_add_column_is_stale_and_cannot_pass(
    change_type: SchemaChangeType, new_nullable: bool
) -> None:
    class ExistingColumnMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "list_schema_fields":
                self.calls.append((tool, arguments))
                return _response(
                    tool,
                    _schema_page([{"fieldPath": "region", "nativeDataType": "VARCHAR"}]),
                    "schema-existing-addition",
                )
            return await super().call_read(tool, arguments)

    addition = SchemaChange(
        change_type=change_type,
        relation="analytics.stg_orders",
        new_column="region",
        new_type="VARCHAR",
        new_nullable=new_nullable,
    )
    context = await DataHubContextCollector(ExistingColumnMCP(), FakeGraphQL()).collect(addition)
    assessment = RiskEngine.from_policy_file(
        Path(__file__).parents[2] / "config/risk-policy.yaml"
    ).assess([addition], context.impacted_assets, context.evidence_state)

    assert context.evidence_state.catalog is EvidenceStatus.STALE
    assert "catalog.addition_column_exists" in context.reason_codes
    assert assessment.decision is not RiskDecision.PASS
    assert assessment.decision_override is not None


@pytest.mark.parametrize(
    ("change_type", "new_nullable"),
    [
        (SchemaChangeType.ADD_COLUMN, True),
        (SchemaChangeType.ADD_NULLABLE_COLUMN, True),
        (SchemaChangeType.ADD_REQUIRED_COLUMN, False),
    ],
)
@pytest.mark.asyncio
async def test_truncated_add_column_absence_is_not_complete_or_passing(
    change_type: SchemaChangeType, new_nullable: bool
) -> None:
    class TruncatedSchemaMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "list_schema_fields":
                self.calls.append((tool, arguments))
                return _response(
                    tool,
                    {
                        "urn": SOURCE,
                        "fields": [{"fieldPath": f"a_region_{index}"} for index in range(100)],
                        "totalFields": 101,
                        "returned": 100,
                        "remainingCount": 1,
                        "matchingCount": 101,
                        "offset": 0,
                    },
                    "schema-truncated-addition",
                )
            return await super().call_read(tool, arguments)

    addition = SchemaChange(
        change_type=change_type,
        relation="analytics.stg_orders",
        new_column="region",
        new_type="VARCHAR",
        new_nullable=new_nullable,
    )
    context = await DataHubContextCollector(TruncatedSchemaMCP(), FakeGraphQL()).collect(addition)
    assessment = RiskEngine.from_policy_file(
        Path(__file__).parents[2] / "config/risk-policy.yaml"
    ).assess([addition], context.impacted_assets, context.evidence_state)

    assert context.evidence_state.catalog is EvidenceStatus.TRUNCATED
    assert "catalog.schema_truncated" in context.reason_codes
    assert assessment.decision is not RiskDecision.PASS
    assert assessment.decision_override is not None


@pytest.mark.asyncio
async def test_empty_schema_with_null_matching_count_proves_addition_absence() -> None:
    class EmptySchemaMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "list_schema_fields":
                self.calls.append((tool, arguments))
                page = _schema_page([])
                page["matchingCount"] = None
                return _response(tool, page, "schema-empty-null-matching")
            return await super().call_read(tool, arguments)

    addition = SchemaChange(
        change_type=SchemaChangeType.ADD_COLUMN,
        relation="analytics.stg_orders",
        new_column="region",
        new_type="VARCHAR",
        new_nullable=True,
    )
    context = await DataHubContextCollector(EmptySchemaMCP(), FakeGraphQL()).collect(addition)

    assert context.evidence_state.catalog is EvidenceStatus.COMPLETE
    assert "catalog.schema_unavailable" not in context.reason_codes


@pytest.mark.asyncio
async def test_catalog_type_drift_is_explicitly_stale() -> None:
    context = await DataHubContextCollector(FakeMCP(), FakeGraphQL()).collect(
        SchemaChange(
            change_type=SchemaChangeType.RENAME_COLUMN,
            relation="analytics.stg_orders",
            old_column="order_total",
            new_column="gross_amount",
            old_type="INTEGER",
            new_type="INTEGER",
        )
    )
    assert context.evidence_state.catalog is EvidenceStatus.STALE
    assert "catalog.type_fingerprint_stale" in context.reason_codes


@pytest.mark.asyncio
async def test_missing_catalog_type_fingerprint_is_not_complete() -> None:
    class MissingTypeMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "list_schema_fields":
                self.calls.append((tool, arguments))
                return _response(
                    tool,
                    _schema_page([{"fieldPath": "order_total"}]),
                    "schema-missing",
                )
            return await super().call_read(tool, arguments)

    context = await DataHubContextCollector(MissingTypeMCP(), FakeGraphQL()).collect(_change())

    assert context.evidence_state.catalog is EvidenceStatus.MISSING
    assert "catalog.type_fingerprint_missing" in context.reason_codes


@pytest.mark.asyncio
async def test_catalog_type_formatting_whitespace_is_not_drift() -> None:
    class DecimalMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "list_schema_fields":
                self.calls.append((tool, arguments))
                return _response(
                    tool,
                    _schema_page(
                        [
                            {
                                "fieldPath": "order_total",
                                "nativeDataType": "DECIMAL(12,2)",
                            }
                        ]
                    ),
                    "schema-decimal",
                )
            return await super().call_read(tool, arguments)

    context = await DataHubContextCollector(DecimalMCP(), FakeGraphQL()).collect(
        SchemaChange(
            change_type=SchemaChangeType.RENAME_COLUMN,
            relation="analytics.stg_orders",
            old_column="order_total",
            new_column="gross_amount",
            old_type="DECIMAL(12, 2)",
            new_type="DECIMAL(12, 2)",
        )
    )

    assert context.evidence_state.catalog is EvidenceStatus.COMPLETE


@pytest.mark.asyncio
async def test_schema_fields_must_be_bound_to_the_resolved_dataset() -> None:
    other = "urn:li:dataset:(urn:li:dataPlatform:duckdb,analytics.other,PROD)"

    class WrongDatasetSchemaMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "list_schema_fields":
                assert isinstance(response.data, dict)
                response.data["urn"] = other
            return response

    context = await DataHubContextCollector(WrongDatasetSchemaMCP(), FakeGraphQL()).collect(
        _change()
    )

    assert context.source_urn is None
    assert context.evidence_state.catalog is EvidenceStatus.UNAVAILABLE
    assert "catalog.schema_unavailable" in context.reason_codes


@pytest.mark.asyncio
async def test_schema_field_pagination_must_be_self_consistent() -> None:
    class MalformedSchemaPageMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "list_schema_fields":
                assert isinstance(response.data, dict)
                response.data["returned"] = 2
            return response

    context = await DataHubContextCollector(MalformedSchemaPageMCP(), FakeGraphQL()).collect(
        _change()
    )

    assert context.evidence_state.catalog is EvidenceStatus.UNAVAILABLE
    assert "catalog.schema_unavailable" in context.reason_codes


@pytest.mark.asyncio
async def test_truncated_lineage_can_never_report_complete_traversal() -> None:
    context = await DataHubContextCollector(
        FakeMCP(truncated=True), FakeGraphQL(), max_pages=1
    ).collect(_change())
    assert context.evidence_state.lineage is EvidenceStatus.COMPLETE
    assert context.evidence_state.traversal is EvidenceStatus.TRUNCATED
    assert "lineage.truncated" in context.reason_codes


@pytest.mark.asyncio
async def test_missing_authoritative_lineage_total_fails_closed() -> None:
    class MissingTotalMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_lineage":
                del response.data["downstreams"]["total"]
            return response

    context = await DataHubContextCollector(MissingTotalMCP(), FakeGraphQL()).collect(_change())

    assert context.evidence_state.traversal is EvidenceStatus.TRUNCATED
    assert "lineage.truncated" in context.reason_codes


@pytest.mark.asyncio
async def test_zero_result_lineage_still_requires_valid_pagination_metadata() -> None:
    class MalformedEmptyMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "get_lineage":
                self.calls.append((tool, arguments))
                return _response(
                    tool,
                    {
                        "downstreams": {
                            "searchResults": [],
                            "total": 0,
                            "offset": 99,
                            "returned": 0,
                            "hasMore": True,
                        }
                    },
                    "lineage-empty-malformed",
                )
            return await super().call_read(tool, arguments)

    context = await DataHubContextCollector(MalformedEmptyMCP(), FakeGraphQL()).collect(_change())

    assert context.evidence_state.traversal is EvidenceStatus.TRUNCATED
    assert "lineage.truncated" in context.reason_codes


@pytest.mark.asyncio
async def test_graphql_total_overrides_false_mcp_has_more_at_result_cap() -> None:
    class CappedMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool != "get_lineage":
                return response
            assert isinstance(response.data, dict)
            response.data["downstreams"]["total"] = 3
            response.data["downstreams"]["hasMore"] = False
            response.data["downstreams"]["offset"] = 0
            response.data["downstreams"]["returned"] = 2
            return response

    context = await DataHubContextCollector(
        CappedMCP(), FakeGraphQL(), page_size=2, max_pages=1
    ).collect(_change())

    assert context.evidence_state.traversal is EvidenceStatus.TRUNCATED
    assert "lineage.truncated" in context.reason_codes


@pytest.mark.asyncio
async def test_token_budget_pages_complete_within_the_mcp_result_window() -> None:
    class TokenBudgetMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "get_lineage":
                self.calls.append((tool, arguments))
                offset = int((arguments or {}).get("offset", 0))
                all_items = [
                    {"entity": {"urn": MODEL}, "degree": 1},
                    {"entity": {"urn": DASHBOARD}, "degree": 2},
                    {"entity": {"urn": DATA_JOB}, "degree": 1},
                ]
                page = all_items[:2] if offset == 0 else all_items[2:]
                return _response(
                    tool,
                    {
                        "downstreams": {
                            "searchResults": page,
                            "total": 3,
                            "offset": offset,
                            "returned": len(page),
                            "hasMore": offset + len(page) < 3,
                        }
                    },
                    f"lineage-{offset}",
                )
            if tool == "get_entities":
                response = await super().call_read(tool, arguments)
                assert isinstance(response.data, list)
                return _response(
                    tool,
                    [
                        *response.data,
                        {"urn": DATA_JOB, "properties": {"name": "build_revenue"}},
                    ],
                    "entities-token-budget",
                )
            return await super().call_read(tool, arguments)

    context = await DataHubContextCollector(TokenBudgetMCP(), FakeGraphQL()).collect(_change())

    assert context.evidence_state.traversal is EvidenceStatus.COMPLETE
    assert {asset.urn for asset in context.impacted_assets} >= {MODEL, DASHBOARD, DATA_JOB}


@pytest.mark.asyncio
async def test_out_of_range_lineage_degree_fails_traversal_closed() -> None:
    class InvalidDegreeMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_lineage":
                response.data["downstreams"]["searchResults"][0]["degree"] = 999
            return response

    context = await DataHubContextCollector(InvalidDegreeMCP(), FakeGraphQL()).collect(_change())

    assert context.evidence_state.traversal is EvidenceStatus.TRUNCATED


@pytest.mark.asyncio
async def test_invalid_lineage_entity_urn_fails_traversal_closed() -> None:
    class InvalidURNMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_lineage":
                response.data["downstreams"]["searchResults"][0]["entity"]["urn"] = (
                    "not-a-datahub-urn"
                )
            return response

    context = await DataHubContextCollector(InvalidURNMCP(), FakeGraphQL()).collect(_change())

    assert context.evidence_state.traversal is EvidenceStatus.TRUNCATED
    assert "not-a-datahub-urn" not in {asset.urn for asset in context.impacted_assets}


@pytest.mark.asyncio
async def test_assertion_pagination_rejects_duplicate_urns_across_pages() -> None:
    class OverlappingGraphQL(FakeGraphQL):
        def get_dataset_assertions(
            self, dataset_urn: str, *, start: int = 0, count: int = 100
        ) -> AssertionPage:
            del count
            if dataset_urn != SOURCE:
                return super().get_dataset_assertions(dataset_urn, start=start)
            assertion = {"urn": "urn:li:assertion:repeated", "info": {}}
            return AssertionPage(
                assertions=(assertion,),
                total=2,
                start=start,
                count=1,
                digest=f"assertion-overlap-{start}",
            )

    context = await DataHubContextCollector(FakeMCP(), OverlappingGraphQL()).collect(_change())

    assert context.evidence_state.assertions is EvidenceStatus.TRUNCATED
    assert "assertions.pagination_invalid" in context.reason_codes


def test_first_string_field_priority_is_process_deterministic() -> None:
    value = {"name": "fallback", "displayName": "preferred", "title": "last"}

    assert _find_first_string(value, ("displayName", "name", "title")) == "preferred"
