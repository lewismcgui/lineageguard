"""Deterministic official-SDK metadata seed for the Acme dbt demo."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

from datahub.emitter import mce_builder
from datahub.emitter.generic_emitter import Emitter
from datahub.emitter.mcp import MetadataChangeProposalWrapper
from datahub.emitter.rest_emitter import DataHubRestEmitter, EmitMode
from datahub.metadata.schema_classes import (
    AccessLevelClass,
    AssertionInfoClass,
    AssertionSourceClass,
    AssertionSourceTypeClass,
    AssertionStdAggregationClass,
    AssertionStdOperatorClass,
    AssertionTypeClass,
    AuditStampClass,
    AzkabanJobTypeClass,
    ChangeAuditStampsClass,
    ChartInfoClass,
    ChartTypeClass,
    CorpGroupInfoClass,
    DashboardInfoClass,
    DataFlowInfoClass,
    DataJobInfoClass,
    DataJobInputOutputClass,
    DatasetAssertionInfoClass,
    DatasetAssertionScopeClass,
    DatasetLineageTypeClass,
    DatasetPropertiesClass,
    DateTypeClass,
    FabricTypeClass,
    FineGrainedLineageClass,
    FineGrainedLineageDownstreamTypeClass,
    FineGrainedLineageUpstreamTypeClass,
    GlobalTagsClass,
    NumberTypeClass,
    OtherSchemaClass,
    OwnerClass,
    OwnershipClass,
    OwnershipSourceClass,
    OwnershipSourceTypeClass,
    OwnershipTypeClass,
    SchemaFieldClass,
    SchemaFieldDataTypeClass,
    SchemaMetadataClass,
    StatusClass,
    StringTypeClass,
    SystemMetadataClass,
    TagAssociationClass,
    TagPropertiesClass,
    UpstreamClass,
    UpstreamLineageClass,
)
from datahub.metadata.schema_classes import (
    _Aspect as MetadataAspect,
)

from lineageguard.config import Settings

ENV = FabricTypeClass.PROD
PLATFORM = "duckdb"
PLATFORM_URN = mce_builder.make_data_platform_urn(PLATFORM)
SYSTEM_ACTOR = "urn:li:corpuser:__datahub_system"
DEMO_SEED_TIMESTAMP_MS = 1_783_814_400_000


@dataclass(frozen=True, slots=True)
class DemoUrns:
    """Stable identities shared by the seed plan and offline verification."""

    raw_orders: str
    staging_orders: str
    daily_revenue: str
    dbt_flow: str
    dbt_job: str
    revenue_chart: str
    revenue_dashboard: str
    revenue_assertion: str


DEMO_URNS = DemoUrns(
    # These names match the relations produced by demo/acme_dbt's checked-in profile.
    raw_orders=mce_builder.make_dataset_urn(PLATFORM, "acme_commerce.analytics_raw.orders", ENV),
    staging_orders=mce_builder.make_dataset_urn(
        PLATFORM, "acme_commerce.analytics_staging.stg_orders", ENV
    ),
    daily_revenue=mce_builder.make_dataset_urn(
        PLATFORM, "acme_commerce.analytics_marts.fct_daily_revenue", ENV
    ),
    dbt_flow=mce_builder.make_data_flow_urn("dbt", "acme_commerce", ENV),
    dbt_job=mce_builder.make_data_job_urn("dbt", "acme_commerce", "dbt_build", ENV),
    revenue_chart=mce_builder.make_chart_urn("lineageguard_demo", "daily_gross_revenue"),
    revenue_dashboard=mce_builder.make_dashboard_urn(
        "lineageguard_demo", "executive_revenue_overview"
    ),
    revenue_assertion=mce_builder.make_assertion_urn(
        "lineageguard.acme.fct_daily_revenue.gross_revenue_not_null"
    ),
)

FieldKind = Literal["date", "number", "string"]


@dataclass(frozen=True, slots=True)
class FieldSpec:
    name: str
    native_type: str
    kind: FieldKind
    description: str
    nullable: bool = False
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ColumnLineageSpec:
    upstream_dataset: str
    upstream_fields: tuple[str, ...]
    downstream_field: str
    transform: str


@dataclass(frozen=True, slots=True)
class DatasetSpec:
    urn: str
    qualified_name: str
    display_name: str
    description: str
    logical_layer: str
    owner: str
    tags: tuple[str, ...]
    raw_schema: str
    fields: tuple[FieldSpec, ...]
    upstreams: tuple[str, ...] = ()
    column_lineage: tuple[ColumnLineageSpec, ...] = ()


_ORDER_FIELDS = (
    FieldSpec("order_id", "BIGINT", "number", "Stable synthetic order identifier."),
    FieldSpec("customer_id", "VARCHAR", "string", "Stable synthetic customer identifier."),
    FieldSpec("order_date", "DATE", "date", "UTC order calendar date."),
    FieldSpec("status", "VARCHAR", "string", "Synthetic order lifecycle state."),
    FieldSpec(
        "order_total",
        "DECIMAL(12,2)",
        "number",
        "Contracted order value in the settlement currency.",
        tags=("internal",),
    ),
    FieldSpec("currency", "VARCHAR", "string", "ISO 4217 settlement currency."),
)

_MART_FIELDS = (
    FieldSpec("order_date", "DATE", "date", "UTC revenue reporting date."),
    FieldSpec("currency", "VARCHAR", "string", "ISO 4217 settlement currency."),
    FieldSpec("order_count", "BIGINT", "number", "Completed orders on the reporting date."),
    FieldSpec(
        "gross_revenue",
        "DECIMAL(14,2)",
        "number",
        "Sum of completed-order values.",
        tags=("internal", "business_critical"),
    ),
)

_DATASETS = (
    DatasetSpec(
        urn=DEMO_URNS.raw_orders,
        qualified_name="acme_commerce.analytics_raw.orders",
        display_name="orders",
        description="Synthetic checkout orders used only by the LineageGuard demo.",
        logical_layer="raw",
        owner="commerce_platform",
        tags=("lineageguard_demo", "synthetic_data"),
        raw_schema="""create table acme_commerce.analytics_raw.orders (
  order_id bigint,
  customer_id varchar,
  order_date date,
  status varchar,
  order_total decimal(12,2),
  currency varchar
)""",
        fields=_ORDER_FIELDS,
    ),
    DatasetSpec(
        urn=DEMO_URNS.staging_orders,
        qualified_name="acme_commerce.analytics_staging.stg_orders",
        display_name="stg_orders",
        description="Typed order events forming the stable commerce analytics contract.",
        logical_layer="staging",
        owner="commerce_analytics",
        tags=("lineageguard_demo", "synthetic_data", "business_critical"),
        raw_schema="""create view acme_commerce.analytics_staging.stg_orders as
select order_id, customer_id, order_date, status, order_total, currency
from acme_commerce.analytics_raw.orders""",
        fields=_ORDER_FIELDS,
        upstreams=(DEMO_URNS.raw_orders,),
        column_lineage=tuple(
            ColumnLineageSpec(
                upstream_dataset=DEMO_URNS.raw_orders,
                upstream_fields=(field.name,),
                downstream_field=field.name,
                transform="CAST",
            )
            for field in _ORDER_FIELDS
        ),
    ),
    DatasetSpec(
        urn=DEMO_URNS.daily_revenue,
        qualified_name="acme_commerce.analytics_marts.fct_daily_revenue",
        display_name="fct_daily_revenue",
        description="Daily completed-order revenue for the synthetic finance dashboard.",
        logical_layer="mart",
        owner="finance_analytics",
        tags=("lineageguard_demo", "synthetic_data", "business_critical"),
        raw_schema="""create table acme_commerce.analytics_marts.fct_daily_revenue as
select order_date, currency, count(*) as order_count, sum(order_total) as gross_revenue
from acme_commerce.analytics_staging.stg_orders
where status = 'completed'
group by order_date, currency""",
        fields=_MART_FIELDS,
        upstreams=(DEMO_URNS.staging_orders,),
        column_lineage=(
            ColumnLineageSpec(DEMO_URNS.staging_orders, ("order_date",), "order_date", "GROUP_BY"),
            ColumnLineageSpec(DEMO_URNS.staging_orders, ("currency",), "currency", "GROUP_BY"),
            ColumnLineageSpec(DEMO_URNS.staging_orders, ("order_id",), "order_count", "COUNT"),
            ColumnLineageSpec(DEMO_URNS.staging_orders, ("order_total",), "gross_revenue", "SUM"),
        ),
    ),
)

_TAG_DEFINITIONS = (
    (
        "lineageguard_demo",
        "Synthetic metadata belonging to the local LineageGuard demonstration.",
    ),
    ("synthetic_data", "Contains only generated data safe for the public demo."),
    ("business_critical", "Represents a business-critical demo dependency."),
    ("internal", "Internal-use demo field."),
    ("LineageGuard_PASS", "LineageGuard approved the proposed change."),
    (
        "LineageGuard_PASS_WITH_REMEDIATION",
        "LineageGuard approved the change only with its tested compatibility remediation.",
    ),
    ("LineageGuard_REVIEW", "LineageGuard requires human review before merge."),
    ("LineageGuard_BLOCK", "LineageGuard blocked the proposed change."),
)

_GROUP_DEFINITIONS = (
    (
        "commerce_platform",
        "Commerce Platform",
        "Owns the synthetic raw order feed.",
        "commerce-platform@example.invalid",
    ),
    (
        "commerce_analytics",
        "Commerce Analytics",
        "Owns the synthetic dbt staging contract and build flow.",
        "commerce-analytics@example.invalid",
    ),
    (
        "finance_analytics",
        "Finance Analytics",
        "Owns the synthetic revenue mart and dashboard.",
        "finance-analytics@example.invalid",
    ),
)


def _audit_stamp() -> AuditStampClass:
    # A fixed stamp keeps every emitted aspect byte-for-byte deterministic.
    return AuditStampClass(time=DEMO_SEED_TIMESTAMP_MS, actor=SYSTEM_ACTOR)


def _status() -> StatusClass:
    return StatusClass(removed=False)


def _global_tags(names: Sequence[str]) -> GlobalTagsClass:
    return GlobalTagsClass(
        tags=[TagAssociationClass(tag=mce_builder.make_tag_urn(name)) for name in names]
    )


def _ownership(group_id: str) -> OwnershipClass:
    return OwnershipClass(
        owners=[
            OwnerClass(
                owner=mce_builder.make_group_urn(group_id),
                type=OwnershipTypeClass.DATAOWNER,
                source=OwnershipSourceClass(type=OwnershipSourceTypeClass.SOURCE_CONTROL),
            )
        ],
        lastModified=_audit_stamp(),
    )


def _field_type(kind: FieldKind) -> SchemaFieldDataTypeClass:
    if kind == "date":
        return SchemaFieldDataTypeClass(type=DateTypeClass.from_obj({}))
    if kind == "number":
        return SchemaFieldDataTypeClass(type=NumberTypeClass.from_obj({}))
    return SchemaFieldDataTypeClass(type=StringTypeClass.from_obj({}))


def _schema_field(field: FieldSpec) -> SchemaFieldClass:
    return SchemaFieldClass(
        fieldPath=field.name,
        type=_field_type(field.kind),
        nativeDataType=field.native_type,
        nullable=field.nullable,
        description=field.description,
        globalTags=_global_tags(field.tags) if field.tags else None,
    )


def _dataset_aspects(spec: DatasetSpec) -> tuple[MetadataAspect, ...]:
    fine_lineage = [
        FineGrainedLineageClass(
            upstreamType=FineGrainedLineageUpstreamTypeClass.FIELD_SET,
            downstreamType=FineGrainedLineageDownstreamTypeClass.FIELD,
            upstreams=[
                mce_builder.make_schema_field_urn(lineage.upstream_dataset, field)
                for field in lineage.upstream_fields
            ],
            downstreams=[mce_builder.make_schema_field_urn(spec.urn, lineage.downstream_field)],
            transformOperation=lineage.transform,
            confidenceScore=1.0,
        )
        for lineage in spec.column_lineage
    ]
    return (
        _status(),
        DatasetPropertiesClass(
            name=spec.display_name,
            qualifiedName=spec.qualified_name,
            description=spec.description,
            customProperties={
                "dbt_project": "acme_commerce",
                "logical_layer": spec.logical_layer,
                "synthetic_data": "true",
            },
        ),
        SchemaMetadataClass(
            schemaName=spec.qualified_name,
            platform=PLATFORM_URN,
            version=0,
            hash=sha256(spec.raw_schema.encode("utf-8")).hexdigest(),
            platformSchema=OtherSchemaClass(rawSchema=spec.raw_schema),
            fields=[_schema_field(field) for field in spec.fields],
            created=_audit_stamp(),
            lastModified=_audit_stamp(),
            dataset=spec.urn,
        ),
        UpstreamLineageClass(
            upstreams=[
                UpstreamClass(
                    dataset=urn,
                    type=DatasetLineageTypeClass.TRANSFORMED,
                    auditStamp=_audit_stamp(),
                )
                for urn in spec.upstreams
            ],
            fineGrainedLineages=fine_lineage,
        ),
        _ownership(spec.owner),
        _global_tags(spec.tags),
    )


def _entity_proposals(
    urn: str, aspects: Sequence[MetadataAspect]
) -> list[MetadataChangeProposalWrapper]:
    return [
        MetadataChangeProposalWrapper(
            entityUrn=urn,
            aspect=aspect,
            systemMetadata=SystemMetadataClass(
                lastObserved=DEMO_SEED_TIMESTAMP_MS,
                runId="lineageguard-acme-demo-v1",
                pipelineName="lineageguard-demo-seed",
                properties={},
            ),
        )
        for aspect in aspects
    ]


def build_demo_mcps() -> tuple[MetadataChangeProposalWrapper, ...]:
    """Build the complete deterministic UPSERT plan without contacting DataHub."""

    proposals: list[MetadataChangeProposalWrapper] = []

    for name, description in _TAG_DEFINITIONS:
        proposals.extend(
            _entity_proposals(
                mce_builder.make_tag_urn(name),
                (
                    _status(),
                    TagPropertiesClass(name=name, description=description),
                ),
            )
        )

    for group_id, display_name, description, email in _GROUP_DEFINITIONS:
        proposals.extend(
            _entity_proposals(
                mce_builder.make_group_urn(group_id),
                (
                    _status(),
                    CorpGroupInfoClass(
                        admins=[],
                        members=[],
                        groups=[],
                        displayName=display_name,
                        description=description,
                        email=email,
                        created=_audit_stamp(),
                    ),
                ),
            )
        )

    for dataset in _DATASETS:
        proposals.extend(_entity_proposals(dataset.urn, _dataset_aspects(dataset)))

    proposals.extend(
        _entity_proposals(
            DEMO_URNS.dbt_flow,
            (
                _status(),
                DataFlowInfoClass(
                    name="Acme Commerce dbt project",
                    description="Synthetic dbt flow that builds the Acme analytics models.",
                    project="acme_commerce",
                    env=ENV,
                    customProperties={"synthetic_data": "true"},
                ),
                _ownership("commerce_analytics"),
                _global_tags(("lineageguard_demo", "synthetic_data")),
            ),
        )
    )
    proposals.extend(
        _entity_proposals(
            DEMO_URNS.dbt_job,
            (
                _status(),
                DataJobInfoClass(
                    name="dbt build",
                    type=AzkabanJobTypeClass.COMMAND,
                    description="Builds staging and revenue models and executes dbt tests.",
                    flowUrn=DEMO_URNS.dbt_flow,
                    env=ENV,
                    customProperties={
                        "command": "dbt build",
                        "dbt_project": "acme_commerce",
                        "synthetic_data": "true",
                    },
                ),
                DataJobInputOutputClass(
                    inputDatasets=[DEMO_URNS.staging_orders],
                    outputDatasets=[DEMO_URNS.daily_revenue],
                ),
                _ownership("commerce_analytics"),
                _global_tags(("lineageguard_demo", "synthetic_data")),
            ),
        )
    )

    chart_stamps = ChangeAuditStampsClass(created=_audit_stamp(), lastModified=_audit_stamp())
    proposals.extend(
        _entity_proposals(
            DEMO_URNS.revenue_chart,
            (
                _status(),
                ChartInfoClass(
                    title="Daily Gross Revenue",
                    description="Synthetic completed-order revenue by day.",
                    lastModified=chart_stamps,
                    inputs=[DEMO_URNS.daily_revenue],
                    type=ChartTypeClass.BAR,
                    access=AccessLevelClass.PUBLIC,
                    customProperties={"synthetic_data": "true"},
                ),
                _ownership("finance_analytics"),
                _global_tags(("lineageguard_demo", "synthetic_data", "business_critical")),
            ),
        )
    )
    proposals.extend(
        _entity_proposals(
            DEMO_URNS.revenue_dashboard,
            (
                _status(),
                DashboardInfoClass(
                    title="Executive Revenue Overview",
                    description="Synthetic finance dashboard for the LineageGuard demo.",
                    lastModified=ChangeAuditStampsClass(
                        created=_audit_stamp(), lastModified=_audit_stamp()
                    ),
                    charts=[DEMO_URNS.revenue_chart],
                    datasets=[DEMO_URNS.daily_revenue],
                    access=AccessLevelClass.PUBLIC,
                    customProperties={
                        "business_criticality": "high",
                        "synthetic_data": "true",
                    },
                ),
                _ownership("finance_analytics"),
                _global_tags(("lineageguard_demo", "synthetic_data", "business_critical")),
            ),
        )
    )

    proposals.extend(
        _entity_proposals(
            DEMO_URNS.revenue_assertion,
            (
                _status(),
                AssertionInfoClass(
                    type=AssertionTypeClass.DATASET,
                    description="dbt not_null contract for fct_daily_revenue.gross_revenue.",
                    customProperties={
                        "dbt_project": "acme_commerce",
                        "dbt_test": "not_null",
                        "synthetic_data": "true",
                    },
                    source=AssertionSourceClass(
                        type=AssertionSourceTypeClass.EXTERNAL,
                        created=_audit_stamp(),
                    ),
                    datasetAssertion=DatasetAssertionInfoClass(
                        dataset=DEMO_URNS.daily_revenue,
                        scope=DatasetAssertionScopeClass.DATASET_COLUMN,
                        fields=[
                            mce_builder.make_schema_field_urn(
                                DEMO_URNS.daily_revenue, "gross_revenue"
                            )
                        ],
                        operator=AssertionStdOperatorClass.NOT_NULL,
                        aggregation=AssertionStdAggregationClass.IDENTITY,
                        nativeType="dbt.not_null",
                        nativeParameters={"column_name": "gross_revenue"},
                    ),
                ),
                _global_tags(("lineageguard_demo", "synthetic_data", "business_critical")),
            ),
        )
    )

    return tuple(proposals)


def emit_demo_metadata(emitter: Emitter) -> int:
    """Emit the stable plan through an official DataHub SDK emitter."""

    proposals = build_demo_mcps()
    for proposal in proposals:
        if not proposal.validate():
            raise ValueError(
                f"Invalid DataHub proposal for {proposal.entityType}/{proposal.aspectName}"
            )
        emitter.emit(proposal)
    return len(proposals)


def seed_demo(settings: Settings) -> int:
    """UPSERT the Acme demo into the configured GMS without exposing credentials."""

    if settings.datahub_gms_url.host not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("The synthetic demo seed is restricted to loopback DataHub Core")

    emitter = DataHubRestEmitter(
        gms_server=str(settings.datahub_gms_url).rstrip("/"),
        token=settings.resolve_datahub_token(),
        timeout_sec=settings.mcp_timeout_seconds,
        datahub_component="lineageguard-demo-seed",
        default_emit_mode=EmitMode.SYNC_WAIT,
    )
    try:
        return emit_demo_metadata(emitter)
    finally:
        emitter.close()
