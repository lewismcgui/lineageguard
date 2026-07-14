"""Unit tests for the deterministic LineageGuard risk engine."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from lineageguard.models import (
    AssetType,
    ConfidenceLevel,
    EvidenceKind,
    EvidenceRecord,
    EvidenceState,
    EvidenceStatus,
    ImpactedAsset,
    RiskCategory,
    RiskDecision,
    SchemaChange,
    SchemaChangeType,
)
from lineageguard.risk import RiskEngine, RiskPolicyError, assess_risk, load_policy

POLICY_PATH = Path(__file__).parents[2] / "config" / "risk-policy.yaml"


@pytest.fixture(scope="module")
def policy():  # type: ignore[no-untyped-def]
    return load_policy(POLICY_PATH)


@pytest.fixture(scope="module")
def complete_evidence() -> EvidenceState:
    return EvidenceState.complete()


def change(
    change_type: SchemaChangeType = SchemaChangeType.ADD_REQUIRED_COLUMN,
    *,
    change_id: str = "change-1",
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
) -> SchemaChange:
    common = {
        "id": change_id,
        "change_type": change_type,
        "relation": "urn:li:dataset:(urn:li:dataPlatform:dbt,orders,PROD)",
        "source_path": "models/orders.sql",
        "confidence": confidence,
        "evidence_refs": ("diff:orders",),
    }
    if change_type in {
        SchemaChangeType.ADD_COLUMN,
        SchemaChangeType.ADD_REQUIRED_COLUMN,
        SchemaChangeType.ADD_NULLABLE_COLUMN,
    }:
        return SchemaChange(
            **common,
            new_column="customer_tier",
            new_nullable=change_type is SchemaChangeType.ADD_NULLABLE_COLUMN,
        )
    if change_type is SchemaChangeType.DROP_COLUMN:
        return SchemaChange(**common, old_column="customer_id")
    if change_type is SchemaChangeType.RENAME_COLUMN:
        return SchemaChange(**common, old_column="customer_id", new_column="buyer_id")
    if change_type in {
        SchemaChangeType.TYPE_CHANGE,
        SchemaChangeType.INCOMPATIBLE_TYPE,
        SchemaChangeType.WIDENING_TYPE,
    }:
        return SchemaChange(**common, old_type="integer", new_type="varchar")
    if change_type in {
        SchemaChangeType.NULLABILITY_CHANGE,
        SchemaChangeType.NULLABLE_TO_REQUIRED,
    }:
        return SchemaChange(**common, old_nullable=True, new_nullable=False)
    raise AssertionError(f"unsupported test change: {change_type}")


def asset(
    suffix: str = "one",
    *,
    asset_type: AssetType = AssetType.DATASET,
    hop_count: int = 1,
    owners: tuple[str, ...] | None = ("urn:li:corpuser:owner",),
    assertion_urns: tuple[str, ...] | None = (),
    critical_asset: bool | None = False,
    sensitive_data: bool | None = False,
    direct_column_lineage: bool | None = False,
    recent_query_usage_score: int | None = 0,
    evidence: tuple[EvidenceRecord, ...] = (),
) -> ImpactedAsset:
    return ImpactedAsset(
        urn=f"urn:li:dataset:(urn:li:dataPlatform:dbt,{suffix},PROD)",
        asset_type=asset_type,
        hop_count=hop_count,
        owners=owners,
        assertion_urns=assertion_urns,
        critical_asset=critical_asset,
        sensitive_data=sensitive_data,
        direct_column_lineage=direct_column_lineage,
        recent_query_usage_score=recent_query_usage_score,
        evidence_refs=(f"mcp:{suffix}",),
        evidence=evidence,
    )


def score(
    changes: Sequence[SchemaChange],
    assets: Sequence[ImpactedAsset],
    evidence_state: EvidenceState,
    policy,  # type: ignore[no-untyped-def]
):  # type: ignore[no-untyped-def]
    return assess_risk(changes, assets, evidence_state, policy)


def test_policy_file_loads_and_exposes_fixed_formula(policy) -> None:  # type: ignore[no-untyped-def]
    assert policy.version == "1.0.0"
    assert policy.thresholds.pass_max == 24
    assert policy.thresholds.review_max == 59
    assert policy.maximum_score == 100
    assert policy.breadth.formula == "round_half_up_log2_one_plus_assets"


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ("pass_max: 24", "pass_max"),
        ("review_max: 59", "review_max"),
        ("maximum_score: 100", "maximum_score"),
        (
            "formula: round_half_up_log2_one_plus_assets",
            "formula",
        ),
    ],
)
def test_policy_rejects_changed_public_contract(
    tmp_path: Path,
    replacement: str,
    message: str,
) -> None:
    text = POLICY_PATH.read_text(encoding="utf-8")
    invalid_values = {
        "pass_max: 24": "pass_max: 23",
        "review_max: 59": "review_max: 60",
        "maximum_score: 100": "maximum_score: 99",
        "formula: round_half_up_log2_one_plus_assets": "formula: linear",
    }
    path = tmp_path / "risk-policy.yaml"
    path.write_text(text.replace(replacement, invalid_values[replacement]), encoding="utf-8")

    with pytest.raises(RiskPolicyError, match=message):
        load_policy(path)


def test_policy_rejects_unknown_fields_and_non_mapping(tmp_path: Path) -> None:
    text = POLICY_PATH.read_text(encoding="utf-8")
    unknown = tmp_path / "unknown.yaml"
    unknown.write_text(f"{text}\nunknown: true\n", encoding="utf-8")
    with pytest.raises(RiskPolicyError, match="Extra inputs are not permitted"):
        load_policy(unknown)

    not_mapping = tmp_path / "list.yaml"
    not_mapping.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    with pytest.raises(RiskPolicyError, match="must contain a YAML mapping"):
        load_policy(not_mapping)


def test_policy_rejects_boolean_disguised_as_integer(tmp_path: Path) -> None:
    text = POLICY_PATH.read_text(encoding="utf-8")
    path = tmp_path / "boolean-weight.yaml"
    path.write_text(text.replace("hop_penalty: 4", "hop_penalty: true"), encoding="utf-8")

    with pytest.raises(RiskPolicyError, match="hop_penalty"):
        load_policy(path)


@pytest.mark.parametrize(
    ("usage_points", "expected_score", "expected_decision"),
    [
        (9, 24, RiskDecision.PASS),
        (10, 25, RiskDecision.REVIEW),
    ],
)
def test_pass_review_boundary_is_inclusive(
    policy,
    complete_evidence: EvidenceState,
    usage_points: int,
    expected_score: int,
    expected_decision: RiskDecision,
) -> None:
    result = score(
        [change()],
        [asset(recent_query_usage_score=usage_points)],
        complete_evidence,
        policy,
    )

    assert result.score == expected_score
    assert result.score_decision is expected_decision
    assert result.decision is expected_decision


@pytest.mark.parametrize(
    ("usage_points", "expected_score", "expected_decision"),
    [
        (1, 59, RiskDecision.REVIEW),
        (2, 60, RiskDecision.BLOCK),
    ],
)
def test_review_block_boundary_is_inclusive(
    policy,
    complete_evidence: EvidenceState,
    usage_points: int,
    expected_score: int,
    expected_decision: RiskDecision,
) -> None:
    result = score(
        [change(SchemaChangeType.NULLABLE_TO_REQUIRED)],
        [
            asset(
                assertion_urns=("urn:li:assertion:orders_not_null",),
                recent_query_usage_score=usage_points,
            )
        ],
        complete_evidence,
        policy,
    )

    assert result.score == expected_score
    assert result.score_decision is expected_decision
    assert result.decision is expected_decision


@pytest.mark.parametrize(
    ("asset_count", "expected_breadth"),
    [(0, 0), (1, 3), (2, 5), (3, 6), (7, 9), (31, 15), (1_023, 15)],
)
def test_logarithmic_breadth_rounds_half_up_and_caps(
    policy,
    complete_evidence: EvidenceState,
    asset_count: int,
    expected_breadth: int,
) -> None:
    assets = [asset(str(index)) for index in range(asset_count)]
    result = score(
        [change(SchemaChangeType.ADD_NULLABLE_COLUMN)],
        assets,
        complete_evidence,
        policy,
    )
    breadth = next(item for item in result.contributions if item.category is RiskCategory.BREADTH)

    assert breadth.points == expected_breadth
    assert result.score == 2 + expected_breadth


def test_hop_penalty_starts_after_direct_hop(
    policy,
    complete_evidence: EvidenceState,
) -> None:
    direct = score(
        [change(SchemaChangeType.DROP_COLUMN)],
        [asset(hop_count=1)],
        complete_evidence,
        policy,
    )
    distant = score(
        [change(SchemaChangeType.DROP_COLUMN)],
        [asset(hop_count=3)],
        complete_evidence,
        policy,
    )

    assert direct.asset_risks[0].score == 45
    assert distant.asset_risks[0].score == 37
    assert distant.score == direct.score - 8
    penalty = next(
        item
        for item in distant.asset_risks[0].contributions
        if item.category is RiskCategory.HOP_PENALTY
    )
    assert penalty.points == -8


def test_asset_score_is_clamped_before_breadth(
    policy,
    complete_evidence: EvidenceState,
) -> None:
    result = score(
        [change(SchemaChangeType.ADD_NULLABLE_COLUMN)],
        [asset(hop_count=3)],
        complete_evidence,
        policy,
    )

    assert result.asset_risks[0].score == 0
    assert sum(item.points for item in result.asset_risks[0].contributions) == 0
    assert result.score == 3
    assert sum(item.points for item in result.contributions) == 3
    assert any(item.category is RiskCategory.CLAMP for item in result.asset_risks[0].contributions)


def test_explicit_missing_owner_adds_signal_but_unknown_owner_does_not(
    policy,
    complete_evidence: EvidenceState,
) -> None:
    known_missing = score(
        [change(SchemaChangeType.ADD_NULLABLE_COLUMN)],
        [asset(owners=())],
        complete_evidence,
        policy,
    )
    unknown = score(
        [change(SchemaChangeType.ADD_NULLABLE_COLUMN)],
        [asset(owners=None)],
        complete_evidence,
        policy,
    )

    missing_owner = [
        item for item in known_missing.asset_risks[0].contributions if item.key == "missing_owner"
    ]
    unknown_missing_owner = [
        item for item in unknown.asset_risks[0].contributions if item.key == "missing_owner"
    ]
    assert [item.points for item in missing_owner] == [5]
    assert unknown_missing_owner == []
    assert known_missing.score == unknown.score + 5
    assert unknown.decision_override is not None
    assert any("ownership_missing" in reason for reason in unknown.decision_override.reason_codes)


def test_assertion_contract_adds_exact_policy_signal(
    policy,
    complete_evidence: EvidenceState,
) -> None:
    without = score(
        [change(SchemaChangeType.ADD_NULLABLE_COLUMN)],
        [asset(assertion_urns=())],
        complete_evidence,
        policy,
    )
    with_assertion = score(
        [change(SchemaChangeType.ADD_NULLABLE_COLUMN)],
        [asset(assertion_urns=("urn:li:assertion:orders_pk",))],
        complete_evidence,
        policy,
    )

    contribution = next(
        item
        for item in with_assertion.asset_risks[0].contributions
        if item.key == "assertion_contract"
    )
    assert contribution.points == 25
    assert with_assertion.score == without.score + 25


def test_only_highest_risk_asset_is_used_then_breadth_is_added(
    policy,
    complete_evidence: EvidenceState,
) -> None:
    result = score(
        [change(SchemaChangeType.ADD_NULLABLE_COLUMN)],
        [
            asset("plain"),
            asset("dashboard", asset_type=AssetType.DASHBOARD),
            asset("job", asset_type=AssetType.DATA_JOB),
        ],
        complete_evidence,
        policy,
    )

    per_asset = {item.asset_urn: item.score for item in result.asset_risks}
    assert per_asset[asset("plain").urn] == 2
    assert per_asset[asset("dashboard").urn] == 17
    assert per_asset[asset("job").urn] == 14
    assert result.score_basis_asset_urn == asset("dashboard").urn
    assert result.score == 17 + 6


def test_score_clamps_to_100_and_breakdown_reconciles(
    policy,
    complete_evidence: EvidenceState,
) -> None:
    result = score(
        [change(SchemaChangeType.DROP_COLUMN)],
        [
            asset(
                asset_type=AssetType.DASHBOARD,
                owners=(),
                assertion_urns=("urn:li:assertion:contract",),
                critical_asset=True,
                sensitive_data=True,
                direct_column_lineage=True,
                recent_query_usage_score=100,
            )
        ],
        complete_evidence,
        policy,
    )

    assert result.asset_risks[0].score == 100
    assert sum(item.points for item in result.asset_risks[0].contributions) == 100
    assert result.score == 100
    assert sum(item.points for item in result.contributions) == 100
    assert any(item.category is RiskCategory.CLAMP for item in result.contributions)
    assert result.decision is RiskDecision.BLOCK


@pytest.mark.parametrize(
    "status",
    [
        EvidenceStatus.MISSING,
        EvidenceStatus.AMBIGUOUS,
        EvidenceStatus.TRUNCATED,
        EvidenceStatus.STALE,
    ],
)
@pytest.mark.parametrize("field", ["catalog", "lineage", "traversal", "ownership", "assertions"])
def test_incomplete_critical_coverage_explicitly_prevents_pass(
    policy,
    status: EvidenceStatus,
    field: str,
) -> None:
    payload = EvidenceState.complete().model_dump()
    payload[field] = status
    evidence_state = EvidenceState.model_validate(payload)
    result = score(
        [change(SchemaChangeType.ADD_NULLABLE_COLUMN)],
        [],
        evidence_state,
        policy,
    )

    assert result.score == 2
    assert result.score_decision is RiskDecision.PASS
    assert result.decision is RiskDecision.REVIEW
    assert result.decision_override is not None
    assert result.decision_override.reason_codes == (f"critical_evidence.{field}.{status.value}",)


@pytest.mark.parametrize(
    "status",
    [
        EvidenceStatus.MISSING,
        EvidenceStatus.AMBIGUOUS,
        EvidenceStatus.TRUNCATED,
        EvidenceStatus.STALE,
    ],
)
def test_incomplete_critical_record_prevents_pass(
    policy,
    status: EvidenceStatus,
) -> None:
    record = EvidenceRecord(
        id="mcp:lineage-page-1",
        kind=EvidenceKind.LINEAGE,
        status=status,
        source="datahub-mcp",
        critical=True,
    )
    result = score(
        [change(SchemaChangeType.ADD_NULLABLE_COLUMN)],
        [],
        EvidenceState.complete(records=(record,)),
        policy,
    )

    assert result.score_decision is RiskDecision.PASS
    assert result.decision is RiskDecision.REVIEW
    assert result.decision_override is not None
    assert result.decision_override.reason_codes == (f"critical_record.{record.id}.{status.value}",)


def test_low_confidence_change_prevents_pass(
    policy,
    complete_evidence: EvidenceState,
) -> None:
    low_confidence = change(
        SchemaChangeType.ADD_NULLABLE_COLUMN,
        confidence=ConfidenceLevel.LOW,
    )
    result = score([low_confidence], [], complete_evidence, policy)

    assert result.score_decision is RiskDecision.PASS
    assert result.decision is RiskDecision.REVIEW
    assert result.decision_override is not None
    assert result.decision_override.reason_codes == (
        f"schema_change.{low_confidence.id}.low_confidence",
    )


@pytest.mark.parametrize(
    ("ambiguous_change", "reason_suffix"),
    [
        (
            SchemaChange(
                id="unknown-requiredness",
                change_type=SchemaChangeType.ADD_COLUMN,
                relation="analytics.orders",
                new_column="region",
            ),
            "requiredness_missing",
        ),
        (
            SchemaChange(
                id="unknown-compatibility",
                change_type=SchemaChangeType.TYPE_CHANGE,
                relation="analytics.orders",
                old_type="integer",
                new_type="varchar",
            ),
            "type_compatibility_ambiguous",
        ),
    ],
)
def test_ambiguous_change_classification_has_explicit_override(
    policy,
    complete_evidence: EvidenceState,
    ambiguous_change: SchemaChange,
    reason_suffix: str,
) -> None:
    result = score([ambiguous_change], [], complete_evidence, policy)

    assert result.decision is not RiskDecision.PASS
    assert result.decision_override is not None
    assert result.decision_override.reason_codes == (
        f"schema_change.{ambiguous_change.id}.{reason_suffix}",
    )


def test_default_evidence_state_is_fail_closed(policy) -> None:  # type: ignore[no-untyped-def]
    result = score(
        [change(SchemaChangeType.ADD_NULLABLE_COLUMN)],
        [],
        EvidenceState(),
        policy,
    )

    assert result.score_decision is RiskDecision.PASS
    assert result.decision is RiskDecision.REVIEW
    assert result.decision_override is not None
    assert len(result.decision_override.reason_codes) == 5


def test_high_numeric_risk_is_not_lowered_by_confidence_override(
    policy,
) -> None:  # type: ignore[no-untyped-def]
    result = score(
        [change(SchemaChangeType.DROP_COLUMN)],
        [
            asset(
                assertion_urns=("urn:li:assertion:contract",),
                critical_asset=True,
            )
        ],
        EvidenceState(),
        policy,
    )

    assert result.score_decision is RiskDecision.BLOCK
    assert result.decision is RiskDecision.BLOCK
    assert result.decision_override is not None


def test_deterministic_result_is_independent_of_input_and_evidence_order(
    policy,
) -> None:  # type: ignore[no-untyped-def]
    record_a = EvidenceRecord(
        id="evidence:a",
        kind=EvidenceKind.LINEAGE,
        status=EvidenceStatus.COMPLETE,
    )
    record_b = EvidenceRecord(
        id="evidence:b",
        kind=EvidenceKind.OWNERSHIP,
        status=EvidenceStatus.COMPLETE,
    )
    first_assets = [
        asset("z", owners=("owner:z", "owner:a"), evidence=(record_b, record_a)),
        asset("a", evidence=(record_a, record_b)),
    ]
    second_assets = [
        asset("a", evidence=(record_b, record_a)),
        asset("z", owners=("owner:a", "owner:z"), evidence=(record_a, record_b)),
    ]
    changes = [
        change(SchemaChangeType.ADD_NULLABLE_COLUMN, change_id="change-z"),
        change(SchemaChangeType.WIDENING_TYPE, change_id="change-a"),
    ]

    first = score(changes, first_assets, EvidenceState.complete(), policy)
    second = score(list(reversed(changes)), second_assets, EvidenceState.complete(), policy)

    assert first.model_dump_json() == second.model_dump_json()
    assert first.change_ids == ("change-a", "change-z")
    assert first.impacted_asset_urns == tuple(sorted(first.impacted_asset_urns))


def test_no_signal_or_evidence_reference_is_invented(
    policy,
    complete_evidence: EvidenceState,
) -> None:
    unknown = ImpactedAsset(
        urn="urn:li:dataset:(urn:li:dataPlatform:dbt,unknown,PROD)",
        asset_type=AssetType.DATASET,
        hop_count=1,
    )
    result = score(
        [change(SchemaChangeType.ADD_NULLABLE_COLUMN)],
        [unknown],
        complete_evidence,
        policy,
    )

    signal_contributions = [
        item for item in result.asset_risks[0].contributions if item.category is RiskCategory.SIGNAL
    ]
    assert signal_contributions == []
    assert all(
        set(item.evidence_refs) <= {"diff:orders"} for item in result.asset_risks[0].contributions
    )
    assert result.decision is RiskDecision.REVIEW


def test_schema_change_aliases_stable_id_and_conservative_classification() -> None:
    first = SchemaChange(
        change_type="add",
        dataset="analytics.orders",
        new_column="region",
        source_path="models\\orders.sql",
    )
    second = SchemaChange(
        change_type=SchemaChangeType.ADD_COLUMN,
        relation="analytics.orders",
        new_column="region",
        source_path="models/orders.sql",
    )
    unknown_type = SchemaChange(
        change_type="type",
        relation="analytics.orders",
        old_type="integer",
        new_type="custom_type",
    )

    assert first.id == second.id
    assert first.source_path == "models/orders.sql"
    assert first.severity_key == "add_required_column"
    assert unknown_type.severity_key == "incompatible_type"


def test_duplicate_change_ids_and_asset_urns_are_rejected(
    policy,
    complete_evidence: EvidenceState,
) -> None:
    with pytest.raises(ValueError, match="duplicate schema change id"):
        score([change(), change()], [], complete_evidence, policy)

    with pytest.raises(ValueError, match="duplicate impacted asset urn"):
        score([change()], [asset(), asset()], complete_evidence, policy)


def test_risk_engine_facade_uses_loaded_policy(
    complete_evidence: EvidenceState,
) -> None:
    engine = RiskEngine.from_policy_file(POLICY_PATH)
    result = engine.assess(
        [change(SchemaChangeType.ADD_NULLABLE_COLUMN)],
        [],
        complete_evidence,
    )

    assert result.policy_version == "1.0.0"
    assert result.score == 2
    assert result.decision is RiskDecision.PASS
