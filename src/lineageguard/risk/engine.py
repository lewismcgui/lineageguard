"""Deterministic, auditable risk scoring for proposed schema changes."""

from __future__ import annotations

import math
from collections.abc import Sequence
from decimal import ROUND_HALF_UP, Decimal
from itertools import pairwise
from pathlib import Path

from lineageguard.models import (
    AssetRisk,
    AssetType,
    ConfidenceLevel,
    DecisionOverride,
    EvidenceRecord,
    EvidenceState,
    ImpactedAsset,
    RiskAssessment,
    RiskCategory,
    RiskContribution,
    RiskDecision,
    SchemaChange,
    SchemaChangeType,
)
from lineageguard.risk.policy import RiskPolicy, load_policy

_DECISION_RANK = {
    RiskDecision.PASS: 0,
    RiskDecision.REVIEW: 1,
    RiskDecision.BLOCK: 2,
}


def _clamp(value: int, *, maximum: int) -> int:
    return max(0, min(value, maximum))


def _round_half_up(value: float) -> int:
    """Round a non-negative finite value to an integer without banker's ties."""

    return int(Decimal(str(value)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _decision_for_score(score: int, policy: RiskPolicy) -> RiskDecision:
    if score <= policy.thresholds.pass_max:
        return RiskDecision.PASS
    if score <= policy.thresholds.review_max:
        return RiskDecision.REVIEW
    return RiskDecision.BLOCK


def _maximum_decision(left: RiskDecision, right: RiskDecision) -> RiskDecision:
    return left if _DECISION_RANK[left] >= _DECISION_RANK[right] else right


def _validate_unique_changes(changes: Sequence[SchemaChange]) -> tuple[SchemaChange, ...]:
    if not changes:
        raise ValueError("risk assessment requires at least one schema change")
    ordered = tuple(sorted(changes, key=lambda change: change.id))
    for previous, current in pairwise(ordered):
        if previous.id == current.id:
            raise ValueError(f"duplicate schema change id: {current.id}")
    return ordered


def _validate_unique_assets(assets: Sequence[ImpactedAsset]) -> tuple[ImpactedAsset, ...]:
    ordered = tuple(sorted(assets, key=lambda asset: asset.urn))
    for previous, current in pairwise(ordered):
        if previous.urn == current.urn:
            raise ValueError(f"duplicate impacted asset urn: {current.urn}")
    return ordered


def _severity_points(change: SchemaChange, policy: RiskPolicy) -> int:
    return int(getattr(policy.change_severity, change.severity_key))


def _worst_change(
    changes: tuple[SchemaChange, ...], policy: RiskPolicy
) -> tuple[SchemaChange, int]:
    ranked = sorted(
        ((_severity_points(change, policy), change.id, change) for change in changes),
        key=lambda item: (-item[0], item[1]),
    )
    points, _, change = ranked[0]
    return change, points


def _severity_contribution(
    change: SchemaChange,
    points: int,
    *,
    asset_urn: str | None,
) -> RiskContribution:
    return RiskContribution(
        category=RiskCategory.SEVERITY,
        key=change.severity_key,
        points=points,
        asset_urn=asset_urn,
        change_id=change.id,
        evidence_refs=change.all_evidence_refs,
        explanation=f"Worst applicable schema change: {change.severity_key}.",
    )


def _signal_contributions(
    asset: ImpactedAsset,
    policy: RiskPolicy,
) -> tuple[RiskContribution, ...]:
    """Return source-backed signals in a fixed, documented order."""

    refs = asset.all_evidence_refs
    signals: list[tuple[str, int, bool, str]] = [
        (
            "assertion_contract",
            policy.signals.assertion_contract,
            bool(asset.assertion_urns),
            "Asset has an assertion or contract dependency.",
        ),
        (
            "critical_asset",
            policy.signals.critical_asset,
            asset.critical_asset is True,
            "Asset is explicitly marked critical.",
        ),
        (
            "dashboard_or_chart",
            policy.signals.dashboard_or_chart,
            asset.asset_type in {AssetType.DASHBOARD, AssetType.CHART},
            "Impacted asset is a dashboard or chart.",
        ),
        (
            "data_job_or_flow",
            policy.signals.data_job_or_flow,
            asset.asset_type in {AssetType.DATA_JOB, AssetType.DATA_FLOW},
            "Impacted asset is a data job or flow.",
        ),
        (
            "sensitive_data",
            policy.signals.sensitive_data,
            asset.sensitive_data is True,
            "Asset is explicitly marked as containing sensitive data.",
        ),
        (
            "direct_column_lineage",
            policy.signals.direct_column_lineage,
            asset.direct_column_lineage is True,
            "Direct column-level lineage connects the change to this asset.",
        ),
        (
            "missing_owner",
            policy.signals.missing_owner,
            asset.owners == (),
            "Ownership enrichment explicitly reported no owners.",
        ),
    ]

    contributions = [
        RiskContribution(
            category=RiskCategory.SIGNAL,
            key=key,
            points=int(points),
            asset_urn=asset.urn,
            evidence_refs=refs,
            explanation=explanation,
        )
        for key, points, applies, explanation in signals
        if applies and points
    ]

    if asset.recent_query_usage_score:
        points = min(asset.recent_query_usage_score, policy.signals.max_recent_query_usage)
        if points:
            contributions.append(
                RiskContribution(
                    category=RiskCategory.SIGNAL,
                    key="recent_query_usage",
                    points=points,
                    asset_urn=asset.urn,
                    evidence_refs=refs,
                    explanation="Evidence-derived recent query usage points, policy-capped.",
                )
            )
    return tuple(contributions)


def _asset_risk(
    asset: ImpactedAsset,
    *,
    worst_change: SchemaChange,
    severity_points: int,
    policy: RiskPolicy,
) -> AssetRisk:
    contributions: list[RiskContribution] = [
        _severity_contribution(worst_change, severity_points, asset_urn=asset.urn)
    ]
    contributions.extend(_signal_contributions(asset, policy))

    penalty = policy.hop_penalty * max(0, asset.hop_count - 1)
    if penalty:
        contributions.append(
            RiskContribution(
                category=RiskCategory.HOP_PENALTY,
                key="downstream_hops",
                points=-penalty,
                asset_urn=asset.urn,
                evidence_refs=asset.all_evidence_refs,
                explanation=(f"Hop penalty: {policy.hop_penalty} x ({asset.hop_count} - 1)."),
            )
        )

    raw_score = sum(item.points for item in contributions)
    score = _clamp(raw_score, maximum=policy.maximum_score)
    if score != raw_score:
        contributions.append(
            RiskContribution(
                category=RiskCategory.CLAMP,
                key="asset_score_range",
                points=score - raw_score,
                asset_urn=asset.urn,
                explanation=f"Clamp asset score to 0..{policy.maximum_score}.",
            )
        )

    return AssetRisk(
        asset_urn=asset.urn,
        hop_count=asset.hop_count,
        score=score,
        contributions=tuple(contributions),
    )


def _breadth_points(asset_count: int, policy: RiskPolicy) -> int:
    """Apply round-half-up(multiplier * log2(1 + unique assets)), then cap."""

    unbounded = _round_half_up(policy.breadth.multiplier * math.log2(1 + asset_count))
    return min(unbounded, policy.breadth.maximum)


def _critical_records(
    changes: tuple[SchemaChange, ...],
    assets: tuple[ImpactedAsset, ...],
    state: EvidenceState,
) -> tuple[EvidenceRecord, ...]:
    records = [*state.records]
    records.extend(record for change in changes for record in change.evidence)
    records.extend(record for asset in assets for record in asset.evidence)
    return tuple(sorted(records, key=lambda record: (record.id, record.kind.value)))


def _override_reasons(
    changes: tuple[SchemaChange, ...],
    assets: tuple[ImpactedAsset, ...],
    evidence_state: EvidenceState,
) -> tuple[str, ...]:
    reasons = {
        f"critical_evidence.{name}.{status.value}"
        for name, status in evidence_state.incomplete_critical_evidence
    }
    reasons.update(
        f"critical_record.{record.id}.{record.status.value}"
        for record in _critical_records(changes, assets, evidence_state)
        if record.critical and not record.status.is_complete
    )
    reasons.update(
        f"schema_change.{change.id}.low_confidence"
        for change in changes
        if change.confidence is ConfidenceLevel.LOW
    )
    reasons.update(
        f"schema_change.{change.id}.requiredness_missing"
        for change in changes
        if change.change_type is SchemaChangeType.ADD_COLUMN and change.new_nullable is None
    )
    reasons.update(
        f"schema_change.{change.id}.type_compatibility_ambiguous"
        for change in changes
        if change.change_type is SchemaChangeType.TYPE_CHANGE
    )
    reasons.update(
        f"impacted_asset.{asset.urn}.ownership_missing"
        for asset in assets
        if evidence_state.ownership.is_complete and asset.owners is None
    )
    reasons.update(
        f"impacted_asset.{asset.urn}.assertion_evidence_missing"
        for asset in assets
        if evidence_state.assertions.is_complete and asset.assertion_urns is None
    )
    return tuple(sorted(reasons))


def assess_risk(
    changes: Sequence[SchemaChange],
    impacted_assets: Sequence[ImpactedAsset],
    evidence_state: EvidenceState,
    policy: RiskPolicy,
) -> RiskAssessment:
    """Compute a risk decision with no I/O, inference, or order dependence.

    Formula::

        per asset = clamp(worst change severity + asset signals
                    - hop_penalty * max(0, hop_count - 1), 0, maximum_score)
        breadth   = min(maximum, round_half_up(multiplier * log2(1 + asset_count)))
        score     = clamp(max(per-asset score) + breadth, 0, maximum_score)

    When there are no impacted assets, the worst change severity is the score
    base.  Any incomplete critical evidence creates an explicit REVIEW minimum;
    it never modifies the numeric score or hides the threshold-only decision.
    """

    ordered_changes = _validate_unique_changes(changes)
    ordered_assets = _validate_unique_assets(impacted_assets)
    worst_change, severity_points = _worst_change(ordered_changes, policy)

    asset_risks = tuple(
        _asset_risk(
            asset,
            worst_change=worst_change,
            severity_points=severity_points,
            policy=policy,
        )
        for asset in ordered_assets
    )

    if asset_risks:
        basis = sorted(asset_risks, key=lambda risk: (-risk.score, risk.asset_urn))[0]
        score_basis_asset_urn: str | None = basis.asset_urn
        score_base = basis.score
        contributions = list(basis.contributions)
    else:
        score_basis_asset_urn = None
        score_base = severity_points
        contributions = [_severity_contribution(worst_change, severity_points, asset_urn=None)]

    breadth_points = _breadth_points(len(ordered_assets), policy)
    contributions.append(
        RiskContribution(
            category=RiskCategory.BREADTH,
            key=policy.breadth.formula,
            points=breadth_points,
            explanation=(
                "Breadth bonus: round-half-up("
                f"{policy.breadth.multiplier} * log2(1 + {len(ordered_assets)})), "
                f"capped at {policy.breadth.maximum}."
            ),
        )
    )

    raw_score = score_base + breadth_points
    score = _clamp(raw_score, maximum=policy.maximum_score)
    if score != raw_score:
        contributions.append(
            RiskContribution(
                category=RiskCategory.CLAMP,
                key="overall_score_range",
                points=score - raw_score,
                explanation=f"Clamp overall score to 0..{policy.maximum_score}.",
            )
        )

    score_decision = _decision_for_score(score, policy)
    override_reasons = _override_reasons(ordered_changes, ordered_assets, evidence_state)
    decision_override = (
        DecisionOverride(reason_codes=override_reasons) if override_reasons else None
    )
    decision = score_decision
    if decision_override is not None:
        decision = _maximum_decision(decision, decision_override.minimum_decision)

    return RiskAssessment(
        policy_version=policy.version,
        score=score,
        score_decision=score_decision,
        decision=decision,
        score_basis_asset_urn=score_basis_asset_urn,
        asset_risks=asset_risks,
        contributions=tuple(contributions),
        evidence_state=evidence_state,
        decision_override=decision_override,
        change_ids=tuple(change.id for change in ordered_changes),
        impacted_asset_urns=tuple(asset.urn for asset in ordered_assets),
    )


class RiskEngine:
    """Small policy-bound facade for application-layer callers."""

    def __init__(self, policy: RiskPolicy) -> None:
        self.policy = policy

    @classmethod
    def from_policy_file(cls, path: str | Path) -> RiskEngine:
        return cls(load_policy(path))

    def assess(
        self,
        changes: Sequence[SchemaChange],
        impacted_assets: Sequence[ImpactedAsset],
        evidence_state: EvidenceState,
    ) -> RiskAssessment:
        return assess_risk(changes, impacted_assets, evidence_state, self.policy)


# Readable alias for callers that treat the engine as a pure scoring function.
score_risk = assess_risk


__all__ = ["RiskEngine", "assess_risk", "score_risk"]
