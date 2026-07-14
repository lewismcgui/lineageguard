"""Validated loader for LineageGuard's versioned deterministic risk policy."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

NonNegativeInt = Annotated[int, Field(ge=0, strict=True)]
PositiveInt = Annotated[int, Field(gt=0, strict=True)]
BreadthFormula = Literal["round_half_up_log2_one_plus_assets"]


class PolicyModel(BaseModel):
    """Strict immutable base for all risk-policy sections."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ThresholdPolicy(PolicyModel):
    """Inclusive upper bounds for PASS and REVIEW."""

    pass_max: NonNegativeInt
    review_max: PositiveInt


class ChangeSeverityPolicy(PolicyModel):
    """Base points for each normalized schema-change class."""

    drop_column: NonNegativeInt
    incompatible_type: NonNegativeInt
    rename_column: NonNegativeInt
    nullable_to_required: NonNegativeInt
    widening_type: NonNegativeInt
    add_required_column: NonNegativeInt
    add_nullable_column: NonNegativeInt


class SignalPolicy(PolicyModel):
    """Evidence-backed points added to an individual impacted asset."""

    assertion_contract: NonNegativeInt
    critical_asset: NonNegativeInt
    dashboard_or_chart: NonNegativeInt
    data_job_or_flow: NonNegativeInt
    sensitive_data: NonNegativeInt
    direct_column_lineage: NonNegativeInt
    missing_owner: NonNegativeInt
    max_recent_query_usage: NonNegativeInt


class BreadthPolicy(PolicyModel):
    """Logarithmic fan-out bonus applied after the worst per-asset score."""

    multiplier: NonNegativeInt
    maximum: NonNegativeInt
    formula: BreadthFormula = "round_half_up_log2_one_plus_assets"


class RiskPolicy(PolicyModel):
    """Fully validated scoring policy.

    Decision boundaries and score range are fixed by the public scoring
    contract: PASS 0..24, REVIEW 25..59, BLOCK 60..100.
    """

    version: Annotated[str, Field(min_length=1)]
    thresholds: ThresholdPolicy
    change_severity: ChangeSeverityPolicy
    signals: SignalPolicy
    breadth: BreadthPolicy
    hop_penalty: NonNegativeInt
    maximum_score: PositiveInt

    @model_validator(mode="after")
    def validate_public_scoring_contract(self) -> Self:
        """Reject policies that would silently change documented decisions."""

        if self.thresholds.pass_max != 24:
            raise ValueError("thresholds.pass_max must be 24")
        if self.thresholds.review_max != 59:
            raise ValueError("thresholds.review_max must be 59")
        if self.maximum_score != 100:
            raise ValueError("maximum_score must be 100")

        weights = (
            *self.change_severity.model_dump().values(),
            *self.signals.model_dump().values(),
            self.breadth.maximum,
        )
        if any(weight > self.maximum_score for weight in weights):
            raise ValueError("individual policy weights cannot exceed maximum_score")
        return self


class RiskPolicyError(ValueError):
    """Raised when a policy file cannot be read or validated."""


def load_policy(path: str | Path) -> RiskPolicy:
    """Load a YAML policy using ``safe_load`` and validate every field."""

    policy_path = Path(path)
    try:
        raw_text = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RiskPolicyError(f"cannot read risk policy {policy_path}: {exc}") from exc

    try:
        payload = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise RiskPolicyError(f"invalid YAML in risk policy {policy_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RiskPolicyError(f"risk policy {policy_path} must contain a YAML mapping")

    try:
        return RiskPolicy.model_validate(payload)
    except ValidationError as exc:
        raise RiskPolicyError(f"invalid risk policy {policy_path}: {exc}") from exc


__all__ = [
    "BreadthFormula",
    "BreadthPolicy",
    "ChangeSeverityPolicy",
    "RiskPolicy",
    "RiskPolicyError",
    "SignalPolicy",
    "ThresholdPolicy",
    "load_policy",
]
