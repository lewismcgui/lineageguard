from __future__ import annotations

from pathlib import Path

from datahub.api.entities.structuredproperties.structuredproperties import (
    StructuredProperties,
)

from lineageguard.run_models import GateDecision, RemediationStatus

ROOT = Path(__file__).resolve().parents[2]


def test_official_datahub_model_validates_all_structured_property_definitions() -> None:
    properties = StructuredProperties.from_yaml(str(ROOT / "config/structured-properties.yaml"))

    assert len(properties) == 8
    assert all(item.generate_mcps()[0].validate() for item in properties)
    assert {item.fqn for item in properties} == {
        "io.lineageguard.runId",
        "io.lineageguard.originalRisk",
        "io.lineageguard.residualRisk",
        "io.lineageguard.decision",
        "io.lineageguard.remediationStatus",
        "io.lineageguard.evidenceHash",
        "io.lineageguard.commitSha",
        "io.lineageguard.writebackState",
    }


def test_allowed_values_cover_every_runtime_decision_and_remediation_state() -> None:
    properties = {
        item.fqn: item
        for item in StructuredProperties.from_yaml(str(ROOT / "config/structured-properties.yaml"))
    }
    decisions = {
        value.value for value in properties["io.lineageguard.decision"].allowed_values or []
    }
    remediations = {
        value.value
        for value in properties["io.lineageguard.remediationStatus"].allowed_values or []
    }

    assert {decision.value for decision in GateDecision} <= decisions
    assert {status.value for status in RemediationStatus} <= remediations
    writeback_states = {
        value.value for value in properties["io.lineageguard.writebackState"].allowed_values or []
    }
    assert writeback_states == {"PENDING", "VERIFIED"}
