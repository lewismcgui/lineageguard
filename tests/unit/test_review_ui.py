"""Route, safety, and static-contract tests for the local review UI."""

from __future__ import annotations

import importlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lineageguard.review_ui import create_app
from lineageguard.run_models import RunResult, calculate_artifact_hash, run_result_payload

review_app = importlib.import_module("lineageguard.review_ui.app")


@pytest.fixture
def artifact_path(tmp_path: Path) -> Path:
    return tmp_path / ".lineageguard" / "runs" / "latest.json"


def _client(path: Path) -> TestClient:
    return TestClient(create_app(path))


def _sealed_payload() -> dict[str, object]:
    complete_state = {
        "catalog": "complete",
        "lineage": "complete",
        "traversal": "complete",
        "ownership": "complete",
        "assertions": "complete",
        "records": [],
    }
    result = RunResult.model_validate(
        {
            "schema_version": "1.0",
            "run_id": "lg-local-run",
            "created_at": "2026-07-12T09:00:00Z",
            "status": "COMPLETE",
            "final_decision": "PASS",
            "inputs": {
                "before_manifest": "baseline/manifest.json",
                "before_manifest_sha256": "a" * 64,
                "after_manifest": "proposed/manifest.json",
                "after_manifest_sha256": "b" * 64,
                "project": "demo/acme_dbt",
                "commit_sha": "abc123",
            },
            "changes": [],
            "context": {
                "source_urns": [],
                "impacted_assets": [],
                "evidence_state": complete_state,
                "response_digests": [],
                "reason_codes": [],
            },
            "initial_risk": {
                "policy_version": "1.0",
                "score": 0,
                "score_decision": "PASS",
                "decision": "PASS",
                "asset_risks": [],
                "contributions": [],
                "evidence_state": complete_state,
                "change_ids": [],
                "impacted_asset_urns": [],
            },
            "remediation": {"status": "NOT_NEEDED"},
            "evidence_hash": "e" * 64,
            "writeback": {"state": "NOT_REQUESTED"},
            "mcp_trace": [],
        }
    )
    sealed = result.model_copy(update={"artifact_hash": calculate_artifact_hash(result)})
    return run_result_payload(sealed)


def _sealed_v11_payload() -> dict[str, object]:
    payload = _sealed_payload()
    payload["schema_version"] = "1.1"
    payload["artifact_hash"] = None
    payload["inputs"]["analyzed_input_state"] = "GENERATED_IN_PROCESS"  # type: ignore[index]
    result = RunResult.model_validate(payload)
    sealed = result.model_copy(update={"artifact_hash": calculate_artifact_hash(result)})
    return run_result_payload(sealed)


def test_review_page_and_alias_serve_the_operational_interface(artifact_path: Path) -> None:
    with _client(artifact_path) as client:
        root = client.get("/")
        alias = client.get("/review")

    assert root.status_code == 200
    assert alias.status_code == 200
    assert root.text == alias.text
    assert root.headers["content-type"].startswith("text/html")
    assert "Schema change review" in root.text
    assert 'href="#main-content"' in root.text
    assert root.text.count('aria-live="polite"') == 4
    assert '<main id="main-content"' in root.text
    assert "style=" not in root.text
    assert "PASS_WITH_REMEDIATION" not in root.text
    assert "run-123" not in root.text
    assert "urn:li:dataset:" not in root.text
    assert 'class="decision-fork-shell"' in root.text
    assert "Follow the change with and without the patch" in root.text
    assert 'id="fork-trunk"' in root.text
    assert 'id="fork-blocked"' in root.text
    assert 'id="fork-patched"' in root.text
    assert 'id="map-detail"' in root.text
    assert "View full evidence" in root.text
    assert "Source commit" in root.text
    assert "Analyzed inputs" in root.text
    assert '<details id="technical-evidence"' in root.text


def test_every_response_has_local_security_and_no_store_headers(artifact_path: Path) -> None:
    with _client(artifact_path) as client:
        page = client.get("/")
        api = client.get("/api/runs/latest")

    for response in (page, api):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        policy = response.headers["content-security-policy"]
        assert "default-src 'self'" in policy
        assert "script-src 'self'" in policy
        assert "style-src 'self'" in policy
        assert "'unsafe-inline'" not in policy


def test_missing_latest_artifact_is_an_honest_empty_state(artifact_path: Path) -> None:
    with _client(artifact_path) as client:
        response = client.get("/api/runs/latest")

    assert response.status_code == 404
    assert response.json() == {
        "status": "empty",
        "message": "No local LineageGuard run has been recorded yet.",
    }
    assert str(artifact_path) not in response.text


def test_latest_api_returns_a_schema_validated_sealed_run(
    artifact_path: Path,
) -> None:
    payload = _sealed_payload()
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_text(json.dumps(payload), encoding="utf-8")

    with _client(artifact_path) as client:
        response = client.get("/api/runs/latest")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "run": payload}
    assert json.loads(artifact_path.read_text(encoding="utf-8")) == payload


def test_latest_api_accepts_v11_provenance_and_seals_input_state(
    artifact_path: Path,
) -> None:
    payload = _sealed_v11_payload()
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_text(json.dumps(payload), encoding="utf-8")

    with _client(artifact_path) as client:
        response = client.get("/api/runs/latest")

    assert response.status_code == 200
    assert response.json()["run"]["inputs"]["analyzed_input_state"] == "GENERATED_IN_PROCESS"

    payload["inputs"]["analyzed_input_state"] = "SUPPLIED_MANIFESTS"  # type: ignore[index]
    artifact_path.write_text(json.dumps(payload), encoding="utf-8")
    with _client(artifact_path) as client:
        tampered = client.get("/api/runs/latest")
    assert tampered.status_code == 422


@pytest.mark.parametrize(
    ("schema_version", "analyzed_input_state"),
    [
        ("1.0", "SUPPLIED_MANIFESTS"),
        ("1.1", None),
        ("2.0", None),
    ],
)
def test_run_contract_rejects_inconsistent_or_unknown_provenance_schema(
    schema_version: str,
    analyzed_input_state: str | None,
) -> None:
    payload = _sealed_payload()
    payload["artifact_hash"] = None
    payload["schema_version"] = schema_version
    if analyzed_input_state is not None:
        payload["inputs"]["analyzed_input_state"] = analyzed_input_state  # type: ignore[index]

    with pytest.raises(ValueError, match=r"schema|unsupported"):
        RunResult.model_validate(payload)


@pytest.mark.parametrize("payload", [[], "recorded text", 12, None, {"artifact_hash": "f" * 64}])
def test_api_rejects_valid_json_that_is_not_a_typed_sealed_run(
    artifact_path: Path,
    payload: object,
) -> None:
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_text(json.dumps(payload), encoding="utf-8")

    with _client(artifact_path) as client:
        response = client.get("/api/runs/latest")

    assert response.status_code == 422
    assert response.json()["status"] == "error"


def test_api_rejects_tampering_that_claims_verified_writeback(artifact_path: Path) -> None:
    payload = _sealed_payload()
    payload["writeback"]["state"] = "VERIFIED"  # type: ignore[index]
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_text(json.dumps(payload), encoding="utf-8")

    with _client(artifact_path) as client:
        response = client.get("/api/runs/latest")

    assert response.status_code == 422
    assert "VERIFIED" not in response.text


@pytest.mark.parametrize("content", ["{broken", '{"score": NaN}', "\udcff"])
def test_invalid_json_or_encoding_returns_safe_error(
    artifact_path: Path,
    content: str,
) -> None:
    artifact_path.parent.mkdir(parents=True)
    if content == "\udcff":
        artifact_path.write_bytes(b"\xff\xfe")
    else:
        artifact_path.write_text(content, encoding="utf-8")

    with _client(artifact_path) as client:
        response = client.get("/api/runs/latest")

    assert response.status_code == 422
    assert response.json() == {
        "status": "error",
        "message": "The latest run artifact is not a valid sealed LineageGuard run.",
    }
    assert content not in response.text
    assert str(artifact_path) not in response.text


def test_directory_at_artifact_path_returns_read_error(artifact_path: Path) -> None:
    artifact_path.mkdir(parents=True)

    with _client(artifact_path) as client:
        response = client.get("/api/runs/latest")

    assert response.status_code == 500
    assert response.json()["message"] == "The latest run artifact could not be read."


def test_symlinked_artifact_path_is_not_followed(artifact_path: Path) -> None:
    target = artifact_path.parent / "target.json"
    target.parent.mkdir(parents=True)
    target.write_text('{"secret":"must-not-be-served"}', encoding="utf-8")
    artifact_path.symlink_to(target)

    with _client(artifact_path) as client:
        response = client.get("/api/runs/latest")

    assert response.status_code == 500
    assert "must-not-be-served" not in response.text


def test_oversized_artifact_is_rejected_before_read(
    artifact_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_text('{"run_id":"too-large"}', encoding="utf-8")
    monkeypatch.setattr(review_app, "MAX_RUN_ARTIFACT_BYTES", 4)

    with _client(artifact_path) as client:
        response = client.get("/api/runs/latest")

    assert response.status_code == 413
    assert response.json()["status"] == "error"
    assert "too-large" not in response.text


def test_assets_are_local_and_frontend_avoids_unsafe_data_rendering(artifact_path: Path) -> None:
    with _client(artifact_path) as client:
        stylesheet = client.get("/assets/review.css")
        script = client.get("/assets/review.js")
        traversal = client.get("/assets/../app.py")
        page = client.get("/")

    assert stylesheet.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
    assert "@media (max-width: 520px)" in stylesheet.text
    assert "@media (prefers-reduced-motion: reduce)" in stylesheet.text
    assert "Georgia" not in stylesheet.text
    assert "Inter" not in stylesheet.text
    assert "repeating-linear-gradient" not in stylesheet.text

    assert script.status_code == 200
    assert "textContent" in script.text
    assert "innerHTML" not in script.text
    assert "eval(" not in script.text
    assert "buildOverview" in script.text
    assert "buildDecisionFork" in script.text
    assert "allRecordedCommandsPassed" in script.text
    assert "recordedEvidenceIsComplete" in script.text
    assert '=== "VERIFIED"' in script.text
    assert "Do not treat this run as approval to merge" in script.text
    assert "application state is not recorded" in script.text
    assert "initial_assessment" in script.text
    assert "initialAssessment" in script.text
    assert "remediation.residual_risk" in script.text
    assert "inputs.commit_sha" in script.text
    assert "inputs.analyzed_input_state" in script.text
    assert "output_tail" in script.text
    assert '"state", "status", "writeback_status"' in script.text
    assert "runStatus" in script.text
    assert "SIGNATURE RECORDED" not in script.text
    assert 'setText("artifact-hash", compact(model.artifactHash, 20));' in script.text
    assert "model.artifactHash || model.evidenceHash" not in script.text
    assert "Verification record" in page.text
    assert "Artifact hash" in page.text
    assert "aria-labelledby" in script.text
    assert 'event.key === "Home"' in script.text
    assert 'event.key === "End"' in script.text
    assert "WRITEBACK_PENDING" not in script.text
    assert traversal.status_code == 404


def test_plain_english_overview_handles_mixed_assets_and_unverified_writeback() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the review UI behavior test")

    script_path = (
        Path(__file__).parents[2] / "src" / "lineageguard" / "review_ui" / "static" / "review.js"
    )
    program = r"""
const assert = require("node:assert/strict");
const { buildDecisionFork, buildOverview } = require(process.argv[1]);

const completeState = {
  catalog: "complete",
  lineage: "complete",
  traversal: "complete",
  ownership: "complete",
  assertions: "complete",
};
const base = {
  root: { context: { evidence_state: completeState } },
  initial: { evidence_state: completeState },
  residual: {},
  changes: [],
  assets: [
    { display_name: "orders", asset_type: "dataset" },
    { display_name: "revenue board", asset_type: "dashboard" },
  ],
  remediation: { status: "NOT_NEEDED" },
  verification: {},
  artifacts: [],
  writeback: { state: "NOT_REQUESTED" },
  finalDecision: "PASS",
  initialDecision: "PASS",
  residualDecision: "",
  runStatus: "COMPLETE",
};

const mixed = buildOverview(base);
assert.equal(mixed.impactTitle, "2 downstream assets");
assert.equal(mixed.verdictLabel, "PASS");
assert.equal(mixed.title, "Merge check passed");
assert.equal(mixed.writebackTitle, "Not requested");
assert.match(mixed.note, /DataHub verification not recorded/);

const oneDataJob = buildOverview({
  ...base,
  assets: [{ display_name: "dbt build", asset_type: "data_job" }],
});
assert.equal(oneDataJob.impactTitle, "1 downstream data job");

const verified = buildOverview({
  ...base,
  writeback: {
    state: "VERIFIED",
    document_urn: "urn:li:document:run-record",
    mutation_digests: ["a".repeat(64)],
    readback_digests: ["b".repeat(64)],
  },
});
assert.equal(verified.verdictLabel, "PASS");
assert.equal(verified.writebackTitle, "Verified");

const patchedModel = {
  ...base,
  changes: [
      {
        change_type: "RENAME_COLUMN",
        old_column: "order_total",
        new_column: "gross_amount",
        old_type: "DECIMAL(12, 2)",
        new_type: "DECIMAL(12, 2)",
        confidence: "high",
        relation: "stg_orders",
      },
    ],
  assets: [{
    display_name: "fct_daily_revenue",
    asset_type: "dataset",
    direct_column_lineage: true,
    hop_count: 1,
    critical_asset: true,
    owners: ["urn:li:corpGroup:finance_analytics"],
    assertion_urns: ["urn:li:assertion:revenue"],
  }],
  remediation: {
    status: "TESTED",
    interface_preserved: true,
    counterfactual_verified: true,
  },
  verification: {
    status: "TESTED",
    patched_manifest_sha256: "c".repeat(64),
    evidence_digest: "d".repeat(64),
    run_results_digest: "e".repeat(64),
    verified_node_ids: ["model.stg_orders", "model.fct_daily_revenue"],
    commands: [
      { exit_code: 0, output_digest: "f".repeat(64) },
      { exit_code: 0, output_digest: "0".repeat(64) },
    ],
  },
  artifacts: [{}],
  writeback: {
    state: "VERIFIED",
    document_urn: "urn:li:document:run-record",
    mutation_digests: ["1".repeat(64)],
    readback_digests: ["2".repeat(64)],
  },
  finalDecision: "PASS_WITH_REMEDIATION",
  initialDecision: "BLOCK",
  initialScore: 88,
  residualScore: 12,
  residualDecision: "PASS",
};
const patched = buildOverview(patchedModel);
assert.equal(patched.verdictLabel, "PASS WITH PATCH");
assert.equal(patched.title, "Apply the patch before merging");
assert.equal(patched.actionTitle, "Compatibility alias generated");
assert.match(patched.actionDetail, /Apply before merging/);
assert.equal(patched.checksDetail, "Passed against a temporary patched copy");
assert.equal(patched.resultDetail, "Initial → projected after tested patch");
assert.equal(patched.mutationCountLabel, "1");
assert.equal(patched.readbackCountLabel, "1");
assert.equal(patched.recordId, "run-record");

const fork = buildDecisionFork(patchedModel);
assert.equal(fork.defaultId, "patch");
assert.equal(fork.nodes.length, 7);
assert.match(fork.nodes.find((node) => node.id === "impact").status, /CRITICAL · DIRECT/);
assert.equal(fork.nodes.find((node) => node.id === "block").status, "BLOCK");
assert.equal(fork.nodes.find((node) => node.id === "patch").state, "passed");
assert.equal(fork.nodes.find((node) => node.id === "pass").value, "12 PASS");
assert.equal(fork.nodes.find((node) => node.id === "datahub").status, "VERIFIED");
assert.equal(fork.nodes.find((node) => node.id === "datahub").label, "Decision record");
assert.match(
  fork.nodes.find((node) => node.id === "patch").detail,
  /application state is not recorded/,
);

const finalBlockFork = buildDecisionFork({ ...patchedModel, finalDecision: "BLOCK" });
assert.equal(finalBlockFork.projectionVerified, false);
assert.equal(finalBlockFork.nodes.find((node) => node.id === "pass").state, "review");
assert.doesNotMatch(finalBlockFork.forkSummary, /continues to/);

const incompleteFork = buildDecisionFork({
  ...patchedModel,
  initial: { evidence_state: { ...completeState, lineage: "partial" } },
});
assert.equal(incompleteFork.projectionVerified, false);
assert.equal(incompleteFork.nodes.find((node) => node.id === "pass").state, "review");

const failedFork = buildDecisionFork({
  ...patchedModel,
  verification: { ...patchedModel.verification, status: "TEST_FAILED" },
});
assert.equal(failedFork.nodes.find((node) => node.id === "patch").state, "failed");
assert.equal(failedFork.nodes.find((node) => node.id === "patch").label, "Patch");
assert.equal(failedFork.nodes.find((node) => node.id === "checks").tone, "danger");

const errorFork = buildDecisionFork({
  ...patchedModel,
  remediation: { ...patchedModel.remediation, status: "VERIFICATION_ERROR" },
  verification: { ...patchedModel.verification, status: "VERIFICATION_ERROR" },
});
assert.equal(errorFork.nodes.find((node) => node.id === "patch").state, "failed");
assert.equal(errorFork.nodes.find((node) => node.id === "patch").label, "Patch");
assert.equal(errorFork.nodes.find((node) => node.id === "checks").tone, "danger");

const pendingFork = buildDecisionFork({
  ...base,
  writeback: { state: "WRITEBACK_PENDING" },
});
assert.equal(pendingFork.nodes.find((node) => node.id === "datahub").state, "pending");
assert.equal(pendingFork.nodes.find((node) => node.id === "datahub").value, "Pending");

const notRequestedFork = buildDecisionFork(base);
assert.equal(notRequestedFork.nodes.find((node) => node.id === "datahub").state, "not-requested");
assert.equal(
  notRequestedFork.nodes.find((node) => node.id === "change").detail,
  "No normalized schema change was recorded.",
);

const unverifiedCounterfactual = buildOverview({
  ...patchedModel,
  remediation: { status: "TESTED", interface_preserved: true },
});
assert.equal(unverifiedCounterfactual.verdictLabel, "REVIEW");

const missingVerificationDigest = buildOverview({
  ...patchedModel,
  verification: { ...patchedModel.verification, evidence_digest: "" },
});
assert.equal(missingVerificationDigest.verdictLabel, "REVIEW");
assert.equal(missingVerificationDigest.verificationStatus, "PROOF INCOMPLETE");

const unverifiedWriteback = buildOverview({
  ...base,
  writeback: {
    state: "VERIFIED",
    document_urn: "urn:li:document:run-record",
    readback_digests: ["3".repeat(64)],
  },
});
assert.equal(unverifiedWriteback.writebackTitle, "Not verified");
assert.equal(unverifiedWriteback.writebackDetail, "Verification evidence is incomplete");

const mismatchedResidual = buildOverview({
  ...patchedModel,
  residualDecision: "REVIEW",
});
assert.equal(mismatchedResidual.verdictLabel, "REVIEW");
assert.equal(mismatchedResidual.patchStatus, "PROOF INCOMPLETE");
assert.equal(mismatchedResidual.verificationStatus, "PROOF INCOMPLETE");

const conflictingVerification = buildOverview({
  ...patchedModel,
  verification: {
    ...patchedModel.verification,
    status: "TEST_FAILED",
  },
});
assert.equal(conflictingVerification.verdictLabel, "REVIEW");
assert.equal(conflictingVerification.verificationStatus, "TEST_FAILED");

const addedColumn = buildOverview({
  ...base,
  changes: [{ change_type: "ADD_COLUMN", relation: "stg_orders" }],
  assets: [{
    display_name: "fct_daily_revenue",
    asset_type: "dataset",
    direct_column_lineage: true,
  }],
});
assert.doesNotMatch(addedColumn.summary, /being renamed/);

const aggregateAssets = buildOverview({
  ...base,
  assets: [
    {
      display_name: "first",
      asset_type: "dataset",
      direct_column_lineage: true,
      hop_count: 1,
      critical_asset: true,
      owners: ["urn:li:corpuser:first_owner"],
      assertion_urns: ["one"],
    },
    {
      display_name: "second",
      asset_type: "dataset",
      critical_asset: false,
      owners: ["urn:li:corpuser:second_owner"],
      assertion_urns: ["two", "three"],
    },
  ],
});
assert.equal(aggregateAssets.targetName, "2 downstream assets");
assert.equal(aggregateAssets.lineageLabel, "Open individual lineage records");
assert.equal(aggregateAssets.criticalityLabel, "1 of 2 critical");
assert.equal(aggregateAssets.ownerLabel, "2 owners");
assert.equal(aggregateAssets.assertionLabel, "3 assertions");

const multipleChanges = buildOverview({
  ...patchedModel,
  changes: [
    ...patchedModel.changes,
    { change_type: "ADD_COLUMN", relation: "stg_orders" },
  ],
});
assert.equal(multipleChanges.verdictLabel, "REVIEW");
assert.equal(multipleChanges.patchStatus, "PROOF INCOMPLETE");

const partialOwners = buildOverview({
  ...base,
  assets: [
    {
      display_name: "first",
      asset_type: "dataset",
      owners: ["urn:li:corpuser:first_owner"],
    },
    { display_name: "second", asset_type: "dataset" },
  ],
});
assert.equal(partialOwners.ownerLabel, "Owners not fully recorded");

const incomplete = buildOverview({
  ...base,
  initial: { evidence_state: { ...completeState, lineage: "partial" } },
});
assert.equal(incomplete.verdictLabel, "REVIEW");
assert.equal(incomplete.title, "Impact check is incomplete");

const blocked = buildOverview({ ...base, finalDecision: "BLOCK" });
assert.equal(blocked.verdictLabel, "BLOCKED");
assert.equal(blocked.title, "Do not merge");

const failed = buildOverview({
  ...base,
  verification: { commands: [{ exit_code: 1 }] },
});
assert.equal(failed.verdictLabel, "REVIEW");
assert.equal(failed.title, "A recorded check failed");
"""
    subprocess.run(  # noqa: S603 - executes the resolved Node binary against local UI code
        [node, "-e", program, str(script_path)],
        check=True,
        capture_output=True,
        text=True,
    )


def test_healthcheck_is_minimal_and_framework_docs_are_disabled(artifact_path: Path) -> None:
    with _client(artifact_path) as client:
        health = client.get("/healthz")
        docs = client.get("/docs")
        schema = client.get("/openapi.json")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert docs.status_code == 404
    assert schema.status_code == 404


def test_non_loopback_host_header_is_rejected(artifact_path: Path) -> None:
    with _client(artifact_path) as client:
        response = client.get("/api/runs/latest", headers={"Host": "attacker.example"})

    assert response.status_code == 400


def test_explicit_deployment_host_is_accepted(
    artifact_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LINEAGEGUARD_ALLOWED_HOSTS", "demo.example")

    with _client(artifact_path) as client:
        response = client.get("/healthz", headers={"Host": "demo.example"})

    assert response.status_code == 200


@pytest.mark.parametrize(
    "configured",
    [
        "*",
        "*.example.com",
        "demo.example:443",
        "https://demo.example",
        "demo..example",
        "demo.example/path",
        "[::1]",
    ],
)
def test_wildcard_and_unsafe_deployment_hosts_are_rejected(
    artifact_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    configured: str,
) -> None:
    monkeypatch.setenv("LINEAGEGUARD_ALLOWED_HOSTS", configured)

    with pytest.raises(ValueError, match="LINEAGEGUARD_ALLOWED_HOSTS"):
        create_app(artifact_path)


def test_deployment_host_limit_is_not_silently_truncated(
    artifact_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hosts = ",".join(f"demo-{index}.example" for index in range(11))
    monkeypatch.setenv("LINEAGEGUARD_ALLOWED_HOSTS", hosts)

    with pytest.raises(ValueError, match="at most 10"):
        create_app(artifact_path)
