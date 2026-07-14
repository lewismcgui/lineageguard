"use strict";

const byId = (id) => document.getElementById(id);

const isRecord = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const getPath = (root, path) => {
  let current = root;
  for (const part of path.split(".")) {
    if (!isRecord(current) || !(part in current)) {
      return undefined;
    }
    current = current[part];
  }
  return current;
};

const pick = (root, paths) => {
  for (const path of paths) {
    const value = getPath(root, path);
    if (value !== undefined && value !== null) {
      return value;
    }
  }
  return undefined;
};

const asRecord = (value) => (isRecord(value) ? value : {});
const asArray = (value) => (Array.isArray(value) ? value : []);

const asNumber = (value) => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
};

const asText = (value, fallback = "Not recorded") => {
  if (typeof value === "string" && value.trim() !== "") {
    return value.trim();
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }
  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }
  if (Array.isArray(value)) {
    const parts = value.map((item) => asText(item, "")).filter(Boolean);
    return parts.length ? parts.join(", ") : fallback;
  }
  if (isRecord(value)) {
    return asText(
      pick(value, ["display_name", "displayName", "name", "urn", "id", "value"]),
      fallback,
    );
  }
  return fallback;
};

const compact = (value, length = 18) => {
  const text = asText(value, "Not recorded");
  if (text === "Not recorded" || text.length <= length) {
    return text;
  }
  return `${text.slice(0, length)}…`;
};

const setText = (id, value, fallback = "Not recorded") => {
  const element = byId(id);
  if (element) {
    element.textContent = asText(value, fallback);
  }
};

const create = (tag, className, text) => {
  const element = document.createElement(tag);
  if (className) {
    element.className = className;
  }
  if (text !== undefined) {
    element.textContent = text;
  }
  return element;
};

const decisionKind = (decision) => {
  const normalized = asText(decision, "").toUpperCase();
  if (normalized.includes("BLOCK") || normalized.includes("FAIL")) {
    return "block";
  }
  if (normalized.includes("REVIEW") || normalized.includes("PENDING")) {
    return "review";
  }
  if (normalized.includes("PASS") || normalized === "VERIFIED" || normalized === "TESTED") {
    return "pass";
  }
  return "unknown";
};

const statusClass = (status) => {
  const kind = decisionKind(status);
  if (kind === "pass") {
    return "is-success";
  }
  if (kind === "block" || kind === "review") {
    return "is-warning";
  }
  return "";
};

const formatTimestamp = (value) => {
  if (typeof value !== "string" || value.trim() === "") {
    return "Time not recorded";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(parsed);
};

const uppercaseText = (value) => asText(value, "").toUpperCase();

const isSha256 = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);

const shortEntityName = (value) => {
  const text = asText(value, "").replaceAll('"', "");
  if (!text) {
    return "";
  }
  const datasetMatch = text.match(/,([^,()]+),[^,()]+\)$/);
  if (datasetMatch) {
    return datasetMatch[1].split(".").pop() || datasetMatch[1];
  }
  const dotted = text.split(".").pop();
  const colon = (dotted || text).split(":").pop();
  return colon || text;
};

const humanizeAssetKind = (value) => {
  const normalized = asText(value, "").toLowerCase().replaceAll(/[_-]+/g, " ").trim();
  return normalized || "asset";
};

const recordedCommands = (verification) =>
  asArray(pick(verification, ["commands", "results", "command_results"]));

const allRecordedCommandsPassed = (verification) => {
  const commands = recordedCommands(verification);
  return (
    commands.length > 0 &&
    commands.every((rawCommand) => {
      const command =
        typeof rawCommand === "string" || Array.isArray(rawCommand)
          ? { command: rawCommand }
          : asRecord(rawCommand);
      return asNumber(pick(command, ["exit_code", "exitCode", "returncode"])) === 0;
    })
  );
};

const recordedEvidenceIsComplete = (model) => {
  const states = [
    asRecord(pick(model.initial, ["evidence_state", "evidenceState"])),
    asRecord(pick(model.root, ["context.evidence_state", "context.evidenceState"])),
  ].filter((state) => Object.keys(state).length > 0);
  const required = ["catalog", "lineage", "traversal", "ownership", "assertions"];
  return (
    states.length > 0 &&
    states.every((state) => required.every((field) => uppercaseText(state[field]) === "COMPLETE"))
  );
};

const buildOverview = (model) => {
  const firstChange = asRecord(model.changes[0]);
  const changeType = uppercaseText(pick(firstChange, ["change_type", "changeType", "type"]));
  const oldColumn = asText(pick(firstChange, ["old_column", "oldColumn"]), "");
  const newColumn = asText(pick(firstChange, ["new_column", "newColumn"]), "");
  const relation = shortEntityName(pick(firstChange, ["relation", "dataset", "dataset_urn"]));
  const singleRename =
    model.changes.length === 1 &&
    changeType === "RENAME_COLUMN" &&
    Boolean(oldColumn) &&
    Boolean(newColumn);
  const firstAsset = asRecord(model.assets[0]);
  const firstAssetName = asText(
    pick(firstAsset, ["display_name", "displayName", "name", "title"]),
    shortEntityName(pick(firstAsset, ["urn", "asset_urn", "assetUrn"])),
  );
  const firstOwner = shortEntityName(asArray(pick(firstAsset, ["owners"]))[0]);
  const assertionValue = pick(firstAsset, ["assertion_urns", "assertionUrns", "assertions"]);
  const assertionCount = Array.isArray(assertionValue) ? assertionValue.length : undefined;
  const hopCount = asNumber(pick(firstAsset, ["hop_count", "hopCount"]));
  const directLineage = pick(firstAsset, ["direct_column_lineage", "directColumnLineage"]) === true;
  const firstAssetCritical = pick(firstAsset, ["critical_asset", "criticalAsset"]);
  const assetOwnerValues = model.assets.map((asset) => pick(asRecord(asset), ["owners"]));
  const assetOwnersFullyRecorded = assetOwnerValues.every(Array.isArray);
  const assetOwners = assetOwnerValues.flatMap((owners) =>
    asArray(owners).map((owner) => shortEntityName(owner)).filter(Boolean),
  );
  const uniqueAssetOwners = [...new Set(assetOwners)];
  const assetAssertionValues = model.assets.map((asset) =>
    pick(asRecord(asset), ["assertion_urns", "assertionUrns", "assertions"]),
  );
  const aggregateAssertionCount = assetAssertionValues.every(Array.isArray)
    ? assetAssertionValues.reduce((total, value) => total + value.length, 0)
    : undefined;
  const assetCriticalityValues = model.assets.map((asset) =>
    pick(asRecord(asset), ["critical_asset", "criticalAsset"]),
  );
  const assetKinds = model.assets.map((asset) =>
    humanizeAssetKind(
      pick(asRecord(asset), ["asset_type", "assetType", "entity_type", "type"]),
    ),
  );
  const assetNoun = new Set(assetKinds).size === 1 ? assetKinds[0] : "asset";
  const criticalAssets = model.assets.filter(
    (asset) => pick(asRecord(asset), ["critical_asset", "criticalAsset"]) === true,
  ).length;
  const rawDecision =
    model.finalDecision || model.residualDecision || model.initialDecision || "Not recorded";
  const rawKind = decisionKind(rawDecision);
  const runComplete = uppercaseText(model.runStatus) === "COMPLETE";
  const evidenceComplete = recordedEvidenceIsComplete(model);
  const remediationStatus = uppercaseText(
    pick(model.remediation, ["status", "remediation_status"]),
  );
  const verificationStatus = uppercaseText(
    pick(model.verification, ["status", "result.status"]),
  );
  const commands = recordedCommands(model.verification);
  const commandsPassed = allRecordedCommandsPassed(model.verification);
  const requiresPatch = uppercaseText(rawDecision) === "PASS_WITH_REMEDIATION";
  const needsTestedFix =
    uppercaseText(rawDecision).includes("REMEDIATION") || model.artifacts.length > 0;
  const interfacePreserved = pick(model.remediation, ["interface_preserved"]) === true;
  const counterfactualVerified =
    pick(model.remediation, ["counterfactual_verified"]) === true;
  const counterfactualCondition = uppercaseText(
    pick(model.remediation, ["counterfactual_condition"]),
  );
  const residualPassVerified =
    uppercaseText(model.residualDecision) === "PASS" ||
    counterfactualCondition === "NO_RESIDUAL_CHANGES";
  const patchedManifestDigest = asText(
    pick(model.verification, ["patched_manifest_sha256", "patchedManifestSha256"]),
    "",
  );
  const verificationEvidenceDigest = asText(
    pick(model.verification, ["evidence_digest", "evidenceDigest"]),
    "",
  );
  const runResultsDigest = asText(
    pick(model.verification, ["run_results_digest", "runResultsDigest"]),
    "",
  );
  const verificationFailure = asText(
    pick(model.verification, ["failure_reason", "failureReason"]),
    "",
  );
  const commandDigestsComplete = commands.every((rawCommand) => {
    const command = asRecord(rawCommand);
    return isSha256(pick(command, ["output_digest", "outputDigest"]));
  });
  const verificationProofComplete =
    verificationStatus === "TESTED" &&
    commandsPassed &&
    commandDigestsComplete &&
    isSha256(patchedManifestDigest) &&
    isSha256(verificationEvidenceDigest) &&
    isSha256(runResultsDigest) &&
    !verificationFailure;
  const testedFix =
    remediationStatus === "TESTED" &&
    verificationProofComplete &&
    (!requiresPatch ||
      (interfacePreserved &&
        counterfactualVerified &&
        residualPassVerified &&
        singleRename &&
        Boolean(patchedManifestDigest) &&
        model.artifacts.length > 0));
  const writebackState = uppercaseText(
    pick(model.writeback, ["state", "status", "writeback_status"]),
  );
  const mutationDigestValue = pick(model.writeback, ["mutation_digests", "mutationDigests"]);
  const readbackDigestValue = pick(model.writeback, ["readback_digests", "readbackDigests"]);
  const mutationDigests = asArray(mutationDigestValue);
  const readbackDigests = asArray(readbackDigestValue);
  const documentUrn = asText(
    pick(model.writeback, ["document_urn", "documentUrn", "passport_urn"]),
    "",
  );
  const writebackVerified =
    writebackState === "VERIFIED" &&
    /^urn:li:document:\S+$/.test(documentUrn) &&
    mutationDigests.length > 0 &&
    mutationDigests.every(isSha256) &&
    readbackDigests.length > 0 &&
    readbackDigests.every(isSha256);
  const passedCommands = commands.filter((rawCommand) => {
    const command =
      typeof rawCommand === "string" || Array.isArray(rawCommand)
        ? { command: rawCommand }
        : asRecord(rawCommand);
    return asNumber(pick(command, ["exit_code", "exitCode", "returncode"])) === 0;
  }).length;
  const hasFailedCommand = commands.some((rawCommand) => {
    const command =
      typeof rawCommand === "string" || Array.isArray(rawCommand)
        ? { command: rawCommand }
        : asRecord(rawCommand);
    const exitCode = asNumber(pick(command, ["exit_code", "exitCode", "returncode"]));
    return exitCode !== undefined && exitCode !== 0;
  });

  let kind = rawKind;
  if (rawKind !== "block" && (!runComplete || !evidenceComplete)) {
    kind = "review";
  } else if (rawKind === "pass" && hasFailedCommand) {
    kind = "review";
  } else if (rawKind === "pass" && needsTestedFix && !testedFix) {
    kind = "review";
  }

  let title = "No decision is available";
  if (kind === "block") {
    title = "Do not merge";
  } else if (kind === "review") {
    if (!runComplete) {
      title = "No completed check";
    } else if (!evidenceComplete) {
      title = "Impact check is incomplete";
    } else if (hasFailedCommand) {
      title = needsTestedFix ? "The patch failed its checks" : "A recorded check failed";
    } else if (needsTestedFix && !testedFix) {
      title = "The patch still needs checking";
    } else {
      title = "Review required";
    }
  } else if (kind === "pass") {
    title = requiresPatch ? "Apply the patch before merging" : "Merge check passed";
  }

  let note = "Evidence state unavailable";
  if (kind === "pass") {
    note = writebackVerified
      ? `${testedFix ? "Commands passed" : "Policy passed"} · DataHub record verified`
      : `${testedFix ? "Commands passed" : "Policy passed"} · DataHub verification not recorded`;
  } else if (kind === "block") {
    note = "The recorded policy decision blocks this change";
  } else if (kind === "review") {
    note = "Do not treat this run as approval to merge";
  }

  let changeTitle = model.changes.length
    ? `${model.changes.length} schema change${model.changes.length === 1 ? "" : "s"}`
    : "Change not recorded";
  if (model.changes.length === 1 && changeType === "RENAME_COLUMN" && oldColumn && newColumn) {
    changeTitle = `${oldColumn} → ${newColumn}`;
  } else if (model.changes.length === 1 && changeType === "ADD_COLUMN") {
    changeTitle = "1 column added";
  } else if (model.changes.length === 1 && changeType === "DROP_COLUMN") {
    changeTitle = "1 column removed";
  } else if (model.changes.length === 1 && changeType.includes("TYPE")) {
    changeTitle = "1 column type changed";
  }

  const changeDetail =
    oldColumn && newColumn
      ? relation
        ? `Column rename in ${relation}`
        : "One column renamed"
      : relation
        ? `Recorded in ${relation}`
        : "Open the evidence for the exact schema delta.";

  let impactTitle = "Impact evidence is incomplete";
  let impactDetail = "Do not assume that no downstream assets are affected.";
  if (evidenceComplete && model.assets.length === 0) {
    impactTitle = "No downstream impact found";
    impactDetail = "Within the recorded DataHub lineage scope.";
  } else if (evidenceComplete && model.assets.length > 0) {
    const criticalLabel = criticalAssets === model.assets.length ? "critical " : "";
    impactTitle = `${model.assets.length} ${criticalLabel}downstream ${assetNoun}${model.assets.length === 1 ? "" : "s"}`;
    impactDetail = firstAssetName
      ? `${firstAssetName}${
          model.assets.length === 1
            ? " could be affected."
            : ` is first in the impact path.${criticalAssets ? ` ${criticalAssets} marked critical.` : ""}`
        }`
      : "Open the evidence for the impacted assets.";
  }

  let actionTitle = "No automatic action recorded";
  let actionDetail = "Review the evidence before merging.";
  if (testedFix) {
    actionTitle =
      interfacePreserved
        ? "Compatibility alias generated"
        : "Patch generated and tested";
    actionDetail =
      interfacePreserved && oldColumn && newColumn
        ? `Apply before merging. Keeps ${oldColumn} available while teams move to ${newColumn}.`
        : `${model.artifacts.length} generated file change${model.artifacts.length === 1 ? "" : "s"}.`;
  } else if (remediationStatus === "NOT_NEEDED") {
    actionTitle = "No compatibility fix was needed";
    actionDetail = "The recorded policy decision did not require remediation.";
  } else if (model.artifacts.length) {
    actionTitle = "Compatibility fix generated, not verified";
    actionDetail = hasFailedCommand
      ? "At least one recorded check failed."
      : "Passing command evidence was not recorded.";
  }

  const resultTitle =
    model.initialScore !== undefined && model.residualScore !== undefined
      ? `${model.initialScore} → ${model.residualScore}`
      : "Not recorded";
  const resultDetail =
    model.initialScore !== undefined && model.residualScore !== undefined
      ? kind === "pass" && model.residualScore < model.initialScore
        ? requiresPatch
          ? "Initial → projected after tested patch"
          : "Reduced after the recorded change"
        : "Recorded policy score"
      : "No risk scores are available.";
  const checksTitle = commands.length ? `${passedCommands} of ${commands.length} passed` : "Not recorded";
  const checksDetail = commands.length
    ? commandsPassed
      ? requiresPatch
        ? testedFix
          ? "Passed against a temporary patched copy"
          : "Commands passed; full patch proof is incomplete"
        : "All recorded dbt checks passed"
      : hasFailedCommand
        ? "At least one recorded check failed"
        : "Some check results are missing"
    : "No check results are available.";
  const writebackTitle = writebackVerified
    ? "Verified"
    : writebackState === "NOT_REQUESTED"
      ? "Not requested"
      : "Not verified";
  const writebackDetail = writebackVerified
    ? "Decision record written and read back"
    : writebackState === "VERIFIED"
      ? "Verification evidence is incomplete"
    : writebackState
      ? `Recorded state: ${writebackState.replaceAll("_", " ").toLowerCase()}`
      : "No writeback result is available.";

  let changeLead = "The recorded schema change";
  if (changeType === "RENAME_COLUMN" && oldColumn && newColumn) {
    changeLead = `Renaming ${oldColumn} to ${newColumn}${relation ? ` in ${relation}` : ""}`;
  }
  let summary;
  if (evidenceComplete && singleRename && model.assets.length === 1 && firstAssetName && directLineage) {
    summary = `${relation && oldColumn ? `${relation}.${oldColumn}` : changeLead} is being renamed to ${newColumn || "a new column"}, but ${firstAssetName} still depends on the old name.`;
  } else if (evidenceComplete && model.assets.length) {
    summary = `${changeLead} could affect ${model.assets.length === 1 ? "one" : model.assets.length} downstream ${
      model.assets.length === 1 ? assetNoun : "assets"
    }.`;
  } else if (evidenceComplete) {
    summary = `${changeLead} has no downstream impact in the recorded DataHub scope.`;
  } else {
    summary = `${changeLead}. Downstream impact evidence is incomplete.`;
  }
  if (testedFix) {
    summary += ` A compatibility patch passed ${commands.length} verification command${commands.length === 1 ? "" : "s"} in a temporary copy. Apply it before merging.`;
  } else if (model.artifacts.length) {
    summary += " A patch was generated, but passing checks are not fully recorded.";
  }
  if (!writebackVerified && kind === "pass") {
    summary += " DataHub verification was not recorded.";
  }

  const singleChange = model.changes.length === 1;
  const singleAsset = model.assets.length === 1;
  const sourceRelationLabel = singleChange
    ? relation || "Relation not recorded"
    : model.changes.length
      ? `${model.changes.length} schema changes`
      : "Change not recorded";
  const targetName = singleAsset
    ? firstAssetName || "Asset not recorded"
    : model.assets.length
      ? `${model.assets.length} downstream assets`
      : evidenceComplete
        ? "No downstream asset"
        : "Impact not recorded";
  const lineageLabel =
    !singleAsset && model.assets.length
      ? "Open individual lineage records"
      : singleAsset && directLineage
      ? `Direct column lineage${hopCount !== undefined ? ` · ${hopCount} hop${hopCount === 1 ? "" : "s"}` : ""}`
      : hopCount !== undefined
        ? `Recorded lineage · ${hopCount} hop${hopCount === 1 ? "" : "s"}`
        : "Recorded lineage";
  const criticalityLabel = !singleAsset && model.assets.length
    ? assetCriticalityValues.every((value) => typeof value === "boolean")
      ? `${criticalAssets} of ${model.assets.length} critical`
      : "Criticality varies"
    : firstAssetCritical === true
      ? "Critical"
      : firstAssetCritical === false
        ? "Not marked critical"
        : "Criticality not recorded";
  const ownerLabel = !singleAsset && model.assets.length
    ? !assetOwnersFullyRecorded
      ? "Owners not fully recorded"
      : uniqueAssetOwners.length === 1
      ? uniqueAssetOwners[0].replaceAll(/[_-]+/g, " ")
      : uniqueAssetOwners.length
        ? `${uniqueAssetOwners.length} owners`
        : "Owners not recorded"
    : firstOwner
      ? firstOwner.replaceAll(/[_-]+/g, " ")
      : "Owner not recorded";
  const displayedAssertionCount = singleAsset ? assertionCount : aggregateAssertionCount;
  const assertionLabel =
    displayedAssertionCount === undefined
      ? "Assertions not recorded"
      : `${displayedAssertionCount} assertion${displayedAssertionCount === 1 ? "" : "s"}`;
  const artifactCountLabel = model.artifacts.length
    ? `${model.artifacts.length} file${model.artifacts.length === 1 ? "" : "s"}`
    : "None recorded";
  const mutationCountLabel = Array.isArray(mutationDigestValue)
    ? String(mutationDigests.length)
    : "—";
  const readbackCountLabel = Array.isArray(readbackDigestValue)
    ? String(readbackDigests.length)
    : "—";
  const recordId = documentUrn ? shortEntityName(documentUrn) : "Not recorded";

  return {
    actionDetail,
    actionTitle,
    artifactCountLabel,
    assertionLabel,
    changeDetail,
    changeTitle,
    checksDetail,
    checksTitle,
    criticalityLabel,
    impactDetail,
    impactTitle,
    initialDecision: model.initialDecision,
    initialScore: model.initialScore,
    kind,
    lineageLabel,
    mutationCountLabel,
    newColumn: singleChange ? newColumn || "New column not recorded" : "Review changes",
    note,
    oldColumn: singleChange ? oldColumn || "Old column not recorded" : "Multiple changes",
    ownerLabel,
    patchStatus:
      testedFix
        ? "TESTED"
        : needsTestedFix && remediationStatus === "TESTED"
          ? "PROOF INCOMPLETE"
          : remediationStatus || "Not recorded",
    rawDecision,
    readbackCountLabel,
    recordId,
    residualDecision: model.residualDecision,
    residualScore: model.residualScore,
    resultDetail,
    resultTitle,
    sourceRelationLabel,
    summary,
    targetName,
    title,
    verificationStatus:
      testedFix || (!needsTestedFix && verificationStatus === "TESTED" && commandsPassed)
        ? "PASSED"
        : needsTestedFix && verificationStatus === "TESTED"
          ? "PROOF INCOMPLETE"
          : verificationStatus || "Not recorded",
    verdictLabel:
      kind === "pass"
        ? requiresPatch
          ? "PASS WITH PATCH"
          : "PASS"
        : kind === "block"
          ? "BLOCKED"
          : kind === "review"
            ? "REVIEW"
            : "NO RESULT",
    writebackDetail,
    writebackTitle,
  };
};

const buildDecisionFork = (model) => {
  const overview = buildOverview(model);
  const firstChange = asRecord(model.changes[0]);
  const firstAsset = asRecord(model.assets[0]);
  const singleChange = model.changes.length === 1;
  const singleAsset = model.assets.length === 1;
  const changeType = uppercaseText(pick(firstChange, ["change_type", "changeType", "type"]));
  const relation = shortEntityName(pick(firstChange, ["relation", "dataset", "dataset_urn"]));
  const oldType = asText(pick(firstChange, ["old_type", "oldType"]), "");
  const newType = asText(pick(firstChange, ["new_type", "newType"]), "");
  const confidence = asText(pick(firstChange, ["confidence"]), "");
  const changesRecorded =
    model.changes.length > 0 &&
    model.changes.every((rawChange) => {
      const change = asRecord(rawChange);
      const type = uppercaseText(pick(change, ["change_type", "changeType", "type"]));
      const hasIdentity = Boolean(type && pick(change, ["relation", "dataset", "dataset_urn"]));
      if (type !== "RENAME_COLUMN") {
        return hasIdentity;
      }
      return Boolean(
        hasIdentity &&
          pick(change, ["old_column", "oldColumn"]) &&
          pick(change, ["new_column", "newColumn"]),
      );
    });
  const evidenceComplete = recordedEvidenceIsComplete(model);
  const directLineage = pick(firstAsset, ["direct_column_lineage", "directColumnLineage"]) === true;
  const criticalAsset = pick(firstAsset, ["critical_asset", "criticalAsset"]) === true;
  const hopCount = asNumber(pick(firstAsset, ["hop_count", "hopCount"]));
  const firstAssetName = singleAsset ? overview.targetName : "";
  const commandCount = recordedCommands(model.verification).length;
  const verifiedNodeCount = asArray(
    pick(model.verification, ["verified_node_ids", "verifiedNodeIds"]),
  ).length;
  const patchPassed = overview.patchStatus === "TESTED";
  const verificationPassed = overview.verificationStatus === "PASSED";
  const datahubPassed = overview.writebackTitle === "Verified";
  const residualPassed = uppercaseText(overview.residualDecision) === "PASS";
  const remediationStatus = uppercaseText(
    pick(model.remediation, ["status", "remediation_status"]),
  );
  const rawVerificationStatus = uppercaseText(
    pick(model.verification, ["status", "result.status"]),
  );
  const writebackState = uppercaseText(
    pick(model.writeback, ["state", "status", "writeback_status"]),
  );
  const projectionVerified =
    patchPassed &&
    residualPassed &&
    overview.kind === "pass" &&
    uppercaseText(overview.rawDecision) === "PASS_WITH_REMEDIATION" &&
    evidenceComplete &&
    uppercaseText(model.runStatus) === "COMPLETE";
  const remediationFailed =
    remediationStatus.includes("FAIL") || remediationStatus.includes("ERROR");
  const verificationFailed =
    rawVerificationStatus.includes("FAIL") || rawVerificationStatus.includes("ERROR");
  const patchNodeState = patchPassed
    ? { status: "TESTED", state: "passed", tone: "success" }
    : remediationFailed || verificationFailed
      ? { status: remediationFailed ? remediationStatus : rawVerificationStatus, state: "failed", tone: "danger" }
      : remediationStatus === "NOT_NEEDED"
        ? { status: "NOT REQUIRED", state: "not-requested", tone: "neutral" }
        : { status: overview.patchStatus, state: "review", tone: "warning" };
  const verificationNodeState = verificationPassed
    ? { status: "PASSED", state: "passed", tone: "success" }
    : verificationFailed
      ? { status: rawVerificationStatus, state: "failed", tone: "danger" }
      : remediationStatus === "NOT_NEEDED" && commandCount === 0
        ? { status: "NOT REQUIRED", state: "not-requested", tone: "neutral" }
        : rawVerificationStatus.includes("PENDING")
          ? { status: "PENDING", state: "pending", tone: "warning" }
          : { status: overview.verificationStatus, state: "review", tone: "warning" };
  const datahubNodeState = datahubPassed
    ? { status: "VERIFIED", state: "passed", tone: "success", value: "Verified" }
    : writebackState === "NOT_REQUESTED"
      ? { status: "NOT REQUESTED", state: "not-requested", tone: "neutral", value: "Not requested" }
      : writebackState.includes("PENDING")
        ? { status: "PENDING", state: "pending", tone: "warning", value: "Pending" }
        : writebackState.includes("FAIL") || writebackState.includes("ERROR")
          ? { status: writebackState, state: "failed", tone: "danger", value: "Failed" }
          : { status: "REVIEW", state: "review", tone: "warning", value: overview.writebackTitle };

  const typeEvidence =
    singleChange && oldType && newType
      ? oldType === newType
        ? `${oldType} preserved`
        : `${oldType} → ${newType}`
      : "Type evidence in full record";
  const changeDetail = singleChange
    ? `${changeType === "RENAME_COLUMN" ? "Rename" : "Schema change"}${relation ? ` in ${relation}` : ""} · ${typeEvidence}${confidence ? ` · confidence ${confidence.toLowerCase()}` : ""}`
    : model.changes.length
      ? `${model.changes.length} schema changes recorded. Open the exact delta for individual fields.`
      : "No normalized schema change was recorded.";
  const impactTitle = singleAsset
    ? directLineage
      ? `${firstAssetName} is directly affected`
      : `${firstAssetName} is affected`
    : overview.impactTitle;
  const impactDetail = singleAsset
    ? `${overview.criticalityLabel} · ${overview.lineageLabel} · ${overview.ownerLabel} · ${overview.assertionLabel}`
    : `${overview.impactDetail} ${overview.lineageLabel}.`;
  const initialDecision = uppercaseText(overview.initialDecision);
  const initialState = !evidenceComplete
    ? { status: "REVIEW", state: "review", tone: "warning" }
    : initialDecision === "BLOCK"
      ? { status: "BLOCK", state: "blocked", tone: "danger" }
      : initialDecision === "PASS"
        ? { status: "PASS", state: "clear", tone: "success" }
        : { status: initialDecision || "REVIEW", state: "review", tone: "warning" };
  const impactState = !evidenceComplete
    ? { status: "REVIEW", state: "review", tone: "warning" }
    : singleAsset && criticalAsset && directLineage
      ? {
          status: `CRITICAL · DIRECT${hopCount !== undefined ? ` · ${hopCount} HOP${hopCount === 1 ? "" : "S"}` : ""}`,
          state: "recorded",
          tone: "danger",
        }
      : { status: "RECORDED", state: "recorded", tone: "neutral" };
  const currentResult =
    overview.initialScore !== undefined
      ? `${overview.initialScore} ${overview.initialDecision || ""}`.trim()
      : "Risk not recorded";
  const projectedResult =
    overview.residualScore !== undefined
      ? `${overview.residualScore} ${overview.residualDecision || ""}`.trim()
      : "Projection unavailable";

  const nodes = [
    {
      id: "change",
      order: 1,
      group: "trunk",
      label: "Change",
      value: overview.changeTitle,
      status: changesRecorded ? "RECORDED" : "REVIEW",
      state: changesRecorded ? "recorded" : "review",
      tone: changesRecorded ? "neutral" : "warning",
      title: overview.changeTitle,
      detail: changeDetail,
      targetId: "lineage",
      actionLabel: "View schema delta",
    },
    {
      id: "impact",
      order: 2,
      group: "trunk",
      label: "Impact",
      value: singleAsset ? overview.targetName : overview.impactTitle,
      status: impactState.status,
      state: impactState.state,
      tone: impactState.tone,
      title: impactTitle,
      detail: evidenceComplete ? impactDetail : "Impact evidence is incomplete. Do not assume no downstream effect.",
      targetId: "lineage",
      actionLabel: "View lineage evidence",
    },
    {
      id: "block",
      order: 3,
      group: "blocked",
      label: "Current result",
      value: currentResult,
      status: initialState.status,
      state: initialState.state,
      tone: initialState.tone,
      title: initialDecision === "BLOCK" ? "The current change is blocked" : "Current policy result",
      detail:
        overview.initialScore !== undefined
          ? `Score ${overview.initialScore} is the recorded result before remediation.`
          : "No current risk score was recorded.",
      targetId: "trajectory",
      actionLabel: "View risk inputs",
    },
    {
      id: "patch",
      order: 4,
      group: "patched",
      label: patchPassed ? "Tested patch" : "Patch",
      value: overview.artifactCountLabel,
      status: patchNodeState.status,
      state: patchNodeState.state,
      tone: patchNodeState.tone,
      title: overview.actionTitle,
      detail: patchPassed
        ? `${model.artifacts.length} generated files preserve ${overview.oldColumn} while consumers move to ${overview.newColumn}. Generated and tested in a temporary copy; application state is not recorded.`
        : overview.actionDetail,
      targetId: "remediation",
      actionLabel: "Inspect generated patch",
    },
    {
      id: "checks",
      order: 5,
      group: "patched",
      label: "Verification",
      value: overview.checksTitle,
      status: verificationNodeState.status,
      state: verificationNodeState.state,
      tone: verificationNodeState.tone,
      title: overview.checksTitle,
      detail: `${overview.checksDetail}${verifiedNodeCount ? ` · ${verifiedNodeCount} dbt nodes verified` : ""}.`,
      targetId: "verification",
      actionLabel: "View command output",
    },
    {
      id: "pass",
      order: 6,
      group: "patched",
      label: "Projected result",
      value: projectedResult,
      status: projectionVerified ? "PROJECTED" : "REVIEW",
      state: projectionVerified ? "passed" : "review",
      tone: projectionVerified ? "success" : "warning",
      title: projectionVerified ? "Projected to pass with the tested patch" : "Projection is not verified",
      detail:
        overview.residualScore !== undefined
          ? `Residual score ${overview.residualScore} is projected after the tested patch. Application state is not recorded.`
          : "No residual risk projection was recorded.",
      targetId: "trajectory",
      actionLabel: "View projected risk",
    },
    {
      id: "datahub",
      order: 7,
      group: "patched",
      label: "Decision record",
      value: datahubNodeState.value,
      status: datahubNodeState.status,
      state: datahubNodeState.state,
      tone: datahubNodeState.tone,
      title: datahubPassed ? "Decision record written and read back" : overview.writebackDetail,
      detail: datahubPassed
        ? `${overview.mutationCountLabel} mutation digests · ${overview.readbackCountLabel} readback digest entries · record ${overview.recordId}`
        : overview.writebackDetail,
      targetId: "passport",
      actionLabel: "View writeback proof",
    },
  ];

  const forkSummary =
    overview.initialScore !== undefined && overview.residualScore !== undefined && projectionVerified
      ? `The current path stops at ${currentResult}; the tested patch continues to ${projectedResult}.`
      : "Select a point to inspect its recorded evidence.";

  return {
    defaultId: projectionVerified ? "patch" : initialState.state === "blocked" ? "block" : "change",
    forkSummary,
    nodes,
    overview,
    commandCount,
    projectionVerified,
  };
};

const normalizeArtifact = (root) => {
  const initialCandidate = pick(root, [
    "initial_assessment",
    "initialAssessment",
    "initial_risk",
    "initialRisk",
    "risk_assessment",
    "riskAssessment",
    "analysis.initial_assessment",
    "analysis.risk",
    "assessment",
    "risk",
  ]);
  const residualCandidate = pick(root, [
    "residual_assessment",
    "residualAssessment",
    "residual_risk",
    "residualRisk",
    "counterfactual.assessment",
    "counterfactual",
    "remediation.residual_risk",
    "remediation.residual_assessment",
    "analysis.residual_assessment",
  ]);
  const initial = asRecord(initialCandidate);
  const residual = asRecord(residualCandidate);
  const passportCandidate = pick(root, [
    "passport",
    "change_passport",
    "changePassport",
    "datahub.passport",
  ]);
  const passport = asRecord(passportCandidate);
  const remediationCandidate = pick(root, [
    "remediation",
    "generated_remediation",
    "generatedRemediation",
  ]);
  const remediation = asRecord(remediationCandidate);
  const verificationCandidate =
    pick(root, ["verification", "remediation.verification"]) ??
    pick(remediation, ["verification"]);
  const verification =
    typeof verificationCandidate === "string"
      ? { status: verificationCandidate }
      : asRecord(verificationCandidate);
  const writebackCandidate =
    pick(root, ["writeback", "datahub.writeback", "passport.writeback"]) ??
    pick(passport, ["writeback"]);
  const writeback =
    typeof writebackCandidate === "string"
      ? { status: writebackCandidate }
      : asRecord(writebackCandidate);

  let changes = asArray(
    pick(root, [
      "changes",
      "schema_changes",
      "schemaChanges",
      "change_set.changes",
      "changeSet.changes",
      "analysis.changes",
      "initial_assessment.changes",
    ]),
  );
  if (!changes.length && isRecord(pick(root, ["change"]))) {
    changes = [pick(root, ["change"])];
  }

  let assets = asArray(
    pick(root, [
      "impacted_assets",
      "impactedAssets",
      "context.impacted_assets",
      "lineage.impacted_assets",
      "lineage.assets",
      "analysis.impacted_assets",
    ]),
  );
  if (!assets.length) {
    const urns = asArray(pick(initial, ["impacted_asset_urns", "impactedAssetUrns"]));
    assets = urns.map((urn) => ({ urn }));
  }

  let artifacts = asArray(
    pick(remediation, ["artifacts", "bundle.artifacts", "generated_artifacts"]) ??
      pick(root, [
      "remediation.artifacts",
      "remediation.bundle.artifacts",
      "remediation.generated_artifacts",
      "remediation_artifacts",
      "patch.artifacts",
      ]),
  );
  if (!artifacts.length && typeof remediationCandidate === "string") {
    artifacts = [{ path: "Recorded patch", unified_diff: remediationCandidate }];
  }
  if (!artifacts.length && typeof pick(remediation, ["diff", "patch", "unified_diff"]) === "string") {
    artifacts = [
      {
        path: pick(remediation, ["path", "target_path"]) || "Recorded patch",
        unified_diff: pick(remediation, ["unified_diff", "diff", "patch"]),
      },
    ];
  }

  const scalarInitialScore = asNumber(initialCandidate);
  const scalarResidualScore = asNumber(residualCandidate);
  const firstChange = asRecord(changes[0]);
  const contextSourceUrns = asArray(pick(root, ["context.source_urns"]));
  const source =
    pick(root, [
    "source_urn",
    "sourceUrn",
    "source.urn",
    "source.relation",
    "source",
    "relation",
    "dataset",
      "passport.source_urn",
    ]) ??
    pick(passport, ["source_urn", "sourceUrn"]) ??
    (contextSourceUrns.length ? contextSourceUrns.join(" · ") : undefined) ??
    pick(firstChange, ["relation", "dataset"]);
  const initialScore =
    scalarInitialScore ??
    asNumber(pick(initial, ["score", "risk_score", "riskScore", "original_risk"])) ??
    asNumber(pick(root, ["original_risk", "originalRisk", "passport.original_risk"]));
  const residualScore =
    scalarResidualScore ??
    asNumber(pick(residual, ["score", "risk_score", "riskScore", "residual_risk"])) ??
    asNumber(pick(root, ["passport.residual_risk"]));

  return {
    root,
    initial,
    residual,
    passport,
    remediation,
    verification,
    verificationCandidate,
    writeback,
    writebackCandidate,
    changes,
    assets,
    artifacts,
    source,
    initialScore,
    residualScore,
    initialDecision: pick(initial, ["decision", "score_decision", "scoreDecision"]),
    residualDecision: pick(residual, ["decision", "score_decision", "scoreDecision"]),
    finalDecision:
      pick(root, [
        "decision",
        "final_decision",
        "finalDecision",
        "passport.decision",
        "residual_assessment.decision",
        "initial_assessment.decision",
      ]) ?? pick(passport, ["decision"]),
    runId:
      pick(root, ["run_id", "runId", "id", "passport.run_id"]) ??
      pick(passport, ["run_id", "runId"]),
    timestamp: pick(root, [
      "completed_at",
      "completedAt",
      "created_at",
      "createdAt",
      "timestamp",
      "started_at",
    ]),
    commitSha:
      pick(root, [
        "commit_sha",
        "commitSha",
        "git.sha",
        "inputs.commit_sha",
        "passport.commit_sha",
      ]) ??
      pick(passport, ["commit_sha", "commitSha"]),
    analyzedInputState: pick(root, [
      "analyzed_input_state",
      "analyzedInputState",
      "inputs.analyzed_input_state",
      "inputs.analyzedInputState",
    ]),
    policyVersion:
      pick(root, [
        "policy_version",
        "policyVersion",
        "initial_assessment.policy_version",
        "risk_assessment.policy_version",
      ]) ?? pick(initial, ["policy_version", "policyVersion"]),
    evidenceHash:
      pick(root, [
        "evidence_hash",
        "evidenceHash",
        "passport.evidence_hash",
        "verification.evidence_digest",
      ]) ?? pick(passport, ["evidence_hash", "evidenceHash"]),
    artifactHash: pick(root, ["artifact_hash", "artifactHash"]),
    runStatus: pick(root, ["status", "run_status", "runStatus"]),
    assetRisks: asArray(pick(initial, ["asset_risks", "assetRisks"])),
    contextReasonCodes: asArray(pick(root, ["context.reason_codes"])),
  };
};

const showSystemState = (kind, title, message) => {
  const state = byId("system-state");
  const review = byId("review");
  state.hidden = false;
  state.className = `system-state ${kind ? `is-${kind}` : ""}`.trim();
  state.setAttribute("aria-busy", "false");
  setText("state-title", title);
  setText("state-message", message);
  const rule = state.querySelector(".loading-rule");
  if (rule) {
    rule.hidden = true;
  }
  review.hidden = true;
};

const fact = (term, value) => {
  const wrapper = create("div");
  wrapper.append(create("dt", "", term), create("dd", "", asText(value)));
  return wrapper;
};

const setDecisionStamp = (decision, note, forcedKind) => {
  const stamp = byId("decision-stamp");
  const kind = forcedKind || decisionKind(decision);
  stamp.className = `outcome-verdict is-${kind}`;
  setText("final-decision", decision, "Decision unavailable");
  setText("decision-note", note, "Evidence state unavailable");
};

const renderMapDetail = (node, nodes, reveal = false) => {
  document.querySelectorAll(".map-node").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.stepId === node.id));
  });
  setText("map-detail-count", `${node.order} / ${nodes.length}`);
  setText("map-detail-label", node.label);
  setText("map-detail-title", node.title);
  setText("map-detail-text", node.detail);
  const link = byId("map-detail-link");
  link.setAttribute("href", `#${node.targetId}`);
  link.textContent = node.actionLabel;
  if (
    reveal &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(max-width: 900px)").matches
  ) {
    byId("map-detail").scrollIntoView({ block: "nearest" });
  }
};

const renderDecisionFork = (model) => {
  const fork = buildDecisionFork(model);
  const targets = {
    trunk: byId("fork-trunk"),
    blocked: byId("fork-blocked"),
    patched: byId("fork-patched"),
  };
  Object.values(targets).forEach((target) => target.replaceChildren());

  fork.nodes.forEach((node) => {
    const button = create("button", `map-node is-${node.tone}`);
    button.type = "button";
    button.dataset.stepId = node.id;
    button.setAttribute("aria-controls", "map-detail");
    button.setAttribute("aria-pressed", "false");
    button.setAttribute("aria-label", `${node.label}: ${node.value}. ${node.status}`);

    const marker = create("span", "map-node-marker", String(node.order).padStart(2, "0"));
    marker.setAttribute("aria-hidden", "true");
    const copy = create("span", "map-node-copy");
    copy.append(
      create("span", "map-node-label", node.label),
      create("strong", "map-node-value", node.value),
      create("span", "map-node-status", node.status),
    );
    button.append(marker, copy);
    button.addEventListener("click", () => renderMapDetail(node, fork.nodes, true));
    targets[node.group].append(button);
  });

  setText("fork-summary", fork.forkSummary);
  const currentNode = fork.nodes.find((node) => node.id === "block");
  const projectedNode = fork.nodes.find((node) => node.id === "pass");
  const mobileProjection = fork.projectionVerified
    ? projectedNode?.value
    : "Projection unverified";
  setText("mobile-current-result", currentNode?.value);
  setText(
    "mobile-projected-label",
    fork.projectionVerified ? "With tested patch" : "Patch projection",
  );
  setText("mobile-projected-result", mobileProjection);
  byId("mobile-fork-compare").setAttribute(
    "aria-label",
    fork.projectionVerified
      ? `${currentNode?.value || "Current risk not recorded"} without the patch; ${projectedNode?.value || "projected risk not recorded"} with the tested patch.`
      : `${currentNode?.value || "Current risk not recorded"} without the patch; patch projection unverified.`,
  );
  setText(
    "blocked-branch-title",
    fork.nodes.find((node) => node.id === "block")?.state === "blocked"
      ? "Without patch"
      : "Current result",
  );
  setText(
    "patched-branch-title",
    fork.nodes.find((node) => node.id === "patch")?.state === "passed"
      ? "With tested patch"
      : "Patch path",
  );
  const selected = fork.nodes.find((node) => node.id === fork.defaultId) || fork.nodes[0];
  renderMapDetail(selected, fork.nodes);
  return fork.overview;
};

const renderOverview = (model) => {
  const overview = renderDecisionFork(model);
  setDecisionStamp(overview.verdictLabel, overview.note, overview.kind);
  setText("outcome-title", overview.title, "No decision is available");
  setText("outcome-summary", overview.summary, "No result is available for this run.");
  setText("raw-decision", overview.rawDecision);
};

const setupEvidenceLinks = () => {
  const details = byId("technical-evidence");
  document.querySelectorAll("[data-evidence-target]").forEach((link) => {
    link.addEventListener("click", (event) => {
      const target = document.querySelector(link.getAttribute("href"));
      if (!target) {
        return;
      }
      event.preventDefault();
      details.open = true;
      target.scrollIntoView({ block: "start" });
    });
  });
};

const setRiskMarker = (id, score) => {
  const marker = byId(id);
  const numeric = asNumber(score);
  if (numeric === undefined) {
    marker.hidden = true;
    return;
  }
  marker.hidden = false;
  marker.value = String(Math.max(0, Math.min(100, numeric)));
};

const renderRiskTrajectory = (model) => {
  setText("initial-score", model.initialScore, "—");
  setText("residual-score", model.residualScore, "—");
  setText("initial-decision", model.initialDecision);
  setText("residual-decision", model.residualDecision);
  setRiskMarker("initial-marker", model.initialScore);
  setRiskMarker("residual-marker", model.residualScore);

  const initialLabel =
    model.initialScore === undefined ? "not recorded" : `${model.initialScore} of 100`;
  const residualLabel =
    model.residualScore === undefined ? "not recorded" : `${model.residualScore} of 100`;
  byId("risk-rail").setAttribute(
    "aria-label",
    `Initial risk ${initialLabel}; residual risk ${residualLabel}.`,
  );

  const verificationStatus = pick(model.verification, ["status", "result.status"]);
  const remediationStatus = pick(model.remediation, ["status", "remediation_status"]);
  const writebackStatus = pick(model.writeback, ["state", "status", "writeback_status"]);
  const stages = [
    ["Run status", model.runStatus || "Not recorded", statusClass(model.runStatus)],
    ["Initial risk", model.initialDecision || model.initialScore, statusClass(model.initialDecision)],
    [
      "Lineage",
      model.assets.length ? `${model.assets.length} asset record${model.assets.length === 1 ? "" : "s"}` : "Not recorded",
      model.assets.length ? "is-recorded" : "",
    ],
    [
      "Remediation",
      remediationStatus || (model.artifacts.length ? "Patch recorded" : "Not recorded"),
      statusClass(remediationStatus) || (model.artifacts.length ? "is-recorded" : ""),
    ],
    ["dbt verify", verificationStatus || "Not recorded", statusClass(verificationStatus)],
    [
      "Residual risk",
      model.residualDecision || model.residualScore || "Not recorded",
      statusClass(model.residualDecision),
    ],
    ["DataHub", writebackStatus || "Not recorded", statusClass(writebackStatus)],
  ];
  const track = byId("stage-track");
  track.replaceChildren();
  for (const [name, status, className] of stages) {
    const item = create("li", className);
    item.append(create("strong", "", name), create("span", "", asText(status)));
    track.append(item);
  }
};

const renderChanges = (changes) => {
  const body = byId("change-rows");
  body.replaceChildren();
  byId("change-empty").hidden = changes.length !== 0;
  for (const rawChange of changes) {
    const change = asRecord(rawChange);
    const beforeParts = [
      pick(change, ["old_column", "oldColumn"]),
      pick(change, ["old_type", "oldType"]),
    ].filter((value) => value !== undefined && value !== null);
    const afterParts = [
      pick(change, ["new_column", "newColumn"]),
      pick(change, ["new_type", "newType"]),
    ].filter((value) => value !== undefined && value !== null);
    const row = create("tr");
    for (const value of [
      pick(change, ["change_type", "changeType", "type"]),
      pick(change, ["relation", "dataset", "dataset_urn"]),
      beforeParts.length ? beforeParts.join(" · ") : undefined,
      afterParts.length ? afterParts.join(" · ") : undefined,
      pick(change, ["confidence", "evidence_status"]),
    ]) {
      row.append(create("td", "", asText(value)));
    }
    body.append(row);
  }
};

const explicitListText = (value, emptyLabel) => {
  if (value === undefined || value === null) {
    return "Not recorded";
  }
  if (Array.isArray(value) && value.length === 0) {
    return emptyLabel;
  }
  return asText(value);
};

const renderAssets = (assets, assetRisks) => {
  const list = byId("lineage-list");
  list.replaceChildren();
  byId("lineage-empty").hidden = assets.length !== 0;
  setText(
    "lineage-summary",
    assets.length
      ? `${assets.length} impacted asset record${assets.length === 1 ? "" : "s"}, ordered by recorded hop.`
      : "No impacted asset records loaded.",
  );

  const ordered = assets
    .map((value, index) => ({
      value: typeof value === "string" ? { urn: value } : asRecord(value),
      index,
    }))
    .sort((left, right) => {
      const leftHop = asNumber(pick(left.value, ["hop_count", "hopCount", "hop"])) ?? 999;
      const rightHop = asNumber(pick(right.value, ["hop_count", "hopCount", "hop"])) ?? 999;
      if (leftHop !== rightHop) {
        return leftHop - rightHop;
      }
      return asText(pick(left.value, ["urn", "id"]), "").localeCompare(
        asText(pick(right.value, ["urn", "id"]), ""),
      );
    });

  const scores = new Map();
  for (const rawRisk of assetRisks) {
    const risk = asRecord(rawRisk);
    const urn = pick(risk, ["asset_urn", "assetUrn", "urn"]);
    const score = pick(risk, ["score", "risk_score", "riskScore"]);
    if (typeof urn === "string" && score !== undefined) {
      scores.set(urn, score);
    }
  }

  for (const entry of ordered) {
    const item = entry.value;
    const hop = asNumber(pick(item, ["hop_count", "hopCount", "hop"]));
    const urn = pick(item, ["urn", "asset_urn", "assetUrn", "id"]);
    const name = pick(item, ["display_name", "displayName", "name", "title"]);
    const kind = pick(item, ["asset_type", "assetType", "entity_type", "type"]);
    const owners = pick(item, ["owners", "owner_urns", "ownerUrns"]);
    const assertions = pick(item, [
      "assertion_urns",
      "assertionUrns",
      "assertions",
      "contracts",
    ]);
    const risk = pick(item, ["score", "risk_score", "riskScore"]) ?? scores.get(urn);

    const node = create("li", "lineage-node");
    node.dataset.hop = String(Math.max(0, Math.min(5, Math.round(hop ?? 0))));
    const hopLabel = create("div", "lineage-hop", hop === undefined ? "HOP —" : `HOP ${hop}`);
    const identity = create("div", "lineage-identity");
    identity.append(
      create("span", "asset-kind", asText(kind, "Asset")),
      create("strong", "", asText(name || urn, "Unnamed asset")),
      create("small", "", asText(urn)),
    );
    const evidence = create("div", "lineage-evidence");
    const details = create("dl");
    details.append(
      create("dt", "", "Owner"),
      create("dd", "", explicitListText(owners, "None reported")),
      create("dt", "", "Assertions"),
      create("dd", "", explicitListText(assertions, "None reported")),
      create("dt", "", "Asset risk"),
      create("dd", "", asText(risk)),
    );
    evidence.append(details);
    node.append(hopLabel, identity, evidence);
    list.append(node);
  }
};

const artifactText = (artifact) =>
  asText(
    pick(artifact, ["unified_diff", "unifiedDiff", "diff", "patch", "content"]),
    "",
  );

const renderDiff = (artifact) => {
  const diff = artifactText(artifact);
  const view = byId("diff-view");
  const empty = byId("diff-empty");
  view.replaceChildren();
  if (!diff) {
    view.hidden = true;
    empty.hidden = false;
    empty.textContent = "This artifact has no recorded diff or content body.";
    return;
  }
  empty.hidden = true;
  view.hidden = false;
  for (const line of diff.split("\n")) {
    let className = "diff-line";
    if (line.startsWith("@@")) {
      className += " is-hunk";
    } else if (line.startsWith("+") && !line.startsWith("+++")) {
      className += " is-addition";
    } else if (line.startsWith("-") && !line.startsWith("---")) {
      className += " is-removal";
    }
    view.append(create("span", className, line), document.createTextNode("\n"));
  }
};

const renderArtifacts = (artifacts) => {
  const tabs = byId("artifact-tabs");
  tabs.replaceChildren();
  if (!artifacts.length) {
    byId("diff-view").hidden = true;
    byId("diff-empty").hidden = false;
    byId("diff-panel").removeAttribute("aria-labelledby");
    return;
  }

  const records = artifacts.map((value, index) =>
    typeof value === "string"
      ? { path: `Artifact ${index + 1}`, content: value }
      : asRecord(value),
  );
  const select = (selectedIndex) => {
    Array.from(tabs.children).forEach((button, index) => {
      button.setAttribute("aria-selected", index === selectedIndex ? "true" : "false");
      button.tabIndex = index === selectedIndex ? 0 : -1;
    });
    byId("diff-panel").setAttribute("aria-labelledby", `artifact-tab-${selectedIndex}`);
    renderDiff(records[selectedIndex]);
  };

  records.forEach((artifact, index) => {
    const button = create(
      "button",
      "",
      asText(pick(artifact, ["path", "target_path", "name"]), `Artifact ${index + 1}`),
    );
    button.type = "button";
    button.id = `artifact-tab-${index}`;
    button.setAttribute("role", "tab");
    button.setAttribute("aria-controls", "diff-panel");
    button.setAttribute("aria-selected", index === 0 ? "true" : "false");
    button.tabIndex = index === 0 ? 0 : -1;
    button.addEventListener("click", () => select(index));
    button.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
        return;
      }
      event.preventDefault();
      let next;
      if (event.key === "Home") {
        next = 0;
      } else if (event.key === "End") {
        next = records.length - 1;
      } else {
        const direction = event.key === "ArrowRight" ? 1 : -1;
        next = (index + direction + records.length) % records.length;
      }
      select(next);
      tabs.children[next].focus();
    });
    tabs.append(button);
  });
  renderDiff(records[0]);
};

const renderVerification = (verification) => {
  const status = pick(verification, ["status", "result.status"]);
  const digest = pick(verification, ["evidence_digest", "evidenceDigest", "digest"]);
  const failure = pick(verification, ["failure_reason", "failureReason", "reason"]);
  setText(
    "verification-summary",
    status
      ? `${asText(status)} · evidence ${compact(digest, 14)}${failure ? ` · ${asText(failure)}` : ""}`
      : "No verification result loaded.",
  );
  const commands = asArray(pick(verification, ["commands", "results", "command_results"]));
  const list = byId("command-list");
  list.replaceChildren();
  byId("command-empty").hidden = commands.length !== 0;

  for (const rawCommand of commands) {
    const command =
      typeof rawCommand === "string" || Array.isArray(rawCommand)
        ? { command: rawCommand }
        : asRecord(rawCommand);
    const exitCode = asNumber(pick(command, ["exit_code", "exitCode", "returncode"]));
    const explicitStatus = pick(command, ["status"]);
    const commandStatus =
      explicitStatus || (exitCode === undefined ? "Not recorded" : `EXIT ${exitCode}`);
    const item = create("li", "command-entry");
    const statusNode = create(
      "div",
      `command-status ${
        exitCode === 0 || decisionKind(commandStatus) === "pass"
          ? "is-success"
          : exitCode !== undefined || decisionKind(commandStatus) === "block"
            ? "is-failure"
            : ""
      }`.trim(),
      asText(commandStatus),
    );
    const body = create("div", "command-body");
    const argv = pick(command, ["command", "argv"]);
    body.append(create("code", "", Array.isArray(argv) ? argv.join(" ") : asText(argv)));
    const output = pick(command, ["output_tail", "output", "stdout", "stderr"]);
    if (typeof output === "string" && output.trim()) {
      const details = create("details");
      details.append(create("summary", "", "Captured output"), create("pre", "", output));
      body.append(details);
    }
    const duration = pick(command, ["duration_ms", "durationMs", "duration"]);
    const digestValue = pick(command, ["output_digest", "outputDigest", "digest"]);
    const meta = create(
      "div",
      "command-meta",
      `${duration === undefined ? "time —" : `${duration} ms`}\n${compact(digestValue, 12)}`,
    );
    item.append(statusNode, body, meta);
    list.append(item);
  }
};

const renderContributions = (model) => {
  const contributions = asArray(pick(model.initial, ["contributions", "breakdown"]));
  const overrideReasons = asArray(
    pick(model.initial, ["decision_override.reason_codes", "decisionOverride.reasonCodes"]),
  );
  const reasonCodes = [...new Set([...overrideReasons, ...model.contextReasonCodes])];
  const list = byId("contribution-list");
  list.replaceChildren();
  byId("contribution-empty").hidden = contributions.length !== 0 || reasonCodes.length !== 0;
  for (const rawContribution of contributions) {
    const contribution = asRecord(rawContribution);
    const points = asNumber(pick(contribution, ["points", "score", "value"]));
    const item = create(
      "li",
      points === undefined ? "" : points < 0 ? "is-negative" : "is-positive",
    );
    item.append(
      create("strong", "", asText(pick(contribution, ["key", "name", "category"]))),
      create("span", "", points === undefined ? "—" : `${points > 0 ? "+" : ""}${points}`),
      create("small", "", asText(pick(contribution, ["explanation", "reason"]))),
    );
    list.append(item);
  }
  for (const reason of reasonCodes) {
    const item = create("li", "is-negative");
    item.append(
      create("strong", "", "Fail-closed reason"),
      create("span", "", "!"),
      create("small", "", asText(reason)),
    );
    list.append(item);
  }
};

const renderResidual = (model) => {
  const facts = byId("residual-facts");
  facts.replaceChildren(
    fact("Residual score", model.residualScore),
    fact("Residual decision", model.residualDecision),
    fact("Counterfactual verified", pick(model.remediation, ["counterfactual_verified"])),
    fact("Interface preserved", pick(model.remediation, ["interface_preserved"])),
    fact(
      "Counterfactual condition",
      pick(model.remediation, ["counterfactual_condition"]),
    ),
    fact(
      "Counterfactual evidence",
      compact(pick(model.remediation, ["counterfactual_evidence_digest"]), 20),
    ),
    fact(
      "Preserved expression",
      compact(pick(model.remediation, ["preserved_expression_fingerprint"]), 20),
    ),
    fact(
      "Preserved contract",
      compact(pick(model.remediation, ["preserved_contract_sha256"]), 20),
    ),
    fact(
      "Query context",
      compact(pick(model.remediation, ["preserved_query_context_sha256"]), 20),
    ),
    fact(
      "Baseline manifest",
      compact(pick(model.remediation, ["baseline_manifest_sha256"]), 20),
    ),
    fact(
      "Patched manifest",
      compact(pick(model.verification, ["patched_manifest_sha256"]), 20),
    ),
    fact(
      "dbt run results",
      compact(pick(model.verification, ["run_results_digest"]), 20),
    ),
    fact("Verified dbt nodes", pick(model.verification, ["verified_node_ids"])),
    fact(
      "Residual changes",
      asArray(pick(model.remediation, ["residual_changes"])).length,
    ),
    fact(
      "Confidence override",
      pick(model.residual, ["decision_override.minimum_decision", "decisionOverride.minimumDecision"]),
    ),
    fact(
      "Override reasons",
      pick(model.residual, ["decision_override.reason_codes", "override_reasons", "reason_codes"]),
    ),
  );
};

const renderWriteback = (model) => {
  const status =
    pick(model.writeback, ["state", "status", "writeback_status"]) ||
    (typeof model.writebackCandidate === "string" ? model.writebackCandidate : undefined);
  const mutationDigests = asArray(
    pick(model.writeback, ["mutation_digests", "mutationDigests", "mutations"]),
  );
  const readbackDigests = asArray(
    pick(model.writeback, ["readback_digests", "readbackDigests", "readbacks"]),
  );
  const documentUrn = pick(model.writeback, ["document_urn", "documentUrn"]);
  const notRequested = asText(status, "").toUpperCase() === "NOT_REQUESTED";
  const timeline = byId("writeback-timeline");
  timeline.replaceChildren();

  const appendStage = (name, detail, className = "") => {
    const item = create("li", className);
    item.append(create("strong", "", name), create("small", "", asText(detail)));
    timeline.append(item);
  };
  appendStage("Writeback", status || "Not recorded", statusClass(status));
  appendStage(
    "MCP mutations",
    mutationDigests.length
      ? `${mutationDigests.length} digest${mutationDigests.length === 1 ? "" : "s"} recorded`
      : notRequested
        ? "Not requested"
        : "Not recorded",
    mutationDigests.length ? "is-recorded" : "",
  );
  appendStage(
    "MCP readback",
    readbackDigests.length
      ? `${readbackDigests.length} digest${readbackDigests.length === 1 ? "" : "s"} recorded`
      : notRequested
        ? "Not requested"
        : "Not recorded",
    asText(status, "").toUpperCase() === "VERIFIED" ? "is-success" : statusClass(status),
  );

  const facts = byId("passport-facts");
  facts.replaceChildren(
    fact("Document URN", documentUrn),
    fact("Decision evidence hash", model.evidenceHash),
    fact("Final artifact hash", model.artifactHash),
    fact("Mutation digests", mutationDigests),
    fact("Readback digests", readbackDigests),
    fact("Reason", pick(model.writeback, ["reason", "failure_reason"])),
  );

  const verified = asText(status, "").toUpperCase() === "VERIFIED";
  setText("passport-signature", model.evidenceHash ? compact(model.evidenceHash, 22) : undefined);
  setText("seal-writeback", status);
  setText("seal-readback", verified ? "VERIFIED" : readbackDigests.length ? "RECORDED" : undefined);
  const seal = byId("seal-status");
  seal.className = verified ? "is-verified" : "";
  seal.textContent = verified
    ? "READBACK VERIFIED"
    : model.evidenceHash
      ? "EVIDENCE HASH RECORDED"
      : "NOT RECORDED";
};

const renderReview = (root) => {
  const model = normalizeArtifact(root);
  const state = byId("system-state");
  state.hidden = true;
  state.setAttribute("aria-busy", "false");
  byId("review").hidden = false;

  setText("header-run", model.runId || model.source, "Latest artifact");
  setText("run-id", compact(model.runId, 24));
  setText("commit-sha", compact(model.commitSha, 18));
  setText("analyzed-input-state", model.analyzedInputState, "Legacy artifact");
  setText("policy-version", model.policyVersion);
  setText("artifact-hash", compact(model.artifactHash, 20));
  setText("run-timestamp", formatTimestamp(model.timestamp), "Time not recorded");

  renderOverview(model);
  renderRiskTrajectory(model);
  renderChanges(model.changes);
  renderAssets(model.assets, model.assetRisks);
  setText(
    "remediation-summary",
    pick(model.remediation, ["status", "remediation_status"]) ||
      (model.artifacts.length
        ? `${model.artifacts.length} generated artifact${model.artifacts.length === 1 ? "" : "s"} recorded.`
        : undefined),
    "No remediation status loaded.",
  );
  renderArtifacts(model.artifacts);
  renderVerification(model.verification);
  renderContributions(model);
  renderResidual(model);
  renderWriteback(model);
  setText("artifact-status", `Loaded ${compact(model.runId || model.source || "latest artifact", 32)}`);
};

const loadLatestRun = async () => {
  const reload = byId("reload-run");
  reload.disabled = true;
  reload.textContent = "Reading…";
  try {
    const response = await fetch("/api/runs/latest", {
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    let payload;
    try {
      payload = await response.json();
    } catch {
      showSystemState("error", "The review API returned an unreadable response", "Reload the local server and try again.");
      return;
    }
    if (!response.ok) {
      const kind = response.status === 404 ? "empty" : "error";
      const title =
        kind === "empty" ? "No run has been recorded yet" : "The latest run cannot be reviewed";
      showSystemState(kind, title, asText(payload.message, "The local artifact is unavailable."));
      setText("header-run", kind === "empty" ? "No latest run" : "Artifact error");
      return;
    }
    const run = isRecord(payload) && "run" in payload ? payload.run : payload;
    if (!isRecord(run) || Object.keys(run).length === 0) {
      showSystemState(
        "error",
        "The artifact has no reviewable run object",
        "The JSON is readable, but no recorded run fields are present.",
      );
      setText("header-run", "Artifact has no run object");
      return;
    }
    renderReview(run);
  } catch {
    showSystemState(
      "error",
      "The local review server is unavailable",
      "The run record could not be requested. Check the local server and reload.",
    );
    setText("header-run", "Review API unavailable");
  } finally {
    reload.disabled = false;
    reload.textContent = "Reload";
  }
};

if (typeof document !== "undefined") {
  setupEvidenceLinks();
  byId("reload-run").addEventListener("click", loadLatestRun);
  loadLatestRun();
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { buildDecisionFork, buildOverview, normalizeArtifact };
}
