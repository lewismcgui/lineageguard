"""Bounded remediation generation public API."""

from lineageguard.remediation.counterfactual import (
    CounterfactualCondition,
    CounterfactualError,
    CounterfactualResult,
    verify_remediation_counterfactual,
)
from lineageguard.remediation.generator import (
    AmbiguousRemediationError,
    GeneratedArtifact,
    RemediationBundle,
    RemediationError,
    RemediationGenerator,
    UnsafePathError,
    UnsupportedRemediationError,
    generate_rename_remediation,
)
from lineageguard.remediation.verifier import (
    CommandResult,
    ManifestSnapshot,
    RemediationVerifier,
    VerificationError,
    VerificationResult,
    VerificationStatus,
    snapshot_dbt_manifest,
)

__all__ = [
    "AmbiguousRemediationError",
    "CommandResult",
    "CounterfactualCondition",
    "CounterfactualError",
    "CounterfactualResult",
    "GeneratedArtifact",
    "ManifestSnapshot",
    "RemediationBundle",
    "RemediationError",
    "RemediationGenerator",
    "RemediationVerifier",
    "UnsafePathError",
    "UnsupportedRemediationError",
    "VerificationError",
    "VerificationResult",
    "VerificationStatus",
    "generate_rename_remediation",
    "snapshot_dbt_manifest",
    "verify_remediation_counterfactual",
]
