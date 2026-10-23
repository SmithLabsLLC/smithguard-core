"""Synthetic source-governance fixtures with no production or legal claim."""

from __future__ import annotations

import json
from datetime import UTC
from pathlib import Path
from typing import Any

from smithguard.acquisition import AcquisitionRequest
from smithguard.identifiers import sha256_id
from smithguard.source_governance import SourceAuthorization, SourceGovernancePolicy
from smithguard.source_rights import RightsRegistry

REPO_ROOT = Path(__file__).resolve().parents[1]
RIGHTS_REGISTER = REPO_ROOT / "contracts/v1/source-rights-register.json"
GOVERNANCE_POLICY = REPO_ROOT / "contracts/v1/source-governance-policy.json"
SYNTHETIC_QUALIFIED_DECISION = "gbsec:publication-decision:synthetic-test-only"


def active_governance_policy(
    *source_ids: str,
) -> SourceGovernancePolicy:
    """Return a test-only active policy without changing the tracked pending gate."""
    if not source_ids:
        source_ids = ("gbsec:source:github-advisory-database",)
    document = json.loads(GOVERNANCE_POLICY.read_text(encoding="utf-8"))
    document["publication_decision"] = {
        "state": "active",
        "decision_id": SYNTHETIC_QUALIFIED_DECISION,
        "decided_at": "2026-08-05T00:00:00Z",
        "source_ids": list(source_ids),
    }
    document["evidence_disposition"]["authorized_adapter_ids"] = [
        "synthetic-disposition-adapter-v1"
    ]
    for source in document["sources"]:
        if source["source_id"] not in source_ids:
            continue
        source["enabled"] = True
        for evidence in source["rights_evidence"]:
            evidence["state"] = "verified_snapshot"
            evidence["content_sha256"] = sha256_id(
                json.dumps(evidence["url"], ensure_ascii=True).encode("ascii")
            )
    return SourceGovernancePolicy(
        document,
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
    )


def synthetic_authorization(
    *,
    source: dict[str, Any],
    request: AcquisitionRequest,
    acquisition_method: str,
    accepted_field_paths: tuple[str, ...] = ("records",),
    operating_mode: str = "exact_lookup",
) -> SourceAuthorization:
    """Build a bounded unit-test authorization for the generic ingestion service."""
    return SourceAuthorization(
        policy_id="gbsec:source-governance-policy:synthetic-test-v1",
        policy_version="1.0.0",
        policy_sha256="sha256:" + "a" * 64,
        rights_register_id="gbsec:rights-register:phase-0a-v1",
        authorized_disposition_adapter_ids=("synthetic-disposition-adapter-v1",),
        source_id=source["id"],
        connector_id="gbsec:connector:synthetic-test-v1",
        acquisition_method=acquisition_method,
        operating_mode=operating_mode,
        field_policy_id="gbsec:field-policy:synthetic-test-v1",
        accepted_field_paths=accepted_field_paths,
        attribution_text=source["rights"]["attribution_text"],
        license_expression=source["rights"]["license_expression"],
        rights_evidence_ids=("gbsec:rights-evidence:synthetic-test-v1",),
        rights_evidence_verified=True,
        retention_behavior=source["rights"]["retention"],
        public_status_ceiling="confirmed",
        correction_behavior="append_corrected_revision",
        withdrawal_behavior=source["withdrawal_behavior"],
        rights_drift_behavior="fail_closed_and_reconcile",
        qualified_publication_decision_id=SYNTHETIC_QUALIFIED_DECISION,
        canonical_url=request.canonical_url,
        source_record_id=request.source_record_id,
        authorized_at=request.retrieved_at.astimezone(UTC),
    )
