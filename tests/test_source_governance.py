"""Versioned source governance fails closed before storage and publication."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.db.models import SourceGovernanceDecisionRecord
from smithguard.identifiers import sha256_id
from smithguard.source_governance import (
    SourceGovernanceError,
    SourceGovernancePolicy,
    append_governance_decision,
    governance_policy_sha256,
)
from smithguard.source_rights import RightsRegistry

from .governance_fixtures import active_governance_policy

REPO_ROOT = Path(__file__).resolve().parents[1]
RIGHTS_REGISTER = REPO_ROOT / "contracts/v1/source-rights-register.json"
GOVERNANCE_POLICY = REPO_ROOT / "contracts/v1/source-governance-policy.json"
NOW = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
GITHUB_SOURCE = "gbsec:source:github-advisory-database"
GITHUB_CONNECTOR = "gbsec:connector:github-advisory-rest-v1"
OSV_SOURCE = "gbsec:source:osv-dev"
OSV_CONNECTOR = "gbsec:connector:osv-gateway-v1"


def _tracked_policy() -> SourceGovernancePolicy:
    return SourceGovernancePolicy.from_path(
        GOVERNANCE_POLICY,
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
    )


def _authorize(policy: SourceGovernancePolicy):
    return policy.authorize_collection(
        connector_id=GITHUB_CONNECTOR,
        source_id=GITHUB_SOURCE,
        acquisition_method="rest_api",
        operating_mode="updates",
        canonical_url="https://github.com/advisories/GHSA-aaaa-bbbb-9999",
        source_record_id="GHSA-aaaa-bbbb-9999:2026-08-06T12:00:00Z",
        authorized_at=NOW,
    )


def test_tracked_policy_is_active_and_projects_nested_fields_before_storage() -> None:
    policy = _tracked_policy()
    authorization = _authorize(policy)
    assert authorization.authorized_disposition_adapter_ids == ()
    body = json.dumps(
        [
            {
                "ghsa_id": "GHSA-aaaa-bbbb-9999",
                "type": "malware",
                "published_at": "2026-08-06T11:00:00Z",
                "updated_at": "2026-08-06T12:00:00Z",
                "withdrawn_at": None,
                "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-9999",
                "identifiers": [{"type": "GHSA", "value": "GHSA-aaaa-bbbb-9999"}],
                "references": ["https://github.com/advisories/GHSA-aaaa-bbbb-9999"],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "npm", "name": "synthetic"},
                        "vulnerable_version_range": "= 1.0.0",
                        "first_patched_version": "1.0.1",
                    }
                ],
                "summary": "must not be retained",
                "credits": [{"user": {"login": "must-not-be-retained"}}],
            }
        ],
        sort_keys=True,
    ).encode("utf-8")
    projected = json.loads(authorization.project_body(body))
    assert projected[0]["ghsa_id"] == "GHSA-aaaa-bbbb-9999"
    assert "withdrawn_at" in projected[0] and projected[0]["withdrawn_at"] is None
    assert "summary" not in projected[0]
    assert "credits" not in projected[0]
    assert projected[0]["vulnerabilities"][0]["first_patched_version"] == "1.0.1"
    assert authorization.field_policy_id == "gbsec:field-policy:github-advisory-catalog-v3"
    assert authorization.policy_version == "1.2.0"
    enveloped = json.loads(
        authorization.project_body(
            json.dumps({"schema_version": "1.0.0", "records": json.loads(body)}).encode("ascii")
        )
    )
    assert enveloped == {"records": projected}
    assert (
        authorization.qualified_publication_decision_id
        == "gbsec:qualified-publication-decision:authoritative-feeds-20261006-v1"
    )
    assert authorization.rights_evidence_verified
    assert governance_policy_sha256() == policy.policy_sha256


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("connector_id", "gbsec:connector:openssf-git-v1", "connector"),
        ("acquisition_method", "git", "acquisition method"),
        ("operating_mode", "exact_lookup", "operating mode"),
        (
            "canonical_url",
            "https://example.test/advisories/GHSA-aaaa-bbbb-9999",
            "host boundary",
        ),
    ),
)
def test_collection_rejects_connector_method_mode_and_url_mismatch(
    field: str,
    value: str,
    message: str,
) -> None:
    arguments = {
        "connector_id": GITHUB_CONNECTOR,
        "source_id": GITHUB_SOURCE,
        "acquisition_method": "rest_api",
        "operating_mode": "updates",
        "canonical_url": "https://github.com/advisories/GHSA-aaaa-bbbb-9999",
        "source_record_id": "GHSA-aaaa-bbbb-9999:2026-08-06T12:00:00Z",
        "authorized_at": NOW,
    }
    arguments[field] = value
    with pytest.raises(SourceGovernanceError, match=message):
        _tracked_policy().authorize_collection(**arguments)


def test_policy_shape_tamper_duplicate_connector_and_unverified_dispatch_fail() -> None:
    document = json.loads(GOVERNANCE_POLICY.read_text(encoding="utf-8"))
    unexpected = deepcopy(document)
    unexpected["unexpected"] = True
    with pytest.raises(SourceGovernanceError, match="invalid shape"):
        SourceGovernancePolicy(
            unexpected,
            registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        )

    duplicated = deepcopy(document)
    duplicated["sources"][1]["connectors"][0]["connector_id"] = GITHUB_CONNECTOR
    with pytest.raises(SourceGovernanceError, match="duplicated"):
        SourceGovernancePolicy(
            duplicated,
            registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        )

    wrong_terms = deepcopy(document)
    wrong_terms["sources"][0]["rights_evidence"][0]["url"] = (
        "https://docs.github.com/en/site-policy/github-terms/github-terms-of-service"
    )
    with pytest.raises(SourceGovernanceError, match="differs from the reviewed source rights"):
        SourceGovernancePolicy(
            wrong_terms,
            registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        )

    postdated_evidence = deepcopy(document)
    postdated_evidence["sources"][0]["rights_evidence"][0]["captured_on"] = "2026-08-08"
    with pytest.raises(SourceGovernanceError, match="captured after"):
        SourceGovernancePolicy(
            postdated_evidence,
            registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        )

    changed_retention = deepcopy(document)
    changed_retention["sources"][0]["retention_behavior"] = "until_withdrawn"
    with pytest.raises(SourceGovernanceError, match="retention differs"):
        SourceGovernancePolicy(
            changed_retention,
            registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        )

    changed_withdrawal = deepcopy(document)
    changed_withdrawal["sources"][0]["withdrawal_behavior"] = "remove_raw_keep_minimal_tombstone"
    with pytest.raises(SourceGovernanceError, match="withdrawal differs"):
        SourceGovernancePolicy(
            changed_withdrawal,
            registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        )

    duplicate_adapters = deepcopy(document)
    duplicate_adapters["evidence_disposition"]["authorized_adapter_ids"] = [
        "synthetic-disposition-adapter-v1",
        "synthetic-disposition-adapter-v1",
    ]
    with pytest.raises(SourceGovernanceError, match="adapter IDs"):
        SourceGovernancePolicy(
            duplicate_adapters,
            registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        )

    broken_history = deepcopy(document)
    broken_history["rights_evidence_history"][0]["superseded_by"] = "gbsec:rights-evidence:missing"
    with pytest.raises(SourceGovernanceError, match="history identity"):
        SourceGovernancePolicy(
            broken_history,
            registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        )

    broadened_shadow = deepcopy(document)
    broadened_shadow["gateway_shadow_field_policies"][0]["accepted_field_paths"].append("summary")
    broadened_policy = SourceGovernancePolicy(
        broadened_shadow,
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
    )
    with pytest.raises(SourceGovernanceError, match="projection exceeds"):
        broadened_policy.authorize_gateway_shadow(
            gateway_connector_id=OSV_CONNECTOR,
            upstream_source_id=GITHUB_SOURCE,
            canonical_url="https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-9999",
            source_record_id="GHSA-aaaa-bbbb-9999",
            authorized_at=NOW,
        )

    rights_document = json.loads(RIGHTS_REGISTER.read_text(encoding="utf-8"))
    github_profile = next(
        profile
        for profile in rights_document["source_profiles"]
        if profile["source"]["id"] == GITHUB_SOURCE
    )
    github_profile["field_rules"][1]["fields"].append("aliases")
    origin_restricted_policy = SourceGovernancePolicy(
        document,
        registry=RightsRegistry(rights_document),
    )
    with pytest.raises(SourceGovernanceError, match="projection exceeds"):
        origin_restricted_policy.authorize_gateway_shadow(
            gateway_connector_id=OSV_CONNECTOR,
            upstream_source_id=GITHUB_SOURCE,
            canonical_url="https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-9999",
            source_record_id="GHSA-aaaa-bbbb-9999",
            authorized_at=NOW,
        )

    policy = _tracked_policy()
    with pytest.raises(SourceGovernanceError, match="disabled"):
        policy.resolve_authenticated_upstream(
            gateway_connector_id="gbsec:connector:osv-gateway-v1",
            upstream_source_id=GITHUB_SOURCE,
            authorized_at=NOW,
        )


def test_active_test_policy_enforces_status_ceiling_and_decision_replay(database) -> None:
    policy = active_governance_policy()
    authorization = _authorize(policy)
    assert authorization.authorized_disposition_adapter_ids == ("synthetic-disposition-adapter-v1",)
    accepted_sha256 = sha256_id(b"synthetic accepted source representation")
    with Session(database.engine) as session, session.begin():
        first, created = append_governance_decision(
            session,
            authorization=authorization,
            accepted_sha256=accepted_sha256,
            decided_at=NOW,
        )
        assert created
        repeated, created = append_governance_decision(
            session,
            authorization=authorization,
            accepted_sha256=accepted_sha256,
            decided_at=NOW,
        )
        assert not created
        assert repeated.decision_id == first.decision_id
        policy.authorize_stored_publication(first, public_status="contained")
        policy.authorize_stored_publication(first, public_status="resolved")
        assert session.scalar(select(func.count()).select_from(SourceGovernanceDecisionRecord)) == 1


def test_governance_decision_preserves_legacy_mode_and_scopes_a_second_mode(
    database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import smithguard.source_governance as source_governance_module

    policy = active_governance_policy()
    updates = _authorize(policy)
    historical = replace(updates, operating_mode="historical")
    accepted_sha256 = sha256_id(b"synthetic cross-mode representation")
    original_stable_id = source_governance_module.stable_id

    def legacy_mode_omitting_stable_id(namespace: str, *parts: str) -> str:
        if namespace == "source-governance-decision" and len(parts) == 5:
            parts = (*parts[:3], parts[4])
        return original_stable_id(namespace, *parts)

    with Session(database.engine) as session, session.begin():
        with monkeypatch.context() as scoped:
            scoped.setattr(
                source_governance_module,
                "stable_id",
                legacy_mode_omitting_stable_id,
            )
            legacy, created = append_governance_decision(
                session,
                authorization=updates,
                accepted_sha256=accepted_sha256,
                decided_at=NOW,
            )
        assert created

        replay, created = append_governance_decision(
            session,
            authorization=updates,
            accepted_sha256=accepted_sha256,
            decided_at=NOW,
        )
        assert not created
        assert replay.decision_id == legacy.decision_id

        second_mode, created = append_governance_decision(
            session,
            authorization=historical,
            accepted_sha256=accepted_sha256,
            decided_at=NOW,
        )
        assert created
        assert second_mode.decision_id != legacy.decision_id
        assert second_mode.operating_mode == "historical"
        assert session.scalar(select(func.count()).select_from(SourceGovernanceDecisionRecord)) == 2


def test_internal_only_gateway_can_dispatch_but_cannot_authorize_direct_storage() -> None:
    source_id = "gbsec:source:osv-dev"
    policy = active_governance_policy(source_id)
    assert (
        policy.resolve_authenticated_upstream(
            gateway_connector_id="gbsec:connector:osv-gateway-v1",
            upstream_source_id="gbsec:source:github-advisory-database",
            authorized_at=NOW,
        ).source_id
        == "gbsec:source:github-advisory-database"
    )
    with pytest.raises(SourceGovernanceError, match="identity-dispatch gateway only"):
        policy.authorize_collection(
            connector_id="gbsec:connector:osv-gateway-v1",
            source_id=source_id,
            acquisition_method="rest_api",
            operating_mode="exact_lookup",
            canonical_url="https://api.osv.dev/v1/vulns/GHSA-2345-6789-cfgh",
            source_record_id="GHSA-2345-6789-cfgh",
            authorized_at=NOW,
        )


def test_conditional_storage_labels_cannot_populate_accepted_fields() -> None:
    document = json.loads(GOVERNANCE_POLICY.read_text(encoding="utf-8"))
    osv_rule = next(
        source for source in document["sources"] if source["source_id"] == "gbsec:source:osv-dev"
    )
    osv_rule["authenticated_upstream_source_ids"] = []
    osv_rule["accepted_field_paths"] = ["id"]
    with pytest.raises(SourceGovernanceError, match="not allowed by source rights"):
        SourceGovernancePolicy(
            document,
            registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        )


def test_dispatch_gateway_cannot_mix_direct_fields_with_upstream_mapping() -> None:
    document = json.loads(GOVERNANCE_POLICY.read_text(encoding="utf-8"))
    osv_rule = next(
        source for source in document["sources"] if source["source_id"] == "gbsec:source:osv-dev"
    )
    osv_rule["accepted_field_paths"] = ["id"]
    with pytest.raises(SourceGovernanceError, match="accepted field paths"):
        SourceGovernancePolicy(
            document,
            registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        )
