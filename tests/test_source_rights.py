"""Reviewed source rights fail closed at method, host, date, and upstream gates."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from smithguard.collectors import (
    GITHUB_ADVISORY,
)
from smithguard.contracts.runtime import parse_contract
from smithguard.source_governance import (
    DEFAULT_GOVERNANCE_POLICY_PATH,
    SourceGovernanceError,
    SourceGovernancePolicy,
)
from smithguard.source_rights import RightsRegistry, SourceProfile, SourceRightsError

REPO_ROOT = Path(__file__).resolve().parents[1]
RIGHTS_REGISTER = REPO_ROOT / "contracts/v1/source-rights-register.json"


def test_phase_1_registry_has_the_reviewed_paths() -> None:
    registry = RightsRegistry.from_path(RIGHTS_REGISTER)
    assert registry.register_id == "gbsec:rights-register:phase-0a-v1"
    assert registry.schema_version == "1.0.0"
    assert {profile.source_id for profile in registry.phase_1_profiles()} == {
        GITHUB_ADVISORY,
        "gbsec:source:openssf-malicious-packages",
        "gbsec:source:pypa-advisory-database",
        "gbsec:source:pypi-apis",
        "gbsec:source:osv-dev",
        "gbsec:source:first-epss",
        "gbsec:source:cisa-kev",
        "gbsec:source:rustsec-advisory-database",
        "gbsec:source:go-vulnerability-database",
        "gbsec:source:php-security-notices",
        "gbsec:source:mozilla-security-blog",
        "gbsec:source:mozilla-mfsa",
        "gbsec:source:ubuntu-usn-feed",
        "gbsec:source:node-security-feed",
        "gbsec:source:gitlab-security-feed",
        "gbsec:source:zdi-published-feed",
        "gbsec:source:cisco-security-feed",
        "gbsec:source:fortinet-security-feed",
        "gbsec:source:aws-bulletin-feed",
        "gbsec:source:apple-release-index",
        "gbsec:source:paloalto-advisory-index",
        "gbsec:source:zdi-upcoming-discovery",
        "gbsec:source:oss-security-discovery",
        "gbsec:source:linux-security-discovery",
    }
    github = registry.get(GITHUB_ADVISORY)
    github.authorize_collection(
        method="rest_api",
        canonical_url="https://api.github.com/advisories/GHSA-synthetic",
        today=date(2026, 8, 5),
    )
    assert github.is_public_output_approved
    assert github.source["revision"] == 4
    assert [revision for revision, _source_hash in registry.revision_history(GITHUB_ADVISORY)] == [
        1,
        2,
        3,
        4,
    ]
    openssf = registry.get("gbsec:source:openssf-malicious-packages")
    assert openssf.source["revision"] == 4
    assert [
        revision for revision, _source_hash in registry.revision_history(openssf.source_id)
    ] == [1, 2, 3, 4]
    for source_id in (
        "gbsec:source:first-epss",
        "gbsec:source:cisa-kev",
        "gbsec:source:rustsec-advisory-database",
        "gbsec:source:go-vulnerability-database",
    ):
        profile = registry.get(source_id)
        expected_revision = 3 if source_id == "gbsec:source:go-vulnerability-database" else 2
        assert profile.source["revision"] == expected_revision
        assert profile.is_public_output_approved
        recorded_revisions = [
            revision for revision, _source_hash in registry.revision_history(source_id)
        ]
        assert recorded_revisions == list(range(1, expected_revision + 1))


def test_source_revision_history_fails_closed_on_drift_or_incomplete_history() -> None:
    document = json.loads(RIGHTS_REGISTER.read_text(encoding="utf-8"))
    missing = deepcopy(document)
    missing["source_revisions"].pop()
    duplicated = deepcopy(document)
    duplicated["source_revisions"].append(deepcopy(duplicated["source_revisions"][0]))
    stale = deepcopy(document)
    stale["source_profiles"][0]["source"]["revision"] = 5
    non_contiguous = deepcopy(document)
    non_contiguous["source_revisions"][0]["revisions"][1]["revision"] = 3
    mismatched = deepcopy(document)
    mismatched["source_revisions"][0]["revisions"][-1]["source_sha256"] = "sha256:" + "0" * 64

    cases = (
        (missing, "coverage"),
        (duplicated, "duplicated"),
        (stale, "recorded head"),
        (non_contiguous, "not contiguous"),
        (mismatched, "differs"),
    )
    for changed, message in cases:
        with pytest.raises(SourceRightsError, match=message):
            RightsRegistry(changed)


def test_source_register_is_canonical_and_persisted_hashes_must_match() -> None:
    document = json.loads(RIGHTS_REGISTER.read_text(encoding="utf-8"))
    registry = RightsRegistry(document)
    for profile in document["source_profiles"]:
        raw_source = profile["source"]
        assert raw_source == parse_contract("Source", raw_source).model_dump(
            mode="json",
            exclude_none=False,
        )

    history = registry.revision_history(GITHUB_ADVISORY)
    registry.validate_persisted_history(GITHUB_ADVISORY, history)
    with pytest.raises(SourceRightsError, match="stored source history differs"):
        registry.validate_persisted_history(
            GITHUB_ADVISORY,
            ((1, "sha256:" + "0" * 64),),
        )


def test_rights_reject_stale_wrong_method_and_off_host_use() -> None:
    profile = RightsRegistry.from_path(RIGHTS_REGISTER).get(GITHUB_ADVISORY)
    with pytest.raises(SourceRightsError, match="stale"):
        profile.authorize_collection(
            method="rest_api",
            canonical_url="https://api.github.com/advisories/GHSA-synthetic",
            today=date(2027, 1, 1),
        )
    with pytest.raises(SourceRightsError, match="method"):
        profile.authorize_collection(
            method="rss",
            canonical_url="https://api.github.com/advisories/GHSA-synthetic",
            today=date(2026, 8, 5),
        )
    with pytest.raises(SourceRightsError, match="host"):
        profile.authorize_collection(
            method="rest_api",
            canonical_url="https://example.com/advisories/GHSA-synthetic",
            today=date(2026, 8, 5),
        )


def test_osv_gateway_dispatch_is_disabled_until_authenticated_mapping_exists() -> None:
    registry = RightsRegistry.from_path(RIGHTS_REGISTER)
    policy = SourceGovernancePolicy.from_path(
        DEFAULT_GOVERNANCE_POLICY_PATH,
        registry=registry,
    )
    with pytest.raises(SourceGovernanceError, match="disabled"):
        policy.resolve_authenticated_upstream(
            gateway_connector_id="gbsec:connector:osv-gateway-v1",
            upstream_source_id=GITHUB_ADVISORY,
            authorized_at=datetime(2026, 8, 5, tzinfo=UTC),
        )


def test_gateway_dispatch_applies_activation_kill_retrieval_and_staleness_gates() -> None:
    registry = RightsRegistry.from_path(RIGHTS_REGISTER)
    github = registry.get(GITHUB_ADVISORY)
    github.authorize_gateway_dispatch(today=date(2026, 8, 5))

    with pytest.raises(SourceRightsError, match="stale"):
        github.authorize_gateway_dispatch(today=date(2027, 1, 1))

    deferred_profile = registry.get("gbsec:source:cve-list-v5")
    with pytest.raises(SourceRightsError, match="not a Phase 1 path"):
        deferred_profile.authorize_gateway_dispatch(today=date(2026, 8, 5))

    disabled_source = deepcopy(github.source)
    disabled_source["kill_switch"] = False
    with pytest.raises(SourceRightsError, match="kill switch"):
        SourceProfile(
            activation=github.activation,
            source=disabled_source,
            field_rules=github.field_rules,
        ).authorize_gateway_dispatch(today=date(2026, 8, 5))

    denied_source = deepcopy(github.source)
    denied_source["rights"]["retrieval"] = "prohibited"
    with pytest.raises(SourceRightsError, match="retrieval"):
        SourceProfile(
            activation=github.activation,
            source=denied_source,
            field_rules=github.field_rules,
        ).authorize_gateway_dispatch(today=date(2026, 8, 5))
