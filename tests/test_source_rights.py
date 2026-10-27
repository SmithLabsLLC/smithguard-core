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


def renewed_register(source_id=GITHUB_ADVISORY):
    """Synthetic date-only renewal; never changes the deployed register."""
    from smithguard.identifiers import canonical_json_bytes, sha256_id

    document = json.loads(RIGHTS_REGISTER.read_text())
    profile = next(p for p in document["source_profiles"] if p["source"]["id"] == source_id)
    historical = deepcopy(profile)
    source = profile["source"]
    source["revision"] += 1
    source["updated_at"] = "2026-10-24T00:00:00Z"
    source["rights"].update(reviewed_on="2026-10-24", review_due_on="2026-12-01")
    history = next(h for h in document["source_revisions"] if h["source_id"] == source_id)
    history["revisions"].append(
        {"revision": source["revision"], "source_sha256": sha256_id(canonical_json_bytes(source))}
    )
    document["publication_renewals"] = [
        {"historical_profile": historical, "current_revision": source["revision"]}
    ]
    return document


def test_publication_renewal_requires_explicit_authentic_unchanged_policy():
    document = renewed_register()
    registry = RightsRegistry(document)
    assert registry.permits_publication_revision(GITHUB_ADVISORY, 4)
    assert registry.permits_publication_revision(GITHUB_ADVISORY, 5)
    for revision in (1, 3, 6, True, "4"):
        assert not registry.permits_publication_revision(GITHUB_ADVISORY, revision)
    del document["publication_renewals"]
    assert not RightsRegistry(document).permits_publication_revision(GITHUB_ADVISORY, 4)


@pytest.mark.parametrize("change", ["hash", "fields", "activation", "target", "duplicate"])
def test_publication_renewal_rejects_forged_or_ambiguous_relations(change):
    document = renewed_register()
    renewal = document["publication_renewals"][0]
    if change == "hash":
        renewal["historical_profile"]["source"]["rights"]["attribution_text"] = "Forged"
    elif change == "fields":
        renewal["historical_profile"]["field_rules"][0]["fields"].append("description")
    elif change == "activation":
        renewal["historical_profile"]["activation"] = "disabled"
    elif change == "target":
        renewal["current_revision"] = True
    else:
        document["publication_renewals"].append(deepcopy(renewal))
    with pytest.raises(SourceRightsError, match="renewal"):
        RightsRegistry(document)


@pytest.mark.parametrize("change", ["attribution", "fields", "revoked", "disabled", "hosts"])
def test_publication_renewal_does_not_infer_compatibility_after_terms_change(change):
    from smithguard.identifiers import canonical_json_bytes, sha256_id

    document = renewed_register()
    profile = next(p for p in document["source_profiles"] if p["source"]["id"] == GITHUB_ADVISORY)
    source = profile["source"]
    if change == "attribution":
        source["rights"]["attribution_text"] = "Different attribution"
    elif change == "fields":
        profile["field_rules"][0]["fields"].remove("ghsa_id")
    elif change == "revoked":
        source["rights"]["normalized_fact_redistribution"] = "prohibited"
    elif change == "disabled":
        source["kill_switch"] = False
    else:
        source["allowed_hosts"] = ["api.github.com"]
    history = next(h for h in document["source_revisions"] if h["source_id"] == GITHUB_ADVISORY)
    history["revisions"][-1]["source_sha256"] = sha256_id(canonical_json_bytes(source))
    with pytest.raises(SourceRightsError, match="substantive"):
        RightsRegistry(document)


def test_publication_renewal_keeps_inclusive_collection_and_publication_deadlines():
    from smithguard.bulletin_contract import BulletinError
    from smithguard.bulletin_policy import publication_rights
    from tests.test_bulletins import content

    registry = RightsRegistry(renewed_register())
    profile = registry.get(GITHUB_ADVISORY)
    profile.authorize_collection(
        method="rest_api",
        canonical_url="https://api.github.com/advisories",
        today=date(2026, 12, 1),
    )
    publication_rights(content(), registry, now=datetime(2026, 12, 1, 23, 59, 59, tzinfo=UTC))
    with pytest.raises(SourceRightsError, match="stale"):
        profile.authorize_gateway_dispatch(today=date(2026, 12, 2))
    with pytest.raises(BulletinError, match="rights_not_current"):
        publication_rights(content(), registry, now=datetime(2026, 12, 2, tzinfo=UTC))


@pytest.mark.parametrize("change", ["revision", "attribution", "fields", "url"])
def test_renewed_publication_still_checks_each_reference(change):
    from smithguard.bulletin_contract import BulletinError
    from smithguard.bulletin_policy import publication_rights
    from tests.test_bulletins import NOW, content

    document = content()
    reference = document["sources"][0]
    reference[
        {
            "revision": "rights_revision",
            "attribution": "attribution",
            "fields": "used_fields",
            "url": "record_url",
        }[change]
    ] = {
        "revision": 3,
        "attribution": "Forged",
        "fields": ["credits"],
        "url": "https://example.com/advisories/synthetic",
    }[change]
    with pytest.raises(BulletinError):
        publication_rights(document, RightsRegistry(renewed_register()), now=NOW)


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
