import copy
from datetime import timedelta

import pytest
from test_client_verification import NOW, oracle_encode
from test_client_verification import signed as signed

from smithguard_client.discovery import artifact
from smithguard_client.interpretation import candidate_decision, evaluate_conditions
from smithguard_client.verification import verify_assessment


def pair(signed, change=None):
    body, key, sign = signed
    body.update(
        schema_version="2.4.0",
        artifact=artifact("public-demo", "1.0"),
        unknowns=[],
        registry_state="available",
        reason_codes=["identity_unverified"],
    )
    body["coverage"]["ecosystem"] = "pypi"
    incident = body["incidents"][0]
    incident.update(source_fixed_versions=["1.1"], fix_evidence_incomplete=False)
    source = incident["source_reports"][0]
    source.update(
        applies_to_version=True,
        source_fixed_versions=["1.1"],
        fix_evidence=[
            {
                "package_entry_id": "gbsec:advisory-package:synthetic",
                "range_index": 0,
                "range_sha256": "sha256:" + "a" * 64,
                "range_type": "GITHUB",
                "expression": "< 1.1",
                "introduced_version": None,
                "fixed_version": "1.1",
                "source_field": "first_patched_version",
                "applies_to_requested_version": True,
                "patch_field_state": "explicit_value",
            }
        ],
    )
    after = copy.deepcopy(body)
    after.update(
        artifact=artifact("public-demo", "1.1"),
        result="not_affected",
        incidents=[],
        incident_ids=[],
        affected_range_ids=[],
        recommended_action_ids=[],
        not_applicable_incident_count=1,
        relationship_state="no_incidents",
    )
    if change:
        change(body, after)

    def verify(value):
        return verify_assessment(
            sign(value),
            expected_artifact=value["artifact"],
            key_raw=oracle_encode(key),
            key_fetched_at=NOW,
            now=NOW,
        )

    return verify(body), verify(after)


def decide(before, after):
    return candidate_decision(
        before,
        after,
        compatibility="reviewed_supported",
        installed_identity="independently_verified",
    )


def test_exact_source_patch_can_only_earn_application_testing(signed):
    before, after = pair(signed)
    assert before.current_decision_eligible and after.current_decision_eligible
    decision = decide(before, after)
    assert decision["outcome"] == "candidate_for_application_testing"
    assert decision["matched_fix_evidence"][0]["fix_evidence"][0]["fixed_version"] == "1.1"
    assert candidate_decision(before, after)["outcome"] == "no_verified_recommendation"


@pytest.mark.parametrize(
    "case",
    [
        "other_advisory",
        "other_branch",
        "no_fix",
        "conflict",
        "withdrawn",
        "prerelease",
        "yanked",
        "unknown",
        "old_response",
        "optional_constraints",
        "changed_feed",
        "missing_metadata",
        "truncated",
    ],
)
def test_candidate_must_resolve_all_evidence(signed, case):
    def change(before, after):
        source = before["incidents"][0]["source_reports"][0]
        if case == "other_advisory":
            after.update(result="affected", incidents=copy.deepcopy(before["incidents"]))
        elif case == "other_branch":
            source["fix_evidence"][0]["applies_to_requested_version"] = False
        elif case == "no_fix":
            source["fix_evidence"] = []
        elif case == "conflict":
            after["result"] = "conflicting"
        elif case == "withdrawn":
            source["state"] = "withdrawn"
        elif case == "prerelease":
            after["artifact"]["version"] = "1.1rc1"
        elif case == "yanked":
            after["registry_state"] = "yanked"
        elif case == "unknown":
            after["result"] = "unknown"
        elif case == "old_response":
            after["updated_at"] = (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        elif case == "optional_constraints":
            after["unknowns"] = ["Optional dependency constraint not checked"]
        elif case == "changed_feed":
            after["feed_revision"] = "feed-changed-current"
        elif case == "missing_metadata":
            source["historical_metadata_incomplete"] = True
        elif case == "truncated":
            after["incidents_truncated"] = True

    before, after = pair(signed, change)
    assert decide(before, after)["outcome"] == "no_verified_recommendation"


def test_largest_version_is_never_selected_from_branch_union(signed):
    def change(before, after):
        source = before["incidents"][0]["source_reports"][0]
        source["source_fixed_versions"] = ["1.1", "9.9"]
        unrelated = {
            **source["fix_evidence"][0],
            "fixed_version": "9.9",
            "applies_to_requested_version": False,
        }
        source["fix_evidence"].append(unrelated)
        after["artifact"]["version"] = "9.9"

    assert decide(*pair(signed, change))["outcome"] == "no_verified_recommendation"


@pytest.mark.parametrize(
    "facts,outcome",
    [
        ({}, "uncertain"),
        ({"target_os": "linux"}, "uncertain"),
        ({"target_os": "linux", "server_mode": "disabled"}, "conditions_not_met"),
        ({"target_os": "windows"}, "conditions_met"),
    ],
)
def test_no_local_exclusion_from_absent_facts(facts, outcome):
    condition = {
        "state": "recorded",
        "any_of": [
            {"all_of": [{"fact": "target_os", "values": ["windows"]}]},
            {"all_of": [{"fact": "server_mode", "values": ["http"]}]},
        ],
    }
    assert evaluate_conditions(condition, facts) == outcome
    assert evaluate_conditions({"state": "unknown"}, facts) == "uncertain"


@pytest.mark.parametrize("facts", [{"target_os": None}, {"target_os": False}, [], None])
def test_malformed_local_facts_cannot_exclude_conditions(facts):
    conditions = {
        "state": "recorded",
        "any_of": [{"all_of": [{"fact": "target_os", "values": ["windows"]}]}],
    }
    assert evaluate_conditions(conditions, facts) == "uncertain"
