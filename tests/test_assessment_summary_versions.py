"""Exact-version input validation and truthful source-state projection."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from smithguard import summary_contract as contract
from smithguard.assessment_summary import SummaryRejected, project_summary
from smithguard.identifiers import parse_timestamp

FIXTURES = Path(__file__).resolve().parents[1] / "integrations/t3/fixtures"


def assessment(version):
    original = json.loads((FIXTURES / "assessment.json").read_text())
    original["schema_version"] = version
    if version == "2.4.0":
        for item in original["source_freshness"]:
            item.pop("unresolved_record_count", None)
        for incident in original["incidents"]:
            for source in incident["source_reports"]:
                source.pop("source_state_status", None)
    if version == "2.5.0":
        for item in original["source_freshness"]:
            item.setdefault("unresolved_record_count", 0)
        for incident in original["incidents"]:
            for source in incident["source_reports"]:
                source["source_state_status"] = "current"
    return original


def project(original):
    return project_summary(
        original, original["artifact"], now=parse_timestamp(original["updated_at"])
    )


def test_legacy_missing_state_is_unknown_and_cannot_supply_current_fixes():
    original = assessment("2.4.0")
    report = project(original)
    assert report["assessment"]["schema_version"] == "2.4.0"
    for source in report["incidents"][0]["source_reports"]:
        assert source["source_state_status"] == "unknown"
        assert source["fix_evidence_incomplete"] is True
        assert source["source_fixed_versions"] == source["fix_evidence"] == []
    assert report["check_state"] == "partial"


def test_saved_synthetic_summary_matches_current_projection_and_closed_schema():
    original = assessment("2.5.0")
    saved = json.loads((FIXTURES / "summary.json").read_text())
    actual = project_summary(
        original, original["artifact"], now=parse_timestamp(saved["generated_at"])
    )
    assert actual == saved
    contract.SUMMARY_VALIDATOR.validate(saved)


def test_current_v25_preserves_branch_and_source_patch_provenance():
    original = assessment("2.5.0")
    for lane in original["source_freshness"]:
        lane["unresolved_record_count"] = 0
    patch = original["incidents"][0]["source_reports"][0]
    patch["source_fixed_versions"] = ["3.3.7"]
    patch["fix_evidence"][0].update(
        fixed_version="3.3.7",
        source_field="first_patched_version",
        patch_field_state="explicit_value",
    )
    untouched = deepcopy(original)
    report = project(original)
    source = report["incidents"][0]["source_reports"][0]
    expected = original["incidents"][0]["source_reports"][0]
    assert source["source_state_status"] == "current"
    for key in ("source_fixed_versions", "range_bound_evidence"):
        assert source[key] == expected[key]
    assert source["fix_evidence"] == [
        {key: value for key, value in row.items() if key in contract.FIX["properties"]}
        for row in expected["fix_evidence"]
    ]
    assert report["assessment"]["schema_version"] == "2.5.0"
    assert report["source_freshness"] == original["source_freshness"]
    assert original == untouched


def test_unknown_v25_accounting_suppresses_advice_without_fabricating_negative_failure():
    original = assessment("2.5.0")
    original["result"] = "not_affected"
    for lane in original["source_freshness"]:
        lane["unresolved_record_count"] = None
    report = project(original)
    assert report["result"] == "not_affected"
    assert all(row["unresolved_record_count"] is None for row in report["source_freshness"])
    for source in report["incidents"][0]["source_reports"]:
        assert source["fix_evidence"] == source["range_bound_evidence"] == []
        assert source["source_fixed_versions"] == []
        assert source["fix_evidence_incomplete"] is True
    assert report["omissions"]["fix_evidence"] >= 1


def test_historical_unresolved_v25_counts_suppressed_fix_rows():
    original = assessment("2.5.0")
    original["incidents"][0]["source_reports"][0]["source_state_status"] = "historical_unresolved"
    report = project(original)
    source = report["incidents"][0]["source_reports"][0]
    assert source["source_state_status"] == "historical_unresolved"
    assert source["fix_evidence_incomplete"] is True
    assert source["source_fixed_versions"] == source["fix_evidence"] == []
    assert source["range_bound_evidence"] == []
    assert report["omissions"]["fix_evidence"] >= 1
    assert report["check_state"] == "partial"


@pytest.mark.parametrize("outcome", ["affected", "unknown"])
def test_unresolved_lane_preserves_count_and_suppresses_current_fix_arrays(outcome):
    original = assessment("2.5.0")
    source = original["incidents"][0]["source_reports"][0]
    lane = next(
        row for row in original["source_freshness"] if row["source_id"] == source["source_id"]
    )
    lane.update(freshness_state="unresolved", unresolved_record_count=2)
    original["result"] = outcome
    report = project(original)
    assert report["result"] == outcome
    actual = report["incidents"][0]["source_reports"][0]
    assert actual["source_state_status"] == "current"
    assert actual["source_fixed_versions"] == actual["fix_evidence"] == []
    assert actual["fix_evidence_incomplete"] is True
    assert report["source_freshness"][0]["unresolved_record_count"] == 2
    assert report["check_state"] == "partial"


def test_inconsistent_v25_negative_with_unresolved_source_is_rejected():
    original = assessment("2.5.0")
    original["result"] = "not_affected"
    original["source_freshness"][0].update(freshness_state="unresolved", unresolved_record_count=1)
    with pytest.raises(SummaryRejected):
        project(original)


def test_historical_v25_negative_is_rejected_even_if_freshness_did_not_disclose_it():
    original = assessment("2.5.0")
    original["result"] = "not_affected"
    original["incidents"][0]["source_reports"][0]["source_state_status"] = "historical_unresolved"
    with pytest.raises(SummaryRejected):
        project(original)


def test_unresolved_count_remains_bounded_without_silently_dropping_it():
    original = assessment("2.5.0")
    original["source_freshness"][0]["unresolved_record_count"] = 1_000_001
    with pytest.raises(SummaryRejected):
        project(original)


@pytest.mark.parametrize("field", ["source_state_status", "unresolved_record_count"])
@pytest.mark.parametrize("value", ["missing", None, "unrecognized", -1])
def test_v25_required_source_state_is_not_backfilled_before_validation(field, value):
    original = assessment("2.5.0")
    target = (
        original["incidents"][0]["source_reports"][0]
        if field == "source_state_status"
        else original["source_freshness"][0]
    )
    if value == "missing":
        target.pop(field)
    else:
        target[field] = value
    # Null is a meaningful unknown count in2.5, while a null source state is invalid.
    if field == "unresolved_record_count" and value is None:
        assert project(original)["source_freshness"][0][field] is None
    else:
        with pytest.raises(SummaryRejected):
            project(original)


def test_unknown_assessment_version_is_rejected():
    with pytest.raises(SummaryRejected, match="summary_schema_unsupported"):
        project(assessment("2.6.0"))
