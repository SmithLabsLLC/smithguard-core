"""Dated independently labeled public boundaries; never calls a live provider."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from smithguard.advisory_catalog import _github_range_matches
from smithguard.advisory_context import github_public_context
from smithguard.assessment_evidence import source_fix_evidence

LABELS = json.loads(
    (Path(__file__).parent / "fixtures/interpretation-heldout-20261026.json").read_text()
)
CASES = [(ref, case) for ref in LABELS["references"] for case in ref["cases"]]


@pytest.mark.parametrize("ref,case", CASES, ids=[f"{r['name']}-{c['version']}" for r, c in CASES])
def test_heldout_source_boundary_and_explicit_patch(ref, case):
    def match(expression):
        return _github_range_matches("pypi", case["version"], expression)

    assert match(ref["expression"]) is case["expected_applies"]
    package = SimpleNamespace(
        package_event_id="gbsec:advisory-package:heldout",
        affected_ranges=[
            {
                "type": "GITHUB",
                "expression": ref["expression"],
                "first_patched_version": ref["expected_explicit_fix"],
            }
        ],
    )
    evidence = source_fix_evidence(
        [package],
        ecosystem="pypi",
        github_match=match,
        osv_match=lambda _: None,
        historical=False,
        unresolved=False,
    )
    assert evidence["source_fixed_versions"] == [ref["expected_explicit_fix"]]
    assert evidence["fix_evidence"][0]["patch_field_state"] == "explicit_value"
    assert evidence["fix_evidence"][0]["applies_to_requested_version"] is case["expected_applies"]
    assert not evidence["fix_evidence_incomplete"]
    # Synthetic prose is not a reviewed target-condition extraction.
    context = github_public_context(
        {
            "ghsa_id": ref["id"],
            "html_url": ref["url"],
            "updated_at": ref["updated_at"],
            "summary": "Synthetic context fixture",
            "description": "A Windows installation may be affected.",
            "severity": "high",
        }
    )
    assert context["conditions"]["state"] == ref["expected_condition_state"]
    assert context["conditions"]["local_applicability"] == "not_evaluated"
