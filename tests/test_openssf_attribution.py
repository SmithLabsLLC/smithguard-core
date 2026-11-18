"""Only an admitted OpenSSF record path may be returned with its attribution."""

from copy import deepcopy
from datetime import datetime

import pytest
from jsonschema import ValidationError

from smithguard import summary_contract as contract
from smithguard.assessment_summary import SummaryRejected, project_summary
from smithguard.openssf_attribution import (
    LICENSE,
    MAX_URL_CHARS,
    PREFIX,
    SOURCE_NAME,
    verified_record_url,
)
from smithguard.openssf_git import OPENSSF_MALICIOUS
from tests.test_assessment_summary_versions import assessment

RECORD = "MAL-2026-12345"
ROOT = PREFIX + "a" * 40 + "/osv/"
PATH = "malicious/npm/@scope/pkg/" + RECORD + ".json"


@pytest.mark.parametrize(
    "path", [PATH, PATH.replace("malicious/npm/@scope/pkg", "withdrawn/PyPI/caf%C3%A9")]
)
def test_accepted_pinned_source_record(path):
    assert verified_record_url(ROOT + path, upstream_record_id=RECORD) == ROOT + path


@pytest.mark.parametrize(
    "url",
    [
        "https://example.org/" + PATH,
        PREFIX + "main/osv/" + PATH,
        ROOT + PATH + "?extra=1",
        ROOT + PATH + "#extra",
        ROOT + PATH.replace("@scope/pkg", "../other"),
        ROOT + PATH.replace("@scope", "%40scope"),
        ROOT + PATH.replace("MAL-2026-12345", "MAL-2026-7"),
        ROOT + PATH.replace("@scope/pkg", "a%2Fb"),
        ROOT + "x" * MAX_URL_CHARS,
    ],
)
def test_mismatched_and_noncanonical_record_is_unavailable(url):
    assert verified_record_url(url, upstream_record_id=RECORD) is None


def attributed_assessment():
    body = assessment("2.5.0")
    row = body["incidents"][0]["source_reports"][0]
    row.update(source_id=OPENSSF_MALICIOUS, source_name=SOURCE_NAME, upstream_record_id=RECORD)
    from smithguard.advisory_context import github_public_context

    context = github_public_context({"summary": "Synthetic advisory", "html_url": ROOT + PATH})
    assert context
    row["source_context"] = {
        **context,
        "attribution": SOURCE_NAME,
        "license_expression": LICENSE,
        "source_url": ROOT + PATH,
    }
    row["source_context_state"] = "available"
    return body


def project(body):
    return project_summary(body, body["artifact"], now=datetime.fromisoformat(body["updated_at"]))


def test_exact_record_credit_is_bound_independently_of_general_citation_limit():
    body = attributed_assessment()
    body["incidents"][0]["upstream_urls"] = [
        f"https://github.com/advisories/GHSA-aaaa-bbbb-{i}" for i in range(8)
    ]
    result = project(body)
    incident = result["incidents"][0]
    assert result["summary_schema_version"] == result["projection_version"] == "1.1.0"
    assert len(incident["citations"]) == 4
    assert incident["source_reports"][0]["source_attribution"] == {
        "name": SOURCE_NAME,
        "license": LICENSE,
        "record_url": ROOT + PATH,
    }
    result["summary_schema_version"] = "1.0.0"
    with pytest.raises(ValidationError):
        contract.SUMMARY_VALIDATOR.validate(result)


def test_missing_credit_and_omitted_required_source_never_emit_unattributed_facts():
    body = attributed_assessment()
    incident = body["incidents"][0]
    original = deepcopy(incident["source_reports"][0])
    incident["source_reports"][0]["source_context"] = None
    with pytest.raises(SummaryRejected):
        project(body)
    incident["source_reports"] = [deepcopy(original) for _ in range(5)]
    with pytest.raises(SummaryRejected, match="summary_limit_exceeded"):
        project(body)
