"""An exact retained OpenSSF record earns the same credit on every assessment display."""

import json

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard import summary_contract
from smithguard.advisory_catalog import OPENSSF_SOURCE_ID, append_openssf_advisory
from smithguard.db.models import AdvisoryCatalogRecord
from smithguard.openssf_attribution import LICENSE, PREFIX, SOURCE_NAME
from smithguard.service import (
    ResponseLimitExceeded,
    _listed_incidents,
)
from tests.test_advisory_catalog import EVIDENCE_ID, GOVERNANCE_ID, NOW, _matching_openssf
from tests.test_assessment_summary import _rpc
from tests.test_service_api import _public_client
from tools.verification import verify_signature

REQUEST = {"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"}
RECORD = "MAL-2026-54321"
URL = PREFIX + "a" * 40 + "/osv/malicious/npm/event-stream/" + RECORD + ".json"


def append(database, url):
    with Session(database.engine) as session, session.begin():
        return append_openssf_advisory(
            session,
            document=_matching_openssf(),
            canonical_url=url,
            source_state="active",
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )


def test_signed_full_rest_and_mcp_summary_use_original_record_after_replay(database):
    original = append(database, URL)
    replay = append(database, URL.replace("a" * 40, "b" * 40))
    assert not replay.created
    assert replay.catalog_event_id == original.catalog_event_id
    assert replay.source_sha256 == original.source_sha256
    with Session(database.engine) as session:
        row = session.scalars(select(AdvisoryCatalogRecord)).one()
        assert (row.canonical_url, row.source_sha256) == (URL, original.source_sha256)
    with _public_client(database) as client:
        full = client.get("/v1/artifacts/assess", params=REQUEST)
        assert full.status_code == 200, full.text
        body = full.json()
        verify_signature(body, client.get("/v1/public-key.json").json())
        row = body["incidents"][0]["source_reports"][0]
        assert row["catalog_event_id"] == original.catalog_event_id
        assert row["source_context_state"] == "available"
        context = row["source_context"]
        assert (context["source_url"], context["attribution"], context["license_expression"]) == (
            URL,
            SOURCE_NAME,
            LICENSE,
        )
        assert context["title"] is context["description"] is context["severity"] is None
        assert context["conditions"]["state"] == "unknown"
        compact = client.post(summary_contract.REST_PATH, json=REQUEST)
        assert compact.status_code == 200, compact.text
        mcp = _rpc(client, "tools/call", {"name": summary_contract.TOOL_NAME, "arguments": REQUEST})
        assert mcp.status_code == 200, mcp.text
        tool = mcp.json()["result"]
        assert not tool["isError"]
        for answer in [
            compact.json(),
            tool["structuredContent"],
            json.loads(tool["content"][0]["text"]),
        ]:
            source = answer["incidents"][0]["source_reports"][0]
            assert source["source_attribution"] == {
                "name": SOURCE_NAME,
                "license": LICENSE,
                "record_url": URL,
            }


@pytest.mark.parametrize("gate", ["url", "bytes", "reports"])
def test_required_attribution_failure_withholds_signed_result(database, monkeypatch, gate):
    append(database, URL.replace(RECORD, "MAL-2026-999") if gate == "url" else URL)
    if gate != "url":
        name = "MAX_CONTEXT_BYTES" if gate == "bytes" else "MAX_CONTEXT_REPORTS"
        monkeypatch.setattr("smithguard.catalog_context." + name, 0)
    with _public_client(database) as client:
        full = client.get("/v1/artifacts/assess", params=REQUEST)
        assert full.status_code == (500 if gate == "url" else 413), full.text
        assert "incidents" not in full.json()
        assert "signature" not in full.json()


def test_applicable_incident_omission_cannot_remove_its_source_credit(monkeypatch):
    monkeypatch.setattr("smithguard.service.MAX_LISTED_INCIDENTS", 1)
    reports = [{"source_id": OPENSSF_SOURCE_ID}]
    with pytest.raises(ResponseLimitExceeded, match="listed incident"):
        _listed_incidents(
            [
                {"applies_to_version": True, "incident_id": "a", "source_reports": []},
                {"applies_to_version": True, "incident_id": "b", "source_reports": reports},
            ]
        )


@pytest.mark.parametrize("all_openssf", [False, True])
def test_full_family_limit_preserves_required_credits_or_refuses(all_openssf):
    from smithguard.advisory_catalog import CatalogMatchFamily
    from smithguard.service import _project_assessment_incidents

    # The OpenSSF report would be last under the ordinary lexicographic bound.
    another = OPENSSF_SOURCE_ID if all_openssf else "gbsec:source:github-advisories"
    reports = [
        {"source_id": another, "upstream_record_id": f"MAL-2026-{i}"} for i in range(100)
    ] + [{"source_id": OPENSSF_SOURCE_ID, "upstream_record_id": RECORD}]
    family = CatalogMatchFamily(
        family_key="family",
        incident_id="incident",
        revision=1,
        status="confirmed",
        confidence="confirmed",
        classification="malicious",
        title="Synthetic family",
        last_changed_at=NOW.isoformat(),
        source_reports=tuple(reports),
        evaluations=(True,),
        matched_range_ids=(),
    )
    if all_openssf:
        with pytest.raises(ResponseLimitExceeded, match="source reports"):
            _project_assessment_incidents([], {}, {}, (family,), {})
    else:
        (result,) = _project_assessment_incidents([], {}, {}, (family,), {})
        assert len(result["source_reports"]) == 100
        assert result["source_reports_truncated"]
        assert reports[-1] in result["source_reports"]
