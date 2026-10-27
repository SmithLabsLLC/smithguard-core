"""Context is revision-bound, bounded, and read through the exact existing payload store."""

from sqlalchemy.orm import Session

from smithguard.advisory_catalog import append_github_advisory
from smithguard.db.models import SupplementalPayloadRecord
from smithguard.identifiers import canonical_json_bytes, sha256_id
from tests.test_advisory_catalog import EVIDENCE_ID, GOVERNANCE_ID, NOW, _github_event_stream
from tests.test_service_api import _public_client
from tools.verification import verify_signature


def append(database, document):
    with Session(database.engine) as session, session.begin():
        return append_github_advisory(
            session,
            document=document,
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )


def test_context_only_change_appends_with_same_source_time_and_invalidates_cache(database):
    document = _github_event_stream()
    document.update(summary="Source title", description="First description", severity="high")
    first = append(database, document)
    with _public_client(database) as api:
        key = api.get("/v1/public-key.json").json()
        before = api.get(
            "/v1/artifacts/assess",
            params={"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"},
        ).json()
        verify_signature(before, key)
        document["description"] = "Corrected description with unchanged upstream date"
        second = append(database, document)
        assert second.created and second.revision == first.revision + 1
        assert not append(database, document).created
        after = api.get(
            "/v1/artifacts/assess",
            params={"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"},
        ).json()
        verify_signature(after, key)
        assert after["feed_revision"] != before["feed_revision"]
        assert (
            after["incidents"][0]["source_reports"][0]["source_context"]["description"]
            == document["description"]
        )
        assert (
            before["incidents"][0]["source_reports"][0]["source_context"]["description"]
            == "First description"
        )
    with Session(database.engine) as session:
        for row in (first, second):
            stored = session.get(SupplementalPayloadRecord, row.source_sha256)
            assert sha256_id(canonical_json_bytes(stored.document)) == row.source_sha256
        assert (
            session.get(SupplementalPayloadRecord, first.source_sha256).document["public_context"][
                "description"
            ]
            == "First description"
        )


def test_context_budget_omission_is_visible_and_does_not_hide_the_incident(database, monkeypatch):
    document = _github_event_stream()
    document.update(summary="Source title", description="x" * 2000)
    append(database, document)
    monkeypatch.setattr("smithguard.catalog_context.MAX_CONTEXT_BYTES", 10)
    with _public_client(database) as api:
        body = api.get(
            "/v1/artifacts/assess",
            params={"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"},
        ).json()
        assert body["result"] == "affected" and body["incidents"]
        assert body["incidents"][0]["source_reports"][0]["source_context"] is None
        assert body["incidents"][0]["source_reports"][0]["source_context_state"] == "omitted_budget"
        assert "results_incomplete" in body["reason_codes"]


def test_invalid_optional_text_keeps_the_signed_core_finding(database):
    document = _github_event_stream()
    document.update(summary="Valid title", description="invalid\x00optional text")
    append(database, document)
    with _public_client(database) as api:
        body = api.get(
            "/v1/artifacts/assess",
            params={"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"},
        ).json()
        verify_signature(body, api.get("/v1/public-key.json").json())
        assert body["result"] == "affected"
        report = body["incidents"][0]["source_reports"][0]
        assert report["source_context"] is None
        assert report["source_context_state"] == "unavailable"


def test_dense_catalog_answer_fails_closed_instead_of_truncating_silently(database):
    """100 incidents with 40 ranges plus full context exceed the public byte cap."""
    from copy import deepcopy

    with Session(database.engine) as session, session.begin():
        for index in range(100):
            document = _github_event_stream()
            advisory = f"GHSA-2345-6789-{index:04d}"
            document.update(
                ghsa_id=advisory,
                html_url=f"https://github.com/advisories/{advisory}",
                identifiers=[{"type": "GHSA", "value": advisory}],
                summary="Synthetic heavy source " + "x" * 270,
                description="y" * 2000,
                vulnerabilities=[
                    {
                        "package": {"ecosystem": "npm", "name": "event-stream"},
                        "vulnerable_version_range": f">= 0.0.0, < {branch + 4}.0.0",
                        "first_patched_version": f"{branch + 4}.0.0",
                    }
                    for branch in range(40)
                ],
            )
            append_github_advisory(
                session,
                document=deepcopy(document),
                evidence_id=EVIDENCE_ID,
                governance_decision_id=GOVERNANCE_ID,
                observed_at=NOW,
            )
    with _public_client(database) as api:
        response = api.get(
            "/v1/artifacts/assess",
            params={"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"},
        )
        assert response.status_code == 413
        assert "result" not in response.json()
        assert "incidents" not in response.json()
