"""Real API + public reader regression; no hand-filled source counts or live HTTP."""

from datetime import datetime
from email.utils import format_datetime
from pathlib import Path

import httpx
import pytest
from sqlalchemy.orm import Session, sessionmaker

from smithguard.advisory_catalog import append_github_advisory
from smithguard.anonymous_quota import AnonymousQuotaStore
from smithguard.api import create_public_beta_app
from smithguard.feeds import SnapshotSigner
from tests.api_client import TestClient
from tests.support import openssf_manifest_pair
from tests.test_service_api import NOW, _update_progress


def test_real_service_pair_reaches_client_with_measured_github_counts(database, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "clients/python/src"))
    from smithguard_client import transport
    from smithguard_client.discovery import artifact
    from smithguard_client.interpretation import candidate_decision

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW.astimezone(tz) if tz is not None else NOW.replace(tzinfo=None)

    monkeypatch.setattr(transport, "datetime", FixedDateTime)
    with Session(database.engine) as session, session.begin():
        append_github_advisory(
            session,
            document={
                "ghsa_id": "GHSA-2345-6789-cfgh",
                "type": "reviewed",
                "published_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-02T00:00:00Z",
                "withdrawn_at": None,
                "html_url": "https://github.com/advisories/GHSA-2345-6789-cfgh",
                "cwes": [],
                "identifiers": [{"type": "GHSA", "value": "GHSA-2345-6789-cfgh"}],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "pip", "name": "public-demo"},
                        "vulnerable_version_range": "< 1.1",
                        "first_patched_version": "1.1",
                    }
                ],
            },
            evidence_id="gbsec:evidence:client-service-pair",
            governance_decision_id="gbsec:governance:client-service-pair",
            observed_at=NOW,
        )
        for segment in ["malware", "reviewed", "unreviewed"]:
            session.add(_update_progress(1, segment=segment))
        session.add_all(openssf_manifest_pair(observed_at=NOW))
    app = create_public_beta_app(
        session_factory=sessionmaker(database.engine),
        signer=SnapshotSigner.ephemeral(),
        base_url=transport.API,
        clock=lambda: NOW,
        anonymous_quota_store=AnonymousQuotaStore(),
        anonymous_quota_secret=b"synthetic-public-quota-secret!!!",
    )

    class LocalHTTPDateTransport(httpx.AsyncBaseTransport):
        """ASGI has no HTTP server; supply its ordinary Date header, never alter JSON."""

        async def handle_async_request(self, request):
            response = await httpx.ASGITransport(
                app=app, client=("8.8.8.8", 50000)
            ).handle_async_request(request)
            response.headers["Date"] = format_datetime(NOW, usegmt=True)
            return response

    with TestClient(app, base_url=transport.API):
        reader = transport.PublicReader(_transport=LocalHTTPDateTransport())
        before = reader.assess(artifact("public-demo", "1.0"))
        after = reader.assess(artifact("public-demo", "1.1"))
    assert before.status == after.status == "verified"
    for verified in [before, after]:
        body = verified.document
        assert body["schema_version"] == "2.5.0"
        assert body["source_freshness"]
        assert all(row["unresolved_record_count"] == 0 for row in body["source_freshness"])
    decision = candidate_decision(
        before,
        after,
        compatibility="reviewed_supported",
        installed_identity="independently_verified",
    )
    assert "source_freshness_unqualified" not in decision.get("reasons", [])
    # This fixture has no registry observation/full historical inventory. The fix
    # must remove only the false unknown-count refusal, not invent those facts.
    assert decision["outcome"] == "no_verified_recommendation"
    assert "registry_state_unqualified" in decision["reasons"]


@pytest.mark.parametrize("unrelated_quarantine", [False, True])
def test_measured_unrelated_github_quarantine_downgrades_negative_for_consumers(
    database, tmp_path, unrelated_quarantine
):
    import json

    from smithguard import summary_contract
    from tests.test_collection_records import advisory, collector, response
    from tests.test_service_api import _public_client

    good = advisory(name="accounting-package")
    bad = advisory("cfgj", "unrelated-package")
    bad["published_at"] = "invalid"
    records = [good, bad] if unrelated_quarantine else [good]
    instance, _store = collector(tmp_path, lambda req: response(req, records))
    with Session(database.engine) as session, session.begin():
        collected = instance.run(session, lane="updates")
        assert collected.state == "complete"
        for segment in ["malware", "unreviewed"]:
            session.add(_update_progress(1, segment=segment))
        session.add_all(openssf_manifest_pair(observed_at=NOW))
    coordinate = {"ecosystem": "npm", "name": "accounting-package", "version": "2.0.0"}
    with _public_client(database) as client:
        raw = client.post("/v1/artifacts/assess", json=coordinate)
        assert raw.status_code == 200, raw.text
        body = raw.json()
        summary = client.post(summary_contract.REST_PATH, json=coordinate)
        assert summary.status_code == 200, summary.text
    expected = "unknown" if unrelated_quarantine else "not_affected"
    assert body["result"] == summary.json()["result"] == expected
    lane = next(
        row for row in body["source_freshness"] if row["record_type"] == "reviewed_advisory"
    )
    assert lane["unresolved_record_count"] == int(unrelated_quarantine)
    if unrelated_quarantine:
        assert "source_unavailable" in body["reason_codes"]
        assert "source_unavailable" in summary.json()["reason_codes"]
        # A real API-produced synthetic response is retained in pytest's bounded
        # temporary output for the separate browser guard regression. No live data.
        (tmp_path / "api-unrelated-quarantine.json").write_text(json.dumps(body) + "\n")
    summary_contract.SUMMARY_VALIDATOR.validate(summary.json())
