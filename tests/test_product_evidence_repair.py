"""Historical pip metadata repairs must reach signed answers without rewriting history."""

import json
from contextlib import closing

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.collectors import GITHUB_ADVISORY, GitHubAdvisoryRestCollector
from smithguard.db.models import (
    AdvisoryCatalogRecord,
    CollectorProgressRecord,
    EvidenceRecord,
)
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.source_governance import SourceGovernancePolicy
from smithguard.source_rights import RightsRegistry
from tests.governance_fixtures import active_governance_policy
from tests.test_collectors import NOW, REPO_ROOT, RIGHTS_REGISTER, _github_advisory
from tests.test_service_api import _public_client
from tools.verification import verify_signature


@pytest.mark.parametrize(
    "advisory_id,expression,patch,old_candidates",
    [
        ("GHSA-58qw-9mgm-455v", "<= 26.0.1", "26.1", []),
        ("GHSA-4xh5-x5gv-qwph", "<= 25.2", "25.3", []),
        # A correct-looking inferred answer does not establish retained patch evidence.
        ("GHSA-jp4c-xjxw-mgf9", "< 26.1", "26.1", ["26.1"]),
    ],
)
def test_pip_historical_repair_changes_signed_answer_and_preserves_evidence(
    database, tmp_path, monkeypatch, advisory_id, expression, patch, old_candidates
):
    advisory = _github_advisory(
        advisory_id=advisory_id,
        name="pip",
        version="24.0",
        published_at="2025-01-01T00:00:00Z",
        updated_at="2026-05-20T20:54:26Z",
    )
    advisory["type"] = "reviewed"
    advisory["summary"] = "Synthetic pip source title"
    advisory["description"] = "Synthetic source context, not a local exposure claim."
    advisory["severity"] = "medium"
    advisory["vulnerabilities"] = [
        {
            "package": {"ecosystem": "pip", "name": "pip"},
            "vulnerable_version_range": expression,
            "first_patched_version": patch,
        }
    ]
    registry = RightsRegistry.from_path(RIGHTS_REGISTER)
    old_document = json.loads(
        (REPO_ROOT / "contracts/v1/source-governance-policy.json").read_text()
    )
    old_document["policy_version"] = "1.0.0"
    rule = next(r for r in old_document["sources"] if r["source_id"] == GITHUB_ADVISORY)
    rule["field_policy_id"] = "gbsec:field-policy:github-advisory-catalog-v2"
    rule["accepted_field_paths"] = [
        path
        for path in rule["accepted_field_paths"]
        if path
        not in {"vulnerabilities.first_patched_version", "summary", "description", "severity"}
    ]
    old_policy = SourceGovernancePolicy(old_document, registry=registry)
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=[advisory], request=request)

    with (
        closing(LocalImmutableEvidenceStore(tmp_path / "evidence")) as store,
        httpx.Client(transport=httpx.MockTransport(handler)) as upstream,
        _public_client(database) as api,
    ):
        collector = GitHubAdvisoryRestCollector(
            registry=registry,
            evidence_store=store,
            client=upstream,
            clock=lambda: NOW,
            governance_policy=active_governance_policy(),
            advisory_type="reviewed",
            catalog_mode=True,
        )
        with monkeypatch.context() as old:
            old.setattr(collector, "_governance_policy", old_policy)
            old.setattr(
                collector, "_catalog_processing_version", "github-advisory-catalog-4-reviewed"
            )
            with Session(database.engine) as session, session.begin():
                collector.backfill_advisory(session, advisory_id=advisory_id)
                original = session.scalar(select(AdvisoryCatalogRecord))
                original_id, original_hash = original.catalog_event_id, original.record_hash
                original_evidence_id = original.evidence_id
                evidence = session.scalar(select(EvidenceRecord))
                original_digest = evidence.sha256
            original_bytes = store.read_bytes(original_digest)
            assert (
                "first_patched_version" not in json.loads(original_bytes)[0]["vulnerabilities"][0]
            )

        request = {"ecosystem": "pypi", "name": "pip", "version": "24.0"}
        before_response = api.get("/v1/artifacts/assess", params=request)
        assert before_response.status_code == 200
        before = before_response.json()
        key = api.get("/v1/public-key.json").json()
        verify_signature(before, key)
        assert before["incidents"][0]["fixed_versions"] == old_candidates
        assert before["incidents"][0]["source_fixed_versions"] == []
        assert "historical_metadata_incomplete" in before["reason_codes"]
        assert "results_incomplete" in before["reason_codes"]
        assert before["incidents"][0]["fix_evidence_incomplete"] is True
        assert before["incidents"][0]["source_reports"][0]["fix_evidence_incomplete"] is True
        assert before["incidents"][0]["source_reports"][0]["source_context"] is None

        for created in (True, False):
            with Session(database.engine) as session, session.begin():
                result = collector.backfill_advisory(session, advisory_id=advisory_id)
                assert result.catalog_append_result.created is created
                assert result.catalog_append_result.revision == 2

        after_response = api.get("/v1/artifacts/assess", params=request)
        assert after_response.status_code == 200
        assert after_response.headers["cache-control"] == "no-store"
        after = after_response.json()
        verify_signature(after, key)
        assert after["feed_revision"] != before["feed_revision"]
        assert after["incidents"][0]["applies_to_version"] is True
        assert after["incidents"][0]["fixed_versions"] == [patch]
        assert after["incidents"][0]["source_reports"][0]["fixed_versions"] == [patch]
        assert after["incidents"][0]["source_fixed_versions"] == [patch]
        report = after["incidents"][0]["source_reports"][0]
        assert report["source_fixed_versions"] == [patch]
        assert report["fix_evidence"][0]["fixed_version"] == patch
        assert report["fix_evidence"][0]["applies_to_requested_version"] is True
        assert report["source_context"]["severity"] == "medium"
        assert report["source_context"]["title"] == "Synthetic pip source title"
        assert after["incidents"][0]["title"] != "Synthetic pip source title"
        assert "historical_metadata_incomplete" not in after["reason_codes"]
        assert after["identity_assurance"] == "caller_asserted"
        assert after["local_applicability"] == report["local_applicability"] == "not_evaluated"
        with Session(database.engine) as session:
            assert session.get(AdvisoryCatalogRecord, original_id).record_hash == original_hash
            assert (
                session.scalar(
                    select(EvidenceRecord.sha256).where(EvidenceRecord.id == original_evidence_id)
                )
                == original_digest
            )
            assert store.read_bytes(original_digest) == original_bytes
            assert session.query(AdvisoryCatalogRecord).count() == 2
            assert session.query(CollectorProgressRecord).count() == 0
        assert store.pending_manifest() == []
        assert len(requests) == 3
        assert all(r.url.params["ghsa_id"] == advisory_id for r in requests)
        assert all(r.url.params["type"] == "reviewed" for r in requests)
