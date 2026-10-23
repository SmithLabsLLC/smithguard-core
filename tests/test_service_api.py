"""Explicit local unpublished REST, pagination, limits, cache, and parity checks."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event, Lock
from time import sleep
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

import smithguard.api as api_module
import smithguard.coverage as coverage_module
import smithguard.service as service_module
from smithguard.advisory_catalog import append_github_advisory, append_openssf_advisory
from smithguard.anonymous_quota import AnonymousQuotaStore
from smithguard.api import (
    create_public_beta_app,
)
from smithguard.assessment_cache import AssessmentCacheCapacityError
from smithguard.collectors import GITHUB_ADVISORY
from smithguard.db.models import (
    CollectorProgressRecord,
    SourceIncidentLinkRecord,
)
from smithguard.db.repository import append_contract
from smithguard.feeds import SnapshotSigner
from smithguard.identifiers import canonical_json_bytes, stable_id, timestamp
from smithguard.incidents import (
    IncidentSeed,
    create_incident,
)
from smithguard.normalization import normalize_artifact_identity
from smithguard.signals import (
    PreliminaryWarningDraft,
    create_preliminary_warning,
    expire_due_warnings,
)
from smithguard.snapshot_archive import SnapshotArchive
from tests.api_client import TestClient, coverage_runtime
from tests.support import openssf_manifest_pair

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _example(
    contract_examples: list[dict[str, Any]],
    definition: str,
) -> dict[str, Any]:
    return deepcopy(
        next(entry["value"] for entry in contract_examples if entry["definition"] == definition)
    )


def _create_incident(
    session: Session,
    suffix: str,
    *,
    artifact_ids: tuple[str, ...] = (),
    range_ids: tuple[str, ...] = (),
    claim_ids: tuple[str, ...] = (),
    status: str = "confirmed",
    authority: dict[str, Any] | None = None,
) -> dict[str, Any]:
    incident_id = f"gbsec:incident:api-{suffix}"
    seed = IncidentSeed(
        incident_id=incident_id,
        title=f"Synthetic API incident {suffix}",
        initial_status=status,
        initial_confidence=("confirmed" if status == "confirmed" else "unverified"),
        claim_ids=claim_ids,
        artifact_ids=artifact_ids,
        affected_range_ids=range_ids,
        relationship_ids=(),
        coverage=(
            {
                "ecosystem": "npm",
                "stage": "matched",
                "result": "supported",
                "as_of": timestamp(NOW),
            },
        ),
        unknowns=("Synthetic fixture only.",),
        first_observed_at=NOW,
        created_at=NOW,
        authority_decision_ids=((authority["id"],) if authority is not None else ()),
        authority=authority,
    )
    return create_incident(
        session,
        seed=seed,
        event={
            "id": stable_id("event", incident_id, "created"),
            "kind": "incident_event",
            "schema_version": "1.0.0",
            "revision": 1,
            "created_at": timestamp(NOW),
            "updated_at": timestamp(NOW),
            "data_classification": "public",
            "incident_id": incident_id,
            "event_type": "created",
            "old_status": None,
            "new_status": status,
            "actor_type": "reviewer",
            "actor_id": "reviewer-api",
            "reason_code": "synthetic_created",
            "evidence_ids": [],
            "occurred_at": timestamp(NOW),
            "confidence": ("confirmed" if status == "confirmed" else "unverified"),
            "superseded_revision": None,
        },
    ).document


def _append_catalog_families(
    session: Session, count: int, *, version: str = "3.3.6", offset: int = 0
) -> None:
    alphabet = "23456789"

    def suffix(index: int) -> str:
        digits = []
        for _position in range(4):
            digits.append(alphabet[index % len(alphabet)])
            index //= len(alphabet)
        return "".join(reversed(digits))

    for index in range(offset, offset + count):
        ghsa_id = f"GHSA-2345-6789-{suffix(index)}"
        append_github_advisory(
            session,
            document={
                "ghsa_id": ghsa_id,
                "type": "reviewed",
                "published_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-02T00:00:00Z",
                "withdrawn_at": None,
                "html_url": f"https://github.com/advisories/{ghsa_id}",
                "cwes": [],
                "identifiers": [{"type": "GHSA", "value": ghsa_id}],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "npm", "name": "event-stream"},
                        "vulnerable_version_range": f"= {version}",
                    }
                ],
            },
            evidence_id=f"gbsec:evidence:catalog-family-{index:03d}",
            governance_decision_id=f"gbsec:governance:catalog-family-{index:03d}",
            observed_at=NOW,
        )


def _public_client(
    database,
    *,
    snapshot_root=None,
    signer=None,
    revoked_public_key_ids=frozenset(),
    raise_server_exceptions=True,
) -> TestClient:
    archive = SnapshotArchive(snapshot_root) if snapshot_root is not None else None
    app = create_public_beta_app(
        session_factory=sessionmaker(database.engine),
        signer=signer or SnapshotSigner.ephemeral(),
        base_url="https://security.example",
        clock=lambda: NOW,
        snapshot_archive=archive,
        revoked_public_key_ids=revoked_public_key_ids,
        anonymous_quota_store=AnonymousQuotaStore(),
        anonymous_quota_secret=b"synthetic-public-quota-secret!!!",
        trusted_proxy_header=True,
    )
    return TestClient(
        app,
        base_url="https://security.example",
        client=("127.0.0.1", 50000),
        headers={"X-Forwarded-For": "8.8.8.8"},
        raise_server_exceptions=raise_server_exceptions,
    )


def _update_progress(
    sequence: int,
    *,
    state: str = "complete",
    occurred_at: datetime = NOW,
    segment: str = "malware",
) -> CollectorProgressRecord:
    return CollectorProgressRecord(
        progress_event_id=f"gbsec:collector-progress:api-{segment}-{sequence}",
        source_id=GITHUB_ADVISORY,
        segment=segment,
        lane="updates",
        sequence=sequence,
        state=state,
        cursor_value=None,
        cursor_parameter=None,
        page_count=sequence,
        source_record_count=sequence,
        normalized_record_count=sequence,
        window_started_at=occurred_at - timedelta(hours=1),
        window_ended_at=occurred_at,
        oldest_published_at=None,
        newest_published_at=None,
        reason_code="synthetic_api_progress",
        occurred_at=occurred_at,
        record_hash="sha256:" + f"{sequence + 200:064x}",
    )


def test_public_artifact_assessment_uses_the_same_canonical_incident(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    artifact = _example(contract_examples, "Artifact")
    affected_range = _example(contract_examples, "AffectedRange")
    claim = _example(contract_examples, "Claim")
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    source = _example(contract_examples, "Source")
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Source", source)
        append_contract(session, "Artifact", artifact)
        append_contract(session, "AffectedRange", affected_range)
        append_contract(session, "Claim", claim)
        incident = _create_incident(
            session,
            "artifact",
            artifact_ids=(artifact["id"],),
            range_ids=(affected_range["id"],),
            claim_ids=(claim["id"],),
        )
        session.add(
            SourceIncidentLinkRecord(
                link_event_id="gbsec:source-link:api-artifact-1",
                source_id=source["id"],
                upstream_record_id="GHSA-2345-6789-cfgh",
                artifact_id=artifact["id"],
                incident_id=incident["id"],
                sequence=1,
                state="active",
                source_updated_at=NOW,
                evidence_id="gbsec:evidence:synthetic-ghsa-record-001",
                observed_at=NOW,
                record_hash="sha256:" + "a" * 64,
            )
        )
        session.add(
            SourceIncidentLinkRecord(
                link_event_id="gbsec:source-link:api-artifact-2",
                source_id=source["id"],
                upstream_record_id="GHSA-2345-6789-cfgh",
                artifact_id=artifact["id"],
                incident_id=incident["id"],
                sequence=2,
                state="withdrawn",
                source_updated_at=NOW + timedelta(minutes=1),
                evidence_id="gbsec:evidence:synthetic-ghsa-record-001",
                observed_at=NOW + timedelta(minutes=1),
                record_hash="sha256:" + "b" * 64,
            )
        )
        append_github_advisory(
            session,
            document={
                "ghsa_id": "GHSA-2345-6789-cfgh",
                "type": "reviewed",
                "published_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-02T00:00:00Z",
                "withdrawn_at": None,
                "html_url": "https://github.com/advisories/GHSA-2345-6789-cfgh",
                "cwes": [{"cwe_id": "CWE-506"}],
                "identifiers": [{"type": "GHSA", "value": "GHSA-2345-6789-cfgh"}],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "npm", "name": "event-stream"},
                        "vulnerable_version_range": "= 3.3.6",
                    }
                ],
            },
            evidence_id="gbsec:evidence:synthetic-ghsa-record-001",
            governance_decision_id="gbsec:governance:synthetic-ghsa-record-001",
            observed_at=NOW,
        )
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
        assert response.status_code == 200
        result = response.json()
        assert result["result"] == "affected"
        assert result["incident_ids"] == [incident["id"]]
        assert affected_range["id"] in result["affected_range_ids"]
        assert len(result["affected_range_ids"]) == 2
        assert result["schema_version"] == "2.2.0"
        assert result["relationship_state"] == "single_incident_record"
        assert len(result["incidents"]) == 1
        projected = result["incidents"][0]
        assert projected["incident_id"] == incident["id"]
        assert projected["title"] == incident["title"]
        assert projected["classification"] == "compromised"
        assert projected["status"] == "confirmed"
        assert projected["confidence"] == "confirmed"
        assert projected["relationship_basis"] == "catalog_assignment"
        assert len(projected["source_reports"]) == 1
        assert projected["source_reports"][0]["state"] == "active"
        assert result["preliminary_warnings"] == []
        assert result["preliminary_warnings_truncated"] is False
        wrong_registry = deepcopy(request)
        wrong_registry["artifact"]["registry_host"] = "pypi.org"
        mismatch = client.post("/v1/artifacts/assess", json=wrong_registry)
        assert mismatch.status_code == 400
        assert mismatch.json()["error"]["code"] == "invalid_request"
        inexact = deepcopy(request)
        inexact["artifact"]["version"] = None
        inexact["artifact"]["digest"] = None
        rejected = client.post("/v1/artifacts/assess", json=inexact)
        assert rejected.status_code == 400
        assert rejected.json()["error"]["code"] == "invalid_request"
        too_large = client.post(
            "/v1/artifacts/assess",
            content=b" " * 8193,
            headers={"content-type": "application/json"},
        )
        assert too_large.status_code == 413
        wrong_media = client.post(
            "/v1/artifacts/assess",
            content=b"{}",
            headers={"content-type": "text/plain"},
        )
        assert wrong_media.status_code == 415
        duplicate = client.post(
            "/v1/artifacts/assess",
            content=b'{"id":"one","id":"two"}',
            headers={"content-type": "application/problem+json"},
        )
        assert duplicate.status_code == 400
        assert duplicate.json()["error"]["code"] == "invalid_request"
        assert duplicate.json()["error"]["message"] == "request contains a duplicate JSON key"
        malformed = client.post(
            "/v1/artifacts/assess",
            content=b"{",
            headers={"content-type": "application/json"},
        )
        assert malformed.status_code == 400
        assert malformed.json()["error"]["message"] == "request body is not valid JSON"
        # A UTF-16 body decodes as json.loads decoded it and is judged on its content.
        utf8_result = client.post(
            "/v1/artifacts/assess",
            content=b'{"id":"one"}',
            headers={"content-type": "application/json"},
        )
        utf16 = client.post(
            "/v1/artifacts/assess",
            content='{"id":"one"}'.encode("utf-16"),
            headers={"content-type": "application/json"},
        )
        assert utf16.status_code == utf8_result.status_code == 400
        assert utf16.json() == utf8_result.json()
        assert "codec" not in utf16.json()["error"]["message"]
        deep = client.post(
            "/v1/artifacts/assess",
            content=b"[" * 40 + b"]" * 40,
            headers={"content-type": "application/json"},
        )
        assert deep.status_code == 400
        assert deep.json()["error"]["message"] == "request must be a JSON object"
        non_finite = client.post(
            "/v1/artifacts/assess",
            content=b'{"id": NaN}',
            headers={"content-type": "application/json"},
        )
        assert non_finite.status_code == 400
        assert non_finite.json()["error"]["code"] == "invalid_request"
        # The decoder keeps its previous behavior; contract validation supplies
        # the same response as for any other object with an invalid request shape.
        assert non_finite.json() == utf8_result.json()


def test_artifact_assessment_truncates_distinct_source_reports_honestly(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    artifact = _example(contract_examples, "Artifact")
    affected_range = _example(contract_examples, "AffectedRange")
    claim = _example(contract_examples, "Claim")
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    source = _example(contract_examples, "Source")
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Source", source)
        append_contract(session, "Artifact", artifact)
        append_contract(session, "AffectedRange", affected_range)
        append_contract(session, "Claim", claim)
        incident = _create_incident(
            session,
            "source-report-bound",
            artifact_ids=(artifact["id"],),
            range_ids=(affected_range["id"],),
            claim_ids=(claim["id"],),
        )
        for index in range(101):
            session.add(
                SourceIncidentLinkRecord(
                    link_event_id=f"gbsec:source-link:api-bound-{index:03d}",
                    source_id=source["id"],
                    upstream_record_id=f"GHSA-0000-0000-{index:04d}",
                    artifact_id=artifact["id"],
                    incident_id=incident["id"],
                    sequence=1,
                    state="active",
                    source_updated_at=NOW,
                    evidence_id=f"gbsec:evidence:api-bound-{index:03d}",
                    observed_at=NOW,
                    record_hash="sha256:" + f"{index + 1:064x}",
                )
            )
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
    assert response.status_code == 200
    projected = response.json()["incidents"][0]
    assert len(projected["source_reports"]) == 100
    assert projected["source_reports_truncated"] is True
    assert projected["relationship_basis"] == "catalog_assignment"


@pytest.mark.parametrize(
    ("source_type", "ghsa_id", "expected_result"),
    [
        ("reviewed", "GHSA-2345-6789-cfgj", "affected"),
        ("unreviewed", "GHSA-2345-6789-cfgr", "possibly_affected"),
    ],
)
def test_http_assessment_honors_reviewed_and_unreviewed_catalog_confidence(
    database,
    contract_examples: list[dict[str, Any]],
    source_type: str,
    ghsa_id: str,
    expected_result: str,
) -> None:
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    with Session(database.engine) as session, session.begin():
        append_github_advisory(
            session,
            document={
                "ghsa_id": ghsa_id,
                "type": source_type,
                "published_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-02T00:00:00Z",
                "withdrawn_at": None,
                "html_url": f"https://github.com/advisories/{ghsa_id}",
                "cwes": [],
                "identifiers": [{"type": "GHSA", "value": ghsa_id}],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "npm", "name": "event-stream"},
                        "vulnerable_version_range": "= 3.3.6",
                    }
                ],
            },
            evidence_id=f"gbsec:evidence:http-{source_type}",
            governance_decision_id=f"gbsec:governance:http-{source_type}",
            observed_at=NOW,
        )
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
    assert response.status_code == 200
    body = response.json()
    assert body["result"] == expected_result
    assert len(body["incidents"]) == 1
    assert body["incidents"][0]["classification"] == "vulnerable"
    assert body["incidents"][0]["confidence"] == (
        "confirmed" if source_type == "reviewed" else "unverified"
    )


def test_reported_exact_malware_is_possible_not_confirmed_exposure(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    artifact = _example(contract_examples, "Artifact")
    affected_range = _example(contract_examples, "AffectedRange")
    claim = _example(contract_examples, "Claim")
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Artifact", artifact)
        append_contract(session, "AffectedRange", affected_range)
        append_contract(session, "Claim", claim)
        incident = _create_incident(
            session,
            "reported-artifact",
            artifact_ids=(artifact["id"],),
            range_ids=(affected_range["id"],),
            claim_ids=(claim["id"],),
            status="reported",
        )
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
        assert response.status_code == 200
        result = response.json()
        assert result["result"] == "possibly_affected"
        assert result["incident_ids"] == [incident["id"]]
        assert "not yet confirmed" in " ".join(result["unknowns"])


def test_artifact_assessment_does_not_cross_pair_incidents_or_stale_ranges(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    artifact = _example(contract_examples, "Artifact")
    exact_range = _example(contract_examples, "AffectedRange")
    exact_claim = _example(contract_examples, "Claim")
    nonexact_range = {
        **deepcopy(exact_range),
        "id": "gbsec:range:api-nonexact",
        "expression": "= 9.9.9",
        "introduced": "9.9.9",
        "last_affected": "9.9.9",
    }
    nonexact_claim = {
        **deepcopy(exact_claim),
        "id": "gbsec:claim:api-nonexact",
        "subject_id": artifact["id"],
    }
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Artifact", artifact)
        append_contract(session, "AffectedRange", exact_range)
        append_contract(session, "AffectedRange", nonexact_range)
        append_contract(session, "Claim", exact_claim)
        append_contract(session, "Claim", nonexact_claim)
        confirmed = _create_incident(
            session,
            "confirmed-nonexact",
            artifact_ids=(artifact["id"],),
            range_ids=(nonexact_range["id"],),
            claim_ids=(nonexact_claim["id"],),
        )
        reported = _create_incident(
            session,
            "reported-exact",
            artifact_ids=(artifact["id"],),
            range_ids=(exact_range["id"],),
            claim_ids=(exact_claim["id"],),
            status="reported",
        )
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
        assert response.status_code == 200
        assert response.json()["result"] == "possibly_affected"
        # The confirmed incident's range excludes 3.3.6: it is counted, not listed.
        assert response.json()["incident_ids"] == [reported["id"]]
        assert response.json()["not_applicable_incident_count"] == 1
        assert confirmed["id"] not in response.json()["incident_ids"]
        assert response.json()["relationship_state"] == "not_confirmed"

    stale_range = {
        **deepcopy(exact_range),
        "revision": 2,
        "updated_at": timestamp(NOW + timedelta(minutes=1)),
        "expression": "= 8.8.8",
        "introduced": "8.8.8",
        "last_affected": "8.8.8",
    }
    with Session(database.engine) as session, session.begin():
        append_contract(session, "AffectedRange", stale_range)
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
        assert response.status_code == 200
        assert response.json()["result"] == "not_affected"
        assert exact_range["id"] not in response.json()["affected_range_ids"]

    with Session(database.engine) as session, session.begin():
        create_preliminary_warning(
            session,
            draft=PreliminaryWarningDraft(
                title="Synthetic warning overrides a negative official range result",
                claim="A public early lead requires investigation despite the older range result.",
                affected_artifacts=("npm:event-stream@3.3.6",),
                source_urls=("https://example.net/emerging-lead",),
                evidence_class="web_only",
                independent_source_clusters=1,
                observed_at=NOW,
                reviewer_id="reviewer:api-test",
            ),
            reviewed_at=NOW,
        )
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
        assert response.status_code == 200
        assert response.json()["result"] == "possibly_affected"
        assert len(response.json()["preliminary_warnings"]) == 1

    stale_artifact = {
        **deepcopy(artifact),
        "revision": 2,
        "updated_at": timestamp(NOW + timedelta(minutes=2)),
        "version": "8.8.8",
    }
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Artifact", stale_artifact)
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
        assert response.status_code == 200
        assert response.json()["result"] == "possibly_affected"
        assert len(response.json()["preliminary_warnings"]) == 1
        assert response.json()["incident_ids"] == []


def test_resolved_incident_preserves_its_confirmed_authority_lineage(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    artifact = _example(contract_examples, "Artifact")
    affected_range = _example(contract_examples, "AffectedRange")
    claim = _example(contract_examples, "Claim")
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    incident_id = "gbsec:incident:api-resolved-authority"
    authority = _example(contract_examples, "AuthorityDecision")
    authority.update(
        {
            "id": "gbsec:authority-decision:api-resolved",
            "incident_id": incident_id,
            "artifact_id": artifact["id"],
            "claim_id": "gbsec:claim:api-resolved",
            "evidence_ids": ["gbsec:evidence:api-resolved"],
            "public_status": "confirmed",
            "confirmation_method": "automated_source_policy",
            "created_at": timestamp(NOW),
            "updated_at": timestamp(NOW),
            "decided_at": timestamp(NOW),
        }
    )
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Artifact", artifact)
        append_contract(session, "AffectedRange", affected_range)
        append_contract(session, "Claim", claim)
        append_contract(session, "AuthorityDecision", authority)
        incident = _create_incident(
            session,
            "resolved-authority",
            artifact_ids=(artifact["id"],),
            range_ids=(affected_range["id"],),
            claim_ids=(claim["id"],),
            status="resolved",
            authority=authority,
        )
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
        assert response.status_code == 200
        result = response.json()
        assert result["result"] == "affected"
        assert result["incident_ids"] == [incident["id"]]
        assert "not yet confirmed" not in " ".join(result["unknowns"])


def test_go_and_rust_artifact_assessments_return_honest_research_coverage(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    cases = (
        ("go", "proxy.golang.org", "example.com/module"),
        ("rust", "crates.io", "serde"),
    )
    with _public_client(database) as client:
        for ecosystem, registry_host, name in cases:
            candidate = deepcopy(request)
            candidate["id"] = f"gbsec:request:public-artifact-{ecosystem}"
            candidate["artifact"].update(
                {
                    "ecosystem": ecosystem,
                    "registry_host": registry_host,
                    "name": name,
                    "version": "1.0.0",
                    "digest": None,
                }
            )
            response = client.post("/v1/artifacts/assess", json=candidate)
            assert response.status_code == 200
            assert response.json()["result"] == "unknown"
            assert response.json()["coverage"] == {
                "ecosystem": ecosystem,
                "stage": "research",
                "result": "unknown",
                "as_of": timestamp(NOW),
            }


def test_artifact_assessment_fails_closed_above_its_correlation_bound(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    artifact = _example(contract_examples, "Artifact")
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Artifact", artifact)
        for index in range(101):
            _create_incident(
                session,
                f"correlation-{index:03d}",
                artifact_ids=(artifact["id"],),
            )
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "service_capacity_exceeded"
        assert response.json()["error"]["retryable"] is False
        assert response.json()["error"]["message"] == (
            "artifact assessment exceeds the current correlation bound"
        )


def test_more_than_100_applicable_catalog_families_are_truncated_not_refused(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    with Session(database.engine) as session, session.begin():
        _append_catalog_families(session, 101)
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
    assert response.status_code == 200
    body = response.json()
    assert body["result"] == "affected"
    assert len(body["incidents"]) == 100
    assert body["incidents_truncated"] is True
    assert body["not_applicable_incident_count"] == 0


def test_families_that_exclude_the_version_are_counted_not_listed(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    """A popular package with many old advisories still gets an answer."""
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    with Session(database.engine) as session, session.begin():
        _append_catalog_families(session, 150, version="9.9.9")
        _append_catalog_families(session, 1, offset=200)
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
    assert response.status_code == 200
    body = response.json()
    assert body["result"] == "affected"
    assert [item["applies_to_version"] for item in body["incidents"]] == [True]
    assert body["not_applicable_incident_count"] == 150
    assert body["incidents_truncated"] is False


@pytest.mark.parametrize(
    ("legacy_count", "catalog_count"),
    [(100, 1), (1, 100)],
)
def test_merged_incidents_above_100_are_truncated(
    database,
    contract_examples: list[dict[str, Any]],
    legacy_count: int,
    catalog_count: int,
) -> None:
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    artifact = _example(contract_examples, "Artifact")
    affected_range = _example(contract_examples, "AffectedRange")
    claim = _example(contract_examples, "Claim")
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Artifact", artifact)
        append_contract(session, "AffectedRange", affected_range)
        append_contract(session, "Claim", claim)
        for index in range(legacy_count):
            _create_incident(
                session,
                f"merged-correlation-{index:03d}",
                artifact_ids=(artifact["id"],),
                range_ids=(affected_range["id"],),
                claim_ids=(claim["id"],),
            )
        _append_catalog_families(session, catalog_count)
    with _public_client(database) as client:
        response = client.post("/v1/artifacts/assess", json=request)
    assert response.status_code == 200
    body = response.json()
    assert len(body["incidents"]) == 100
    assert body["incidents_truncated"] is True


def test_public_assessment_keeps_the_event_loop_responsive_and_caps_database_work(
    database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered_eight = Event()
    release = Event()
    lock = Lock()
    active = 0
    maximum_active = 0

    def bounded_assessment(_self, _session, _request):
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
            if active == api_module.PUBLIC_ASSESSMENT_CONCURRENCY:
                entered_eight.set()
        try:
            assert release.wait(timeout=3)
            return {"bounded": True}
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        service_module.SmithGuardService,
        "assess_public_artifact",
        bounded_assessment,
    )
    monkeypatch.setattr(
        service_module.SmithGuardService,
        "validate_public_artifact_request",
        lambda _self, request: (request, request),
    )
    monkeypatch.setattr(
        service_module.SmithGuardService,
        "project_public_artifact_response",
        lambda _self, response, _parsed: response,
    )
    with _public_client(database) as client, ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(
                client.post,
                "/v1/artifacts/assess",
                json={"synthetic": index},
                headers={"X-Forwarded-For": f"8.8.4.{index + 1}"},
            )
            for index in range(10)
        ]
        assert entered_eight.wait(timeout=3)
        assert client.get("/healthz").status_code == 200
        with lock:
            assert maximum_active == api_module.PUBLIC_ASSESSMENT_CONCURRENCY
        release.set()
        assert all(future.result(timeout=3).status_code == 200 for future in futures)


@pytest.mark.audit_ids("API-14")
def test_public_quota_disk_work_does_not_block_health_requests(
    database,
    contract_examples: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = Event()
    release = Event()
    original_reserve = AnonymousQuotaStore.reserve

    def slow_reserve(self, **kwargs):
        entered.set()
        assert release.wait(timeout=3)
        return original_reserve(self, **kwargs)

    monkeypatch.setattr(AnonymousQuotaStore, "reserve", slow_reserve)
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    with _public_client(database) as client, ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(client.post, "/v1/artifacts/assess", json=request)
        assert entered.wait(timeout=3)
        assert client.get("/healthz").status_code == 200
        release.set()
        assert future.result(timeout=3).status_code == 200


@pytest.mark.audit_ids("API-04")
def test_public_assessment_cache_serves_101_repeats_with_one_quota_charge(
    database,
    contract_examples: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # This binding measures reuse with unchanged evidence. Other parallel test
    # databases share PostgreSQL's cluster-wide XID clock; correction tests cover
    # the real watermark separately.
    monkeypatch.setattr(api_module, "assessment_watermark", lambda _session: "unchanged")
    reserve_calls = 0
    assessment_calls = 0
    first_assessment_entered = Event()
    release_first_assessment = Event()
    start = Barrier(102)
    original_reserve = AnonymousQuotaStore.reserve
    original_assess = service_module.SmithGuardService.assess_public_artifact

    def count_reserve(self, **kwargs):
        nonlocal reserve_calls
        reserve_calls += 1
        return original_reserve(self, **kwargs)

    def slow_first_assessment(self, session, request):
        nonlocal assessment_calls
        assessment_calls += 1
        first_assessment_entered.set()
        assert release_first_assessment.wait(timeout=5)
        return original_assess(self, session, request)

    monkeypatch.setattr(AnonymousQuotaStore, "reserve", count_reserve)
    monkeypatch.setattr(
        service_module.SmithGuardService,
        "assess_public_artifact",
        slow_first_assessment,
    )
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    with _public_client(database) as client, ThreadPoolExecutor(max_workers=101) as executor:

        def send_request() -> Any:
            start.wait(timeout=5)
            return client.post("/v1/artifacts/assess", json=request)

        futures = [executor.submit(send_request) for _index in range(101)]
        start.wait(timeout=5)
        assert first_assessment_entered.wait(timeout=5)
        sleep(0.25)
        release_first_assessment.set()
        responses = [future.result(timeout=10) for future in futures]
    assert all(response.status_code == 200 for response in responses)
    assert sum("X-SmithGuard-Cache" not in response.headers for response in responses) == 1
    assert sum(response.headers.get("X-SmithGuard-Cache") == "hit" for response in responses) == 100
    assert reserve_calls == 1
    assert assessment_calls == 1


@pytest.mark.audit_ids("API-02")
def test_public_coverage_and_assessment_share_one_cached_report(
    database,
    contract_examples: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builds = 0
    original_build = coverage_module._build_coverage_report
    coverage_module._COVERAGE_REPORT_CACHE.clear()

    def count_build(*args, **kwargs):
        nonlocal builds
        builds += 1
        return original_build(*args, **kwargs)

    monkeypatch.setattr(coverage_module, "_build_coverage_report", count_build)
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    with _public_client(database) as client:
        assert client.get("/v1/coverage.json").status_code == 200
        assert client.post("/v1/artifacts/assess", json=request).status_code == 200
    assert builds == 1


@pytest.mark.audit_ids("API-06", "API-14")
def test_public_assessment_has_an_end_to_end_processing_deadline(
    database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = Event()

    def slow_assessment(_self, _session, _request):
        release.wait(timeout=1)
        return {"late": True}

    monkeypatch.setattr(api_module, "PUBLIC_ASSESSMENT_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(
        service_module.SmithGuardService,
        "assess_public_artifact",
        slow_assessment,
    )
    monkeypatch.setattr(
        service_module.SmithGuardService,
        "validate_public_artifact_request",
        lambda _self, request: (request, {}),
    )
    try:
        with _public_client(database) as client:
            response = client.post("/v1/artifacts/assess", json={"synthetic": True})
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "request_deadline_exceeded"
    finally:
        release.set()


def test_timed_out_assessment_keeps_its_worker_slot_until_database_work_ends(
    database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = Event()
    entered = Event()
    exited = Event()
    calls = 0

    def slow_assessment(_self, _session, _request):
        nonlocal calls
        calls += 1
        entered.set()
        try:
            assert release.wait(timeout=10)
            return {"late": True}
        finally:
            exited.set()

    monkeypatch.setattr(api_module, "PUBLIC_ASSESSMENT_CONCURRENCY", 1)
    # Allow database/quota setup under parallel-suite load. This test needs the
    # worker to start before its caller times out; the worker stays held explicitly.
    monkeypatch.setattr(api_module, "PUBLIC_ASSESSMENT_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(
        service_module.SmithGuardService,
        "assess_public_artifact",
        slow_assessment,
    )
    monkeypatch.setattr(
        service_module.SmithGuardService,
        "validate_public_artifact_request",
        # Distinct identities exercise the shared worker bound, not single-flight.
        lambda _self, request: (
            request,
            {"ecosystem": "npm", "name": f"synthetic-{request['synthetic']}", "version": "1.0.0"},
        ),
    )
    with _public_client(database) as client:
        runtime = coverage_runtime(client.app)
        try:
            first = client.post("/v1/artifacts/assess", json={"synthetic": 1})
            assert entered.is_set() and not exited.is_set()
            assert client.portal.call(runtime.assessment_slots.locked)
            second = client.post("/v1/artifacts/assess", json={"synthetic": 2})
            assert first.status_code == second.status_code == 503
            assert first.json()["error"]["code"] == "request_deadline_exceeded"
            assert second.json()["error"]["code"] == "request_deadline_exceeded"
            assert calls == 1 and not exited.is_set()
            assert client.portal.call(runtime.assessment_slots.locked)
        finally:
            release.set()
        assert exited.wait(timeout=5)
        assert client.portal.call(runtime.run_bounded, lambda: "slot_released") == "slot_released"


@pytest.mark.audit_ids("DATA-02")
def test_retired_public_snapshot_keeps_old_verification_keys_available(
    database,
    tmp_path,
) -> None:
    snapshot_root = tmp_path / "snapshots"
    snapshot_root.mkdir(mode=0o750)
    first_signer = SnapshotSigner.ephemeral()
    # The archive is read-only since the producer and retention pass were removed;
    # a retained key document is written the way the historical archive left it.
    (snapshot_root / f"{first_signer.public_key_id}.public-key.json").write_bytes(
        canonical_json_bytes(first_signer.public_key_document())
    )
    assert SnapshotArchive(snapshot_root).public_key_document(first_signer.public_key_id) == (
        first_signer.public_key_document()
    )
    assert len(tuple(snapshot_root.glob("*.public-key.json"))) == 1

    second_signer = SnapshotSigner.ephemeral()
    with _public_client(
        database,
        snapshot_root=snapshot_root,
        signer=second_signer,
        revoked_public_key_ids=frozenset({first_signer.public_key_id}),
    ) as second:
        assert second.get("/v1/snapshot.json").status_code == 404
        old_key = second.get(f"/v1/public-keys/{first_signer.public_key_id}.json")
        assert old_key.status_code == 200
        assert old_key.json()["status"] == "revoked"
        assert old_key.json()["canonicalization"] == "smithguard-canonical-json-v1"
    assert len(tuple(snapshot_root.glob("*.public-key.json"))) == 1

    with pytest.raises(ValueError, match="active snapshot signing key is revoked"):
        _public_client(
            database,
            snapshot_root=snapshot_root,
            signer=second_signer,
            revoked_public_key_ids=frozenset({second_signer.public_key_id}),
        )


def test_every_retired_public_catalog_route_uses_the_unknown_route_envelope(database) -> None:
    retired_paths = (
        "/v1/incidents",
        "/v1/incidents/gbsec:incident:retired-test",
        "/v1/incidents/gbsec:incident:retired-test/changes",
        "/v1/incidents/gbsec:incident:retired-test/actions",
        "/v1/delivery-events",
        "/v1/delivery-events/feed.json",
        "/v1/feed.json",
        "/v1/feed.atom",
        "/v1/signals",
        "/v1/signals/gbsec:preliminary-warning:retired-test",
        "/v1/snapshot.json",
    )

    startup_complete = False

    def forbidden_session():
        if startup_complete:
            raise AssertionError("retired public routes must not read the database")
        return Session(database.engine)

    public_app = create_public_beta_app(
        session_factory=forbidden_session,
        signer=SnapshotSigner.ephemeral(),
        base_url="https://security.example",
        clock=lambda: NOW,
        anonymous_quota_store=AnonymousQuotaStore(),
        anonymous_quota_secret=b"synthetic-public-quota-secret!!!",
    )
    with TestClient(public_app, base_url="https://security.example") as public:
        startup_complete = True
        for path in retired_paths:
            response = public.get(path)
            assert response.status_code == 404, path
            assert response.json() == {
                "error": {
                    "code": "not_found",
                    "message": "The requested route is not available.",
                    "retryable": False,
                }
            }
        for response in (
            public.post("/healthz"),
            public.put("/v1/artifacts/assess"),
        ):
            assert response.status_code == 405
            assert response.json() == {
                "error": {
                    "code": "method_not_allowed",
                    "message": "The requested method is not available for this route.",
                    "retryable": False,
                }
            }
            assert response.headers["X-SmithGuard-Service-State"] == "public-beta"
        # HEAD answers read-only routes (no body) and stays 405 for the assessment.
        head = public.head("/healthz")
        assert head.status_code == 200
        assert head.content == b""
        assert head.headers["X-SmithGuard-Service-State"] == "public-beta"
        assert public.head("/v1/artifacts/assess").status_code == 405


@pytest.mark.audit_ids("API-14")
def test_public_app_returns_generic_503_and_logs_only_exception_class(
    database, monkeypatch
) -> None:
    logged: list[tuple[str, str]] = []
    monkeypatch.setattr(
        api_module.LOGGER,
        "error",
        lambda message, class_name: logged.append((message, class_name)),
    )

    startup_complete = False

    def failing_session():
        if startup_complete:
            raise RuntimeError("private internal failure detail")
        return Session(database.engine)

    public_app = create_public_beta_app(
        session_factory=failing_session,
        signer=SnapshotSigner.ephemeral(),
        base_url="https://security.example",
        clock=lambda: NOW,
        anonymous_quota_store=AnonymousQuotaStore(),
        anonymous_quota_secret=b"synthetic-public-quota-secret!!!",
    )
    with TestClient(
        public_app,
        base_url="https://security.example",
        raise_server_exceptions=False,
    ) as public:
        startup_complete = True
        coverage_module._COVERAGE_REPORT_CACHE.clear()
        response = public.get("/v1/coverage.json")
    assert response.status_code == 503
    assert response.json() == {
        "error": {
            "code": "service_unavailable",
            "message": "The service is temporarily unavailable.",
            "retryable": True,
        }
    }
    assert response.headers["X-SmithGuard-Service-State"] == "public-beta"
    assert logged == [("Unhandled public exception type=%s", "RuntimeError")]


def test_public_beta_exposes_agent_quick_start_and_honest_source_coverage(
    database,
) -> None:
    with _public_client(database) as client:
        root = client.get("/")
        assert root.status_code == 200
        # Public display labels use the approved SmithGuard name; the
        # local-unpublished and unavailable surfaces keep the working name.
        assert root.json()["name"] == "SmithGuard"
        assert client.app.title == "SmithGuard public beta"
        assert root.json()["quick_start"]["coverage"] == "/v1/coverage.json"
        assert root.json()["quick_start"]["openapi"] == "/openapi.json"
        assert "incidents" not in root.json()["quick_start"]
        assert "signed_snapshot" not in root.json()["quick_start"]
        coverage = client.get("/v1/coverage.json")
        assert coverage.status_code == 200
        source_lanes = coverage.json()["source_lanes"]
        assert len(source_lanes) == 11
        assert {
            lane["source_id"] for lane in source_lanes if lane["record_type"] == "origin_advisory"
        } == {"gbsec:source:rustsec-advisory-database", "gbsec:source:go-vulnerability-database"}
        assert {(lane["lane"], lane["record_type"], lane["state"]) for lane in source_lanes} == {
            ("historical", "malware_advisory", "not_started"),
            ("updates", "malware_advisory", "not_started"),
            ("historical", "reviewed_advisory", "not_started"),
            ("updates", "reviewed_advisory", "not_started"),
            ("historical", "unreviewed_advisory", "not_started"),
            ("updates", "unreviewed_advisory", "not_started"),
            ("historical", "malicious_package_catalog", "not_started"),
            ("updates", "exploit_prediction_context", "not_started"),
            ("updates", "known_exploited_context", "not_started"),
            ("updates", "origin_advisory", "not_started"),
        }
        assert all(lane["unknowns"] for lane in source_lanes)
        openapi = client.get("/openapi.json")
        assert openapi.status_code == 200
        assert openapi.json()["info"]["title"] == "SmithGuard contract"
        assert openapi.json()["x-smithguard-service-state"] == "public_beta"
        operation = openapi.json()["paths"]["/v1/coverage.json"]["get"]
        assert operation["x-smithguard-availability"] == "public_beta"
        assert operation["x-smithguard-read-only"]
        for retired_path in (
            "/v1/incidents",
            "/v1/incidents/{incident_id}",
            "/v1/incidents/{incident_id}/changes",
            "/v1/incidents/{incident_id}/actions",
            "/v1/delivery-events",
            "/v1/delivery-events/feed.json",
            "/v1/feed.json",
            "/v1/feed.atom",
            "/v1/signals",
            "/v1/signals/{signal_id}",
            "/v1/snapshot.json",
        ):
            assert retired_path not in openapi.json()["paths"]
        invalid_key = client.get("/v1/public-keys/invalid.json")
        assert invalid_key.status_code == 400
        assert invalid_key.json()["error"]["code"] == "invalid_request"
        assert invalid_key.headers["x-smithguard-service-state"] == "public-beta"


def test_public_beta_rejects_noncanonical_host(database) -> None:
    with _public_client(database) as client:
        assert client.get("/healthz").status_code == 200
        for host in ("guard-staging.smithlabs.ai", "unrelated.invalid"):
            assert client.get("/healthz", headers={"Host": host}).status_code == 400


def test_public_beta_live_response_families_match_generated_openapi(database) -> None:
    with _public_client(database) as client:
        openapi = client.get("/openapi.json").json()
        responses = (
            ("/", "get", client.get("/")),
            ("/healthz", "get", client.get("/healthz")),
            ("/readyz", "get", client.get("/readyz")),
            ("/v1/coverage.json", "get", client.get("/v1/coverage.json")),
            ("/v1/public-key.json", "get", client.get("/v1/public-key.json")),
        )
        for path, method, response in responses:
            media_type = response.headers["content-type"].split(";", 1)[0]
            schema = openapi["paths"][path][method]["responses"][str(response.status_code)][
                "content"
            ][media_type]["schema"]
            instance = (
                response.json()
                if media_type == "application/json" or media_type.endswith("+json")
                else response.text
            )
            Draft202012Validator(
                {
                    "allOf": [schema],
                    "components": openapi["components"],
                }
            ).validate(instance)


def test_public_beta_has_no_customer_inventory_upload_surface(database) -> None:
    private_paths = {
        "/v1/exposure/match",
        "/v1/dependency-changes/assess",
    }
    private_components = {
        "InventorySnapshot",
        "DependencyDelta",
        "PrivateWatchlistSet",
        "PrivateWatchlistRejection",
        "AssessmentReceipt",
        "PolicyDecision",
        "PolicyException",
    }
    with _public_client(database) as client:
        openapi = client.get("/openapi.json").json()
        assert private_paths.isdisjoint(openapi["paths"])
        assert private_components.isdisjoint(openapi["components"]["schemas"])

        operations = {
            operation["operationId"]: operation
            for path_item in openapi["paths"].values()
            for method, operation in path_item.items()
            if method in {"get", "post", "put", "patch", "delete"}
        }
        request_operations = {
            operation_id: operation["requestBody"]["content"]["application/json"]["schema"]
            for operation_id, operation in operations.items()
            if "requestBody" in operation
        }
        assert request_operations == {
            "assess_public_artifact": {
                "oneOf": [
                    {"$ref": "#/components/schemas/PublicArtifactAssessmentShortRequest"},
                    {"$ref": "#/components/schemas/PublicArtifactAssessmentRequest"},
                ]
            }
        }
        assert {
            (method, route.path)
            for route in client.app.routes
            if isinstance(route, api_module.APIRoute)
            for method in route.methods
        } == api_module.PUBLIC_BETA_ROUTE_ALLOWLIST

        marker = {"inventory_id": "synthetic-private-marker-must-not-be-accepted"}
        for path in private_paths:
            response = client.post(path, json=marker)
            assert response.status_code == 404


def test_public_beta_returns_only_matching_warning_and_retires_warning_catalog(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    def legacy_warning(
        *,
        suffix: str,
        title: str,
        claim: str,
        source_urls: list[str],
    ) -> dict[str, Any]:
        document = _example(contract_examples, "PreliminaryWarning")
        document.update(
            {
                "id": f"gbsec:preliminary-warning:legacy-{suffix}",
                "schema_version": "1.0.0",
                "title": title,
                "claim": claim,
                "affected_artifacts": ["npm:event-stream@3.3.6"],
                "source_urls": source_urls,
                "source_origins": [url.split("/")[2] for url in source_urls],
                "created_at": timestamp(NOW),
                "updated_at": timestamp(NOW),
                "observed_at": timestamp(NOW),
                "last_checked_at": timestamp(NOW),
                "next_check_at": timestamp(NOW + timedelta(hours=1)),
                "expires_at": timestamp(NOW + timedelta(hours=12)),
            }
        )
        for field in (
            "qualification_basis",
            "qualification_actor_id",
            "qualification_reason",
            "qualification_sha256",
            "source_origins",
            "latest_recheck_reason",
            "latest_recheck_source_urls",
            "terminal_actor_id",
            "terminal_evidence_urls",
            "terminal_expected_revision",
        ):
            document.pop(field)
        return document

    with Session(database.engine) as session, session.begin():
        assert (
            session.scalar(text("SELECT version_num FROM public.alembic_version"))
            == "0036_bulletin_source_updates"
        )
        append_contract(
            session,
            "PreliminaryWarning",
            legacy_warning(
                suffix="archived",
                title="Synthetic archived warning",
                claim="Two synthetic public leads require investigation.",
                source_urls=[
                    "https://example.com/first",
                    "https://example.org/second",
                ],
            ),
        )
        expire_due_warnings(session, now=NOW + timedelta(hours=12))
        append_contract(
            session,
            "PreliminaryWarning",
            legacy_warning(
                suffix="active",
                title="Synthetic active warning",
                claim="Two newer synthetic public leads still require investigation.",
                source_urls=[
                    "https://example.com/third",
                    "https://example.org/fourth",
                ],
            ),
        )
        session.add_all(
            [_update_progress(1, segment=value) for value in ("malware", "reviewed", "unreviewed")]
        )
        session.add_all(openssf_manifest_pair(observed_at=NOW))

    with _public_client(database) as client:
        active = client.get("/v1/signals")
        assert active.status_code == 404
        expired = client.get("/v1/signals", params={"state": "expired"})
        assert expired.status_code == 404
        assert expired.json()["error"]["code"] == "not_found"
        request = _example(contract_examples, "PublicArtifactAssessmentRequest")
        assessment = client.post("/v1/artifacts/assess", json=request)
        assert assessment.status_code == 200
        result = assessment.json()
        assert result["result"] == "possibly_affected"
        assert result["preliminary_warnings_truncated"] is False
        assert {warning["state"] for warning in result["preliminary_warnings"]} == {"active"}
        assert {warning["title"] for warning in result["preliminary_warnings"]} == {
            "Synthetic active warning"
        }
        assert all(
            "affected_artifacts" not in warning for warning in result["preliminary_warnings"]
        )
        ready = client.get("/readyz")
        assert ready.status_code == 200
        wrong_host = client.get(
            "/healthz",
            headers={"Host": "untrusted.example"},
        )
        assert wrong_host.status_code == 400


def test_public_assessment_reports_invalid_proxy_identity_as_nonretryable(
    public_runtime_database,
    contract_examples: list[dict[str, Any]],
) -> None:
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    with _public_client(public_runtime_database) as client:
        response = client.post(
            "/v1/artifacts/assess",
            json=request,
            headers={"X-Forwarded-For": "127.0.0.1"},
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "proxy_network_identity_invalid"
    assert response.json()["error"]["retryable"] is False


def _append_api_match_catalog(
    session, *, name="event-stream", ecosystem="npm", version="3.3.6", source_type="reviewed"
) -> None:
    ghsa = "GHSA-mh6f-8j2x-4483"
    append_github_advisory(
        session,
        document={
            "ghsa_id": ghsa,
            "type": source_type,
            "published_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-02T00:00:00Z",
            "withdrawn_at": None,
            "html_url": f"https://github.com/advisories/{ghsa}",
            "cwes": [],
            "identifiers": [{"type": "GHSA", "value": ghsa}],
            "vulnerabilities": [
                {
                    "package": {"ecosystem": ecosystem, "name": name},
                    "vulnerable_version_range": "= " + version,
                }
            ],
        },
        evidence_id="gbsec:evidence:api-match-catalog",
        governance_decision_id="gbsec:governance:api-match-catalog",
        observed_at=NOW,
    )


def _append_api_legacy_match(
    session, contract_examples, *, ecosystem="npm", name="event-stream", status="reported"
) -> str:
    artifact = _example(contract_examples, "Artifact")
    identity = normalize_artifact_identity(
        {
            "ecosystem": ecosystem,
            "name": name,
            "version": "3.3.6",
            "digest": None,
        }
    )
    artifact.update(identity)
    artifact["id"] = stable_id("artifact", identity["coordinate"])
    claim = _example(contract_examples, "Claim")
    claim["subject_id"] = artifact["id"]
    affected_range = _example(contract_examples, "AffectedRange")
    affected_range["artifact_id"] = artifact["id"]
    for definition, value in (
        ("Artifact", artifact),
        ("Claim", claim),
        ("AffectedRange", affected_range),
    ):
        append_contract(session, definition, value)
    incident = _create_incident(
        session,
        "match-alias",
        artifact_ids=(artifact["id"],),
        range_ids=(affected_range["id"],),
        claim_ids=(claim["id"],),
        status=status,
    )
    source = _example(contract_examples, "Source")
    append_contract(session, "Source", source)
    session.add(
        SourceIncidentLinkRecord(
            link_event_id="gbsec:source-link:api-match-alias",
            source_id=source["id"],
            upstream_record_id="GHSA-mh6f-8j2x-4483",
            artifact_id=artifact["id"],
            incident_id=incident["id"],
            sequence=1,
            state="active",
            source_updated_at=NOW,
            evidence_id="gbsec:evidence:api-match-alias",
            observed_at=NOW,
            record_hash="sha256:" + "a" * 64,
        )
    )
    return incident["id"]


@pytest.mark.audit_ids("AUD-01")
@pytest.mark.parametrize(
    "conflict", ["nonmatching_confirmed", "unverified_matching", "confirmed_legacy"]
)
def test_legacy_alias_merge_never_borrows_nonmatching_catalog_authority(
    database, contract_examples, conflict
) -> None:
    with Session(database.engine) as session, session.begin():
        incident_id = _append_api_legacy_match(
            session,
            contract_examples,
            status="confirmed" if conflict == "confirmed_legacy" else "reported",
        )
        _append_api_match_catalog(
            session,
            version="9.9.9" if conflict == "nonmatching_confirmed" else "3.3.6",
            source_type="reviewed" if conflict == "nonmatching_confirmed" else "unreviewed",
        )
        if conflict == "unverified_matching":
            append_openssf_advisory(
                session,
                document={
                    "id": "MAL-2026-54321",
                    "published": "2026-08-01T00:00:00Z",
                    "modified": "2026-08-02T00:00:00Z",
                    "aliases": ["GHSA-mh6f-8j2x-4483"],
                    "affected": [
                        {
                            "package": {"ecosystem": "npm", "name": "event-stream"},
                            "versions": ["9.9.9"],
                            "ranges": [],
                        }
                    ],
                },
                canonical_url="https://github.com/ossf/malicious-packages/blob/"
                "0123456789012345678901234567890123456789/example.json",
                source_state="active",
                evidence_id="gbsec:evidence:api-match-openssf",
                governance_decision_id="gbsec:governance:api-match-openssf",
                observed_at=NOW,
            )
    with _public_client(database) as client:
        response = client.post(
            "/v1/artifacts/assess",
            json=_example(contract_examples, "PublicArtifactAssessmentRequest"),
        )
    assert response.status_code == 200
    body = response.json()
    assert body["incident_ids"] == [incident_id]
    projected = body["incidents"][0]
    if conflict == "confirmed_legacy":
        assert body["result"] == "affected"
        assert projected["confidence"] == projected["status"] == "confirmed"
        assert projected["classification"] is None
    else:
        assert body["result"] == "possibly_affected"
        assert projected["confidence"] == "unverified"
        assert projected["status"] == "reported"
        if conflict == "nonmatching_confirmed":
            assert projected["classification"] is None
        else:
            assert projected["classification"] == "vulnerable"


@pytest.mark.audit_ids("AUD-06")
@pytest.mark.parametrize("evidence", ["catalog", "legacy", "both"])
def test_http_nuget_casing_matches_retained_catalog_and_legacy_alias(
    database, contract_examples, evidence
) -> None:
    with Session(database.engine) as session, session.begin():
        if evidence in {"legacy", "both"}:
            incident_id = _append_api_legacy_match(
                session,
                contract_examples,
                ecosystem="nuget",
                name="Audit.Example",
                status="confirmed",
            )
        if evidence in {"catalog", "both"}:
            _append_api_match_catalog(session, ecosystem="nuget", name="Audit.Example")
    responses = []
    for name in ("Audit.Example", "audit.EXAMPLE"):
        request = _example(contract_examples, "PublicArtifactAssessmentRequest")
        request["artifact"].update(ecosystem="nuget", registry_host="api.nuget.org", name=name)
        with _public_client(database) as client:
            response = client.post("/v1/artifacts/assess", json=request)
        assert response.status_code == 200
        body = response.json()
        assert body["artifact"]["name"] == name
        assert body["result"] == "affected"
        assert len(body["incidents"]) == 1
        if evidence in {"legacy", "both"}:
            assert body["incident_ids"] == [incident_id]
        responses.append(body)
    assert responses[0]["feed_revision"] == responses[1]["feed_revision"]
    assert responses[0]["affected_range_ids"] == responses[1]["affected_range_ids"]


@pytest.mark.audit_ids("AUD-05")
def test_legacy_range_correction_changes_feed_without_incident_revision(
    database, contract_examples
) -> None:
    with Session(database.engine) as session, session.begin():
        _append_api_legacy_match(session, contract_examples, status="confirmed")
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    with _public_client(database) as client:
        before = client.post("/v1/artifacts/assess", json=request).json()
    with Session(database.engine) as session, session.begin():
        affected_range = _example(contract_examples, "AffectedRange")
        identity = normalize_artifact_identity(
            {"ecosystem": "npm", "name": "event-stream", "version": "3.3.6", "digest": None}
        )
        affected_range.update(
            artifact_id=stable_id("artifact", identity["coordinate"]),
            revision=2,
            expression="= 9.9.9",
            introduced="9.9.9",
            last_affected="9.9.9",
        )
        append_contract(session, "AffectedRange", affected_range)
    with _public_client(database) as client:
        after = client.post("/v1/artifacts/assess", json=request).json()
    assert before["result"] == "affected"
    assert after["result"] == "not_affected"
    # The corrected range excludes the version: the unchanged incident is now counted.
    assert before["incidents"][0]["applies_to_version"] is True
    assert after["incidents"] == []
    assert after["not_applicable_incident_count"] == 1
    assert before["feed_revision"] != after["feed_revision"]
    assert before["id"] != after["id"]


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (AssessmentCacheCapacityError("public read work is at capacity"), "read_capacity"),
        (TimeoutError("readiness deadline"), "readiness_timeout"),
        (RuntimeError("connection refused"), "database_unavailable"),
    ],
)
def test_readiness_reports_the_distinct_cause_of_a_bounded_failure(
    database, monkeypatch: pytest.MonkeyPatch, error: Exception, reason: str
) -> None:
    def failing_readiness(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(api_module, "public_readiness", failing_readiness)
    with _public_client(database) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["error"]["code"] == "service_not_ready"
    # The cause stays in the service log; the public message is fixed.
    assert body["error"]["message"] == "public data is not ready"
    assert body["error"]["retryable"] is True


def test_public_api_accepts_the_canonical_and_legacy_hosts_whatever_its_base_url(
    database,
) -> None:
    # Nginx normalizes Host to api.smithguard.io; the process must accept that and the
    # legacy production host regardless of the base URL its environment still carries.
    with _public_client(database) as client:
        for host in ("api.smithguard.io", "guard.smithlabs.ai", "security.example"):
            assert client.get("/healthz", headers={"Host": host}).status_code == 200, host
        assert client.get("/healthz", headers={"Host": "smithguard.io"}).status_code == 400
    # The live step-2 pairing and its reverse: the environment still names one host
    # while Nginx forwards the other.
    for base_url, forwarded in (
        ("https://guard.smithlabs.ai", "api.smithguard.io"),
        ("https://api.smithguard.io", "guard.smithlabs.ai"),
    ):
        app = create_public_beta_app(
            session_factory=sessionmaker(database.engine),
            signer=SnapshotSigner.ephemeral(),
            base_url=base_url,
            clock=lambda: NOW,
            snapshot_archive=None,
            revoked_public_key_ids=frozenset(),
            anonymous_quota_store=AnonymousQuotaStore(),
            anonymous_quota_secret=b"synthetic-public-quota-secret!!!",
            trusted_proxy_header=True,
        )
        with TestClient(
            app,
            base_url=base_url,
            client=("127.0.0.1", 50000),
            headers={"X-Forwarded-For": "8.8.8.8"},
        ) as client:
            assert client.get("/healthz", headers={"Host": forwarded}).status_code == 200
            assert client.get("/healthz", headers={"Host": "smithguard.io"}).status_code == 400


def test_head_answers_read_only_routes_without_a_body(database) -> None:
    with _public_client(database) as client:
        head = client.head("/healthz")
        get = client.get("/healthz")
        assert head.status_code == 200 and head.content == b""
        assert head.headers["content-length"] == get.headers["content-length"]
        assert client.head("/openapi.json").status_code == 200
        # HEAD never runs a counted assessment.
        assert client.head("/v1/artifacts/assess").status_code == 405


def test_usage_counts_hold_only_route_method_and_status(database, capsys) -> None:
    with _public_client(database) as client:
        client.get("/healthz")
        client.get("/healthz")
        client.get("/v1/public-keys/gbsec:snapshot-public-key:" + "a" * 40 + ".json")
        client.get("/no-such-route?secret=1")
    err = capsys.readouterr().err
    lines = sorted(line for line in err.splitlines() if line.startswith("api_usage "))
    assert "api_usage route=/healthz method=GET status=200 count=2" in lines
    assert any(
        "route=/v1/public-keys/{public_key_id}.json" in line and "status=404" in line
        for line in lines
    )
    assert any("route=unmatched" in line for line in lines)
    assert "secret" not in err and "8.8.8.8" not in err and "a" * 40 not in err


def test_usage_counts_name_head_routes_and_unhandled_failures(
    database, capsys, monkeypatch
) -> None:
    def broken(_self, _session):
        raise RuntimeError("synthetic coverage failure")

    monkeypatch.setattr(service_module.SmithGuardService, "get_source_coverage", broken)
    with _public_client(database, raise_server_exceptions=False) as client:
        client.head("/healthz")
        assert client.get("/v1/coverage.json").status_code == 503
    lines = [line for line in capsys.readouterr().err.splitlines() if "api_usage" in line]
    assert "api_usage route=/healthz method=HEAD status=200 count=1" in lines
    assert "api_usage route=/v1/coverage.json method=GET status=503 count=1" in lines


def test_head_error_completes_without_a_body_under_a_real_server(
    database, tmp_path, monkeypatch
) -> None:
    """An unhandled failure on a HEAD route is answered by the outer error handler;
    the server must still see HEAD, so the 503 goes out without a body. Otherwise h11
    refuses the body and the server logs a protocol error instead of the failure."""
    import http.client
    import logging
    import socket
    import threading

    import uvicorn

    def broken(_self, _session):
        raise RuntimeError("synthetic coverage failure")

    monkeypatch.setattr(service_module.SmithGuardService, "get_source_coverage", broken)
    app = create_public_beta_app(
        session_factory=sessionmaker(database.engine),
        signer=SnapshotSigner.ephemeral(),
        base_url="https://security.example",
        clock=lambda: NOW,
        anonymous_quota_store=AnonymousQuotaStore(),
        anonymous_quota_secret=b"synthetic-public-quota-secret!!!",
        trusted_proxy_header=True,
    )
    path = str(tmp_path / "api.sock")
    server = uvicorn.Server(
        uvicorn.Config(app, uds=path, log_config=None, lifespan="on", http="h11")
    )
    logged: list[type[BaseException]] = []

    class Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            if record.exc_info and record.exc_info[0] is not None:
                logged.append(record.exc_info[0])

    handler = Collect()
    server_log = logging.getLogger("uvicorn.error")
    # Another test's logging configuration (for example Alembic's) may have disabled
    # or raised this logger; this test needs its error records.
    previous = (server_log.disabled, server_log.level)
    server_log.disabled = False
    server_log.setLevel(logging.ERROR)
    server_log.addHandler(handler)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    class UnixConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(path)

    try:
        for _ in range(500):
            if server.started and coverage_runtime(app).coverage_ready.is_set():
                break
            sleep(0.01)
        assert server.started and coverage_runtime(app).coverage_ready.is_set()
        for method in ("HEAD", "GET"):
            connection = UnixConnection("security.example", timeout=5)
            connection.request(
                method,
                "/v1/coverage.json",
                headers={"Host": "security.example", "X-Forwarded-For": "8.8.8.8"},
            )
            response = connection.getresponse()
            body = response.read()
            connection.close()
            assert response.status == 503
            assert (body == b"") is (method == "HEAD")
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        server_log.removeHandler(handler)
        server_log.disabled, level = previous
        server_log.setLevel(level)
    # Each request logs only the original failure, never a transport protocol error.
    assert logged == [RuntimeError, RuntimeError]
