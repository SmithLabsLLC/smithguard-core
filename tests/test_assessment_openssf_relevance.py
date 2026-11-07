"""Signed assessment barriers apply only to sources covering the ecosystem.

Real retained ranges, PostgreSQL queries and the HTTP/signature path are exercised.
Only the independently tested live/cached gap observations are injected here.
"""

from __future__ import annotations

import base64
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session

from smithguard import service
from smithguard.advisory_catalog import OPENSSF_SOURCE_ID
from smithguard.db.repository import append_contract
from smithguard.feeds import SnapshotSigner
from smithguard.identifiers import canonical_json_bytes, stable_id
from smithguard.normalization import normalize_artifact_identity
from tests.test_service_api import _create_incident, _example, _public_client


def seed_excluded_version(session, examples, *, ecosystem, name):
    identity = normalize_artifact_identity(
        {
            "ecosystem": ecosystem,
            "name": name,
            "version": None if ecosystem == "docker" else "3.3.6",
            "digest": "sha256:" + "a" * 64 if ecosystem == "docker" else None,
        }
    )
    artifact = _example(examples, "Artifact")
    artifact.update(identity)
    artifact["id"] = stable_id("artifact", identity["coordinate"])
    affected = _example(examples, "AffectedRange")
    affected.update(
        artifact_id=artifact["id"],
        range_type="DIGEST" if ecosystem == "docker" else "EXACT",
        expression="sha256:" + "b" * 64 if ecosystem == "docker" else "= 2.0.0",
        introduced="2.0.0",
        last_affected="2.0.0",
        evaluation_state="supported",
    )
    claim = _example(examples, "Claim")
    claim["subject_id"] = artifact["id"]
    append_contract(session, "Artifact", artifact)
    append_contract(session, "Claim", claim)
    append_contract(session, "AffectedRange", affected)
    _create_incident(
        session,
        "openssf-relevance",
        artifact_ids=(artifact["id"],),
        range_ids=(affected["id"],),
        claim_ids=(claim["id"],),
        status="confirmed",
    )


def signed_answer(database, signer, request):
    # A new application/cache prevents a prior response from hiding the injected gap.
    with _public_client(database, signer=signer) as client:
        response = client.post("/v1/artifacts/assess", json=request)
    assert response.status_code == 200, response.text
    answer = response.json()
    unsigned = {key: value for key, value in answer.items() if key != "signature"}
    Ed25519PublicKey.from_public_bytes(signer.public_key_bytes).verify(
        base64.b64decode(answer["signature"]["value"], validate=True),
        canonical_json_bytes(unsigned),
    )
    assert answer["schema_version"] == "2.5.0"
    return answer


@pytest.mark.parametrize("gap", ["live", "cached", "both"])
@pytest.mark.parametrize(
    "ecosystem,name,openssf_relevant",
    [
        ("github-actions", "example/action", False),
        ("docker", "example/image", False),
        ("npm", "example", True),
        ("pypi", "example", True),
    ],
)
def test_global_openssf_gap_respects_signed_assessment_source_relevance(
    database, contract_examples, monkeypatch, gap, ecosystem, name, openssf_relevant
):
    with Session(database.engine) as session, session.begin():
        seed_excluded_version(session, contract_examples, ecosystem=ecosystem, name=name)
    request = {"ecosystem": ecosystem, "name": name, "version": "3.3.6"}
    if ecosystem == "docker":
        request.pop("version")
        request.update(registry_host="docker.io", digest="sha256:" + "a" * 64)
    signer = SnapshotSigner.ephemeral()
    before = signed_answer(database, signer, request)
    assert before["result"] == "not_affected"
    assert before["not_applicable_incident_count"] == 1
    assert (
        any(row["source_id"] == OPENSSF_SOURCE_ID for row in before["source_freshness"])
        is openssf_relevant
    )

    catalog = service.catalog_evidence_for_package
    coverage = service.build_coverage_report

    def live_gap(*args, **kwargs):
        return replace(
            catalog(*args, **kwargs), openssf_unresolved_count=1 if gap in {"live", "both"} else 0
        )

    def cached_gap(*args, **kwargs):
        report = coverage(*args, **kwargs)
        return replace(
            report,
            source_lanes=tuple(
                replace(lane, freshness_state="unresolved", unresolved_record_count=2)
                if lane.source_id == OPENSSF_SOURCE_ID and gap in {"cached", "both"}
                else lane
                for lane in report.source_lanes
            ),
        )

    monkeypatch.setattr(service, "catalog_evidence_for_package", live_gap)
    monkeypatch.setattr(service, "build_coverage_report", cached_gap)
    after = signed_answer(database, signer, request)
    assert after["not_applicable_incident_count"] == 1
    if openssf_relevant:
        assert after["result"] == "unknown"
        assert "source_unavailable" in after["reason_codes"]
        lane = next(
            row for row in after["source_freshness"] if row["source_id"] == OPENSSF_SOURCE_ID
        )
        assert lane["freshness_state"] == "unresolved"
        assert lane["unresolved_record_count"] == (2 if gap in {"cached", "both"} else 1)
    else:
        assert after["result"] == "not_affected"
        assert all(row["source_id"] != OPENSSF_SOURCE_ID for row in after["source_freshness"])
        assert after["source_freshness"] == before["source_freshness"]
        assert after["reason_codes"] == before["reason_codes"]
        assert after["unknowns"] == before["unknowns"]
