"""One hundred synthetic records rebuild with exact traceability."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.collectors import (
    GITHUB_ADVISORY,
    CollectorRunner,
    TransportResponse,
)
from smithguard.db.models import AffectedRangeRecord, ArtifactRecord, ClaimRecord
from smithguard.db.repository import latest_contract
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.identifiers import stable_id, timestamp
from smithguard.incidents import (
    IncidentSeed,
    create_incident,
    rebuild_incident,
)
from smithguard.reconciliation import SourceMember, append_source_member
from smithguard.review_queue import ReviewEvent, append_review_event
from smithguard.source_rights import RightsRegistry

REPO_ROOT = Path(__file__).resolve().parents[1]
RIGHTS_REGISTER = REPO_ROOT / "contracts/v1/source-rights-register.json"
NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
REPLAY_COUNT = 100


def verify_latest_incident_rebuild(session: Session, incident_id: str) -> dict:
    """Rebuild the incident and require it to equal the latest stored revision."""
    rebuilt = rebuild_incident(session, incident_id)
    latest = latest_contract(session, "Incident", incident_id)
    assert latest is not None and latest.document == rebuilt
    return rebuilt


def _body() -> bytes:
    return json.dumps(
        {
            "records": [
                {
                    "ghsa_id": "GHSA-replay-batch",
                    "type": "malware",
                    "published_at": "2026-08-05T10:00:00Z",
                    "updated_at": "2026-08-05T11:00:00Z",
                    "withdrawn_at": None,
                    "html_url": "https://github.com/advisories/GHSA-replay-batch",
                    "identifiers": [
                        {
                            "type": "GHSA",
                            "value": "GHSA-replay-batch",
                        }
                    ],
                    "references": [],
                    "vulnerabilities": [
                        {
                            "package": {
                                "ecosystem": "npm",
                                "name": f"synthetic-package-{index:04d}",
                            },
                            "vulnerable_version_range": f"= 1.0.{index}",
                            "first_patched_version": None,
                        }
                        for index in range(REPLAY_COUNT)
                    ],
                }
            ]
        },
        sort_keys=True,
    ).encode("ascii")


def test_one_hundred_synthetic_records_rebuild_deterministically(
    database,
    tmp_path: Path,
) -> None:
    body = _body()

    def transport(_spec, _checkpoint):
        return TransportResponse(
            body=body,
            canonical_url="https://api.github.com/advisories/GHSA-replay-batch",
            media_type="application/json",
            retrieved_at=NOW,
            source_record_id="synthetic-cp1-replay-batch",
            source_published_at=NOW,
            checkpoint_token="synthetic-cp1-replay-cursor",
        )

    runner = CollectorRunner(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        transport=transport,
    )
    with Session(database.engine) as session, session.begin():
        collected = runner.run_public(session, source_id=GITHUB_ADVISORY)
        assert collected.outcome is not None
        assert collected.outcome.record_count == REPLAY_COUNT
        artifacts = tuple(session.scalars(select(ArtifactRecord).order_by(ArtifactRecord.id)))
        claims = tuple(session.scalars(select(ClaimRecord).order_by(ClaimRecord.id)))
        ranges = tuple(
            session.scalars(select(AffectedRangeRecord).order_by(AffectedRangeRecord.id))
        )
        assert len(artifacts) == len(claims) == len(ranges) == REPLAY_COUNT
        claim_by_artifact = {record.subject_id: record for record in claims}
        range_by_artifact = {record.artifact_id: record for record in ranges}
        incident_ids: list[str] = []
        queue_item_ids: list[str] = []
        for artifact in artifacts:
            claim = claim_by_artifact[artifact.id]
            affected_range = range_by_artifact[artifact.id]
            assert claim.provenance["source_id"] == GITHUB_ADVISORY
            assert claim.provenance["source_record_id"] == "synthetic-cp1-replay-batch"
            assert claim.provenance["evidence_id"] == collected.outcome.raw_evidence_id
            incident_id = stable_id("incident", artifact.id)
            incident_ids.append(incident_id)
            cluster_member, _created = append_source_member(
                session,
                member=SourceMember(
                    source_id=GITHUB_ADVISORY,
                    source_record_id=claim.provenance["source_record_id"] + ":" + artifact.name,
                    evidence_id=collected.outcome.raw_evidence_id,
                    artifact_id=artifact.id,
                    independent_origin_id="gbsec:origin:github-advisory-database",
                    claim_fingerprint=claim.record_hash,
                    observed_at=NOW,
                ),
            )
            queue_item_id = stable_id("review-item", artifact.id)
            queue_item_ids.append(queue_item_id)
            append_review_event(
                session,
                event=ReviewEvent(
                    event_id=stable_id("review-event", queue_item_id, "opened"),
                    queue_item_id=queue_item_id,
                    cluster_id=cluster_member.cluster_id,
                    incident_id=incident_id,
                    event_type="opened",
                    actor_type="system",
                    actor_id="system-synthetic-replay",
                    reason_code="synthetic_review_opened",
                    evidence_ids=(collected.outcome.raw_evidence_id,),
                    occurred_at=NOW,
                ),
            )
            append_review_event(
                session,
                event=ReviewEvent(
                    event_id=stable_id("review-event", queue_item_id, "assigned"),
                    queue_item_id=queue_item_id,
                    cluster_id=cluster_member.cluster_id,
                    incident_id=incident_id,
                    event_type="assigned",
                    actor_type="reviewer",
                    actor_id="reviewer-synthetic-replay",
                    reason_code="synthetic_review_assigned",
                    evidence_ids=(collected.outcome.raw_evidence_id,),
                    occurred_at=NOW + timedelta(minutes=1),
                ),
            )
            append_review_event(
                session,
                event=ReviewEvent(
                    event_id=stable_id("review-event", queue_item_id, "decided"),
                    queue_item_id=queue_item_id,
                    cluster_id=cluster_member.cluster_id,
                    incident_id=incident_id,
                    event_type="decided",
                    actor_type="reviewer",
                    actor_id="reviewer-synthetic-replay",
                    reason_code="synthetic_review_approved",
                    evidence_ids=(collected.outcome.raw_evidence_id,),
                    occurred_at=NOW + timedelta(minutes=2),
                    decision="approved",
                ),
            )
            created_at = NOW + timedelta(minutes=3)
            seed = IncidentSeed(
                incident_id=incident_id,
                title=f"Synthetic replay incident {artifact.name}",
                initial_status="confirmed",
                initial_confidence="probable",
                claim_ids=(claim.id,),
                artifact_ids=(artifact.id,),
                affected_range_ids=(affected_range.id,),
                relationship_ids=(),
                coverage=(
                    {
                        "ecosystem": "npm",
                        "stage": "matched",
                        "result": "supported",
                        "as_of": timestamp(created_at),
                    },
                ),
                unknowns=("Synthetic replay only.",),
                first_observed_at=NOW,
                created_at=created_at,
            )
            event_id = stable_id("event", incident_id, "created")
            create_incident(
                session,
                seed=seed,
                event={
                    "id": event_id,
                    "kind": "incident_event",
                    "schema_version": "1.0.0",
                    "revision": 1,
                    "created_at": timestamp(created_at),
                    "updated_at": timestamp(created_at),
                    "data_classification": "public",
                    "incident_id": incident_id,
                    "event_type": "created",
                    "old_status": None,
                    "new_status": "confirmed",
                    "actor_type": "reviewer",
                    "actor_id": "reviewer-synthetic-replay",
                    "reason_code": "synthetic_replay_confirmed",
                    "evidence_ids": [collected.outcome.raw_evidence_id],
                    "occurred_at": timestamp(created_at),
                    "confidence": "probable",
                    "superseded_revision": None,
                },
            )
        rebuilt = [verify_latest_incident_rebuild(session, value) for value in incident_ids]
        assert len(rebuilt) == REPLAY_COUNT
        retry = runner.run_public(session, source_id=GITHUB_ADVISORY)
        assert retry.outcome is not None and not retry.outcome.created
        assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == REPLAY_COUNT
        assert [verify_latest_incident_rebuild(session, value) for value in incident_ids] == rebuilt
