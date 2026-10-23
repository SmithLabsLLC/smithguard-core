"""Unified publication and evidence-disposition lifecycle checks."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from smithguard.acquisition import AcquisitionRequest
from smithguard.db.repository import append_contract
from smithguard.identifiers import sha256_id, stable_id, timestamp
from smithguard.incidents import IncidentSeed, apply_incident_event, create_incident
from smithguard.publication_lifecycle import (
    LifecycleEvent,
    PublicationLifecycleError,
    PublicationLifecycleReplayConflict,
    append_lifecycle_event,
)
from smithguard.source_governance import append_governance_decision

from .governance_fixtures import synthetic_authorization

NOW = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
INCIDENT_ID = "gbsec:incident:synthetic-publication-lifecycle"


def _foundation(
    session: Session,
    contract_examples: list[dict],
) -> tuple[dict, str]:
    source = deepcopy(
        next(entry["value"] for entry in contract_examples if entry["definition"] == "Source")
    )
    append_contract(session, "Source", source)
    body = b"synthetic governed publication evidence"
    evidence_sha = sha256_id(body)
    evidence = deepcopy(
        next(entry["value"] for entry in contract_examples if entry["definition"] == "RawEvidence")
    )
    evidence.update(
        {
            "id": stable_id("evidence", "synthetic-publication-lifecycle"),
            "source_id": source["id"],
            "source_record_id": "synthetic-publication-lifecycle-record",
            "canonical_url": source["canonical_url"],
            "retrieved_at": timestamp(NOW),
            "source_published_at": timestamp(NOW),
            "source_modified_at": None,
            "sha256": evidence_sha,
            "byte_count": len(body),
            "media_type": "application/json",
            "storage_state": "stored_immutable",
            "rights_decision": source["rights"]["decision"],
            "quarantine_reasons": [],
        }
    )
    append_contract(session, "RawEvidence", evidence, storage_key=evidence_sha)
    artifact = deepcopy(
        next(entry["value"] for entry in contract_examples if entry["definition"] == "Artifact")
    )
    artifact.update(
        {
            "id": "gbsec:artifact:synthetic-publication-lifecycle",
            "name": "synthetic-publication-lifecycle",
            "coordinate": "pkg:npm/synthetic-publication-lifecycle@1.0.0",
            "version": "1.0.0",
        }
    )
    append_contract(session, "Artifact", artifact)
    replacement_claim = deepcopy(
        next(entry["value"] for entry in contract_examples if entry["definition"] == "Claim")
    )
    replacement_claim.update(
        {
            "id": "gbsec:claim:synthetic-lifecycle",
            "subject_id": artifact["id"],
            "object_value": INCIDENT_ID,
        }
    )
    append_contract(session, "Claim", replacement_claim)
    request = AcquisitionRequest(
        source_record_id=evidence["source_record_id"],
        canonical_url=evidence["canonical_url"],
        retrieved_at=NOW,
        source_published_at=NOW,
        media_type="application/json",
    )
    governance, _created = append_governance_decision(
        session,
        authorization=synthetic_authorization(
            source=source,
            request=request,
            acquisition_method=source["acquisition_methods"][0],
        ),
        accepted_sha256=evidence_sha,
        decided_at=NOW,
    )
    created = create_incident(
        session,
        seed=IncidentSeed(
            incident_id=INCIDENT_ID,
            title="Synthetic lifecycle incident",
            initial_status="confirmed",
            initial_confidence="confirmed",
            claim_ids=(),
            artifact_ids=(),
            affected_range_ids=(),
            relationship_ids=(),
            coverage=(
                {
                    "ecosystem": "npm",
                    "stage": "normalized",
                    "result": "supported",
                    "as_of": timestamp(NOW),
                },
            ),
            unknowns=("Synthetic lifecycle fixture only.",),
            first_observed_at=NOW,
            created_at=NOW,
        ),
        event={
            "id": stable_id("event", INCIDENT_ID, "created"),
            "kind": "incident_event",
            "schema_version": "1.0.0",
            "revision": 1,
            "created_at": timestamp(NOW),
            "updated_at": timestamp(NOW),
            "data_classification": "public",
            "incident_id": INCIDENT_ID,
            "event_type": "created",
            "old_status": None,
            "new_status": "confirmed",
            "actor_type": "system",
            "actor_id": "system-lifecycle-test",
            "reason_code": "synthetic_created",
            "evidence_ids": [evidence["id"]],
            "occurred_at": timestamp(NOW),
            "confidence": "confirmed",
            "superseded_revision": None,
        },
    )
    return {
        "source_id": source["id"],
        "source_record_id": evidence["source_record_id"],
        "evidence_id": evidence["id"],
        "governance_decision_id": governance.decision_id,
        "incident_revision": created.document["revision"],
        "replacement_claim_id": replacement_claim["id"],
    }, evidence_sha


def _event(
    references: dict,
    *,
    event_type: str,
    occurred_at: datetime,
    revision: int | None = 1,
    old_status: str | None = None,
    new_status: str | None = None,
) -> LifecycleEvent:
    incident_event = revision is not None
    return LifecycleEvent(
        event_type=event_type,
        actor_type="system" if incident_event else "maintenance",
        actor_id="system-lifecycle-test" if incident_event else "maintenance-lifecycle-test",
        source_id=references["source_id"],
        source_record_id=references["source_record_id"],
        evidence_id=references["evidence_id"],
        governance_decision_id=references["governance_decision_id"],
        reason_code=f"synthetic_{event_type}",
        occurred_at=occurred_at,
        incident_id=INCIDENT_ID if incident_event else None,
        incident_revision=revision,
        old_public_status=(
            old_status
            if old_status is not None
            else None
            if not incident_event or event_type == "published"
            else "confirmed"
        ),
        new_public_status=(
            new_status
            if new_status is not None
            else "withdrawn"
            if event_type == "withdrawn"
            else "disputed"
            if event_type == "disputed"
            else "confirmed"
            if incident_event
            else None
        ),
    )


def test_publication_lifecycle_is_ordered_and_replay_safe(
    database,
    contract_examples: list[dict],
) -> None:
    with Session(database.engine) as session, session.begin():
        references, _evidence_sha = _foundation(session, contract_examples)
        first = append_lifecycle_event(
            session,
            event=_event(
                references,
                event_type="published",
                occurred_at=NOW,
            ),
            idempotency_key="synthetic-lifecycle-published",
        )
        assert first.created
        repeated = append_lifecycle_event(
            session,
            event=_event(
                references,
                event_type="published",
                occurred_at=NOW,
            ),
            idempotency_key="synthetic-lifecycle-published",
        )
        assert not repeated.created
        with pytest.raises(PublicationLifecycleReplayConflict, match="reused"):
            append_lifecycle_event(
                session,
                event=_event(
                    references,
                    event_type="withdrawn",
                    occurred_at=NOW + timedelta(minutes=1),
                ),
                idempotency_key="synthetic-lifecycle-published",
            )
        with pytest.raises(PublicationLifecycleError, match="backwards"):
            append_lifecycle_event(
                session,
                event=_event(
                    references,
                    event_type="source_deleted",
                    occurred_at=NOW - timedelta(seconds=1),
                ),
                idempotency_key="synthetic-lifecycle-backwards",
            )


def test_corrected_lifecycle_event_follows_a_public_correction(
    database,
    contract_examples: list[dict],
) -> None:
    with Session(database.engine) as session, session.begin():
        references, _evidence_sha = _foundation(session, contract_examples)
        append_lifecycle_event(
            session,
            event=_event(references, event_type="published", occurred_at=NOW),
            idempotency_key="synthetic-lifecycle-initial",
        )
        corrected_at = NOW + timedelta(minutes=1)
        corrected = apply_incident_event(
            session,
            event={
                "id": stable_id("event", INCIDENT_ID, "corrected"),
                "kind": "incident_event",
                "schema_version": "1.0.0",
                "revision": 1,
                "created_at": timestamp(corrected_at),
                "updated_at": timestamp(corrected_at),
                "data_classification": "public",
                "incident_id": INCIDENT_ID,
                "event_type": "corrected",
                "old_status": "confirmed",
                "new_status": "confirmed",
                "actor_type": "reviewer",
                "actor_id": "reviewer-lifecycle-test",
                "reason_code": "synthetic_corrected",
                "evidence_ids": [references["evidence_id"]],
                "occurred_at": timestamp(corrected_at),
                "confidence": "confirmed",
                "superseded_revision": 1,
            },
            details={"replacement_claim_ids": [references["replacement_claim_id"]]},
        )
        written = append_lifecycle_event(
            session,
            event=_event(
                references,
                event_type="corrected",
                occurred_at=corrected_at,
                revision=corrected.document["revision"],
            ),
            idempotency_key="synthetic-lifecycle-corrected",
        )
        assert written.created


@pytest.mark.parametrize(
    ("event_type", "old_status", "new_status", "message"),
    (
        ("published", "reported", "confirmed", "old status"),
        ("corrected", None, "confirmed", "requires an old status"),
        ("disputed", "confirmed", "reported", "invalid statuses"),
        ("withdrawn", "confirmed", "confirmed", "invalid statuses"),
        ("source_deleted", "confirmed", "withdrawn", "preserve"),
        ("rights_tombstoned", None, None, "unsupported"),
    ),
)
def test_lifecycle_rejects_impossible_event_status_combinations(
    database,
    contract_examples: list[dict],
    event_type: str,
    old_status: str | None,
    new_status: str | None,
    message: str,
) -> None:
    with Session(database.engine) as session, session.begin():
        references, _evidence_sha = _foundation(session, contract_examples)
        with pytest.raises(PublicationLifecycleError, match=message):
            event = _event(
                references,
                event_type=event_type,
                occurred_at=NOW,
                revision=None if event_type.startswith("rights_") else 1,
            )
            append_lifecycle_event(
                session,
                event=replace(
                    event,
                    old_public_status=old_status,
                    new_public_status=new_status,
                ),
                idempotency_key=f"invalid:{event_type}:{message}",
            )
