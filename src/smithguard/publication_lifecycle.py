"""One append-only lifecycle trail across automated, human, and rights paths."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256

from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.db.models import (
    AuthorityDecisionRecord,
    EvidenceRecord,
    IncidentRecord,
    PublicationLifecycleEventRecord,
    SourceGovernanceDecisionRecord,
)
from smithguard.identifiers import (
    ACTOR_ID,
    REASON_CODE_LONG,
    STABLE_ID,
    canonical_json_bytes,
    sha256_id,
    stable_id,
    timestamp,
)

REASON_CODE = REASON_CODE_LONG
INCIDENT_EVENTS = {"published", "corrected", "disputed", "withdrawn", "source_deleted"}
EVENT_TYPES = set(INCIDENT_EVENTS)
ACTOR_TYPES = {"system", "reviewer", "publisher", "maintenance"}
PUBLIC_STATUSES = {
    "reported",
    "corroborated",
    "confirmed",
    "contained",
    "resolved",
    "disputed",
    "withdrawn",
}


class PublicationLifecycleError(ValueError):
    """A lifecycle event is invalid, out of order, or lacks source decisions."""


class PublicationLifecycleReplayConflict(ValueError):
    """One lifecycle idempotency key was reused for different metadata."""


@dataclass(frozen=True, slots=True)
class LifecycleEvent:
    event_type: str
    actor_type: str
    actor_id: str
    source_id: str
    source_record_id: str
    evidence_id: str
    governance_decision_id: str
    reason_code: str
    occurred_at: datetime
    incident_id: str | None = None
    incident_revision: int | None = None
    authority_decision_id: str | None = None
    old_public_status: str | None = None
    new_public_status: str | None = None


@dataclass(frozen=True, slots=True)
class LifecycleWrite:
    lifecycle_event_id: str
    created: bool


def _key_hash(value: str) -> str:
    if not value or len(value) > 256:
        raise PublicationLifecycleError("lifecycle idempotency key is invalid")
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _validate(event: LifecycleEvent) -> None:
    if event.event_type not in EVENT_TYPES:
        raise PublicationLifecycleError("lifecycle event type is unsupported")
    if event.actor_type not in ACTOR_TYPES or not ACTOR_ID.fullmatch(event.actor_id):
        raise PublicationLifecycleError("lifecycle actor is invalid")
    stable_ids = (
        event.source_id,
        event.evidence_id,
        event.governance_decision_id,
    )
    if any(not STABLE_ID.fullmatch(value) for value in stable_ids):
        raise PublicationLifecycleError("lifecycle source evidence is invalid")
    if event.authority_decision_id is not None and not STABLE_ID.fullmatch(
        event.authority_decision_id
    ):
        raise PublicationLifecycleError("lifecycle authority decision is invalid")
    if (
        not event.source_record_id
        or len(event.source_record_id) > 512
        or not event.source_record_id.isascii()
    ):
        raise PublicationLifecycleError("lifecycle source record ID is invalid")
    if not REASON_CODE.fullmatch(event.reason_code):
        raise PublicationLifecycleError("lifecycle reason code is invalid")
    if event.occurred_at.tzinfo is None or event.occurred_at.utcoffset() is None:
        raise PublicationLifecycleError("lifecycle time must include a timezone")
    if event.event_type in INCIDENT_EVENTS:
        if (
            event.incident_id is None
            or not STABLE_ID.fullmatch(event.incident_id)
            or event.incident_revision is None
            or event.incident_revision < 1
            or event.new_public_status is None
        ):
            raise PublicationLifecycleError("incident lifecycle event has no revision")
    elif (
        event.incident_id is not None
        or event.incident_revision is not None
        or event.old_public_status is not None
        or event.new_public_status is not None
    ):
        raise PublicationLifecycleError(
            "evidence disposition cannot imply an incident or public status"
        )
    for status in (event.old_public_status, event.new_public_status):
        if status is not None and status not in PUBLIC_STATUSES:
            raise PublicationLifecycleError("lifecycle public status is invalid")
    if event.event_type == "published" and event.old_public_status is not None:
        raise PublicationLifecycleError("published lifecycle event cannot have an old status")
    if event.event_type == "corrected" and event.old_public_status is None:
        raise PublicationLifecycleError("corrected lifecycle event requires an old status")
    if event.event_type == "disputed" and (
        event.old_public_status is None or event.new_public_status != "disputed"
    ):
        raise PublicationLifecycleError("disputed lifecycle event has invalid statuses")
    if event.event_type == "withdrawn" and (
        event.old_public_status is None or event.new_public_status != "withdrawn"
    ):
        raise PublicationLifecycleError("withdrawn lifecycle event has invalid statuses")
    if event.event_type == "source_deleted" and (
        event.old_public_status is None
        or event.new_public_status is None
        or event.old_public_status != event.new_public_status
    ):
        raise PublicationLifecycleError(
            "source-deleted lifecycle event must preserve the public status"
        )


def _validate_references(session: Session, event: LifecycleEvent) -> None:
    governance = session.get(SourceGovernanceDecisionRecord, event.governance_decision_id)
    if governance is None:
        raise PublicationLifecycleError("source governance decision is missing")
    evidence = session.scalar(
        select(EvidenceRecord)
        .where(EvidenceRecord.id == event.evidence_id)
        .order_by(EvidenceRecord.revision.desc())
        .limit(1)
    )
    if evidence is None:
        raise PublicationLifecycleError("lifecycle evidence is missing")
    if (
        governance.source_id != event.source_id
        or governance.source_record_id != event.source_record_id
        or governance.accepted_sha256 != evidence.sha256
        or evidence.source_id != event.source_id
        or evidence.source_record_id != event.source_record_id
    ):
        raise PublicationLifecycleError("lifecycle source decisions do not match evidence")
    if event.authority_decision_id is not None:
        authority = session.scalar(
            select(AuthorityDecisionRecord)
            .where(AuthorityDecisionRecord.id == event.authority_decision_id)
            .order_by(AuthorityDecisionRecord.revision.desc())
            .limit(1)
        )
        if authority is None:
            raise PublicationLifecycleError("lifecycle authority decision is missing")
        if event.evidence_id not in authority.evidence_ids:
            raise PublicationLifecycleError("authority decision does not cite lifecycle evidence")
        if event.incident_id is not None and authority.incident_id != event.incident_id:
            raise PublicationLifecycleError("authority decision targets another incident")
    if event.incident_id is not None:
        incident = session.scalar(
            select(IncidentRecord)
            .where(
                IncidentRecord.id == event.incident_id,
                IncidentRecord.revision == event.incident_revision,
            )
            .limit(1)
        )
        if incident is None:
            raise PublicationLifecycleError("lifecycle incident revision is missing")


def _validate_order(session: Session, event: LifecycleEvent) -> None:
    if event.incident_id is not None:
        prior = session.scalar(
            select(PublicationLifecycleEventRecord)
            .where(PublicationLifecycleEventRecord.incident_id == event.incident_id)
            .order_by(
                PublicationLifecycleEventRecord.occurred_at.desc(),
                PublicationLifecycleEventRecord.lifecycle_event_id.desc(),
            )
            .limit(1)
        )
        if prior is not None and event.occurred_at < prior.occurred_at:
            raise PublicationLifecycleError("incident lifecycle time cannot move backwards")
        return
    prior_events = tuple(
        session.scalars(
            select(PublicationLifecycleEventRecord)
            .where(PublicationLifecycleEventRecord.evidence_id == event.evidence_id)
            .order_by(
                PublicationLifecycleEventRecord.occurred_at,
                PublicationLifecycleEventRecord.lifecycle_event_id,
            )
        )
    )
    if prior_events and event.occurred_at < prior_events[-1].occurred_at:
        raise PublicationLifecycleError("evidence lifecycle time cannot move backwards")


def append_lifecycle_event(
    session: Session,
    *,
    event: LifecycleEvent,
    idempotency_key: str,
) -> LifecycleWrite:
    """Append one metadata-only publication, correction or withdrawal event."""
    _validate(event)
    key_hash = _key_hash(idempotency_key)
    lifecycle_event_id = stable_id("publication-lifecycle", key_hash)
    values = {
        "incident_id": event.incident_id,
        "incident_revision": event.incident_revision,
        "event_type": event.event_type,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "source_id": event.source_id,
        "source_record_id": event.source_record_id,
        "evidence_id": event.evidence_id,
        "authority_decision_id": event.authority_decision_id,
        "governance_decision_id": event.governance_decision_id,
        "old_public_status": event.old_public_status,
        "new_public_status": event.new_public_status,
        "reason_code": event.reason_code,
        "disposition_proof_sha256": None,
        "occurred_at": timestamp(event.occurred_at),
    }
    record_hash = sha256_id(canonical_json_bytes(values))
    existing = session.scalar(
        select(PublicationLifecycleEventRecord).where(
            PublicationLifecycleEventRecord.idempotency_key_hash == key_hash
        )
    )
    if existing is not None:
        if existing.record_hash != record_hash:
            raise PublicationLifecycleReplayConflict("lifecycle idempotency key was reused")
        return LifecycleWrite(existing.lifecycle_event_id, False)
    _validate_references(session, event)
    _validate_order(session, event)
    record = PublicationLifecycleEventRecord(
        lifecycle_event_id=lifecycle_event_id,
        idempotency_key_hash=key_hash,
        incident_id=event.incident_id,
        incident_revision=event.incident_revision,
        event_type=event.event_type,
        actor_type=event.actor_type,
        actor_id=event.actor_id,
        source_id=event.source_id,
        source_record_id=event.source_record_id,
        evidence_id=event.evidence_id,
        authority_decision_id=event.authority_decision_id,
        governance_decision_id=event.governance_decision_id,
        old_public_status=event.old_public_status,
        new_public_status=event.new_public_status,
        reason_code=event.reason_code,
        disposition_proof_sha256=None,
        occurred_at=event.occurred_at,
        record_hash=record_hash,
    )
    session.add(record)
    session.flush()
    return LifecycleWrite(lifecycle_event_id, True)
