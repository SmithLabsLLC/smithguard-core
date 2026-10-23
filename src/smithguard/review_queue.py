"""Append-only human review queue and independent appeal rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import ReviewQueueEventRecord
from smithguard.identifiers import (
    ACTOR_ID,
    REASON_CODE_LONG,
    STABLE_ID,
    canonical_json_bytes,
    require_aware_utc,
    sha256_id,
    timestamp,
)

REASON_CODE = REASON_CODE_LONG
ACTOR_TYPES = {"system", "reviewer", "maintainer", "affected_party"}


class ReviewQueueError(ValueError):
    """A review event violates the bounded state machine."""


@dataclass(frozen=True, slots=True)
class ReviewEvent:
    event_id: str
    queue_item_id: str
    cluster_id: str
    incident_id: str | None
    event_type: str
    actor_type: str
    actor_id: str
    reason_code: str
    evidence_ids: tuple[str, ...]
    occurred_at: datetime
    decision: str | None = None


@dataclass(frozen=True, slots=True)
class ReviewState:
    queue_item_id: str
    cluster_id: str
    incident_id: str | None
    sequence: int
    state: str
    decision: str | None
    last_actor_id: str
    last_occurred_at: datetime


def _history(session: Session, queue_item_id: str) -> tuple[ReviewQueueEventRecord, ...]:
    return tuple(
        session.scalars(
            select(ReviewQueueEventRecord)
            .where(ReviewQueueEventRecord.queue_item_id == queue_item_id)
            .order_by(ReviewQueueEventRecord.sequence)
        )
    )


def rebuild_review_state(session: Session, queue_item_id: str) -> ReviewState:
    history = _history(session, queue_item_id)
    if not history:
        raise ReviewQueueError("review item does not exist")
    latest = history[-1]
    if tuple(item.sequence for item in history) != tuple(range(1, len(history) + 1)):
        raise ReviewQueueError("review history is incomplete")
    return ReviewState(
        queue_item_id=latest.queue_item_id,
        cluster_id=latest.cluster_id,
        incident_id=latest.incident_id,
        sequence=latest.sequence,
        state=latest.state,
        decision=next(
            (item.decision for item in reversed(history) if item.decision is not None),
            None,
        ),
        last_actor_id=latest.actor_id,
        last_occurred_at=latest.occurred_at,
    )


def _next_state(
    event: ReviewEvent,
    history: tuple[ReviewQueueEventRecord, ...],
) -> tuple[str, str | None]:
    current = history[-1].state if history else None
    if not history:
        if event.event_type != "opened" or event.actor_type != "system":
            raise ReviewQueueError("review history must start with a system open event")
        return "pending", None
    transitions: dict[str, tuple[set[str], str]] = {
        "assigned": ({"pending", "in_review"}, "in_review"),
        "disputed": ({"approved", "rejected"}, "disputed"),
        "appealed": ({"disputed"}, "in_review"),
        "correction_requested": ({"approved", "closed"}, "correction_pending"),
        "withdrawal_requested": ({"approved", "closed"}, "withdrawal_pending"),
        "expired": ({"pending", "in_review", "disputed"}, "expired"),
        "closed": (
            {
                "approved",
                "rejected",
                "correction_pending",
                "withdrawal_pending",
                "expired",
            },
            "closed",
        ),
    }
    if event.event_type == "opened":
        raise ReviewQueueError("review item can be opened only once")
    if event.event_type == "decided":
        if current != "in_review" or event.actor_type != "reviewer":
            raise ReviewQueueError("only a reviewer can decide an in-review item")
        if event.decision not in {"approved", "rejected"}:
            raise ReviewQueueError("decision event requires approved or rejected")
        return event.decision, event.decision
    if event.event_type not in transitions:
        raise ReviewQueueError("review event type is unsupported")
    allowed, target = transitions[event.event_type]
    if current not in allowed:
        raise ReviewQueueError("review event is invalid for the current state")
    if event.decision is not None:
        raise ReviewQueueError("only a decision event may carry a decision")
    if event.event_type in {"assigned", "appealed"} and event.actor_type != "reviewer":
        raise ReviewQueueError("review assignment and appeal require a reviewer")
    if event.event_type == "appealed":
        dispute = next(
            (item for item in reversed(history) if item.event_type == "disputed"),
            None,
        )
        if dispute is None or dispute.actor_id == event.actor_id:
            raise ReviewQueueError("appeal requires an independent reviewer")
    return target, None


def append_review_event(
    session: Session,
    *,
    event: ReviewEvent,
) -> tuple[ReviewQueueEventRecord, bool]:
    """Append one validated review transition under a per-item transaction lock."""
    if (
        not STABLE_ID.fullmatch(event.event_id)
        or not STABLE_ID.fullmatch(event.queue_item_id)
        or not STABLE_ID.fullmatch(event.cluster_id)
        or (event.incident_id is not None and not STABLE_ID.fullmatch(event.incident_id))
    ):
        raise ReviewQueueError("review event contains an invalid stable ID")
    if event.actor_type not in ACTOR_TYPES or not ACTOR_ID.fullmatch(event.actor_id):
        raise ReviewQueueError("review event contains an invalid actor")
    if not REASON_CODE.fullmatch(event.reason_code):
        raise ReviewQueueError("review event contains an invalid reason code")
    try:
        # Validation only: the event is stored with the caller's own offset, unchanged,
        # so the normalized value is deliberately not bound.
        require_aware_utc(event.occurred_at)
    except ValueError as error:
        raise ReviewQueueError("review event time must be timezone-aware") from error
    if len(event.evidence_ids) > 100 or any(
        not STABLE_ID.fullmatch(value) for value in event.evidence_ids
    ):
        raise ReviewQueueError("review evidence IDs are invalid")
    lock_name = f"review-queue:{event.queue_item_id}"
    advisory_xact_lock(session, lock_name)
    existing = session.get(ReviewQueueEventRecord, event.event_id)
    if existing is not None:
        comparable = {
            "queue_item_id": event.queue_item_id,
            "cluster_id": event.cluster_id,
            "incident_id": event.incident_id,
            "event_type": event.event_type,
            "actor_type": event.actor_type,
            "actor_id": event.actor_id,
            "reason_code": event.reason_code,
            "decision": event.decision,
            "evidence_ids": list(dict.fromkeys(event.evidence_ids)),
            "occurred_at": event.occurred_at,
        }
        if any(getattr(existing, key) != value for key, value in comparable.items()):
            raise ReviewQueueError("review event ID conflicts with history")
        return existing, False
    history = _history(session, event.queue_item_id)
    sequence = len(history) + 1
    if history:
        latest = history[-1]
        if event.cluster_id != latest.cluster_id or event.incident_id != latest.incident_id:
            raise ReviewQueueError("review item identity cannot change")
        if event.occurred_at < latest.occurred_at:
            raise ReviewQueueError("review event time cannot move backwards")
    state, decision = _next_state(event, history)
    values = {
        "event_id": event.event_id,
        "queue_item_id": event.queue_item_id,
        "cluster_id": event.cluster_id,
        "incident_id": event.incident_id,
        "sequence": sequence,
        "event_type": event.event_type,
        "state": state,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "reason_code": event.reason_code,
        "decision": decision,
        "evidence_ids": list(dict.fromkeys(event.evidence_ids)),
        "occurred_at": event.occurred_at,
    }
    record_hash = sha256_id(
        canonical_json_bytes({**values, "occurred_at": timestamp(event.occurred_at)})
    )
    record = ReviewQueueEventRecord(**values, record_hash=record_hash)
    session.add(record)
    session.flush()
    return record, True
