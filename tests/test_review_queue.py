"""Append-only review transitions and independent appeals."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from smithguard.review_queue import (
    ReviewEvent,
    ReviewQueueError,
    append_review_event,
    rebuild_review_state,
)

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
ITEM = "gbsec:review-item:synthetic"
CLUSTER = "gbsec:source-cluster:synthetic"


def _event(
    suffix: str,
    event_type: str,
    *,
    minute: int,
    actor_type: str,
    actor_id: str,
    decision: str | None = None,
) -> ReviewEvent:
    return ReviewEvent(
        event_id=f"gbsec:review-event:{suffix}",
        queue_item_id=ITEM,
        cluster_id=CLUSTER,
        incident_id=None,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        reason_code=f"synthetic_{event_type}",
        evidence_ids=(),
        occurred_at=NOW + timedelta(minutes=minute),
        decision=decision,
    )


def test_full_review_dispute_appeal_and_close_history(database) -> None:
    events = (
        _event("open", "opened", minute=0, actor_type="system", actor_id="system-local"),
        _event(
            "assign",
            "assigned",
            minute=1,
            actor_type="reviewer",
            actor_id="reviewer-alpha",
        ),
        _event(
            "approve",
            "decided",
            minute=2,
            actor_type="reviewer",
            actor_id="reviewer-alpha",
            decision="approved",
        ),
        _event(
            "dispute",
            "disputed",
            minute=3,
            actor_type="maintainer",
            actor_id="maintainer-opaque",
        ),
        _event(
            "appeal",
            "appealed",
            minute=4,
            actor_type="reviewer",
            actor_id="reviewer-beta",
        ),
        _event(
            "reject",
            "decided",
            minute=5,
            actor_type="reviewer",
            actor_id="reviewer-beta",
            decision="rejected",
        ),
        _event(
            "close",
            "closed",
            minute=6,
            actor_type="reviewer",
            actor_id="reviewer-beta",
        ),
    )
    with Session(database.engine) as session, session.begin():
        for event in events:
            _record, created = append_review_event(session, event=event)
            assert created
        replay, created = append_review_event(session, event=events[0])
        assert not created and replay.sequence == 1
        state = rebuild_review_state(session, ITEM)
        assert state.sequence == 7
        assert state.state == "closed"
        assert state.decision == "rejected"


def test_review_rejects_nonindependent_or_out_of_order_appeals(database) -> None:
    with Session(database.engine) as session, session.begin():
        append_review_event(
            session,
            event=_event(
                "open",
                "opened",
                minute=0,
                actor_type="system",
                actor_id="system-local",
            ),
        )
        with pytest.raises(ReviewQueueError, match="current state"):
            append_review_event(
                session,
                event=_event(
                    "appeal-early",
                    "appealed",
                    minute=1,
                    actor_type="reviewer",
                    actor_id="reviewer-alpha",
                ),
            )
        append_review_event(
            session,
            event=_event(
                "assign",
                "assigned",
                minute=2,
                actor_type="reviewer",
                actor_id="reviewer-alpha",
            ),
        )
        append_review_event(
            session,
            event=_event(
                "decide",
                "decided",
                minute=3,
                actor_type="reviewer",
                actor_id="reviewer-alpha",
                decision="approved",
            ),
        )
        append_review_event(
            session,
            event=_event(
                "dispute",
                "disputed",
                minute=4,
                actor_type="reviewer",
                actor_id="reviewer-alpha",
            ),
        )
        with pytest.raises(ReviewQueueError, match="independent reviewer"):
            append_review_event(
                session,
                event=_event(
                    "appeal-same",
                    "appealed",
                    minute=5,
                    actor_type="reviewer",
                    actor_id="reviewer-alpha",
                ),
            )


def test_correction_withdrawal_and_expiry_paths_are_bounded(database) -> None:
    with Session(database.engine) as session, session.begin():
        append_review_event(
            session,
            event=_event(
                "open",
                "opened",
                minute=0,
                actor_type="system",
                actor_id="system-local",
            ),
        )
        append_review_event(
            session,
            event=_event(
                "expire",
                "expired",
                minute=1,
                actor_type="system",
                actor_id="system-local",
            ),
        )
        append_review_event(
            session,
            event=_event(
                "close",
                "closed",
                minute=2,
                actor_type="reviewer",
                actor_id="reviewer-alpha",
            ),
        )
        append_review_event(
            session,
            event=_event(
                "withdraw-after-close",
                "withdrawal_requested",
                minute=3,
                actor_type="maintainer",
                actor_id="maintainer-opaque",
            ),
        )
        assert rebuild_review_state(session, ITEM).state == "withdrawal_pending"
