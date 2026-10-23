"""Append-only lead state, bounded public projection and non-renewing expiry."""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, tuple_
from sqlalchemy.orm import Session

from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import EmergingLeadRecord
from smithguard.discovery import citation_key
from smithguard.identifiers import canonical_json_bytes, require_aware_utc, sha256_id, timestamp
from smithguard.lead_protocol import LIFETIME, POLICY_ID, PUBLICATION_ENV, STATES

NOTICE = (
    "Emerging / Unverified. This is an attributed public allegation, not a confirmed "
    "vulnerability or an exact-artifact assessment. Use it to investigate; "
    "it does not authorize disruptive action."
)

LOGGER = logging.getLogger(__name__)


def publication_enabled() -> bool:
    value = os.environ.get(PUBLICATION_ENV, "disabled")
    if value not in {"disabled", POLICY_ID}:
        raise ValueError("emerging_lead_publication_policy_invalid")
    return value == POLICY_ID


def latest_lead(session: Session, lead_id: str) -> EmergingLeadRecord | None:
    return session.scalar(
        select(EmergingLeadRecord)
        .where(EmergingLeadRecord.lead_id == lead_id)
        .order_by(EmergingLeadRecord.revision.desc())
        .limit(1)
    )


def retained_lead_for(session: Session, candidate: dict) -> EmergingLeadRecord | None:
    """The current record of a lead first seen under another identity for the same
    source and subject (an earlier identity rule, or another link form of the same
    source). Its identity, state and expiry are kept; nothing is rewritten.

    The SQL filter is a superset: any record with the same citation key contains the
    key's post ID, or its path (and, ignoring case, its ASCII host), in its stored URL.
    Every page is read, and the exact test (citation key and Python case folding) is
    done here.
    """
    if candidate.get("provenance_kind", "social_allegation") != "social_allegation":
        return None
    key = citation_key(candidate["sources"][0]["url"])
    subject = candidate["subject"].casefold()
    stored_url = EmergingLeadRecord.document["sources"][0]["url"].as_string()
    query = _current_query().where(_social_provenance())
    if key.startswith("x-status:"):
        query = query.where(stored_url.contains(key.removeprefix("x-status:"), autoescape=True))
    else:
        host, _, rest = key.partition("/")
        path = "/" + rest.split("?", 1)[0].rstrip("/")
        query = query.where(stored_url.contains(path, autoescape=True))
        if host.isascii():
            # The key's host is lowercased; the stored URL may not be.
            query = query.where(stored_url.icontains(host, autoescape=True))
    position: tuple[datetime, str] | None = None
    while True:
        page_query = query.order_by(EmergingLeadRecord.first_seen_at, EmergingLeadRecord.lead_id)
        if position is not None:
            page_query = page_query.where(
                tuple_(EmergingLeadRecord.first_seen_at, EmergingLeadRecord.lead_id) > position
            )
        rows = list(session.scalars(page_query.limit(500)))
        for row in rows:
            sources = row.document.get("sources") or []
            if (
                sources
                and str(row.document.get("subject", "")).casefold() == subject
                and citation_key(sources[0]["url"]) == key
            ):
                return row
        if len(rows) < 500:
            return None
        position = (rows[-1].first_seen_at, rows[-1].lead_id)


def _heads():
    return (
        select(EmergingLeadRecord.lead_id, func.max(EmergingLeadRecord.revision).label("revision"))
        .group_by(EmergingLeadRecord.lead_id)
        .subquery()
    )


def _social_provenance():
    # Legacy social records predate explicit provenance. Unknown kinds fail closed.
    return (
        func.coalesce(
            EmergingLeadRecord.document["provenance_kind"].as_string(), "social_allegation"
        )
        == "social_allegation"
    )


def _current_query():
    heads = _heads()
    return select(EmergingLeadRecord).join(
        heads,
        (EmergingLeadRecord.lead_id == heads.c.lead_id)
        & (EmergingLeadRecord.revision == heads.c.revision),
    )


def enrichment_targets(session: Session, *, now: datetime) -> list[dict]:
    """Rotate a bounded pool within existing search calls; no additional dispatch."""
    now = require_aware_utc(now)
    rows = list(
        session.scalars(
            _current_query()
            .where(
                _social_provenance(),
                EmergingLeadRecord.state.in_(("needs_enrichment", "unverified")),
                EmergingLeadRecord.expires_at > now,
            )
            .order_by(EmergingLeadRecord.first_seen_at, EmergingLeadRecord.lead_id)
            .limit(100)
        )
    )
    if not rows:
        return []
    start = (int(now.timestamp()) // 1800 * 2) % len(rows)
    selected = (rows[start:] + rows[:start])[:2]
    return [
        {
            "subject": row.document["subject"],
            "source_url": row.document["sources"][0]["url"],
            "missing": "check_for_correction_or_withdrawal"
            if row.state == "unverified"
            else row.reason,
        }
        for row in selected
    ]


def overdue_lead_count(session: Session, *, now: datetime) -> int:
    """Count overdue current active revisions in SQL, without loading documents."""
    return int(
        session.scalar(
            _current_query()
            .with_only_columns(func.count(), maintain_column_froms=True)
            .where(
                EmergingLeadRecord.state.in_(("unverified", "needs_enrichment")),
                EmergingLeadRecord.expires_at <= require_aware_utc(now),
            )
        )
        or 0
    )


def _try_expiry_lock(session: Session, name: str) -> bool:
    # Use the same keys as record_lead; an always-on cleanup never waits for a
    # discovery/qualification transaction to release a lead.
    return bool(
        session.scalar(select(func.pg_try_advisory_xact_lock(func.hashtextextended(name, 0))))
    )


def expire_leads(
    session: Session, *, now: datetime, limit: int = 100, deadline: float | None = None
) -> int:
    """Append one bounded expiry batch; changed or busy leads remain for a later batch."""
    now = require_aware_utc(now)
    if isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError("lead_expiry_limit_invalid")
    rows = list(
        session.scalars(
            _current_query()
            .where(
                EmergingLeadRecord.state.in_(("unverified", "needs_enrichment")),
                EmergingLeadRecord.expires_at <= now,
            )
            .order_by(EmergingLeadRecord.expires_at, EmergingLeadRecord.lead_id)
            .limit(limit)
        )
    )
    count = 0
    for row in rows:
        if deadline is not None and time.monotonic() >= deadline:
            break
        if not _try_expiry_lock(session, "emerging-lead-fingerprint:" + row.fingerprint):
            continue
        if not _try_expiry_lock(session, "emerging-lead:" + row.lead_id):
            continue
        current = latest_lead(session, row.lead_id)
        if (
            current is None
            or current.revision != row.revision
            or current.state not in {"unverified", "needs_enrichment"}
            or current.expires_at > now
        ):
            continue
        _, created = record_lead(
            session, current.document, state="expired", reason="lead_expired", now=now
        )
        count += int(created)
    return count


def record_lead(
    session: Session,
    candidate: dict,
    *,
    state: str,
    reason: str,
    now: datetime,
    publish: bool = False,
    publication_run_id: str | None = None,
) -> tuple[EmergingLeadRecord, bool]:
    """Caller transaction owns the job and revision; unchanged repeats never renew."""
    now = require_aware_utc(now)
    if state not in STATES or not re.fullmatch(r"[a-z][a-z0-9_]{1,79}", reason):
        raise ValueError("lead_state_invalid")
    lead_id = candidate["lead_id"]
    if not isinstance(lead_id, str) or not re.fullmatch(r"[a-f0-9]{64}", lead_id):
        raise ValueError("lead_identity_invalid")
    kind = candidate.get("provenance_kind", "social_allegation")
    if kind not in {"social_allegation", "official_announcement"}:
        raise ValueError("lead_provenance_invalid")
    fingerprint_input = [candidate["subject"].casefold(), candidate["allegation"].casefold()]
    if kind == "official_announcement":
        fingerprint_input = [kind, "v1", candidate["sources"][0]["url"]]
    fingerprint = sha256_id(canonical_json_bytes(fingerprint_input))
    advisory_xact_lock(session, "emerging-lead-fingerprint:" + fingerprint)
    advisory_xact_lock(session, "emerging-lead:" + lead_id)
    previous = latest_lead(session, lead_id)
    if previous and previous.document.get("provenance_kind", "social_allegation") != kind:
        raise ValueError("lead_provenance_change_refused")
    if previous is None:
        duplicate = session.scalar(
            select(EmergingLeadRecord)
            .where(
                EmergingLeadRecord.fingerprint == fingerprint, EmergingLeadRecord.expires_at > now
            )
            .order_by(EmergingLeadRecord.first_seen_at, EmergingLeadRecord.lead_id)
            .limit(1)
        )
        if duplicate is not None:
            current = latest_lead(session, duplicate.lead_id)
            if current is None:
                raise RuntimeError("lead_duplicate_disappeared")
            return current, False
    first_seen = previous.first_seen_at if previous else now
    expires = previous.expires_at if previous else now + LIFETIME
    if previous and previous.state in {"withdrawn", "rejected", "expired"}:
        return previous, False
    if now >= expires and state not in {"withdrawn", "rejected"}:
        state, reason = "expired", "lead_expired"
    # Publication requires an explicitly selected policy AND the bounded qualification.
    primary = candidate["sources"][0]
    eligible = bool(
        kind == "social_allegation"
        and (publish or (previous and previous.public_eligible))
        and state == "unverified"
        and primary["citation_bound"]
        and primary["context"]
    )
    if (
        previous is not None
        and previous.state == state
        and previous.reason == reason
        and previous.public_eligible == eligible
        and all(
            previous.document.get(k) == candidate[k] for k in ("subject", "allegation", "sources")
        )
    ):
        return previous, False
    doc = {
        **candidate,
        "policy_id": POLICY_ID,
        "first_seen_at": timestamp(first_seen),
        "expires_at": timestamp(expires),
        "state": state,
        "reason": reason,
        "public_eligible": eligible,
        "publication_run_id": publication_run_id if eligible else None,
        "revision": previous.revision + 1 if previous else 1,
    }
    row = EmergingLeadRecord(
        lead_id=lead_id,
        revision=doc["revision"],
        state=state,
        reason=reason,
        first_seen_at=first_seen,
        observed_at=now,
        expires_at=expires,
        fingerprint=fingerprint,
        public_eligible=eligible,
        document=doc,
        record_hash=sha256_id(canonical_json_bytes(doc)),
    )
    session.add(row)
    session.flush()
    return row, True


def public_page(
    session: Session, *, now: datetime, limit: int = 25, after: str | None = None
) -> dict[str, Any]:
    now = require_aware_utc(now)
    if (
        isinstance(limit, bool)
        or not 1 <= limit <= 100
        or (after is not None and not re.fullmatch(r"[a-f0-9]{64}", after))
    ):
        raise ValueError("lead_page_invalid")
    enabled = publication_enabled()
    output: dict[str, Any] = {
        "status": "active" if enabled else "publication_disabled",
        "as_of": timestamp(now),
        "notice": NOTICE,
        "leads": [],
        "next_cursor": None,
    }
    if not enabled:
        return output
    query = _current_query().where(
        _social_provenance(),
        EmergingLeadRecord.public_eligible.is_(True),
        EmergingLeadRecord.state == "unverified",
        EmergingLeadRecord.expires_at > now,
    )
    # Newest first. The cursor stays a lead ID: the page continues after that lead's
    # (first_seen_at, lead_id) position; an unknown cursor ends the feed.
    if after:
        # The cursor's position comes from its retained history, so a lead withdrawn or
        # expired between two pages still marks where the next page starts.
        cursor = session.scalar(
            select(EmergingLeadRecord)
            .where(EmergingLeadRecord.lead_id == after)
            .order_by(EmergingLeadRecord.revision.desc())
            .limit(1)
        )
        if cursor is None:
            return output
        query = query.where(
            tuple_(EmergingLeadRecord.first_seen_at, EmergingLeadRecord.lead_id)
            < tuple_(cursor.first_seen_at, cursor.lead_id)
        )
    rows = list(
        session.scalars(
            query.order_by(
                EmergingLeadRecord.first_seen_at.desc(), EmergingLeadRecord.lead_id.desc()
            ).limit(limit + 1)
        )
    )
    for row in rows[:limit]:
        doc = row.document
        if sha256_id(canonical_json_bytes(doc)) != row.record_hash:
            # One damaged row is skipped (and logged), not the whole page.
            LOGGER.warning("Emerging lead skipped: integrity check failed")
            continue
        primary = doc["sources"][0]
        # No source context, model explanation or inferred artifact match in public output.
        output["leads"].append(
            {
                "id": row.lead_id,
                "status": "Emerging / Unverified",
                "subject": doc["subject"],
                "reported_allegation": doc["allegation"],
                "source_url": primary["url"],
                "published_at": primary["published_at"],
                "time_precision": primary["time_precision"],
                "first_seen_at": timestamp(row.first_seen_at),
                "expires_at": timestamp(row.expires_at),
                "unknowns": ["independently_unconfirmed", "affected_versions_unverified"]
                + (["publication_date_unknown"] if primary["published_at"] is None else []),
            }
        )
    if len(rows) > limit:
        output["next_cursor"] = rows[limit - 1].lead_id
    return output


def yield_summary(session: Session, *, since: datetime) -> dict[str, int]:
    """Internal counts of lead decisions; provider health remains a separate measure."""
    rows = session.execute(
        select(EmergingLeadRecord.state, func.count())
        .where(_social_provenance(), EmergingLeadRecord.observed_at >= require_aware_utc(since))
        .group_by(EmergingLeadRecord.state)
    )
    return {state: count for state, count in rows}
