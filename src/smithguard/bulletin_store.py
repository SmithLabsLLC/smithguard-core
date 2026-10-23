"""Transactional bulletin ledger and revocable public projection.

Callers own the transaction. A locked singleton allocates event numbers, so a
consumer can never skip a lower-numbered transaction that commits later.
"""

from __future__ import annotations

import base64
import binascii
from copy import deepcopy
from datetime import datetime, timedelta

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert

from smithguard.bulletin_contract import BulletinError, content_id, require_id, validate_content
from smithguard.bulletin_policy import (
    CORRECTION_RESERVE,
    FEED_SOURCES,
    MAX_ADDITIONAL_BYTES,
    MAX_KEV_IDENTITIES,
    MAX_PREVIEW,
    MAX_PUBLIC_IDENTITIES,
    authorize,
)
from smithguard.db.bulletin_models import (
    BulletinCurrent,
    BulletinDecision,
    BulletinEvent,
    BulletinPublicVersion,
    BulletinRevision,
    BulletinSourceStatus,
    BulletinStream,
    OfficialNoticeCurrent,
    OfficialNoticeEvidence,
)
from smithguard.identifiers import (
    canonical_json_bytes,
    require_aware_utc,
    sha256_id,
    strict_json_loads,
)

RETENTION = timedelta(days=90)
STATUS_DEADLINE = timedelta(minutes=5)
TABLE_NAMES = (
    "bulletin_identity_aliases",
    "bulletin_review_queue",
    "bulletin_maintenance_receipts",
    "bulletin_source_status",
    "bulletin_stream",
    "bulletin_current",
    "bulletin_revisions",
    "bulletin_public_versions",
    "bulletin_events",
    "bulletin_decisions",
    "official_source_checkpoints",
    "official_notice_current",
    "official_notice_evidence",
    "official_notice_pending",
    "official_intake_runs",
)
NEUTRAL_REASONS = {
    "verification_pending",
    "verification_overdue",
    "source_unavailable",
    "catalog_entry_absent",
    "rights_review_due",
    "policy_paused",
    "public_content_revoked",
    "retention_expired",
    "verified_unchanged",
}


def timestamp(value):
    return value.isoformat().replace("+00:00", "Z") if value is not None else None


def lock_stream(session, *, now):
    require_aware_utc(now)
    session.execute(
        insert(BulletinStream)
        .values(
            stream_id="v1",
            sequence=0,
            mode="paused",
            created_at=now,
        )
        .on_conflict_do_nothing(index_elements=["stream_id"])
    )
    return session.scalar(
        select(BulletinStream)
        .where(
            BulletinStream.stream_id == "v1",
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def allocated_bytes(session):
    return session.scalar(
        text(
            "SELECT coalesce(sum(pg_total_relation_size(('smithguard.' || name)::regclass)), 0) "
            "FROM unnest(CAST(:names AS text[])) AS name"
        ),
        {"names": list(TABLE_NAMES)},
    )


def capacity(session, *, new_identity):
    # Leave room for the maximum transaction and keep corrections ahead of new
    # admissions. Relation size includes indexes and TOAST, not just JSON bytes.
    ceiling = MAX_ADDITIONAL_BYTES - (CORRECTION_RESERVE if new_identity else 0)
    if allocated_bytes(session) + 256 * 1024 > ceiling:
        raise BulletinError("bulletin_storage_capacity")


def _decision(session, stream, row, *, kind, reason, now, document):
    stream.sequence += 1
    row.sequence = stream.sequence
    row.updated_at = now
    payload = {
        "bulletin_id": row.bulletin_id,
        "revision": row.revision,
        "sequence": stream.sequence,
        "kind": kind,
        "reason": reason,
        "decided_at": timestamp(now),
        **document,
    }
    decision_id = sha256_id(canonical_json_bytes(payload))
    session.add(
        BulletinDecision(
            decision_id=decision_id,
            bulletin_id=row.bulletin_id,
            sequence=stream.sequence,
            manual_approval_id=document.get("manual_approval_id"),
            document=payload,
            created_at=now,
        )
    )
    session.add(
        BulletinEvent(
            sequence=stream.sequence,
            bulletin_id=row.bulletin_id,
            revision=row.revision,
            kind=kind,
            reason=reason,
            occurred_at=now,
        )
    )
    return stream.sequence, decision_id


def accepted_input(session, document, *, now):
    """Resolve private accepted evidence; a caller cannot supply invented input."""
    if document["source_key"] == "kev":
        from smithguard.bulletin_kev import accepted_input as kev_input

        return kev_input(session, document, now=now)
    references = document.get("sources", [])
    from smithguard.bulletin_sources import SOURCE_IDS

    if not references or document["source_key"] not in SOURCE_IDS and len(references) != 1:
        raise BulletinError("bulletin_accepted_input_required")
    identity = references[0]["source_evidence_hash"]
    evidence = session.get(OfficialNoticeEvidence, identity)
    if evidence is None or sha256_id(canonical_json_bytes(evidence.document)) != identity:
        raise BulletinError("bulletin_accepted_input_required")
    current = session.get(OfficialNoticeCurrent, (evidence.source_key, evidence.record_key))
    if (
        current is None
        or current.semantic_hash != evidence.document.get("semantic_hash")
        or not now - STATUS_DEADLINE <= current.updated_at <= now
        or evidence.source_key != document["source_key"]
    ):
        raise BulletinError("bulletin_accepted_input_not_current")
    from smithguard.bulletin_sources import CATALOG_SOURCES

    if evidence.source_key in CATALOG_SOURCES:
        from smithguard.bulletin_catalog import validate_observation

        validate_observation(session, evidence.document, now=now)
    return evidence.document


def publish(session, document, *, grant, registry, now, manual_approval=None):
    validate_content(document, now=now)
    observation = accepted_input(session, document, now=now) if manual_approval is None else None
    mode = authorize(
        document,
        grant,
        registry,
        now=now,
        manual_approval=manual_approval,
        accepted_input=observation,
    )
    stream = lock_stream(session, now=now)
    identity = content_id(document)
    row = session.get(BulletinCurrent, identity)
    if row is not None and row.tombstoned:
        raise BulletinError("bulletin_tombstone_permanent")
    if (
        manual_approval is not None
        and session.scalar(
            select(BulletinDecision.decision_id).where(
                BulletinDecision.manual_approval_id == manual_approval,
            )
        )
        is not None
    ):
        raise BulletinError("bulletin_approval_consumed")
    content_hash = sha256_id(canonical_json_bytes(document))
    previous = None if row is None else session.get(BulletinRevision, (identity, row.revision))
    if previous is not None and previous.content_hash == content_hash:
        raise BulletinError("bulletin_unchanged_use_verification")
    capacity(session, new_identity=row is None)
    if row is None:
        total = session.scalar(
            select(func.count())
            .select_from(BulletinCurrent)
            .where(
                (BulletinCurrent.expires_at.is_(None)) | (BulletinCurrent.expires_at > now),
            )
        )
        if total >= MAX_PUBLIC_IDENTITIES:
            raise BulletinError("bulletin_admission_capacity")
        if (
            document["source_key"] == "kev"
            and session.scalar(
                select(func.count())
                .select_from(BulletinCurrent)
                .where(BulletinCurrent.source_key == "kev")
            )
            >= MAX_KEV_IDENTITIES
        ):
            raise BulletinError("bulletin_source_identity_capacity")
        if mode == "manual_preview" and total >= MAX_PREVIEW:
            raise BulletinError("bulletin_preview_capacity")
        row = BulletinCurrent(
            bulletin_id=identity,
            revision=1,
            sequence=1,
            source_key=document["source_key"],
            evidence_class=document["evidence_class"],
            mode=mode,
            tombstoned=False,
            first_seen_at=now,
            updated_at=now,
            verified_at=now,
            verification_due_at=now + timedelta(hours=24),
        )
        session.add(row)
    else:
        if row.evidence_class != document["evidence_class"]:
            raise BulletinError("bulletin_class_change_requires_separate_identity")
        row.revision += 1
        row.mode = mode
        row.verified_at = now
        row.verification_due_at = now + timedelta(hours=24)
    if document["source_key"] == "kev" and observation is not None:
        from smithguard.bulletin_kev import verification_due

        row.verification_due_at = verification_due(observation, now=now)
    from smithguard.bulletin_freshness import due as detail_due
    from smithguard.bulletin_sources import NETWORK_SOURCES

    if document["source_key"] in NETWORK_SOURCES:
        row.verification_due_at = detail_due(
            document["source_key"], document["source_published_at"], now
        )
    row.freshness_reason = None
    row.expires_at = (
        row.first_seen_at + timedelta(hours=24)
        if document["evidence_class"] == "emerging_report"
        else None
    )
    stream.mode = grant["mode"]
    stream.grant_hash = sha256_id(canonical_json_bytes(grant))
    kind = "published" if previous is None else document["lifecycle"]
    if kind not in {"published", "disputed", "withdrawn", "expired"}:
        kind = "corrected"
    sequence, decision_id = _decision(
        session,
        stream,
        row,
        kind=kind,
        reason="qualified_publication",
        now=now,
        document={
            "grant_hash": stream.grant_hash,
            "policy_id": grant["policy_id"],
            "content_hash": content_hash,
            "manual_approval_id": manual_approval,
            "source_evidence": document["sources"],
            "accepted_observation": observation if document["source_key"] == "kev" else None,
        },
    )
    predecessor = previous.content_hash if previous is not None else None
    session.add(
        BulletinRevision(
            bulletin_id=identity,
            revision=row.revision,
            document=deepcopy(document),
            content_hash=content_hash,
            predecessor_hash=predecessor,
            created_at=now,
        )
    )
    session.add(
        BulletinPublicVersion(
            bulletin_id=identity,
            revision=row.revision,
            sequence=sequence,
            document=deepcopy(document),
            content_hash=content_hash,
            predecessor_hash=predecessor,
            publication_decision_id=decision_id,
            policy_id=grant["policy_id"],
            grant_hash=stream.grant_hash,
            created_at=now,
            tombstoned=False,
        )
    )
    session.flush()
    from smithguard.bulletin_identity import register
    from smithguard.bulletin_sources import SOURCE_IDS

    register(session, identity, document, now=now)
    if document["source_key"] in SOURCE_IDS:
        row.expires_at = row.first_seen_at + timedelta(days=90)
    session.flush()
    return {"bulletin_id": identity, "revision": row.revision, "sequence": sequence}


def mark_stale(session, identity, *, reason, now):
    if reason not in NEUTRAL_REASONS - {"verified_unchanged", "public_content_revoked"}:
        raise BulletinError("bulletin_status_reason")
    stream = lock_stream(session, now=now)
    row = session.get(BulletinCurrent, require_id(identity))
    if row is None or row.tombstoned or row.freshness_reason == reason:
        return False
    row.freshness_reason = reason
    _decision(
        session,
        stream,
        row,
        kind="freshness_stale",
        reason=reason,
        now=now,
        document={"authority": "neutral_status_v1"},
    )
    session.flush()
    return True


def verify_unchanged(
    session, identity, *, content_hash, grant, registry, now, manual_approval=None
):
    stream = lock_stream(session, now=now)
    row = session.get(BulletinCurrent, require_id(identity))
    if row is None or row.tombstoned:
        raise BulletinError("bulletin_not_found")
    revision = session.get(BulletinRevision, (identity, row.revision))
    if content_hash != revision.content_hash:
        raise BulletinError("bulletin_verification_changed")
    observation = (
        accepted_input(session, revision.document, now=now) if manual_approval is None else None
    )
    authorize(
        revision.document,
        grant,
        registry,
        now=now,
        manual_approval=manual_approval,
        accepted_input=observation,
    )
    if manual_approval is not None and session.scalar(
        select(BulletinDecision.decision_id).where(
            BulletinDecision.manual_approval_id == manual_approval,
        )
    ):
        raise BulletinError("bulletin_approval_consumed")
    row.verified_at = now
    row.verification_due_at = now + timedelta(hours=24)
    if revision.document["source_key"] == "kev" and observation is not None:
        from smithguard.bulletin_kev import verification_due

        row.verification_due_at = verification_due(observation, now=now)
    from smithguard.bulletin_freshness import due as detail_due
    from smithguard.bulletin_sources import NETWORK_SOURCES

    if revision.document["source_key"] in NETWORK_SOURCES:
        row.verification_due_at = detail_due(
            revision.document["source_key"], revision.document["source_published_at"], now
        )
    row.freshness_reason = None
    _decision(
        session,
        stream,
        row,
        kind="freshness_verified",
        reason="verified_unchanged",
        now=now,
        document={
            "content_hash": content_hash,
            "accepted_observation": observation
            if revision.document["source_key"] == "kev"
            else None,
            "grant_hash": sha256_id(canonical_json_bytes(grant)),
            "manual_approval_id": manual_approval,
        },
    )
    session.flush()


def tombstone(session, identity, *, now):
    """One atomic gate and purge; public readers never consult private originals."""
    stream = lock_stream(session, now=now)
    row = session.get(BulletinCurrent, require_id(identity))
    if row is None:
        raise BulletinError("bulletin_not_found")
    if row.tombstoned:
        return False
    row.tombstoned = True
    row.freshness_reason = "public_content_revoked"
    for kind in ("public_tombstoned", "public_purge_requested"):
        _decision(
            session,
            stream,
            row,
            kind=kind,
            reason="public_content_revoked",
            now=now,
            document={"authority": "public_takedown_v1"},
        )
    session.execute(
        update(BulletinPublicVersion)
        .where(
            BulletinPublicVersion.bulletin_id == identity,
        )
        .values(document={}, tombstoned=True)
    )
    _decision(
        session,
        stream,
        row,
        kind="public_purged",
        reason="public_content_revoked",
        now=now,
        document={"authority": "public_takedown_v1", "controlled_cache": "no_store"},
    )
    session.flush()
    return True


def status_tick(session, *, now):
    stream = lock_stream(session, now=now)
    expiring = session.scalars(
        select(BulletinCurrent)
        .where(
            BulletinCurrent.tombstoned.is_(False),
            BulletinCurrent.expires_at <= now,
            (BulletinCurrent.freshness_reason.is_(None))
            | (BulletinCurrent.freshness_reason != "retention_expired"),
        )
        .order_by(BulletinCurrent.expires_at, BulletinCurrent.bulletin_id)
        .limit(500)
    ).all()
    for row in expiring:
        row.freshness_reason = "retention_expired"
        _decision(
            session,
            stream,
            row,
            kind="expired",
            reason="retention_expired",
            now=now,
            document={"authority": "neutral_status_v1"},
        )
    session.flush()
    # The public population is capped at 10,000. Each tick processes a bounded
    # indexed page; an unfinished overdue tail makes the stream unavailable.
    overdue = session.scalars(
        select(BulletinCurrent)
        .where(
            BulletinCurrent.tombstoned.is_(False),
            BulletinCurrent.verification_due_at <= now,
            BulletinCurrent.freshness_reason.is_(None),
        )
        .order_by(BulletinCurrent.verification_due_at, BulletinCurrent.bulletin_id)
        .limit(500)
    ).all()
    for row in overdue:
        row.freshness_reason = "verification_overdue"
        _decision(
            session,
            stream,
            row,
            kind="freshness_stale",
            reason="verification_overdue",
            now=now,
            document={"authority": "neutral_status_v1"},
        )
    stream.status_checked_at = now
    session.flush()
    return len(overdue) + len(expiring)


def stream_status(session, *, now):
    require_aware_utc(now)
    stream = session.get(BulletinStream, "v1")
    if stream is None:
        return {
            "mode": "paused",
            "available": False,
            "watermark": 0,
            "checked_at": None,
            "reason": "not_activated",
        }
    unchecked = session.scalar(
        select(BulletinCurrent.bulletin_id)
        .where(
            BulletinCurrent.tombstoned.is_(False),
            BulletinCurrent.verification_due_at <= now - STATUS_DEADLINE,
            BulletinCurrent.freshness_reason.is_(None),
        )
        .limit(1)
    )
    alive = (
        stream.status_checked_at is not None and now - stream.status_checked_at <= STATUS_DEADLINE
    )
    available = alive and unchecked is None
    return {
        "mode": stream.mode,
        "available": available,
        "watermark": stream.sequence,
        "checked_at": timestamp(stream.status_checked_at),
        "reason": None if available else "status_worker_unavailable",
    }


def source_status(session, *, now):
    from smithguard.bulletin_sources import coverage

    status = stream_status(session, now=now)
    sources = []
    rows = session.scalars(
        select(BulletinSourceStatus).order_by(BulletinSourceStatus.source_key).limit(65)
    ).all()
    if len(rows) > 64:
        raise BulletinError("bulletin_source_status_capacity")
    for row in rows:
        state, reason = row.state, row.reason
        if state == "fresh" and (
            row.last_success_at is None or now - row.last_success_at > timedelta(minutes=75)
        ):
            state, reason = "stale", "source_check_overdue"
        if state == "fresh" and row.upstream_due_at is not None and row.upstream_due_at <= now:
            state, reason = "stale", "upstream_check_overdue"
        if status["mode"] == "paused" and reason != "source_not_selected":
            state, reason = "paused", "policy_paused"
        sources.append(
            {
                "source_key": row.source_key,
                **coverage(row.source_key),
                "state": state,
                "reason": reason,
                "last_attempt_at": timestamp(row.last_attempt_at),
                "last_success_at": timestamp(row.last_success_at),
                "complete_through_at": timestamp(row.complete_through_at),
                "coverage_start_at": timestamp(row.coverage_start_at),
                "upstream_due_at": timestamp(row.upstream_due_at),
                "initial_history_complete": row.initial_history_complete,
                "coverage_gaps": row.coverage_gaps,
                "oldest_pending_at": timestamp(row.oldest_pending_at),
                "pending_count": row.pending_count,
                "updated_at": timestamp(row.updated_at),
            }
        )
    return {
        "stream": status,
        "sources": sources,
        "scope": "qualified_sources_only",
        "applicability": "not_evaluated",
        "signed": False,
    }


def _source_observation(session, row, *, now):
    from smithguard.bulletin_sources import CATALOG_SOURCES, NETWORK_SOURCES

    if row.source_key in NETWORK_SOURCES:
        return None, None  # Detail evidence has its own deadline; coverage is separate.
    if row.source_key not in FEED_SOURCES:
        return None, None
    source = session.get(BulletinSourceStatus, row.source_key)
    if source is None:
        return ("unavailable", "source_not_observed"), None
    deadline = source.last_success_at + timedelta(minutes=75) if source.last_success_at else None
    if source.upstream_due_at is not None:
        deadline = min(deadline, source.upstream_due_at) if deadline else source.upstream_due_at
    publication_debt = source.state == "incomplete" and source.reason in {
        "catching_up",
        "publication_pending",
        "catalog_record_omitted",
    }
    if source.state != "fresh" and not publication_debt:
        state = source.state if source.state in {"unavailable", "paused"} else "stale"
        return (state, source.reason or "source_unavailable"), deadline
    if row.source_key in CATALOG_SOURCES and source.upstream_due_at is None:
        return ("unavailable", "upstream_not_observed"), deadline
    if deadline is None or deadline <= now:
        return ("stale", "source_check_overdue"), deadline
    return None, deadline


def render(row, version, *, now, mode, source_observation=None):
    source_freshness, source_due = source_observation or (None, None)
    due = min(row.verification_due_at, source_due) if source_due else row.verification_due_at
    revoked = row.tombstoned or version.tombstoned
    freshness = "fresh"
    reason = row.freshness_reason
    if revoked:
        freshness, reason = "unavailable", "public_content_revoked"
    elif mode == "paused":
        freshness, reason = "paused", "policy_paused"
    elif source_freshness is not None:
        freshness, reason = source_freshness
    elif due <= now:
        freshness, reason = "stale", reason or "verification_overdue"
    elif reason:
        freshness = "stale"
    expired = row.expires_at is not None and row.expires_at <= now
    return {
        "bulletin_id": row.bulletin_id,
        "revision": version.revision,
        "current_revision": row.revision,
        "historical": version.revision != row.revision,
        "sequence": version.sequence,
        "content_hash": version.content_hash,
        "predecessor_hash": version.predecessor_hash,
        "publication_decision_id": version.publication_decision_id,
        "policy_id": version.policy_id,
        "grant_hash": version.grant_hash,
        "hash_basis": "canonical_content_v1",
        "signed": False,
        "tombstoned": revoked,
        "content": None if revoked else version.document,
        "mode": row.mode,
        "freshness": freshness,
        "freshness_reason": reason,
        "effective_lifecycle": "expired"
        if expired
        else (None if revoked else version.document["lifecycle"]),
        "first_seen_at": timestamp(row.first_seen_at),
        "published_at": timestamp(version.created_at),
        "updated_at": timestamp(row.updated_at),
        "verified_at": timestamp(row.verified_at),
        "verification_due_at": timestamp(due),
        "expires_at": timestamp(row.expires_at),
    }


def detail(session, identity, *, now, revision=None):
    row = session.get(BulletinCurrent, require_id(identity))
    if row is None:
        raise BulletinError("bulletin_not_found")
    if revision is not None and (type(revision) is not int or not 1 <= revision <= row.revision):
        raise BulletinError("bulletin_revision_not_found")
    version = session.get(BulletinPublicVersion, (identity, revision or row.revision))
    if version is None:
        raise BulletinError("bulletin_revision_not_found")
    stream = session.get(BulletinStream, "v1")
    return render(
        row,
        version,
        now=now,
        mode=stream.mode if stream else "paused",
        source_observation=_source_observation(session, row, now=now),
    )


def encode_cursor(payload):
    return base64.urlsafe_b64encode(canonical_json_bytes(payload)).decode("ascii").rstrip("=")


def decode_cursor(value, *, kind, filters, now, maximum):
    if not isinstance(value, str) or len(value) > 2048:
        raise BulletinError("bulletin_cursor_invalid")
    try:
        payload = strict_json_loads(
            base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        )
        if (
            not isinstance(payload, dict)
            or set(payload) != {"v", "kind", "filters", "after", "upper", "issued"}
            or payload["v"] != 1
            or payload["kind"] != kind
            or payload["filters"] != filters
            or type(payload["upper"]) is not int
            or not 0 <= payload["upper"] <= maximum
            or not isinstance(payload["issued"], str)
        ):
            raise ValueError
        issued = datetime.fromisoformat(payload["issued"].replace("Z", "+00:00"))
        require_aware_utc(issued)
        if issued > now:
            raise ValueError
        if now - issued > RETENTION:
            raise BulletinError("bulletin_cursor_expired")
        if kind == "snapshot":
            if payload["after"] != "":
                require_id(payload["after"])
        elif type(payload["after"]) is not int or not 0 <= payload["after"] <= payload["upper"]:
            raise ValueError
        return payload
    except (ValueError, TypeError, binascii.Error, UnicodeError) as error:
        if isinstance(error, BulletinError) and str(error) == "bulletin_cursor_expired":
            raise
        raise BulletinError("bulletin_cursor_invalid") from error


def _filters(source, evidence_class, subject):
    if source is not None and (not isinstance(source, str) or not 1 <= len(source) <= 40):
        raise BulletinError("bulletin_filter_invalid")
    if evidence_class not in {None, "official_notice", "official_advisory", "emerging_report"}:
        raise BulletinError("bulletin_filter_invalid")
    if subject is not None and (not isinstance(subject, str) or not 1 <= len(subject) <= 120):
        raise BulletinError("bulletin_filter_invalid")
    return {"source": source, "evidence_class": evidence_class, "subject": subject}


def snapshot(
    session, *, now, cursor=None, limit=50, source=None, evidence_class=None, subject=None
):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise BulletinError("bulletin_limit_invalid")
    status = stream_status(session, now=now)
    filters = _filters(source, evidence_class, subject)
    payload = (
        {
            "v": 1,
            "kind": "snapshot",
            "filters": filters,
            "after": "",
            "upper": status["watermark"],
            "issued": timestamp(now),
        }
        if cursor is None
        else decode_cursor(
            cursor, kind="snapshot", filters=filters, now=now, maximum=status["watermark"]
        )
    )
    latest = (
        select(BulletinPublicVersion.bulletin_id, BulletinPublicVersion.revision)
        .where(
            BulletinPublicVersion.sequence <= payload["upper"],
            BulletinPublicVersion.bulletin_id > payload["after"],
        )
        .distinct(BulletinPublicVersion.bulletin_id)
        .order_by(
            BulletinPublicVersion.bulletin_id,
            BulletinPublicVersion.sequence.desc(),
        )
        .subquery()
    )
    query = (
        select(BulletinCurrent, BulletinPublicVersion)
        .join(latest, BulletinCurrent.bulletin_id == latest.c.bulletin_id)
        .join(
            BulletinPublicVersion,
            (BulletinPublicVersion.bulletin_id == latest.c.bulletin_id)
            & (BulletinPublicVersion.revision == latest.c.revision),
        )
    )
    if source is not None:
        query = query.where(BulletinCurrent.source_key == source)
    if evidence_class is not None:
        query = query.where(BulletinCurrent.evidence_class == evidence_class)
    if subject is not None:
        query = query.where(BulletinPublicVersion.document["subjects"].contains([subject]))
    rows = session.execute(query.order_by(BulletinCurrent.bulletin_id).limit(limit + 1)).all()
    items = [
        render(
            row,
            version,
            now=now,
            mode=status["mode"],
            source_observation=_source_observation(session, row, now=now),
        )
        for row, version in rows[:limit]
    ]
    size = 0
    count = 0
    for item in items:
        size += len(canonical_json_bytes(item))
        if size > 768 * 1024:
            break
        count += 1
    items = items[:count]
    more = len(rows) > count
    next_cursor = encode_cursor({**payload, "after": items[-1]["bulletin_id"]}) if more else None
    # Changes are deliberately unfiltered. A client must apply its filter after
    # resolving current content, including removing records that leave a filter.
    changes = encode_cursor(
        {
            "v": 1,
            "kind": "events",
            "filters": {},
            "after": payload["upper"],
            "upper": payload["upper"],
            "issued": payload["issued"],
        }
    )
    return {
        "items": items,
        "next_cursor": next_cursor,
        "watermark": payload["upper"],
        "changes_cursor": changes if not more and status["available"] else None,
        "status": status,
    }


def events(session, *, now, cursor=None, limit=100, identity=None):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise BulletinError("bulletin_limit_invalid")
    status = stream_status(session, now=now)
    if not status["available"]:
        raise BulletinError("bulletin_stream_unavailable")
    filters = {} if identity is None else {"bulletin_id": require_id(identity)}
    payload = (
        {
            "v": 1,
            "kind": "events",
            "filters": filters,
            "after": 0,
            "upper": status["watermark"],
            "issued": timestamp(now),
        }
        if cursor is None
        else decode_cursor(
            cursor, kind="events", filters=filters, now=now, maximum=status["watermark"]
        )
    )
    if payload["after"] == payload["upper"]:
        payload = {**payload, "upper": status["watermark"], "issued": timestamp(now)}
    query = select(BulletinEvent).where(
        BulletinEvent.sequence > payload["after"], BulletinEvent.sequence <= payload["upper"]
    )
    if identity is None:
        query = query.where(BulletinEvent.occurred_at >= now - RETENTION)
    if identity is not None:
        query = query.where(BulletinEvent.bulletin_id == identity)
    rows = session.scalars(query.order_by(BulletinEvent.sequence).limit(limit + 1)).all()
    items = [
        {
            "sequence": row.sequence,
            "bulletin_id": row.bulletin_id,
            "revision": row.revision,
            "kind": row.kind,
            "reason": row.reason,
            "occurred_at": timestamp(row.occurred_at),
        }
        for row in rows[:limit]
    ]
    more = len(rows) > limit
    after = items[-1]["sequence"] if more else payload["upper"]
    return {
        "items": items,
        "next_cursor": encode_cursor({**payload, "after": after}),
        "has_more": more,
        "watermark": payload["upper"],
        "retention_days": 90,
        "status": status,
    }
