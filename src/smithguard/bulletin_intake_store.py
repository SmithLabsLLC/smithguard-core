"""Durable official intake checkpoints, work pointers and immutable source evidence."""

from copy import deepcopy
from datetime import datetime, timedelta

from sqlalchemy import func, select

from smithguard.bulletin_contract import BulletinError, bulletin_id
from smithguard.bulletin_policy import (
    MAX_CHANGES_PER_SOURCE,
    MAX_SOURCE_IDENTITIES,
)
from smithguard.bulletin_store import capacity, lock_stream, mark_stale
from smithguard.db.bulletin_models import (
    BulletinSourceStatus,
    OfficialIntakeRun,
    OfficialNoticeCurrent,
    OfficialNoticeEvidence,
    OfficialNoticePending,
    OfficialSourceCheckpoint,
)
from smithguard.db.models import JobRecord
from smithguard.identifiers import canonical_json_bytes, sha256_id, timestamp
from smithguard.official_notice_fetch import ENDPOINTS
from smithguard.official_notice_store import MAX_RECORDS, QUEUE, notice_document, semantic_hash

CUTOVER = "official-intake-v2-cutover"
MAX_PENDING = 2000
OVERLAP = timedelta(hours=24)


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def checkpoint(session, source, *, now):
    row = session.get(OfficialSourceCheckpoint, source)
    if row is None:
        row = OfficialSourceCheckpoint(
            source_key=source,
            updated_at=now,
            document={
                "schema_version": 1,
                "baseline_at": timestamp(now),
                "complete_through": None,
                "last_attempt": None,
                "last_success": None,
                "etag": None,
                "modified": None,
                "consumed_epoch": None,
                "pending_count": 0,
                "gap_since": None,
                "failures": 0,
                "next_attempt_at": None,
                "daily_date": now.date().isoformat(),
                "daily_new": 0,
            },
        )
        session.add(row)
        session.flush()
    return row


def record_run(session, epoch, kind, document, *, now):
    if len(canonical_json_bytes(document)) > 24 * 1024:
        raise BulletinError("official_run_bytes")
    previous = session.get(OfficialIntakeRun, (epoch, kind))
    if previous is not None:
        raise BulletinError("official_epoch_consumed")
    session.add(OfficialIntakeRun(epoch=epoch, kind=kind, document=document, created_at=now))
    session.flush()


def envelope(doc, *, now, retrospective):
    return {
        "schema_version": 1,
        "source": doc["source"],
        "record_key": sha256_id(doc["url"].encode())[7:],
        "document": doc,
        "semantic_hash": semantic_hash(doc),
        "fetch_url": ENDPOINTS[doc["source"]][0],
        "transport": "publisher_endpoint_tls",
        "accepted_at": timestamp(now),
        "retrospective": retrospective,
    }


def retain(session, value, *, now):
    identity = sha256_id(canonical_json_bytes(value))
    if session.get(OfficialNoticeEvidence, identity) is None:
        session.add(
            OfficialNoticeEvidence(
                evidence_id=identity,
                source_key=value["source"],
                record_key=value["record_key"],
                document=value,
                created_at=now,
            )
        )
        session.flush()
    return identity


def cutover(session, *, now):
    """Caller holds the shared intake lock. No fetch, old-row edit, or public replay."""
    if session.get(OfficialIntakeRun, (CUTOVER, "cutover")) is not None:
        return False
    lock_stream(session, now=now)
    count = session.scalar(
        select(func.count()).select_from(JobRecord).where(JobRecord.queue == QUEUE)
    )
    if count > MAX_RECORDS:
        raise BulletinError("official_legacy_budget")
    key = JobRecord.payload["url"].as_string()
    rows = list(
        session.scalars(
            select(JobRecord)
            .where(
                JobRecord.queue == QUEUE,
                JobRecord.payload["kind"].as_string() == "notice",
            )
            .distinct(key)
            .order_by(key, JobRecord.created_at.desc(), JobRecord.job_id)
            .limit(MAX_SOURCE_IDENTITIES + 1)
        )
    )
    if len(rows) > MAX_SOURCE_IDENTITIES:
        raise BulletinError("official_identity_capacity")
    imported = []
    for row in rows:
        payload = row.payload
        if payload.get("source") not in ENDPOINTS:
            raise BulletinError("official_legacy_source")
        doc = {
            k: payload[k]
            for k in (
                "source",
                "url",
                "title",
                "context",
                "published_at",
                "modified_at",
                "withdrawn",
                "entry_sha256",
                "content_sha256",
            )
        }
        if semantic_hash(doc) != payload["semantic_sha256"]:
            raise BulletinError("official_legacy_hash")
        value = envelope(doc, now=row.created_at, retrospective=True)
        capacity(session, new_identity=True)
        retain(session, value, now=now)
        session.add(
            OfficialNoticeCurrent(
                source_key=doc["source"],
                record_key=value["record_key"],
                document=value,
                semantic_hash=value["semantic_hash"],
                first_seen_at=row.created_at,
                updated_at=row.created_at,
            )
        )
        imported.append([str(row.job_id), value["semantic_hash"]])
    for source in ENDPOINTS:
        checkpoint(session, source, now=now)
    record_run(
        session,
        CUTOVER,
        "cutover",
        {
            "schema_version": 1,
            "legacy_receipt_count": count,
            "imported_identities": len(rows),
            "import_hash": sha256_id(canonical_json_bytes(imported)),
            "baseline_at": timestamp(now),
            "legacy_history_preserved": True,
        },
        now=now,
    )
    return True


def known_urls(session, source):
    current = session.scalars(
        select(OfficialNoticeCurrent.document["document"]["url"].as_string())
        .where(OfficialNoticeCurrent.source_key == source)
        .limit(MAX_SOURCE_IDENTITIES + 1)
    ).all()
    pending = session.scalars(
        select(OfficialNoticePending.record_url)
        .where(
            OfficialNoticePending.source_key == source,
            OfficialNoticePending.processed_at.is_(None),
        )
        .limit(MAX_PENDING + 1)
    ).all()
    if len(current) > MAX_SOURCE_IDENTITIES or len(pending) > MAX_PENDING:
        raise BulletinError("official_identity_capacity")
    return frozenset(current) | frozenset(pending)


def reset_detail_failures(pending):
    """A completed or newly qualified work slot starts a fresh failure history."""
    pending.failure_count = 0
    pending.failure_category = None
    pending.first_failure_at = pending.last_failure_at = None


def stage(session, source, notices, *, now, baseline):
    """Retain the pending tail before the transaction can claim a complete fetch."""
    lock_stream(session, now=now)
    keys = [sha256_id(n.url.encode())[7:] for n in notices]
    existing = {
        r.record_key: r
        for r in session.scalars(
            select(OfficialNoticeCurrent).where(
                OfficialNoticeCurrent.source_key == source,
                OfficialNoticeCurrent.record_key.in_(keys),
            )
        )
    }
    work = {
        r.record_key: r
        for r in session.scalars(
            select(OfficialNoticePending).where(
                OfficialNoticePending.source_key == source,
                OfficialNoticePending.record_key.in_(keys),
            )
        )
    }
    pending_count = session.scalar(
        select(func.count())
        .select_from(OfficialNoticePending)
        .where(
            OfficialNoticePending.source_key == source,
            OfficialNoticePending.processed_at.is_(None),
        )
    )
    identities = session.scalar(
        select(func.count())
        .select_from(OfficialNoticeCurrent)
        .where(
            OfficialNoticeCurrent.source_key == source,
        )
    )
    unchanged, deferred, changes, ignored = [], 0, [], 0
    for notice, key in zip(notices, keys, strict=True):
        previous = existing.get(key)
        pending = work.get(key)
        doc = notice_document(notice)
        if previous is None and pending is None and notice.published < baseline:
            ignored += 1
            continue
        previous_doc = previous.document["document"] if previous else None
        if previous_doc and notice.withdrawn:
            doc["published_at"] = previous_doc["published_at"]
        if (
            previous_doc
            and previous_doc["modified_at"]
            and doc["modified_at"]
            and doc["modified_at"] < previous_doc["modified_at"]
        ):
            raise BulletinError("official_source_revision_regressed")
        digest = semantic_hash(doc)
        if previous is not None and digest == previous.semantic_hash:
            previous.updated_at = now  # The current input was observed again, not changed.
            unchanged.append(previous)
            if pending is not None:
                pending.processed_at = now  # Source reverted before an unaccepted update.
                pending.qualification_required, pending.next_attempt_at = False, None
                reset_detail_failures(pending)
            continue
        if pending is not None and pending.processed_at is None:
            old = session.get(OfficialNoticeEvidence, pending.evidence_id)
            if old.document["semantic_hash"] == digest:
                # A retained tail is freshly observed only after a successful
                # complete response, not merely because it is drained later.
                pending.updated_at = now
                pending.qualification_required, pending.next_attempt_at = False, None
                reset_detail_failures(pending)
                continue
        kind = "withdrawn" if notice.withdrawn else "corrected" if previous else "new"
        changes.append((kind, notice.published, key, doc, previous, pending))
    # All corrections precede new admissions: a full new queue cannot starve them.
    changes.sort(key=lambda item: (item[0] == "new", item[1], item[2]))
    for kind, _published, key, doc, previous, pending in changes:
        if previous is not None:
            mark_stale(
                session, bulletin_id(source, doc["url"]), reason="verification_pending", now=now
            )
        new_slot = pending is None or pending.processed_at is not None
        pending_ceiling = MAX_PENDING - MAX_PENDING // 5 if previous is None else MAX_PENDING
        if (new_slot and pending_count >= pending_ceiling) or (
            previous is None and identities + pending_count >= MAX_SOURCE_IDENTITIES
        ):
            deferred += 1
            continue
        try:
            capacity(session, new_identity=previous is None)
        except BulletinError:
            if previous is not None:
                raise
            deferred += 1
            continue
        value = envelope(
            doc, now=now, retrospective=(previous.document["retrospective"] if previous else False)
        )
        evidence_id = retain(session, value, now=now)
        if pending is None:
            pending = OfficialNoticePending(
                source_key=source, record_key=key, record_url=doc["url"], first_seen_at=now
            )
            session.add(pending)
        pending.evidence_id, pending.kind = evidence_id, kind
        pending.updated_at, pending.processed_at = now, None
        pending.qualification_required, pending.next_attempt_at = False, None
        reset_detail_failures(pending)
        pending_count += int(new_slot)
        mark_stale(session, bulletin_id(source, doc["url"]), reason="verification_pending", now=now)
    session.flush()
    return {"unchanged": unchanged, "deferred": deferred, "excluded_before_baseline": ignored}


def drain(session, source, *, now, process, limit=MAX_CHANGES_PER_SOURCE):
    """Process retained work even if the next network call fails or returns 304."""
    row = checkpoint(session, source, now=now)
    state = deepcopy(row.document)
    if state["daily_date"] != now.date().isoformat():
        state["daily_date"], state["daily_new"] = now.date().isoformat(), 0
    pending = list(
        session.scalars(
            select(OfficialNoticePending)
            .where(
                OfficialNoticePending.source_key == source,
                OfficialNoticePending.processed_at.is_(None),
            )
            .order_by(
                (OfficialNoticePending.kind == "new"),
                OfficialNoticePending.first_seen_at,
                OfficialNoticePending.record_key,
            )
            .limit(limit)
        )
    )
    accepted = {"new": 0, "corrected": 0, "withdrawn": 0}
    publication_failures = 0
    for item in pending:
        current = session.get(OfficialNoticeCurrent, (source, item.record_key))
        try:
            capacity(session, new_identity=current is None)
        except BulletinError as error:
            if current is not None or str(error) != "bulletin_storage_capacity":
                raise
            # Preserve already accepted corrections when new work reaches its
            # smaller allocation ceiling. The durable unprocessed tail remains.
            continue
        evidence = session.get(OfficialNoticeEvidence, item.evidence_id)
        value = evidence.document
        if sha256_id(canonical_json_bytes(value)) != evidence.evidence_id:
            raise BulletinError("official_evidence_hash")
        if current is None:
            current = OfficialNoticeCurrent(
                source_key=source, record_key=item.record_key, first_seen_at=item.first_seen_at
            )
            session.add(current)
            state["daily_new"] += 1
        current.document, current.semantic_hash = value, value["semantic_hash"]
        current.updated_at = item.updated_at
        session.flush()
        # Publication is its own gate; an accepted private notice is never lost
        # because publication is paused or needs individual review.
        current.publication_pending = not process(session, current, now=now)
        publication_failures += int(current.publication_pending)
        accepted[item.kind] += 1
        item.processed_at = now
    row.document, row.updated_at = state, now
    session.flush()
    return {"accepted": accepted, "publication_pending": publication_failures}


def public_status(session, source, *, state, reason, now):
    checkpoint_row = checkpoint(session, source, now=now)
    value = checkpoint_row.document
    pending_count, oldest = session.execute(
        select(func.count(), func.min(OfficialNoticePending.first_seen_at)).where(
            OfficialNoticePending.source_key == source, OfficialNoticePending.processed_at.is_(None)
        )
    ).one()
    row = session.get(BulletinSourceStatus, source)
    if row is None:
        row = BulletinSourceStatus(source_key=source, updated_at=now)
        session.add(row)
    row.state, row.reason = state, reason
    row.last_attempt_at, row.last_success_at = (
        instant(value["last_attempt"]),
        instant(value["last_success"]),
    )
    row.complete_through_at = instant(value["complete_through"])
    row.coverage_start_at = instant(value.get("coverage_start_at"))
    row.initial_history_complete = value.get("initial_history_complete")
    row.coverage_gaps = value.get("coverage_gaps")
    row.upstream_due_at = instant(value.get("upstream_due_at"))
    publishing_count, publishing_oldest = session.execute(
        select(func.count(), func.min(OfficialNoticeCurrent.first_seen_at)).where(
            OfficialNoticeCurrent.source_key == source,
            OfficialNoticeCurrent.publication_pending.is_(True),
        )
    ).one()
    row.pending_count = pending_count + publishing_count
    row.oldest_pending_at = min(
        [v for v in (oldest, publishing_oldest) if v is not None], default=None
    )
    row.updated_at = now
    if row.state == "fresh" and publishing_count:
        row.state, row.reason = "incomplete", "publication_pending"
    return pending_count


def daily_rollup(session, *, now):
    """Bounded previous-day accounting preserves missing epochs and closures."""
    day = now.date() - timedelta(days=1)
    prefix = day.strftime("%Y%m%d")
    epoch = prefix + "-daily"
    if session.get(OfficialIntakeRun, (epoch, "rollup")):
        return
    rows = session.scalars(
        select(OfficialIntakeRun)
        .where(
            OfficialIntakeRun.epoch >= prefix + "T00",
            OfficialIntakeRun.epoch <= prefix + "T23",
            OfficialIntakeRun.kind.in_(("intent", "closure")),
        )
        .limit(49)
    ).all()
    if len(rows) > 48:
        raise BulletinError("official_daily_epoch_integrity")
    if not rows:
        return
    intents = {r.epoch for r in rows if r.kind == "intent"}
    closures = {r.epoch: r.document for r in rows if r.kind == "closure"}
    record_run(
        session,
        epoch,
        "rollup",
        {
            "schema_version": 1,
            "utc_day": day.isoformat(),
            "expected_hour_slots": 24,
            "consumed_hours": len(intents),
            "unobserved_hours": 24 - len(intents),
            "missing_closures": sorted(intents - closures.keys()),
            "complete_hours": sum(v.get("status") == "complete" for v in closures.values()),
            "degraded_hours": sum(v.get("status") == "degraded" for v in closures.values()),
            "interrupted_hours": sum(v.get("status") == "interrupted" for v in closures.values()),
            "closure_hash": sha256_id(canonical_json_bytes(closures)),
        },
        now=now,
    )
