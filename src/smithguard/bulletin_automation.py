"""Bounded ongoing source work under the existing hourly intake authority."""

import time
from copy import deepcopy
from datetime import timedelta

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from smithguard import bulletin_intake_store as store
from smithguard.bulletin_contract import BulletinError, bulletin_id
from smithguard.bulletin_facts import envelope, semantic_hash
from smithguard.bulletin_freshness import recheck_due
from smithguard.bulletin_source_parser import (
    CISCO_DATE_BASIS,
    SourceCandidate,
    parse_index,
    publisher_detail,
)
from smithguard.bulletin_sources import NETWORK_SOURCES, SOURCE_IDS
from smithguard.bulletin_store import capacity, lock_stream, mark_stale
from smithguard.db.bulletin_models import (
    BulletinSourceStatus,
    OfficialNoticeCurrent,
    OfficialNoticeEvidence,
    OfficialNoticePending,
)
from smithguard.identifiers import canonical_json_bytes, sha256_id, timestamp
from smithguard.official_notice_fetch import fetch_public

ACTIVE_DAYS = 90
INITIAL_DAYS = 14
DETAIL_LIMIT = 6
SOURCE_LIMIT = 50


class FetchBudget:
    """One invocation budget shared across sources, including detail requests."""

    def __init__(self, fetch=fetch_public, *, seconds=600, maximum=84):
        self.fetch = fetch
        self.deadline = time.monotonic() + seconds
        self.maximum = maximum
        self.attempts = 0
        self.archive_ready_at = 0.0

    def __call__(self, source, **kwargs):
        if self.attempts >= self.maximum or time.monotonic() >= self.deadline:
            raise BulletinError("bulletin_network_budget")
        # These two archives share an upstream service. A burst across their
        # different hostnames can time out the later source. Space requests,
        # including failures, without retrying or extending the shared budget.
        archive = source in {"oss-security", "linux-security"}
        if archive:
            delay = max(0.0, self.archive_ready_at - time.monotonic())
            if time.monotonic() + delay >= self.deadline:
                raise BulletinError("bulletin_network_budget")
            if delay:
                time.sleep(delay)
            if time.monotonic() >= self.deadline:
                raise BulletinError("bulletin_network_budget")
        self.attempts += 1
        try:
            return self.fetch(source, **kwargs)
        finally:
            if archive:
                self.archive_ready_at = time.monotonic() + 5.0


def date_requalification(current):
    """Legacy Cisco feed dates require a bounded authoritative detail recheck."""
    return (
        current.source_key == "cisco-advisories"
        and current.document["document"]["facts"].get("date_basis") != CISCO_DATE_BASIS
    )


def active_known(session, source, *, now):
    rows = session.scalars(
        select(OfficialNoticeCurrent)
        .where(
            OfficialNoticeCurrent.source_key == source,
            OfficialNoticeCurrent.first_seen_at >= now - timedelta(days=ACTIVE_DAYS),
        )
        .limit(10001)
    ).all()
    if len(rows) > 10000:
        raise BulletinError("bulletin_active_population")
    return {row.document["document"]["url"]: row for row in rows}


def stage(session, source, candidates, *, now, baseline):
    """Persist complete candidate tails before advertising cursor progress."""
    lock_stream(session, now=now)
    keys = [row.record_key for row in candidates]
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
    count = session.scalar(
        select(func.count())
        .select_from(OfficialNoticePending)
        .where(
            OfficialNoticePending.source_key == source,
            OfficialNoticePending.processed_at.is_(None),
        )
    )
    ordered = sorted(
        candidates, key=lambda c: (c.record_key not in existing, c.published, c.record_key)
    )
    unchanged, deferred = [], 0
    for candidate in ordered:
        previous, pending = existing.get(candidate.record_key), work.get(candidate.record_key)
        if previous is None and pending is None and candidate.published < baseline:
            continue
        if previous is not None and previous.first_seen_at < now - timedelta(days=ACTIVE_DAYS):
            continue
        doc = candidate.document()
        repair_dates = previous is not None and date_requalification(previous)
        if previous is not None and candidate.needs_detail:
            previous_doc = previous.document["document"]
            index_same = previous_doc["facts"].get("index_hash") == doc["facts"].get(
                "index_hash", doc["facts"]["body_hash"]
            )
            if (
                index_same
                and not repair_dates
                and not recheck_due(previous, now)
                and not previous.publication_pending
            ):
                continue  # An index does not re-verify a detail page.
        digest = semantic_hash(doc)
        if previous is not None and digest == previous.semantic_hash:
            previous.updated_at = now
            unchanged.append(previous)
            if pending is not None:
                pending.processed_at = now
            continue
        if pending is not None and pending.processed_at is None:
            old = session.get(OfficialNoticeEvidence, pending.evidence_id)
            if old.document["semantic_hash"] == digest:
                pending.updated_at = now
                continue
        if previous is not None and not candidate.needs_detail:
            old_modified = previous.document["document"]["modified_at"]
            if old_modified and doc["modified_at"] and doc["modified_at"] < old_modified:
                from smithguard.bulletin_catalog import queue_omission

                queue_omission(session, source, candidate.record_key, digest, now=now)
                mark_stale(
                    session,
                    bulletin_id(source, candidate.url),
                    reason="verification_pending",
                    now=now,
                )
                continue
        new_slot = pending is None or pending.processed_at is not None
        ceiling = store.MAX_PENDING if previous else store.MAX_PENDING * 4 // 5
        if new_slot and count >= ceiling:
            deferred += 1
            continue
        try:
            capacity(session, new_identity=previous is None)
        except BulletinError:
            if previous:
                raise
            deferred += 1
            continue
        value = envelope(
            candidate,
            now=now,
            retrospective=(
                previous.document["retrospective"]
                if previous
                else candidate.published < baseline + timedelta(days=INITIAL_DAYS)
            ),
        )
        if (
            previous is not None
            and candidate.needs_detail
            and (
                previous.document["document"]["facts"].get("index_hash")
                == doc["facts"].get("index_hash", doc["facts"]["body_hash"])
            )
        ):
            # A recheck reuses accepted facts until a new detail response changes them.
            evidence_id = sha256_id(canonical_json_bytes(previous.document))
        else:
            evidence_id = store.retain(session, value, now=now)
        if pending is None:
            pending = OfficialNoticePending(
                source_key=source,
                record_key=candidate.record_key,
                record_url=candidate.url,
                first_seen_at=now,
            )
            session.add(pending)
        pending.evidence_id = evidence_id
        pending.qualification_required = candidate.needs_detail
        pending.kind = (
            "recheck"
            if previous and candidate.needs_detail and index_same and not repair_dates
            else "withdrawn"
            if candidate.facts["withdrawn"]
            else "corrected"
            if previous
            else "new"
        )
        pending.updated_at, pending.processed_at = now, None
        if new_slot:
            if pending.kind == "recheck" and not previous.publication_pending:
                from smithguard.bulletin_freshness import due

                pending.next_attempt_at = due(
                    source, previous.document["document"]["published_at"], previous.updated_at
                ) - timedelta(hours=2)
            else:
                pending.next_attempt_at = None
        count += int(new_slot)
        if previous is not None and (not candidate.needs_detail or repair_dates):
            mark_stale(
                session, bulletin_id(source, candidate.url), reason="verification_pending", now=now
            )
    session.flush()
    return unchanged, deferred


def qualify_details(connection, source, *, now, fetch, registry, enabled):
    if source not in NETWORK_SOURCES:
        return {"attempted": 0, "failed": 0}
    with Session(connection) as session:
        work = session.execute(
            select(OfficialNoticePending, OfficialNoticeEvidence)
            .join(
                OfficialNoticeEvidence,
                OfficialNoticeEvidence.evidence_id == OfficialNoticePending.evidence_id,
            )
            .where(
                OfficialNoticePending.source_key == source,
                OfficialNoticePending.processed_at.is_(None),
                OfficialNoticePending.qualification_required.is_(True),
                (OfficialNoticePending.next_attempt_at.is_(None))
                | (OfficialNoticePending.next_attempt_at <= now),
            )
            .order_by(
                case(
                    (OfficialNoticePending.kind == "corrected", 0),
                    (OfficialNoticePending.kind == "withdrawn", 0),
                    (OfficialNoticePending.kind == "recheck", 1),
                    else_=2,
                ),
                OfficialNoticePending.next_attempt_at.asc().nullsfirst(),
                OfficialNoticePending.updated_at,
                OfficialNoticePending.first_seen_at,
                OfficialNoticePending.record_key,
            )
            .limit(store.MAX_PENDING)
        ).all()
        # At least one slot remains available for a new arrival under sustained rechecks.
        new = [row for row in work if row[0].kind == "new"]
        other = [row for row in work if row[0].kind != "new"]
        work = (
            (new[:1] + other[: DETAIL_LIMIT - 1] + new[1:] + other[DETAIL_LIMIT - 1 :])[
                :DETAIL_LIMIT
            ]
            if new
            else other[:DETAIL_LIMIT]
        )
        documents = [
            (pending.record_key, deepcopy(evidence.document)) for pending, evidence in work
        ]
    attempted = failed = 0
    for key, value in documents:
        doc = value["document"]
        if not enabled():
            break
        try:
            registry.get(SOURCE_IDS[source]).authorize_collection(
                method="download",
                canonical_url=doc["url"],
                today=now.date(),
            )
            attempted += 1
            fetched = fetch(source, url=doc["url"])
            if fetched.status != 200:
                raise BulletinError("bulletin_detail_http")
            initial = SourceCandidate(
                source,
                doc["url"],
                store.instant(doc["published_at"]),
                store.instant(doc["modified_at"]),
                doc["facts"],
                True,
            )
            candidate = publisher_detail(initial, fetched.body, now=now)
            qualified = envelope(candidate, now=now, retrospective=value["retrospective"])
            with Session(connection) as session, session.begin():
                lock_stream(session, now=now)
                capacity(session, new_identity=False)
                pending = session.get(OfficialNoticePending, (source, key))
                current = session.get(OfficialNoticeCurrent, (source, key))
                if current is not None and current.semantic_hash == qualified["semantic_hash"]:
                    pending.evidence_id = sha256_id(canonical_json_bytes(current.document))
                else:
                    pending.evidence_id = store.retain(session, qualified, now=now)
                pending.qualification_required = False
                pending.next_attempt_at = None
                pending.updated_at = now
        except Exception:
            failed += 1
            with Session(connection) as session, session.begin():
                pending = session.get(OfficialNoticePending, (source, key))
                pending.next_attempt_at = now + timedelta(hours=6)
                mark_stale(
                    session, bulletin_id(source, doc["url"]), reason="verification_pending", now=now
                )
    return {"attempted": attempted, "failed": failed}


def drain_qualified(session, source, *, now, process, limit=SOURCE_LIMIT):
    """Detail-required entries remain pending; each source has its own fair share."""
    work = session.execute(
        select(OfficialNoticePending, OfficialNoticeEvidence)
        .join(
            OfficialNoticeEvidence,
            OfficialNoticeEvidence.evidence_id == OfficialNoticePending.evidence_id,
        )
        .where(
            OfficialNoticePending.source_key == source,
            OfficialNoticePending.processed_at.is_(None),
            OfficialNoticePending.qualification_required.is_(False),
        )
        .order_by(
            (OfficialNoticePending.kind == "new"),
            OfficialNoticePending.first_seen_at,
            OfficialNoticePending.record_key,
        )
        .limit(limit)
    ).all()
    accepted = {"new": 0, "corrected": 0, "withdrawn": 0, "recheck": 0}
    for item, evidence in work:
        value = evidence.document
        if sha256_id(canonical_json_bytes(value)) != evidence.evidence_id:
            raise BulletinError("bulletin_evidence_hash")
        current = session.get(OfficialNoticeCurrent, (source, item.record_key))
        try:
            capacity(session, new_identity=current is None)
        except BulletinError:
            if current is not None:
                raise
            continue  # Preserve the correction reserve and leave new admission pending.
        if current is None:
            current = OfficialNoticeCurrent(
                source_key=source, record_key=item.record_key, first_seen_at=item.first_seen_at
            )
            session.add(current)
        current.document, current.semantic_hash = value, value["semantic_hash"]
        current.updated_at = item.updated_at
        session.flush()
        current.publication_pending = not process(session, current, now=now)
        item.processed_at = now
        accepted[item.kind] += 1
    session.flush()
    return accepted


def run_source(
    connection,
    source,
    *,
    now,
    epoch,
    registry,
    process,
    enabled,
    fetch=fetch_public,
    limit=SOURCE_LIMIT,
):
    from smithguard.bulletin_intake import reason

    if source in NETWORK_SOURCES and NETWORK_SOURCES[source].discovery_only:
        from smithguard.bulletin_discovery import run as discover

        return discover(
            connection,
            source,
            now=now,
            epoch=epoch,
            registry=registry,
            enabled=enabled,
            fetch=fetch,
            limit=limit,
        )
    with Session(connection, expire_on_commit=False) as session, session.begin():
        row = store.checkpoint(session, source, now=now)
        state = deepcopy(row.document)
        if not state.get("automation_version"):
            state.update(
                automation_version=1, baseline_at=timestamp(now - timedelta(days=INITIAL_DAYS))
            )
            row.document = deepcopy(state)
        known = active_known(session, source, now=now)
    attempted, diagnostics, error, fetched = False, {}, None, None
    deferred, unchanged_keys, coverage_gap = 0, [], None
    baseline = store.instant(state["baseline_at"])
    try:
        if not enabled():
            raise BulletinError("policy_paused")
        if state["next_attempt_at"] and store.instant(state["next_attempt_at"]) > now:
            raise BulletinError("source_cooldown")
        if source in NETWORK_SOURCES:
            spec = NETWORK_SOURCES[source]
            registry.get(SOURCE_IDS[source]).authorize_collection(
                method="download",
                canonical_url=spec.endpoint,
                today=now.date(),
            )
            attempted = True
            fetched = fetch(source)
            if fetched.status != 200:
                raise BulletinError("bulletin_source_http")
            candidates = list(parse_index(source, fetched.body, now=now))
            seen = {c.url for c in candidates}
            for url, current in known.items():
                if url not in seen and (
                    date_requalification(current)
                    or recheck_due(current, now)
                    or current.publication_pending
                ):
                    doc = current.document["document"]
                    candidates.append(
                        SourceCandidate(
                            source,
                            url,
                            store.instant(doc["published_at"]),
                            store.instant(doc["modified_at"]),
                            doc["facts"],
                            True,
                        )
                    )
            diagnostics = {
                "feed_hash": fetched.sha256,
                "bytes": len(fetched.body),
                "records": len(candidates),
            }
            oldest = min((c.published for c in candidates if c.url in seen), default=baseline)
            boundary = store.instant(state.get("observed_through"))
            if boundary is None:
                state["coverage_start_at"] = timestamp(max(baseline, oldest))
                state["initial_history_complete"] = oldest <= baseline
            if boundary is not None and oldest > boundary:
                coverage_gap = {
                    "schema_version": 1,
                    "kind": "source_coverage_gap",
                    "source_key": source,
                    "since": timestamp(boundary),
                    "until": timestamp(oldest),
                    "detected_at": timestamp(now),
                    "feed_hash": fetched.sha256,
                }
                gaps = state.setdefault("coverage_gaps", {"count": 0, "recent": []})
                gaps["count"] += 1
                gaps["recent"] = (
                    gaps["recent"]
                    + [
                        {
                            "since": timestamp(boundary),
                            "until": timestamp(oldest),
                            "detected_at": timestamp(now),
                        }
                    ]
                )[-16:]
            state["gap_since"] = None  # Historical holes remain disclosed separately.
        else:
            from smithguard.bulletin_catalog import candidates as catalog_candidates

            with Session(connection) as session, session.begin():
                candidates, diagnostics = catalog_candidates(
                    session,
                    source,
                    now=now,
                    baseline=max(baseline, now - timedelta(days=ACTIVE_DAYS)),
                    known_urls=list(known),
                )
        with Session(connection) as session, session.begin():
            unchanged, deferred = stage(session, source, candidates, now=now, baseline=baseline)
            unchanged_keys = [row.record_key for row in unchanged]
        if not deferred:
            state["observed_through"] = timestamp(now)
        if source not in NETWORK_SOURCES:
            state.setdefault("coverage_start_at", timestamp(baseline))
            state.setdefault("initial_history_complete", True)
            state["upstream_due_at"] = diagnostics["collector_due_at"]
        state["last_success"], state["last_attempt"] = timestamp(now), timestamp(now)
        state["failures"], state["next_attempt_at"] = 0, None
    except Exception as caught:
        error = reason(caught)
        state["last_attempt"] = timestamp(now)
        if error not in {"policy_paused", "source_cooldown"}:
            state["failures"] += 1
            if state["failures"] >= 3:
                state["next_attempt_at"] = timestamp(now + timedelta(hours=6))
    # Previously accepted detail URLs remain independently scheduled even if the
    # index fails. Index failure stays visible and cannot advance its cursor.
    if error and error != "policy_paused" and enabled() and source in NETWORK_SOURCES:
        corrections = []
        for url, current in known.items():
            if (
                date_requalification(current)
                or recheck_due(current, now)
                or current.publication_pending
            ):
                doc = current.document["document"]
                corrections.append(
                    SourceCandidate(
                        source,
                        url,
                        store.instant(doc["published_at"]),
                        store.instant(doc["modified_at"]),
                        doc["facts"],
                        True,
                    )
                )
        with Session(connection) as session, session.begin():
            stage(session, source, corrections, now=now, baseline=baseline)
    details = (
        qualify_details(
            connection, source, now=now, fetch=fetch, registry=registry, enabled=enabled
        )
        if error != "policy_paused" and enabled()
        else {"attempted": 0, "failed": 0}
    )
    with Session(connection) as session, session.begin():
        lock_stream(session, now=now)
        if coverage_gap is not None:
            from smithguard.db.bulletin_models import BulletinMaintenanceReceipt

            capacity(session, new_identity=False)
            session.add(
                BulletinMaintenanceReceipt(
                    receipt_id=sha256_id(canonical_json_bytes(coverage_gap)),
                    document=coverage_gap,
                    created_at=now,
                )
            )
        row = store.checkpoint(session, source, now=now)
        row.document = deepcopy(state)
        for key in unchanged_keys:
            current = session.get(OfficialNoticeCurrent, (source, key))
            current.publication_pending = not process(session, current, now=now)
        accepted = drain_qualified(session, source, now=now, process=process, limit=limit)
        # Retry publication-only debt independently of whether a finite feed still
        # contains the row. Old evidence still fails the accepted-input clock gate.
        pending = store.public_status(
            session, source, state="incomplete", reason="catching_up", now=now
        )
        pending = session.get(BulletinSourceStatus, source).pending_count
        if error:
            status, why = ("paused" if error == "policy_paused" else "unavailable"), error[:40]
        elif details["failed"]:
            status, why = "incomplete", "detail_qualification_failed"
        elif diagnostics.get("omitted_records", 0):
            status, why = "incomplete", "catalog_record_omitted"
        elif pending or deferred:
            status, why = "incomplete", "catching_up"
        else:
            status, why = "fresh", None
            state["complete_through"] = timestamp(now)
        state.update(consumed_epoch=epoch, pending_count=pending)
        row.document, row.updated_at = deepcopy(state), now
        store.public_status(session, source, state=status, reason=why, now=now)
        from smithguard.bulletin_renewal import flush

        flush(session, now=now)
        report = {
            "source": source,
            "state": status,
            "reason": why,
            "accepted": accepted,
            "pending": pending,
            "deferred": deferred,
            "network_attempted": attempted,
            "http_status": fetched.status if fetched else None,
            "input_qualified": error is None,
            "qualified_records": session.scalar(
                select(func.count())
                .select_from(OfficialNoticeCurrent)
                .where(OfficialNoticeCurrent.source_key == source)
            ),
            "eligible_records": sum(c.published >= baseline for c in candidates)
            if error is None
            else None,
            "detail_requests": details,
            "observation": diagnostics,
            "checkpoint_hash": sha256_id(canonical_json_bytes(state)),
        }
    return report
