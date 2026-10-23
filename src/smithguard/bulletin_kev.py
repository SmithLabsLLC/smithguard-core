"""Bounded bulletin projection of the existing immutable CISA catalog snapshots.

No network access. A retained catalog checkpoint prevents historical backfill.
CVE is the publisher's record identity; the catalog URL remains a real source link.
"""

from copy import deepcopy
from datetime import date, timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import aliased

from smithguard.bulletin_contract import BulletinError, content_id, validate_content
from smithguard.bulletin_policy import MAX_KEV_VERIFICATIONS
from smithguard.db.bulletin_models import (
    BulletinCurrent,
    BulletinRevision,
    BulletinSourceStatus,
    OfficialSourceCheckpoint,
)
from smithguard.db.models import (
    SupplementalFactRecord,
    SupplementalPayloadRecord,
    SupplementalSnapshotRecord,
)
from smithguard.identifiers import canonical_json_bytes, sha256_id, timestamp
from smithguard.supplemental_store import CVE, KEV_SOURCE, MAX_AGE, latest_snapshot

CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
MAX_CATALOG = 20_000


def fact(session, snapshot, cve):
    row = session.get(SupplementalFactRecord, (snapshot.snapshot_id, cve))
    if row is None:
        return None
    value = row.document
    if value is None:
        payload = session.get(SupplementalPayloadRecord, row.payload_sha256)
        if (
            payload is None
            or sha256_id(canonical_json_bytes(payload.document)) != row.payload_sha256
        ):
            raise BulletinError("kev_payload_integrity")
        value = payload.document
    if (
        not CVE.fullmatch(cve)
        or set(value) != {"date_added"}
        or sha256_id(
            canonical_json_bytes(
                {"snapshot_id": snapshot.snapshot_id, "subject_id": cve, "document": value}
            )
        )
        != row.record_hash
    ):
        raise BulletinError("kev_fact_integrity")
    day = date.fromisoformat(value["date_added"])
    if day > snapshot.observed_at.date():
        raise BulletinError("kev_fact_future")
    return {
        "source": "kev",
        "cve": cve,
        "date_added": value["date_added"],
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_hash": snapshot.record_hash,
        "observed_at": timestamp(snapshot.observed_at),
    }


def fresh_snapshot(session, *, now):
    # The latest attempt must itself be complete: a later failure is visible.
    snapshot = latest_snapshot(session, KEV_SOURCE)
    if (
        snapshot is None
        or snapshot.state != "complete"
        or not now - MAX_AGE < snapshot.observed_at <= now
        or snapshot.record_count > MAX_CATALOG
    ):
        raise BulletinError("kev_snapshot_unavailable")
    return snapshot


def project_kev(value, registry, *, now):
    cve, day = value["cve"], value["date_added"]
    if not CVE.fullmatch(cve) or date.fromisoformat(day) > now.date():
        raise BulletinError("kev_fact_invalid")
    profile = registry.get(KEV_SOURCE)
    evidence = sha256_id(canonical_json_bytes({"source": "kev", "cve": cve, "date_added": day}))
    return validate_content(
        {
            "schema_version": "1.0.0",
            "source_key": "kev",
            "source_record_id": cve,
            "record_url": CATALOG,
            "evidence_class": "official_advisory",
            "verification": "publisher_endpoint_tls",
            "applicability": "not_evaluated",
            "lifecycle": "current",
            "title": f"CISA lists {cve} as exploited",
            "summary": f"CISA lists {cve} in its Known Exploited Vulnerabilities Catalog, "
            f"with an addition date of {day}. Search the linked catalog for this CVE.",
            "subjects": [cve],
            "aliases": [cve],
            "source_published_at": day + "T00:00:00Z",
            "source_modified_at": None,
            "time_precision": "day",
            "severity": "unknown",
            "exploitation": "source_reports_exploitation",
            "remediation": "unknown",
            "conditions": [],
            "guidance": [],
            "unknowns": [
                "The catalog addition date is not the first exploitation date.",
                "Affected versions, fixes and installation applicability are not assessed here.",
            ],
            "sources": [
                {
                    "source_id": KEV_SOURCE,
                    "record_url": CATALOG,
                    "source_evidence_hash": evidence,
                    "rights_revision": profile.source["revision"],
                    "attribution": profile.source["rights"]["attribution_text"],
                    "used_fields": ["cve", "date_added"],
                }
            ],
            "related_bulletins": [],
            "retrospective": False,
        },
        now=now,
    )


def accepted_input(session, document, *, now):
    snapshot = fresh_snapshot(session, now=now)
    checkpoint = session.get(OfficialSourceCheckpoint, "kev")
    if checkpoint is None:
        raise BulletinError("kev_baseline_required")
    current = session.get(BulletinCurrent, content_id(document))
    if (
        current is None
        and session.get(
            SupplementalFactRecord,
            (checkpoint.document["initial_snapshot"], document["source_record_id"]),
        )
        is not None
    ):
        raise BulletinError("kev_historical_backfill_forbidden")
    value = fact(session, snapshot, document["source_record_id"])
    if value is None:
        raise BulletinError("bulletin_accepted_input_not_current")
    return value


def verification_due(value, *, now):
    from datetime import datetime

    return min(now + timedelta(hours=24), datetime.fromisoformat(value["observed_at"]) + MAX_AGE)


def run(session, *, registry, grant_reader, now):
    """200 due checks plus 80 existing/20 new items; no source tail is discarded."""
    from smithguard import bulletin_store as store

    stream = store.lock_stream(session, now=now)
    grant = grant_reader(now=now)
    if "kev" not in grant["source_keys"] or grant["mode"] == "paused":
        return {"status": "paused", "network_attempts": 0}
    status = session.get(BulletinSourceStatus, "kev")
    if status is None:
        status = BulletinSourceStatus(
            source_key="kev", state="unavailable", updated_at=now, pending_count=0
        )
        session.add(status)
    status.last_attempt_at = now
    try:
        snapshot = fresh_snapshot(session, now=now)
    except BulletinError:
        status.state, status.reason, status.updated_at = (
            "unavailable",
            "kev_snapshot_unavailable",
            now,
        )
        return {"status": "unavailable", "network_attempts": 0}
    checkpoint = session.get(OfficialSourceCheckpoint, "kev")
    if checkpoint is None:
        store.capacity(session, new_identity=True)
        checkpoint = OfficialSourceCheckpoint(
            source_key="kev",
            updated_at=now,
            document={
                "schema_version": 1,
                "initial_snapshot": snapshot.snapshot_id,
                "baseline_snapshot": snapshot.snapshot_id,
                "baseline_sequence": snapshot.sequence,
                "baseline_at": timestamp(now),
                "target_snapshot": None,
                "current_after": "",
                "new_after": "",
                "current_done": False,
                "new_done": False,
                "gap": False,
            },
        )
        session.add(checkpoint)
        from smithguard.bulletin_intake_store import record_run

        record_run(
            session,
            "kev-catalog-baseline",
            "cutover",
            {
                "schema_version": 1,
                "snapshot_id": snapshot.snapshot_id,
                "snapshot_hash": snapshot.record_hash,
                "record_count": snapshot.record_count,
                "observed_at": timestamp(snapshot.observed_at),
                "baseline_at": timestamp(now),
                "grant_hash": sha256_id(canonical_json_bytes(grant)),
            },
            now=now,
        )
        status.state, status.reason = "fresh", None
        status.last_success_at = now
        status.complete_through_at = snapshot.observed_at
        status.updated_at = now
        return {
            "status": "checkpointed",
            "baseline_count": snapshot.record_count,
            "network_attempts": 0,
        }
    state = deepcopy(checkpoint.document)
    if grant["mode"] != "automatic":
        status.state, status.reason, status.updated_at = "paused", "manual_review_required", now
        return {"status": "paused", "network_attempts": 0}
    if state["target_snapshot"]:
        target = session.get(SupplementalSnapshotRecord, state["target_snapshot"])
    else:
        target = session.scalar(
            select(SupplementalSnapshotRecord)
            .where(
                SupplementalSnapshotRecord.source_id == KEV_SOURCE,
                SupplementalSnapshotRecord.mode == "public",
                SupplementalSnapshotRecord.state == "complete",
                SupplementalSnapshotRecord.sequence > state["baseline_sequence"],
            )
            .order_by(SupplementalSnapshotRecord.sequence)
            .limit(1)
        )
        if target:
            state.update(
                target_snapshot=target.snapshot_id,
                current_after="",
                new_after="",
                current_done=False,
                new_done=False,
            )
    changes, blocked = 0, 0

    def process(cve):
        nonlocal changes, blocked
        value = fact(session, snapshot, cve)
        identity = content_id({"source_key": "kev", "source_record_id": cve})
        current = session.get(BulletinCurrent, identity)
        if current and current.tombstoned:
            return True
        if value is None:
            # Disappearance is not a fabricated withdrawal or a safety claim.
            if current:
                store.mark_stale(session, identity, reason="catalog_entry_absent", now=now)
            return True
        document = project_kev(value, registry, now=now)
        digest = sha256_id(canonical_json_bytes(document))
        prior = session.get(BulletinRevision, (identity, current.revision)) if current else None
        try:
            # Preserve the immutable snapshot identity in each actual decision.
            if prior is None or prior.content_hash != digest:
                store.publish(
                    session, document, grant=grant_reader(now=now), registry=registry, now=now
                )
                changes += 1
            elif current.freshness_reason or (
                current.verification_due_at <= now + renewal_window
                and verification_due(value, now=now) > current.verification_due_at
            ):
                store.verify_unchanged(
                    session,
                    identity,
                    content_hash=digest,
                    grant=grant_reader(now=now),
                    registry=registry,
                    now=now,
                )
                changes += 1
            return True
        except BulletinError as error:
            if current:
                reason = (
                    "rights_review_due"
                    if str(error) == "bulletin_rights_not_current"
                    else "verification_pending"
                )
                store.mark_stale(session, identity, reason=reason, now=now)
            blocked += 1
            return False

    population = session.scalar(
        select(func.count())
        .select_from(BulletinCurrent)
        .where(BulletinCurrent.source_key == "kev", BulletinCurrent.tombstoned.is_(False))
    )
    # The renewal window covers a full bounded sweep plus one hourly interval.
    # Prioritizing deadlines prevents a rotating identity cursor from missing it.
    renewal_window = timedelta(
        hours=max(2, (population + MAX_KEV_VERIFICATIONS - 1) // MAX_KEV_VERIFICATIONS + 1)
    )
    due_rows = session.execute(
        select(BulletinCurrent, BulletinRevision)
        .join(
            BulletinRevision,
            (BulletinRevision.bulletin_id == BulletinCurrent.bulletin_id)
            & (BulletinRevision.revision == BulletinCurrent.revision),
        )
        .where(
            BulletinCurrent.source_key == "kev",
            BulletinCurrent.tombstoned.is_(False),
            BulletinCurrent.verification_due_at <= now + renewal_window,
            BulletinCurrent.verification_due_at
            < min(now + timedelta(hours=24), snapshot.observed_at + MAX_AGE),
            select(SupplementalFactRecord.subject_id)
            .where(
                SupplementalFactRecord.snapshot_id == snapshot.snapshot_id,
                SupplementalFactRecord.subject_id
                == BulletinRevision.document["source_record_id"].astext,
            )
            .exists(),
        )
        .order_by(BulletinCurrent.verification_due_at, BulletinCurrent.bulletin_id)
        .limit(MAX_KEV_VERIFICATIONS)
    ).all()
    checked = set()
    for current, revision in due_rows:
        checked.add(current.bulletin_id)
        process(revision.document["source_record_id"])
    # Select only changed, absent or returning identities. An unchanged six-hour
    # catalog must not require an 80/hour walk of all 1,000 surviving identities.
    # Deadline renewals remain independently bounded above; the join is bounded
    # by the admitted identity ceiling and each payload is checked by process().
    catalog_day = func.coalesce(
        SupplementalFactRecord.document["date_added"].astext,
        SupplementalPayloadRecord.document["date_added"].astext,
    )
    current_rows = session.execute(
        select(BulletinCurrent, BulletinRevision)
        .join(
            BulletinRevision,
            (BulletinRevision.bulletin_id == BulletinCurrent.bulletin_id)
            & (BulletinRevision.revision == BulletinCurrent.revision),
        )
        .outerjoin(
            SupplementalFactRecord,
            (SupplementalFactRecord.snapshot_id == snapshot.snapshot_id)
            & (
                SupplementalFactRecord.subject_id
                == BulletinRevision.document["source_record_id"].astext
            ),
        )
        .outerjoin(
            SupplementalPayloadRecord,
            SupplementalPayloadRecord.payload_sha256 == SupplementalFactRecord.payload_sha256,
        )
        .where(
            BulletinCurrent.source_key == "kev",
            BulletinCurrent.tombstoned.is_(False),
            BulletinCurrent.bulletin_id.not_in(checked),
            or_(
                and_(
                    SupplementalFactRecord.subject_id.is_(None),
                    BulletinCurrent.freshness_reason.is_distinct_from("catalog_entry_absent"),
                ),
                and_(
                    SupplementalFactRecord.subject_id.is_not(None),
                    or_(
                        catalog_day.is_(None),
                        catalog_day
                        != func.substr(
                            BulletinRevision.document["source_published_at"].astext, 1, 10
                        ),
                        BulletinCurrent.freshness_reason.is_not(None),
                    ),
                ),
            ),
        )
        .order_by(BulletinCurrent.bulletin_id)
        .limit(81)
    ).all()
    for _current, revision in current_rows[:80]:
        if not process(revision.document["source_record_id"]):
            break
    state["current_done"] = len(current_rows) <= 80 and not blocked
    if target is not None and not state["new_done"]:
        if target.record_count > MAX_CATALOG:
            raise BulletinError("kev_catalog_limit")
        old = aliased(SupplementalFactRecord)
        candidates = session.scalars(
            select(SupplementalFactRecord.subject_id)
            .where(
                SupplementalFactRecord.snapshot_id == target.snapshot_id,
                SupplementalFactRecord.subject_id > state["new_after"],
                ~select(old.subject_id)
                .where(
                    old.snapshot_id == state["baseline_snapshot"],
                    old.subject_id == SupplementalFactRecord.subject_id,
                )
                .exists(),
            )
            .order_by(SupplementalFactRecord.subject_id)
            .limit(21)
        ).all()
        for cve in candidates[:20]:
            if not process(cve):
                break
            state["new_after"] = cve
        if len(candidates) <= 20 and not blocked:
            state["new_done"] = True
    if target is not None and state["new_done"] and state["current_done"]:
        state.update(
            baseline_snapshot=target.snapshot_id,
            baseline_sequence=target.sequence,
            target_snapshot=None,
            new_after="",
            current_after="",
            current_done=False,
            new_done=False,
        )
        status.complete_through_at = target.observed_at
    elif target is None and state["current_done"]:
        state.update(current_after="", current_done=False)
    pending = bool(state["target_snapshot"]) or state["baseline_sequence"] < snapshot.sequence
    # A complete catalog may explicitly omit an individual former member. Its
    # own stale record persists; that does not make verified siblings stale.
    state["gap"] = False
    status.state = "incomplete" if pending or blocked else "fresh"
    status.reason = "catching_up" if pending or blocked else None
    # At least one pending unit means incomplete, never claim an exact record count.
    status.pending_count = int(pending or bool(blocked))
    status.oldest_pending_at = target.observed_at if pending and target else None
    status.last_success_at, status.updated_at = now, now
    checkpoint.document, checkpoint.updated_at = state, now
    stream.mode, stream.grant_hash = grant["mode"], sha256_id(canonical_json_bytes(grant))
    return {
        "status": status.state,
        "changes": changes,
        "deadline_checks": len(checked),
        "renewal_window_hours": renewal_window.total_seconds() / 3600,
        "blocked": blocked,
        "pending_snapshot": pending,
        "network_attempts": 0,
    }
