"""One hourly official intake authority with durable catch-up and compact receipts."""

import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard import bulletin_intake_store as store
from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_intake_parser import parse_complete
from smithguard.bulletin_policy import FEED_SOURCES, MAX_CHANGES_PER_RUN
from smithguard.bulletin_store import capacity, lock_stream
from smithguard.db.bulletin_models import (
    BulletinSourceStatus,
    OfficialIntakeRun,
    OfficialNoticeCurrent,
)
from smithguard.identifiers import canonical_json_bytes, require_aware_utc, sha256_id, timestamp
from smithguard.official_notice_coordinator import LOCK_NAME
from smithguard.official_notice_fetch import ENDPOINTS, selected_sources
from smithguard.official_notice_fetch import fetch as fetch_feed
from smithguard.official_notice_store import started_hour


def clock():
    return datetime.now(UTC)


def no_publication(session, row, *, now):
    # Private-only callers have no requested public work to leave pending.
    # The publication-enabled runtime must pass the release-bound processor.
    return True


def reason(error):
    if isinstance(error, TimeoutError):
        return "source_timeout"
    message = str(error)
    if isinstance(error, ValueError) and re.fullmatch("[a-z][a-z0-9_]{0,70}", message):
        return message
    return "source_processing_failed"


def _source(connection, source, *, now, epoch, fetch, enabled, registry, process, limit):
    with Session(connection) as session, session.begin():
        row = store.checkpoint(session, source, now=now)
        before = deepcopy(row.document)
        known = store.known_urls(session, source)
    fetched, diagnostics, parsed, error_code = None, {}, None, None
    recovered_gap = None
    attempted = False
    if not enabled():
        error_code = "policy_paused"
    elif before["next_attempt_at"] and store.instant(before["next_attempt_at"]) > now:
        error_code = "source_cooldown"
    else:
        try:
            registry.get(FEED_SOURCES[source]).authorize_collection(
                method="download",
                canonical_url=ENDPOINTS[source][0],
                today=now.date(),
            )
            attempted = True
            conditional = not before["pending_count"] and not before["gap_since"]
            fetched = fetch(
                source,
                etag=before["etag"] if conditional else None,
                modified=before["modified"] if conditional else None,
            )
            if fetched.status == 304:
                if not conditional or not (before["etag"] or before["modified"]):
                    raise BulletinError("unsolicited_not_modified")
            elif fetched.status == 200:
                boundary = store.instant(before["complete_through"] or before["baseline_at"])
                parsed = parse_complete(
                    source,
                    fetched.body,
                    now=now,
                    known_urls=known,
                    earliest_unseen=max(
                        store.instant(before["baseline_at"]), boundary - store.OVERLAP
                    ),
                    diagnostics=diagnostics,
                )
            else:
                raise BulletinError("official_http_status")
        except Exception as error:
            error_code = reason(error)
    try:
        with Session(connection) as session, session.begin():
            lock_stream(session, now=now)
            row = store.checkpoint(session, source, now=now)
            state = deepcopy(row.document)
            state["consumed_epoch"] = epoch
            if attempted:
                state["last_attempt"] = timestamp(now)
            if error_code is None:
                state["failures"], state["next_attempt_at"] = 0, None
                if parsed is not None:
                    staged = store.stage(
                        session,
                        source,
                        parsed,
                        now=now,
                        baseline=store.instant(state["baseline_at"]),
                    )
                    boundary = store.instant(state["complete_through"] or state["baseline_at"])
                    oldest = store.instant(diagnostics["oldest_published_at"])
                    if oldest is None or oldest > boundary:
                        state["gap_since"] = state["gap_since"] or timestamp(boundary)
                    elif state["gap_since"]:
                        recovered_gap = {
                            "since": state["gap_since"],
                            "recovered_at": timestamp(now),
                            "feed_sha256": fetched.sha256,
                        }
                        state["last_recovered_gap"] = recovered_gap
                        state["gap_since"] = None
                    observed = staged["unchanged"]
                else:
                    # A valid 304 rechecks only identities present in the last
                    # complete response, not every historical identity we know.
                    observed = list(
                        session.scalars(
                            select(OfficialNoticeCurrent)
                            .where(
                                OfficialNoticeCurrent.source_key == source,
                                OfficialNoticeCurrent.updated_at
                                == store.instant(state["last_success"]),
                            )
                            .limit(store.MAX_SOURCE_IDENTITIES)
                        )
                    )
                    staged = {"deferred": 0, "excluded_before_baseline": 0}
                    for current in observed:
                        current.updated_at = now
                for current in observed:
                    current.publication_pending = not process(session, current, now=now)
                state["last_success"] = timestamp(now)
            else:
                staged = {"deferred": 0, "excluded_before_baseline": 0}
                if attempted:
                    state["failures"] += 1
                    if state["failures"] >= 3:
                        state["next_attempt_at"] = timestamp(now + timedelta(hours=6))
            row.document = state
            # The already validated tail survives unavailable or changed feeds.
            drained = store.drain(session, source, now=now, process=process, limit=limit)
            state = deepcopy(row.document)
            pending = store.public_status(
                session, source, state="incomplete", reason="catching_up", now=now
            )
            state["pending_count"] = pending
            if error_code:
                status, status_reason = (
                    ("paused" if error_code == "policy_paused" else "unavailable"),
                    error_code,
                )
            elif state["gap_since"]:
                status, status_reason = "incomplete", "finite_feed_gap"
            elif pending or staged["deferred"]:
                status, status_reason = "incomplete", "catching_up"
            else:
                status, status_reason = "fresh", None
                state["complete_through"] = timestamp(now)
                state["etag"], state["modified"] = fetched.etag, fetched.modified
            row.document, row.updated_at = state, now
            store.public_status(session, source, state=status, reason=status_reason, now=now)
            public = session.get(BulletinSourceStatus, source)
            return {
                "source": source,
                "state": public.state,
                "reason": public.reason,
                "network_attempted": attempted,
                "http_status": fetched.status if fetched else None,
                "feed_sha256": fetched.sha256 if fetched else None,
                "bytes": len(fetched.body) if fetched else 0,
                "parser": diagnostics or None,
                "pending": pending,
                "deferred": staged["deferred"],
                "recovered_gap": recovered_gap,
                **drained,
                "checkpoint_hash": sha256_id(canonical_json_bytes(state)),
            }
    except Exception as error:
        # The source transaction is rolled back. Preserve an explicit failure and
        # the prior checkpoint; never turn a failed stage into complete coverage.
        code = reason(error)
        with Session(connection) as session, session.begin():
            row = store.checkpoint(session, source, now=now)
            state = deepcopy(row.document)
            state["consumed_epoch"] = epoch
            if attempted:
                state["last_attempt"] = timestamp(now)
                state["failures"] += 1
                if state["failures"] >= 3:
                    state["next_attempt_at"] = timestamp(now + timedelta(hours=6))
            row.document, row.updated_at = state, now
            store.public_status(session, source, state="unavailable", reason=code[:40], now=now)
        return {
            "source": source,
            "state": "unavailable",
            "reason": code,
            "network_attempted": attempted,
            "accepted": {},
            "checkpoint_hash": sha256_id(canonical_json_bytes(state)),
        }


def run(
    engine,
    *,
    registry,
    fetch=fetch_feed,
    enabled=lambda: False,
    process=no_publication,
    now=None,
    artifact_commit=None,
    invocation_id=None,
    source_keys=tuple(ENDPOINTS),
):
    now = require_aware_utc(now or clock())
    source_keys = selected_sources(source_keys)
    if not isinstance(artifact_commit, str) or not re.fullmatch("[a-f0-9]{40}", artifact_commit):
        raise BulletinError("official_artifact_invalid")
    if not isinstance(invocation_id, str) or not re.fullmatch("[a-f0-9]{32}", invocation_id):
        raise BulletinError("official_invocation_invalid")
    if not enabled():
        return {"status": "paused", "network_attempts": 0}
    epoch = now.strftime("%Y%m%dT%H")
    with engine.connect() as connection:
        locked = connection.scalar(
            select(func.pg_try_advisory_lock(func.hashtextextended(LOCK_NAME, 0)))
        )
        connection.commit()
        if not locked:
            return {"status": "busy", "network_attempts": 0}
        try:
            with Session(connection) as session, session.begin():
                if started_hour(session, epoch) or session.get(
                    OfficialIntakeRun, (epoch, "intent")
                ):
                    return {"status": "hour_consumed", "run_id": epoch, "network_attempts": 0}
                store.cutover(session, now=now)
                lock_stream(session, now=now)
                previous_sources = set(session.scalars(select(BulletinSourceStatus.source_key)))
                for excluded in (set(ENDPOINTS) | previous_sources) - set(source_keys) - {"kev"}:
                    store.public_status(
                        session, excluded, state="paused", reason="source_not_selected", now=now
                    )
                capacity(session, new_identity=False)
                # A crashed hourly intent remains consumed. Reconcile its closure
                # as interrupted before the new epoch; no earlier GET is replayed.
                previous = session.scalar(
                    select(OfficialIntakeRun)
                    .where(OfficialIntakeRun.kind == "intent")
                    .order_by(OfficialIntakeRun.created_at.desc())
                    .limit(1)
                )
                if previous and session.get(OfficialIntakeRun, (previous.epoch, "closure")) is None:
                    store.record_run(
                        session,
                        previous.epoch,
                        "closure",
                        {
                            "status": "interrupted",
                            "reconciled_at": timestamp(now),
                            "network_outcomes": "unknown_except_committed_checkpoints",
                        },
                        now=now,
                    )
                store.daily_rollup(session, now=now)
                store.record_run(
                    session,
                    epoch,
                    "intent",
                    {
                        "schema_version": 1,
                        "sources": list(source_keys),
                        "artifact_commit": artifact_commit,
                        "invocation_id": invocation_id,
                        "started_at": timestamp(now),
                    },
                    now=now,
                )
            from smithguard.bulletin_identity import seed

            with Session(connection) as session, session.begin():
                lock_stream(session, now=now)
                seed(session, now=now)
            reports = []
            remaining = MAX_CHANGES_PER_RUN
            from smithguard.bulletin_automation import FetchBudget

            public_fetch = FetchBudget()
            expanded = [key for key in source_keys if key not in ENDPOINTS]
            offset = int(now.timestamp() // 3600) % len(expanded) if expanded else 0
            ordered = (
                [key for key in source_keys if key in ENDPOINTS]
                + expanded[offset:]
                + expanded[:offset]
            )
            for source in ordered:
                if source not in ENDPOINTS:
                    from smithguard.bulletin_automation import run_source

                    try:
                        report = run_source(
                            connection,
                            source,
                            now=now,
                            epoch=epoch,
                            registry=registry,
                            process=process,
                            enabled=enabled,
                            fetch=public_fetch,
                            limit=min(50, remaining),
                        )
                    except Exception as error:
                        code = reason(error)
                        with Session(connection) as session, session.begin():
                            row = store.checkpoint(session, source, now=now)
                            state = deepcopy(row.document)
                            state["consumed_epoch"] = epoch
                            state["last_attempt"] = timestamp(now)
                            row.document, row.updated_at = state, now
                            store.public_status(
                                session, source, state="unavailable", reason=code[:40], now=now
                            )
                        report = {
                            "source": source,
                            "state": "unavailable",
                            "reason": code,
                            "network_attempted": False,
                            "accepted": {},
                        }
                    reports.append(report)
                    remaining -= sum(v for k, v in report["accepted"].items() if k != "recheck")
                    continue
                report = _source(
                    connection,
                    source,
                    now=now,
                    epoch=epoch,
                    fetch=fetch,
                    enabled=enabled,
                    registry=registry,
                    process=process,
                    limit=min(store.MAX_CHANGES_PER_SOURCE, remaining),
                )
                reports.append(report)
                remaining -= sum(v for k, v in report["accepted"].items() if k != "recheck")
            result = {
                "status": "complete" if all(r["state"] == "fresh" for r in reports) else "degraded",
                "run_id": epoch,
                "artifact_commit": artifact_commit,
                "invocation_id": invocation_id,
                "sources": reports,
                "network_attempts": sum(
                    r["network_attempted"] for r in reports if r["source"] in ENDPOINTS
                )
                + public_fetch.attempts,
            }
            with Session(connection) as session, session.begin():
                store.record_run(session, epoch, "closure", result, now=clock())
            return result
        finally:
            try:
                connection.rollback()
                connection.execute(
                    select(func.pg_advisory_unlock(func.hashtextextended(LOCK_NAME, 0)))
                )
                connection.commit()
            except Exception:
                connection.invalidate()
                raise
