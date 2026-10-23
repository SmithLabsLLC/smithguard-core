"""Serial hourly official intake with immutable receipts and no AI calls."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from smithguard.db.models import JobRecord
from smithguard.identifiers import sha256_id, timestamp
from smithguard.official_notice_fetch import fetch as fetch_feed
from smithguard.official_notice_parser import SOURCES, parse_feed
from smithguard.official_notice_store import (
    MAX_KNOWN,
    MAX_RECORDS,
    QUEUE,
    all_count,
    candidate,
    cursor,
    known_notices,
    last_successful_fetch,
    notice_changes,
    receipt,
    started_hour,
)
from smithguard.official_notice_store import (
    project_lead as project_official_lead,
)

LOCK_NAME = "smithguard:official-notice-intake:v1"


def clock():
    return datetime.now(UTC)


def cooling_down(session, source, now):
    rows = list(
        session.scalars(
            select(JobRecord)
            .where(
                JobRecord.queue == QUEUE,
                JobRecord.payload["kind"].as_string() == "fetch",
                JobRecord.payload["source"].as_string() == source,
                JobRecord.payload["network_attempted"].as_boolean().is_(True),
            )
            .order_by(JobRecord.created_at.desc(), JobRecord.job_id)
            .limit(3)
        )
    )
    return (
        len(rows) == 3
        and all(row.payload["outcome"] == "failed" for row in rows)
        and now - rows[0].created_at < timedelta(hours=6)
    )


def run(
    engine,
    *,
    fetch=fetch_feed,
    project_lead=project_official_lead,
    enabled=lambda: False,
    now=None,
    observe_clock=clock,
    artifact_commit=None,
    invocation_id=None,
):
    """A committed hourly start prevents redispatch after an interrupted transaction."""
    now = now or observe_clock()
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("official_clock_invalid")
    if artifact_commit is not None and not re.fullmatch(r"[a-f0-9]{40}", artifact_commit):
        raise ValueError("official_artifact_invalid")
    if invocation_id is not None and not re.fullmatch(r"[a-f0-9]{32}", invocation_id):
        raise ValueError("official_invocation_invalid")
    if not enabled():
        return {"status": "paused", "network_attempts": 0}
    run_id = now.strftime("%Y%m%dT%H")
    with engine.connect() as connection:
        locked = connection.scalar(
            select(func.pg_try_advisory_lock(func.hashtextextended(LOCK_NAME, 0)))
        )
        connection.commit()
        if not locked:
            return {"status": "busy", "network_attempts": 0}
        try:
            with Session(connection) as session, session.begin():
                if session.scalar(text("SELECT to_regclass('smithguard.official_intake_runs')")):
                    selected = session.scalar(
                        text(
                            "SELECT 1 FROM smithguard.official_intake_runs "
                            "WHERE epoch = 'official-intake-v2-cutover' AND kind = 'cutover'"
                        )
                    )
                    if selected:
                        return {"status": "bulletin_intake_selected", "network_attempts": 0}
                if started_hour(session, run_id):
                    return {"status": "hour_consumed", "run_id": run_id, "network_attempts": 0}
                if all_count(session) > MAX_RECORDS - 10:
                    return {"status": "storage_budget_paused", "network_attempts": 0}
                total_known = sum(len(known_notices(session, source)) for source in SOURCES)
                if total_known > MAX_KNOWN:
                    return {"status": "identity_budget_paused", "network_attempts": 0}
                receipt(
                    session,
                    identity=run_id + ":started",
                    kind="started",
                    now=now,
                    data={
                        "run_id": run_id,
                        "sources": list(SOURCES),
                        "maximum_changes": 4,
                        "artifact_commit": artifact_commit,
                        "unit_invocation_id": invocation_id,
                    },
                )
            remaining = 4
            reports = []
            network_attempts = 0
            source_order = list(SOURCES)
            if now.hour % 2:
                source_order.reverse()
            for source in source_order:
                with Session(connection) as session, session.begin():
                    known = known_notices(session, source)
                    saved_cursor = cursor(session, source)
                    prior_success = last_successful_fetch(session, source)
                    prior_success_at = prior_success.created_at if prior_success else None
                    cooldown = cooling_down(session, source, now)
                outcome = None
                if not enabled():
                    outcome = "paused"
                elif cooldown:
                    outcome = "cooldown"
                if outcome is not None:
                    report = {
                        "source": source,
                        "outcome": outcome,
                        "network_attempted": False,
                        "cursor_committed": False,
                    }
                    with Session(connection) as session, session.begin():
                        receipt(
                            session,
                            identity=run_id + ":fetch:" + source,
                            kind="fetch",
                            now=observe_clock(),
                            data={"run_id": run_id, **report},
                        )
                    reports.append(report)
                    continue
                network_attempts += 1
                diagnostics = {}
                identity_deferred = 0
                try:
                    fetched = fetch(source, **saved_cursor)
                    if fetched.status == 304:
                        changes = {
                            "changes": [],
                            "unchanged": None,
                            "overflow": False,
                            "unprocessed": 0,
                        }
                    else:
                        notices = parse_feed(
                            source,
                            fetched.body,
                            now=now,
                            known_urls=frozenset(known),
                            diagnostics=diagnostics,
                        )
                        changes = notice_changes(notices, known, remaining)
                        slots = MAX_KNOWN - total_known
                        bounded = []
                        for item in changes["changes"]:
                            if item["change"] == "new":
                                if slots == 0:
                                    identity_deferred += 1
                                    continue
                                slots -= 1
                            bounded.append(item)
                        changes["changes"] = bounded
                        changes["overflow"] = changes["overflow"] or identity_deferred > 0
                        changes["unprocessed"] += identity_deferred
                except Exception as error:
                    # Store a bounded error class/code, never response bodies or arbitrary text.
                    code = (
                        str(error)
                        if isinstance(error, ValueError)
                        and str(error).replace("_", "").isalnum()
                        and len(str(error)) < 80
                        else type(error).__name__
                    )
                    report = {
                        "source": source,
                        "outcome": "failed",
                        "network_attempted": True,
                        "cursor_committed": False,
                        "reason": code,
                    }
                    with Session(connection) as session, session.begin():
                        receipt(
                            session,
                            identity=run_id + ":fetch:" + source,
                            kind="fetch",
                            now=observe_clock(),
                            data={"run_id": run_id, **report},
                        )
                    reports.append(report)
                    continue
                accepted = {"new": 0, "corrected": 0, "withdrawn": 0}
                with Session(connection) as session, session.begin():
                    observed = observe_clock()
                    for change in changes["changes"]:
                        doc = change["document"]
                        lead = candidate(doc, observed)
                        projected = project_lead(
                            session, lead, withdrawn=doc["withdrawn"], now=observed
                        )
                        receipt(
                            session,
                            identity=run_id + ":notice:" + sha256_id(doc["url"].encode()),
                            kind="notice",
                            now=observed,
                            data={
                                "run_id": run_id,
                                **doc,
                                "semantic_sha256": change["semantic_sha256"],
                                "prior_semantic_sha256": change["prior_semantic_sha256"],
                                "change": change["change"],
                                "lead_id": lead["lead_id"],
                                "lead_projection": projected,
                            },
                        )
                        accepted[change["change"]] += 1
                    remaining -= len(changes["changes"])
                    total_known += accepted["new"]
                    report = {
                        "source": source,
                        "outcome": "identity_budget"
                        if identity_deferred
                        else "degraded"
                        if changes["overflow"]
                        else "not_modified"
                        if fetched.status == 304
                        else "success",
                        "network_attempted": True,
                        "http_status": fetched.status,
                        "feed_sha256": fetched.sha256,
                        "bytes": len(fetched.body),
                        "accepted": accepted,
                        "unchanged": changes["unchanged"],
                        "unprocessed": changes["unprocessed"],
                        "degradation_reason": "identity_budget"
                        if identity_deferred
                        else "hourly_change_budget"
                        if changes["overflow"]
                        else None,
                        "parser": diagnostics if fetched.status == 200 else None,
                        "prior_success_observed_at": timestamp(prior_success_at)
                        if prior_success_at
                        else None,
                        "observation_gap_seconds": (observed - prior_success_at).total_seconds()
                        if prior_success_at
                        else None,
                        "cursor_committed": not changes["overflow"],
                        "etag": fetched.etag,
                        "modified": fetched.modified,
                    }
                    receipt(
                        session,
                        identity=run_id + ":fetch:" + source,
                        kind="fetch",
                        now=observed,
                        data={"run_id": run_id, **report},
                    )
                reports.append(report)
            result = {
                "status": "complete"
                if all(row["outcome"] in {"success", "not_modified"} for row in reports)
                else "degraded",
                "run_id": run_id,
                "network_attempts": network_attempts,
                "sources": reports,
            }
            with Session(connection) as session, session.begin():
                receipt(
                    session,
                    identity=run_id + ":completed",
                    kind="completed",
                    now=observe_clock(),
                    data=result,
                )
            # Fresh wall clock after the result transaction commits is an upper bound.
            with Session(connection) as session, session.begin():
                receipt(
                    session,
                    identity=run_id + ":available",
                    kind="available",
                    now=observe_clock(),
                    data={"run_id": run_id, "scope": "internal_committed_result"},
                )
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
