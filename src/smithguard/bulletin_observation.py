"""Read-only, bounded prospective operation measurements; never a recall estimate."""

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text

from smithguard.db.bulletin_models import OfficialIntakeRun
from smithguard.identifiers import parse_timestamp, require_aware_utc, timestamp

WINDOW_START = datetime(2026, 10, 24, tzinfo=UTC)
WINDOW_END = datetime(2026, 10, 31, tzinfo=UTC)


def _time(value):
    return require_aware_utc(value) if isinstance(value, datetime) else parse_timestamp(value)


def _window(start, end, now):
    start, end, now = (_time(value) for value in (start, end, now))
    if (
        start != start.replace(hour=0, minute=0, second=0, microsecond=0)
        or end != end.replace(hour=0, minute=0, second=0, microsecond=0)
        or not timedelta(days=1) <= end - start <= timedelta(days=31)
    ):
        raise ValueError("complete UTC observation window required")
    return start, end, now


def summarize_hours(runs, *, start=WINDOW_START, end=WINDOW_END, now):
    start, end, now = _window(start, end, now)
    cutoff = min(end, now.replace(minute=0, second=0, microsecond=0))
    rows = {}
    for row in runs:
        key = (row["epoch"], row["kind"])
        if key in rows:
            raise ValueError("duplicate hourly observation")
        rows[key] = row["document"]
    missing, invalid, completed, interrupted = [], [], [], []
    sources = defaultdict(Counter)
    hour = start
    while hour < cutoff:
        epoch = hour.strftime("%Y%m%dT%H")
        intent, closure = (rows.get((epoch, kind)) for kind in ("intent", "closure"))
        if intent is None or closure is None:
            missing.append(
                {"epoch": epoch, "intent": intent is not None, "closure": closure is not None}
            )
        elif closure.get("status") == "interrupted":
            interrupted.append(epoch)
        else:
            intended = intent.get("sources", [])
            observed = closure.get("sources", [])
            names = [item.get("source") for item in observed]
            valid = (
                bool(intended)
                and len(set(intended)) == len(intended)
                and len(set(names)) == len(names)
                and set(names) == set(intended)
                and closure.get("run_id") == epoch
                and all(
                    intent.get(key) and intent.get(key) == closure.get(key)
                    for key in ("invocation_id", "artifact_commit")
                )
            )
            if not valid:
                invalid.append(epoch)
            else:
                completed.append({"epoch": epoch, "status": closure.get("status", "unknown")})
                for source in observed:
                    counts = sources[source["source"]]
                    counts["observed_hours"] += 1
                    counts["state_" + source.get("state", "unknown")] += 1
                    counts["failed_detail_checks"] += source.get("detail_requests", {}).get(
                        "failed", 0
                    )
                    counts["detail_checks"] += source.get("detail_requests", {}).get("attempted", 0)
                    counts["deferred"] += source.get("deferred", 0)
                    counts["maximum_processing_pending"] = max(
                        counts["maximum_processing_pending"], source.get("pending", 0)
                    )
                    for kind, count in source.get("accepted", {}).items():
                        counts["accepted_" + kind] += count
        hour += timedelta(hours=1)
    expected = len(missing) + len(invalid) + len(completed) + len(interrupted)
    return {
        "start_at": timestamp(start),
        "end_at_exclusive": timestamp(end),
        "observed_at": timestamp(now),
        "window_elapsed": now >= end,
        "expected_elapsed_hours": expected,
        "matched_closures": len(completed),
        "missing": missing,
        "invalid_binding": invalid,
        "interrupted": interrupted,
        "closure_status_counts": dict(Counter(item["status"] for item in completed)),
        "sources": {name: dict(counts) for name, counts in sorted(sources.items())},
        "complete": now >= end and not missing and not invalid and not interrupted,
        "independent_eligible_reference_count": None,
        "missed_eligible_reference_count": None,
        "correction_delay_seconds": None,
        "takedown_delay_seconds": None,
        "limits": "Matched receipts are operation accounting, not source correctness or recall. "
        "Future/current hours are excluded. Independent reference facts and actual first "
        "availability need separate primary-source review; unknown measurements remain null.",
    }


def summarize_queue(rows, *, start=WINDOW_START, end=WINDOW_END, now):
    start, end, now = _window(start, end, now)
    parsed = [
        {**row, "created_at": _time(row["created_at"]), "updated_at": _time(row["updated_at"])}
        for row in rows
    ]
    if any(row["state"] not in {"pending", "resolved", "dismissed"} for row in parsed):
        raise ValueError("unknown queue state")
    pending = [row for row in parsed if row["state"] == "pending"]
    discovery = [row for row in pending if row["reason"] == "discovery_requires_review"]
    by_source = {}
    for source in sorted({row["source_key"] for row in parsed}):
        selected = [row for row in pending if row["source_key"] == source]
        by_source[source] = {
            "pending": len(selected),
            "oldest_pending_at": timestamp(min(row["created_at"] for row in selected))
            if selected
            else None,
        }
    days = []
    day = start
    while day + timedelta(days=1) <= min(end, now):
        tomorrow = day + timedelta(days=1)
        arrivals, dispositions = Counter(), Counter()
        discovery_arrivals = discovery_dispositions = 0
        for row in parsed:
            arrived = day <= row["created_at"] < tomorrow
            disposed = row["state"] != "pending" and day <= row["updated_at"] < tomorrow
            arrivals[row["source_key"]] += int(arrived)
            dispositions[row["source_key"]] += int(disposed)
            if row["reason"] == "discovery_requires_review":
                discovery_arrivals += int(arrived)
                discovery_dispositions += int(disposed)
        days.append(
            {
                "utc_date": day.date().isoformat(),
                "sources": {
                    source: {
                        "arrivals": arrivals[source],
                        "dispositions": dispositions[source],
                        "net": arrivals[source] - dispositions[source],
                    }
                    for source in sorted(by_source)
                },
                "net": sum(arrivals.values()) - sum(dispositions.values()),
                "discovery_net": discovery_arrivals - discovery_dispositions,
            }
        )
        day = tomorrow
    samples = len(days)
    mean = sum(item["net"] for item in days) / samples if samples >= 2 else None
    discovery_mean = sum(item["discovery_net"] for item in days) / samples if samples >= 2 else None
    headroom = (2000 - len(pending)) / mean if mean and mean > 0 else None
    discovery_headroom = (
        (1600 - len(discovery)) / discovery_mean if discovery_mean and discovery_mean > 0 else None
    )
    return {
        "pending": len(pending),
        "discovery_pending": len(discovery),
        "sources": by_source,
        "complete_utc_days": days,
        "rate_sample_days": samples,
        "mean_daily_net": mean,
        "mean_daily_discovery_net": discovery_mean,
        "conditional_days_to_total_limit": headroom,
        "conditional_days_to_discovery_limit": discovery_headroom,
        "early_review_due": len(discovery) >= 800
        or any(value is not None and value < 14 for value in (headroom, discovery_headroom)),
        "limits": "Conditional arithmetic from at least two complete UTC days, not a forecast. "
        "Discovery shares 1600 slots globally inside the 2000 total. Resolutions are not "
        "proof that a report was false; immutable decisions retain their reasons.",
    }


def observe(session, *, now, start=WINDOW_START, end=WINDOW_END):
    """Caller supplies a repeatable-read, read-only maintenance transaction and lock."""
    start, end, now = _window(start, end, now)
    runs = session.scalars(
        select(OfficialIntakeRun).where(
            OfficialIntakeRun.epoch >= start.strftime("%Y%m%dT%H"),
            OfficialIntakeRun.epoch < end.strftime("%Y%m%dT%H"),
            OfficialIntakeRun.kind.in_(["intent", "closure"]),
        )
    ).all()
    rows = (
        session.execute(
            text(
                "SELECT source_key,state,reason,created_at,updated_at "
                "FROM smithguard.bulletin_review_queue "
                "WHERE state='pending' OR created_at>=:start OR updated_at>=:start LIMIT 100001"
            ),
            {"start": start},
        )
        .mappings()
        .all()
    )
    if len(rows) > 100000:
        raise ValueError("observation queue read capacity exceeded")
    deadlines = (
        session.execute(
            text(
                "SELECT source_key, count(*) AS active, "
                "count(*) FILTER (WHERE verification_due_at<:now) AS overdue, "
                "count(*) FILTER (WHERE verification_due_at>=:now AND "
                "verification_due_at<:now + interval '8 hours') AS due_within_eight_hours, "
                "min(verification_due_at) AS earliest_due "
                "FROM smithguard.bulletin_current WHERE NOT tombstoned "
                "AND (expires_at IS NULL OR expires_at>:now) GROUP BY source_key"
            ),
            {"now": now},
        )
        .mappings()
        .all()
    )
    events = (
        session.execute(
            text(
                "SELECT kind,count(*) AS count FROM smithguard.bulletin_events "
                "WHERE occurred_at>=:start AND occurred_at<:cutoff GROUP BY kind"
            ),
            {"start": start, "cutoff": min(end, now)},
        )
        .mappings()
        .all()
    )
    return {
        "schema_version": 1,
        "hours": summarize_hours(
            [{"epoch": row.epoch, "kind": row.kind, "document": row.document} for row in runs],
            start=start,
            end=end,
            now=now,
        ),
        "queue": summarize_queue(rows, start=start, end=end, now=now),
        "current_recheck_cohorts": [dict(row) for row in deadlines],
        "event_counts": {row["kind"]: row["count"] for row in events},
        "event_limits": "Counts cover retained events during the elapsed observation window. "
        "Source updates are separate from factual corrections. Counts do not establish "
        "correction speed or the time an upstream change first became available.",
        "recheck_limits": "Point-in-time deadline cohorts, not historical uninterrupted freshness. "
        "Compare repeated observations with actual completed detail throughput by source.",
    }
