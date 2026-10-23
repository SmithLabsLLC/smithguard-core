"""Read-only assessment of complete UTC daily maxima, never a capacity forecast."""

from __future__ import annotations

import argparse
import json
import math
from datetime import date, datetime, time, timedelta
from pathlib import Path

from smithguard.identifiers import parse_timestamp, require_aware_utc

GIB = 1024**3
REVIEW_BYTES = 9 * GIB
REVIEW_BY = date(2026, 12, 1)


def assess_growth(
    metric: dict, *, start: date, days: int, measured_at: datetime, database_bytes: int
) -> dict:
    measured_at = require_aware_utc(measured_at)
    if type(days) is not int or not 2 <= days <= 31:
        raise ValueError("daily observation span must be between 2 and 31 days")
    if type(database_bytes) is not int or not 0 < database_bytes < 2**53:
        raise ValueError("database size invalid")
    expected = [start + timedelta(days=n) for n in range(days)]
    points = {}
    counts = {}
    if metric.get("Label") != "DatabaseBytes" or not isinstance(metric.get("Datapoints"), list):
        raise ValueError("DatabaseBytes daily metric required")
    for point in metric["Datapoints"]:
        stamp = parse_timestamp(point["Timestamp"])
        value = point["Maximum"]
        count = point.get("SampleCount")
        if (
            stamp.time() != time.min
            or stamp.date() not in expected
            or stamp.date() >= measured_at.date()
            or stamp.date() in points
            or point.get("Unit") != "Bytes"
            or type(value) not in (int, float)
            or not math.isfinite(value)
            or not 0 < value < 2**53
            or int(value) != value
            or type(count) not in (int, float)
            or not math.isfinite(count)
            or not 0 < count < 2**53
            or int(count) != count
        ):
            raise ValueError("invalid, duplicate, incomplete or out-of-range UTC daily maximum")
        points[stamp.date()] = int(value)
        counts[stamp.date()] = int(count)
    missing = [day.isoformat() for day in expected if day not in points]
    deltas = [
        points[b] - points[a]
        for a, b in zip(expected, expected[1:], strict=False)
        if a in points and b in points
    ]
    due = database_bytes >= REVIEW_BYTES or measured_at.date() >= REVIEW_BY
    complete = not missing
    next_review = min(expected[-1] + timedelta(days=1), REVIEW_BY)
    crossing = None
    crossing_beyond_range = False
    if complete:
        next_review = min(measured_at.date() + timedelta(days=7), REVIEW_BY)
        fastest = max(deltas)
        if fastest > 0 and database_bytes < REVIEW_BYTES:
            try:
                crossing = measured_at + timedelta(days=(REVIEW_BYTES - database_bytes) / fastest)
            except OverflowError:
                crossing_beyond_range = True
            if crossing is not None:
                next_review = min(next_review, crossing.date() - timedelta(days=1))
    if due or next_review <= measured_at.date():
        next_review = measured_at.date()
    return {
        "schema_version": "1.0.0",
        "status": "review_due" if due else "complete" if complete else "pending",
        "measured_at": measured_at.isoformat(),
        "database_bytes": database_bytes,
        "review_bytes": REVIEW_BYTES,
        "standing_review_by": REVIEW_BY.isoformat(),
        "required_utc_dates": [day.isoformat() for day in expected],
        "missing_utc_dates": missing,
        "daily_maxima": [
            {"utc_date": day.isoformat(), "bytes": points[day], "sample_count": counts[day]}
            for day in sorted(points)
        ],
        "consecutive_daily_changes_bytes": deltas,
        "mean_daily_change_bytes": sum(deltas) / len(deltas) if complete else None,
        "maximum_daily_change_bytes": max(deltas) if complete else None,
        "conditional_9gib_crossing_at_maximum_rate": crossing.isoformat() if crossing else None,
        "conditional_crossing_beyond_datetime_range": crossing_beyond_range,
        "next_review_date": next_review.isoformat(),
        "limits": "Maxima of available samples in complete UTC windows. "
        "This is not uninterrupted coverage. "
        "Conditional arithmetic; no causal savings or workload forecast. "
        "The 9 GiB review has no dedicated alarm. Existing alarms remain 10/12 GiB. "
        "Missing future days cannot establish a complete observation.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metric_json", type=Path)
    parser.add_argument("--start", type=date.fromisoformat, required=True)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--measured-at", type=parse_timestamp, required=True)
    parser.add_argument("--database-bytes", type=int, required=True)
    args = parser.parse_args()
    metric = json.loads(args.metric_json.read_text())
    result = assess_growth(
        metric,
        start=args.start,
        days=args.days,
        measured_at=args.measured_at,
        database_bytes=args.database_bytes,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
