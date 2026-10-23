"""Read-only compact intake status and strict deployment result verification."""

import re
from datetime import datetime, timedelta

from sqlalchemy import select

from smithguard import bulletin_store
from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_sources import CATALOG_SOURCES, NETWORK_SOURCES
from smithguard.db.bulletin_models import BulletinSourceStatus, BulletinStream, OfficialIntakeRun
from smithguard.official_notice_fetch import ENDPOINTS, selected_sources

STATUS_SQL = """
WITH latest AS (
 SELECT epoch FROM smithguard.official_intake_runs WHERE kind = 'intent'
 ORDER BY created_at DESC, epoch DESC LIMIT 1
)
SELECT coalesce(json_agg(json_build_object('kind', kind, 'epoch', epoch,
 'created_at', created_at, 'document', document) ORDER BY kind), '[]'::json)::text
FROM smithguard.official_intake_runs WHERE epoch = (SELECT epoch FROM latest)
 AND kind IN ('intent', 'closure');
"""


def status(session, *, now):
    intent = session.scalar(
        select(OfficialIntakeRun)
        .where(OfficialIntakeRun.kind == "intent")
        .order_by(OfficialIntakeRun.created_at.desc(), OfficialIntakeRun.epoch.desc())
        .limit(1)
    )
    closure = session.get(OfficialIntakeRun, (intent.epoch, "closure")) if intent else None
    result = bulletin_store.source_status(session, now=now)
    result.update(
        {
            "intake_version": 2,
            "status": closure.document["status"]
            if closure
            else "incomplete"
            if intent
            else "never_run",
            "run_id": intent.epoch if intent else None,
            "last_closed_at": bulletin_store.timestamp(closure.created_at) if closure else None,
            "retrieval_recall": None,
        }
    )
    return result


def qualified_input(source):
    key = source.get("source")
    if key in ENDPOINTS:
        return source.get("http_status") in (200, 304) and source.get("network_attempted") is True
    if source.get("input_qualified") is not True:
        return False
    if key in CATALOG_SOURCES:
        evidence = source.get("observation", {})
        return bool(evidence.get("collector_observed_at") and evidence.get("collector_due_at"))
    spec = NETWORK_SOURCES.get(key)
    if spec is None or source.get("network_attempted") is not True:
        return False
    if spec.discovery_only:
        receipts = source.get("observations", [])
        return bool(receipts) and all(r.get("status") in {200, 404} for r in receipts)
    return source.get("http_status") == 200 and bool(source.get("observation", {}).get("feed_hash"))


def verified_result(
    outcome, rows, *, now, invocation_id, artifact_commit, source_keys=tuple(ENDPOINTS)
):
    try:
        source_keys = selected_sources(source_keys)
        if not isinstance(rows, list) or len(rows) != 2:
            raise ValueError()
        by_kind = {row["kind"]: row for row in rows}
        origin, closure = by_kind["intent"], by_kind["closure"]
        intent, closed = origin["document"], closure["document"]
        started, ended = [
            datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))
            for row in (origin, closure)
        ]
        reused = outcome.get("status") == "hour_consumed"
        if (
            not started.tzinfo
            or not ended.tzinfo
            or not started <= ended <= now
            or now - started > timedelta(hours=2)
            or origin["epoch"] != closure["epoch"]
            or outcome.get("run_id") != origin["epoch"]
            or closed.get("run_id") != origin["epoch"]
            or intent.get("schema_version") != 1
            or set(intent["sources"]) != set(source_keys)
            or not re.fullmatch("[a-f0-9]{40}", intent["artifact_commit"])
            or not re.fullmatch("[a-f0-9]{32}", intent["invocation_id"])
        ):
            raise ValueError()
        if reused:
            if outcome.get("network_attempts") != 0 or intent["invocation_id"] == invocation_id:
                raise ValueError()
        elif (
            outcome.get("status") != closed.get("status")
            or intent["invocation_id"] != invocation_id
            or intent["artifact_commit"] != artifact_commit
        ):
            raise ValueError()
        sources = closed["sources"]
        if (
            len(sources) != len(source_keys)
            or {s["source"] for s in sources} != set(source_keys)
            or any(
                not qualified_input(s)
                or not (
                    s["state"] == "fresh"
                    or s["state"] == "incomplete"
                    and s.get("reason") in {"catching_up", "publication_pending"}
                )
                for s in sources
            )
        ):
            raise ValueError()
        expected = "complete" if all(s["state"] == "fresh" for s in sources) else "degraded"
        if closed["status"] != expected:
            raise ValueError()
        return {
            "intake_version": 2,
            "run_id": origin["epoch"],
            "status": expected,
            "source_artifact_commit": intent["artifact_commit"],
            "source_unit_invocation_id": intent["invocation_id"],
            "reused": reused,
            "worker_outcome": {
                key: outcome.get(key) for key in ("status", "run_id", "network_attempts")
            },
            "sources": sources,
            "internal_available_upper_bound": bulletin_store.timestamp(ended),
        }
    except (ValueError, TypeError, KeyError) as error:
        raise BulletinError("official_compact_intake_not_verified") from error


def health(session, *, now):
    """Only content-free status tables are visible to the health identity."""
    stream = session.get(BulletinStream, "v1")
    if stream is None:
        return "paused"
    if stream.mode == "paused":
        return "publication_paused" if stream.grant_hash else "paused"
    if (
        stream.status_checked_at is None
        or not now - timedelta(minutes=5) <= stream.status_checked_at <= now
    ):
        return "unavailable"
    rows = session.scalars(select(BulletinSourceStatus).limit(65)).all()
    if len(rows) > 64:
        return "unavailable"
    for row in rows:
        if row.state == "paused" and row.reason == "source_not_selected":
            continue
        if (
            row.state != "fresh"
            or row.last_success_at is None
            or not now - timedelta(minutes=75) <= row.last_success_at <= now
            or row.upstream_due_at is not None
            and row.upstream_due_at <= now
        ):
            return "incomplete"
    return "fresh"
