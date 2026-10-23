"""Intake liveness is independent of publication backlog and actual timer enablement."""

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from smithguard.db.bulletin_models import OfficialIntakeRun
from smithguard.identifiers import parse_timestamp

# Next hour's :17 timer, up to 40s jitter and 15m runtime, plus a small margin.
EPOCH_DEADLINE = timedelta(minutes=94)
INITIALIZATION_GRACE = timedelta(seconds=960)
DRAIN_GRACE = timedelta(seconds=240)  # Includes bounded timer-stop/readback overhead.


def _recent(control, field, now, bound):
    value = control.get(field)
    return bool(value and timedelta(0) <= now - parse_timestamp(value) < bound)


def _awaiting_first_closure(control, now):
    try:
        enabled_at = parse_timestamp(control.get("enabled_at"))
    except ValueError:
        return False
    hour = enabled_at.replace(minute=0, second=0, microsecond=0)
    return enabled_at <= now < hour + EPOCH_DEADLINE


def health(
    session,
    *,
    now,
    control,
    expected_sources,
    timer_enabled,
    timer_active,
    service_active,
    service_result,
):
    if control is None:
        return "control_unavailable"
    if not control["enabled"]:
        if timer_enabled is False and timer_active is False and service_active is False:
            return "contained"
        if (
            _recent(control, "draining_at", now, DRAIN_GRACE)
            and timer_enabled is not None
            and timer_active is not None
            and service_active is not None
            and service_result == "success"
        ):
            return "draining"
        return "containment_unproved"
    if set(control.get("source_keys", ())) != set(expected_sources):
        return "source_configuration_mismatch"
    if service_active is None:
        return "service_state_unknown"
    if service_result != "success":
        return "service_failed"
    if timer_enabled is not True or timer_active is not True:
        if (
            timer_enabled is not None
            and timer_active is not None
            and _recent(control, "enabled_at", now, INITIALIZATION_GRACE)
        ):
            return "initializing"
        return "timer_stopped"
    closure = session.scalar(
        select(OfficialIntakeRun)
        .where(
            OfficialIntakeRun.kind == "closure",
            OfficialIntakeRun.created_at <= now,
        )
        .order_by(OfficialIntakeRun.created_at.desc(), OfficialIntakeRun.epoch.desc())
        .limit(1)
    )
    epoch = None
    if closure:
        try:
            if not re.fullmatch(r"[0-9]{8}T[0-9]{2}", closure.epoch):
                return "closure_binding_invalid"
            epoch = datetime.strptime(closure.epoch, "%Y%m%dT%H").replace(tzinfo=UTC)
        except (TypeError, ValueError):
            return "closure_binding_invalid"
        if not epoch <= closure.created_at <= now:
            return "closure_binding_invalid"
    intent = session.get(OfficialIntakeRun, (closure.epoch, "intent")) if closure else None
    if intent is not None and (
        intent.created_at.astimezone(UTC).replace(minute=0, second=0, microsecond=0) != epoch
        or not intent.created_at <= closure.created_at
    ):
        return "closure_binding_invalid"
    current_release = control["artifact_commit"]
    if intent is None or intent.document.get("artifact_commit") != current_release:
        # Initialization may reuse an already consumed hour without a fetch. It
        # may wait for next hour's :17 run, including jitter and bounded runtime.
        if _awaiting_first_closure(control, now):
            return "awaiting_first_closure"
        return "closure_missing"
    started, closed = intent.document, closure.document
    names = [row.get("source") for row in closed.get("sources", [])]
    if (
        closed.get("run_id") != closure.epoch
        or closed.get("artifact_commit") != current_release
        or not started.get("invocation_id")
        or closed.get("invocation_id") != started["invocation_id"]
        or len(started.get("sources", ())) != len(expected_sources)
        or set(started.get("sources", ())) != set(expected_sources)
        or len(names) != len(expected_sources)
        or set(names) != set(expected_sources)
        or closed.get("status") not in {"complete", "degraded"}
    ):
        return "closure_binding_invalid"
    if now >= epoch + EPOCH_DEADLINE:
        return "closure_stale"
    return "fresh"
