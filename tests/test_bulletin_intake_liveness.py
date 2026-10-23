"""A stopped collector pages; working backlogs and intentional containment do not."""

from dataclasses import replace
from datetime import timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from smithguard.bulletin_intake_health import health
from smithguard.db.bulletin_models import OfficialIntakeRun
from smithguard.identifiers import timestamp
from smithguard.operational_health import build_metric_receipt, evaluate_operational_health
from tests.test_bulletin_intake import NOW
from tests.test_operational_health import _healthy_inputs


def state(**changes):
    return {
        "now": NOW,
        "control": {
            "enabled": True,
            "artifact_commit": "a" * 40,
            "source_keys": ["php"],
            "enabled_at": timestamp(NOW - timedelta(hours=3)),
        },
        "expected_sources": ("php",),
        "timer_enabled": True,
        "timer_active": True,
        "service_active": False,
        "service_result": "success",
        **changes,
    }


def seed(
    session,
    *,
    age=timedelta(minutes=30),
    status="degraded",
    commit="a" * 40,
    sources=("php",),
    closure=True,
    started_at=None,
    epoch=None,
):
    started_at = started_at or NOW - age - timedelta(seconds=10)
    epoch = epoch or started_at.strftime("%Y%m%dT%H")
    document = {"artifact_commit": commit, "invocation_id": "b" * 32}
    session.add(
        OfficialIntakeRun(
            epoch=epoch,
            kind="intent",
            created_at=started_at,
            document={**document, "schema_version": 1, "sources": list(sources)},
        )
    )
    if closure:
        session.add(
            OfficialIntakeRun(
                epoch=epoch,
                kind="closure",
                created_at=started_at + timedelta(seconds=10),
                document={
                    **document,
                    "run_id": epoch,
                    "status": status,
                    "sources": [
                        {"source": source, "state": "incomplete", "reason": "catching_up"}
                        for source in sources
                    ],
                },
            )
        )
    session.flush()
    return epoch


@pytest.mark.parametrize(
    "change,expected",
    [
        ({}, "fresh"),
        ({"timer_active": False}, "timer_stopped"),
        ({"timer_enabled": False}, "timer_stopped"),
        ({"timer_enabled": None}, "timer_stopped"),
        ({"service_result": "timeout"}, "service_failed"),
        ({"service_active": None}, "service_state_unknown"),
        ({"control": None}, "control_unavailable"),
        ({"service_active": True}, "fresh"),
        ({"expected_sources": ("php", "mozilla")}, "source_configuration_mismatch"),
    ],
)
def test_liveness_is_independent_of_backlog_and_actual_enablement(database, change, expected):
    with Session(database.engine) as session, session.begin():
        seed(session)
        assert health(session, **state(**change)) == expected


@pytest.mark.parametrize(
    "age,closure,status,commit,expected",
    [
        (timedelta(minutes=76), True, "complete", "a" * 40, "closure_stale"),
        (timedelta(minutes=75, seconds=59), True, "complete", "a" * 40, "closure_stale"),
        (timedelta(minutes=30), False, "complete", "a" * 40, "closure_missing"),
        (timedelta(minutes=30), True, "interrupted", "a" * 40, "closure_binding_invalid"),
        (timedelta(minutes=30), True, "complete", "c" * 40, "closure_missing"),
    ],
)
def test_closed_run_age_release_and_interruption(database, age, closure, status, commit, expected):
    with Session(database.engine) as session, session.begin():
        seed(session, age=age, closure=closure, status=status, commit=commit)
        assert health(session, **state()) == expected


def test_containment_and_first_release_closure_have_distinct_bounded_states(database):
    with Session(database.engine) as session:
        args = state(timer_active=False, timer_enabled=False)
        args["control"]["enabled"] = False
        assert health(session, **args) == "contained"
        assert health(session, **{**args, "service_active": None}) == "containment_unproved"
        args = state()
        args["control"]["enabled_at"] = timestamp(NOW)
        assert health(session, **args) == "awaiting_first_closure"
        assert health(session, **{**args, "now": NOW + timedelta(minutes=94)}) == "closure_missing"


@pytest.mark.parametrize(
    "start_offset,check_offset,expected",
    [
        (timedelta(seconds=30), timedelta(hours=1, minutes=20), "fresh"),
        (timedelta(minutes=17), timedelta(hours=1, minutes=33, seconds=59), "fresh"),
        (timedelta(minutes=17), timedelta(hours=1, minutes=34), "closure_stale"),
    ],
)
def test_epoch_deadline_allows_early_initialization_and_next_hour_runtime(
    database, start_offset, check_offset, expected
):
    with Session(database.engine) as session, session.begin():
        seed(session, started_at=NOW + start_offset)
        assert health(session, **state(now=NOW + check_offset)) == expected


@pytest.mark.parametrize("prior_release", [False, True])
def test_first_closure_grace_covers_consumed_hour_but_ends_at_epoch_deadline(
    database, prior_release
):
    with Session(database.engine) as session, session.begin():
        if prior_release:
            seed(session, started_at=NOW + timedelta(seconds=10), commit="c" * 40)
        args = state(now=NOW + timedelta(hours=1, minutes=20))
        args["control"]["enabled_at"] = timestamp(NOW + timedelta(seconds=30))
        assert health(session, **args) == "awaiting_first_closure"
        args["now"] = NOW + timedelta(hours=1, minutes=34)
        assert health(session, **args) == "closure_missing"


@pytest.mark.parametrize(
    "epoch",
    [
        "20261021T5",
        "20261021T050",
        "20261021t05",
        "20260230T05",
        "20261021T03",
        "20261021T06",
    ],
)
def test_malformed_future_or_mismatched_closure_epoch_fails_closed(database, epoch):
    with Session(database.engine) as session, session.begin():
        seed(session, epoch=epoch)
        args = state()
        args["control"]["enabled_at"] = timestamp(NOW)
        assert health(session, **args) == "closure_binding_invalid"


def test_epoch_binding_uses_the_intent_utc_hour(database):
    with Session(database.engine) as session, session.begin():
        seed(
            session,
            epoch=NOW.strftime("%Y%m%dT%H"),
            started_at=(NOW + timedelta(minutes=17)).astimezone(timezone(timedelta(hours=-4))),
        )
        assert health(session, **state(now=NOW + timedelta(hours=1, minutes=20))) == "fresh"


@pytest.mark.parametrize("enabled_at", ["not-a-date", "2026-10-21T05:00:01Z"])
def test_invalid_or_future_first_closure_authority_does_not_start_grace(database, enabled_at):
    with Session(database.engine) as session:
        args = state()
        args["control"]["enabled_at"] = enabled_at
        assert health(session, **args) == "closure_missing"


@pytest.mark.parametrize(
    "status,expected",
    [
        ("timer_stopped", "critical"),
        ("closure_missing", "critical"),
        ("closure_stale", "critical"),
        ("closure_binding_invalid", "critical"),
        ("service_failed", "critical"),
        ("contained", "healthy"),
        ("fresh", "healthy"),
        ("awaiting_first_closure", "degraded"),
        ("initializing", "degraded"),
        ("draining", "degraded"),
        ("service_state_unknown", "critical"),
    ],
)
def test_liveness_drives_existing_critical_alarm(status, expected):
    inputs = replace(_healthy_inputs(), official_intake_status=status)
    report = evaluate_operational_health(inputs)
    check = next(c for c in report.checks if c.code == "official_intake_liveness")
    assert check.status == expected
    receipt = build_metric_receipt(inputs, report)
    metric = next(m for m in receipt.metrics if m.name == "HealthCritical")
    assert metric.value == int(expected == "critical")


@pytest.mark.parametrize(
    "seconds,expected", [(0, "initializing"), (959, "initializing"), (960, "timer_stopped")]
)
def test_initialization_grace_has_strict_bound(database, seconds, expected):
    with Session(database.engine) as session:
        args = state(timer_enabled=False, timer_active=False, service_active=True)
        args["control"]["enabled_at"] = timestamp(NOW - timedelta(seconds=seconds))
        assert health(session, **args) == expected
        assert health(session, **{**args, "timer_active": None}) == "timer_stopped"
        assert health(session, **{**args, "service_result": "timeout"}) == "service_failed"


@pytest.mark.parametrize(
    "seconds,expected", [(0, "draining"), (239, "draining"), (240, "containment_unproved")]
)
def test_containment_drain_has_strict_bound(database, seconds, expected):
    with Session(database.engine) as session:
        args = state(timer_enabled=False, timer_active=False, service_active=True)
        args["control"] = {
            "enabled": False,
            "draining_at": timestamp(NOW - timedelta(seconds=seconds)),
        }
        assert health(session, **args) == expected
        assert health(session, **{**args, "service_active": None}) == "containment_unproved"
        assert health(session, **{**args, "service_result": "timeout"}) == "containment_unproved"


def test_closure_committed_after_measurement_does_not_invalidate_snapshot(database):
    with Session(database.engine) as session, session.begin():
        earlier = seed(session, age=timedelta(minutes=30))
        later = seed(session, started_at=NOW + timedelta(seconds=1))
        assert earlier != later
        assert health(session, **state()) == "fresh"
        # It becomes eligible in a later measurement, with the same strict binding.
        assert health(session, **state(now=NOW + timedelta(seconds=12))) == "fresh"


def test_future_closure_cannot_hide_a_stale_previous_epoch(database):
    with Session(database.engine) as session, session.begin():
        seed(session, age=timedelta(hours=2))
        seed(session, started_at=NOW + timedelta(seconds=1))
        assert health(session, **state()) == "closure_stale"
