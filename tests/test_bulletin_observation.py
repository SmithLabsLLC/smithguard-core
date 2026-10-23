"""UTC accounting never substitutes receipt success for independent recall."""

from copy import deepcopy
from datetime import timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from smithguard.bulletin_observation import (
    WINDOW_END,
    WINDOW_START,
    observe,
    summarize_hours,
    summarize_queue,
)


def runs():
    common = {"invocation_id": "a" * 32, "artifact_commit": "b" * 40}
    return [
        {
            "epoch": "20261024T00",
            "kind": "intent",
            "document": {**common, "sources": ["php", "node-releases"]},
        },
        {
            "epoch": "20261024T00",
            "kind": "closure",
            "document": {
                **common,
                "run_id": "20261024T00",
                "status": "complete",
                "sources": [
                    {"source": "php", "state": "fresh", "accepted": {"new": 2}},
                    {
                        "source": "node-releases",
                        "state": "incomplete",
                        "detail_requests": {"failed": 1, "attempted": 3},
                        "pending": 4,
                    },
                ],
            },
        },
    ]


def test_future_and_current_hours_cannot_be_missing_or_completed():
    before = summarize_hours([], now=WINDOW_START - timedelta(hours=1))
    assert before["expected_elapsed_hours"] == 0 and not before["complete"]
    active = summarize_hours(runs(), now=WINDOW_START + timedelta(minutes=59))
    assert active["expected_elapsed_hours"] == 0
    ended = summarize_hours(runs(), now=WINDOW_START + timedelta(hours=1))
    assert ended["matched_closures"] == 1
    assert ended["independent_eligible_reference_count"] is None
    assert ended["sources"]["node-releases"]["failed_detail_checks"] == 1
    assert ended["sources"]["node-releases"]["state_incomplete"] == 1
    assert not ended["complete"]


def test_missing_closure_cannot_be_an_empty_success():
    result = summarize_hours(runs()[:1], now=WINDOW_START + timedelta(hours=1))
    assert result["matched_closures"] == 0
    assert result["missing"] == [{"epoch": "20261024T00", "intent": True, "closure": False}]


@pytest.mark.parametrize("field", ["invocation_id", "artifact_commit", "run_id"])
def test_wrong_closure_binding_remains_visible(field):
    values = runs()
    values[1]["document"][field] = "different"
    result = summarize_hours(values, now=WINDOW_START + timedelta(hours=1))
    assert result["invalid_binding"] == ["20261024T00"]
    assert result["matched_closures"] == 0


@pytest.mark.parametrize("duplicate", [True, False])
def test_omitted_or_duplicate_sources_fail_accounting(duplicate):
    values = runs()
    sources = values[1]["document"]["sources"]
    if duplicate:
        sources.append(deepcopy(sources[0]))
    else:
        sources.pop()
    result = summarize_hours(values, now=WINDOW_START + timedelta(hours=1))
    assert result["invalid_binding"] == ["20261024T00"]


def test_complete_window_accounts_for_every_hour():
    result = summarize_hours(runs(), now=WINDOW_END)
    assert result["expected_elapsed_hours"] == 168
    assert len(result["missing"]) == 167
    assert result["window_elapsed"] and not result["complete"]


def queue_row(
    *, created=WINDOW_START, state="pending", updated=WINDOW_START, source="oss-security"
):
    return {
        "source_key": source,
        "reason": "discovery_requires_review",
        "state": state,
        "created_at": created,
        "updated_at": updated,
    }


def test_queue_uses_complete_utc_days_and_separates_arrivals_from_dispositions():
    end_day_one = WINDOW_START + timedelta(days=1)
    rows = [
        queue_row(),
        queue_row(created=WINDOW_START - timedelta(days=2), state="resolved", updated=WINDOW_START),
        queue_row(created=end_day_one, updated=end_day_one, source="linux-security"),
    ]
    early = summarize_queue(rows, now=end_day_one + timedelta(hours=3))
    assert early["rate_sample_days"] == 1
    assert early["mean_daily_net"] is None
    complete = summarize_queue(rows, now=WINDOW_START + timedelta(days=2))
    assert complete["rate_sample_days"] == 2
    assert complete["complete_utc_days"][0]["sources"]["oss-security"] == {
        "arrivals": 1,
        "dispositions": 1,
        "net": 0,
    }
    assert complete["mean_daily_net"] == 0.5
    assert complete["pending"] == 2 and complete["discovery_pending"] == 2
    assert complete["conditional_days_to_discovery_limit"] == (1600 - 2) / 0.5


def test_queue_counts_shared_capacity_across_sources():
    rows = [queue_row(source="oss-security") for _ in range(400)]
    rows += [queue_row(source="linux-security") for _ in range(400)]
    result = summarize_queue(rows, now=WINDOW_START)
    assert result["early_review_due"] and result["discovery_pending"] == 800
    assert result["conditional_days_to_total_limit"] is None


def test_dates_normalize_offsets_and_refuse_partial_days():
    offset = timezone(timedelta(hours=-4))
    result = summarize_hours([], now=WINDOW_START.astimezone(offset) + timedelta(hours=1))
    assert result["expected_elapsed_hours"] == 1
    with pytest.raises(ValueError, match="complete UTC"):
        summarize_hours([], start=WINDOW_START + timedelta(minutes=1), now=WINDOW_END)


def test_observation_is_read_only_and_empty_future_is_not_proof(database):
    with Session(database.engine) as session, session.begin():
        from sqlalchemy import text

        session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
        result = observe(session, now=WINDOW_START - timedelta(hours=1))
        assert not result["hours"]["complete"]
        assert result["queue"]["rate_sample_days"] == 0
        assert result["current_recheck_cohorts"] == []


def test_reconciled_interruption_is_separate_from_binding_failure():
    values = runs()
    values[1]["document"] = {
        "status": "interrupted",
        "network_outcomes": "unknown_except_committed_checkpoints",
    }
    result = summarize_hours(values, now=WINDOW_START + timedelta(hours=1))
    assert result["interrupted"] == ["20261024T00"]
    assert result["invalid_binding"] == []
    assert result["expected_elapsed_hours"] == 1
    assert result["matched_closures"] == 0 and not result["complete"]
