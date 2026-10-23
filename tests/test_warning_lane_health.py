"""Warning-lane source metrics fail closed without changing the seven live alarms."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from smithguard.db.jobs import acknowledge_dead_letter, dead_letter, enqueue, lease_next
from smithguard.scheduled_discovery import append_receipt
from smithguard.spend import load_spend_policy_path
from smithguard.warning_lane_health import (
    WARNING_LANE_MAX_AGE_SECONDS,
    WARNING_LANE_METRIC_NAMESPACE,
    WARNING_LANE_METRIC_SPECS,
    collect_warning_lane_health,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "contracts/v1/xai-spend-policy.json"
ALARM_TEMPLATE = REPO_ROOT / "deploy/aws/smithguard-warning-lane-alarms.yaml"
NOW = datetime(2026, 8, 20, 16, 0, tzinfo=UTC)


def _active_policy():
    return replace(
        load_spend_policy_path(POLICY_PATH),
        policy_state="active",
        external_calls_allowed=True,
        unattended_collection_allowed=True,
        all_required_controls_pass=True,
    )


def test_inactive_policy_is_visible_without_claiming_activation(database) -> None:
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=load_spend_policy_path(POLICY_PATH),
            measured_at=NOW,
            expiry_job_success=True,
        )
    assert health.policy_active == 0
    assert health.last_discovery_success_age_seconds == WARNING_LANE_MAX_AGE_SECONDS
    assert health.healthy
    metrics = [
        {"name": spec.name, "unit": spec.unit, "value": value}
        for spec, value in zip(WARNING_LANE_METRIC_SPECS, health.metric_values, strict=True)
    ]
    assert WARNING_LANE_METRIC_NAMESPACE == "SmithLabs/SmithGuardWarningLane"
    assert len(metrics) == 10
    assert metrics[0] == {"name": "WarningLanePolicyActive", "unit": "Count", "value": 0}
    assert [metric["value"] for metric in metrics][1:] == [0] * 9


def test_active_policy_without_a_success_or_with_backlog_fails_closed(database) -> None:
    policy = _active_policy()
    with Session(database.engine) as session, session.begin():
        enqueue(
            session,
            queue="ai-warning-discovery",
            job_type="scheduled_public_discovery",
            idempotency_key="stale-health-job",
            payload={"synthetic": True},
            max_attempts=2,
            available_at=NOW - timedelta(hours=1),
            now=NOW - timedelta(hours=1),
        )
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=policy,
            measured_at=NOW,
            expiry_job_success=False,
            schedule_expected=True,
        )
    assert health.policy_active == 1
    assert health.oldest_pending_age_seconds == 3600
    assert health.last_discovery_success_age_seconds == WARNING_LANE_MAX_AGE_SECONDS
    assert health.expiry_failures == 1
    assert not health.healthy


@pytest.mark.audit_ids("WL-06")
def test_recent_discovery_receipt_makes_an_empty_active_lane_healthy(database) -> None:
    policy = _active_policy()
    with Session(database.engine) as session, session.begin():
        append_receipt(
            session,
            receipt_type="discovery_completed",
            reason_code="bounded_discovery_processed",
            run_id="gbsec:ai-warning-run:health",
            occurred_at=NOW - timedelta(minutes=30),
            public_metadata={"accepted_candidates": 0, "rejected_candidates": 0},
        )
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=policy,
            measured_at=NOW,
            expiry_job_success=True,
            schedule_expected=True,
        )
    assert health.last_discovery_success_age_seconds == 1800
    assert health.healthy


@pytest.mark.audit_ids("WL-06")
def test_one_validation_rejection_stays_below_sample_floor(database) -> None:
    policy = _active_policy()
    with Session(database.engine) as session, session.begin():
        append_receipt(
            session,
            receipt_type="discovery_completed",
            reason_code="bounded_discovery_processed",
            run_id="gbsec:ai-warning-run:health-rate",
            occurred_at=NOW - timedelta(minutes=30),
            public_metadata={"accepted_candidates": 0, "rejected_candidates": 1},
        )
        append_receipt(
            session,
            receipt_type="validation_rejection",
            reason_code="discovery_source_citation_missing",
            run_id="gbsec:ai-warning-run:health-rate",
            occurred_at=NOW - timedelta(minutes=29),
            public_metadata={"candidate_sha256": "sha256:" + "a" * 64},
        )
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=policy,
            measured_at=NOW,
            expiry_job_success=True,
            schedule_expected=True,
        )
    assert health.candidates_sampled_24h == 1
    assert health.windows_completed_24h == 1
    assert health.validation_rejection_basis_points == 0
    assert health.healthy


@pytest.mark.audit_ids("WL-06")
def test_four_whole_response_rejections_are_below_the_minimum_sample(database) -> None:
    """Item 25: four empty windows plus rejections no longer open the quality gate."""
    policy = _active_policy()
    with Session(database.engine) as session, session.begin():
        for index in range(4):
            append_receipt(
                session,
                receipt_type="validation_rejection",
                reason_code="provider_output_type_invalid",
                run_id=f"gbsec:ai-warning-run:whole-response-{index}",
                occurred_at=NOW - timedelta(minutes=30 - index),
                public_metadata={"queue": "ai-warning-discovery"},
            )
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=policy,
            measured_at=NOW,
            expiry_job_success=True,
            schedule_expected=True,
        )
    assert health.candidates_sampled_24h == 4
    assert health.windows_completed_24h == 4
    assert health.validation_rejection_basis_points == 0


def test_quality_gate_excludes_owner_selected_reasons_from_numerator(database) -> None:
    policy = _active_policy()
    run_id = "gbsec:ai-warning-run:quality-exclusions"
    with Session(database.engine) as session, session.begin():
        append_receipt(
            session,
            receipt_type="discovery_completed",
            reason_code="bounded_discovery_processed",
            run_id=run_id,
            occurred_at=NOW - timedelta(minutes=30),
            public_metadata={"accepted_candidates": 4, "rejected_candidates": 4},
        )
        for index, reason_code in enumerate(
            (
                "candidate_withdrawn_or_corrected",
                "candidate_directly_contradicted",
                "candidate_repost_or_duplicate",
                "discovery_source_citation_missing",
            )
        ):
            append_receipt(
                session,
                receipt_type="validation_rejection",
                reason_code=reason_code,
                run_id=run_id,
                occurred_at=NOW - timedelta(minutes=29 - index),
                public_metadata={"candidate_sha256": "sha256:" + f"{index + 1:064x}"},
            )
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=policy,
            measured_at=NOW,
            expiry_job_success=True,
            schedule_expected=True,
        )
    assert health.candidates_sampled_24h == 8
    assert health.windows_completed_24h == 1
    assert health.validation_rejection_basis_points == 1_250


def test_warning_volume_health_uses_utc_day_not_rolling_day(database) -> None:
    policy = _active_policy()
    with Session(database.engine) as session, session.begin():
        append_receipt(
            session,
            receipt_type="discovery_completed",
            reason_code="bounded_discovery_processed",
            run_id="gbsec:ai-warning-run:volume-health",
            occurred_at=NOW - timedelta(minutes=30),
            public_metadata={"accepted_candidates": 0, "rejected_candidates": 0},
        )
        for index in range(4):
            append_receipt(
                session,
                receipt_type="warning_created",
                reason_code="owner_policy_qualified",
                run_id=f"gbsec:ai-warning-run:yesterday-{index}",
                occurred_at=NOW - timedelta(hours=17, minutes=index),
                public_metadata={"candidate_id": f"yesterday-{index}"},
            )
            append_receipt(
                session,
                receipt_type="warning_created",
                reason_code="owner_policy_qualified",
                run_id=f"gbsec:ai-warning-run:today-{index}",
                occurred_at=NOW - timedelta(hours=3, minutes=index),
                public_metadata={"candidate_id": f"today-{index}"},
            )
        append_receipt(
            session,
            receipt_type="policy_denial",
            reason_code="qualification_run_limit",
            run_id="gbsec:ai-warning-run:designed-limit",
            occurred_at=NOW - timedelta(minutes=10),
            public_metadata={"candidate_id": "bounded-extra-candidate"},
        )
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=policy,
            measured_at=NOW,
            expiry_job_success=True,
            schedule_expected=True,
        )
    assert health.technical_envelope_breaches_24h == 0


def test_exact_usage_overage_is_a_provider_and_technical_health_failure(database) -> None:
    policy = _active_policy()
    with Session(database.engine) as session, session.begin():
        append_receipt(
            session,
            receipt_type="discovery_completed",
            reason_code="bounded_discovery_processed",
            run_id="gbsec:ai-warning-run:technical-health",
            occurred_at=NOW - timedelta(minutes=30),
            public_metadata={"accepted_candidates": 0, "rejected_candidates": 0},
        )
        append_receipt(
            session,
            receipt_type="provider_failure",
            reason_code="provider_tool_usage_exceeded",
            run_id="gbsec:ai-warning-run:technical-health",
            occurred_at=NOW - timedelta(minutes=20),
            public_metadata={
                "queue": "ai-warning-discovery",
                "error_class": "ScheduledProviderError",
            },
        )
        append_receipt(
            session,
            receipt_type="policy_denial",
            reason_code="provider_tool_usage_exceeded",
            run_id="gbsec:ai-warning-run:technical-health",
            occurred_at=NOW - timedelta(minutes=19),
            public_metadata={"queue": "ai-warning-discovery"},
        )
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=policy,
            measured_at=NOW,
            expiry_job_success=True,
            schedule_expected=True,
        )
    assert health.provider_failures_24h == 1
    assert health.technical_envelope_breaches_24h == 1
    assert not health.healthy


@pytest.mark.audit_ids("WL-09")
def test_acknowledged_and_over_24_hour_dead_letters_do_not_breach_health(database) -> None:
    policy = _active_policy()
    with Session(database.engine) as session, session.begin():
        append_receipt(
            session,
            receipt_type="discovery_completed",
            reason_code="bounded_discovery_processed",
            run_id="gbsec:ai-warning-run:dead-letter-health",
            occurred_at=NOW - timedelta(minutes=30),
            public_metadata={"accepted_candidates": 0, "rejected_candidates": 0},
        )
        old, _created = enqueue(
            session,
            queue="ai-warning-discovery",
            job_type="scheduled_public_discovery",
            idempotency_key="old-dead-letter",
            payload={"run_id": "gbsec:ai-warning-run:old-dead-letter"},
            max_attempts=1,
            available_at=NOW - timedelta(hours=25),
            now=NOW - timedelta(hours=25),
        )
        acknowledged, _created = enqueue(
            session,
            queue="ai-warning-qualification",
            job_type="candidate_qualification",
            idempotency_key="acknowledged-dead-letter",
            payload={"run_id": "gbsec:ai-warning-run:acknowledged-dead-letter"},
            max_attempts=1,
            available_at=NOW - timedelta(hours=1),
            now=NOW - timedelta(hours=1),
        )
        old_id = old.job_id
        acknowledged_id = acknowledged.job_id
    with Session(database.engine) as session, session.begin():
        old_lease = lease_next(
            session,
            queue="ai-warning-discovery",
            worker_id="old-health-worker",
            lease_for=timedelta(minutes=1),
            now=NOW - timedelta(hours=25),
        )
        assert old_lease is not None
        dead_letter(
            session,
            job_id=old_id,
            lease_token=old_lease.lease_token,
            error_code="old_failure",
            now=NOW - timedelta(hours=25) + timedelta(seconds=1),
        )
        acknowledged_lease = lease_next(
            session,
            queue="ai-warning-qualification",
            worker_id="acknowledged-health-worker",
            lease_for=timedelta(minutes=1),
            now=NOW - timedelta(hours=1),
        )
        assert acknowledged_lease is not None
        dead_letter(
            session,
            job_id=acknowledged_id,
            lease_token=acknowledged_lease.lease_token,
            error_code="reviewed_failure",
            now=NOW - timedelta(hours=1) + timedelta(seconds=1),
        )
        acknowledge_dead_letter(
            session,
            job_id=acknowledged_id,
            reason="operator_reviewed",
            now=NOW - timedelta(minutes=59),
        )
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=policy,
            measured_at=NOW,
            expiry_job_success=True,
            schedule_expected=True,
        )
    assert health.dead_letters_24h == 0
    assert health.healthy


@pytest.mark.audit_ids("WL-01")
def test_model_reason_code_is_not_a_technical_breach(database) -> None:
    policy = _active_policy()
    with Session(database.engine) as session, session.begin():
        append_receipt(
            session,
            receipt_type="discovery_completed",
            reason_code="bounded_discovery_processed",
            run_id="gbsec:ai-warning-run:model-reason-health",
            occurred_at=NOW - timedelta(minutes=30),
            public_metadata={"accepted_candidates": 1, "rejected_candidates": 0},
        )
        append_receipt(
            session,
            receipt_type="qualification_rejection",
            reason_code="model_qualification_rejected",
            run_id="gbsec:ai-warning-run:model-reason-health",
            occurred_at=NOW - timedelta(minutes=20),
            public_metadata={"model_reason_code": "provider_tool_usage_exceeded"},
        )
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=policy,
            measured_at=NOW,
            expiry_job_success=True,
            schedule_expected=True,
        )
    assert health.technical_envelope_breaches_24h == 0
    assert health.healthy


@pytest.mark.audit_ids("WL-10")
def test_source_alarm_template_is_separate_and_fail_closed() -> None:
    body = ALARM_TEMPLATE.read_text(encoding="ascii")
    assert body.count("Type: AWS::CloudWatch::Alarm") == 9
    assert body.count("TreatMissingData: breaching") == 8
    assert body.count("TreatMissingData: notBreaching") == 1
    assert body.count("ActionsEnabled: !If [AlarmActionsEnabled, true, false]") == 9
    assert "AlarmActionsState:" in body
    assert "Default: disabled" in body
    assert "SmithLabs/SmithGuardWarningLane" in body
    assert "WarningLaneExactCostIntegrity" not in body
    assert "WarningLaneTechnicalEnvelopeBreaches24h" in body
    assert "WarningLaneSpendRemainingMicroUSD" not in body
    assert "SmithLabs/SmithGuard\n" not in body


def _dispatch_and_fail(session, *, runs: int, failures: set[int]) -> None:
    for index in range(runs):
        run_id = f"gbsec:ai-warning-run:budget-{index:03d}"
        at = NOW - timedelta(hours=20) + timedelta(minutes=30 * index)
        append_receipt(
            session,
            receipt_type="provider_request_started",
            reason_code="discovery_dispatch",
            run_id=run_id,
            occurred_at=at,
            public_metadata={"queue": "ai-warning-discovery", "attempt": 1},
        )
        if index in failures:
            append_receipt(
                session,
                receipt_type="provider_failure",
                reason_code="provider_http_failure",
                run_id=run_id,
                occurred_at=at + timedelta(seconds=30),
                public_metadata={"queue": "ai-warning-discovery", "error_class": "Synthetic"},
            )


@pytest.mark.parametrize(
    ("failures", "over_budget"),
    [
        (set(), 0),
        ({3}, 0),  # one isolated failure in 40 attempts is within 5 percent
        ({3, 20}, 0),  # two isolated failures: budget is max(1, 5% of 40) = 2
        ({3, 20, 30}, 1),  # three exceed it
        ({38, 39}, 1),  # the two most recent runs both failed
    ],
)
def test_provider_failures_use_an_error_budget(database, failures, over_budget) -> None:
    policy = _active_policy()
    with Session(database.engine) as session, session.begin():
        _dispatch_and_fail(session, runs=40, failures=failures)
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=policy,
            measured_at=NOW,
            expiry_job_success=True,
            schedule_expected=True,
        )
    assert health.provider_attempts_24h == 40
    assert health.provider_failures_24h == len(failures)
    assert health.provider_failures_over_budget == over_budget


def test_paused_lane_retains_raw_failures_and_only_suppresses_schedule_ages(database):
    with Session(database.engine) as session, session.begin():
        _dispatch_and_fail(session, runs=4, failures={2, 3})
        enqueue(
            session,
            queue="ai-warning-discovery",
            job_type="scheduled_public_discovery",
            idempotency_key="paused-backlog",
            payload={"synthetic": True},
            max_attempts=2,
            available_at=NOW - timedelta(hours=1),
            now=NOW - timedelta(hours=1),
        )
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=_active_policy(),
            measured_at=NOW,
            expiry_job_success=True,
            schedule_expected=False,
            dispatch_enabled=False,
            discovery_timer_active=False,
        )
    assert health.control_healthy and not health.healthy
    assert health.provider_failures_24h == 2
    assert health.provider_failures_over_budget > 0
    assert health.oldest_pending_age_seconds == 3600
    assert health.last_discovery_success_age_seconds == WARNING_LANE_MAX_AGE_SECONDS
    metrics = dict(
        zip((spec.name for spec in WARNING_LANE_METRIC_SPECS), health.metric_values, strict=True)
    )
    assert metrics["WarningLaneProviderFailures24h"] == health.provider_failures_over_budget
    assert metrics["WarningLaneOldestPendingAgeSeconds"] == 0
    assert metrics["WarningLaneLastDiscoverySuccessAgeSeconds"] == 0
    unexpected = replace(health, discovery_service_active=True)
    assert not unexpected.control_healthy
    assert unexpected.metric_values[2] == 3600
    assert unexpected.metric_values[4] == WARNING_LANE_MAX_AGE_SECONDS


@pytest.mark.parametrize(
    "field,value",
    [
        ("control_valid", False),
        ("discovery_timer_active", True),
        ("discovery_timer_active", None),
        ("discovery_service_active", True),
        ("recheck_service_active", None),
        ("dispatch_enabled", True),
    ],
)
def test_pause_requires_authority_and_observed_stopped_units(database, field, value):
    with Session(database.engine) as session:
        health = collect_warning_lane_health(
            session,
            policy=_active_policy(),
            measured_at=NOW,
            expiry_job_success=True,
            schedule_expected=False,
        )
    changed = replace(health, **{field: value})
    assert not changed.control_healthy
    assert not changed.healthy
    assert changed.metric_values[4] == WARNING_LANE_MAX_AGE_SECONDS


def test_paused_expiry_measures_latest_v4_state_with_cleanup_grace(database):
    from smithguard.emerging_leads import record_lead
    from tests.test_emerging_leads import candidate

    with Session(database.engine) as session, session.begin():
        row, _ = record_lead(
            session,
            candidate(),
            state="unverified",
            reason="attributable_security_report",
            now=NOW,
        )
        expiry = row.expires_at
    with Session(database.engine) as session:
        grace = collect_warning_lane_health(
            session,
            policy=_active_policy(),
            measured_at=expiry + timedelta(minutes=5),
            expiry_job_success=True,
            schedule_expected=False,
        )
        overdue = collect_warning_lane_health(
            session,
            policy=_active_policy(),
            measured_at=expiry + timedelta(minutes=11),
            expiry_job_success=True,
            schedule_expected=False,
        )
    assert grace.overdue_leads == 1 and grace.overdue_leads_beyond_grace == 0
    assert grace.expiry_failures == 0
    assert overdue.overdue_leads == overdue.overdue_leads_beyond_grace == 1
    assert overdue.expiry_failures == 1 and not overdue.healthy
    assert overdue.metric_values[-1] == 1
