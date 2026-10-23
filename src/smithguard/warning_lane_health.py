"""Fail-closed health metrics for the scheduled AI warning lane."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.db.models import JobRecord, PreliminaryWarningRecheckRecord
from smithguard.emerging_leads import overdue_lead_count
from smithguard.spend import SpendPolicy
from smithguard.warning_lane_budget import (
    DISCOVERY_QUEUE,
    QUALIFICATION_QUEUE,
    calculate_dispatch_budget,
)
from smithguard.warning_lane_receipts import RECEIPT_QUEUE

WARNING_LANE_METRIC_NAMESPACE = "SmithLabs/SmithGuardWarningLane"
WARNING_LANE_METRIC_SCHEMA_VERSION = "3.0.0"
WARNING_LANE_MAX_AGE_SECONDS = 10**9
# v4 rejections that are the decoder doing its job (junk, placeholders, old news),
# excluded from the validation-rejection quality metric.
CORRECT_REJECTION_CODES = frozenset(
    {"lead_placeholder", "lead_stale_report", "lead_no_public_source"}
)


DISCOVERY_STALE_SECONDS = 45 * 60
# The independent expiry timer runs every five minutes. Two slots allow ordinary
# scheduling jitter; raw overdue counts remain visible throughout that grace.
LEAD_EXPIRY_GRACE = timedelta(minutes=10)


@dataclass(frozen=True, slots=True)
class MetricSpec:
    """One published metric: its identity, bounds, source attribute and alarm."""

    name: str
    unit: str
    maximum: int
    fail_closed: int
    contained: int | None
    attribute: str
    alarm: str | None
    # True for the metrics that publish ``contained`` while their schedule is disabled.
    openssf: bool = False


WARNING_LANE_METRIC_SPECS: tuple[MetricSpec, ...] = (
    MetricSpec("WarningLanePolicyActive", "Count", 1, 0, 0, "policy_active", "policy-inactive"),
    MetricSpec(
        "WarningLaneProviderFailures24h",
        "Count",
        WARNING_LANE_MAX_AGE_SECONDS,
        1,
        0,
        "provider_failures_over_budget",
        "provider-failure",
    ),
    MetricSpec(
        "WarningLaneOldestPendingAgeSeconds",
        "Count",
        WARNING_LANE_MAX_AGE_SECONDS,
        901,
        0,
        "oldest_pending_age_seconds",
        "pending-stale",
    ),
    MetricSpec(
        "WarningLaneDeadLetters24h",
        "Count",
        WARNING_LANE_MAX_AGE_SECONDS,
        1,
        0,
        "dead_letters_over_budget",
        "dead-letter",
    ),
    MetricSpec(
        "WarningLaneLastDiscoverySuccessAgeSeconds",
        "Count",
        WARNING_LANE_MAX_AGE_SECONDS,
        2701,
        0,
        "last_discovery_success_age_seconds",
        "discovery-stale",
    ),
    MetricSpec(
        "WarningLaneCandidatesSampled24h",
        "Count",
        WARNING_LANE_MAX_AGE_SECONDS,
        0,
        0,
        "candidates_sampled_24h",
        None,
    ),
    MetricSpec(
        "WarningLaneValidationRejectionBasisPoints",
        "Count",
        10_000,
        7501,
        0,
        "validation_rejection_basis_points",
        "validation-rejection-high",
    ),
    MetricSpec(
        "WarningLaneTechnicalEnvelopeBreaches24h",
        "Count",
        WARNING_LANE_MAX_AGE_SECONDS,
        1,
        0,
        "technical_envelope_breaches_24h",
        "technical-envelope-breached",
    ),
    MetricSpec(
        "WarningLaneRecheckFailures24h",
        "Count",
        WARNING_LANE_MAX_AGE_SECONDS,
        1,
        0,
        "recheck_failures_24h",
        "recheck-failure",
    ),
    MetricSpec("WarningLaneExpiryFailures", "Count", 1, 1, 0, "expiry_failures", "expiry-failure"),
)
# Kept as a hand-written literal on purpose: the release topology generator reads this
# tuple from the module source with ast.literal_eval. A test proves it equals the specs.
WARNING_LANE_METRICS = (
    ("WarningLanePolicyActive", "Count"),
    ("WarningLaneProviderFailures24h", "Count"),
    ("WarningLaneOldestPendingAgeSeconds", "Count"),
    ("WarningLaneDeadLetters24h", "Count"),
    ("WarningLaneLastDiscoverySuccessAgeSeconds", "Count"),
    ("WarningLaneCandidatesSampled24h", "Count"),
    ("WarningLaneValidationRejectionBasisPoints", "Count"),
    ("WarningLaneTechnicalEnvelopeBreaches24h", "Count"),
    ("WarningLaneRecheckFailures24h", "Count"),
    ("WarningLaneExpiryFailures", "Count"),
)
WARNING_LANE_METRIC_MAXIMUMS = tuple(spec.maximum for spec in WARNING_LANE_METRIC_SPECS)
WARNING_LANE_FAIL_CLOSED_VALUES = tuple(spec.fail_closed for spec in WARNING_LANE_METRIC_SPECS)


def _contained_values(specs: tuple[MetricSpec, ...]) -> tuple[int, ...]:
    """Every warning-lane metric publishes a contained value; the length is structural."""
    values = []
    for spec in specs:
        if spec.contained is None:
            raise ValueError(f"warning-lane metric {spec.name} has no contained value")
        values.append(spec.contained)
    return tuple(values)


WARNING_LANE_CONTAINED_VALUES = _contained_values(WARNING_LANE_METRIC_SPECS)


@dataclass(frozen=True, slots=True)
class WarningLaneHealth:
    schedule_expected: bool
    policy_active: int
    provider_failures_24h: int
    oldest_pending_age_seconds: int
    dead_letters_24h: int
    last_discovery_success_age_seconds: int
    candidates_sampled_24h: int
    windows_completed_24h: int
    validation_rejection_basis_points: int
    technical_envelope_breaches_24h: int
    recheck_failures_24h: int
    expiry_failures: int
    credential_routes: tuple[tuple[str, str], ...] = ()
    provider_attempts_24h: int = 0
    # Error budget: failures beyond max(1, 5% of attempts) in 24 hours, or two
    # consecutive runs that each failed, count against the alarm; single hiccups don't.
    provider_failures_over_budget: int = 0
    dead_letters_over_budget: int = 0
    dispatch_enabled: bool = False
    recheck_dispatch_enabled: bool = False
    control_valid: bool = True
    discovery_timer_active: bool | None = False
    discovery_service_active: bool | None = False
    recheck_timer_active: bool | None = False
    recheck_service_active: bool | None = False
    dispatch_latched: bool = False
    overdue_leads: int = 0
    overdue_leads_beyond_grace: int = 0

    @property
    def control_healthy(self) -> bool:
        if not self.control_valid or self.dispatch_enabled != self.schedule_expected:
            return False
        for enabled, timer, service in (
            (self.dispatch_enabled, self.discovery_timer_active, self.discovery_service_active),
            (self.recheck_dispatch_enabled, self.recheck_timer_active, self.recheck_service_active),
        ):
            if timer is None or service is None or timer != enabled or (not enabled and service):
                return False
        return True

    @property
    def restart_budget_clear(self) -> bool:
        return not (
            self.provider_failures_over_budget
            or self.dead_letters_over_budget
            or self.technical_envelope_breaches_24h
        )

    @property
    def metric_values(self) -> tuple[int, ...]:
        contained_ages = {"oldest_pending_age_seconds", "last_discovery_success_age_seconds"}
        contained = not self.dispatch_enabled and self.control_healthy
        return tuple(
            0 if contained and spec.attribute in contained_ages else getattr(self, spec.attribute)
            for spec in WARNING_LANE_METRIC_SPECS
        )

    @property
    def healthy(self) -> bool:
        return (
            self.control_healthy
            and self.restart_budget_clear
            and not self.dispatch_latched
            and (
                not self.dispatch_enabled
                or (
                    self.policy_active == 1
                    and self.oldest_pending_age_seconds <= 15 * 60
                    and self.last_discovery_success_age_seconds <= DISCOVERY_STALE_SECONDS
                )
            )
            and self.recheck_failures_24h == 0
            and self.expiry_failures == 0
        )


def _age(measured_at: datetime, occurred_at: datetime | None) -> int:
    if occurred_at is None:
        return WARNING_LANE_MAX_AGE_SECONDS
    seconds = int((measured_at - occurred_at.astimezone(UTC)).total_seconds())
    if seconds < 0:
        return WARNING_LANE_MAX_AGE_SECONDS
    return min(seconds, WARNING_LANE_MAX_AGE_SECONDS)


def warning_lane_schedule_expected() -> bool:
    value = os.environ.get("SMITHGUARD_WARNING_LANE_SCHEDULE_EXPECTED", "0")
    if value not in {"0", "1"}:
        raise ValueError("SMITHGUARD_WARNING_LANE_SCHEDULE_EXPECTED must be exactly 0 or 1")
    return value == "1"


def collect_warning_lane_health(
    session: Session,
    *,
    policy: SpendPolicy,
    measured_at: datetime,
    expiry_job_success: bool | None,
    schedule_expected: bool | None = None,
    dispatch_enabled: bool | None = None,
    recheck_dispatch_enabled: bool = False,
    control_valid: bool = True,
    discovery_timer_active: bool | None | Literal["not_provided"] = "not_provided",
    discovery_service_active: bool | None = False,
    recheck_timer_active: bool | None = False,
    recheck_service_active: bool | None = False,
    dispatch_latched: bool = False,
) -> WarningLaneHealth:
    """Measure recovered jobs, receipts, rechecks, and expiry status."""
    if measured_at.tzinfo is None or measured_at.utcoffset() is None:
        raise ValueError("warning lane health time must be timezone-aware")
    current = measured_at.astimezone(UTC)
    expected = warning_lane_schedule_expected() if schedule_expected is None else schedule_expected
    if not isinstance(expected, bool):
        raise ValueError("warning lane schedule expectation must be boolean")
    enabled = expected if dispatch_enabled is None else dispatch_enabled
    # Pure callers can evaluate receipt history with explicit synthetic state.
    # Production supplies every observed control/unit field, including unknowns.
    timer_active = expected if discovery_timer_active == "not_provided" else discovery_timer_active
    since = current - timedelta(hours=24)
    oldest_pending_created_at = session.scalar(
        select(func.min(JobRecord.created_at)).where(
            JobRecord.queue.in_((DISCOVERY_QUEUE, QUALIFICATION_QUEUE)),
            JobRecord.state.in_(("pending", "running", "retry_wait")),
        )
    )
    dead_letters_24h = int(
        session.scalar(
            select(func.count())
            .select_from(JobRecord)
            .where(
                JobRecord.queue.in_((DISCOVERY_QUEUE, QUALIFICATION_QUEUE)),
                JobRecord.state == "dead_letter",
                JobRecord.completed_at >= since,
                JobRecord.completed_at <= current,
            )
        )
        or 0
    )
    recent_receipt_records = tuple(
        session.scalars(
            select(JobRecord).where(
                JobRecord.queue == RECEIPT_QUEUE,
                JobRecord.state == "succeeded",
                JobRecord.completed_at >= since,
                JobRecord.completed_at <= current,
            )
        )
    )
    recent_receipts = [record.payload for record in recent_receipt_records]
    credential_routes: dict[str, str] = {}
    for record in sorted(recent_receipt_records, key=lambda row: (row.completed_at, row.job_id)):
        provider = record.payload.get("provider")
        if not isinstance(provider, dict):
            continue
        stage = provider.get("stage")
        route = provider.get("credential_route")
        if stage in {"discovery", "qualification", "recheck"} and route in {
            "subscription",
            "grok_build_subscription",
            "claude_code_subscription",
            "api_key",
        }:
            credential_routes[stage] = route

    discovery_receipts = [
        item for item in recent_receipts if item.get("receipt_type") == "discovery_completed"
    ]
    validation_accepted = sum(
        int(item.get("public_metadata", {}).get("accepted_candidates", 0))
        for item in discovery_receipts
    )
    excluded_quality_reasons = {
        "candidate_withdrawn_or_corrected",
        "candidate_directly_contradicted",
        "candidate_repost_or_duplicate",
        *CORRECT_REJECTION_CODES,
    }
    validation_receipts = [
        item for item in recent_receipts if item.get("receipt_type") == "validation_rejection"
    ]
    validation_rejections = sum(
        item.get("reason_code") not in excluded_quality_reasons for item in validation_receipts
    )
    candidates_sampled = validation_accepted + len(validation_receipts)
    windows_completed = len(
        {
            item.get("run_id")
            for item in (*discovery_receipts, *validation_receipts)
            if isinstance(item.get("run_id"), str)
        }
    )
    # A minimum sample always applies; a few empty windows never make one rejection 100%.
    quality_gate_eligible = candidates_sampled >= 8
    rejection_basis_points = (
        min(10_000, validation_rejections * 10_000 // candidates_sampled)
        if quality_gate_eligible and candidates_sampled
        else 0
    )
    last_discovery = session.scalar(
        select(func.max(JobRecord.completed_at)).where(
            JobRecord.queue == RECEIPT_QUEUE,
            JobRecord.state == "succeeded",
            JobRecord.payload["receipt_type"].as_string() == "discovery_completed",
            JobRecord.completed_at >= since,
            JobRecord.completed_at <= current,
        )
    )
    recheck_failures = len(
        tuple(
            session.scalars(
                select(PreliminaryWarningRecheckRecord.recheck_id).where(
                    PreliminaryWarningRecheckRecord.checked_at >= since,
                    PreliminaryWarningRecheckRecord.checked_at <= current,
                    PreliminaryWarningRecheckRecord.outcome == "provider_unavailable",
                )
            )
        )
    )
    budget = calculate_dispatch_budget(recent_receipts, dead_letters=dead_letters_24h)
    overdue = overdue_lead_count(session, now=current)
    overdue_beyond_grace = overdue_lead_count(session, now=current - LEAD_EXPIRY_GRACE)
    return WarningLaneHealth(
        schedule_expected=expected,
        policy_active=int(policy.unattended_dispatch_allowed),
        provider_failures_24h=budget.provider_failures_24h,
        oldest_pending_age_seconds=_age(current, oldest_pending_created_at)
        if oldest_pending_created_at is not None
        else 0,
        dead_letters_24h=dead_letters_24h,
        last_discovery_success_age_seconds=_age(current, last_discovery),
        candidates_sampled_24h=candidates_sampled,
        windows_completed_24h=windows_completed,
        validation_rejection_basis_points=rejection_basis_points,
        technical_envelope_breaches_24h=budget.technical_envelope_breaches_24h,
        recheck_failures_24h=recheck_failures,
        expiry_failures=int(expiry_job_success is not True or overdue_beyond_grace > 0),
        credential_routes=tuple(sorted(credential_routes.items())),
        provider_attempts_24h=budget.provider_attempts_24h,
        provider_failures_over_budget=budget.provider_failures_over_budget,
        dead_letters_over_budget=budget.dead_letters_over_budget,
        dispatch_enabled=enabled,
        recheck_dispatch_enabled=recheck_dispatch_enabled,
        control_valid=control_valid,
        discovery_timer_active=timer_active,
        discovery_service_active=discovery_service_active,
        recheck_timer_active=recheck_timer_active,
        recheck_service_active=recheck_service_active,
        dispatch_latched=dispatch_latched,
        overdue_leads=overdue,
        overdue_leads_beyond_grace=overdue_beyond_grace,
    )
