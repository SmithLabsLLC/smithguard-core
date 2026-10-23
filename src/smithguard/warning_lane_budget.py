"""One rolling failure calculation for warning dispatch, restart and health."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.db.models import JobRecord
from smithguard.identifiers import require_aware_utc
from smithguard.spend import TECHNICAL_USAGE_STOP_REASONS
from smithguard.warning_lane_receipts import RECEIPT_QUEUE

DISCOVERY_QUEUE = "ai-warning-discovery"
QUALIFICATION_QUEUE = "ai-warning-qualification"
WORKER_LOCK = "smithguard-ai-warning-single-worker"
PROVIDER_FAILURE_BUDGET_BASIS_POINTS = 500
MAX_PROVIDER_REQUESTS_24H = 48 * 4 + 12 * 12


def failure_budget(attempts: int) -> int:
    return max(1, attempts * PROVIDER_FAILURE_BUDGET_BASIS_POINTS // 10_000)


def consecutive_failed_runs(receipts: Sequence[Mapping[str, Any]]) -> bool:
    runs: dict[str, tuple[str, bool]] = {}
    for item in receipts:
        run_id, occurred = item.get("run_id"), item.get("occurred_at")
        if not isinstance(run_id, str) or not isinstance(occurred, str):
            continue
        if item.get("receipt_type") not in {"provider_request_started", "provider_failure"}:
            continue
        latest, failed = runs.get(run_id, ("", False))
        runs[run_id] = (
            max(latest, occurred),
            failed or item.get("receipt_type") == "provider_failure",
        )
    recent = sorted(runs.values(), reverse=True)[:2]
    return len(recent) == 2 and all(failed for _time, failed in recent)


@dataclass(frozen=True, slots=True)
class DispatchBudget:
    provider_attempts_24h: int
    provider_failures_24h: int
    dead_letters_24h: int
    provider_failures_over_budget: int
    dead_letters_over_budget: int
    technical_envelope_breaches_24h: int

    @property
    def allowed(self) -> bool:
        return not (
            self.provider_failures_over_budget
            or self.dead_letters_over_budget
            or self.technical_envelope_breaches_24h
        )


def calculate_dispatch_budget(
    receipts: Sequence[Mapping[str, Any]], *, dead_letters: int
) -> DispatchBudget:
    attempts = sum(item.get("receipt_type") == "provider_request_started" for item in receipts)
    failures = sum(item.get("receipt_type") == "provider_failure" for item in receipts)
    usage = sum(item.get("receipt_type") == "provider_cost_observed" for item in receipts)
    technical = len(
        {
            (item.get("run_id"), item.get("reason_code"))
            for item in receipts
            if item.get("receipt_type")
            in {"provider_cost_observed", "policy_denial", "provider_failure"}
            and item.get("reason_code") in TECHNICAL_USAGE_STOP_REASONS
        }
    ) + int(usage > MAX_PROVIDER_REQUESTS_24H)
    budget = failure_budget(attempts)
    consecutive = int(consecutive_failed_runs(receipts))
    return DispatchBudget(
        provider_attempts_24h=attempts,
        provider_failures_24h=failures,
        dead_letters_24h=dead_letters,
        provider_failures_over_budget=max(0, failures - budget) or consecutive,
        dead_letters_over_budget=max(0, dead_letters - budget) or consecutive,
        technical_envelope_breaches_24h=technical,
    )


def collect_dispatch_budget(session: Session, *, now: datetime) -> DispatchBudget:
    current = require_aware_utc(now).astimezone(UTC)
    since = current - timedelta(hours=24)
    receipts = tuple(
        session.scalars(
            select(JobRecord.payload).where(
                JobRecord.queue == RECEIPT_QUEUE,
                JobRecord.state == "succeeded",
                JobRecord.completed_at >= since,
                JobRecord.completed_at <= current,
            )
        )
    )
    dead_letters = int(
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
    return calculate_dispatch_budget(receipts, dead_letters=dead_letters)
