"""Synchronous catalog deadlines shared by bounded Git and database work."""

from __future__ import annotations

import os
import signal
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import timedelta
from threading import current_thread, main_thread

CATALOG_TIMEOUT_SECONDS = 600
CATALOG_SHUTDOWN_RESERVE_SECONDS = 360
CATALOG_PAGE_SECONDS = 180
CATALOG_SCHEDULE_INTERVAL = timedelta(hours=1)
# Data stays fresh through one missed or failed hourly run: two intervals, the timer's
# five-minute randomized delay, and one run's timeout. A single failed attempt is
# reported as degraded, not as stale data.
CATALOG_FRESHNESS_MAX_AGE = 2 * CATALOG_SCHEDULE_INTERVAL + timedelta(
    minutes=5, seconds=CATALOG_TIMEOUT_SECONDS
)
# Receipts written before September 24, 2026 used one interval; they stay readable
# until the next catalog run replaces them.
LEGACY_CATALOG_FRESHNESS_MAX_AGE = timedelta(minutes=66, seconds=CATALOG_TIMEOUT_SECONDS)


class CatalogStopped(RuntimeError):
    """Catalog work stopped at a safe boundary or exhausted its finite deadline."""


@dataclass(slots=True)
class CatalogBudget:
    deadline: float
    page_deadline: float | None = None
    stop_requested: bool = False

    def remaining(self) -> float:
        deadline = min(self.deadline, self.page_deadline or self.deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CatalogStopped("OpenSSF catalog work deadline expired")
        return remaining

    def checkpoint(self) -> None:
        if self.stop_requested:
            raise CatalogStopped("OpenSSF catalog stop requested")
        self.remaining()


_current: ContextVar[CatalogBudget | None] = ContextVar("openssf_catalog_budget", default=None)


def bounded_timeout(maximum: float) -> float:
    """Leave retained callers unchanged when no catalog run is active."""
    budget = _current.get()
    return min(maximum, budget.remaining()) if budget is not None else maximum


def checkpoint() -> None:
    budget = _current.get()
    if budget is not None:
        budget.checkpoint()


@contextmanager
def catalog_budget():
    raw = os.environ.get("SMITHGUARD_OPENSSF_TIMEOUT_SECONDS", str(CATALOG_TIMEOUT_SECONDS))
    if raw != str(CATALOG_TIMEOUT_SECONDS):
        raise ValueError("OpenSSF timeout must be exactly 600 seconds")
    budget = CatalogBudget(time.monotonic() + int(raw) - CATALOG_SHUTDOWN_RESERVE_SECONDS)
    token = _current.set(budget)
    previous = None

    def request_stop(_signum, _frame):
        # Never throw asynchronously through a database commit or stage finalization.
        budget.stop_requested = True

    if current_thread() is main_thread():
        previous = signal.signal(signal.SIGTERM, request_stop)
    try:
        yield budget
    finally:
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)
        _current.reset(token)


@contextmanager
def page_budget():
    budget = _current.get()
    if budget is None:
        yield
        return
    budget.checkpoint()
    previous = budget.page_deadline
    budget.page_deadline = time.monotonic() + CATALOG_PAGE_SECONDS
    try:
        yield
    finally:
        budget.page_deadline = previous


def set_statement_budget(session) -> None:
    """Bound the next record's SQL work by this page's remaining time."""
    milliseconds = max(1, int(bounded_timeout(10.0) * 1000))
    from sqlalchemy import text

    session.execute(
        text("SELECT set_config('statement_timeout', :limit, true)"), {"limit": str(milliseconds)}
    )
    session.execute(
        text("SELECT set_config('lock_timeout', :limit, true)"),
        {"limit": str(min(milliseconds, 5000))},
    )
