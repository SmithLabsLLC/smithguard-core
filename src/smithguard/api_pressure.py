"""Bounded, private aggregate API pressure; never retains requests or addresses."""

from __future__ import annotations

import json
import math
import os
import stat
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic

from smithguard.fsio import atomic_write, read_private_file
from smithguard.identifiers import parse_timestamp, pretty_json_bytes, timestamp

PRESSURE_PATH = Path("/var/lib/smithguard/api-health/latest.json")
PRESSURE_INTERVAL_SECONDS = 60
MAX_AGE = timedelta(seconds=180)
WINDOW_MINUTES = 5
KERNEL_PRESSURE_ROOT = Path("/run/smithguard-health-kernel")


class ApiPressure:
    """Five minute buckets bound memory independently of request volume."""

    def __init__(self, *, clock: Callable[[], float] = monotonic) -> None:
        self.clock = clock
        self.buckets: dict[int, list[int]] = {}

    def _current(self) -> int:
        minute = int(self.clock() // 60)
        self.buckets = {
            key: value
            for key, value in self.buckets.items()
            if minute - WINDOW_MINUTES < key <= minute
        }
        return minute

    def observe(self, *, status: int, seconds: float) -> None:
        minute = self._current()
        counts = self.buckets.setdefault(minute, [0, 0, 0])
        for index, increment in enumerate((1, int(status >= 500), int(seconds >= 2))):
            counts[index] = min(10**9, counts[index] + increment)

    def document(self, *, now: datetime) -> dict:
        self._current()
        totals = [sum(row[i] for row in self.buckets.values()) for i in range(3)]
        return {
            "schema_version": "1.0.0",
            "measured_at": timestamp(now),
            "window_seconds": WINDOW_MINUTES * 60,
            "requests": totals[0],
            "server_errors": totals[1],
            "slow_requests": totals[2],
        }

    def write(self, path: Path, *, now: datetime) -> None:
        write_pressure(path, self.document(now=now))


def write_pressure(path: Path, document: dict) -> None:
    """Write a prebuilt snapshot without touching the event-loop-owned counters."""
    parent = path.parent
    metadata = parent.lstat()
    if (
        not path.is_absolute()
        or parent.resolve() != parent
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o2750
        or metadata.st_uid != os.getuid()
    ):
        raise ValueError("API pressure directory is unsafe")
    atomic_write(path, pretty_json_bytes(document), mode=0o640)


def pressure_status(path: Path, *, now: datetime | None = None) -> str:
    """A missing/stale/malformed heartbeat is visible, never treated as idle."""
    try:
        raw = read_private_file(path, maximum=4096, minimum=1, mode_mask=0o027)
        # Sample after the read: a heartbeat may be replaced during earlier health checks.
        if now is None:
            now = datetime.now(UTC)
        document = json.loads(raw)
        if not isinstance(document, dict) or set(document) != {
            "schema_version",
            "measured_at",
            "window_seconds",
            "requests",
            "server_errors",
            "slow_requests",
        }:
            return "unavailable"
        if (
            document["schema_version"] != "1.0.0"
            or document["window_seconds"] != WINDOW_MINUTES * 60
        ):
            return "unavailable"
        if not timedelta(0) <= now - parse_timestamp(document["measured_at"]) <= MAX_AGE:
            return "unavailable"
        counts = [document[k] for k in ("requests", "server_errors", "slow_requests")]
        if any(type(v) is not int or not 0 <= v <= WINDOW_MINUTES * 10**9 for v in counts):
            return "unavailable"
        requests, errors, slow = counts
        if errors > requests or slow > requests:
            return "unavailable"
        if errors >= 100 or (errors >= 10 and errors * 20 >= requests):
            return "server_errors"
        if slow >= 100 or (slow >= 25 and slow * 5 >= requests):
            return "slow_responses"
        if requests >= 18_000:
            return "high_arrival_rate"
        return "healthy"
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return "unavailable"


def host_pressure_status() -> str:
    """Five-minute load and Linux available memory measure shared host pressure."""
    try:
        cores = os.cpu_count()
        load = float((KERNEL_PRESSURE_ROOT / "loadavg").read_text(encoding="ascii").split()[1])
        memory = {}
        for line in (KERNEL_PRESSURE_ROOT / "meminfo").read_text(encoding="ascii").splitlines():
            name, value = line.split(":", 1)
            if name in {"MemTotal", "MemAvailable"}:
                memory[name] = int(value.split()[0])
        total, available = memory["MemTotal"], memory["MemAvailable"]
        if not cores or not math.isfinite(load) or load < 0 or not 0 <= available <= total:
            return "unavailable"
        if total <= 0:
            return "unavailable"
        if available * 10 < total:
            return "low_memory"
        if load > 2 * cores:
            return "high_load"
        return "healthy"
    except (OSError, ValueError, KeyError, IndexError):
        return "unavailable"
