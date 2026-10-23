"""Bounded, content-free timing observations; never provider usage or dispatch policy."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from smithguard.identifiers import require_aware_utc, timestamp
from smithguard.native_event_observations import EventObservation, EventRecorder

PHASES = (
    "preflight",
    "ram_setup",
    "inspection",
    "bootstrap",
    "pre_dispatch_validation",
    "launch",
    "stream_read",
    "stream_parse",
    "completion",
    "process_cleanup",
    "post_run_validation",
    "ram_cleanup",
)
CATEGORIES = ("timeout", "transport", "invalid_data", "filesystem", "contract_rejection", "other")
MAX_MS = 3_600_000
MAX_STREAM_BYTES = 1_056_768
BUCKET_MS = 5_000
BUCKET_COUNT = 7  # Current partial bucket plus six preceding five-second buckets.
MAX_INVOCATIONS = 3


def _count(value: int, maximum: int = MAX_MS) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("native timing count invalid")


@dataclass(frozen=True, slots=True)
class ActivityBucket:
    start_elapsed_ms: int
    stream_bytes: int
    parsed_events: int

    def __post_init__(self) -> None:
        _count(self.start_elapsed_ms)
        _count(self.stream_bytes, MAX_STREAM_BYTES)
        _count(self.parsed_events)
        if self.start_elapsed_ms % BUCKET_MS:
            raise ValueError("native timing bucket invalid")

    def metadata(self) -> dict[str, int]:
        return {
            "start_elapsed_ms": self.start_elapsed_ms,
            "stream_bytes": self.stream_bytes,
            "parsed_events": self.parsed_events,
        }


@dataclass(frozen=True, slots=True)
class ActivityObservation:
    elapsed_ms: int
    stream_bytes: int
    parsed_events: int
    first_event_elapsed_ms: int | None
    last_event_age_ms: int | None
    buckets: tuple[ActivityBucket, ...]

    def __post_init__(self) -> None:
        _count(self.elapsed_ms)
        _count(self.stream_bytes, MAX_STREAM_BYTES)
        _count(self.parsed_events)
        for value in (self.first_event_elapsed_ms, self.last_event_age_ms):
            if value is not None:
                _count(value, self.elapsed_ms)
        if (self.parsed_events == 0) != (self.first_event_elapsed_ms is None) or (
            self.first_event_elapsed_ms is None
        ) != (self.last_event_age_ms is None):
            raise ValueError("native timing event boundary invalid")
        if type(self.buckets) is not tuple or not 1 <= len(self.buckets) <= BUCKET_COUNT:
            raise ValueError("native timing buckets invalid")
        slot = self.elapsed_ms // BUCKET_MS
        expected = tuple(range(max(0, slot - BUCKET_COUNT + 1), slot + 1))
        if (
            any(type(item) is not ActivityBucket for item in self.buckets)
            or tuple(item.start_elapsed_ms // BUCKET_MS for item in self.buckets) != expected
            or sum(item.stream_bytes for item in self.buckets) > self.stream_bytes
            or sum(item.parsed_events for item in self.buckets) > self.parsed_events
        ):
            raise ValueError("native timing bucket sequence invalid")

    def metadata(self) -> dict[str, Any]:
        return {
            "elapsed_ms": self.elapsed_ms,
            "stream_bytes": self.stream_bytes,
            "parsed_events": self.parsed_events,
            "first_event_elapsed_ms": self.first_event_elapsed_ms,
            "last_event_age_ms": self.last_event_age_ms,
            "bucket_width_ms": BUCKET_MS,
            "recent_activity": [item.metadata() for item in self.buckets],
        }


@dataclass(frozen=True, slots=True)
class InvocationTiming:
    start_elapsed_ms: int
    elapsed_ms: int
    events: EventObservation | None = None

    def __post_init__(self) -> None:
        _count(self.start_elapsed_ms)
        _count(self.elapsed_ms)
        if self.events is not None and type(self.events) is not EventObservation:
            raise ValueError("native timing event observation invalid")

    def metadata(self) -> dict[str, Any]:
        return {
            "start_elapsed_ms": self.start_elapsed_ms,
            "elapsed_ms": self.elapsed_ms,
            **({"events": self.events.metadata()} if self.events is not None else {}),
        }


@dataclass(frozen=True, slots=True)
class TimingFailure:
    phase: str
    exception_category: str
    activity: ActivityObservation
    invocations: tuple[InvocationTiming, ...] = ()

    def __post_init__(self) -> None:
        if (
            self.phase not in PHASES
            or self.exception_category not in CATEGORIES
            or type(self.activity) is not ActivityObservation
            or type(self.invocations) is not tuple
            or len(self.invocations) > MAX_INVOCATIONS
            or any(type(item) is not InvocationTiming for item in self.invocations)
        ):
            raise ValueError("native timing failure invalid")


@dataclass(frozen=True, slots=True)
class NativeTimingDiagnostic:
    observed_finished_at: datetime
    activity: ActivityObservation
    phase_elapsed_ms: tuple[int, ...]
    invocations: tuple[InvocationTiming, ...]
    first_failure: TimingFailure | None = None

    def __post_init__(self) -> None:
        require_aware_utc(self.observed_finished_at)
        if type(self.activity) is not ActivityObservation:
            raise ValueError("native timing activity invalid")
        if type(self.phase_elapsed_ms) is not tuple or len(self.phase_elapsed_ms) != len(PHASES):
            raise ValueError("native timing phases invalid")
        for value in self.phase_elapsed_ms:
            _count(value)
        if (
            type(self.invocations) is not tuple
            or len(self.invocations) > MAX_INVOCATIONS
            or any(type(item) is not InvocationTiming for item in self.invocations)
        ):
            raise ValueError("native timing invocations invalid")
        if self.first_failure is not None and type(self.first_failure) is not TimingFailure:
            raise ValueError("native timing failure invalid")

    def metadata(self) -> dict[str, Any]:
        return {
            "schema_version": "1.1.0",
            "observed_finished_at": timestamp(self.observed_finished_at),
            "activity": self.activity.metadata(),
            "phase_elapsed_ms": dict(zip(PHASES, self.phase_elapsed_ms, strict=True)),
            "invocations": [item.metadata() for item in self.invocations],
            **(
                {
                    "first_failure": {
                        "phase": self.first_failure.phase,
                        "exception_category": self.first_failure.exception_category,
                        "activity": self.first_failure.activity.metadata(),
                        "invocations": [item.metadata() for item in self.first_failure.invocations],
                    }
                }
                if self.first_failure is not None
                else {}
            ),
        }


class NativeTimingRecorder:
    """Fixed-size counters only. Clock reads never extend or select the deadline."""

    def __init__(
        self, *, started: float, clock: Callable[[], float], utc_now: Callable[[], datetime]
    ) -> None:
        self.started, self.clock, self.utc_now = started, clock, utc_now
        self.phase = "preflight"
        self.phase_started = started
        self.phases = dict.fromkeys(PHASES, 0.0)
        self.invocations: list[InvocationTiming] = []
        self.invocation_started: float | None = None
        self.events = EventRecorder()
        self.process_bytes = 0
        self.stream_bytes = self.parsed_events = 0
        self.first_event: float | None = None
        self.last_event: float | None = None
        self.buckets = [[-1, 0, 0] for _ in range(BUCKET_COUNT)]
        self.first_failure: TimingFailure | None = None

    @staticmethod
    def _ms(seconds: float) -> int:
        return min(MAX_MS, max(0, int(seconds * 1000)))

    def switch(self, phase: str) -> None:
        if phase not in PHASES:
            raise ValueError("native timing phase invalid")
        now = self.clock()
        self.phases[self.phase] += max(0.0, now - self.phase_started)
        self.phase, self.phase_started = phase, now

    def start_invocation(self) -> None:
        self.events = EventRecorder()
        self.invocation_started = self.clock()
        self.process_bytes = 0

    def finish_invocation(self) -> None:
        if self.invocation_started is not None:
            self.invocations.append(
                InvocationTiming(
                    self._ms(self.invocation_started - self.started),
                    self._ms(self.clock() - self.invocation_started),
                    self.events.snapshot(),
                )
            )
            self.invocation_started = None

    def _bucket(self, now: float) -> list[int]:
        slot = self._ms(now - self.started) // BUCKET_MS
        bucket = self.buckets[slot % BUCKET_COUNT]
        if bucket[0] != slot:
            bucket[:] = [slot, 0, 0]
        return bucket

    def observe_bytes(self, cumulative_process_bytes: int) -> None:
        # Called immediately after either pipe is drained, even without a full line.
        size = min(MAX_STREAM_BYTES, max(0, cumulative_process_bytes))
        delta = min(MAX_STREAM_BYTES - self.stream_bytes, max(0, size - self.process_bytes))
        self.process_bytes = size
        self.stream_bytes += delta
        self._bucket(self.clock())[1] += delta

    def observe_pipe(self, channel: str, size: int) -> None:
        self.events.pipe(channel, size)

    def observe_line(self, kind: object, size: int, framing: int, *, malformed=False) -> None:
        start = self.invocation_started
        self.events.line(
            kind,
            size,
            framing,
            self._ms(self.clock() - start) if start is not None else 0,
            malformed=malformed,
        )

    def observe_event(self) -> None:
        now = self.clock()
        if self.first_event is None:
            self.first_event = now
        self.last_event = now
        if self.parsed_events < MAX_MS:
            self.parsed_events += 1
            self._bucket(now)[2] += 1

    def activity(self, now: float) -> ActivityObservation:
        elapsed = self._ms(now - self.started)
        slot = elapsed // BUCKET_MS
        buckets = []
        for index in range(max(0, slot - BUCKET_COUNT + 1), slot + 1):
            current = self.buckets[index % BUCKET_COUNT]
            counts = current[1:] if current[0] == index else (0, 0)
            buckets.append(ActivityBucket(index * BUCKET_MS, *counts))
        return ActivityObservation(
            elapsed,
            self.stream_bytes,
            self.parsed_events,
            None if self.first_event is None else self._ms(self.first_event - self.started),
            None if self.last_event is None else self._ms(now - self.last_event),
            tuple(buckets),
        )

    def failure(self, phase: str, category: str) -> None:
        # Preserve the pre-cleanup failure, including its deadline observation.
        if self.first_failure is None:
            now = self.clock()
            self.first_failure = TimingFailure(
                phase, category, self.activity(now), self._invocations(now)
            )

    def snapshot(self) -> NativeTimingDiagnostic:
        now = self.clock()
        phases = dict(self.phases)
        phases[self.phase] += max(0.0, now - self.phase_started)
        return NativeTimingDiagnostic(
            self.utc_now(),
            self.activity(now),
            tuple(self._ms(phases[p]) for p in PHASES),
            self._invocations(now),
            self.first_failure,
        )

    def _invocations(self, now: float) -> tuple[InvocationTiming, ...]:
        invocations = list(self.invocations)
        if self.invocation_started is not None:
            invocations.append(
                InvocationTiming(
                    self._ms(self.invocation_started - self.started),
                    self._ms(now - self.invocation_started),
                    self.events.snapshot(),
                )
            )
        return tuple(invocations)
