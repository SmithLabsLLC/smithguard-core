"""Fixed-vocabulary byte counts only; no event content or arbitrary labels survive."""

from __future__ import annotations

from dataclasses import dataclass

EVENT_TYPES = (
    "available_commands",
    "thought",
    "text",
    "usage",
    "tool_call",
    "tool_call_update",
    "error",
    "end",
    "max_turns_reached",
    "unknown",
)
MAX_BYTES = 1_056_768  # Envelope plus one bounded pipe read that detects overflow.
MAX_COUNT = 3_600_000


def _bounded(value: int, maximum: int) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("native event observation invalid")


@dataclass(frozen=True, slots=True)
class EventObservation:
    counts: tuple[int, ...]
    serialized_bytes: tuple[int, ...]
    stdout_bytes: int
    stderr_bytes: int
    framing_bytes: int
    malformed_bytes: int
    malformed_lines: int
    first_text_elapsed_ms: int | None

    def __post_init__(self) -> None:
        for values, maximum in ((self.counts, MAX_COUNT), (self.serialized_bytes, MAX_BYTES)):
            if type(values) is not tuple or len(values) != len(EVENT_TYPES):
                raise ValueError("native event observation invalid")
            for value in values:
                _bounded(value, maximum)
        for value in (
            self.stdout_bytes,
            self.stderr_bytes,
            self.framing_bytes,
            self.malformed_bytes,
        ):
            _bounded(value, MAX_BYTES)
        _bounded(self.malformed_lines, MAX_COUNT)
        if self.first_text_elapsed_ms is not None:
            _bounded(self.first_text_elapsed_ms, MAX_COUNT)
        if (
            sum(self.serialized_bytes) + self.framing_bytes + self.malformed_bytes
            > self.stdout_bytes
        ):
            raise ValueError("native event byte attribution invalid")
        if self.stdout_bytes + self.stderr_bytes > MAX_BYTES:
            raise ValueError("native event pipe total invalid")

    def metadata(self) -> dict:
        return {
            "event_types": {
                name: {"count": count, "serialized_bytes": size}
                for name, count, size in zip(
                    EVENT_TYPES, self.counts, self.serialized_bytes, strict=True
                )
            },
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "framing_bytes": self.framing_bytes,
            "malformed_bytes": self.malformed_bytes,
            "malformed_lines": self.malformed_lines,
            "unparsed_stdout_bytes": self.stdout_bytes
            - self.framing_bytes
            - self.malformed_bytes
            - sum(self.serialized_bytes),
            "first_text_elapsed_ms": self.first_text_elapsed_ms,
        }


class EventRecorder:
    def __init__(self) -> None:
        self.counts = [0] * len(EVENT_TYPES)
        self.sizes = [0] * len(EVENT_TYPES)
        self.stdout = self.stderr = self.framing = self.malformed = self.malformed_lines = 0
        self.first_text: int | None = None

    def pipe(self, channel: str, size: int) -> None:
        _bounded(size, MAX_BYTES)
        room = MAX_BYTES - self.stdout - self.stderr
        if channel == "stdout":
            self.stdout += min(room, size)
        elif channel == "stderr":
            self.stderr += min(room, size)
        else:
            raise ValueError("native event pipe invalid")

    def line(
        self, kind: object, size: int, framing: int, elapsed_ms: int, *, malformed=False
    ) -> None:
        _bounded(size, MAX_BYTES)
        _bounded(framing, 1)
        _bounded(elapsed_ms, MAX_COUNT)
        # A test/alternate process without per-pipe observation has unknown attribution.
        # Never invent stdout or stderr bytes from its combined counter.
        if size + framing > self.stdout - sum(self.sizes) - self.malformed - self.framing:
            return
        self.framing += framing
        if malformed:
            self.malformed += size
            self.malformed_lines = min(MAX_COUNT, self.malformed_lines + 1)
            return
        index = EVENT_TYPES.index(kind) if type(kind) is str and kind in EVENT_TYPES else -1
        self.counts[index] = min(MAX_COUNT, self.counts[index] + 1)
        self.sizes[index] += size
        if kind == "text" and self.first_text is None:
            self.first_text = elapsed_ms

    def snapshot(self) -> EventObservation:
        return EventObservation(
            tuple(self.counts),
            tuple(self.sizes),
            self.stdout,
            self.stderr,
            self.framing,
            self.malformed,
            self.malformed_lines,
            self.first_text,
        )
