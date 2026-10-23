"""Bounded canonical assessment reuse with authoritative correction/expiry checks."""

from __future__ import annotations

import asyncio
import json
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha256
from threading import Lock
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from smithguard.identifiers import canonical_json_bytes

CACHE_MAX_AGE = timedelta(minutes=5)
CACHE_MAX_ENTRIES = 10_000
CACHE_MAX_BYTES = 64 * 1024 * 1024
CACHE_MAX_ENTRY_BYTES = 1024 * 1024
CACHE_MAINTENANCE_SECONDS = 1.0


class AssessmentCacheCapacityError(RuntimeError):
    """Distinct assessment work has reached its fixed admission bound."""


def assessment_watermark(session: Session) -> str:
    """Read all transaction visibility components, including older pending writers.

    A sequence maximum misses an older transaction committing out of order. A
    fresh READ COMMITTED snapshot detects that transition without scanning any
    evidence table. Unrelated writes conservatively invalidate reuse as well.
    Server-start identity prevents reuse across a database restart/restore.
    """
    row = session.execute(
        text(
            "SELECT pg_current_snapshot()::text, pg_postmaster_start_time()::text, "
            "current_setting('transaction_isolation')"
        )
    ).one()
    if row[2] != "read committed":
        raise RuntimeError("assessment cache requires fresh READ COMMITTED visibility")
    return sha256(canonical_json_bytes([row[0], row[1]])).hexdigest()


def active_warning_expiry(response: dict[str, Any]) -> datetime | None:
    """Do not carry an active warning across its exact fixed expiry."""
    expiries = [
        datetime.fromisoformat(warning["expires_at"].replace("Z", "+00:00"))
        for warning in response.get("preliminary_warnings", ())
        if warning["state"] == "active"
    ]
    return min(expiries) if expiries else None


@dataclass(frozen=True, slots=True)
class _Entry:
    created_at: datetime
    expires_at: datetime
    watermark: str
    payload: bytes


@dataclass(slots=True)
class AssessmentResponseCache:
    max_age: timedelta = CACHE_MAX_AGE
    max_entries: int = CACHE_MAX_ENTRIES
    max_bytes: int = CACHE_MAX_BYTES
    max_entry_bytes: int = CACHE_MAX_ENTRY_BYTES
    max_inflight: int = 16
    values: OrderedDict[bytes, _Entry] = field(default_factory=OrderedDict)
    serialized_bytes: int = 0
    _inflight: dict[bytes, asyncio.Future[None]] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def _remove(self, key: bytes) -> None:
        entry = self.values.pop(key)
        self.serialized_bytes -= len(entry.payload)

    def expire(self, *, now: datetime) -> None:
        """Scan at most max_entries; no unbounded heap of eviction tombstones."""
        with self._lock:
            for key, entry in list(self.values.items()):
                if not entry.created_at <= now < entry.expires_at:
                    self._remove(key)

    def begin(
        self,
        identity: dict[str, Any],
        *,
        now: datetime,
        watermark: str,
        loop: asyncio.AbstractEventLoop,
    ) -> tuple[dict[str, Any] | None, asyncio.Future[None], bool]:
        key = canonical_json_bytes(identity)
        with self._lock:
            cached = self.values.get(key)
            if cached is not None:
                if cached.created_at <= now < cached.expires_at and cached.watermark == watermark:
                    self.values.move_to_end(key)
                    completed = loop.create_future()
                    completed.set_result(None)
                    # Each caller owns its decoded value; the cache retains only
                    # bytes, never a multiply copied Python response graph.
                    return json.loads(cached.payload), completed, False
                self._remove(key)
            existing = self._inflight.get(key)
            if existing is not None:
                return None, existing, False
            if len(self._inflight) >= self.max_inflight:
                raise AssessmentCacheCapacityError("assessment work is at capacity")
            future = loop.create_future()
            self._inflight[key] = future
            return None, future, True

    def complete(
        self,
        identity: dict[str, Any],
        response: dict[str, Any],
        *,
        owner: asyncio.Future[None],
        now: datetime,
        watermark: str | None,
    ) -> None:
        key = canonical_json_bytes(identity)
        payload = canonical_json_bytes(response)
        warning_expiry = active_warning_expiry(response)
        expires_at = min(now + self.max_age, warning_expiry or now + self.max_age)
        with self._lock:
            if self._inflight.get(key) is not owner:
                return
            if key in self.values:
                self._remove(key)
            if (
                watermark is not None
                and expires_at > now
                and len(payload) <= min(self.max_entry_bytes, self.max_bytes)
            ):
                self.values[key] = _Entry(now, expires_at, watermark, payload)
                self.serialized_bytes += len(payload)
                while len(self.values) > self.max_entries or self.serialized_bytes > self.max_bytes:
                    self._remove(next(iter(self.values)))
            del self._inflight[key]
        if not owner.done():
            owner.set_result(None)

    def abort(self, identity: dict[str, Any], *, owner: asyncio.Future[None]) -> None:
        key = canonical_json_bytes(identity)
        with self._lock:
            if self._inflight.get(key) is not owner:
                return
            del self._inflight[key]
        if not owner.done():
            owner.set_result(None)

    def clear(self) -> None:
        with self._lock:
            self.values.clear()
            self.serialized_bytes = 0
