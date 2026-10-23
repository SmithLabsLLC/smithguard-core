"""Short-lived, query-blind quota accounting for anonymous exact checks."""

from __future__ import annotations

import hmac
import ipaddress
import os
import sqlite3
from collections import OrderedDict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from hashlib import sha256
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from fastapi import Request

from smithguard.identifiers import canonical_json_bytes, require_aware_utc, timestamp

DAILY_SUCCESS_LIMIT = 100_000
BURST_LIMIT = 100
BURST_WINDOW = timedelta(seconds=10)
MAX_BURST_NETWORKS = 4_096
PENDING_LIFETIME = timedelta(minutes=2)
MAX_COUNT_NETWORKS = 4_096
CLEANUP_BATCH = 1_024


class AnonymousQuotaError(ValueError):
    """The anonymous access boundary is unsafe or unavailable."""


class AnonymousNetworkIdentityError(AnonymousQuotaError):
    """The trusted proxy boundary did not provide one usable public address."""


@dataclass(frozen=True, slots=True)
class QuotaReservation:
    status: str
    network_key: str
    request_key: str
    reset_at: datetime
    attempt_id: str | None = None


class AnonymousQuotaStore:
    """A minimal SQLite store containing only keyed network and request digests."""

    def __init__(self, path: Path | None = None) -> None:
        self._lock = RLock()
        self._counts: OrderedDict[tuple[str, str], tuple[int, int]] = OrderedDict()
        self._data_version: int | None = None
        if path is None:
            self._connection = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            if not path.is_absolute():
                raise AnonymousQuotaError("anonymous quota path must be absolute")
            parent = path.parent
            if not parent.is_dir() or parent.is_symlink():
                raise AnonymousQuotaError("anonymous quota directory is unavailable")
            if parent.stat().st_mode & 0o077:
                raise AnonymousQuotaError("anonymous quota directory permissions are too broad")
            if path.exists() and (path.is_symlink() or not path.is_file()):
                raise AnonymousQuotaError("anonymous quota path is unsafe")
            self._connection = sqlite3.connect(path, check_same_thread=False, timeout=5)
            os.chmod(path, 0o600)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS anonymous_assessment_quota (
                network_key TEXT NOT NULL,
                request_key TEXT NOT NULL,
                quota_day TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('pending', 'complete')),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (network_key, request_key)
            ) WITHOUT ROWID
            """
        )
        # The nullable additive column preserves old rows and the prior runtime's
        # explicit-column SQL. Never identify an attempt by its wall-clock time.
        with self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            columns = {
                row[1]
                for row in self._connection.execute("PRAGMA table_info(anonymous_assessment_quota)")
            }
            if "attempt_id" not in columns:
                self._connection.execute(
                    "ALTER TABLE anonymous_assessment_quota ADD COLUMN attempt_id TEXT"
                )
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS ix_anonymous_assessment_quota_expiry
            ON anonymous_assessment_quota (expires_at)
            """
        )
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS ix_anonymous_assessment_quota_pending
            ON anonymous_assessment_quota (state, updated_at)
            """
        )
        self._connection.commit()

    def _refresh_cache_version(self) -> None:
        version = self._connection.execute("PRAGMA data_version").fetchone()[0]
        if version != self._data_version:
            self._counts.clear()
            self._data_version = version

    def _invalidate(self, networks: set[str]) -> None:
        if not networks:
            return
        for key in tuple(self._counts):
            if key[0] in networks:
                self._counts.pop(key)

    def _cleanup_locked(self, now_seconds: int, limit: int) -> int:
        # Both branches use their existing indexes. No unbounded midnight DELETE
        # or full-store scan is permitted on the request thread.
        rows = self._connection.execute(
            """
            SELECT network_key, request_key FROM anonymous_assessment_quota
            WHERE expires_at <= ? LIMIT ?
            """,
            (now_seconds, limit),
        ).fetchall()
        if len(rows) < limit:
            rows.extend(
                self._connection.execute(
                    """
                SELECT network_key, request_key FROM anonymous_assessment_quota
                WHERE state = 'pending' AND updated_at <= ? LIMIT ?
                """,
                    (now_seconds - int(PENDING_LIFETIME.total_seconds()), limit - len(rows)),
                ).fetchall()
            )
        self._connection.executemany(
            "DELETE FROM anonymous_assessment_quota WHERE network_key = ? AND request_key = ?",
            rows,
        )
        self._invalidate({row[0] for row in rows})
        return len(rows)

    def cleanup(self, *, now: datetime) -> int:
        """Expire one bounded batch even while the API is idle."""
        try:
            with self._lock, self._connection:
                self._connection.execute("BEGIN IMMEDIATE")
                self._refresh_cache_version()
                now_seconds = int(_aware(now).timestamp())
                self._counts = OrderedDict(
                    (key, value) for key, value in self._counts.items() if value[1] > now_seconds
                )
                return self._cleanup_locked(now_seconds, CLEANUP_BATCH)
        except sqlite3.Error as error:
            raise AnonymousQuotaError("anonymous quota store is unavailable") from error

    def _count(self, network: str, day: str, now_seconds: int, reset_seconds: int) -> int:
        key = (network, day)
        cached = self._counts.pop(key, None)
        if cached is not None and now_seconds < cached[1]:
            self._counts[key] = cached
            return cached[0]
        count, oldest_pending = self._connection.execute(
            """
            SELECT COUNT(*), MIN(CASE WHEN state = 'pending' THEN updated_at END)
            FROM anonymous_assessment_quota
            WHERE network_key = ? AND quota_day = ? AND expires_at > ?
              AND (state = 'complete' OR updated_at > ?)
            """,
            (network, day, now_seconds, now_seconds - int(PENDING_LIFETIME.total_seconds())),
        ).fetchone()
        valid_until = reset_seconds
        if oldest_pending is not None:
            valid_until = min(valid_until, oldest_pending + int(PENDING_LIFETIME.total_seconds()))
        self._counts[key] = (count, valid_until)
        while len(self._counts) > MAX_COUNT_NETWORKS:
            self._counts.popitem(last=False)
        return count

    def reserve(
        self,
        *,
        network_key: str,
        request_key: str,
        now: datetime,
    ) -> QuotaReservation:
        checked_now = _aware(now)
        quota_day = checked_now.date().isoformat()
        reset_at = datetime.combine(checked_now.date() + timedelta(days=1), time(), UTC)
        expires_at = reset_at + PENDING_LIFETIME  # Let pre-midnight owners finish.
        now_seconds = int(checked_now.timestamp())
        attempt_id = uuid4().hex
        with self._lock:
            connection = self._connection
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._refresh_cache_version()
                self._cleanup_locked(now_seconds, 128)
                prior = connection.execute(
                    """
                    SELECT state, updated_at, expires_at
                    FROM anonymous_assessment_quota
                    WHERE network_key = ? AND request_key = ?
                    """,
                    (network_key, request_key),
                ).fetchone()
                if prior is not None and prior[2] <= now_seconds:
                    connection.execute(
                        "DELETE FROM anonymous_assessment_quota WHERE network_key = ? "
                        "AND request_key = ?",
                        (network_key, request_key),
                    )
                    self._invalidate({network_key})
                    prior = None
                if prior is not None and prior[0] == "complete":
                    connection.commit()
                    return QuotaReservation("already_counted", network_key, request_key, reset_at)
                pending_cutoff = now_seconds - int(PENDING_LIFETIME.total_seconds())
                if prior is not None and prior[1] > pending_cutoff:
                    connection.commit()
                    pending_reset_at = datetime.fromtimestamp(prior[1], UTC) + PENDING_LIFETIME
                    return QuotaReservation(
                        "in_progress",
                        network_key,
                        request_key,
                        pending_reset_at,
                    )
                if prior is not None:
                    connection.execute(
                        """
                        DELETE FROM anonymous_assessment_quota
                        WHERE network_key = ? AND request_key = ?
                        """,
                        (network_key, request_key),
                    )
                count = self._count(network_key, quota_day, now_seconds, int(reset_at.timestamp()))
                if count >= DAILY_SUCCESS_LIMIT:
                    connection.commit()
                    return QuotaReservation("exhausted", network_key, request_key, reset_at)
                connection.execute(
                    """
                    INSERT INTO anonymous_assessment_quota (
                        network_key, request_key, quota_day, state,
                        created_at, updated_at, expires_at, attempt_id
                    ) VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)
                    """,
                    (
                        network_key,
                        request_key,
                        quota_day,
                        now_seconds,
                        now_seconds,
                        int(expires_at.timestamp()),
                        attempt_id,
                    ),
                )
                connection.commit()
                key = (network_key, quota_day)
                self._counts[key] = (
                    count + 1,
                    min(self._counts[key][1], now_seconds + int(PENDING_LIFETIME.total_seconds())),
                )
            except sqlite3.Error as error:
                self._counts.clear()
                connection.rollback()
                raise AnonymousQuotaError("anonymous quota store is unavailable") from error
            except Exception:
                self._counts.clear()
                connection.rollback()
                raise
        return QuotaReservation("reserved", network_key, request_key, reset_at, attempt_id)

    def complete(self, reservation: QuotaReservation, *, now: datetime) -> None:
        try:
            with self._lock, self._connection:
                updated = self._connection.execute(
                    """
                    UPDATE anonymous_assessment_quota
                    SET state = 'complete', updated_at = ?
                    WHERE network_key = ? AND request_key = ? AND state = 'pending'
                      AND attempt_id = ?
                    """,
                    (
                        int(_aware(now).timestamp()),
                        reservation.network_key,
                        reservation.request_key,
                        reservation.attempt_id,
                    ),
                ).rowcount
        except sqlite3.Error as error:
            raise AnonymousQuotaError("anonymous quota store is unavailable") from error
        if updated != 1:
            raise AnonymousQuotaError("anonymous quota reservation is unavailable")

    def release(self, reservation: QuotaReservation) -> None:
        self.release_many((reservation,))

    def refund(self, reservation: QuotaReservation) -> None:
        """Delete this attempt's completed row: its answer never reached the caller."""
        try:
            with self._lock, self._connection:
                changed = self._connection.execute(
                    """
                    DELETE FROM anonymous_assessment_quota
                    WHERE network_key = ? AND request_key = ? AND state = 'complete'
                      AND attempt_id = ?
                    """,
                    (reservation.network_key, reservation.request_key, reservation.attempt_id),
                ).rowcount
                if changed:
                    self._invalidate({reservation.network_key})
        except sqlite3.Error as error:
            raise AnonymousQuotaError("anonymous quota store is unavailable") from error

    def release_many(self, reservations: tuple[QuotaReservation, ...]) -> None:
        """Release owned pending rows in one transaction and one lock wait."""
        try:
            with self._lock, self._connection:
                changed = self._connection.executemany(
                    """
                    DELETE FROM anonymous_assessment_quota
                    WHERE network_key = ? AND request_key = ? AND state = 'pending'
                      AND attempt_id = ?
                    """,
                    [
                        (reservation.network_key, reservation.request_key, reservation.attempt_id)
                        for reservation in reservations
                    ],
                ).rowcount
                if changed:
                    self._invalidate({r.network_key for r in reservations})
        except sqlite3.Error as error:
            raise AnonymousQuotaError("anonymous quota store is unavailable") from error


class AnonymousAssessmentQuota:
    """Derive rotating pseudonymous keys and enforce daily and burst limits."""

    def __init__(
        self,
        *,
        secret: bytes,
        store: AnonymousQuotaStore,
        trusted_proxy_header: bool = False,
    ) -> None:
        if len(secret) < 32:
            raise AnonymousQuotaError("anonymous quota secret must contain at least 32 bytes")
        self._secret = secret
        self._store = store
        self._trusted_proxy_header = trusted_proxy_header
        self._burst: OrderedDict[str, deque[datetime]] = OrderedDict()
        self._lock = RLock()

    def reserve(
        self,
        *,
        request: Request,
        artifact_identity: Mapping[str, Any],
        now: datetime,
    ) -> QuotaReservation:
        checked_now = _aware(now)
        network = request_network(
            request,
            trusted_proxy_header=self._trusted_proxy_header,
        )
        network_key = self._key("network", checked_now.date(), network)
        request_key = self._key(
            "request",
            checked_now.date(),
            canonical_json_bytes(artifact_identity).decode("ascii"),
        )
        with self._lock:
            attempts = self._burst.pop(network_key, deque())
            cutoff = checked_now - BURST_WINDOW
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if len(attempts) >= BURST_LIMIT:
                self._burst[network_key] = attempts
                return QuotaReservation(
                    "burst",
                    network_key,
                    request_key,
                    attempts[0] + BURST_WINDOW,
                )
            attempts.append(checked_now)
            self._burst[network_key] = attempts
            while len(self._burst) > MAX_BURST_NETWORKS:
                self._burst.popitem(last=False)
        return self._store.reserve(
            network_key=network_key,
            request_key=request_key,
            now=checked_now,
        )

    def cleanup(self, *, now: datetime) -> int:
        return self._store.cleanup(now=now)

    def complete(self, reservation: QuotaReservation, *, now: datetime) -> None:
        self._store.complete(reservation, now=now)

    def release(self, reservation: QuotaReservation) -> None:
        self._store.release(reservation)

    def refund(self, reservation: QuotaReservation) -> None:
        self._store.refund(reservation)

    def release_many(self, reservations: tuple[QuotaReservation, ...]) -> None:
        self._store.release_many(reservations)

    def _key(self, purpose: str, day: date, value: str) -> str:
        body = f"smithguard-anonymous-{purpose}-v1\0{day.isoformat()}\0{value}".encode("ascii")
        return "sha256:" + hmac.new(self._secret, body, sha256).hexdigest()


def request_network(request: Request, *, trusted_proxy_header: bool = False) -> str:
    """Use exactly one Nginx-owned address only on the protected Unix boundary."""
    if trusted_proxy_header:
        forwarded = request.headers.get("x-forwarded-for")
        if not forwarded or "," in forwarded or forwarded != forwarded.strip():
            raise AnonymousNetworkIdentityError("forwarded network identity is invalid")
        try:
            candidate = ipaddress.ip_address(forwarded)
        except ValueError as error:
            raise AnonymousNetworkIdentityError("forwarded network identity is invalid") from error
        if isinstance(candidate, ipaddress.IPv6Address) and candidate.ipv4_mapped is not None:
            candidate = candidate.ipv4_mapped
        if not candidate.is_global:
            raise AnonymousNetworkIdentityError("forwarded network identity is not public")
    else:
        if request.client is None:
            raise AnonymousNetworkIdentityError("request network is unavailable")
        try:
            candidate = ipaddress.ip_address(request.client.host)
        except ValueError as error:
            raise AnonymousNetworkIdentityError("request network is invalid") from error
    if isinstance(candidate, ipaddress.IPv6Address) and candidate.ipv4_mapped is not None:
        candidate = candidate.ipv4_mapped
    if isinstance(candidate, ipaddress.IPv4Address):
        return f"ipv4:{candidate.compressed}"
    network = ipaddress.IPv6Network((candidate, 64), strict=False)
    return f"ipv6:{network.compressed}"


def quota_error_detail(reservation: QuotaReservation) -> dict[str, Any]:
    return {
        "reset_at": timestamp(reservation.reset_at),
        "daily_success_limit": DAILY_SUCCESS_LIMIT,
    }


def _aware(value: datetime) -> datetime:
    try:
        return require_aware_utc(value)
    except ValueError as error:
        raise AnonymousQuotaError("anonymous quota time must be timezone-aware") from error
