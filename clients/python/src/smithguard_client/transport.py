"""Serial, finite public reads with no environment credentials, redirects or cache."""

from __future__ import annotations

import asyncio
import hashlib
import random
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from threading import Event
from typing import Any

import httpx

from .discovery import POLICY_VERSION, artifact, coordinate_id
from .verification import (
    MAX_RESPONSE_BYTES,
    Verification,
    canonical,
    strict_json,
    verify_assessment,
)

API = "https://api.smithguard.io"
KEY_ID = re.compile(r"^gbsec:snapshot-public-key:[a-f0-9]{40}$")


@dataclass
class ReadFailure(Exception):
    reason: str
    stop_run: bool = False
    retry_after: str | None = None


def approved_coordinates(preview: dict[str, Any], approval: str) -> list[dict[str, Any]]:
    expected = hashlib.sha256(
        canonical({k: v for k, v in preview.items() if k != "approval_sha256"})
    ).hexdigest()
    if (
        approval != expected
        or preview.get("approval_sha256") != expected
        or preview.get("policy_version") != POLICY_VERSION
    ):
        raise ValueError("approval must match the exact current preview and policy")
    coordinates = preview["coordinates"]
    if not isinstance(coordinates, list) or len(coordinates) > 5000:
        raise ValueError("coordinate limit exceeded")
    seen = set()
    for value in coordinates:
        if artifact(value["name"], value["version"]) != value:
            raise ValueError("only exact normalized public PyPI coordinates allowed")
        identity = coordinate_id(value)
        if identity in seen:
            raise ValueError("preview coordinates must be unique")
        seen.add(identity)
    return coordinates


class PublicReader:
    def __init__(
        self,
        *,
        budget_seconds: float = 300,
        stopped: Event | None = None,
        _transport: httpx.AsyncBaseTransport | None = None,
        _clock: Callable[[], float] = time.monotonic,
        _sleep: Callable[[float], None] = time.sleep,
    ):
        if not 1 <= budget_seconds <= 3600:
            raise ValueError("budget must be 1..3600 seconds")
        self.clock = _clock
        self.sleep = _sleep
        self.deadline = self.clock() + budget_seconds
        self.stopped = stopped or Event()
        self.previous = -float("inf")
        self.keys: dict[str, tuple[bytes, datetime]] = {}
        self.transport = _transport
        self.key_response_time: datetime | None = None

    def close(self):
        # Each request has a fresh bounded transport scope; no cookies or sessions
        # are carried between requests. Only verified public key bytes stay in RAM.
        pass

    async def _single(self, path, params, limit, timeout):
        async with asyncio.timeout(timeout):
            async with (
                httpx.AsyncClient(
                    trust_env=False,
                    follow_redirects=False,
                    transport=self.transport,
                    timeout=timeout,
                    headers={
                        "User-Agent": "SmithGuardClient/0.1.0",
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                        "Cache-Control": "no-cache",
                    },
                ) as client,
                client.stream("GET", API + path, params=params) as response,
            ):
                if response.status_code == 429:
                    raise ReadFailure("quota_or_rate_limit", True)
                if response.status_code in {502, 503, 504}:
                    raise ReadFailure(
                        "temporary_service_failure", False, response.headers.get("Retry-After")
                    )
                if response.status_code != 200:
                    raise ReadFailure("http_error_" + str(response.status_code))
                if (
                    response.headers.get("Content-Type", "").split(";")[0].strip().lower()
                    != "application/json"
                ):
                    raise ReadFailure("unexpected_content_type")
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise ReadFailure("unexpected_content_encoding")
                length = response.headers.get("Content-Length")
                if length is not None:
                    try:
                        if not 0 <= int(length) <= limit:
                            raise ValueError("length bound")
                    except ValueError:
                        raise ReadFailure("response_byte_limit") from None
                if path.startswith("/v1/public-keys/"):
                    try:
                        date = parsedate_to_datetime(response.headers["Date"])
                        age = int(response.headers.get("Age", "0"))
                        apparent_age = (datetime.now(UTC) - date).total_seconds()
                        if (
                            date.utcoffset() is None
                            or age < 0
                            or not -30 <= apparent_age <= 300
                            or age > 300
                        ):
                            raise ValueError("stale key status headers")
                        self.key_response_time = datetime.now(UTC) - timedelta(
                            seconds=max(age, apparent_age, 0)
                        )
                    except KeyError, ValueError, TypeError, OverflowError:
                        raise ReadFailure("key_status_freshness_unqualified") from None
                chunks = bytearray()
                async for chunk in response.aiter_raw(chunk_size=65536):
                    self._remaining()
                    if len(chunks) + len(chunk) > limit:
                        raise ReadFailure("response_byte_limit")
                    chunks.extend(chunk)
                return bytes(chunks)

    def _remaining(self):
        if self.stopped.is_set():
            raise ReadFailure("cancelled", True)
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise ReadFailure("time_budget_exhausted", True)
        return remaining

    def _wait(self, seconds):
        if seconds >= self._remaining():
            raise ReadFailure("retry_does_not_fit_budget", True)
        until = self.clock() + seconds
        while self.clock() < until:
            self._remaining()
            self.sleep(min(0.1, until - self.clock()))

    def _read(self, path: str, *, params=None, limit=MAX_RESPONSE_BYTES) -> bytes:
        if path != "/v1/artifacts/assess" and not (
            path.startswith("/v1/public-keys/")
            and path.endswith(".json")
            and KEY_ID.fullmatch(path[len("/v1/public-keys/") : -5])
        ):
            raise ValueError("unapproved endpoint")
        for attempt in range(2):
            self._remaining()
            self._wait(max(0, 0.3 - (self.clock() - self.previous)))
            timeout = min(10, self._remaining())
            retry_after = None
            try:
                self.previous = self.clock()
                return asyncio.run(self._single(path, params, limit, timeout))
            except TimeoutError, httpx.TimeoutException, httpx.NetworkError:
                failure = ReadFailure("temporary_network_failure")
            except httpx.HTTPError:
                raise ReadFailure("http_protocol_failure") from None
            except ReadFailure as exc:
                failure = exc
                retry_after = exc.retry_after
            if (
                failure.stop_run
                or attempt
                or failure.reason not in {"temporary_service_failure", "temporary_network_failure"}
            ):
                raise failure
            delay = 1 + random.SystemRandom().uniform(0, 0.25)
            if retry_after is not None:
                try:
                    delay = max(delay, float(int(retry_after)))
                except ValueError, OverflowError:
                    try:
                        date = parsedate_to_datetime(retry_after)
                        if date.utcoffset() is None:
                            raise ValueError("timezone absent")
                        delay = max(delay, (date - datetime.now(UTC)).total_seconds())
                    except ValueError, TypeError, OverflowError:
                        raise ReadFailure("invalid_retry_after") from None
            self._wait(delay)
        raise AssertionError("bounded retry exhausted")

    def assess(self, coordinate: dict[str, Any]) -> Verification:
        # No local path, application, relationship, usage or exposure fact enters params.
        if artifact(coordinate["name"], coordinate["version"]) != coordinate:
            raise ValueError("invalid public coordinate")
        raw = self._read(
            "/v1/artifacts/assess",
            params={
                k: v
                for k, v in coordinate.items()
                if k in {"ecosystem", "registry_host", "name", "version"}
            },
        )
        try:
            body = strict_json(raw)
        except ValueError, UnicodeError, RecursionError:
            return verify_assessment(raw, expected_artifact=coordinate, key_raw=None)
        signature = body.get("signature")
        kid = signature.get("public_key_id") if isinstance(signature, dict) else None
        if not isinstance(kid, str) or KEY_ID.fullmatch(kid) is None:
            return verify_assessment(raw, expected_artifact=coordinate, key_raw=None)
        now = datetime.now(UTC)
        cached = self.keys.get(kid)
        if cached is None or (now - cached[1]).total_seconds() > 300:
            if kid not in self.keys and len(self.keys) >= 10:
                return verify_assessment(raw, expected_artifact=coordinate, key_raw=None)
            try:
                key = self._read("/v1/public-keys/" + kid + ".json", limit=16384)
            except ReadFailure as exc:
                if exc.stop_run:
                    raise
                return verify_assessment(raw, expected_artifact=coordinate, key_raw=None)
            if self.key_response_time is None:
                return verify_assessment(raw, expected_artifact=coordinate, key_raw=key)
            cached = (key, self.key_response_time)
            self.keys[kid] = cached
        return verify_assessment(
            raw,
            expected_artifact=coordinate,
            key_raw=cached[0],
            key_fetched_at=cached[1],
            now=datetime.now(UTC),
        )
