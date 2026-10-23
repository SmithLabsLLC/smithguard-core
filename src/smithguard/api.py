"""FastAPI application for the explicitly allowlisted SmithGuard public beta."""

import asyncio
import json
import logging
import sys
from collections import Counter
from collections.abc import AsyncIterator, Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, suppress
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from functools import cache, partial
from importlib.resources import files
from pathlib import Path as FilePath
from threading import Event
from time import monotonic
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from sqlalchemy import event, text
from sqlalchemy.orm import Session

from smithguard import __version__
from smithguard.anonymous_quota import (
    DAILY_SUCCESS_LIMIT,
    AnonymousAssessmentQuota,
    AnonymousNetworkIdentityError,
    AnonymousQuotaError,
    AnonymousQuotaStore,
    QuotaReservation,
    quota_error_detail,
)
from smithguard.api_pressure import PRESSURE_INTERVAL_SECONDS, ApiPressure, write_pressure
from smithguard.assessment_cache import (
    CACHE_MAINTENANCE_SECONDS,
    AssessmentCacheCapacityError,
    AssessmentResponseCache,
    active_warning_expiry,
    assessment_watermark,
)
from smithguard.bulletin_api import register as register_bulletin_routes
from smithguard.coverage import CoverageReportUnavailable
from smithguard.emerging_leads import public_page as emerging_lead_page
from smithguard.emerging_leads import publication_enabled
from smithguard.feeds import SnapshotSigner
from smithguard.hosted_mcp import MCP_PATH, MCP_TRANSPORT_METHODS, HostedMCP
from smithguard.operational_health import public_readiness
from smithguard.service import NotFound, ServiceError, SmithGuardService
from smithguard.snapshot_archive import SnapshotArchive

# Canonical public API host and the previous production host it replaced.
PUBLIC_API_HOSTS = ("api.smithguard.io", "guard.smithlabs.ai")

LOGGER = logging.getLogger(__name__)

PUBLIC_ASSESSMENT_CONCURRENCY = 8
PUBLIC_ASSESSMENT_MAX_REQUEST_BYTES = 8192
PUBLIC_ASSESSMENT_TIMEOUT_SECONDS = 10.0
PUBLIC_ASSESSMENT_CACHE_MAX_AGE = timedelta(minutes=5)
PUBLIC_ASSESSMENT_CACHE_MAX_ENTRIES = 10_000
PUBLIC_BETA_ACTIVE_ROUTE_ALLOWLIST = frozenset(
    {
        ("GET", "/"),
        ("GET", "/healthz"),
        ("GET", "/readyz"),
        ("GET", "/openapi.json"),
        ("GET", "/v1/coverage.json"),
        ("GET", "/v1/emerging-leads.json"),
        ("GET", "/v1/public-key.json"),
        ("GET", "/v1/bulletins.json"),
        ("GET", "/v1/bulletins/{identity}.json"),
        ("GET", "/v1/bulletin-events.json"),
        ("GET", "/v1/bulletin-status.json"),
        ("GET", "/v1/bulletins.atom"),
        ("GET", "/v1/public-keys/{public_key_id}.json"),
        ("POST", "/v1/artifacts/assess"),
        ("GET", "/v1/artifacts/assess"),
    }
)
# The short request fields, also accepted as query parameters on the GET form.
ASSESSMENT_QUERY_FIELDS = frozenset({"ecosystem", "name", "version", "digest", "registry_host"})
PUBLIC_BETA_ROUTE_ALLOWLIST = PUBLIC_BETA_ACTIVE_ROUTE_ALLOWLIST


@cache
def _openapi_bytes() -> bytes:
    """The generated contract, read once per process."""
    resource = files("smithguard.generated_artifacts").joinpath("openapi-public-beta.json")
    return resource.read_bytes()


def _generated_public_beta_openapi() -> dict[str, Any]:
    return json.loads(_openapi_bytes())


def _service_error(
    error: ServiceError,
    *,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={
            "error": {
                "code": error.code,
                "message": str(error),
                "retryable": error.retryable,
            }
        },
        headers=headers,
    )


class RequestRejected(Exception):
    """A caller error found while reading or validating the request."""

    def __init__(self, code: str, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code

    def response(self, headers: dict[str, str]) -> JSONResponse:
        return _error_response(
            status_code=self.status_code,
            code=self.code,
            message=self.message,
            retryable=False,
            headers=headers,
        )


def _contract_message(error: ValueError) -> str:
    """A bounded message naming where the request broke the contract (JSON pointer)."""
    cause = error.__cause__
    path = getattr(cause, "absolute_path", None)
    if path is not None:
        pointer = "/" + "/".join(str(part) for part in path) if path else ""
        validator = getattr(cause, "validator", "value")
        return f"request does not match the public contract at '{pointer}' ({validator})"
    code = str(error)
    if code and code.replace("_", "").isalnum() and len(code) <= 80:
        return code  # normalization reason codes such as invalid_artifact_name
    return "request does not match the public contract"


USAGE_REPORT_SECONDS = 900
# Below the five-minute report age, so a current report always exists.
COVERAGE_REFRESH_SECONDS = 240
COVERAGE_BUILD_SECONDS = 20.0
COVERAGE_RETRY_SECONDS = 5.0


class UsageCounts:
    """Privacy-safe usage counts: route template, method and status only (no address,
    coordinate or query). A summary line per combination goes to the service log every
    15 minutes, so the owner can see whether the API is used."""

    def __init__(self) -> None:
        self.counts: Counter[tuple[str, str, int]] = Counter()
        self.pressure = ApiPressure()

    def report(self) -> list[str]:
        lines = [
            f"api_usage route={route} method={method} status={status} count={count}"
            for (route, method, status), count in sorted(self.counts.items())
        ]
        self.counts.clear()
        return lines


class UsageCounter:
    """ASGI middleware that adds each finished request to ``UsageCounts``."""

    def __init__(self, app: Any, *, usage: UsageCounts) -> None:
        self.app = app
        self.usage = usage

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        status = [0]
        started = self.usage.pressure.clock()
        method = str(scope.get("method", ""))  # before HEAD handling rewrites it

        disconnected = False

        async def observe_receive() -> dict[str, Any]:
            nonlocal disconnected
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
            return message

        async def observe(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status[0] = int(message["status"])
            await send(message)

        try:
            await self.app(scope, observe_receive, observe)
        except Exception:
            # The outer handler answers unhandled errors with the generic 503.
            status[0] = status[0] or 503
            raise
        finally:
            route = scope.get("route")
            template = getattr(route, "path", None) or "unmatched"
            self.usage.counts[(template, method, status[0])] += 1
            if template == "/v1/artifacts/assess":
                elapsed = self.usage.pressure.clock() - started
                processing = scope.get("smithguard_processing_started")
                if not disconnected:
                    self.usage.pressure.observe(status=status[0], seconds=elapsed)
                elif processing is not None:
                    elapsed = self.usage.pressure.clock() - processing
                    if elapsed >= 2:
                        self.usage.pressure.observe(status=0, seconds=elapsed)


class HeadAsGet:
    """Answer HEAD like GET without a body, for read-only routes only.

    The assessment route is excluded: its GET form counts against the caller's quota,
    so HEAD there stays 405.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("method") != "HEAD"
            or scope.get("path") in {"/v1/artifacts/assess", MCP_PATH}
        ):
            await self.app(scope, receive, send)
            return

        async def send_headers_only(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.body":
                if message.get("more_body", False):
                    return
                message = {"type": "http.response.body", "body": b"", "more_body": False}
            await send(message)

        # A copy: the server and the outer error handler must still see HEAD (so an
        # error answer is sent without a body). Only the resolved route is copied back,
        # for usage counting.
        inner = {**scope, "method": "GET"}
        try:
            await self.app(inner, receive, send_headers_only)
        finally:
            if "route" in inner:
                scope["route"] = inner["route"]


def _error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    retryable: bool,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "retryable": retryable,
            }
        },
        headers=headers,
    )


def _quota_rejection_response(
    *,
    status: str,
    reset_at: str,
    headers: dict[str, str],
    retry_after_seconds: int | None = None,
) -> JSONResponse:
    if status == "in_progress":
        status_code = 409
        code = "assessment_in_progress"
        message = "An identical anonymous assessment is already in progress."
    elif status == "burst":
        status_code = 429
        code = "anonymous_burst_limit_exceeded"
        message = f"Anonymous assessment burst limit exceeded. Try again after {reset_at}."
    else:
        status_code = 429
        code = "anonymous_daily_limit_exceeded"
        message = (
            f"{DAILY_SUCCESS_LIMIT} distinct successful checks per network address "
            "per UTC day have been used. "
            f"Try again after {reset_at}."
        )
    return _error_response(
        status_code=status_code,
        code=code,
        message=message,
        retryable=True,
        headers={
            **headers,
            "X-SmithGuard-Quota-Reset": reset_at,
            # Standard HTTP retry hint, in seconds.
            **(
                {"Retry-After": str(max(1, retry_after_seconds))}
                if retry_after_seconds is not None
                else {}
            ),
        },
    )


def _is_json_media_type(value: str | None) -> bool:
    if value is None:
        return False
    media_type = value.split(";", 1)[0].strip().lower()
    return media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Keep the public decoder's existing validation order and error messages. The
    # strict provider loader has different bounds and constant handling.
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("request contains a duplicate JSON key")
        value[key] = item
    return value


class _PublicAssessmentRuntime:
    """Own bounded readers, request tasks, quota cleanup and cache lifetime."""

    def __init__(
        self,
        *,
        service: SmithGuardService,
        anonymous_quota: AnonymousAssessmentQuota,
        local_clock: Callable[[], datetime],
        session_factory: Callable[[], Session],
        response_headers: dict[str, str],
        pressure_path: FilePath | None = None,
    ) -> None:
        self.service = service
        self.anonymous_quota = anonymous_quota
        self.local_clock = local_clock
        self.session_factory = session_factory
        self.response_headers = response_headers
        self.assessment_slots = asyncio.Semaphore(PUBLIC_ASSESSMENT_CONCURRENCY)
        self.watermark_slots = asyncio.Semaphore(1)
        self.bulletin_slots = asyncio.Semaphore(2)
        self.bulletin_executor = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="smithguard-bulletin-read"
        )
        self.bulletin_read_waiters = 0
        self.max_bulletin_requests = 16
        self.watermark_executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="smithguard-assessment-visibility",
        )
        self.assessment_executor = ThreadPoolExecutor(
            max_workers=PUBLIC_ASSESSMENT_CONCURRENCY,
            thread_name_prefix="smithguard-public-assessment",
        )
        self.quota_executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="smithguard-anonymous-quota",
        )
        self.assessment_responses = AssessmentResponseCache(
            max_inflight=2 * PUBLIC_ASSESSMENT_CONCURRENCY,
        )
        self.max_requests = 16 * PUBLIC_ASSESSMENT_CONCURRENCY
        self.owned_requests: dict[asyncio.Task[Response], Event] = {}
        self.pending_releases: list[tuple[QuotaReservation, asyncio.Future[None]]] = []
        self.release_drainer: asyncio.Task[None] | None = None
        self.bounded_read_waiters = 0
        self.closing = False
        self.coverage_ready = asyncio.Event()
        self.usage = UsageCounts()
        self.pressure_path = pressure_path

    async def drain_releases(self) -> None:
        loop = asyncio.get_running_loop()
        # Coalesce owners released in the same loop turn. During an SQLite lock
        # wait, further cancellations join the next batch instead of each adding
        # another five-second busy wait to shutdown.
        await asyncio.sleep(0)
        while self.pending_releases:
            batch = tuple(self.pending_releases)
            self.pending_releases.clear()
            reservations = tuple(reservation for reservation, _future in batch)
            try:
                await asyncio.shield(
                    loop.run_in_executor(
                        self.quota_executor, self.anonymous_quota.release_many, reservations
                    )
                )
            except Exception as error:
                for _reservation, future in batch:
                    future.set_exception(error)
            else:
                for _reservation, future in batch:
                    future.set_result(None)
            await asyncio.sleep(0)

    async def refund_owned(self, reservation: Any) -> None:
        """Uncount a completed check whose answer never reached the caller."""
        if reservation is None or self.anonymous_quota is None:
            return
        loop = asyncio.get_running_loop()
        try:
            await asyncio.shield(
                loop.run_in_executor(self.quota_executor, self.anonymous_quota.refund, reservation)
            )
        except Exception as error:
            LOGGER.error("Anonymous quota refund failed type=%s", type(error).__name__)

    async def release_owned(self, reservation: QuotaReservation) -> None:
        future = asyncio.get_running_loop().create_future()
        self.pending_releases.append((reservation, future))
        if self.release_drainer is None or self.release_drainer.done():
            self.release_drainer = asyncio.create_task(self.drain_releases())
        await asyncio.shield(future)

    async def run_bounded(
        self,
        operation: Callable[[], Any],
        *,
        deadline: float | None = None,
        metadata: bool = False,
        bulletin: bool = False,
    ) -> Any:
        counter = "bulletin_read_waiters" if bulletin else "bounded_read_waiters"
        limit = self.max_bulletin_requests if bulletin else self.max_requests
        if self.closing or getattr(self, counter) >= limit:
            raise AssessmentCacheCapacityError("public read work is at capacity")
        setattr(self, counter, getattr(self, counter) + 1)
        loop = asyncio.get_running_loop()
        absolute_deadline = deadline or (loop.time() + PUBLIC_ASSESSMENT_TIMEOUT_SECONDS)
        slots = self.watermark_slots if metadata else self.assessment_slots
        executor = self.watermark_executor if metadata else self.assessment_executor
        if bulletin:
            slots, executor = self.bulletin_slots, self.bulletin_executor
        acquired = False
        try:
            async with asyncio.timeout_at(absolute_deadline):
                await slots.acquire()
                acquired = True
                future = loop.run_in_executor(executor, operation)
                acquired = False

                def release_slot(_future: asyncio.Future[Any]) -> None:
                    if not _future.cancelled():
                        # A timed-out caller no longer awaits the read, but the
                        # retained worker callback still consumes its outcome.
                        _future.exception()
                    with suppress(RuntimeError):
                        loop.call_soon_threadsafe(slots.release)

                future.add_done_callback(release_slot)
                return await asyncio.shield(future)
        finally:
            setattr(self, counter, getattr(self, counter) - 1)
            if acquired:
                slots.release()

    async def maintain_cache(self) -> None:
        while True:
            await asyncio.sleep(CACHE_MAINTENANCE_SECONDS)
            self.assessment_responses.expire(now=self.local_clock())

    async def maintain_quota(self) -> None:
        while True:
            try:
                pending = asyncio.get_running_loop().run_in_executor(
                    self.quota_executor,
                    partial(self.anonymous_quota.cleanup, now=self.local_clock()),
                )
                try:
                    await asyncio.shield(pending)
                except asyncio.CancelledError:
                    with suppress(Exception):
                        await pending
                    raise
            except Exception as error:
                LOGGER.error("Anonymous quota maintenance failed type=%s", type(error).__name__)
            await asyncio.sleep(1)

    async def build_coverage(self) -> None:
        """Own one background database build until it closes, including on cancel.

        SQL retains the ten-second statement limit. A monotonic total budget is
        checked between statements and before publication; cancellation stops at
        the next boundary, rather than abandoning a thread with a live session.
        """
        stopped = Event()
        deadline = monotonic() + COVERAGE_BUILD_SECONDS

        def checkpoint(*_arguments: Any) -> None:
            if stopped.is_set() or monotonic() >= deadline:
                raise TimeoutError("coverage build stopped")

        def rebuild() -> None:
            checkpoint()
            with self.session_factory() as session:
                connection = session.connection()
                checkpoint()
                if connection.dialect.name == "postgresql":
                    connection.execute(text("SET LOCAL statement_timeout = '10000ms'"))
                    connection.execute(text("SET LOCAL lock_timeout = '5000ms'"))
                event.listen(connection, "before_cursor_execute", checkpoint)
                event.listen(connection, "after_cursor_execute", checkpoint)
                try:
                    self.service.refresh_coverage(session, checkpoint=checkpoint)
                finally:
                    event.remove(connection, "before_cursor_execute", checkpoint)
                    event.remove(connection, "after_cursor_execute", checkpoint)

        pending = asyncio.create_task(asyncio.to_thread(rebuild))
        try:
            await asyncio.shield(pending)
        except asyncio.CancelledError:
            stopped.set()
            # Repeated cancellation must not discard ownership of the DB worker.
            while not pending.done():
                with suppress(asyncio.CancelledError, Exception):
                    await asyncio.shield(pending)
            with suppress(Exception):
                pending.result()
            raise

    async def refresh_coverage(self) -> None:
        """Build immediately, retry initial failures, then refresh before expiry."""
        while True:
            delay = COVERAGE_REFRESH_SECONDS
            try:
                await self.build_coverage()
            except Exception as error:
                LOGGER.error("Coverage refresh failed type=%s", type(error).__name__)
                delay = COVERAGE_RETRY_SECONDS
            else:
                self.coverage_ready.set()
            await asyncio.sleep(delay)

    async def report_usage(self) -> None:
        while True:
            await asyncio.sleep(USAGE_REPORT_SECONDS)
            self.write_usage()

    def write_usage(self) -> None:
        for line in self.usage.report():
            sys.stderr.write(line + "\n")

    async def report_pressure(self) -> None:
        while True:
            if self.pressure_path is not None:
                try:
                    document = self.usage.pressure.document(now=self.local_clock())
                    await asyncio.to_thread(write_pressure, self.pressure_path, document)
                except (OSError, ValueError):
                    LOGGER.error("API pressure heartbeat could not be written")
            await asyncio.sleep(PRESSURE_INTERVAL_SECONDS)

    @asynccontextmanager
    async def lifespan(self, _application: FastAPI) -> AsyncIterator[None]:
        maintenance = asyncio.create_task(self.maintain_cache())
        usage = asyncio.create_task(self.report_usage())
        coverage = asyncio.create_task(self.refresh_coverage())
        pressure = asyncio.create_task(self.report_pressure())
        quota_maintenance = asyncio.create_task(self.maintain_quota())
        try:
            # Health and static routes remain available while the owned initial
            # build runs. Data routes refuse work until its first publication.
            yield
        finally:
            self.closing = True
            for task in (usage, coverage, pressure, quota_maintenance):
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
            self.write_usage()
            for stopped in tuple(self.owned_requests.values()):
                stopped.set()
            # Running quota operations retain an owner through their eventual
            # result and cleanup. Never cancel their executor futures at shutdown.
            if self.owned_requests:
                await asyncio.gather(*tuple(self.owned_requests), return_exceptions=True)
            if self.release_drainer is not None:
                await self.release_drainer
            maintenance.cancel()
            with suppress(asyncio.CancelledError):
                await maintenance
            self.assessment_responses.clear()
            self.assessment_executor.shutdown(wait=False, cancel_futures=True)
            self.watermark_executor.shutdown(wait=False, cancel_futures=True)
            self.bulletin_executor.shutdown(wait=False, cancel_futures=True)
            self.quota_executor.shutdown(wait=True, cancel_futures=False)

    def deadline_response(self) -> Response:
        return _error_response(
            status_code=503,
            code="request_deadline_exceeded",
            message="request exceeded its fixed processing deadline",
            retryable=True,
            headers=self.response_headers,
        )

    def capacity_response(self) -> Response:
        return _error_response(
            status_code=503,
            code="service_capacity_exceeded",
            message="public assessment work is at capacity",
            retryable=True,
            headers=self.response_headers,
        )

    async def assess_public_artifact(self, request: Request) -> Response:
        return await self._assess(request, query=False)

    async def assess_public_artifact_by_query(self, request: Request) -> Response:
        return await self._assess(request, query=True)

    async def _assess(self, request: Request, *, query: bool) -> Response:
        if self.closing or len(self.owned_requests) >= self.max_requests:
            return self.capacity_response()
        if not self.coverage_ready.is_set():
            raise CoverageReportUnavailable("initial coverage is not ready")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + PUBLIC_ASSESSMENT_TIMEOUT_SECONDS
        stopped = Event()
        # Set by the work, with no await after its last stopped check, once its answer
        # is committed: the caller then gets that answer even if cleanup crosses the
        # deadline, so a counted check never turns into a 503.
        answer_ready = asyncio.Event()
        work = asyncio.create_task(
            self.assessment_work(
                request,
                deadline=deadline,
                stopped=stopped,
                query=query,
                answer_ready=answer_ready,
            )
        )
        self.owned_requests[work] = stopped

        def finished(task: asyncio.Task[Response]) -> None:
            self.owned_requests.pop(task, None)
            if not task.cancelled():
                error = task.exception()
                if error is not None:
                    if isinstance(error, CoverageReportUnavailable):
                        LOGGER.info("Owned assessment unavailable type=%s", type(error).__name__)
                    else:
                        LOGGER.error("Owned assessment failed type=%s", type(error).__name__)

        work.add_done_callback(finished)
        try:
            async with asyncio.timeout_at(deadline):
                return await asyncio.shield(work)
        except TimeoutError:
            # An answer that finished (or committed) as the deadline fired is
            # delivered, never a 503; only cleanup can remain, which is bounded.
            if work.done() and not work.cancelled() and work.exception() is None:
                return work.result()
            if answer_ready.is_set():
                return await asyncio.shield(work)
            # Otherwise the owned work sees ``stopped`` and refunds a counted check.
            stopped.set()
            return self.deadline_response()
        except asyncio.CancelledError:
            stopped.set()
            raise

    async def read_request_body(self, request: Request, *, deadline: float) -> bytes | Response:
        if not _is_json_media_type(request.headers.get("content-type")):
            return _error_response(
                status_code=415,
                code="unsupported_media_type",
                message="request content type must be JSON",
                retryable=False,
                headers=self.response_headers,
            )
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                parsed_content_length = int(content_length)
                if (
                    parsed_content_length < 0
                    or parsed_content_length > PUBLIC_ASSESSMENT_MAX_REQUEST_BYTES
                ):
                    raise OverflowError
            except (ValueError, OverflowError):
                return _error_response(
                    status_code=413,
                    code="request_limit_exceeded",
                    message="request exceeds its fixed byte limit",
                    retryable=False,
                    headers=self.response_headers,
                )
        collected = bytearray()
        try:
            async with asyncio.timeout_at(deadline):
                async for chunk in request.stream():
                    if len(collected) + len(chunk) > PUBLIC_ASSESSMENT_MAX_REQUEST_BYTES:
                        return _error_response(
                            status_code=413,
                            code="request_limit_exceeded",
                            message="request exceeds its fixed byte limit",
                            retryable=False,
                            headers=self.response_headers,
                        )
                    collected.extend(chunk)
        except TimeoutError:
            return _error_response(
                status_code=503,
                code="request_deadline_exceeded",
                message="request exceeded its fixed processing deadline",
                retryable=True,
                headers=self.response_headers,
            )
        return bytes(collected)

    def _validated_request(
        self, body: bytes, request: Request, query: bool
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Parse and validate the caller's request; every failure is a 400 that names
        the problem (and the JSON pointer of a contract mismatch), never stored data."""
        try:
            if query:
                document: Any = _query_document(request)
            else:
                document = json.loads(body, object_pairs_hook=_reject_duplicate_json_keys)
        except ServiceError as error:
            raise RequestRejected(error.code, str(error)) from error
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RequestRejected("invalid_request", "request body is not valid JSON") from error
        except ValueError as error:  # duplicate keys
            raise RequestRejected("invalid_request", str(error)[:200]) from error
        if not isinstance(document, dict):
            raise RequestRejected("invalid_request", "request must be a JSON object")
        try:
            parsed_request, identity = self.service.validate_public_artifact_request(document)
        except ServiceError as error:
            raise RequestRejected(error.code, str(error), status_code=error.status_code) from error
        except ValueError as error:
            raise RequestRejected("invalid_request", _contract_message(error)) from error
        return parsed_request, identity, document

    async def assessment_work(
        self,
        request: Request,
        *,
        deadline: float,
        stopped: Event,
        query: bool = False,
        answer_ready: asyncio.Event | None = None,
    ) -> Response:
        loop = asyncio.get_running_loop()

        def check_active() -> None:
            if stopped.is_set() or loop.time() >= deadline:
                raise TimeoutError

        async def observe_disconnect() -> None:
            while True:
                message = await request.receive()
                if message["type"] == "http.disconnect":
                    stopped.set()
                    return

        def read_watermark() -> str:
            with self.session_factory() as session:
                # Cached assessments also require a current coverage report.
                # API services cannot rebuild it from this request worker.
                self.service.get_source_coverage(session)
                return assessment_watermark(session)

        body = b"" if query else await self.read_request_body(request, deadline=deadline)
        if isinstance(body, Response):
            return body
        quota_reservation = None
        quota_completed = False
        singleflight_identity = None
        singleflight_leader = False
        pending = None
        disconnect = asyncio.create_task(observe_disconnect())
        try:
            check_active()
            try:
                parsed_request, identity, document = self._validated_request(body, request, query)
            except RequestRejected as rejection:
                return rejection.response(self.response_headers)
            request.scope["smithguard_processing_started"] = self.usage.pressure.clock()
            singleflight_identity = identity
            while True:
                check_active()
                watermark = await self.run_bounded(read_watermark, deadline=deadline, metadata=True)
                check_active()
                cached, pending, singleflight_leader = self.assessment_responses.begin(
                    identity,
                    now=self.local_clock(),
                    watermark=watermark,
                    loop=loop,
                )
                if cached is not None:
                    projected = self.service.project_public_artifact_response(
                        cached, parsed_request
                    )
                    expiry = active_warning_expiry(projected)
                    if expiry is not None and self.local_clock() >= expiry:
                        continue
                    check_active()
                    return JSONResponse(
                        projected,
                        headers={
                            **self.response_headers,
                            "Cache-Control": "no-store",
                            "X-SmithGuard-Cache": "hit",
                        },
                    )
                if singleflight_leader:
                    break
                async with asyncio.timeout_at(deadline):
                    await asyncio.shield(pending)
            if self.anonymous_quota is not None:

                def reserve_quota() -> Any:
                    check_active()
                    return self.anonymous_quota.reserve(
                        request=request,
                        artifact_identity=identity,
                        now=self.local_clock(),
                    )

                quota_reservation = await asyncio.shield(
                    loop.run_in_executor(self.quota_executor, reserve_quota)
                )
                check_active()
                if quota_reservation.status in {"burst", "exhausted", "in_progress"}:
                    return _quota_rejection_response(
                        status=quota_reservation.status,
                        reset_at=quota_error_detail(quota_reservation)["reset_at"],
                        headers=self.response_headers,
                        retry_after_seconds=int(
                            (quota_reservation.reset_at - self.local_clock()).total_seconds()
                        ),
                    )

            def assess() -> tuple[dict[str, Any], str | None]:
                check_active()
                with self.session_factory() as session:
                    before = assessment_watermark(session)
                    response = self.service.assess_public_artifact(session, document)
                    after = assessment_watermark(session)
                    return response, before if before == after else None

            while True:
                result, result_watermark = await self.run_bounded(assess, deadline=deadline)
                check_active()
                result = self.service.project_public_artifact_response(result, parsed_request)
                expiry = active_warning_expiry(result)
                if expiry is None or self.local_clock() < expiry:
                    break

            if (
                quota_reservation is not None
                and quota_reservation.status == "reserved"
                and self.anonymous_quota is not None
            ):

                def complete_quota() -> None:
                    check_active()
                    self.anonymous_quota.complete(quota_reservation, now=self.local_clock())

                await asyncio.shield(loop.run_in_executor(self.quota_executor, complete_quota))
                quota_completed = True
            try:
                # Quota I/O can span a warning expiry. Recompute within the same
                # reservation/accounting result; never extend the warning's lifetime.
                while (
                    expiry := active_warning_expiry(result)
                ) is not None and self.local_clock() >= expiry:
                    result, result_watermark = await self.run_bounded(assess, deadline=deadline)
                    check_active()
                    result = self.service.project_public_artifact_response(result, parsed_request)
                if pending is None:
                    raise RuntimeError("assessment completion has no retained owner")
                self.assessment_responses.complete(
                    identity,
                    result,
                    owner=pending,
                    now=self.local_clock(),
                    watermark=result_watermark,
                )
                singleflight_leader = False
                # Finish the disconnect watcher first, so no await remains between this
                # check and the return (awaiting the finished task later does not
                # yield): either the caller gets this answer, or it already got a 503
                # and the check is refunded.
                disconnect.cancel()
                with suppress(asyncio.CancelledError):
                    await disconnect
                if stopped.is_set():
                    raise TimeoutError
                if answer_ready is not None:
                    answer_ready.set()
            except BaseException:
                # Any failure before the answer is committed (deadline, database,
                # capacity) uncounts the completed check: no answer, no charge.
                if quota_completed:
                    await self.refund_owned(quota_reservation)
                raise
            return JSONResponse(
                result,
                headers={**self.response_headers, "Cache-Control": "no-store"},
            )
        except AssessmentCacheCapacityError:
            return self.capacity_response()
        except AnonymousNetworkIdentityError:
            return _error_response(
                status_code=503,
                code="proxy_network_identity_invalid",
                message="trusted proxy network identity is invalid",
                retryable=False,
                headers=self.response_headers,
            )
        except AnonymousQuotaError:
            return _error_response(
                status_code=503,
                code="anonymous_quota_unavailable",
                message="anonymous assessment quota is temporarily unavailable",
                retryable=True,
                headers=self.response_headers,
            )
        except TimeoutError:
            return _error_response(
                status_code=503,
                code="request_deadline_exceeded",
                message="request exceeded its fixed processing deadline",
                retryable=True,
                headers=self.response_headers,
            )
        except ServiceError as error:
            return _service_error(error, headers=self.response_headers)
        except ValueError as error:
            # Past request validation, a value error is stored state, never the caller's
            # input: a fixed message, with only the error type in the log.
            LOGGER.error("Assessment state error type=%s", type(error).__name__)
            return _error_response(
                status_code=500,
                code="internal_state_error",
                message="stored public state could not be read",
                retryable=False,
                headers=self.response_headers,
            )
        finally:
            if (
                quota_reservation is not None
                and quota_reservation.status == "reserved"
                and not quota_completed
                and self.anonymous_quota is not None
            ):
                try:
                    await self.release_owned(quota_reservation)
                except Exception as error:
                    LOGGER.error("Anonymous quota cleanup failed type=%s", type(error).__name__)
            if singleflight_leader and singleflight_identity is not None and pending is not None:
                self.assessment_responses.abort(singleflight_identity, owner=pending)
            disconnect.cancel()
            with suppress(asyncio.CancelledError):
                await disconnect


def _query_document(request: Request) -> dict[str, str]:
    """The short request from query parameters: known fields, each at most once."""
    items = request.query_params.multi_items()
    keys = [key for key, _value in items]
    unknown = sorted(set(keys) - ASSESSMENT_QUERY_FIELDS)
    if unknown:
        raise ServiceError("unsupported query parameter: " + unknown[0][:40])
    if len(keys) != len(set(keys)):
        raise ServiceError("each query parameter may appear only once")
    return dict(items)


def _register_public_routes(
    local: FastAPI,
    *,
    session_factory: Callable[[], Session],
    local_clock: Callable[[], datetime],
    expected_governance_policy_sha256: str | None,
    runtime: _PublicAssessmentRuntime,
    signer: SnapshotSigner,
    snapshot_archive: SnapshotArchive | None,
    revoked_public_key_ids: frozenset[str],
    service: SmithGuardService,
    response_headers: dict[str, str],
) -> None:
    run_bounded = runtime.run_bounded
    register_bulletin_routes(
        local,
        session_factory=session_factory,
        clock=local_clock,
        run_bounded=partial(run_bounded, bulletin=True),
        headers=response_headers,
    )

    @local.get("/")
    def quick_start() -> Response:
        return JSONResponse(
            {
                "name": "SmithGuard",
                "state": "public-beta",
                "description": ("Evidence-first software supply-chain incident intelligence."),
                "quick_start": {
                    "assess_artifact": "/v1/artifacts/assess",
                    "public_key": "/v1/public-key.json",
                    "coverage": "/v1/coverage.json",
                    "emerging_leads": "/v1/emerging-leads.json",
                    "bulletins": "/v1/bulletins.json",
                    "bulletin_status": "/v1/bulletin-status.json",
                    "openapi": "/openapi.json",
                },
                "access": (
                    "Anonymous results are limited to the exact public package "
                    "coordinate in each assessment request."
                ),
            },
            headers=response_headers,
        )

    @local.get("/healthz")
    def health() -> Response:
        return JSONResponse(
            {"status": "ok", "service_state": "public-beta"},
            headers=response_headers,
        )

    @local.get("/readyz")
    async def ready() -> Response:
        if not runtime.coverage_ready.is_set():
            return _error_response(
                status_code=503,
                code="service_not_ready",
                message="public data is not ready",
                retryable=True,
                headers=response_headers,
            )

        def readiness() -> tuple[bool, tuple[str, ...]]:
            with session_factory() as session:
                service.get_source_coverage(session)
                return public_readiness(
                    session,
                    measured_at=local_clock(),
                    expected_governance_policy_sha256=(expected_governance_policy_sha256),
                )

        try:
            is_ready, reasons = await run_bounded(readiness)
        except AssessmentCacheCapacityError:
            reason = "read_capacity"
        except TimeoutError:
            reason = "readiness_timeout"
        except CoverageReportUnavailable:
            reason = "coverage_unavailable"
        except Exception:
            reason = "database_unavailable"
        else:
            reason = None
        if reason is None and not is_ready:
            reason = ",".join(reasons)
        if reason is not None:
            # Internal reason codes stay in the service log, not the public answer.
            LOGGER.warning("Public readiness failed reasons=%s", reason)
            return _error_response(
                status_code=503,
                code="service_not_ready",
                message="public data is not ready",
                retryable=True,
                headers=response_headers,
            )
        return JSONResponse(
            {"status": "ready", "service_state": "public-beta"},
            headers=response_headers,
        )

    @local.get("/v1/public-key.json")
    async def public_key() -> Response:
        document = await run_bounded(signer.public_key_document)
        return JSONResponse(
            document,
            headers={
                **response_headers,
                "Cache-Control": "public, max-age=3600",
            },
        )

    @local.get("/v1/public-keys/{public_key_id}.json")
    async def archived_public_key(
        public_key_id: str = Path(
            pattern=r"^gbsec:snapshot-public-key:[a-f0-9]{40}$",
            max_length=160,
        ),
    ) -> Response:
        def load_public_key() -> dict[str, Any] | None:
            if public_key_id == signer.public_key_id:
                return signer.public_key_document()
            if snapshot_archive is None:
                return None
            archived = snapshot_archive.public_key_document(public_key_id)
            if archived is None:
                return None
            return {
                **archived,
                "status": (
                    "revoked" if public_key_id in revoked_public_key_ids else "verification_only"
                ),
            }

        document = await run_bounded(load_public_key)
        if document is None:
            return _service_error(
                NotFound("public key is not available"),
                headers=response_headers,
            )
        return JSONResponse(
            document,
            headers={
                **response_headers,
                "Cache-Control": "public, max-age=3600",
            },
        )

    @local.get("/openapi.json")
    def public_openapi() -> Response:
        return Response(
            _openapi_bytes(),
            media_type="application/json",
            headers={
                **response_headers,
                "Cache-Control": "public, max-age=3600",
            },
        )

    @local.get("/v1/emerging-leads.json")
    async def emerging_leads(
        limit: int = Query(25, ge=1, le=100),
        after: str | None = Query(None, pattern="^[a-f0-9]{64}$"),
    ) -> Response:
        def load_leads() -> dict[str, Any]:
            with session_factory() as session:
                return emerging_lead_page(session, now=local_clock(), limit=limit, after=after)

        report = await run_bounded(load_leads)
        return JSONResponse(report, headers={**response_headers, "Cache-Control": "no-store"})

    @local.get("/v1/coverage.json")
    async def coverage() -> Response:
        if not runtime.coverage_ready.is_set():
            raise CoverageReportUnavailable("initial coverage is not ready")

        def load_coverage() -> dict[str, Any]:
            with session_factory() as session:
                return service.get_source_coverage(session)

        report = await run_bounded(load_coverage)
        return JSONResponse(
            report,
            headers={
                **response_headers,
                "Cache-Control": "public, max-age=300, stale-if-error=3600",
            },
        )


def _register_public_errors(local: FastAPI, response_headers: dict[str, str]) -> None:

    @local.exception_handler(CoverageReportUnavailable)
    async def coverage_temporarily_unavailable(
        _request: Request, _error: CoverageReportUnavailable
    ) -> Response:
        return _error_response(
            status_code=503,
            code="service_unavailable",
            message="Source coverage is temporarily unavailable.",
            retryable=True,
            headers=response_headers,
        )

    @local.exception_handler(404)
    async def unknown_public_route(_request: Request, _error: Exception) -> Response:
        return _error_response(
            status_code=404,
            code="not_found",
            message="The requested route is not available.",
            retryable=False,
            headers=response_headers,
        )

    @local.exception_handler(405)
    async def unsupported_public_method(_request: Request, _error: Exception) -> Response:
        return _error_response(
            status_code=405,
            code="method_not_allowed",
            message="The requested method is not available for this route.",
            retryable=False,
            headers=response_headers,
        )

    @local.exception_handler(Exception)
    async def unavailable_public_service(_request: Request, error: Exception) -> Response:
        LOGGER.error("Unhandled public exception type=%s", type(error).__name__)
        return _error_response(
            status_code=503,
            code="service_unavailable",
            message="The service is temporarily unavailable.",
            retryable=True,
            headers=response_headers,
        )


def create_public_beta_app(
    *,
    session_factory: Callable[[], Session],
    signer: SnapshotSigner,
    base_url: str,
    clock: Callable[[], datetime] | None = None,
    expected_governance_policy_sha256: str | None = None,
    snapshot_archive: SnapshotArchive | None = None,
    revoked_public_key_ids: frozenset[str] = frozenset(),
    anonymous_quota_store: AnonymousQuotaStore,
    anonymous_quota_secret: bytes,
    trusted_proxy_header: bool = False,
    pressure_path: FilePath | None = None,
) -> FastAPI:
    """Create the explicit read-only production beta surface."""
    publication_enabled()
    local_clock = clock or (lambda: datetime.now(UTC))
    if signer.public_key_id in revoked_public_key_ids:
        raise ValueError("the active snapshot signing key is revoked")
    service = SmithGuardService(
        clock=local_clock,
        expected_governance_policy_sha256=expected_governance_policy_sha256,
        signer=signer,
        build_coverage_on_miss=False,
    )
    anonymous_quota = AnonymousAssessmentQuota(
        secret=anonymous_quota_secret,
        store=anonymous_quota_store,
        trusted_proxy_header=trusted_proxy_header,
    )
    response_headers = {"X-SmithGuard-Service-State": "public-beta"}
    runtime = _PublicAssessmentRuntime(
        service=service,
        anonymous_quota=anonymous_quota,
        local_clock=local_clock,
        session_factory=session_factory,
        response_headers=response_headers,
        pressure_path=pressure_path,
    )

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        async with runtime.lifespan(application), hosted.server.session_manager.run():
            yield

    local = FastAPI(
        title="SmithGuard public beta",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        redirect_slashes=False,
        lifespan=lifespan,
    )
    allowed_host = urlsplit(base_url).hostname
    if allowed_host is None:
        raise ValueError("public beta base URL has no host")
    hosted = HostedMCP(
        local,
        contract=_generated_public_beta_openapi(),
        hosts={allowed_host, *PUBLIC_API_HOSTS},
        trusted_proxy_header=trusted_proxy_header,
    )
    transport_route = hosted.route()
    local.router.routes.append(transport_route)
    # Nginx normalizes every allowed public Host to the canonical one, but the process
    # must accept the canonical and legacy hosts whatever base URL its environment
    # still carries, so the host transition cannot 400 requests in either order.
    local.add_middleware(HeadAsGet)
    local.add_middleware(UsageCounter, usage=runtime.usage)
    local.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=sorted({allowed_host, *PUBLIC_API_HOSTS}),
    )

    @local.exception_handler(RequestValidationError)
    async def invalid_route_input(
        _request: Request,
        _error: RequestValidationError,
    ) -> JSONResponse:
        return _error_response(
            status_code=400,
            code="invalid_request",
            message="request parameters do not match the public contract",
            retryable=False,
            headers=response_headers,
        )

    local.post("/v1/artifacts/assess")(runtime.assess_public_artifact)
    local.get("/v1/artifacts/assess")(runtime.assess_public_artifact_by_query)

    _register_public_routes(
        local,
        session_factory=session_factory,
        local_clock=local_clock,
        expected_governance_policy_sha256=expected_governance_policy_sha256,
        runtime=runtime,
        signer=signer,
        snapshot_archive=snapshot_archive,
        revoked_public_key_ids=revoked_public_key_ids,
        service=service,
        response_headers=response_headers,
    )

    _register_public_errors(local, response_headers)

    actual_routes = frozenset(
        (method, route.path)
        for route in local.routes
        if isinstance(route, APIRoute)
        for method in route.methods
    )
    if actual_routes != PUBLIC_BETA_ROUTE_ALLOWLIST:
        raise RuntimeError("public beta route set differs from its explicit allowlist")
    if (
        transport_route.path != MCP_PATH
        or transport_route.methods != MCP_TRANSPORT_METHODS
        or any(
            route is not transport_route and not isinstance(route, APIRoute)
            for route in local.routes
        )
    ):
        raise RuntimeError("hosted MCP transport differs from its explicit allowlist")

    def openapi() -> dict[str, Any]:
        return deepcopy(_generated_public_beta_openapi())

    local.openapi = openapi  # type: ignore[method-assign]
    return local
