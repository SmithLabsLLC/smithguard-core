"""Cold startup cannot serve early or abandon its owned database build."""

from __future__ import annotations

import asyncio
import logging
from contextlib import nullcontext
from threading import Event
from time import monotonic

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

import smithguard.api as api_module
import smithguard.coverage as coverage_module
from smithguard.anonymous_quota import AnonymousQuotaStore
from smithguard.coverage import _COVERAGE_REPORT_CACHE, CoverageReportUnavailable

from .test_api_cache_ownership import _app, _completed, _pending
from .test_hosted_mcp import COORDINATE, HEADERS, call


def _app_and_runtime(database, monkeypatch, **arguments):
    instances = []
    original = api_module._PublicAssessmentRuntime

    def capture(**arguments):
        runtime = original(**arguments)
        instances.append(runtime)
        return runtime

    monkeypatch.setattr(api_module, "_PublicAssessmentRuntime", capture)
    app = _app(database, **arguments)
    return app, instances[0]


def _wait_ready(client, runtime):
    async def wait():
        await asyncio.wait_for(runtime.coverage_ready.wait(), 3)

    client.portal.call(wait)


def test_initial_background_build_keeps_health_live_and_data_refused(database, monkeypatch):
    entered, release = Event(), Event()
    original = coverage_module._build_coverage_report
    calls = 0

    def build(session, **arguments):
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(5)
        return original(session, **arguments)

    _COVERAGE_REPORT_CACHE.clear()
    store = AnonymousQuotaStore()
    monkeypatch.setattr(coverage_module, "_build_coverage_report", build)
    monkeypatch.setattr(api_module, "public_readiness", lambda *args, **kwargs: (True, ()))
    app, runtime = _app_and_runtime(database, monkeypatch, store=store)
    try:
        with TestClient(
            app,
            base_url="https://security.example",
            client=("127.0.0.1", 50000),
            headers={**HEADERS, "X-Forwarded-For": "8.8.8.8"},
        ) as client:
            assert entered.wait(3)
            started = monotonic()
            for path in ("/healthz", "/", "/openapi.json", "/v1/public-key.json"):
                assert client.get(path).status_code == 200
            for path in ("/readyz", "/v1/coverage.json"):
                assert client.get(path).status_code == 503
            assert client.post("/v1/artifacts/assess", json=COORDINATE).status_code == 503
            for name, arguments in (("get_coverage", {}), ("assess_public_artifact", COORDINATE)):
                result = call(client, name, arguments, modern=True).json()["result"]
                assert result["isError"] is True
                assert result["structuredContent"]["data"]["error"]["retryable"] is True
            assert monotonic() - started < 2
            assert _pending(store) == _completed(store) == 0
            assert not runtime.owned_requests
            # The service fallback also refuses a cold contender without queueing.
            with Session(database.engine) as session, pytest.raises(CoverageReportUnavailable):
                runtime.service.get_source_coverage(session)
            release.set()
            _wait_ready(client, runtime)
            assert client.get("/readyz").status_code == 200
            assert client.get("/v1/coverage.json").status_code == 200
            assert client.post("/v1/artifacts/assess", json=COORDINATE).status_code == 200
            assert _completed(store) == 1
            assert calls == 1
    finally:
        release.set()


def test_busy_cold_coverage_returns_retryable_http_without_waiting(database, monkeypatch):
    _COVERAGE_REPORT_CACHE.clear()
    app, runtime = _app_and_runtime(database, monkeypatch)
    with TestClient(app, base_url="https://security.example") as client:
        _wait_ready(client, runtime)
        _COVERAGE_REPORT_CACHE.clear()
        with _COVERAGE_REPORT_CACHE._build_lock:
            started = monotonic()
            response = client.get("/v1/coverage.json")
            assert response.status_code == 503
            assert response.json()["error"]["retryable"] is True
            assert monotonic() - started < 1


def test_failed_initial_build_keeps_health_live_and_retries_without_restart(database, monkeypatch):
    _COVERAGE_REPORT_CACHE.clear()
    failed, allow_success = Event(), Event()
    original = coverage_module._build_coverage_report
    logged = []
    monkeypatch.setattr(api_module, "COVERAGE_RETRY_SECONDS", 0.01)
    monkeypatch.setattr(api_module.LOGGER, "error", lambda *args: logged.append(args))

    def build(*args, **kwargs):
        if not allow_success.is_set():
            failed.set()
            raise RuntimeError("synthetic private database failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(coverage_module, "_build_coverage_report", build)
    app, runtime = _app_and_runtime(database, monkeypatch)
    with TestClient(app, base_url="https://security.example") as client:
        assert failed.wait(3)
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code == 503
        assert client.get("/v1/coverage.json").status_code == 503
        assert _COVERAGE_REPORT_CACHE.report is None
        allow_success.set()
        _wait_ready(client, runtime)
        assert client.get("/v1/coverage.json").status_code == 200
    assert runtime.closing and runtime.assessment_executor._shutdown
    assert runtime.quota_executor._shutdown
    assert not _COVERAGE_REPORT_CACHE._build_lock.locked()
    assert logged and all(
        args == ("Coverage refresh failed type=%s", "RuntimeError") for args in logged
    )


def test_cancelled_startup_drains_worker_and_never_publishes_late_report(database, monkeypatch):
    entered, release, finished = Event(), Event(), Event()
    original = coverage_module._build_coverage_report
    _COVERAGE_REPORT_CACHE.clear()
    app, runtime = _app_and_runtime(database, monkeypatch)

    def build(session, **arguments):
        entered.set()
        assert release.wait(3)
        try:
            return original(session, **arguments)
        finally:
            finished.set()

    monkeypatch.setattr(coverage_module, "_build_coverage_report", build)

    async def scenario():
        async def serve():
            async with app.router.lifespan_context(app):
                await asyncio.Event().wait()

        startup = asyncio.create_task(serve())
        assert await asyncio.to_thread(entered.wait, 3)
        startup.cancel()
        await asyncio.sleep(0.01)
        startup.cancel()
        await asyncio.sleep(0.01)
        assert not startup.done() and not finished.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(startup, 3)
        assert finished.is_set()
        assert _COVERAGE_REPORT_CACHE.report is None
        assert not _COVERAGE_REPORT_CACHE._build_lock.locked()
        assert runtime.closing

    try:
        asyncio.run(scenario())
    finally:
        release.set()


def test_build_budget_rejects_late_sql_result_without_publishing(database, monkeypatch):
    _COVERAGE_REPORT_CACHE.clear()
    app, runtime = _app_and_runtime(database, monkeypatch)
    finished = Event()
    monkeypatch.setattr(api_module, "COVERAGE_BUILD_SECONDS", 0.05)

    def slow(session, **arguments):
        try:
            session.execute(text("SELECT pg_sleep(0.1)"))
            pytest.fail("expired build continued past its query boundary")
        finally:
            finished.set()

    monkeypatch.setattr(coverage_module, "_build_coverage_report", slow)
    with TestClient(app, base_url="https://security.example") as client:
        assert finished.wait(3)
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code == 503
        assert not runtime.coverage_ready.is_set()
    assert _COVERAGE_REPORT_CACHE.report is None
    assert not _COVERAGE_REPORT_CACHE._build_lock.locked()


def test_refresh_serves_prior_report_and_shutdown_drains_without_late_publish(
    database, monkeypatch
):
    entered, release, finished = Event(), Event(), Event()
    original = coverage_module._build_coverage_report
    calls = 0
    _COVERAGE_REPORT_CACHE.clear()
    app, runtime = _app_and_runtime(database, monkeypatch)
    monkeypatch.setattr(api_module, "COVERAGE_REFRESH_SECONDS", 0.01)

    def build(session, **arguments):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original(session, **arguments)
        entered.set()
        assert release.wait(3)
        try:
            return original(session, **arguments)
        finally:
            finished.set()

    monkeypatch.setattr(coverage_module, "_build_coverage_report", build)

    async def scenario():
        serving, stop = asyncio.Event(), asyncio.Event()

        async def serve():
            async with app.router.lifespan_context(app):
                await asyncio.wait_for(runtime.coverage_ready.wait(), 3)
                serving.set()
                await stop.wait()

        owner = asyncio.create_task(serve())
        await asyncio.wait_for(serving.wait(), 3)
        report = _COVERAGE_REPORT_CACHE.report
        assert await asyncio.to_thread(entered.wait, 3)
        with Session(database.engine) as session:
            assert runtime.service.get_source_coverage(session)["source_lanes"]
        assert calls == 2
        stop.set()
        await asyncio.sleep(0.02)
        assert not owner.done()
        release.set()
        await asyncio.wait_for(owner, 3)
        assert finished.is_set()
        assert _COVERAGE_REPORT_CACHE.report is report
        assert not _COVERAGE_REPORT_CACHE._build_lock.locked()

    try:
        asyncio.run(scenario())
    finally:
        release.set()


def test_failed_refresh_retains_previous_report_and_next_refresh_recovers(database, monkeypatch):
    original = coverage_module._build_coverage_report
    calls = 0
    recovered = Event()
    _COVERAGE_REPORT_CACHE.clear()
    app, runtime = _app_and_runtime(database, monkeypatch)
    monkeypatch.setattr(api_module, "COVERAGE_REFRESH_SECONDS", 0.01)
    monkeypatch.setattr(api_module, "COVERAGE_RETRY_SECONDS", 0.01)

    def build(session, **arguments):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("synthetic later refresh failure")
        result = original(session, **arguments)
        if calls == 3:
            recovered.set()
        return result

    monkeypatch.setattr(coverage_module, "_build_coverage_report", build)

    async def scenario():
        async with app.router.lifespan_context(app):
            await asyncio.wait_for(runtime.coverage_ready.wait(), 3)
            assert await asyncio.to_thread(recovered.wait, 3)
            with Session(database.engine) as session:
                assert runtime.service.get_source_coverage(session)["source_lanes"]
        assert calls >= 3
        assert not _COVERAGE_REPORT_CACHE._build_lock.locked()

    asyncio.run(scenario())


@pytest.mark.parametrize("transport", ["rest", "mcp"])
@pytest.mark.parametrize("busy", [False, True])
def test_expired_busy_coverage_releases_assessment_quota(
    database, monkeypatch, transport, busy, caplog
):
    monkeypatch.setattr(api_module.LOGGER, "disabled", False)
    caplog.set_level(logging.INFO, logger=api_module.LOGGER.name)
    store = AnonymousQuotaStore()
    app, runtime = _app_and_runtime(database, monkeypatch, store=store)
    with TestClient(
        app,
        base_url="https://security.example",
        client=("127.0.0.1", 50000),
        headers={**HEADERS, "X-Forwarded-For": "8.8.8.8"},
    ) as client:
        _wait_ready(client, runtime)
        _COVERAGE_REPORT_CACHE.clear()
        with _COVERAGE_REPORT_CACHE._build_lock if busy else nullcontext():
            started = monotonic()
            if transport == "rest":
                response = client.post("/v1/artifacts/assess", json=COORDINATE)
                assert response.status_code == 503
                error = response.json()["error"]
            else:
                result = call(client, "assess_public_artifact", COORDINATE, modern=True).json()[
                    "result"
                ]
                assert result["isError"] is True
                error = result["structuredContent"]["data"]["error"]
            assert error["retryable"] is True and error["code"] == "service_unavailable"
            assert monotonic() - started < 2
            assert _pending(store) == _completed(store) == 0
            owned_logs = [record for record in caplog.records if "Owned assessment" in record.msg]
            assert [(record.levelno, record.getMessage()) for record in owned_logs] == [
                (logging.INFO, "Owned assessment unavailable type=CoverageReportUnavailable")
            ]
            if transport == "rest":
                assert runtime.usage.counts[("/v1/artifacts/assess", "POST", 503)] == 1
                pressure = runtime.usage.pressure.document(now=runtime.local_clock())
                assert pressure["server_errors"] == 1
        assert client.get("/readyz").status_code == 503
        client.portal.call(runtime.build_coverage)
        # Only the owned background builder can recover a missing API report.
        assert client.post("/v1/artifacts/assess", json=COORDINATE).status_code == 200
        assert _pending(store) == 0 and _completed(store) == 1


def test_owned_assessment_runtime_failure_keeps_error_log(database, monkeypatch, caplog):
    monkeypatch.setattr(api_module.LOGGER, "disabled", False)
    caplog.set_level(logging.INFO, logger=api_module.LOGGER.name)
    store = AnonymousQuotaStore()
    app, runtime = _app_and_runtime(database, monkeypatch, store=store)

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic private failure detail")

    monkeypatch.setattr(runtime.service, "assess_public_artifact", fail)
    with TestClient(
        app,
        base_url="https://security.example",
        client=("127.0.0.1", 50000),
        headers={"X-Forwarded-For": "8.8.8.8"},
        raise_server_exceptions=False,
    ) as client:
        _wait_ready(client, runtime)
        response = client.post("/v1/artifacts/assess", json=COORDINATE)
        assert response.status_code == 503 and response.json()["error"]["retryable"] is True
        assert _pending(store) == _completed(store) == 0
        owned_logs = [record for record in caplog.records if "Owned assessment" in record.msg]
        assert [(record.levelno, record.getMessage()) for record in owned_logs] == [
            (logging.ERROR, "Owned assessment failed type=RuntimeError")
        ]
        assert "synthetic private failure detail" not in caplog.text


@pytest.mark.parametrize("transport", ["rest", "mcp"])
def test_coverage_loss_after_reservation_refunds_quota(database, monkeypatch, transport):
    store = AnonymousQuotaStore()
    app, runtime = _app_and_runtime(database, monkeypatch, store=store)
    original = AnonymousQuotaStore.reserve
    invalidate = True

    def reserve(self, **arguments):
        nonlocal invalidate
        value = original(self, **arguments)
        if invalidate:
            assert value.status == "reserved"
            _COVERAGE_REPORT_CACHE.clear()
            invalidate = False
        return value

    monkeypatch.setattr(AnonymousQuotaStore, "reserve", reserve)
    with TestClient(
        app,
        base_url="https://security.example",
        client=("127.0.0.1", 50000),
        headers={**HEADERS, "X-Forwarded-For": "8.8.8.8"},
    ) as client:
        _wait_ready(client, runtime)
        if transport == "rest":
            assert client.post("/v1/artifacts/assess", json=COORDINATE).status_code == 503
        else:
            result = call(client, "assess_public_artifact", COORDINATE, modern=True).json()[
                "result"
            ]
            assert result["isError"] is True
            assert result["structuredContent"]["data"]["error"]["retryable"] is True
        assert _pending(store) == _completed(store) == 0
        client.portal.call(runtime.build_coverage)
        assert client.post("/v1/artifacts/assess", json=COORDINATE).status_code == 200
        assert _pending(store) == 0 and _completed(store) == 1


def test_cached_assessment_cannot_hide_missing_coverage(database, monkeypatch):
    store = AnonymousQuotaStore()
    app, runtime = _app_and_runtime(database, monkeypatch, store=store)
    with TestClient(
        app,
        base_url="https://security.example",
        client=("127.0.0.1", 50000),
        headers={"X-Forwarded-For": "8.8.8.8"},
    ) as client:
        _wait_ready(client, runtime)
        first = client.post("/v1/artifacts/assess", json=COORDINATE)
        assert first.status_code == 200 and _completed(store) == 1
        _COVERAGE_REPORT_CACHE.clear()
        assert client.post("/v1/artifacts/assess", json=COORDINATE).status_code == 503
        assert _completed(store) == 1 and _pending(store) == 0
        client.portal.call(runtime.build_coverage)
        recovered = client.post("/v1/artifacts/assess", json=COORDINATE)
        assert recovered.status_code == 200 and recovered.headers["X-SmithGuard-Cache"] == "hit"
        assert _completed(store) == 1
