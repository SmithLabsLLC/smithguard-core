"""Generous quotas retain limits; sustained pressure alerts without query data."""

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from fastapi import Request

from smithguard.anonymous_quota import AnonymousAssessmentQuota, AnonymousQuotaStore
from smithguard.api import UsageCounter, UsageCounts
from smithguard.api_pressure import ApiPressure, host_pressure_status, pressure_status
from smithguard.operational_health import build_metric_receipt, evaluate_operational_health
from tests.test_operational_health import _healthy_inputs

NOW = datetime(2026, 9, 27, tzinfo=UTC)


def _path(tmp_path: Path) -> Path:
    p = tmp_path / "pressure"
    p.mkdir(mode=0o2750)
    p.chmod(0o2750)
    return p / "latest.json"


def test_pressure_alerts_and_recovers_without_retaining_requests(tmp_path):
    clock = [0.0]
    counts = ApiPressure(clock=lambda: clock[0])
    path = _path(tmp_path)
    for _ in range(10):
        counts.observe(status=503, seconds=0.01)
    for _ in range(90):
        counts.observe(status=200, seconds=0.01)
    counts.write(path, now=NOW)
    assert pressure_status(path, now=NOW) == "server_errors"
    document = json.loads(path.read_bytes())
    assert set(document) == {
        "schema_version",
        "measured_at",
        "window_seconds",
        "requests",
        "server_errors",
        "slow_requests",
    }
    assert document["requests"] == 100
    assert path.stat().st_mode & 0o777 == 0o640
    for minute in range(1, 1000):
        clock[0] = minute * 60
        counts.observe(status=429, seconds=0.01)
    assert len(counts.buckets) == 5
    counts.write(path, now=NOW)
    assert pressure_status(path, now=NOW) == "healthy"
    assert pressure_status(path, now=NOW + timedelta(seconds=181)) == "unavailable"


def test_pressure_catches_slow_responses_and_invalid_or_missing_heartbeats(tmp_path):
    path = _path(tmp_path)
    assert pressure_status(path, now=NOW) == "unavailable"
    counts = ApiPressure(clock=lambda: 0)
    for _ in range(25):
        counts.observe(status=200, seconds=2)
    counts.write(path, now=NOW)
    assert pressure_status(path, now=NOW) == "slow_responses"
    document = json.loads(path.read_bytes())
    document["server_errors"] = document["requests"] + 1
    path.write_text(json.dumps(document))
    assert pressure_status(path, now=NOW) == "unavailable"
    path.chmod(0o666)
    assert pressure_status(path, now=NOW) == "unavailable"


def test_pressure_uses_existing_health_alarm_and_does_not_alert_on_quota():
    inputs = replace(
        _healthy_inputs(),
        api_pressure_expected=True,
        api_pressure="healthy",
        host_pressure="healthy",
    )
    assert evaluate_operational_health(inputs).status == "healthy"
    for field, bad in [
        ("api_pressure", "server_errors"),
        ("api_pressure", "unavailable"),
        ("host_pressure", "low_memory"),
        ("host_pressure", "high_load"),
    ]:
        failed = replace(inputs, **{field: bad})
        assert evaluate_operational_health(failed).status == "critical"
        metric = next(v for v in build_metric_receipt(failed).metrics if v.name == "HealthCritical")
        assert metric.value == 1
    assert evaluate_operational_health(inputs).status == "healthy"


def test_host_pressure_thresholds(monkeypatch, tmp_path):
    monkeypatch.setattr("smithguard.api_pressure.os.cpu_count", lambda: 2)
    monkeypatch.setattr("smithguard.api_pressure.KERNEL_PRESSURE_ROOT", tmp_path)
    (tmp_path / "loadavg").write_text("0 4.1 0 1/100 123")
    (tmp_path / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 500 kB\n")
    assert host_pressure_status() == "high_load"
    (tmp_path / "loadavg").write_text("0 1 0 1/100 123")
    assert host_pressure_status() == "healthy"
    (tmp_path / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 99 kB\n")
    assert host_pressure_status() == "low_memory"
    (tmp_path / "loadavg").unlink()
    assert host_pressure_status() == "unavailable"


def test_middleware_counts_only_assessments_and_no_query_content():
    counts = UsageCounts()
    clock = [0.0]
    counts.pressure = ApiPressure(clock=lambda: clock[0])

    async def app(scope, receive, send):
        clock[0] += 3
        await send({"type": "http.response.start", "status": 503})

    async def send(message):
        pass

    async def run():
        middleware = UsageCounter(app, usage=counts)
        for route in ["/healthz", "/v1/artifacts/assess"]:
            await middleware(
                {
                    "type": "http",
                    "method": "GET",
                    "route": SimpleNamespace(path=route),
                    "query_string": b"name=do-not-retain",
                },
                None,
                send,
            )

    asyncio.run(run())
    document = counts.pressure.document(now=NOW)
    assert document["requests"] == document["server_errors"] == document["slow_requests"] == 1
    assert "do-not-retain" not in json.dumps(document)


def test_real_generous_burst_accepts_one_hundred_and_backpressure_recovers():
    store = AnonymousQuotaStore()
    quota = AnonymousAssessmentQuota(secret=b"q" * 32, store=store)
    request = Request({"type": "http", "client": ("198.51.100.1", 1234), "headers": []})
    try:
        for i in range(100):
            assert (
                quota.reserve(request=request, artifact_identity={"name": str(i)}, now=NOW).status
                == "reserved"
            )
        assert (
            quota.reserve(request=request, artifact_identity={"name": "blocked"}, now=NOW).status
            == "burst"
        )
        assert (
            quota.reserve(
                request=request, artifact_identity={"name": "next"}, now=NOW + timedelta(seconds=10)
            ).status
            == "reserved"
        )
    finally:
        store._connection.close()


def test_actual_daily_boundary_counts_distinct_successes_and_refunds():
    store = AnonymousQuotaStore()
    epoch = int(NOW.timestamp())
    try:
        with store._connection:
            store._connection.executemany(
                "INSERT INTO anonymous_assessment_quota (network_key,request_key,quota_day,state,"
                "created_at,updated_at,expires_at,attempt_id) VALUES (?,?,?,?,?,?,?,?)",
                (
                    (
                        "network",
                        str(i),
                        NOW.date().isoformat(),
                        "complete",
                        epoch,
                        epoch,
                        epoch + 172800,
                        str(i),
                    )
                    for i in range(99_999)
                ),
            )
        last = store.reserve(network_key="network", request_key="last", now=NOW)
        assert last.status == "reserved"
        store.complete(last, now=NOW)
        assert (
            store.reserve(network_key="network", request_key="last", now=NOW).status
            == "already_counted"
        )
        assert (
            store.reserve(network_key="network", request_key="blocked", now=NOW).status
            == "exhausted"
        )
        store.refund(last)
        assert (
            store.reserve(network_key="network", request_key="after-refund", now=NOW).status
            == "reserved"
        )
    finally:
        store._connection.close()


def test_disconnected_callers_do_not_trigger_pressure():
    counts = UsageCounts()

    async def app(scope, receive, send):
        assert (await receive())["type"] == "http.disconnect"
        await send({"type": "http.response.start", "status": 503})

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        pass

    asyncio.run(
        UsageCounter(app, usage=counts)(
            {
                "type": "http",
                "method": "GET",
                "route": SimpleNamespace(path="/v1/artifacts/assess"),
            },
            receive,
            send,
        )
    )
    assert counts.pressure.document(now=NOW)["requests"] == 0


def test_actual_limit_error_names_current_allowance():
    from smithguard.api import _quota_rejection_response

    response = _quota_rejection_response(
        status="exhausted", reset_at="2026-09-28T00:00:00Z", headers={}
    )
    assert response.status_code == 429
    assert json.loads(response.body)["error"]["message"].startswith("100000 distinct successful")


def test_quota_cache_observes_other_connections_and_pending_expiry(tmp_path, monkeypatch):
    monkeypatch.setattr("smithguard.anonymous_quota.DAILY_SUCCESS_LIMIT", 1)
    root = tmp_path / "quota"
    root.mkdir(mode=0o700)
    first, second = (AnonymousQuotaStore(root / "quota.sqlite3") for _ in range(2))
    try:
        pending = first.reserve(network_key="network", request_key="one", now=NOW)
        assert (
            first.reserve(network_key="network", request_key="two", now=NOW).status == "exhausted"
        )
        second.release(pending)
        next_one = first.reserve(network_key="network", request_key="two", now=NOW)
        assert next_one.status == "reserved"
        assert (
            first.reserve(network_key="network", request_key="three", now=NOW).status == "exhausted"
        )
        assert (
            first.reserve(
                network_key="network", request_key="three", now=NOW + timedelta(seconds=120)
            ).status
            == "reserved"
        )
    finally:
        first._connection.close()
        second._connection.close()


def test_expiration_cleanup_is_bounded_and_does_not_block_new_day_checks():
    from smithguard.anonymous_quota import CLEANUP_BATCH

    store = AnonymousQuotaStore()
    epoch = int(NOW.timestamp())
    try:
        with store._connection:
            store._connection.executemany(
                "INSERT INTO anonymous_assessment_quota VALUES (?,?,?,?,?,?,?,?)",
                (
                    (
                        "old",
                        str(i),
                        "2026-09-25",
                        "complete",
                        epoch - 172800,
                        epoch - 172800,
                        epoch,
                        str(i),
                    )
                    for i in range(5000)
                ),
            )
        assert store.cleanup(now=NOW) == CLEANUP_BATCH
        assert (
            store._connection.execute("SELECT COUNT(*) FROM anonymous_assessment_quota").fetchone()[
                0
            ]
            == 5000 - CLEANUP_BATCH
        )
        assert store.reserve(network_key="new", request_key="new", now=NOW).status == "reserved"
        before = store._connection.execute(
            "SELECT COUNT(*) FROM anonymous_assessment_quota"
        ).fetchone()[0]
        assert before == 5000 - CLEANUP_BATCH - 128 + 1
    finally:
        store._connection.close()


def test_idle_app_lifespan_writes_heartbeat_off_event_loop_and_stops(tmp_path, monkeypatch):
    import threading

    from smithguard.api import _PublicAssessmentRuntime
    from smithguard.api_pressure import write_pressure

    path = _path(tmp_path)
    owner_thread = threading.get_ident()
    writes = []

    def write(p, document):
        assert threading.get_ident() != owner_thread
        write_pressure(p, document)
        writes.append(document)

    monkeypatch.setattr("smithguard.api.write_pressure", write)

    async def unused_coverage(_runtime):
        pass

    monkeypatch.setattr(_PublicAssessmentRuntime, "build_coverage", unused_coverage)
    store = AnonymousQuotaStore()
    runtime = _PublicAssessmentRuntime(
        service=None,
        anonymous_quota=AnonymousAssessmentQuota(secret=b"q" * 32, store=store),
        local_clock=lambda: NOW,
        session_factory=None,
        response_headers={},
        pressure_path=path,
    )

    async def run():
        async with runtime.lifespan(None):
            async with asyncio.timeout(2):
                while not writes:
                    await asyncio.sleep(0.01)
            assert pressure_status(path, now=NOW) == "healthy"
        assert len(writes) == 1

    try:
        asyncio.run(run())
    finally:
        store._connection.close()


def test_midnight_cleanup_keeps_pending_owner_until_it_finishes():
    store = AnonymousQuotaStore()
    before = NOW - timedelta(seconds=2)
    after = NOW + timedelta(seconds=1)
    try:
        reserved = store.reserve(network_key="yesterday", request_key="cross-midnight", now=before)
        assert reserved.status == "reserved"
        assert store.cleanup(now=after) == 0
        store.complete(reserved, now=after)
        store.refund(reserved)
        assert (
            store._connection.execute("SELECT COUNT(*) FROM anonymous_assessment_quota").fetchone()[
                0
            ]
            == 0
        )
    finally:
        store._connection.close()


def test_slow_disconnected_processing_is_visible_but_not_a_server_error():
    counts = UsageCounts()
    clock = [0.0]
    counts.pressure = ApiPressure(clock=lambda: clock[0])

    async def app(scope, receive, send):
        # Upload time alone does not count as slow disconnected processing.
        clock[0] += 5
        if scope.get("validated"):
            scope["smithguard_processing_started"] = clock[0]
            clock[0] += 3
        await receive()
        await send({"type": "http.response.start", "status": 503})

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        pass

    async def run():
        for validated in (False, True):
            await UsageCounter(app, usage=counts)(
                {
                    "type": "http",
                    "method": "GET",
                    "validated": validated,
                    "route": SimpleNamespace(path="/v1/artifacts/assess"),
                },
                receive,
                send,
            )

    asyncio.run(run())
    result = counts.pressure.document(now=NOW)
    assert result["requests"] == result["slow_requests"] == 1
    assert result["server_errors"] == 0


def test_fast_traffic_warns_before_the_shared_origin_fuse(tmp_path):
    counts = ApiPressure(clock=lambda: 0)
    path = _path(tmp_path)
    for _ in range(18_000):
        counts.observe(status=200, seconds=0.01)
    counts.write(path, now=NOW)
    assert pressure_status(path, now=NOW) == "high_arrival_rate"


def test_cleanup_failure_during_cancellation_does_not_lose_shutdown():
    import threading

    from smithguard.anonymous_quota import AnonymousQuotaError
    from smithguard.api import _PublicAssessmentRuntime

    started, finish = threading.Event(), threading.Event()

    class Quota:
        def cleanup(self, *, now):
            started.set()
            finish.wait(2)
            raise AnonymousQuotaError("synthetic failure")

    runtime = _PublicAssessmentRuntime(
        service=None,
        anonymous_quota=Quota(),
        local_clock=lambda: NOW,
        session_factory=None,
        response_headers={},
    )

    async def run():
        task = asyncio.create_task(runtime.maintain_quota())
        async with asyncio.timeout(2):
            while not started.is_set():
                await asyncio.sleep(0.001)
            task.cancel()
            await asyncio.sleep(0)
            finish.set()
            import pytest

            with pytest.raises(asyncio.CancelledError):
                await task

    try:
        asyncio.run(run())
    finally:
        finish.set()
        runtime.quota_executor.shutdown(wait=True)
        runtime.assessment_executor.shutdown(wait=True)
        runtime.watermark_executor.shutdown(wait=True)
        runtime.bulletin_executor.shutdown(wait=True)


def test_real_api_counts_quota_and_capacity_responses(database, contract_examples, monkeypatch):
    from copy import deepcopy

    from sqlalchemy.orm import sessionmaker

    from smithguard.api import _PublicAssessmentRuntime, create_public_beta_app
    from smithguard.feeds import SnapshotSigner
    from tests.api_client import TestClient

    captured = []

    class Runtime(_PublicAssessmentRuntime):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            captured.append(self)

    monkeypatch.setattr("smithguard.api._PublicAssessmentRuntime", Runtime)
    monkeypatch.setattr("smithguard.anonymous_quota.BURST_LIMIT", 1)
    store = AnonymousQuotaStore()
    app = create_public_beta_app(
        session_factory=sessionmaker(database.engine),
        signer=SnapshotSigner.ephemeral(),
        base_url="https://security.example",
        clock=lambda: NOW,
        anonymous_quota_store=store,
        anonymous_quota_secret=b"q" * 32,
        trusted_proxy_header=True,
    )
    example = deepcopy(
        next(
            v["value"]
            for v in contract_examples
            if v["definition"] == "PublicArtifactAssessmentRequest"
        )
    )
    with TestClient(app, base_url="https://security.example") as client:
        first = client.post(
            "/v1/artifacts/assess", json=example, headers={"X-Forwarded-For": "8.8.8.80"}
        )
        assert first.status_code == 200
        example["artifact"]["version"] = "0.0.999"
        limited = client.post(
            "/v1/artifacts/assess", json=example, headers={"X-Forwarded-For": "8.8.8.80"}
        )
        assert limited.status_code == 429
        assert captured[0].usage.pressure.document(now=NOW)["server_errors"] == 0
        captured[0].max_requests = 0
        unavailable = client.post(
            "/v1/artifacts/assess", json=example, headers={"X-Forwarded-For": "8.8.8.80"}
        )
        assert unavailable.status_code == 503
        counts = captured[0].usage.pressure.document(now=NOW)
        assert counts["requests"] == 3 and counts["server_errors"] == 1
    store._connection.close()
