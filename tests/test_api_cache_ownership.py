"""HTTP cache envelopes, corrections, exact expiry and cancelled quota ownership."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from threading import Event
from time import monotonic, sleep

import httpx
import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

import smithguard.api as api_module
from smithguard.advisory_catalog import append_github_advisory
from smithguard.anonymous_quota import AnonymousQuotaStore
from smithguard.api import create_public_beta_app
from smithguard.assessment_cache import AssessmentCacheCapacityError, AssessmentResponseCache
from smithguard.feeds import SnapshotSigner
from smithguard.identifiers import stable_id
from smithguard.service import SmithGuardService
from smithguard.signals import PreliminaryWarningDraft, create_preliminary_warning
from tests.api_client import TestClient, wait_for_initial_coverage

NOW = datetime(2026, 9, 6, 12, tzinfo=UTC)


def _request(examples):
    return deepcopy(
        next(
            item["value"]
            for item in examples
            if item["definition"] == "PublicArtifactAssessmentRequest"
        )
    )


def _app(database, *, current=None, store=None):
    return create_public_beta_app(
        session_factory=sessionmaker(database.engine),
        signer=SnapshotSigner.ephemeral(),
        base_url="https://security.example",
        clock=lambda: current[0] if current is not None else NOW,
        anonymous_quota_store=store if store is not None else AnonymousQuotaStore(),
        anonymous_quota_secret=b"synthetic-quota-owner-test-value!",
        trusted_proxy_header=True,
    )


def _client(app, *, raise_server_exceptions=True, readiness_app=None):
    return TestClient(
        app,
        base_url="https://security.example",
        client=("127.0.0.1", 50000),
        headers={"X-Forwarded-For": "8.8.8.8"},
        raise_server_exceptions=raise_server_exceptions,
        readiness_app=readiness_app,
    )


def _completed(store) -> int:
    with store._lock:
        return store._connection.execute(
            "SELECT count(*) FROM anonymous_assessment_quota WHERE state = 'complete'"
        ).fetchone()[0]


def _pending(store):
    with store._lock:
        return store._connection.execute(
            "SELECT count(*) FROM anonymous_assessment_quota WHERE state='pending'"
        ).fetchone()[0]


def _warning(database, *, expires_in):
    reviewed = NOW - timedelta(hours=12) + timedelta(seconds=expires_in)
    with Session(database.engine) as session, session.begin():
        return create_preliminary_warning(
            session,
            draft=PreliminaryWarningDraft(
                title=f"Synthetic exact expiry {expires_in}",
                claim="A synthetic unverified lead requires investigation.",
                affected_artifacts=("npm:event-stream@3.3.6",),
                source_urls=(f"https://example.net/expiry-{expires_in}",),
                evidence_class="web_only",
                independent_source_clusters=1,
                observed_at=reviewed,
                reviewer_id="reviewer:expiry-test",
            ),
            reviewed_at=reviewed,
        )


@pytest.mark.audit_ids("AUD-07")
@pytest.mark.parametrize("variation", ["registry", "equivalent_name", "request_id"])
def test_cache_projects_current_request_registry_name_and_id(
    database,
    contract_examples,
    variation,
) -> None:
    first = _request(contract_examples)
    if variation == "registry":
        first["artifact"].update(
            ecosystem="oci",
            name="synthetic/image",
            registry_host="docker.io",
            version=None,
            digest="sha256:" + "a" * 64,
        )
    elif variation == "equivalent_name":
        first["artifact"].update(
            ecosystem="pypi",
            name="Synthetic_Package",
            registry_host="pypi.org",
            version="1.0.0",
            digest=None,
        )
    second = deepcopy(first)
    second["id"] = "gbsec:request:second-envelope"
    if variation == "registry":
        second["artifact"]["registry_host"] = "ghcr.io"
    elif variation == "equivalent_name":
        second["artifact"]["name"] = "synthetic-package"
    with _client(_app(database)) as client:
        original = client.post("/v1/artifacts/assess", json=first)
        repeated = client.post("/v1/artifacts/assess", json=second)
    assert original.status_code == repeated.status_code == 200
    assert repeated.headers["X-SmithGuard-Cache"] == "hit"
    result = repeated.json()
    assert result["artifact"] == second["artifact"]
    assert result["id"] == stable_id("assessment", second["id"], result["feed_revision"])
    assert result["id"] != original.json()["id"]
    assert result["created_at"] == original.json()["created_at"]


@pytest.mark.audit_ids("AUD-07")
def test_concurrent_followers_receive_their_own_request_envelopes(
    database,
    contract_examples,
    monkeypatch,
) -> None:
    entered, release = Event(), Event()
    original = SmithGuardService.assess_public_artifact
    calls = []

    def slow(self, session, request):
        calls.append(request["id"])
        entered.set()
        assert release.wait(4)
        return original(self, session, request)

    monkeypatch.setattr(SmithGuardService, "assess_public_artifact", slow)
    first = _request(contract_examples)
    first["artifact"].update(
        ecosystem="oci",
        name="synthetic/image",
        registry_host="docker.io",
        version=None,
        digest="sha256:" + "a" * 64,
    )
    requests = []
    for index in range(12):
        request = deepcopy(first)
        request["id"] = f"gbsec:request:follower-{index}"
        request["artifact"]["registry_host"] = "docker.io" if index % 2 else "ghcr.io"
        requests.append(request)
    with _client(_app(database)) as client, ThreadPoolExecutor(max_workers=12) as executor:
        try:
            futures = [
                executor.submit(client.post, "/v1/artifacts/assess", json=r) for r in requests
            ]
            assert entered.wait(4)
            sleep(0.1)
        finally:
            release.set()
        responses = [future.result(8) for future in futures]
    assert len(calls) == 1
    for request, response in zip(requests, responses, strict=True):
        assert response.status_code == 200
        assert response.json()["artifact"] == request["artifact"]
        assert response.json()["id"] == stable_id(
            "assessment", request["id"], response.json()["feed_revision"]
        )


@pytest.mark.audit_ids("AUD-08")
def test_exact_warning_expiry_recomputes_verdict_and_multiple_warning_times(
    database,
    contract_examples,
) -> None:
    _warning(database, expires_in=1)
    _warning(database, expires_in=3)
    current = [NOW]
    request = _request(contract_examples)
    with _client(_app(database, current=current)) as client:
        first = client.post("/v1/artifacts/assess", json=request)
        assert first.status_code == 200
        assert first.json()["result"] == "possibly_affected"
        assert len(first.json()["preliminary_warnings"]) == 2
        current[0] = NOW + timedelta(seconds=1)
        middle = client.post("/v1/artifacts/assess", json=request)
        assert middle.status_code == 200
        assert len(middle.json()["preliminary_warnings"]) == 1
        assert middle.json()["result"] == "possibly_affected"
        current[0] = NOW + timedelta(seconds=3)
        expired = client.post("/v1/artifacts/assess", json=request)
        assert expired.status_code == 200
        assert expired.json()["preliminary_warnings"] == []
        assert expired.json()["result"] == "unknown"
        assert expired.json()["feed_revision"] != first.json()["feed_revision"]


@pytest.mark.audit_ids("AUD-08")
def test_warning_expiring_during_quota_completion_is_not_returned_active(
    database,
    contract_examples,
    monkeypatch,
) -> None:
    _warning(database, expires_in=1)
    current = [NOW]
    original = AnonymousQuotaStore.complete

    def complete_after_expiry(self, reservation, **kwargs):
        current[0] = NOW + timedelta(seconds=1)
        return original(self, reservation, **kwargs)

    monkeypatch.setattr(AnonymousQuotaStore, "complete", complete_after_expiry)
    store = AnonymousQuotaStore()
    with _client(_app(database, current=current, store=store)) as client:
        response = client.post("/v1/artifacts/assess", json=_request(contract_examples))
    assert response.status_code == 200
    assert response.json()["result"] == "unknown"
    assert response.json()["preliminary_warnings"] == []
    assert _pending(store) == 0


@pytest.mark.audit_ids("AUD-08")
@pytest.mark.parametrize("failure", ["database", "capacity"])
def test_failed_recheck_after_quota_completion_refunds_the_check(
    database,
    contract_examples,
    monkeypatch,
    failure,
) -> None:
    """A warning expires during quota completion and the recheck then fails: the
    caller gets a 503 and the completed check is refunded."""
    _warning(database, expires_in=1)
    current = [NOW]
    original_complete = AnonymousQuotaStore.complete
    original_assess = SmithGuardService.assess_public_artifact
    calls = [0]

    def complete_after_expiry(self, reservation, **kwargs):
        current[0] = NOW + timedelta(seconds=1)
        return original_complete(self, reservation, **kwargs)

    def assess_then_fail(self, session, document):
        calls[0] += 1
        if calls[0] > 1:
            if failure == "database":
                raise OperationalError("SELECT 1", {}, Exception("connection lost"))
            raise AssessmentCacheCapacityError("public read work is at capacity")
        return original_assess(self, session, document)

    monkeypatch.setattr(AnonymousQuotaStore, "complete", complete_after_expiry)
    monkeypatch.setattr(SmithGuardService, "assess_public_artifact", assess_then_fail)
    store = AnonymousQuotaStore()
    app = _app(database, current=current, store=store)
    with _client(app, raise_server_exceptions=False) as client:
        response = client.post("/v1/artifacts/assess", json=_request(contract_examples))
    assert calls[0] == 2
    assert response.status_code == 503
    assert _completed(store) == 0
    assert _pending(store) == 0


@pytest.mark.audit_ids("AUD-08")
@pytest.mark.parametrize("change", ["correction", "withdrawal"])
def test_committed_catalog_correction_invalidates_the_five_minute_cache(
    database,
    contract_examples,
    change,
) -> None:
    advisory = {
        "ghsa_id": "GHSA-2345-6789-cfgh",
        "type": "reviewed",
        "published_at": "2026-09-01T00:00:00Z",
        "updated_at": "2026-09-02T00:00:00Z",
        "withdrawn_at": None,
        "html_url": "https://github.com/advisories/GHSA-2345-6789-cfgh",
        "cwes": [],
        "identifiers": [{"type": "GHSA", "value": "GHSA-2345-6789-cfgh"}],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": "event-stream"},
                "vulnerable_version_range": "= 3.3.6",
            }
        ],
    }

    def append(document, revision):
        with Session(database.engine) as session, session.begin():
            append_github_advisory(
                session,
                document=document,
                evidence_id=f"gbsec:evidence:cache-correction-{revision}",
                governance_decision_id=f"gbsec:governance:cache-correction-{revision}",
                observed_at=NOW,
            )

    append(advisory, 1)
    request = _request(contract_examples)
    with _client(_app(database)) as client:
        first = client.post("/v1/artifacts/assess", json=request)
        assert first.status_code == 200 and first.json()["result"] == "affected"
        assert (
            client.post("/v1/artifacts/assess", json=request).headers["X-SmithGuard-Cache"] == "hit"
        )
        corrected = deepcopy(advisory)
        corrected["updated_at"] = "2026-09-03T00:00:00Z"
        if change == "withdrawal":
            corrected["withdrawn_at"] = "2026-09-03T00:00:00Z"
        else:
            corrected["vulnerabilities"][0]["vulnerable_version_range"] = "= 9.9.9"
        append(corrected, 2)
        response = client.post("/v1/artifacts/assess", json=request)
    assert response.status_code == 200
    assert response.json()["result"] == ("unknown" if change == "withdrawal" else "not_affected")
    assert response.json()["feed_revision"] != first.json()["feed_revision"]


@pytest.mark.audit_ids("AUD-09")
@pytest.mark.parametrize("stage", ["reserve", "complete", "release"])
def test_http_deadline_does_not_wait_for_quota_cleanup_and_late_work_is_owned(
    database,
    contract_examples,
    monkeypatch,
    stage,
) -> None:
    entered, proceed = Event(), Event()
    method = "release_many" if stage == "release" else stage
    original = getattr(AnonymousQuotaStore, method)
    store = AnonymousQuotaStore()

    def delayed(self, *args, **kwargs):
        entered.set()
        assert proceed.wait(4)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(AnonymousQuotaStore, method, delayed)
    monkeypatch.setattr(api_module, "PUBLIC_ASSESSMENT_TIMEOUT_SECONDS", 0.5)
    if stage == "release":

        def failed_assessment(*_args):
            raise TimeoutError

        monkeypatch.setattr(SmithGuardService, "assess_public_artifact", failed_assessment)
    request = _request(contract_examples)
    # Measure quota cleanup, not cold schema initialization under parallel load.
    SmithGuardService(clock=lambda: NOW).validate_public_artifact_request(request)
    with (
        _client(_app(database, store=store)) as client,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        try:
            start = monotonic()
            future = executor.submit(client.post, "/v1/artifacts/assess", json=request)
            assert entered.wait(4)
            response = future.result(1.5)
            assert response.status_code == 503
            assert response.json()["error"]["code"] == "request_deadline_exceeded"
            assert monotonic() - start < 1.5
            assert not proceed.is_set()
            assert client.get("/healthz").status_code == 200
        finally:
            proceed.set()
    # Lifespan has drained the retained owner after the slow operation finished.
    assert _pending(store) == 0
    # A check whose answer became a 503 is never counted (item 88).
    assert _completed(store) == 0


@pytest.mark.audit_ids("AUD-09")
def test_cancelled_queued_reservation_never_runs_after_its_deadline(
    database,
    contract_examples,
    monkeypatch,
) -> None:
    entered, proceed = Event(), Event()
    original = AnonymousQuotaStore.reserve
    calls = []
    store = AnonymousQuotaStore()

    def delayed(self, **kwargs):
        calls.append(kwargs["request_key"])
        entered.set()
        assert proceed.wait(4)
        return original(self, **kwargs)

    monkeypatch.setattr(AnonymousQuotaStore, "reserve", delayed)
    monkeypatch.setattr(api_module, "PUBLIC_ASSESSMENT_TIMEOUT_SECONDS", 0.15)
    first = _request(contract_examples)
    second = deepcopy(first)
    second["artifact"]["name"] = "second-synthetic-package"
    # This test measures queued quota cancellation, not first-use schema setup.
    SmithGuardService(clock=lambda: NOW).validate_public_artifact_request(first)
    with (
        _client(_app(database, store=store)) as client,
        ThreadPoolExecutor(max_workers=2) as executor,
    ):
        try:
            one = executor.submit(client.post, "/v1/artifacts/assess", json=first)
            assert entered.wait(4), one.result(timeout=1).json()
            two = executor.submit(client.post, "/v1/artifacts/assess", json=second)
            assert one.result(0.7).status_code == two.result(0.7).status_code == 503
        finally:
            proceed.set()
    assert len(calls) == 1
    assert _pending(store) == 0


@pytest.mark.audit_ids("AUD-09")
def test_cancelled_http_task_and_shutdown_reconcile_late_reservation(
    database,
    contract_examples,
    monkeypatch,
) -> None:
    entered, proceed = Event(), Event()
    original = AnonymousQuotaStore.reserve
    store = AnonymousQuotaStore()

    def delayed(self, **kwargs):
        entered.set()
        assert proceed.wait(4)
        return original(self, **kwargs)

    monkeypatch.setattr(AnonymousQuotaStore, "reserve", delayed)
    app = _app(database, store=store)

    async def scenario():
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="https://security.example",
                headers={"X-Forwarded-For": "8.8.8.8"},
            ) as client,
        ):
            await wait_for_initial_coverage(app)
            task = asyncio.create_task(
                client.post("/v1/artifacts/assess", json=_request(contract_examples))
            )
            assert await asyncio.to_thread(entered.wait, 4)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            proceed.set()
        assert _pending(store) == 0

    try:
        asyncio.run(scenario())
    finally:
        proceed.set()


@pytest.mark.audit_ids("AUD-10")
def test_distinct_request_saturation_is_bounded_before_quota_submission(
    database,
    contract_examples,
    monkeypatch,
) -> None:
    entered, proceed = Event(), Event()
    original = AnonymousQuotaStore.reserve
    calls = []
    store = AnonymousQuotaStore()
    monkeypatch.setattr(api_module, "PUBLIC_ASSESSMENT_CONCURRENCY", 1)

    def delayed(self, **kwargs):
        calls.append(kwargs["request_key"])
        entered.set()
        assert proceed.wait(4)
        return original(self, **kwargs)

    monkeypatch.setattr(AnonymousQuotaStore, "reserve", delayed)
    first = _request(contract_examples)
    second = deepcopy(first)
    second["artifact"]["name"] = "second-synthetic-package"
    third = deepcopy(first)
    third["artifact"]["name"] = "third-synthetic-package"
    with (
        _client(_app(database, store=store)) as client,
        ThreadPoolExecutor(max_workers=2) as executor,
    ):
        try:
            one = executor.submit(client.post, "/v1/artifacts/assess", json=first)
            assert entered.wait(4), one.result(timeout=1).json()
            two = executor.submit(client.post, "/v1/artifacts/assess", json=second)
            sleep(0.1)
            response = client.post("/v1/artifacts/assess", json=third)
            assert response.status_code == 503
            assert response.json()["error"]["code"] == "service_capacity_exceeded"
            assert response.json()["error"]["retryable"] is True
        finally:
            proceed.set()
        assert one.result(4).status_code == two.result(4).status_code == 200
    assert len(calls) == 2
    assert _pending(store) == 0


@pytest.mark.audit_ids("AUD-10")
def test_cached_identity_keeps_freshness_reads_when_assessment_workers_are_saturated(
    database, contract_examples, monkeypatch
) -> None:
    entered, proceed = Event(), Event()
    original = SmithGuardService.assess_public_artifact
    monkeypatch.setattr(api_module, "PUBLIC_ASSESSMENT_CONCURRENCY", 1)
    monkeypatch.setattr(api_module, "PUBLIC_ASSESSMENT_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(api_module, "assessment_watermark", lambda _session: "unchanged")
    cached = _request(contract_examples)
    blocked = deepcopy(cached)
    blocked["artifact"]["name"] = "blocked-synthetic-package"

    def delayed(self, session, document):
        if document["artifact"]["name"] == "blocked-synthetic-package":
            entered.set()
            assert proceed.wait(4)
        return original(self, session, document)

    monkeypatch.setattr(SmithGuardService, "assess_public_artifact", delayed)
    with _client(_app(database)) as client, ThreadPoolExecutor(max_workers=1) as executor:
        assert client.post("/v1/artifacts/assess", json=cached).status_code == 200
        work = executor.submit(client.post, "/v1/artifacts/assess", json=blocked)
        try:
            assert entered.wait(4)
            response = client.post("/v1/artifacts/assess", json=cached)
            assert response.status_code == 200
            assert response.headers["X-SmithGuard-Cache"] == "hit"
            assert not proceed.is_set()
        finally:
            proceed.set()
        assert work.result(4).status_code == 200


@pytest.mark.audit_ids("AUD-08")
def test_follower_recomputes_when_visibility_changes_during_leader_work(
    database, contract_examples, monkeypatch
) -> None:
    entered, follower_joined, proceed = Event(), Event(), Event()
    generation = ["before"]
    calls = []
    completions = []
    original_assess = SmithGuardService.assess_public_artifact
    original_begin = AssessmentResponseCache.begin
    original_complete = AssessmentResponseCache.complete
    monkeypatch.setattr(api_module, "assessment_watermark", lambda _session: generation[0])

    def begin(self, *args, **kwargs):
        result = original_begin(self, *args, **kwargs)
        if result[0] is None and not result[2]:
            follower_joined.set()
        return result

    def assess(self, session, document):
        calls.append(generation[0])
        result = original_assess(self, session, document)
        if len(calls) == 1:
            entered.set()
            assert proceed.wait(4)
            generation[0] = "after"
        return result

    def complete(self, *args, **kwargs):
        original_complete(self, *args, **kwargs)
        completions.append((kwargs["watermark"], len(self.values)))

    monkeypatch.setattr(AssessmentResponseCache, "begin", begin)
    monkeypatch.setattr(AssessmentResponseCache, "complete", complete)
    monkeypatch.setattr(SmithGuardService, "assess_public_artifact", assess)
    request = _request(contract_examples)
    with _client(_app(database)) as client, ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(client.post, "/v1/artifacts/assess", json=request)
        try:
            assert entered.wait(4)
            second = executor.submit(client.post, "/v1/artifacts/assess", json=request)
            assert follower_joined.wait(4)
        finally:
            proceed.set()
        assert first.result(4).status_code == second.result(4).status_code == 200
    assert calls == ["before", "after"]
    assert completions == [(None, 0), ("after", 1)]


@pytest.mark.audit_ids("AUD-10")
def test_background_cache_maintenance_removes_untouched_expired_responses(
    database,
    contract_examples,
    monkeypatch,
) -> None:
    current = [NOW]
    caches = []
    original = AssessmentResponseCache.expire
    maintained = Event()

    def observe(self, **kwargs):
        caches.append(self)
        original(self, **kwargs)
        if kwargs["now"] > NOW:
            maintained.set()

    monkeypatch.setattr(AssessmentResponseCache, "expire", observe)
    monkeypatch.setattr(api_module, "CACHE_MAINTENANCE_SECONDS", 0.01)
    with _client(_app(database, current=current)) as client:
        assert (
            client.post("/v1/artifacts/assess", json=_request(contract_examples)).status_code == 200
        )
        current[0] = NOW + timedelta(minutes=5)
        assert maintained.wait(2)
        assert caches[-1].serialized_bytes == 0
        assert not caches[-1].values


@pytest.mark.audit_ids("AUD-10")
def test_total_request_admission_is_bounded_before_reading_more_bodies(
    database, monkeypatch
) -> None:
    monkeypatch.setattr(api_module, "PUBLIC_ASSESSMENT_CONCURRENCY", 1)
    app = _app(database)

    async def scenario():
        entered = 0
        full, release = asyncio.Event(), asyncio.Event()

        async def body():
            nonlocal entered
            entered += 1
            if entered == 16:
                full.set()
            await release.wait()
            yield b"{}"

        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="https://security.example",
                headers={"X-Forwarded-For": "8.8.8.8", "Content-Type": "application/json"},
            ) as client,
        ):
            await wait_for_initial_coverage(app)
            requests = [
                asyncio.create_task(client.post("/v1/artifacts/assess", content=body()))
                for _index in range(16)
            ]
            try:
                await asyncio.wait_for(full.wait(), 3)
                overflow = await client.post("/v1/artifacts/assess", json={})
                assert overflow.status_code == 503
                assert overflow.json()["error"]["code"] == "service_capacity_exceeded"
                assert (await client.get("/healthz")).status_code == 200
            finally:
                release.set()
            responses = await asyncio.gather(*requests)
            assert all(response.status_code == 400 for response in responses)

    asyncio.run(scenario())


@pytest.mark.audit_ids("AUD-09")
def test_http_disconnect_signal_abandons_late_quota_work(
    database, contract_examples, monkeypatch
) -> None:
    entered, proceed = Event(), Event()
    original = AnonymousQuotaStore.reserve
    store = AnonymousQuotaStore()
    assessments = []

    def delayed(self, **kwargs):
        entered.set()
        assert proceed.wait(4)
        return original(self, **kwargs)

    def forbidden_assess(*_args):
        assessments.append(True)
        raise AssertionError("disconnected work must not start an assessment")

    monkeypatch.setattr(AnonymousQuotaStore, "reserve", delayed)
    monkeypatch.setattr(SmithGuardService, "assess_public_artifact", forbidden_assess)
    app = _app(database, store=store)

    async def scenario():
        import json

        disconnected = asyncio.Event()
        supplied = False
        sent = []

        async def receive():
            nonlocal supplied
            if not supplied:
                supplied = True
                return {
                    "type": "http.request",
                    "body": json.dumps(_request(contract_examples)).encode(),
                    "more_body": False,
                }
            await disconnected.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message["type"])

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/v1/artifacts/assess",
            "raw_path": b"/v1/artifacts/assess",
            "query_string": b"",
            "root_path": "",
            "server": ("security.example", 443),
            "client": ("127.0.0.1", 50000),
            "headers": [
                (b"host", b"security.example"),
                (b"content-type", b"application/json"),
                (b"x-forwarded-for", b"8.8.8.8"),
            ],
        }
        async with app.router.lifespan_context(app):
            await wait_for_initial_coverage(app)
            task = asyncio.create_task(app(scope, receive, send))
            assert await asyncio.to_thread(entered.wait, 3)
            disconnected.set()
            await asyncio.sleep(0.02)
            proceed.set()
            await asyncio.wait_for(task, 3)
        assert _pending(store) == 0 and not assessments

    try:
        asyncio.run(scenario())
    finally:
        proceed.set()


def test_a_deadline_during_final_cleanup_never_counts_a_check_without_an_answer(
    database, contract_examples, monkeypatch
) -> None:
    """The disconnect watcher's cleanup is slowed past the deadline: the caller either
    gets the answer (and the check counts) or a 503 (and the check is refunded)."""
    import asyncio

    store = AnonymousQuotaStore()
    monkeypatch.setattr(api_module, "PUBLIC_ASSESSMENT_TIMEOUT_SECONDS", 0.6)
    inner = _app(database, store=store)

    async def slow_cleanup_app(scope, receive, send):
        if scope["type"] != "http":
            await inner(scope, receive, send)
            return
        delivered = False

        async def slow_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return await receive()
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                await asyncio.sleep(1.0)  # cleanup crosses the deadline
                raise
            return {"type": "http.disconnect"}

        await inner(scope, slow_receive, send)

    with _client(slow_cleanup_app, readiness_app=inner) as client:
        response = client.post("/v1/artifacts/assess", json=_request(contract_examples))
    assert response.status_code in {200, 503}
    assert (response.status_code == 200) == (_completed(store) == 1)
    assert _pending(store) == 0
