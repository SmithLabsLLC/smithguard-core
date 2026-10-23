"""Anonymous exact-check quotas stay query-blind, retry-safe, and proxy-safe."""

from __future__ import annotations

import sqlite3
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import Request
from sqlalchemy.orm import sessionmaker

from smithguard.anonymous_quota import (
    DAILY_SUCCESS_LIMIT as APPROVED_DAILY_SUCCESS_LIMIT,
)
from smithguard.anonymous_quota import (
    MAX_BURST_NETWORKS,
    AnonymousAssessmentQuota,
    AnonymousQuotaError,
    AnonymousQuotaStore,
    request_network,
)
from smithguard.api import COVERAGE_REFRESH_SECONDS, create_public_beta_app
from smithguard.feeds import SnapshotSigner
from tests.api_client import TestClient, coverage_runtime

NOW = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
DAILY_SUCCESS_LIMIT = 40  # Small boundary for HTTP/state-machine regression fixtures.


@pytest.fixture(autouse=True)
def bounded_quota_fixture(monkeypatch) -> None:
    monkeypatch.setattr("smithguard.anonymous_quota.DAILY_SUCCESS_LIMIT", DAILY_SUCCESS_LIMIT)
    monkeypatch.setattr("smithguard.api.DAILY_SUCCESS_LIMIT", DAILY_SUCCESS_LIMIT)
    monkeypatch.setattr("smithguard.anonymous_quota.BURST_LIMIT", 4)


def test_daily_success_limit_matches_the_owner_approved_value() -> None:
    assert APPROVED_DAILY_SUCCESS_LIMIT == 100_000


def _request(*, peer: str, forwarded: str | None = None) -> Request:
    headers = []
    if forwarded is not None:
        headers.append((b"x-forwarded-for", forwarded.encode("ascii")))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/artifacts/assess",
            "headers": headers,
            "client": (peer, 50000),
            "server": ("127.0.0.1", 8771),
            "scheme": "http",
            "query_string": b"",
        }
    )


def _store(tmp_path: Path) -> AnonymousQuotaStore:
    root = tmp_path / "anonymous-access"
    root.mkdir(mode=0o700)
    return AnonymousQuotaStore(root / "quota.sqlite3")


def test_network_identity_uses_exactly_one_proxy_owned_public_address() -> None:
    proxied = _request(peer="127.0.0.1", forwarded="8.8.8.8")
    assert request_network(proxied, trusted_proxy_header=True) == "ipv4:8.8.8.8"
    with pytest.raises(AnonymousQuotaError, match="invalid"):
        request_network(
            _request(peer="127.0.0.1", forwarded="8.8.8.8, 1.1.1.1"),
            trusted_proxy_header=True,
        )
    direct = _request(peer="198.51.100.9", forwarded="203.0.113.99")
    assert request_network(direct) == "ipv4:198.51.100.9"
    ipv6 = _request(peer="::1", forwarded="2606:4700:4700::1111")
    assert request_network(ipv6, trusted_proxy_header=True) == "ipv6:2606:4700:4700::/64"
    mapped = _request(peer="::ffff:8.8.4.4")
    assert request_network(mapped) == "ipv4:8.8.4.4"
    mapped_proxy = _request(peer="127.0.0.1", forwarded="::ffff:8.8.4.4")
    assert request_network(mapped_proxy, trusted_proxy_header=True) == "ipv4:8.8.4.4"


@pytest.mark.audit_ids("API-04")
def test_store_counts_only_completed_unique_requests_and_allows_safe_retry(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = None
    for index in range(DAILY_SUCCESS_LIMIT):
        reservation = store.reserve(
            network_key="sha256:" + "a" * 64,
            request_key="sha256:" + f"{index:064x}",
            now=NOW,
        )
        assert reservation.status == "reserved"
        store.complete(reservation, now=NOW)
        first = first or reservation
    exhausted = store.reserve(
        network_key="sha256:" + "a" * 64,
        request_key="sha256:" + "f" * 64,
        now=NOW,
    )
    assert exhausted.status == "exhausted"
    assert first is not None
    retry = store.reserve(
        network_key=first.network_key,
        request_key=first.request_key,
        now=NOW,
    )
    assert retry.status == "already_counted"

    failed = store.reserve(
        network_key="sha256:" + "b" * 64,
        request_key="sha256:" + "c" * 64,
        now=NOW,
    )
    store.release(failed)
    replacement = store.reserve(
        network_key=failed.network_key,
        request_key="sha256:" + "d" * 64,
        now=NOW,
    )
    assert replacement.status == "reserved"


def test_store_does_not_count_an_abandoned_pending_request(tmp_path: Path) -> None:
    store = _store(tmp_path)
    network_key = "sha256:" + "e" * 64
    abandoned = store.reserve(
        network_key=network_key,
        request_key="sha256:" + "0" * 64,
        now=NOW,
    )
    assert abandoned.status == "reserved"
    after_pending_timeout = NOW + timedelta(minutes=3)
    for index in range(DAILY_SUCCESS_LIMIT):
        reservation = store.reserve(
            network_key=network_key,
            request_key="sha256:" + f"{index + 1:064x}",
            now=after_pending_timeout,
        )
        assert reservation.status == "reserved"
        store.complete(reservation, now=after_pending_timeout)
    exhausted = store.reserve(
        network_key=network_key,
        request_key="sha256:" + "f" * 64,
        now=after_pending_timeout,
    )
    assert exhausted.status == "exhausted"


@pytest.mark.audit_ids("AUD-09")
def test_late_old_completion_and_release_cannot_take_over_a_new_reservation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.reserve(network_key="synthetic-network", request_key="synthetic-request", now=NOW)
    replacement = store.reserve(
        network_key=first.network_key,
        request_key=first.request_key,
        now=NOW + timedelta(minutes=2),
    )
    assert first.status == replacement.status == "reserved"
    assert first.attempt_id and replacement.attempt_id != first.attempt_id
    with pytest.raises(AnonymousQuotaError, match="unavailable"):
        store.complete(first, now=NOW + timedelta(minutes=2))
    store.release(first)
    store.complete(replacement, now=NOW + timedelta(minutes=2))
    store.release(first)
    assert (
        store.reserve(
            network_key=first.network_key,
            request_key=first.request_key,
            now=NOW + timedelta(minutes=2),
        ).status
        == "already_counted"
    )


@pytest.mark.audit_ids("AUD-09")
def test_quota_owner_upgrade_preserves_legacy_rows_and_prior_runtime_sql(tmp_path: Path) -> None:
    root = tmp_path / "legacy-quota"
    root.mkdir(mode=0o700)
    path = root / "quota.sqlite3"
    columns = "network_key, request_key, quota_day, state, created_at, updated_at, expires_at"
    expiry = int((NOW + timedelta(days=2)).timestamp())
    prior = [
        ("old-network", "complete-request", NOW.date().isoformat(), "complete", 1, 1, expiry),
        ("old-network", "pending-request", NOW.date().isoformat(), "pending", 1, 1, expiry),
    ]
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE anonymous_assessment_quota ("
            "network_key TEXT NOT NULL, request_key TEXT NOT NULL, quota_day TEXT NOT NULL, "
            "state TEXT NOT NULL CHECK (state IN ('pending', 'complete')), "
            "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, "
            "expires_at INTEGER NOT NULL, "
            "PRIMARY KEY (network_key, request_key)) WITHOUT ROWID"
        )
        connection.executemany(
            f"INSERT INTO anonymous_assessment_quota ({columns}) VALUES (?, ?, ?, ?, ?, ?, ?)",
            prior,
        )
    store = AnonymousQuotaStore(path)
    assert (
        store._connection.execute(
            f"SELECT {columns} FROM anonymous_assessment_quota ORDER BY request_key"
        ).fetchall()
        == prior
    )
    assert store._connection.execute(
        "SELECT attempt_id FROM anonymous_assessment_quota"
    ).fetchall() == [(None,), (None,)]
    assert (
        store.reserve(network_key="old-network", request_key="complete-request", now=NOW).status
        == "already_counted"
    )
    # Prior runtime INSERTs explicitly name their columns. The added nullable
    # ownership field does not make a rollback rebuild or erase accounting state.
    with store._connection:
        store._connection.execute(
            f"INSERT INTO anonymous_assessment_quota ({columns}) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("prior-runtime", "new-request", NOW.date().isoformat(), "pending", 1, 1, expiry),
        )
    assert store._connection.execute(
        "SELECT attempt_id FROM anonymous_assessment_quota WHERE network_key='prior-runtime'"
    ).fetchone() == (None,)
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.audit_ids("AUD-09")
def test_batch_cleanup_releases_only_its_attempts_and_preserves_completed_repeats() -> None:
    store = AnonymousQuotaStore()
    first = store.reserve(network_key="synthetic", request_key="first", now=NOW)
    second = store.reserve(network_key="synthetic", request_key="second", now=NOW)
    complete = store.reserve(network_key="synthetic", request_key="complete", now=NOW)
    store.complete(complete, now=NOW)
    replacement = store.reserve(
        network_key="synthetic", request_key="first", now=NOW + timedelta(minutes=2)
    )
    store.release_many((first, second, complete))
    assert store._connection.execute(
        "SELECT request_key, state, attempt_id FROM anonymous_assessment_quota ORDER BY request_key"
    ).fetchall() == [
        ("complete", "complete", complete.attempt_id),
        ("first", "pending", replacement.attempt_id),
    ]


def test_in_progress_retry_reports_the_pending_timeout(tmp_path: Path) -> None:
    store = _store(tmp_path)
    reserved = store.reserve(
        network_key="sha256:" + "1" * 64,
        request_key="sha256:" + "2" * 64,
        now=NOW,
    )
    assert reserved.status == "reserved"
    in_progress = store.reserve(
        network_key=reserved.network_key,
        request_key=reserved.request_key,
        now=NOW + timedelta(seconds=30),
    )
    assert in_progress.status == "in_progress"
    assert in_progress.reset_at == NOW + timedelta(minutes=2)


def test_quota_applies_a_small_secondary_burst_limit(tmp_path: Path) -> None:
    quota = AnonymousAssessmentQuota(secret=b"q" * 32, store=_store(tmp_path))
    request = _request(peer="127.0.0.1", forwarded="203.0.113.50")
    for index in range(4):
        reservation = quota.reserve(
            request=request,
            artifact_identity={"name": f"package-{index}"},
            now=NOW,
        )
        assert reservation.status == "reserved"
    blocked = quota.reserve(
        request=request,
        artifact_identity={"name": "package-5"},
        now=NOW,
    )
    assert blocked.status == "burst"


def test_burst_tracking_is_bounded() -> None:
    quota = AnonymousAssessmentQuota(secret=b"q" * 32, store=AnonymousQuotaStore())
    for index in range(MAX_BURST_NETWORKS + 10):
        request = _request(peer=f"198.51.{index // 256}.{index % 256}")
        reservation = quota.reserve(
            request=request,
            artifact_identity={"name": "same-package"},
            now=NOW,
        )
        assert reservation.status in {"reserved", "already_counted"}
    assert len(quota._burst) == MAX_BURST_NETWORKS


def test_public_api_allows_forty_successes_and_does_not_charge_invalid_requests(
    database,
    contract_examples,
    tmp_path: Path,
) -> None:
    current = [NOW]
    store = _store(tmp_path)
    app = create_public_beta_app(
        session_factory=sessionmaker(database.engine),
        signer=SnapshotSigner.ephemeral(),
        base_url="https://security.example",
        clock=lambda: current[0],
        anonymous_quota_store=store,
        anonymous_quota_secret=b"z" * 32,
        trusted_proxy_header=True,
    )
    example = deepcopy(
        next(
            item["value"]
            for item in contract_examples
            if item["definition"] == "PublicArtifactAssessmentRequest"
        )
    )
    headers = {"X-Forwarded-For": "8.8.8.80"}
    with TestClient(
        app,
        base_url="https://security.example",
        client=("127.0.0.1", 50000),
    ) as client:
        invalid = client.post(
            "/v1/artifacts/assess",
            json={"invalid": True},
            headers=headers,
        )
        assert invalid.status_code == 400
        successful_request = None
        last_refresh = current[0]
        for index in range(DAILY_SUCCESS_LIMIT):
            # This test advances seven minutes without wall-clock timer sleeps.
            # Run the real refresh when its interval passes in that test clock.
            if (current[0] - last_refresh).total_seconds() >= COVERAGE_REFRESH_SECONDS:
                client.portal.call(coverage_runtime(app).build_coverage)
                last_refresh = current[0]
            request = deepcopy(example)
            request["id"] = f"gbsec:request:quota-{index}"
            request["artifact"]["name"] = f"quota-package-{index}"
            successful_request = successful_request or deepcopy(request)
            response = client.post(
                "/v1/artifacts/assess",
                json=request,
                headers=headers,
            )
            assert response.status_code == 200
            assert response.json()["artifact"] == request["artifact"]
            current[0] += timedelta(seconds=11)
        blocked = deepcopy(example)
        blocked["id"] = "gbsec:request:quota-blocked"
        blocked["artifact"]["name"] = "quota-package-blocked"
        response = client.post(
            "/v1/artifacts/assess",
            json=blocked,
            headers=headers,
        )
        assert response.status_code == 429
        assert response.json()["error"]["code"] == "anonymous_daily_limit_exceeded"
        message = response.json()["error"]["message"]
        assert message.startswith(
            f"{DAILY_SUCCESS_LIMIT} distinct successful checks per network address per UTC day"
        )
        assert "X-SmithGuard-Quota-Reset" in response.headers
        current[0] += timedelta(seconds=11)
        retry = client.post(
            "/v1/artifacts/assess",
            json={
                **successful_request,
                "id": "gbsec:request:quota-retry-new-envelope",
                "created_at": "2026-08-12T12:30:00Z",
                "updated_at": "2026-08-12T12:30:00Z",
            },
            headers=headers,
        )
        assert retry.status_code == 200
