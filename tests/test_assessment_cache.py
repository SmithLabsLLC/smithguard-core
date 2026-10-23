"""Canonical cache expiry, correction visibility, ownership and real allocation bounds."""

from __future__ import annotations

import asyncio
import gc
import tracemalloc
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from smithguard.assessment_cache import (
    CACHE_MAX_BYTES,
    AssessmentCacheCapacityError,
    AssessmentResponseCache,
    assessment_watermark,
)
from smithguard.identifiers import timestamp

NOW = datetime(2026, 9, 6, 12, tzinfo=UTC)


@pytest.mark.audit_ids("AUD-08")
@pytest.mark.parametrize("seconds", [0, 0.999999, 1, 300])
def test_cached_warning_obeys_exact_expiry(seconds: float) -> None:
    async def scenario() -> None:
        cache = AssessmentResponseCache()
        identity = {"name": "synthetic"}
        loop = asyncio.get_running_loop()
        _, owner, leader = cache.begin(identity, now=NOW, watermark="a", loop=loop)
        assert leader
        response = {
            "preliminary_warnings": [
                {"state": "active", "expires_at": timestamp(NOW + timedelta(seconds=1))},
                {"state": "active", "expires_at": timestamp(NOW + timedelta(seconds=3))},
                {"state": "withdrawn", "expires_at": timestamp(NOW - timedelta(seconds=1))},
            ]
        }
        cache.complete(identity, response, owner=owner, now=NOW, watermark="a")
        cached, next_owner, next_leader = cache.begin(
            identity, now=NOW + timedelta(seconds=seconds), watermark="a", loop=loop
        )
        assert (cached is not None) is (seconds < 1)
        if next_leader:
            cache.abort(identity, owner=next_owner)

    asyncio.run(scenario())


@pytest.mark.audit_ids("AUD-08")
def test_expired_inflight_warning_wakes_followers_without_becoming_a_cache_hit() -> None:
    async def scenario() -> None:
        cache = AssessmentResponseCache()
        loop = asyncio.get_running_loop()
        key = {"name": "synthetic"}
        _, owner, _ = cache.begin(key, now=NOW, watermark="a", loop=loop)
        _, follower, leader = cache.begin(key, now=NOW, watermark="a", loop=loop)
        assert follower is owner and not leader
        cache.complete(
            key,
            {"preliminary_warnings": [{"state": "active", "expires_at": timestamp(NOW)}]},
            owner=owner,
            now=NOW,
            watermark="a",
        )
        await follower
        assert not cache.values and cache.serialized_bytes == 0
        cached, replacement, leader = cache.begin(key, now=NOW, watermark="a", loop=loop)
        assert cached is None and leader
        cache.abort(key, owner=replacement)

    asyncio.run(scenario())


@pytest.mark.audit_ids("AUD-08")
@pytest.mark.parametrize("watermark", ["corrected", None])
def test_corrections_and_changes_during_computation_cannot_reuse_old_results(watermark) -> None:
    async def scenario() -> None:
        cache = AssessmentResponseCache()
        loop = asyncio.get_running_loop()
        key = {"name": "synthetic"}
        _, owner, _ = cache.begin(key, now=NOW, watermark="original", loop=loop)
        cache.complete(key, {"result": "old"}, owner=owner, now=NOW, watermark=watermark)
        cached, replacement, leader = cache.begin(key, now=NOW, watermark="current", loop=loop)
        assert cached is None and leader
        cache.abort(key, owner=replacement)

    asyncio.run(scenario())


@pytest.mark.audit_ids("AUD-08")
def test_complete_visibility_watermark_detects_an_older_out_of_order_commit(database) -> None:
    with database.engine.connect() as blocker, database.engine.connect() as older:
        blocker.execute(text("SELECT pg_current_xact_id()"))
        older.execute(text("SELECT pg_current_xact_id()"))
        with database.engine.begin() as newer:
            newer.execute(text("SELECT pg_current_xact_id()"))
        with Session(database.engine) as session:
            before = assessment_watermark(session)
            snapshot_before = session.scalar(text("SELECT pg_current_snapshot()::text"))
        older.commit()
        with Session(database.engine) as session:
            after = assessment_watermark(session)
            snapshot_after = session.scalar(text("SELECT pg_current_snapshot()::text"))
        # Neither maximum nor minimum alone changes here: only xip records the
        # older writer's newly visible commit while the oldest transaction remains.
        assert snapshot_before.split(":")[:2] == snapshot_after.split(":")[:2]
        assert before != after
        with Session(database.engine) as session:
            assert assessment_watermark(session) == after
        blocker.rollback()


@pytest.mark.audit_ids("AUD-08")
def test_repeated_read_watermarks_do_not_allocate_a_writer_or_scan_evidence(database) -> None:
    with Session(database.engine) as session:
        before = assessment_watermark(session)
        assert session.scalar(text("SELECT pg_current_xact_id_if_assigned()")) is None
        assert assessment_watermark(session) == before


@pytest.mark.audit_ids("AUD-10")
def test_cache_bounds_mixed_sizes_and_expired_untouched_entries() -> None:
    async def scenario() -> None:
        cache = AssessmentResponseCache(max_bytes=512, max_entry_bytes=300)
        loop = asyncio.get_running_loop()
        for index, length in enumerate((100, 200, 200, 400, 100)):
            key = {"name": str(index)}
            _, owner, _ = cache.begin(key, now=NOW, watermark="a", loop=loop)
            cache.complete(key, {"body": "x" * length}, owner=owner, now=NOW, watermark="a")
            assert cache.serialized_bytes <= 512
            assert all(len(entry.payload) <= 300 for entry in cache.values.values())
            assert owner.done()
        assert cache.values
        cache.expire(now=NOW + timedelta(minutes=5))
        assert cache.serialized_bytes == 0 and not cache.values

    asyncio.run(scenario())


@pytest.mark.audit_ids("AUD-10")
def test_cache_clock_rollback_and_caller_mutation_do_not_preserve_unsafe_values() -> None:
    async def scenario() -> None:
        cache = AssessmentResponseCache()
        loop = asyncio.get_running_loop()
        key = {"name": "synthetic"}
        _, owner, _ = cache.begin(key, now=NOW, watermark="a", loop=loop)
        response = {"nested": [{"value": "original"}]}
        cache.complete(key, response, owner=owner, now=NOW, watermark="a")
        response["nested"][0]["value"] = "caller mutation"
        cached, _, _ = cache.begin(key, now=NOW, watermark="a", loop=loop)
        assert cached == {"nested": [{"value": "original"}]}
        cached["nested"][0]["value"] = "second caller mutation"
        again, _, _ = cache.begin(key, now=NOW, watermark="a", loop=loop)
        assert again == {"nested": [{"value": "original"}]}
        cache.expire(now=NOW - timedelta(microseconds=1))
        assert not cache.values

    asyncio.run(scenario())


@pytest.mark.audit_ids("AUD-10")
def test_inflight_admission_and_attempt_ownership_remain_bounded() -> None:
    async def scenario() -> None:
        cache = AssessmentResponseCache(max_inflight=2)
        loop = asyncio.get_running_loop()
        first = {"name": "first"}
        second = {"name": "second"}
        _, old, _ = cache.begin(first, now=NOW, watermark="a", loop=loop)
        _, other, _ = cache.begin(second, now=NOW, watermark="a", loop=loop)
        with pytest.raises(AssessmentCacheCapacityError):
            cache.begin({"name": "third"}, now=NOW, watermark="a", loop=loop)
        cache.abort(first, owner=old)
        _, replacement, _ = cache.begin(first, now=NOW, watermark="a", loop=loop)
        cache.complete(first, {"old": True}, owner=old, now=NOW, watermark="a")
        cache.abort(first, owner=old)
        assert not replacement.done() and len(cache._inflight) == 2
        cache.abort(first, owner=replacement)
        cache.abort(second, owner=other)
        assert not cache._inflight

    asyncio.run(scenario())


@pytest.mark.audit_ids("AUD-10")
@pytest.mark.parametrize("profile", ["large_responses", "many_keys"])
def test_serialized_cache_has_measured_headroom_under_maximum_sized_churn(profile) -> None:
    async def scenario() -> None:
        gc.collect()
        tracemalloc.start()
        try:
            baseline, _ = tracemalloc.get_traced_memory()
            cache = AssessmentResponseCache()
            loop = asyncio.get_running_loop()
            # Nested independent report strings exercise object allocation rather
            # than measuring one aliased giant string or retained input references.
            many_keys = profile == "many_keys"
            for index in range(11_000 if many_keys else 90):
                response = {
                    "reports": [
                        {
                            "name": f"report-{index}-{item}",
                            "body": str(item) + "x" * (6600 if many_keys else 9000),
                        }
                        for item in range(1 if many_keys else 100)
                    ]
                }
                key = {"name": f"synthetic-{index}"}
                if many_keys:
                    name = f"synthetic-{index}-" + "x" * 280
                    version = "1." + "2" * 198
                    key = {"name": name, "version": version, "coordinate": f"npm:{name}@{version}"}
                _, owner, _ = cache.begin(key, now=NOW, watermark="a", loop=loop)
                cache.complete(key, response, owner=owner, now=NOW, watermark="a")
            current, peak = tracemalloc.get_traced_memory()
            assert CACHE_MAX_BYTES - 1024 * 1024 < cache.serialized_bytes <= CACHE_MAX_BYTES
            assert current - baseline < CACHE_MAX_BYTES + (16 if many_keys else 8) * 1024 * 1024
            assert peak - baseline < CACHE_MAX_BYTES + 20 * 1024 * 1024
            cache.expire(now=NOW + timedelta(minutes=5))
            assert not cache.values and cache.serialized_bytes == 0
        finally:
            tracemalloc.stop()

    asyncio.run(scenario())
