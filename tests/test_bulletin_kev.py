"""CISA additions use retained catalogs, exact CVE identity and durable tails."""

from copy import deepcopy
from datetime import timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard import bulletin_kev as kev
from smithguard import bulletin_runtime as runtime
from smithguard import bulletin_store as store
from smithguard.bulletin_contract import BulletinError, content_id
from smithguard.db.bulletin_models import (
    BulletinCurrent,
    BulletinDecision,
    BulletinEvent,
    BulletinRevision,
    BulletinSourceStatus,
    OfficialSourceCheckpoint,
)
from smithguard.source_rights import SourceProfile
from smithguard.supplemental_store import KEV_SOURCE, append_snapshot

from .test_bulletins import GRANT, NOW, REGISTRY


def grant_reader(*, now):
    return {**GRANT, "mode": "automatic"}


def snapshot(session, cves, *, now=NOW, state="complete"):
    return append_snapshot(
        session,
        source_id=KEV_SOURCE,
        mode="public",
        state=state,
        observed_at=now,
        source_as_of=now if state == "complete" else None,
        document={},
        facts={cve: {"date_added": day} for cve, day in cves.items()},
    )


def tick(session, *, now=NOW):
    return kev.run(session, registry=REGISTRY, grant_reader=grant_reader, now=now)


def test_checkpoint_no_backfill_and_current_additions_have_distinct_ids(database):
    with Session(database.engine) as session, session.begin():
        snapshot(session, {"CVE-2026-1000": "2026-10-20"})
        assert tick(session)["status"] == "checkpointed"
        assert session.scalar(select(func.count()).select_from(BulletinCurrent)) == 0
        snapshot(
            session,
            {
                "CVE-2026-1000": "2026-10-20",
                "CVE-2026-1001": "2026-10-21",
                "CVE-2026-1002": "2026-10-21",
            },
            now=NOW + timedelta(hours=1),
        )
        result = tick(session, now=NOW + timedelta(hours=1))
        assert result["status"] == "fresh" and result["changes"] == 2
        assert result["network_attempts"] == 0
        rows = session.scalars(select(BulletinRevision)).all()
        assert len({r.bulletin_id for r in rows}) == 2
        assert all(r.document["record_url"] == kev.CATALOG for r in rows)
        assert {r.document["source_record_id"] for r in rows} == {"CVE-2026-1001", "CVE-2026-1002"}
        assert all(r.document["guidance"] == [] for r in rows)
        assert all(r.document["retrospective"] is False for r in rows)
        decisions = session.scalars(select(BulletinDecision)).all()
        assert all(r.document["accepted_observation"]["snapshot_id"] for r in decisions)
        assert tick(session, now=NOW + timedelta(hours=2))["changes"] == 0


def test_unchanged_catalog_renews_without_new_revision_and_binds_expiry(database):
    with Session(database.engine) as session, session.begin():
        snapshot(session, {})
        tick(session)
        snapshot(session, {"CVE-2026-1001": "2026-10-21"}, now=NOW + timedelta(hours=1))
        tick(session, now=NOW + timedelta(hours=1))
        # An unchanged catalog receipt is evidence, never a new notice revision.
        snapshot(session, {"CVE-2026-1001": "2026-10-21"}, now=NOW + timedelta(hours=21))
        tick(session, now=NOW + timedelta(hours=21))
        tick(session, now=NOW + timedelta(hours=24))
        row = session.scalar(select(BulletinCurrent))
        assert row.revision == 1
        assert row.verification_due_at == NOW + timedelta(hours=48)
        tick(session, now=NOW + timedelta(hours=47))
        assert row.verification_due_at == NOW + timedelta(hours=51)
        assert tick(session, now=NOW + timedelta(hours=52))["status"] == "unavailable"


def test_correction_before_new_tail_and_absence_is_not_withdrawal(database, monkeypatch):
    with Session(database.engine) as session, session.begin():
        snapshot(session, {})
        tick(session)
        snapshot(session, {"CVE-2026-1001": "2026-10-20"}, now=NOW + timedelta(hours=1))
        tick(session, now=NOW + timedelta(hours=1))
        values = {f"CVE-2026-{i}": "2026-10-21" for i in range(1001, 1043)}
        snapshot(session, values, now=NOW + timedelta(hours=2))
        result = tick(session, now=NOW + timedelta(hours=2))
        assert result["pending_snapshot"] and result["changes"] == 21
        identity = content_id({"source_key": "kev", "source_record_id": "CVE-2026-1001"})
        assert session.get(BulletinCurrent, identity).revision == 2
        tick(session, now=NOW + timedelta(hours=3))
        assert tick(session, now=NOW + timedelta(hours=4))["status"] == "fresh"
        snapshot(session, {}, now=NOW + timedelta(hours=5))
        assert tick(session, now=NOW + timedelta(hours=5))["status"] == "fresh"
        current = session.get(BulletinCurrent, identity)
        assert current.freshness_reason == "catalog_entry_absent"
        assert (
            session.get(BulletinRevision, (identity, current.revision)).document["lifecycle"]
            == "current"
        )


def test_failed_latest_snapshot_and_invented_facts_fail_closed(database):
    with Session(database.engine) as session, session.begin():
        snapshot(session, {})
        tick(session)
        snap = snapshot(session, {"CVE-2026-1001": "2026-10-21"})
        value = kev.fact(session, snap, "CVE-2026-1001")
        document = kev.project_kev(value, REGISTRY, now=NOW)
        document["summary"] = "Invented advice"
        with pytest.raises(BulletinError, match="projection_mismatch"):
            store.publish(
                session, document, grant=grant_reader(now=NOW), registry=REGISTRY, now=NOW
            )
        snapshot(session, {}, now=NOW + timedelta(hours=1), state="failed")
        assert tick(session, now=NOW + timedelta(hours=1))["status"] == "unavailable"
        assert session.get(OfficialSourceCheckpoint, "kev").document["baseline_sequence"] == 1


def test_preview_checkpoint_does_not_publish_and_paused_never_advances(database):
    with Session(database.engine) as session, session.begin():
        snapshot(session, {})
        assert (
            kev.run(session, registry=REGISTRY, grant_reader=lambda **_: GRANT, now=NOW)["status"]
            == "checkpointed"
        )
        snapshot(session, {"CVE-2026-1001": "2026-10-21"}, now=NOW + timedelta(hours=1))
        assert (
            kev.run(
                session,
                registry=REGISTRY,
                grant_reader=lambda **_: GRANT,
                now=NOW + timedelta(hours=1),
            )["status"]
            == "paused"
        )
        assert session.scalar(select(func.count()).select_from(BulletinCurrent)) == 0
        assert tick(session, now=NOW + timedelta(hours=2))["changes"] == 1


def test_historical_catalog_facts_cannot_bypass_checkpoint(database):
    with Session(database.engine) as session, session.begin():
        snap = snapshot(session, {"CVE-2026-1001": "2026-10-21"})
        value = kev.fact(session, snap, "CVE-2026-1001")
        document = kev.project_kev(value, REGISTRY, now=NOW)
        with pytest.raises(BulletinError, match="baseline_required"):
            store.publish(
                session, document, grant=grant_reader(now=NOW), registry=REGISTRY, now=NOW
            )
        tick(session)
        with pytest.raises(BulletinError, match="historical_backfill_forbidden"):
            store.publish(
                session, document, grant=grant_reader(now=NOW), registry=REGISTRY, now=NOW
            )


@pytest.mark.parametrize("population", [400, 1000])
def test_deadline_priority_keeps_large_population_current(database, monkeypatch, population):
    cases = {f"CVE-2026-{i}": "2026-10-21" for i in range(1000, 1000 + population)}
    with Session(database.engine) as session, session.begin():
        snapshot(session, {})
        tick(session)
        snapshot(session, cases, now=NOW + timedelta(hours=1))
        for hour in range(1, 121):
            at = NOW + timedelta(hours=hour)
            if hour > 1 and hour % 6 == 1:
                snapshot(session, cases, now=at)
            result = tick(session, now=at)
            assert result["deadline_checks"] <= 200
            assert result["changes"] <= 300
            page = store.snapshot(session, now=at, limit=100)
            assert all(row["freshness"] == "fresh" for row in page["items"]), hour
            # Once the initial bounded admission tail drains, unchanged six-hour
            # snapshots keep up without waiting for a full population rotation.
            if hour > 2 * (population // 20):
                assert not result["pending_snapshot"], hour
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(BulletinCurrent)
                    .where(BulletinCurrent.verification_due_at <= at)
                )
                == 0
            ), hour
        assert session.scalar(select(func.count()).select_from(BulletinCurrent)) == population
        cases.pop("CVE-2026-1000")
        at = NOW + timedelta(hours=121)
        snapshot(session, cases, now=at)
        assert tick(session, now=at)["status"] == "fresh"
        identity = content_id({"source_key": "kev", "source_record_id": "CVE-2026-1000"})
        assert store.detail(session, identity, now=at)["freshness_reason"] == "catalog_entry_absent"


def test_catalog_absence_is_local_and_reappearance_clears_it(database):
    with Session(database.engine) as session, session.begin():
        snapshot(session, {})
        tick(session)
        cases = {"CVE-2026-1001": "2026-10-21", "CVE-2026-1002": "2026-10-21"}
        snapshot(session, cases, now=NOW + timedelta(hours=1))
        tick(session, now=NOW + timedelta(hours=1))
        snapshot(session, {"CVE-2026-1002": "2026-10-21"}, now=NOW + timedelta(hours=2))
        assert tick(session, now=NOW + timedelta(hours=2))["status"] == "fresh"
        for cve in cases:
            identity = content_id({"source_key": "kev", "source_record_id": cve})
            result = store.detail(session, identity, now=NOW + timedelta(hours=2))
            assert result["freshness"] == ("stale" if cve.endswith("1001") else "fresh")
        snapshot(session, cases, now=NOW + timedelta(hours=3))
        tick(session, now=NOW + timedelta(hours=3))
        for current in session.scalars(select(BulletinCurrent)):
            assert current.freshness_reason is None


def test_identity_ceiling_preserves_catalog_tail(database, monkeypatch):
    monkeypatch.setattr(store, "MAX_KEV_IDENTITIES", 1)
    with Session(database.engine) as session, session.begin():
        snapshot(session, {})
        tick(session)
        snapshot(
            session,
            {"CVE-2026-1001": "2026-10-21", "CVE-2026-1002": "2026-10-21"},
            now=NOW + timedelta(hours=1),
        )
        result = tick(session, now=NOW + timedelta(hours=1))
        assert result["status"] == "incomplete"
        assert result["pending_snapshot"]
        assert session.scalar(select(func.count()).select_from(BulletinCurrent)) == 1
        assert (
            store.snapshot(session, now=NOW + timedelta(hours=1))["items"][0]["freshness"]
            == "fresh"
        )


@pytest.mark.parametrize("reason", ["catching_up", "publication_pending"])
def test_publication_debt_does_not_hide_record_or_source_failures(database, reason):
    with Session(database.engine) as session, session.begin():
        snapshot(session, {})
        tick(session)
        snapshot(session, {"CVE-2026-1001": "2026-10-21"})
        tick(session)
        source = session.get(BulletinSourceStatus, "kev")
        source.state, source.reason, source.pending_count = "incomplete", reason, 1
        current = session.scalar(select(BulletinCurrent))
        identity = current.bulletin_id
        assert store.detail(session, identity, now=NOW)["freshness"] == "fresh"
        assert store.source_status(session, now=NOW)["sources"][0]["state"] == "incomplete"
        overdue = store.detail(session, identity, now=NOW + timedelta(minutes=76))
        assert overdue["freshness_reason"] == "source_check_overdue"
        current.freshness_reason = "verification_pending"
        assert (
            store.detail(session, identity, now=NOW)["freshness_reason"] == "verification_pending"
        )
        source.reason = "finite_feed_gap"
        assert store.detail(session, identity, now=NOW)["freshness_reason"] == "finite_feed_gap"
        source.state, source.reason = "unavailable", "kev_snapshot_unavailable"
        assert store.detail(session, identity, now=NOW)["freshness"] == "unavailable"


def test_paused_stream_preserves_excluded_source_reason(database):
    with Session(database.engine) as session, session.begin():
        store.lock_stream(session, now=NOW)
        session.add(
            BulletinSourceStatus(
                source_key="mozilla",
                state="paused",
                reason="source_not_selected",
                pending_count=0,
                updated_at=NOW,
            )
        )
        session.flush()
        result = store.source_status(session, now=NOW)
        assert result["stream"]["mode"] == "paused"
        assert result["sources"][0]["reason"] == "source_not_selected"


def test_expired_kev_rights_keep_one_stale_reason_and_event(database):
    class ExpiredRegistry:
        def get(self, identity):
            profile = REGISTRY.get(identity)
            source = deepcopy(profile.source)
            source["rights"]["review_due_on"] = (NOW - timedelta(days=1)).date().isoformat()
            return SourceProfile(profile.activation, source, profile.field_rules)

    expired = ExpiredRegistry()
    with Session(database.engine) as session, session.begin():
        snapshot(session, {})
        tick(session)
        snapshot(session, {"CVE-2026-1001": "2026-10-21"})
        tick(session)
        current = session.scalar(select(BulletinCurrent))
        for hour in range(22, 27):
            at = NOW + timedelta(hours=hour)
            kev.run(session, registry=expired, grant_reader=grant_reader, now=at)
            runtime.status_tick(session, registry=expired, grant_reader=grant_reader, now=at)
            assert current.freshness_reason == "rights_review_due"
            assert session.scalar(select(func.count()).select_from(BulletinEvent)) == 2
