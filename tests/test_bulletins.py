"""Real disposable PostgreSQL: publication, bootstrap races, expiry and revocation."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from smithguard import bulletin_store as store
from smithguard.bulletin_contract import BulletinError, validate_content
from smithguard.bulletin_policy import authorize, policy_hash
from smithguard.db.bulletin_models import (
    BulletinDecision,
    BulletinPublicVersion,
    BulletinRevision,
)
from smithguard.source_rights import RightsRegistry

NOW = datetime(2026, 10, 21, 12, tzinfo=UTC)
REGISTRY = RightsRegistry.from_path(
    Path(__file__).resolve().parents[1] / "contracts/v1/source-rights-register.json"
)
GRANT = {
    "schema_version": 1,
    "policy_id": "official-bulletins-v1",
    "policy_hash": policy_hash(),
    "operation_id": "20261021-" + "1" * 32,
    "artifact_commit": "a" * 40,
    "mode": "manual_preview",
    "source_keys": ["php", "mozilla", "kev"],
    "effective_at": "2026-10-21T00:00:00Z",
    "review_due_at": "2026-11-01T00:00:00Z",
    "rights_register_hash": "sha256:" + "a" * 64,
}


def content(number=1):
    url = f"https://github.com/advisories/GHSA-synthetic-{number}"
    return {
        "schema_version": "1.0.0",
        "source_key": "reviewed",
        "record_url": url,
        "evidence_class": "official_advisory",
        "verification": "analyst_reviewed",
        "applicability": "not_evaluated",
        "lifecycle": "current",
        "title": "Synthetic notice",
        "summary": "Synthetic regression evidence, never public production content.",
        "subjects": ["Synthetic product"],
        "aliases": [],
        "source_published_at": "2026-10-21T10:00:00Z",
        "source_modified_at": None,
        "time_precision": "exact",
        "severity": "unknown",
        "exploitation": "no_claim",
        "remediation": "unknown",
        "conditions": [],
        "guidance": [],
        "unknowns": ["Installation applicability has not been assessed."],
        "sources": [
            {
                "source_id": "gbsec:source:github-advisory-database",
                "record_url": url,
                "source_evidence_hash": "sha256:" + "b" * 64,
                "rights_revision": 4,
                "attribution": "GitHub Advisory Database",
                "used_fields": ["ghsa_id", "vulnerabilities.package"],
            }
        ],
        "related_bulletins": [],
        "retrospective": True,
    }


def publish(session, doc=None, *, approval=1, now=NOW):
    return store.publish(
        session,
        doc or content(),
        grant=GRANT,
        registry=REGISTRY,
        now=now,
        manual_approval=f"{approval:064x}",
    )


def test_newest_snapshot_orders_full_collection_and_freezes_dates_across_pages(database):
    records = []
    with Session(database.engine) as session, session.begin():

        def emit(document, *, approval, now=NOW):
            return store.publish(
                session,
                document,
                registry=REGISTRY,
                grant={**GRANT, "mode": "automatic"},
                now=now,
                manual_approval=f"{approval:064x}",
            )

        for index in range(37):
            document = content(index + 1)
            document["source_published_at"] = (
                store.timestamp(NOW - timedelta(days=index % 9, microseconds=index % 3))
                if index < 34
                else None
            )
            document["time_precision"] = "exact" if index < 34 else "unknown"
            record = emit(document, approval=index + 1)
            records.append((document, record))
        store.status_tick(session, now=NOW)
        expected = sorted(
            records,
            key=lambda pair: (
                datetime.fromisoformat(pair[0]["source_published_at"].replace("Z", "+00:00"))
                if pair[0]["source_published_at"]
                else datetime.min.replace(tzinfo=UTC),
                pair[1]["bulletin_id"],
            ),
            reverse=True,
        )
        page = store.snapshot(session, now=NOW, order="newest", limit=7)
        seen = list(page["items"])
        assert [r["bulletin_id"] for r in seen] == [r[1]["bulletin_id"] for r in expected[:7]]
        watermark = page["watermark"]
        cursor = page["next_cursor"]
        # New arrivals and source-date corrections after this watermark must
        # not change the order/membership of the ongoing page traversal.
        later = NOW + timedelta(seconds=1)
        emit(content(100), approval=100, now=later)
        changed = deepcopy(expected[12][0])
        changed["source_published_at"] = store.timestamp(later)
        emit(changed, approval=101, now=later)
        # Rechecks neither create a new version nor promote an old source date.
        target = store.detail(session, expected[20][1]["bulletin_id"], now=later)
        store.verify_unchanged(
            session,
            target["bulletin_id"],
            content_hash=target["content_hash"],
            grant=GRANT,
            registry=REGISTRY,
            now=later,
            manual_approval="d" * 64,
        )
        # Removing an already-seen item cannot cause a second appearance at the
        # unknown-date tail; an unseen removal is omitted immediately.
        store.tombstone(session, expected[0][1]["bulletin_id"], now=later)
        removed = expected[15][1]["bulletin_id"]
        store.tombstone(session, removed, now=later)
        while cursor:
            page = store.snapshot(session, now=later, order="newest", cursor=cursor, limit=7)
            assert page["watermark"] == watermark
            seen.extend(page["items"])
            cursor = page["next_cursor"]
        assert [r["bulletin_id"] for r in seen] == [
            r[1]["bulletin_id"] for r in expected if r[1]["bulletin_id"] != removed
        ]
        assert len({r["bulletin_id"] for r in seen}) == len(seen)
        assert page["changes_cursor"]
        assert store.events(session, now=later, cursor=page["changes_cursor"])["items"]
        fresh = store.snapshot(session, now=later, order="newest")
        assert fresh["items"][0]["bulletin_id"] == expected[12][1]["bulletin_id"]
        # The existing default retains identity order and removal stubs.
        default = store.snapshot(session, now=later)
        ids = [r["bulletin_id"] for r in default["items"]]
        assert ids == sorted(ids)
        assert sum(r["tombstoned"] for r in default["items"]) == 2


def test_newest_snapshot_cursor_binds_order_filters_and_valid_time(database):
    with Session(database.engine) as session, session.begin():
        for i in range(3):
            publish(session, content(i), approval=i + 1)
        store.status_tick(session, now=NOW)
        cursor = store.snapshot(session, now=NOW, order="newest", limit=1)["next_cursor"]
        for kwargs in ({}, {"order": "newest", "subject": "Other"}):
            with pytest.raises(BulletinError, match="cursor_invalid"):
                store.snapshot(session, now=NOW, cursor=cursor, **kwargs)
        payload = store.decode_cursor(
            cursor,
            kind="snapshot_newest",
            filters=store._filters(None, None, None),
            now=NOW,
            maximum=store.stream_status(session, now=NOW)["watermark"],
        )
        for after in (
            "invalid",
            {},
            {"identity": "0" * 64, "published_at": "tomorrow"},
            {"identity": "0" * 64, "published_at": "2027-01-01T00:00:00Z"},
        ):
            with pytest.raises(BulletinError, match="cursor_invalid"):
                store.snapshot(
                    session,
                    now=NOW,
                    order="newest",
                    cursor=store.encode_cursor({**payload, "after": after}),
                )


def test_publication_correction_is_immutable_and_isolated(database):
    with Session(database.engine) as session, session.begin():
        initial = publish(session)
        changed = content()
        changed.update(lifecycle="corrected", severity="high")
        corrected = publish(session, changed, approval=2)
        store.status_tick(session, now=NOW)
        assert corrected["revision"] == 2
        current = store.detail(session, initial["bulletin_id"], now=NOW)
        historical = store.detail(session, initial["bulletin_id"], now=NOW, revision=1)
        assert current["content"]["severity"] == "high"
        assert historical["content"]["severity"] == "unknown"
        assert historical["historical"] is True
        assert current["predecessor_hash"] == historical["content_hash"]
        assert current["content"]["applicability"] == "not_evaluated"
        assert session.scalar(text("SELECT count(*) FROM smithguard.incidents")) == 0
        assert [v["kind"] for v in store.events(session, now=NOW)["items"]] == [
            "published",
            "corrected",
        ]
    with (
        Session(database.engine) as session,
        pytest.raises(DBAPIError, match="immutable|append-only"),
    ):
        session.execute(text("UPDATE smithguard.bulletin_revisions SET document = '{}'::jsonb"))


def test_takedown_removes_every_public_version_preserves_private_evidence(database):
    with Session(database.engine) as session, session.begin():
        initial = publish(session)
        changed = content()
        changed["summary"] = "A corrected synthetic summary."
        publish(session, changed, approval=2)
        assert store.tombstone(session, initial["bulletin_id"], now=NOW)
        assert not store.tombstone(session, initial["bulletin_id"], now=NOW)
        store.status_tick(session, now=NOW)
        for revision in (None, 1, 2):
            value = store.detail(session, initial["bulletin_id"], now=NOW, revision=revision)
            assert value["content"] is None and value["tombstoned"]
        assert all(doc == {} for doc in session.scalars(select(BulletinPublicVersion.document)))
        assert len(session.scalars(select(BulletinRevision.document)).all()) == 2
        assert store.snapshot(session, now=NOW)["items"][0]["content"] is None
        events = store.events(session, now=NOW)["items"]
        assert [e["kind"] for e in events][-3:] == [
            "public_tombstoned",
            "public_purge_requested",
            "public_purged",
        ]
        assert "summary" not in str(events)
        with pytest.raises(BulletinError, match="tombstone_permanent"):
            publish(session, content(), approval=3)


def test_snapshot_concurrent_update_and_new_record_not_lost(database):
    with Session(database.engine) as session, session.begin():
        initial = [publish(session, content(i), approval=i) for i in range(1, 5)]
        store.status_tick(session, now=NOW)
    with Session(database.engine) as session:
        first = store.snapshot(session, now=NOW, limit=1)
    with Session(database.engine) as session, session.begin():
        changed = content(3)
        changed["summary"] = "Changed after the snapshot watermark."
        updated = publish(session, changed, approval=30)
        added = publish(session, content(5), approval=5)
    values = first["items"]
    page = first
    while page["next_cursor"]:
        with Session(database.engine) as session:
            page = store.snapshot(session, now=NOW, limit=1, cursor=page["next_cursor"])
            values += page["items"]
    assert {v["bulletin_id"] for v in values} == {v["bulletin_id"] for v in initial}
    assert all(v["revision"] == 1 for v in values)
    with Session(database.engine) as session:
        changes = store.events(session, now=NOW, cursor=page["changes_cursor"])
    assert [e["sequence"] for e in changes["items"]] == [updated["sequence"], added["sequence"]]


def test_event_watermark_stable_during_pagination(database):
    with Session(database.engine) as session, session.begin():
        for i in range(1, 4):
            publish(session, content(i), approval=i)
        store.status_tick(session, now=NOW)
        page = store.events(session, now=NOW, limit=1)
        publish(session, content(4), approval=4)
        second = store.events(session, now=NOW, limit=1, cursor=page["next_cursor"])
        third = store.events(session, now=NOW, limit=1, cursor=second["next_cursor"])
        assert [page["watermark"], second["watermark"], third["watermark"]] == [3, 3, 3]
        assert not third["has_more"]
        fourth = store.events(session, now=NOW, cursor=third["next_cursor"])
        assert [v["sequence"] for v in fourth["items"]] == [4]


def test_deadline_enforced_without_worker_and_no_false_checkpoint(database):
    with Session(database.engine) as session, session.begin():
        record = publish(session)
        store.status_tick(session, now=NOW)
        later = NOW + timedelta(hours=24, minutes=6)
        value = store.detail(session, record["bulletin_id"], now=later)
        assert value["freshness"] == "stale"
        assert value["freshness_reason"] == "verification_overdue"
        assert store.snapshot(session, now=later)["changes_cursor"] is None
        with pytest.raises(BulletinError, match="stream_unavailable"):
            store.events(session, now=later)
        assert store.status_tick(session, now=later) == 1
        assert store.status_tick(session, now=later) == 0
        assert store.events(session, now=later)["items"][-1]["kind"] == "freshness_stale"


def test_emerging_expiry_never_renewed_by_correction(database):
    with Session(database.engine) as session, session.begin():
        doc = content()
        doc["evidence_class"] = "emerging_report"
        record = publish(session, doc)
        doc["summary"] = "A correction, not a renewed allegation."
        publish(session, doc, approval=2, now=NOW + timedelta(hours=12))
        later = NOW + timedelta(hours=25)
        assert (
            store.detail(session, record["bulletin_id"], now=later)["effective_lifecycle"]
            == "expired"
        )
        store.status_tick(session, now=later)
        assert store.events(session, now=later)["items"][-1]["kind"] == "expired"


def test_pause_or_expired_rights_cannot_block_neutral_takedown(database):
    with Session(database.engine) as session, session.begin():
        record = publish(session)
        with pytest.raises(BulletinError, match="rights_not_current"):
            authorize(
                content(),
                {
                    **GRANT,
                    "effective_at": "2026-11-01T00:00:00Z",
                    "review_due_at": "2026-11-20T00:00:00Z",
                },
                REGISTRY,
                now=datetime(2026, 11, 8, tzinfo=UTC),
                manual_approval="2" * 64,
            )
        assert store.tombstone(session, record["bulletin_id"], now=NOW + timedelta(days=40))


def test_approval_is_one_use_and_rollback_does_not_consume_event_number(database):
    with Session(database.engine) as session, session.begin():
        publish(session)
    with (
        Session(database.engine) as session,
        pytest.raises(BulletinError, match="approval_consumed"),
        session.begin(),
    ):
        publish(session, content(2))
    with Session(database.engine) as session, session.begin():
        assert publish(session, content(2), approval=2)["sequence"] == 2
        assert session.scalar(select(func.count()).select_from(BulletinDecision)) == 2


@pytest.mark.parametrize(
    "mutation",
    [
        {"applicability": "affected"},
        {"title": "Bad\u202etext"},
        {"private_inventory": []},
        {"source_published_at": "2027-01-01T00:00:00Z"},
        {"summary": "x" * 1201},
        {"evidence_class": "emerging_report", "verification": "independently_corroborated"},
    ],
)
def test_closed_content_rejects_unsupported_authority_and_injection(mutation):
    with pytest.raises(BulletinError):
        validate_content({**content(), **mutation}, now=NOW)


def test_cursor_binding_expiry_and_bad_inputs(database):
    with Session(database.engine) as session, session.begin():
        publish(session)
        store.status_tick(session, now=NOW)
        page = store.snapshot(session, now=NOW)
        with pytest.raises(BulletinError, match="cursor_invalid"):
            store.events(session, now=NOW, cursor=page["changes_cursor"], identity="a" * 64)
        payload = {
            "v": 1,
            "kind": "snapshot",
            "filters": {"source": None, "evidence_class": None, "subject": None},
            "upper": 1,
            "after": "",
            "issued": "2026-01-01T00:00:00Z",
        }
        with pytest.raises(BulletinError, match="cursor_expired"):
            store.snapshot(session, now=NOW, cursor=store.encode_cursor(payload))
        for bad in ("!", "x" * 3000, store.encode_cursor({**payload, "upper": 100})):
            with pytest.raises(BulletinError, match="cursor_invalid"):
                store.snapshot(session, now=NOW, cursor=bad)


def test_source_change_marks_preview_stale_and_review_can_reverify(database):
    with Session(database.engine) as session, session.begin():
        record = publish(session)
        assert store.mark_stale(
            session, record["bulletin_id"], now=NOW, reason="verification_pending"
        )
        value = store.detail(session, record["bulletin_id"], now=NOW)
        assert value["freshness"] == "stale"
        store.verify_unchanged(
            session,
            record["bulletin_id"],
            content_hash=value["content_hash"],
            grant=GRANT,
            registry=REGISTRY,
            now=NOW,
            manual_approval="2" * 64,
        )
        assert store.detail(session, record["bulletin_id"], now=NOW)["freshness"] == "fresh"


def test_storage_reserve_blocks_new_admissions_not_takedown(database, monkeypatch):
    with Session(database.engine) as session, session.begin():
        record = publish(session)
        monkeypatch.setattr(store, "allocated_bytes", lambda session: store.MAX_ADDITIONAL_BYTES)
        with pytest.raises(BulletinError, match="storage_capacity"):
            publish(session, content(2), approval=2)
        assert store.tombstone(session, record["bulletin_id"], now=NOW)


def test_field_rights_reference_must_be_current_and_exact():
    doc = deepcopy(content())
    doc["sources"][0]["rights_revision"] = 1
    with pytest.raises(BulletinError, match="rights_not_current"):
        authorize(doc, GRANT, REGISTRY, now=NOW, manual_approval="1" * 64)
    with pytest.raises(BulletinError, match="manual_review_required"):
        authorize(content(), {**GRANT, "mode": "automatic"}, REGISTRY, now=NOW)
    with pytest.raises(BulletinError, match="not_effective"):
        authorize(content(), GRANT, REGISTRY, now=NOW - timedelta(days=1), manual_approval="1" * 64)


def test_same_day_burst_retains_tombstones_and_resource_bounds(database, monkeypatch):
    grant = {**GRANT, "mode": "automatic"}
    monkeypatch.setattr(store, "MAX_PUBLIC_IDENTITIES", 32)
    with Session(database.engine) as session, session.begin():
        records = [
            store.publish(
                session,
                content(number),
                grant=grant,
                registry=REGISTRY,
                now=NOW,
                manual_approval=f"{number:064x}",
            )
            for number in range(1, 33)
        ]
        assert len(records) == 32
        assert store.tombstone(session, records[0]["bulletin_id"], now=NOW)
        with pytest.raises(BulletinError, match="bulletin_admission_capacity"):
            store.publish(
                session,
                content(33),
                grant=grant,
                registry=REGISTRY,
                now=NOW,
                manual_approval=f"{33:064x}",
            )
        # A consumed identity stays consumed, while the correction reserve remains usable.
        monkeypatch.setattr(
            store,
            "allocated_bytes",
            lambda session: store.MAX_ADDITIONAL_BYTES - store.CORRECTION_RESERVE,
        )
        changed = content(2)
        changed.update(lifecycle="corrected", summary="Corrected synthetic facts.")
        correction = store.publish(
            session, changed, grant=grant, registry=REGISTRY, now=NOW, manual_approval=f"{34:064x}"
        )
        assert correction["revision"] == 2
        with pytest.raises(BulletinError, match="bulletin_storage_capacity"):
            store.publish(
                session,
                content(33),
                grant=grant,
                registry=REGISTRY,
                now=NOW,
                manual_approval=f"{35:064x}",
            )


@pytest.mark.parametrize("fraction", ["1234567", "9999999", "123456789"])
def test_newest_cursor_uses_database_fraction_precision_without_skipping(database, fraction):
    with Session(database.engine) as session, session.begin():
        expected = []
        for index in range(3):
            document = content(index)
            document["source_published_at"] = f"2026-10-20T00:00:00.{fraction}Z"
            expected.append(publish(session, document, approval=index + 1)["bulletin_id"])
        seen, cursor = [], None
        while True:
            page = store.snapshot(session, now=NOW, order="newest", limit=1, cursor=cursor)
            seen.extend(item["bulletin_id"] for item in page["items"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert seen == sorted(expected, reverse=True)


def test_newest_fraction_rounding_at_snapshot_time_keeps_cursor_valid(database):
    now = NOW.replace(microsecond=999999)
    with Session(database.engine) as session, session.begin():
        expected = []
        for index in range(2):
            document = content(index)
            document["source_published_at"] = NOW.strftime("%Y-%m-%dT%H:%M:%S.9999999Z")
            expected.append(
                store.publish(
                    session,
                    document,
                    registry=REGISTRY,
                    grant=GRANT,
                    now=now,
                    manual_approval=f"{index + 1:064x}",
                )["bulletin_id"]
            )
        first = store.snapshot(session, now=now, order="newest", limit=1)
        second = store.snapshot(
            session, now=now, order="newest", limit=1, cursor=first["next_cursor"]
        )
        assert [first["items"][0]["bulletin_id"], second["items"][0]["bulletin_id"]] == sorted(
            expected, reverse=True
        )
        assert second["next_cursor"] is None


def test_newest_cursor_survives_publication_after_request_clock_before_watermark(database):
    # The API captures request time before reading the committed stream watermark.
    # A concurrent publisher can commit a source date in that small interval.
    request_started = NOW
    published_at = NOW + timedelta(milliseconds=5)
    next_request = published_at + timedelta(milliseconds=5)
    with Session(database.engine) as session, session.begin():
        expected = []
        for index in range(2):
            document = content(index)
            document["source_published_at"] = store.timestamp(published_at)
            expected.append(
                publish(session, document, approval=index + 1, now=published_at)["bulletin_id"]
            )
    with Session(database.engine) as session, session.begin():
        first = store.snapshot(session, now=request_started, order="newest", limit=1)
        second = store.snapshot(
            session, now=next_request, order="newest", limit=1, cursor=first["next_cursor"]
        )
        assert [first["items"][0]["bulletin_id"], second["items"][0]["bulletin_id"]] == sorted(
            expected, reverse=True
        )
        assert first["watermark"] == second["watermark"]
        assert second["next_cursor"] is None
