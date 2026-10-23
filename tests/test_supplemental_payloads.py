"""Shared storage preserves exact historical facts, atomicity and source semantics."""

from datetime import timedelta

import pytest
from sqlalchemy import event, func, insert, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

import smithguard.supplemental_store as store
from smithguard.db.models import (
    SupplementalFactRecord,
    SupplementalPayloadRecord,
    SupplementalSnapshotRecord,
)
from smithguard.identifiers import canonical_json_bytes, sha256_id, stable_id, timestamp
from tests.support import migrate, migrated_database
from tests.test_supplemental_store import CVE, NOW, add

BIG = {"date_added": "2021-12-10", "context": "retained exact source detail " * 40}


def assert_original_hashes(session, receipt, facts):
    rows = session.scalars(
        select(SupplementalFactRecord)
        .where(SupplementalFactRecord.snapshot_id == receipt.snapshot_id)
        .order_by(SupplementalFactRecord.subject_id)
    ).all()
    expected = [
        (
            subject,
            sha256_id(
                canonical_json_bytes(
                    {"snapshot_id": receipt.snapshot_id, "subject_id": subject, "document": fact}
                )
            ),
        )
        for subject, fact in sorted(facts.items())
    ]
    assert [(r.subject_id, r.record_hash) for r in rows] == expected
    document = {
        "snapshot_id": receipt.snapshot_id,
        "source_id": receipt.source_id,
        "mode": receipt.mode,
        "sequence": receipt.sequence,
        "state": receipt.state,
        "observed_at": timestamp(receipt.observed_at),
        "source_as_of": timestamp(receipt.source_as_of) if receipt.source_as_of else None,
        "record_count": len(facts),
        "document": receipt.document,
        "facts_sha256": sha256_id(canonical_json_bytes(expected)),
    }
    assert receipt.record_hash == sha256_id(canonical_json_bytes(document))


def test_reuse_keeps_every_membership_hash_and_public_result(database):
    with Session(database.engine) as session, session.begin():
        first = add(session, store.KEV_SOURCE, facts={CVE: BIG})
        second = add(session, store.KEV_SOURCE, facts={CVE: BIG}, now=NOW + timedelta(days=1))
        assert session.scalar(select(func.count()).select_from(SupplementalPayloadRecord)) == 1
        assert session.scalar(select(func.count()).select_from(SupplementalFactRecord)) == 2
        for receipt in (first, second):
            row = session.get(SupplementalFactRecord, (receipt.snapshot_id, CVE))
            assert row.document is None
            assert row.payload_sha256 == sha256_id(canonical_json_bytes(BIG))
            assert store.snapshot_facts(session, receipt.snapshot_id, [CVE]) == {CVE: BIG}
            assert_original_hashes(session, receipt, {CVE: BIG})
        result, _ = store.cve_context(session, [CVE], now=NOW + timedelta(days=1))
        assert result[0]["kev"]["value"] == BIG
        assert result[0]["kev"]["snapshot_id"] == second.snapshot_id


def test_corrections_failure_removal_and_shadow_keep_exact_content(database):
    changed = {**BIG, "date_added": "2022-01-01"}
    with Session(database.engine) as session, session.begin():
        old = add(session, store.KEV_SOURCE, facts={CVE: BIG})
        new = add(session, store.KEV_SOURCE, facts={CVE: changed}, now=NOW + timedelta(minutes=1))
        add(session, store.KEV_SOURCE, facts={}, state="failed", now=NOW + timedelta(minutes=2))
        add(session, store.KEV_SOURCE, facts={CVE: BIG}, mode="shadow")
        result, before = store.cve_context(session, [CVE], now=NOW + timedelta(minutes=2))
        assert result[0]["kev"]["value"] == changed
        assert result[0]["kev"]["state"] == "failed"
        assert result[0]["kev"]["snapshot_id"] == new.snapshot_id
        assert store.snapshot_facts(session, old.snapshot_id, [CVE]) == {CVE: BIG}
        add(session, store.KEV_SOURCE, facts={}, now=NOW + timedelta(minutes=3))
        result, after = store.cve_context(session, [CVE], now=NOW + timedelta(minutes=3))
        assert result[0]["kev"]["listed"] is False
        assert result[0]["kev"]["value"] is None
        assert before != after
        assert session.scalar(select(func.count()).select_from(SupplementalPayloadRecord)) == 2


def test_small_payloads_stay_inline_and_new_payloads_rollback(database):
    with Session(database.engine) as session:
        small = add(session)
        assert session.get(SupplementalFactRecord, (small.snapshot_id, CVE)).document is not None
        assert session.scalar(select(func.count()).select_from(SupplementalPayloadRecord)) == 0
        add(session, store.KEV_SOURCE, facts={CVE: BIG})
        session.rollback()
        for model in (
            SupplementalPayloadRecord,
            SupplementalFactRecord,
            SupplementalSnapshotRecord,
        ):
            assert session.scalar(select(func.count()).select_from(model)) == 0


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE smithguard.supplemental_payloads SET document = '{}'::jsonb",
        "DELETE FROM smithguard.supplemental_payloads",
        "TRUNCATE smithguard.supplemental_payloads CASCADE",
    ],
)
def test_shared_payload_is_append_only(database, statement):
    with Session(database.engine) as session, session.begin():
        add(session, store.KEV_SOURCE, facts={CVE: BIG})
    with pytest.raises(DBAPIError, match="append-only"), database.engine.begin() as connection:
        connection.execute(text(statement))


def test_upgrade_keeps_old_bytes_and_reads_both_forms(postgres_cluster):
    handle = migrated_database(postgres_cluster, revision="0032_record_accounting")
    try:
        # Seed exactly the previous inline layout on the actual previous schema.
        snapshot_id = stable_id("supplemental-snapshot", store.KEV_SOURCE, "public", "1")
        fact_hash = sha256_id(
            canonical_json_bytes({"snapshot_id": snapshot_id, "subject_id": CVE, "document": BIG})
        )
        values = {
            "snapshot_id": snapshot_id,
            "source_id": store.KEV_SOURCE,
            "mode": "public",
            "sequence": 1,
            "state": "complete",
            "observed_at": NOW,
            "source_as_of": NOW,
            "record_count": 1,
            "document": {"source_url": "https://www.cisa.gov/"},
        }
        record_hash = sha256_id(
            canonical_json_bytes(
                {
                    **values,
                    "observed_at": timestamp(NOW),
                    "source_as_of": timestamp(NOW),
                    "facts_sha256": sha256_id(canonical_json_bytes([(CVE, fact_hash)])),
                }
            )
        )
        old = SupplementalSnapshotRecord(**values, record_hash=record_hash)
        with Session(handle.engine, expire_on_commit=False) as session, session.begin():
            session.add(old)
            session.flush()
            session.execute(
                text(
                    "INSERT INTO smithguard.supplemental_facts "
                    "(snapshot_id, subject_id, document, record_hash) "
                    "VALUES (:snapshot, :subject, CAST(:document AS jsonb), :hash)"
                ),
                {
                    "snapshot": snapshot_id,
                    "subject": CVE,
                    "document": canonical_json_bytes(BIG).decode(),
                    "hash": fact_hash,
                },
            )
        query = text(
            "SELECT snapshot_id, subject_id, document::text, record_hash "
            "FROM smithguard.supplemental_facts ORDER BY snapshot_id, subject_id"
        )
        with handle.engine.connect() as connection:
            before = list(connection.execute(query))
        migrate(handle.url, "head")
        with handle.engine.connect() as connection:
            assert list(connection.execute(query)) == before
        with Session(handle.engine) as session, session.begin():
            assert store.snapshot_facts(session, old.snapshot_id, [CVE]) == {CVE: BIG}
            assert (
                session.get(SupplementalSnapshotRecord, old.snapshot_id).record_hash
                == old.record_hash
            )
            new = add(session, store.KEV_SOURCE, facts={CVE: BIG}, now=NOW + timedelta(days=1))
            assert store.snapshot_facts(session, new.snapshot_id, [CVE]) == {CVE: BIG}
            assert_original_hashes(session, new, {CVE: BIG})
    finally:
        handle.engine.dispose()


def test_mixed_documents_keep_bulk_batches_and_both_public_readers(database):
    facts = {f"CVE-2026-{i:05d}": {"context": "x" * (600 if i % 2 else 1)} for i in range(1000)}
    statements = []

    def count(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO smithguard.supplemental_facts"):
            statements.append(statement)

    event.listen(database.engine, "before_cursor_execute", count)
    try:
        with Session(database.engine) as session, session.begin():
            receipt = add(session, store.KEV_SOURCE, facts=facts)
            assert len(statements) == 2
            assert store.snapshot_facts(session, receipt.snapshot_id, facts) == facts
            contexts, _ = store.cve_context(session, list(facts), now=NOW)
            assert {row["cve"]: row["kev"]["value"] for row in contexts} == facts
            assert_original_hashes(session, receipt, facts)
            common = {
                "source_sha256": "sha256:" + "a" * 64,
                "license_expression": "CC-BY-4.0",
                "attribution_urls": ["https://vuln.go.dev/"],
            }
            origins = {
                "GO-2026-0001": {**common, "context": {}},
                "GO-2026-0002": {**common, "context": {"detail": "x" * 600}},
            }
            origin = add(session, store.GO_SOURCE, facts=origins)
            reports = [{"source_id": store.GO_SOURCE, "upstream_record_id": key} for key in origins]
            result, _ = store.origin_context_for_reports(session, reports, now=NOW)
            for key, value in origins.items():
                assert result[(store.GO_SOURCE, key)]["context"] == value["context"]
                assert result[(store.GO_SOURCE, key)]["snapshot_id"] == origin.snapshot_id
    finally:
        event.remove(database.engine, "before_cursor_execute", count)


@pytest.mark.parametrize("size", [511, 512])
def test_exact_canonical_size_boundary(database, size):
    fact = {"text": "x" * (size - len(canonical_json_bytes({"text": ""})))}
    assert len(canonical_json_bytes(fact)) == size
    with Session(database.engine) as session, session.begin():
        receipt = add(session, store.KEV_SOURCE, facts={CVE: fact})
        row = session.get(SupplementalFactRecord, (receipt.snapshot_id, CVE))
        assert (row.payload_sha256 is not None) is (size == 512)
        assert (row.document is None) is (size == 512)
        assert store.snapshot_facts(session, receipt.snapshot_id, [CVE]) == {CVE: fact}


@pytest.mark.parametrize("fault", ["both", "neither", "missing_payload"])
def test_invalid_payload_membership_refused_by_database(database, fault):
    with Session(database.engine) as session, session.begin():
        receipt = add(session, store.KEV_SOURCE, facts={CVE: BIG})
        digest = sha256_id(canonical_json_bytes(BIG))
        if fault == "missing_payload":
            digest = "sha256:" + "b" * 64
        with pytest.raises(DBAPIError), session.begin_nested():
            session.execute(
                insert(SupplementalFactRecord).execution_options(render_nulls=True),
                [
                    {
                        "snapshot_id": receipt.snapshot_id,
                        "subject_id": "CVE-2026-99999",
                        "document": {} if fault == "both" else None,
                        "payload_sha256": None if fault == "neither" else digest,
                        "record_hash": "sha256:" + "a" * 64,
                    }
                ],
            )
        assert session.scalar(select(func.count()).select_from(SupplementalFactRecord)) == 1
        assert (
            session.scalar(
                text(
                    "SELECT bool_and(convalidated) FROM pg_constraint WHERE "
                    "conrelid = 'smithguard.supplemental_facts'::regclass"
                )
            )
            is True
        )
