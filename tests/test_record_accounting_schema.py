"""Schema-only safeguards remain effective before or without an application adapter."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from smithguard.db.models import (
    CollectionRecordMembership,
    CollectionRecordOutcome,
    CollectionRecordResolution,
    CollectorProgressRecord,
    IngestionBatchRecord,
)

NOW = datetime(2026, 8, 5, 12, tzinfo=UTC)
SOURCE = "gbsec:source:github-advisory-database"


def outcome(session, suffix, *, disposition="quarantined", **overrides):
    accepted = disposition != "quarantined"
    batch_id = f"gbsec:ingestion:schema-{suffix}"
    digest = "sha256:" + ("a" if suffix == "prior" else "b") * 64
    evidence_id = f"gbsec:evidence:schema-{suffix}" if accepted else None
    governance_id = f"gbsec:source-governance-decision:schema-{suffix}" if accepted else None
    source = overrides.get("source_id", SOURCE)
    session.add(
        IngestionBatchRecord(
            batch_id=batch_id,
            source_id=source,
            idempotency_key_hash="sha256:" + ("1" if suffix == "prior" else "2") * 64,
            request_hash=digest,
            input_sha256=digest,
            outcome="accepted" if accepted else "quarantined",
            raw_evidence_id=evidence_id,
            governance_decision_id=governance_id,
            quarantine_reasons=[] if accepted else ["synthetic"],
            record_count=0,
            normalized_record_ids=[],
            coverage=[],
            completed_at=overrides.get("observed_at", NOW),
        )
    )
    session.flush()
    values = dict(
        outcome_id=f"gbsec:collection-record-outcome:{suffix}",
        source_id=source,
        segment="reviewed",
        record_key="GHSA-2345-6789-cfgh",
        disposition=disposition,
        input_sha256=digest,
        processing_version="schema-test-v1",
        policy_sha256="sha256:" + "c" * 64,
        batch_id=batch_id,
        observed_at=NOW,
        record_hash=digest,
        document={
            "evidence_id": evidence_id,
            "governance_decision_id": governance_id,
            "governed_input_sha256": digest if accepted else None,
            "source_updated_at": "2026-08-05T11:00:00Z",
        },
    )
    values.update(overrides)
    row = CollectionRecordOutcome(**values)
    session.add(row)
    session.flush()
    return row


def membership(session, record, *, observed_at=NOW, suffix="verification"):
    row = CollectionRecordMembership(
        membership_id=f"gbsec:collection-record-membership:{suffix}",
        progress_event_id=None,
        ordinal=0,
        outcome_id=record.outcome_id,
        acquisition_kind="replay",
        observed_at=observed_at,
        transport_sha256="sha256:" + "e" * 64,
        record_hash="sha256:" + "f" * 64,
    )
    session.add(row)
    session.flush()
    return row


def resolve(session, prior, replacement, *, resolved_at=NOW, observation=None):
    observation = observation or membership(session, replacement)
    row = CollectionRecordResolution(
        outcome_id=prior.outcome_id,
        replacement_id=replacement.outcome_id,
        membership_id=observation.membership_id,
        resolved_at=resolved_at,
        record_hash="sha256:" + "d" * 64,
    )
    session.add(row)
    session.flush()
    return row


@pytest.mark.parametrize(
    "violation",
    [
        "accepted_original",
        "quarantined_replacement",
        "excluded_replacement",
        "source",
        "segment",
        "record",
        "opaque",
        "unchanged",
        "older",
        "missing_time",
        "backdated",
    ],
)
def test_resolution_insert_rejects_invalid_link_even_without_adapter(database, violation):
    with Session(database.engine) as session, session.begin():
        prior_args = {"disposition": "accepted"} if violation == "accepted_original" else {}
        if violation == "opaque":
            prior_args["record_key"] = "opaque:sha256:" + "a" * 64
        prior = outcome(session, "prior", **prior_args)
        replacement_args = {"disposition": "accepted"}
        if violation in {"quarantined_replacement", "excluded_replacement"}:
            replacement_args["disposition"] = violation.split("_")[0]
        if violation == "source":
            replacement_args["source_id"] = "gbsec:source:other"
        if violation == "segment":
            replacement_args["segment"] = "unreviewed"
        if violation == "record":
            replacement_args["record_key"] = "GHSA-2345-6789-cfgj"
        if violation == "opaque":
            replacement_args["record_key"] = prior.record_key
        if violation == "unchanged":
            replacement_args["input_sha256"] = prior.input_sha256
        replacement = outcome(session, "replacement", **replacement_args)
        # Timestamp variants are inserted as distinct immutable rows from the outset.
        if violation in {"older", "missing_time"}:
            session.rollback()
    if violation in {"older", "missing_time"}:
        with Session(database.engine) as session, session.begin():
            prior = outcome(session, "prior")
            document = {
                "evidence_id": "gbsec:evidence:schema-replacement",
                "governance_decision_id": "gbsec:source-governance-decision:schema-replacement",
                "governed_input_sha256": "sha256:" + "b" * 64,
                "source_updated_at": "2026-08-05T10:00:00Z" if violation == "older" else None,
            }
            replacement = outcome(session, "replacement", disposition="accepted", document=document)
    with Session(database.engine) as session, session.begin():
        prior = session.get(CollectionRecordOutcome, "gbsec:collection-record-outcome:prior")
        replacement = session.get(
            CollectionRecordOutcome, "gbsec:collection-record-outcome:replacement"
        )
        with (
            pytest.raises(DBAPIError, match="corrected exact accepted record"),
            session.begin_nested(),
        ):
            resolve(
                session,
                prior,
                replacement,
                resolved_at=NOW - timedelta(seconds=1) if violation == "backdated" else NOW,
            )
        assert session.scalar(select(CollectionRecordResolution)) is None


def test_populated_accounting_tables_are_immutable_and_conserved(database):
    with Session(database.engine) as session, session.begin():
        prior = outcome(session, "prior")
        replacement = outcome(session, "replacement", disposition="accepted")
        resolve(session, prior, replacement)
        session.add(
            CollectorProgressRecord(
                progress_event_id="gbsec:collector-progress:schema",
                source_id=SOURCE,
                segment="reviewed",
                lane="updates",
                sequence=1,
                state="complete",
                page_count=1,
                source_record_count=1,
                normalized_record_count=0,
                reason_code="github_lane_complete",
                occurred_at=NOW,
                record_hash="sha256:" + "e" * 64,
            )
        )
        session.flush()
        session.add(
            CollectionRecordMembership(
                membership_id="gbsec:collection-record-membership:page",
                acquisition_kind="page",
                observed_at=NOW,
                progress_event_id="gbsec:collector-progress:schema",
                ordinal=0,
                outcome_id=prior.outcome_id,
                transport_sha256="sha256:" + "f" * 64,
                record_hash="sha256:" + "e" * 64,
            )
        )
    for table in (
        "collection_record_outcomes",
        "collection_record_memberships",
        "collection_record_resolutions",
    ):
        for statement in (
            f"UPDATE smithguard.{table} SET record_hash=record_hash",
            f"DELETE FROM smithguard.{table}",
            f"TRUNCATE smithguard.{table} CASCADE",
        ):
            with (
                pytest.raises(DBAPIError, match="append-only"),
                database.engine.begin() as connection,
            ):
                connection.execute(text(statement))


@pytest.mark.parametrize(
    "violation",
    [
        "source_format",
        "segment_format",
        "record_format",
        "processor_format",
        "batch_source",
        "batch_evidence",
        "too_large",
    ],
)
def test_outcome_insert_rejects_invalid_formats_and_batch_links(database, violation):
    with Session(database.engine) as session, session.begin():
        kwargs = {}
        if violation == "source_format":
            kwargs["source_id"] = "bad source"
        if violation == "segment_format":
            kwargs["segment"] = "bad segment"
        if violation == "record_format":
            kwargs["record_key"] = "bad record"
        if violation == "processor_format":
            kwargs["processing_version"] = "bad processor"
        if violation in {"batch_source", "batch_evidence", "too_large"}:
            # A valid accepted batch lets us isolate the insert trigger/size check.
            row = outcome(session, "prior", disposition="accepted")
            session.expunge(row)
            values = {
                column.name: getattr(row, column.name)
                for column in CollectionRecordOutcome.__table__.columns
            }
            values["outcome_id"] = "gbsec:collection-record-outcome:invalid"
            if violation == "batch_source":
                values["source_id"] = "gbsec:source:other"
            if violation == "batch_evidence":
                values["document"] = {**row.document, "evidence_id": "gbsec:evidence:wrong"}
            if violation == "too_large":
                values["document"] = {**row.document, "padding": "x" * 16385}
            expected = (
                "document_size" if violation == "too_large" else "does not match ingestion batch"
            )
            with pytest.raises(DBAPIError, match=expected), session.begin_nested():
                session.add(CollectionRecordOutcome(**values))
                session.flush()
        else:
            expected = {
                "source_format": "collection_record_outcomes_source_id",
                "segment_format": "collection_record_outcomes_segment",
                "record_format": "collection_record_outcomes_record_key",
                "processor_format": "collection_record_outcomes_processing_version",
            }[violation]
            with pytest.raises(DBAPIError, match=expected), session.begin_nested():
                outcome(session, "prior", **kwargs)


def test_new_failure_needs_new_observation_even_when_accepted_outcome_is_reused(database):
    with Session(database.engine) as session, session.begin():
        prior = outcome(session, "prior", document={"source_updated_at": None})
        old = outcome(
            session, "replacement", disposition="accepted", observed_at=NOW - timedelta(hours=1)
        )
        stale = membership(session, old, observed_at=NOW - timedelta(hours=1), suffix="stale")
        with (
            pytest.raises(DBAPIError, match="corrected exact accepted record"),
            session.begin_nested(),
        ):
            resolve(session, prior, old, observation=stale)
        fresh = membership(session, old, observed_at=NOW, suffix="fresh")
        assert resolve(session, prior, old, observation=fresh).membership_id == fresh.membership_id


@pytest.mark.parametrize("change", ["processor", "policy", "excluded", "no_time"])
def test_resolution_accepts_each_proven_correction_type(database, change):
    with Session(database.engine) as session, session.begin():
        args = {"disposition": "excluded"} if change == "excluded" else {}
        if change == "no_time":
            args["document"] = {"source_updated_at": None}
        prior = outcome(session, "prior", **args)
        correction = {"disposition": "accepted"}
        if change in {"processor", "policy"}:
            correction["input_sha256"] = prior.input_sha256
            correction["processing_version" if change == "processor" else "policy_sha256"] = (
                "schema-test-v2" if change == "processor" else "sha256:" + "f" * 64
            )
        replacement = outcome(session, "replacement", **correction)
        assert resolve(session, prior, replacement).outcome_id == prior.outcome_id


@pytest.mark.parametrize("value", ["not-a-date", "2026-08-05T11:00:00", 123])
def test_outcome_rejects_unparseable_or_timezone_free_timestamp(database, value):
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(DBAPIError, match="source timestamp requires an offset"),
        session.begin_nested(),
    ):
        outcome(session, "prior", document={"source_updated_at": value})


@pytest.mark.parametrize(
    "field", ["disposition", "governance_decision_id", "governed_input_sha256"]
)
def test_outcome_insert_checks_all_ingestion_bindings(database, field):
    with Session(database.engine) as session, session.begin():
        original = outcome(session, "prior", disposition="accepted")
        values = {
            column.name: getattr(original, column.name)
            for column in CollectionRecordOutcome.__table__.columns
        }
        values["outcome_id"] = "gbsec:collection-record-outcome:wrong"
        if field == "disposition":
            values[field] = "quarantined"
        else:
            values["document"] = {**original.document, field: "incorrect"}
        with (
            pytest.raises(DBAPIError, match="does not match ingestion batch"),
            session.begin_nested(),
        ):
            session.add(CollectionRecordOutcome(**values))
            session.flush()


def test_membership_requires_matching_progress_source_segment_and_time(database):
    with Session(database.engine) as session, session.begin():
        prior = outcome(session, "prior")
        session.add(
            CollectorProgressRecord(
                progress_event_id="gbsec:collector-progress:other",
                source_id="gbsec:source:other",
                segment="reviewed",
                lane="updates",
                sequence=1,
                state="complete",
                page_count=1,
                source_record_count=1,
                normalized_record_count=0,
                reason_code="github_lane_complete",
                occurred_at=NOW,
                record_hash="sha256:" + "e" * 64,
            )
        )
        session.flush()
        with (
            pytest.raises(DBAPIError, match="does not match its progress receipt"),
            session.begin_nested(),
        ):
            session.add(
                CollectionRecordMembership(
                    membership_id="gbsec:collection-record-membership:wrong",
                    acquisition_kind="page",
                    observed_at=NOW,
                    progress_event_id="gbsec:collector-progress:other",
                    ordinal=0,
                    outcome_id=prior.outcome_id,
                    transport_sha256="sha256:" + "f" * 64,
                    record_hash="sha256:" + "e" * 64,
                )
            )
            session.flush()
