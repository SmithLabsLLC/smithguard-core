"""PostgreSQL migration and append-only canonical persistence checks."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

import pytest
from alembic import command
from sqlalchemy import create_engine, delete, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from smithguard.db.base import (
    PRIVATE_WATCHLISTS_SCHEMA_NAME,
    SCHEMA_NAME,
    Base,
)
from smithguard.db.inventory import (
    EXPECTED_MAIN_TABLES,
    EXPECTED_PRIVATE_WATCHLISTS_TABLES,
    schema_fingerprint,
)
from smithguard.db.models import (
    APPEND_ONLY_MODELS,
    ArtifactRecord,
    IncidentSeedRecord,
    IncidentTransitionRecord,
    IngestionBatchRecord,
    PublicationLifecycleEventRecord,
    SourceGovernanceDecisionRecord,
    SourceReconciliationRunRecord,
)
from smithguard.db.repository import (
    EvidenceStorageMismatch,
    LedgerClassificationError,
    RevisionConflict,
    RevisionOrderError,
    append_contract,
    canonical_row_counts,
    latest_contract,
)
from smithguard.identifiers import canonical_json_bytes, sha256_id, timestamp
from smithguard.incidents import (
    IncidentSeed,
    create_incident,
    rebuild_incident,
)

from .support import LocalPostgres, alembic_config, migrate

LEGACY_SCHEMA_NAME = "goodboy_security"
LEGACY_WATCHLISTS_SCHEMA_NAME = "goodboy_hosted_watch"

PERSISTED_DEFINITIONS = {
    "Source",
    "RawEvidence",
    "AuthorityDecision",
    "Artifact",
    "Claim",
    "AffectedRange",
    "Relationship",
    "Incident",
    "IncidentEvent",
    "RecommendedAction",
}


def verify_latest_incident_rebuild(session: Session, incident_id: str) -> dict:
    """Rebuild the incident and require it to equal the latest stored revision."""
    rebuilt = rebuild_incident(session, incident_id)
    latest = latest_contract(session, "Incident", incident_id)
    assert latest is not None and latest.document == rebuilt
    return rebuilt


def _persisted_examples(
    contract_examples: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return {
        entry["definition"]: deepcopy(entry["value"])
        for entry in contract_examples
        if entry["definition"] in PERSISTED_DEFINITIONS
    }


def test_append_contracts_are_idempotent_revisioned_and_queryable(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    examples = _persisted_examples(contract_examples)
    with Session(database.engine) as session, session.begin():
        for definition, value in examples.items():
            storage_key = value["sha256"] if definition == "RawEvidence" else None
            _record, created = append_contract(
                session,
                definition,
                value,
                storage_key=storage_key,
            )
            assert created

    with Session(database.engine) as session, session.begin():
        for definition, value in examples.items():
            storage_key = value["sha256"] if definition == "RawEvidence" else None
            record, created = append_contract(
                session,
                definition,
                value,
                storage_key=storage_key,
            )
            assert not created
            assert record.document == value
        assert canonical_row_counts(session) == {
            "affected_ranges": 1,
            "artifacts": 1,
            "authority_decisions": 1,
            "claims": 1,
            "evidence_objects": 1,
            "incident_events": 1,
            "incidents": 1,
            "preliminary_warnings": 0,
            "recommended_actions": 1,
            "relationships": 1,
            "sources": 1,
        }

    artifact = examples["Artifact"]
    conflicting = {**artifact, "name": "different-name"}
    with Session(database.engine) as session, session.begin(), pytest.raises(RevisionConflict):
        append_contract(session, "Artifact", conflicting)

    revision_three = {
        **artifact,
        "revision": 3,
        "updated_at": "2026-08-07T00:00:00Z",
    }
    revision_two = {
        **artifact,
        "revision": 2,
        "updated_at": "2026-08-06T00:00:00Z",
    }
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Artifact", revision_three)
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(RevisionOrderError),
    ):
        append_contract(session, "Artifact", revision_two)
    with Session(database.engine) as session:
        latest = latest_contract(session, "Artifact", artifact["id"])
        assert latest is not None
        assert latest.revision == 3


def test_evidence_metadata_requires_verified_storage_key(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    raw = next(
        deepcopy(entry["value"])
        for entry in contract_examples
        if entry["definition"] == "RawEvidence"
    )
    with Session(database.engine) as session, session.begin():
        with pytest.raises(EvidenceStorageMismatch):
            append_contract(session, "RawEvidence", raw)
        with pytest.raises(EvidenceStorageMismatch):
            append_contract(session, "RawEvidence", raw, storage_key="sha256:" + "f" * 64)

    raw["storage_state"] = "not_retained"
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(EvidenceStorageMismatch),
    ):
        append_contract(session, "RawEvidence", raw, storage_key=raw["sha256"])


def test_customer_local_shared_contracts_do_not_enter_public_ledger(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    examples = _persisted_examples(contract_examples)
    with Session(database.engine) as session, session.begin():
        for definition in ("Relationship", "RecommendedAction"):
            value = {
                **examples[definition],
                "data_classification": "customer_local",
            }
            with pytest.raises(LedgerClassificationError, match="must be public"):
                append_contract(session, definition, value)


def test_database_triggers_reject_ledger_update_and_delete(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    artifact = next(
        entry["value"] for entry in contract_examples if entry["definition"] == "Artifact"
    )
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Artifact", artifact)

    with pytest.raises(DBAPIError, match="append-only"), database.engine.begin() as connection:
        connection.execute(
            update(ArtifactRecord).where(ArtifactRecord.id == artifact["id"]).values(name="mutated")
        )
    with pytest.raises(DBAPIError, match="append-only"), database.engine.begin() as connection:
        connection.execute(delete(ArtifactRecord).where(ArtifactRecord.id == artifact["id"]))
    with (
        pytest.raises(DBAPIError, match="append-only"),
        database.engine.begin() as connection,
    ):
        connection.execute(text(f"TRUNCATE TABLE {SCHEMA_NAME}.artifacts"))
    with Session(database.engine) as session:
        assert session.scalar(select(ArtifactRecord.name)) == artifact["name"]


def test_cp0b2_metadata_tables_are_append_only(database) -> None:
    now = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    with Session(database.engine) as session, session.begin():
        session.add(
            IngestionBatchRecord(
                batch_id="gbsec:ingestion:synthetic-immutable",
                source_id="gbsec:source:synthetic",
                idempotency_key_hash="sha256:" + "a" * 64,
                request_hash="sha256:" + "b" * 64,
                input_sha256="sha256:" + "c" * 64,
                outcome="quarantined",
                raw_evidence_id=None,
                quarantine_reasons=["synthetic_rejection"],
                record_count=0,
                normalized_record_ids=[],
                coverage=[],
                completed_at=now,
            )
        )
        session.add(
            IncidentSeedRecord(
                incident_id="gbsec:incident:synthetic-immutable",
                title="Synthetic immutable incident",
                initial_status="confirmed",
                initial_confidence="confirmed",
                claim_ids=[],
                artifact_ids=[],
                affected_range_ids=[],
                relationship_ids=[],
                coverage=[
                    {
                        "ecosystem": "npm",
                        "stage": "normalized",
                        "result": "supported",
                        "as_of": "2026-08-05T12:00:00Z",
                    }
                ],
                unknowns=[],
                first_observed_at=now,
                created_at=now,
                record_hash="sha256:" + "d" * 64,
            )
        )
        session.add(
            IncidentTransitionRecord(
                event_id="gbsec:event:synthetic-immutable",
                event_revision=1,
                incident_id="gbsec:incident:synthetic-immutable",
                sequence=1,
                expected_incident_revision=0,
                details={},
                record_hash="sha256:" + "e" * 64,
                created_at=now,
            )
        )
    with (
        pytest.raises(DBAPIError, match="append-only"),
        database.engine.begin() as connection,
    ):
        connection.execute(update(IngestionBatchRecord).values(outcome="accepted"))
    with (
        pytest.raises(DBAPIError, match="append-only"),
        database.engine.begin() as connection,
    ):
        connection.execute(text(f"TRUNCATE TABLE {SCHEMA_NAME}.ingestion_batches CASCADE"))
    for model in (
        IngestionBatchRecord,
        IncidentSeedRecord,
        IncidentTransitionRecord,
    ):
        with (
            pytest.raises(DBAPIError, match="append-only"),
            database.engine.begin() as connection,
        ):
            connection.execute(delete(model))


def test_migration_upgrade_downgrade_rebuild_and_model_parity(
    postgres_cluster: LocalPostgres,
) -> None:
    url = postgres_cluster.create_database()
    migrate(url, "head")
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            first_fingerprint = schema_fingerprint(connection)
            tables = set(
                connection.scalars(
                    text("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = :schema"),
                    {"schema": SCHEMA_NAME},
                )
            )
            trigger_rows = tuple(
                connection.execute(
                    text(
                        "SELECT c.relname, t.tgname FROM pg_catalog.pg_trigger AS t "
                        "JOIN pg_catalog.pg_class AS c ON c.oid = t.tgrelid "
                        "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
                        "WHERE n.nspname = :schema AND NOT t.tgisinternal"
                    ),
                    {"schema": SCHEMA_NAME},
                )
            )
        assert tables == set(EXPECTED_MAIN_TABLES)
        assert tables == set(Base.metadata.tables[name].name for name in Base.metadata.tables)
        with engine.connect() as connection:
            private_watchlists_tables = set(
                connection.scalars(
                    text("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = :schema"),
                    {"schema": PRIVATE_WATCHLISTS_SCHEMA_NAME},
                )
            )
        assert private_watchlists_tables == set(EXPECTED_PRIVATE_WATCHLISTS_TABLES)
        # The historical schema stays migration-owned after its unpublished ORM is removed.
        assert len(private_watchlists_tables) == 6
        registered_tables = {model.__tablename__ for model in APPEND_ONLY_MODELS}
        assert len(APPEND_ONLY_MODELS) == len(registered_tables) == 45
        triggers_by_table = {
            table_name: {trigger for row_table, trigger in trigger_rows if row_table == table_name}
            for table_name in registered_tables
        }
        extra_triggers = {
            "collection_record_outcomes": {"validate_collection_outcome"},
            "collection_record_resolutions": {"validate_collection_resolution"},
            "collection_record_memberships": {"validate_collection_membership"},
        }
        assert all(
            triggers
            == {"reject_ledger_mutation", "reject_ledger_truncate"}
            | extra_triggers.get(table, set())
            for table, triggers in triggers_by_table.items()
        )
        assert {table_name for table_name, _trigger in trigger_rows} == registered_tables
        command.check(alembic_config(url))

        with pytest.raises(
            RuntimeError,
            match="forward-only",
        ):
            migrate(url, "base")
        with engine.connect() as connection:
            assert schema_fingerprint(connection) == first_fingerprint

        rebuild_url = postgres_cluster.create_database()
        migrate(rebuild_url, "head")
        rebuild_engine = create_engine(rebuild_url)
        try:
            with rebuild_engine.connect() as connection:
                assert schema_fingerprint(connection) == first_fingerprint
        finally:
            rebuild_engine.dispose()
    finally:
        engine.dispose()


def test_rebrand_migration_refuses_nonempty_disabled_watchlist_state(
    postgres_cluster: LocalPostgres,
) -> None:
    url = postgres_cluster.create_database()
    migrate(url, "0012_mx014")
    engine = create_engine(url)
    now = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    f"""
                    INSERT INTO {LEGACY_WATCHLISTS_SCHEMA_NAME}.tenants (
                        tenant_id, feature_state, synthetic_only, inventory_revision,
                        contract_revision, current_set_hash, current_entry_count,
                        current_payload_bytes, expires_unconfirmed_after_days,
                        backup_expiry_days, max_entries, max_payload_bytes,
                        max_requests_per_minute, max_runtime_ms, max_concurrency,
                        request_window_started_at, request_count, created_at, updated_at
                    ) VALUES (
                        'synthetic_rebrand_refusal', 'disabled', true,
                        'synthetic-rebrand-refusal', 1, :set_hash, 0, 0,
                        45, 35, 1000, 1048576, 60, 5000, 1,
                        :now, 0, :now, :now
                    )
                    """
                ),
                {"set_hash": "sha256:" + "e" * 64, "now": now},
            )

        with pytest.raises(
            RuntimeError,
            match="disabled legacy watchlist schema must be empty",
        ):
            migrate(url, "head")

        with engine.connect() as connection:
            assert (
                connection.scalar(text("SELECT version_num FROM public.alembic_version"))
                == "0012_mx014"
            )
            schemas = set(
                connection.scalars(
                    text(
                        "SELECT nspname FROM pg_catalog.pg_namespace "
                        "WHERE nspname IN (:old_schema, :new_schema)"
                    ),
                    {
                        "old_schema": LEGACY_WATCHLISTS_SCHEMA_NAME,
                        "new_schema": PRIVATE_WATCHLISTS_SCHEMA_NAME,
                    },
                )
            )
            assert schemas == {LEGACY_WATCHLISTS_SCHEMA_NAME}
    finally:
        engine.dispose()


def test_warning_receipt_migration_preserves_prior_projection_and_adds_bounded_indexes(
    postgres_cluster: LocalPostgres,
) -> None:
    url = postgres_cluster.create_database()
    migrate(url, "0022_claims_source_index")
    engine = create_engine(url)
    now = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    f"""
                    INSERT INTO {SCHEMA_NAME}.jobs (
                        job_id, queue, job_type, idempotency_key_hash, payload_hash,
                        payload_classification, payload, state, attempts, max_attempts,
                        available_at, last_error_code, created_at, updated_at, completed_at
                    ) VALUES (
                        'synthetic-prior-readable-job', 'ai-warning-discovery',
                        'scheduled_warning_discovery', :key_hash, :payload_hash,
                        'internal_control', CAST(:payload AS jsonb), 'dead_letter', 1, 1,
                        :now, 'provider_transport_failure', :now, :now, :now
                    )
                    """
                ),
                {
                    "key_hash": "sha256:" + "a" * 64,
                    "payload_hash": "sha256:" + "b" * 64,
                    "payload": json.dumps({"run_id": "synthetic", "receipt_type": "failure"}),
                    "now": now,
                },
            )

        migrate(url, "head")
        with engine.begin() as connection:
            assert (
                connection.scalar(text("SELECT version_num FROM public.alembic_version"))
                == "0036_bulletin_source_updates"
            )
            connection.execute(
                text(
                    f"UPDATE {SCHEMA_NAME}.jobs SET state = 'acknowledged' "
                    "WHERE job_id = 'synthetic-prior-readable-job'"
                )
            )
            prior_release_projection = connection.execute(
                text(
                    f"SELECT job_id, queue, job_type, state, completed_at "
                    f"FROM {SCHEMA_NAME}.jobs "
                    "WHERE job_id = 'synthetic-prior-readable-job'"
                )
            ).one()
            assert prior_release_projection.job_id == "synthetic-prior-readable-job"
            assert prior_release_projection.state == "acknowledged"
            indexes = set(
                connection.scalars(
                    text(
                        "SELECT indexname FROM pg_catalog.pg_indexes "
                        "WHERE schemaname = :schema AND indexname = ANY(:indexes)"
                    ),
                    {
                        "schema": SCHEMA_NAME,
                        "indexes": [
                            "ix_jobs_receipt_run_completed",
                            "ix_jobs_receipt_type_completed",
                            "ix_spend_ledger_reservation_latest",
                            "ix_spend_ledger_provider_cost",
                            "ix_spend_ledger_integrity_denial",
                        ],
                    },
                )
            )
            assert indexes == {
                "ix_jobs_receipt_run_completed",
                "ix_jobs_receipt_type_completed",
            }
    finally:
        engine.dispose()


def test_rebrand_migration_refuses_legacy_minimized_classification_rows(
    postgres_cluster: LocalPostgres,
) -> None:
    url = postgres_cluster.create_database()
    migrate(url, "0012_mx014")
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    f"CREATE TABLE {LEGACY_SCHEMA_NAME}.synthetic_rebrand_classification "
                    "(data_classification text NOT NULL)"
                )
            )
            connection.execute(
                text(
                    f"INSERT INTO {LEGACY_SCHEMA_NAME}.synthetic_rebrand_classification "
                    "(data_classification) VALUES ('hosted_watch_minimized')"
                )
            )

        with pytest.raises(
            RuntimeError,
            match="legacy minimized watchlist rows must be handled",
        ):
            migrate(url, "head")

        with engine.connect() as connection:
            assert (
                connection.scalar(text("SELECT version_num FROM public.alembic_version"))
                == "0012_mx014"
            )
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM "
                        f"{LEGACY_SCHEMA_NAME}.synthetic_rebrand_classification"
                    )
                )
                == 1
            )
    finally:
        engine.dispose()


def test_mx005_upgrade_preserves_pre_governance_ingestion_rows(
    postgres_cluster: LocalPostgres,
) -> None:
    url = postgres_cluster.create_database()
    migrate(url, "0009_mx003")
    engine = create_engine(url)
    now = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    f"""
                    INSERT INTO {LEGACY_SCHEMA_NAME}.ingestion_batches (
                        batch_id, source_id, idempotency_key_hash, request_hash,
                        input_sha256, outcome, raw_evidence_id, quarantine_reasons,
                        record_count, normalized_record_ids, coverage, completed_at
                    ) VALUES (
                        :batch_id, :source_id, :key_hash, :request_hash,
                        :input_sha256, 'quarantined', NULL,
                        '["legacy_synthetic_fixture"]'::jsonb, 0, '[]'::jsonb,
                        '[]'::jsonb, :completed_at
                    )
                    """
                ),
                {
                    "batch_id": "gbsec:ingestion:legacy-before-mx005",
                    "source_id": "gbsec:source:legacy-before-mx005",
                    "key_hash": "sha256:" + "a" * 64,
                    "request_hash": "sha256:" + "b" * 64,
                    "input_sha256": "sha256:" + "c" * 64,
                    "completed_at": now,
                },
            )
        migrate(url, "head")
        with engine.connect() as connection:
            legacy_governance = connection.scalar(
                text(
                    f"""
                    SELECT governance_decision_id
                    FROM {SCHEMA_NAME}.ingestion_batches
                    WHERE batch_id = :batch_id
                    """
                ),
                {"batch_id": "gbsec:ingestion:legacy-before-mx005"},
            )
            tables = set(
                connection.scalars(
                    text("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = :schema"),
                    {"schema": SCHEMA_NAME},
                )
            )
        assert legacy_governance is None
        assert {
            "source_governance_decisions",
            "publication_lifecycle_events",
            "source_reconciliation_runs",
        } <= tables
    finally:
        engine.dispose()


def test_mx006_upgrade_preserves_legacy_ingestion_and_backfills_final_evidence(
    postgres_cluster: LocalPostgres,
    contract_examples: list[dict[str, Any]],
) -> None:
    url = postgres_cluster.create_database()
    migrate(url, "0010_mx005")
    engine = create_engine(url)
    now = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
    raw = deepcopy(
        next(entry["value"] for entry in contract_examples if entry["definition"] == "RawEvidence")
    )
    raw["storage_state"] = "stored_immutable"
    try:
        legacy_engine = engine.execution_options(
            schema_translate_map={SCHEMA_NAME: LEGACY_SCHEMA_NAME}
        )
        with Session(legacy_engine) as session, session.begin():
            append_contract(
                session,
                "RawEvidence",
                raw,
                storage_key=raw["sha256"],
            )
        with engine.begin() as connection:
            connection.execute(
                text(
                    f"""
                    INSERT INTO {LEGACY_SCHEMA_NAME}.ingestion_batches (
                        batch_id, source_id, idempotency_key_hash, request_hash,
                        input_sha256, governance_decision_id, outcome,
                        raw_evidence_id, quarantine_reasons, record_count,
                        normalized_record_ids, coverage, completed_at
                    ) VALUES (
                        :batch_id, :source_id, :key_hash, :request_hash,
                        :input_sha256, NULL, 'quarantined', NULL,
                        '["legacy_synthetic_fixture"]'::jsonb, 0,
                        '[]'::jsonb, '[]'::jsonb, :completed_at
                    )
                    """
                ),
                {
                    "batch_id": "gbsec:ingestion:legacy-before-mx006",
                    "source_id": "gbsec:source:legacy-before-mx006",
                    "key_hash": "sha256:" + "1" * 64,
                    "request_hash": "sha256:" + "2" * 64,
                    "input_sha256": "sha256:" + "3" * 64,
                    "completed_at": now,
                },
            )

        migrate(url, "head")
        with engine.connect() as connection:
            lineage = connection.execute(
                text(
                    f"""
                    SELECT idempotency_root_hash, representation_hash,
                           processing_version, retry_of_batch_id
                    FROM {SCHEMA_NAME}.ingestion_batches
                    WHERE batch_id = :batch_id
                    """
                ),
                {"batch_id": "gbsec:ingestion:legacy-before-mx006"},
            ).one()
            finalization = connection.execute(
                text(
                    f"""
                    SELECT evidence_id, digest, staging_key, byte_count, state,
                           attempts, finalized_at
                    FROM {SCHEMA_NAME}.evidence_finalizations
                    WHERE digest = :digest
                    """
                ),
                {"digest": raw["sha256"]},
            ).one()
        assert tuple(lineage) == (None, None, None, None)
        assert finalization.evidence_id == raw["id"]
        assert finalization.digest == raw["sha256"]
        assert finalization.staging_key == raw["sha256"]
        assert finalization.byte_count == raw["byte_count"]
        assert finalization.state == "finalized"
        assert finalization.attempts == 0
        assert finalization.finalized_at is not None
    finally:
        engine.dispose()


def test_mx006_requires_complete_new_ingestion_lineage(database) -> None:
    now = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
    with (
        pytest.raises(DBAPIError, match="lineage_shape"),
        database.engine.begin() as connection,
    ):
        connection.execute(
            text(
                f"""
                INSERT INTO {SCHEMA_NAME}.ingestion_batches (
                    batch_id, source_id, idempotency_key_hash, request_hash,
                    input_sha256, idempotency_root_hash, representation_hash,
                    processing_version, retry_of_batch_id, outcome,
                    raw_evidence_id, quarantine_reasons, record_count,
                    normalized_record_ids, coverage, completed_at
                ) VALUES (
                    :batch_id, :source_id, :key_hash, :request_hash,
                    :input_sha256, :root_hash, NULL, :processing_version,
                    NULL, 'quarantined', NULL, '[]'::jsonb, 0,
                    '[]'::jsonb, '[]'::jsonb, :completed_at
                )
                """
            ),
            {
                "batch_id": "gbsec:ingestion:incomplete-lineage",
                "source_id": "gbsec:source:incomplete-lineage",
                "key_hash": "sha256:" + "1" * 64,
                "request_hash": "sha256:" + "2" * 64,
                "input_sha256": "sha256:" + "3" * 64,
                "root_hash": "sha256:" + "4" * 64,
                "processing_version": "mx006-test",
                "completed_at": now,
            },
        )


def test_mx005_metadata_tables_are_append_only(database) -> None:
    now = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
    with Session(database.engine) as session, session.begin():
        session.add(
            SourceGovernanceDecisionRecord(
                decision_id="gbsec:source-governance-decision:immutable",
                policy_id="gbsec:source-governance-policy:immutable",
                policy_version="1.0.0",
                policy_sha256="sha256:" + "1" * 64,
                rights_register_id="gbsec:rights-register:immutable",
                authorized_disposition_adapter_ids=[],
                source_id="gbsec:source:immutable",
                connector_id="gbsec:connector:immutable",
                source_record_id="synthetic-immutable-record",
                operating_mode="reconciliation",
                acquisition_method="rest_api",
                field_policy_id="gbsec:field-policy:immutable",
                accepted_sha256="sha256:" + "2" * 64,
                attribution_text="Synthetic immutable source",
                license_expression=None,
                rights_evidence_ids=["gbsec:rights-evidence:immutable"],
                rights_evidence_verified=True,
                retention_behavior="immutable_permitted",
                public_status_ceiling="reported",
                correction_behavior="append_corrected_revision",
                withdrawal_behavior="retain_mark_withdrawn",
                rights_drift_behavior="fail_closed_and_reconcile",
                qualified_publication_decision_id=None,
                decided_at=now,
                record_hash="sha256:" + "3" * 64,
            )
        )
        session.add(
            PublicationLifecycleEventRecord(
                lifecycle_event_id="gbsec:publication-lifecycle:immutable",
                idempotency_key_hash="sha256:" + "4" * 64,
                incident_id=None,
                incident_revision=None,
                event_type="rights_tombstoned",
                actor_type="maintenance",
                actor_id="maintenance-immutable",
                source_id="gbsec:source:immutable",
                source_record_id="synthetic-immutable-record",
                evidence_id="gbsec:evidence:immutable",
                authority_decision_id=None,
                governance_decision_id="gbsec:source-governance-decision:immutable",
                old_public_status=None,
                new_public_status=None,
                reason_code="synthetic_immutable",
                disposition_proof_sha256=None,
                occurred_at=now,
                record_hash="sha256:" + "5" * 64,
            )
        )
        session.add(
            SourceReconciliationRunRecord(
                reconciliation_event_id="gbsec:source-reconciliation:immutable",
                inventory_run_id="gbsec:source-inventory-run:immutable",
                source_id="gbsec:source:immutable",
                connector_id="gbsec:connector:immutable",
                sequence=1,
                page_index=1,
                state="failed",
                complete_inventory=False,
                scanned_count=0,
                observed_count=0,
                observed_record_ids=[],
                late_record_ids=[],
                modified_record_ids=[],
                deleted_record_ids=[],
                missing_record_ids=[],
                unresolved_record_ids=[],
                drift_truncated=False,
                continuation_in_hash=None,
                continuation_out_hash=None,
                has_more=False,
                policy_id="gbsec:source-governance-policy:immutable",
                policy_sha256="sha256:" + "1" * 64,
                observation_sha256="sha256:" + "6" * 64,
                reason_code="synthetic_failure",
                reconciled_at=now,
                next_due_at=now.replace(day=7),
                record_hash="sha256:" + "7" * 64,
            )
        )
    for model in (
        SourceGovernanceDecisionRecord,
        PublicationLifecycleEventRecord,
        SourceReconciliationRunRecord,
    ):
        with (
            pytest.raises(DBAPIError, match="append-only"),
            database.engine.begin() as connection,
        ):
            connection.execute(update(model).values(record_hash="sha256:" + "8" * 64))
        with (
            pytest.raises(DBAPIError, match="append-only"),
            database.engine.begin() as connection,
        ):
            connection.execute(delete(model))


def test_mx005_lifecycle_table_rejects_impossible_direct_event_rows(database) -> None:
    now = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
    with (
        pytest.raises(DBAPIError),
        Session(database.engine) as session,
        session.begin(),
    ):
        session.add(
            PublicationLifecycleEventRecord(
                lifecycle_event_id="gbsec:publication-lifecycle:invalid-direct-purge",
                idempotency_key_hash="sha256:" + "9" * 64,
                incident_id=None,
                incident_revision=None,
                event_type="rights_purged",
                actor_type="maintenance",
                actor_id="maintenance-invalid-direct-purge",
                source_id="gbsec:source:immutable",
                source_record_id="synthetic-invalid-direct-purge",
                evidence_id="gbsec:evidence:immutable",
                authority_decision_id=None,
                governance_decision_id="gbsec:source-governance-decision:immutable",
                old_public_status=None,
                new_public_status=None,
                reason_code="synthetic_invalid_direct_purge",
                disposition_proof_sha256=None,
                occurred_at=now,
                record_hash="sha256:" + "0" * 64,
            )
        )
        session.flush()


def test_mx003_migration_classifies_existing_synthetic_watch_rows(
    postgres_cluster: LocalPostgres,
) -> None:
    url = postgres_cluster.create_database()
    migrate(url, "0008_mx002")
    engine = create_engine(url)
    now = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    tenant_id = "synthetic_tenant_mx003"
    rows = [
        {
            "project_alias": "synthetic-Z-project",
            "artifact_key": "sha256:" + "f" * 64,
            "ecosystem": "npm",
            "registry_host": "registry.npmjs.org",
            "artifact_name": "Z-Package",
            "version": "1.0.0",
            "digest": None,
            "visibility_source_url": "https://www.npmjs.com/package/Z-Package/v/1.0.0",
        },
        {
            "project_alias": "synthetic-project-dependency",
            "artifact_key": "sha256:" + "a" * 64,
            "ecosystem": "npm",
            "registry_host": "registry.npmjs.org",
            "artifact_name": "event-stream",
            "version": "3.3.6",
            "digest": None,
            "visibility_source_url": "https://www.npmjs.com/package/event-stream/v/3.3.6",
        },
        {
            "project_alias": "synthetic-project-action",
            "artifact_key": "sha256:" + "b" * 64,
            "ecosystem": "github-actions",
            "registry_host": "github.com",
            "artifact_name": "actions/checkout",
            "version": "a" * 40,
            "digest": None,
            "visibility_source_url": "https://github.com/actions/checkout/commit/" + "a" * 40,
        },
        {
            "project_alias": "synthetic-project-image",
            "artifact_key": "sha256:" + "c" * 64,
            "ecosystem": "oci",
            "registry_host": "ghcr.io",
            "artifact_name": "smithguard/synthetic",
            "version": None,
            "digest": "sha256:" + "d" * 64,
            "visibility_source_url": "https://registry.example.invalid/smithguard/synthetic/",
        },
    ]
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    f"""
                    INSERT INTO {LEGACY_WATCHLISTS_SCHEMA_NAME}.tenants (
                        tenant_id, feature_state, synthetic_only, inventory_revision,
                        contract_revision, current_set_hash, current_entry_count,
                        current_payload_bytes, expires_unconfirmed_after_days,
                        backup_expiry_days, max_entries, max_payload_bytes,
                        max_requests_per_minute, max_runtime_ms, max_concurrency,
                        request_window_started_at, request_count, created_at, updated_at
                    ) VALUES (
                        :tenant_id, 'disabled', true, 'synthetic-revision-mx003',
                        1, :set_hash, 4, 1, 45, 35, 1000, 1048576, 60, 5000, 1,
                        :now, 0, :now, :now
                    )
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "set_hash": "sha256:" + "e" * 64,
                    "now": now,
                },
            )
            connection.execute(
                text(
                    f"""
                    INSERT INTO {LEGACY_WATCHLISTS_SCHEMA_NAME}.current_entries (
                        tenant_id, project_alias, artifact_key, ecosystem, registry_host,
                        artifact_name, version, digest, public_visibility,
                        visibility_verified_at, visibility_source_url, directness,
                        inventory_revision, first_seen_at, last_confirmed_at,
                        last_incident_revision, delivery_state
                    ) VALUES (
                        :tenant_id, :project_alias, :artifact_key, :ecosystem, :registry_host,
                        :artifact_name, :version, :digest, 'verified_public',
                        :now, :visibility_source_url, 'direct',
                        'synthetic-revision-mx003', :now, :now, 0, 'none'
                    )
                    """
                ),
                [{**row, "tenant_id": tenant_id, "now": now} for row in rows],
            )

        migrate(url, "0012_mx014")

        with engine.connect() as connection:
            classified = list(
                connection.execute(
                    text(
                        f"""
                        SELECT ecosystem, target_type, usage, importance
                        FROM {LEGACY_WATCHLISTS_SCHEMA_NAME}.current_entries
                        ORDER BY ecosystem
                        """
                    )
                )
            )
            tenant_metadata = connection.execute(
                text(
                    f"""
                    SELECT current_set_hash, current_entry_count, current_payload_bytes
                    FROM {LEGACY_WATCHLISTS_SCHEMA_NAME}.tenants
                    WHERE tenant_id = :tenant_id
                    """
                ),
                {"tenant_id": tenant_id},
            ).one()
            columns = {
                row.column_name: (row.is_nullable, row.column_default)
                for row in connection.execute(
                    text(
                        """
                        SELECT column_name, is_nullable, column_default
                        FROM information_schema.columns
                        WHERE table_schema = :schema
                          AND table_name = 'current_entries'
                          AND column_name IN ('target_type', 'usage', 'importance')
                        """
                    ),
                    {"schema": LEGACY_WATCHLISTS_SCHEMA_NAME},
                )
            }
        assert classified == [
            ("github-actions", "github_action", "unknown", "standard"),
            ("npm", "software_dependency", "unknown", "standard"),
            ("npm", "software_dependency", "unknown", "standard"),
            ("oci", "container_image", "unknown", "standard"),
        ]
        assert columns == {
            "target_type": ("NO", None),
            "usage": ("NO", None),
            "importance": ("NO", None),
        }
        expected_entries = [
            {
                "project_alias": row["project_alias"],
                "target_type": (
                    "software_dependency"
                    if row["ecosystem"] == "npm"
                    else "github_action"
                    if row["ecosystem"] == "github-actions"
                    else "container_image"
                ),
                "artifact": {
                    "ecosystem": row["ecosystem"],
                    "registry_host": row["registry_host"],
                    "name": row["artifact_name"],
                    "version": row["version"],
                    "digest": row["digest"],
                },
                "public_visibility": "verified_public",
                "visibility_verified_at": timestamp(now),
                "visibility_source_url": row["visibility_source_url"],
                "directness": "direct",
                "usage": "unknown",
                "importance": "standard",
                "inventory_revision": "synthetic-revision-mx003",
                "first_seen_at": timestamp(now),
                "last_confirmed_at": timestamp(now),
            }
            for row in sorted(
                rows,
                key=lambda item: (
                    item["project_alias"],
                    item["ecosystem"],
                    item["registry_host"],
                    item["artifact_name"],
                    item["version"] or "",
                    item["digest"] or "",
                ),
            )
        ]
        expected_hash = sha256_id(
            canonical_json_bytes(
                {
                    "tenant_id": tenant_id,
                    "inventory_revision": "synthetic-revision-mx003",
                    "entries": expected_entries,
                    "expires_unconfirmed_after_days": 45,
                }
            )
        )
        assert tenant_metadata.current_set_hash == expected_hash
        assert tenant_metadata.current_entry_count == 4
        assert tenant_metadata.current_payload_bytes > 1

        with pytest.raises(DBAPIError), engine.begin() as connection:
            connection.execute(
                text(
                    f"""
                    UPDATE {LEGACY_WATCHLISTS_SCHEMA_NAME}.current_entries
                    SET target_type = 'container_image'
                    WHERE ecosystem = 'npm'
                    """
                )
            )
    finally:
        engine.dispose()


def test_mx002_migration_preserves_existing_incident_without_authority(
    postgres_cluster: LocalPostgres,
) -> None:
    url = postgres_cluster.create_database()
    migrate(url, "0007_cpbeta1")
    engine = create_engine(url)
    incident_id = "gbsec:incident:legacy-before-mx002"
    event_id = "gbsec:event:legacy-before-mx002-created"
    occurred_at = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    rendered_at = timestamp(occurred_at)
    coverage = [
        {
            "ecosystem": "npm",
            "stage": "normalized",
            "result": "supported",
            "as_of": rendered_at,
        }
    ]
    legacy_event = {
        "id": event_id,
        "revision": 1,
        "schema_version": "1.0.0",
        "kind": "incident_event",
        "data_classification": "public",
        "created_at": rendered_at,
        "updated_at": rendered_at,
        "incident_id": incident_id,
        "event_type": "created",
        "old_status": None,
        "new_status": "confirmed",
        "actor_type": "system",
        "actor_id": "system-legacy-migration-test",
        "reason_code": "legacy_incident_created",
        "evidence_ids": [],
        "occurred_at": rendered_at,
        "confidence": "confirmed",
        "superseded_revision": None,
    }
    legacy_document = {
        "id": incident_id,
        "revision": 1,
        "schema_version": "1.0.0",
        "kind": "incident",
        "data_classification": "public",
        "created_at": rendered_at,
        "updated_at": rendered_at,
        "title": "Legacy incident",
        "status": "confirmed",
        "confidence": "confirmed",
        "claim_ids": [],
        "artifact_ids": [],
        "affected_range_ids": [],
        "relationship_ids": [],
        "event_ids": [event_id],
        "alias_ids": [],
        "redirect_to": None,
        "first_observed_at": rendered_at,
        "last_changed_at": rendered_at,
        "coverage": coverage,
        "unknowns": [],
    }
    legacy_seed_state = {
        "incident_id": incident_id,
        "title": "Legacy incident",
        "initial_status": "confirmed",
        "initial_confidence": "confirmed",
        "claim_ids": [],
        "artifact_ids": [],
        "affected_range_ids": [],
        "relationship_ids": [],
        "coverage": coverage,
        "unknowns": [],
        "first_observed_at": rendered_at,
        "created_at": rendered_at,
    }
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    f"""
                    INSERT INTO {LEGACY_SCHEMA_NAME}.incident_seeds (
                        incident_id, title, initial_status, initial_confidence,
                        claim_ids, artifact_ids, affected_range_ids,
                        relationship_ids, coverage, unknowns, first_observed_at,
                        created_at, record_hash
                    ) VALUES (
                        :incident_id, 'Legacy incident', 'confirmed', 'confirmed',
                        '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
                        CAST(:coverage AS jsonb), '[]'::jsonb, :occurred_at,
                        :occurred_at, :record_hash
                    )
                    """
                ),
                {
                    "incident_id": incident_id,
                    "coverage": json.dumps(coverage),
                    "occurred_at": occurred_at,
                    "record_hash": sha256_id(canonical_json_bytes(legacy_seed_state)),
                },
            )
            connection.execute(
                text(
                    f"""
                    INSERT INTO {LEGACY_SCHEMA_NAME}.incident_events (
                        id, revision, schema_version, kind, data_classification,
                        created_at, updated_at, record_hash, document, incident_id,
                        event_type, old_status, new_status, actor_type, actor_id,
                        reason_code, evidence_ids, occurred_at, confidence,
                        superseded_revision
                    ) VALUES (
                        :event_id, 1, '1.0.0', 'incident_event', 'public',
                        :occurred_at, :occurred_at, :record_hash,
                        CAST(:document AS jsonb), :incident_id, 'created', NULL,
                        'confirmed', 'system', 'system-legacy-migration-test',
                        'legacy_incident_created', '[]'::jsonb, :occurred_at,
                        'confirmed', NULL
                    )
                    """
                ),
                {
                    "event_id": event_id,
                    "incident_id": incident_id,
                    "occurred_at": occurred_at,
                    "record_hash": sha256_id(canonical_json_bytes(legacy_event)),
                    "document": json.dumps(legacy_event),
                },
            )
            connection.execute(
                text(
                    f"""
                    INSERT INTO {LEGACY_SCHEMA_NAME}.incident_transitions (
                        event_id, event_revision, incident_id, sequence,
                        expected_incident_revision, details, record_hash,
                        created_at
                    ) VALUES (
                        :event_id, 1, :incident_id, 1, 0, '{{}}'::jsonb,
                        :record_hash, :occurred_at
                    )
                    """
                ),
                {
                    "event_id": event_id,
                    "incident_id": incident_id,
                    "record_hash": sha256_id(
                        canonical_json_bytes(
                            {
                                "event": legacy_event,
                                "details": {},
                            }
                        )
                    ),
                    "occurred_at": occurred_at,
                },
            )
            connection.execute(
                text(
                    f"""
                    INSERT INTO {LEGACY_SCHEMA_NAME}.incidents (
                        id, revision, schema_version, kind, data_classification,
                        created_at, updated_at, record_hash, document, title,
                        status, confidence, claim_ids, artifact_ids,
                        affected_range_ids, relationship_ids, event_ids, alias_ids,
                        redirect_to, first_observed_at, last_changed_at, coverage,
                        unknowns
                    ) VALUES (
                        :id, 1, '1.0.0', 'incident', 'public',
                        :occurred_at, :occurred_at, :record_hash,
                        CAST(:document AS jsonb), 'Legacy incident',
                        'confirmed', 'confirmed', '[]'::jsonb, '[]'::jsonb,
                        '[]'::jsonb, '[]'::jsonb, CAST(:event_ids AS jsonb),
                        '[]'::jsonb, NULL, :occurred_at, :occurred_at,
                        CAST(:coverage AS jsonb), '[]'::jsonb
                    )
                    """
                ),
                {
                    "id": incident_id,
                    "occurred_at": occurred_at,
                    "record_hash": sha256_id(canonical_json_bytes(legacy_document)),
                    "document": json.dumps(legacy_document),
                    "event_ids": json.dumps([event_id]),
                    "coverage": json.dumps(coverage),
                },
            )
        engine.dispose()

        migrate(url, "head")
        engine = create_engine(url)
        with engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        f"""
                    SELECT document, authority_decision_ids, authority
                    FROM {SCHEMA_NAME}.incidents
                    WHERE id = :id AND revision = 1
                    """
                    ),
                    {"id": incident_id},
                )
                .mappings()
                .one()
            )
        assert row["document"] == legacy_document
        assert row["authority_decision_ids"] == []
        assert row["authority"] is None
        with Session(engine) as session, session.begin():
            assert verify_latest_incident_rebuild(session, incident_id) == legacy_document
            existing, created = append_contract(session, "Incident", legacy_document)
            assert created is False
            assert existing.document == legacy_document
            replayed = create_incident(
                session,
                seed=IncidentSeed(
                    incident_id=incident_id,
                    title="Legacy incident",
                    initial_status="confirmed",
                    initial_confidence="confirmed",
                    claim_ids=(),
                    artifact_ids=(),
                    affected_range_ids=(),
                    relationship_ids=(),
                    coverage=tuple(coverage),
                    unknowns=(),
                    first_observed_at=occurred_at,
                    created_at=occurred_at,
                ),
                event=legacy_event,
            )
            assert replayed.created is False
            assert replayed.document == legacy_document
    finally:
        engine.dispose()
