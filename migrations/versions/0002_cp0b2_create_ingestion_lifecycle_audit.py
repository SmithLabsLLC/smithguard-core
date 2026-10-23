"""create CP-0B2 ingestion, lifecycle, and audit state

Revision ID: 0002_cp0b2
Revises: 0001_cp0b1
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_cp0b2"
down_revision: str | None = "0001_cp0b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Create CP-0B2 ingestion, lifecycle, and audit state"
rollback_mode: str = "safe_to_zero"

IMMUTABLE_CP_0B2_TABLES = (
    "incident_seeds",
    "incident_transitions",
    "ingestion_batches",
    "review_audit_events",
)


def _protect(table_name: str) -> None:
    op.execute(
        f"""
        CREATE TRIGGER reject_ledger_mutation
        BEFORE UPDATE OR DELETE ON goodboy_security.{table_name}
        FOR EACH ROW
        EXECUTE FUNCTION goodboy_security.reject_ledger_mutation()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER reject_ledger_truncate
        BEFORE TRUNCATE ON goodboy_security.{table_name}
        FOR EACH STATEMENT
        EXECUTE FUNCTION goodboy_security.reject_ledger_mutation()
        """
    )


def upgrade() -> None:
    """Apply this migration."""
    op.create_table(
        "incident_seeds",
        sa.Column("incident_id", sa.String(length=160), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("initial_status", sa.String(length=40), nullable=False),
        sa.Column("initial_confidence", sa.String(length=40), nullable=False),
        sa.Column("claim_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("artifact_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("affected_range_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("relationship_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("coverage", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("unknowns", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "incident_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_incident_seeds_stable_id"),
        ),
        sa.CheckConstraint(
            "initial_confidence IN ('confirmed', 'probable', 'possible', 'unverified', 'disputed', 'unknown')",
            name=op.f("ck_incident_seeds_initial_confidence"),
        ),
        sa.CheckConstraint(
            "initial_status IN ('internal_candidate', 'emerging_unverified', 'investigating', 'confirmed', 'contained', 'resolved', 'disputed', 'withdrawn', 'expired')",
            name=op.f("ck_incident_seeds_initial_status"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_incident_seeds_record_hash"),
        ),
        sa.PrimaryKeyConstraint("incident_id", name=op.f("pk_incident_seeds")),
        schema="goodboy_security",
    )
    op.create_table(
        "incident_transitions",
        sa.Column("event_id", sa.String(length=160), nullable=False),
        sa.Column("event_revision", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.String(length=160), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("expected_incident_revision", sa.Integer(), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "event_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_incident_transitions_stable_id"),
        ),
        sa.CheckConstraint(
            "event_revision >= 1",
            name=op.f("ck_incident_transitions_positive_event_revision"),
        ),
        sa.CheckConstraint(
            "expected_incident_revision >= 0",
            name=op.f("ck_incident_transitions_expected_revision"),
        ),
        sa.CheckConstraint(
            "sequence >= 1 AND sequence <= 10000",
            name=op.f("ck_incident_transitions_sequence"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_incident_transitions_record_hash"),
        ),
        sa.PrimaryKeyConstraint(
            "event_id",
            "event_revision",
            name=op.f("pk_incident_transitions"),
        ),
        sa.UniqueConstraint(
            "incident_id",
            "sequence",
            name=op.f("uq_incident_transitions_incident_id_sequence"),
        ),
        schema="goodboy_security",
    )
    op.create_index(
        "ix_incident_transitions_incident_sequence",
        "incident_transitions",
        ["incident_id", "sequence"],
        unique=False,
        schema="goodboy_security",
    )
    op.create_table(
        "ingestion_batches",
        sa.Column("batch_id", sa.String(length=160), nullable=False),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=71), nullable=False),
        sa.Column("request_hash", sa.String(length=71), nullable=False),
        sa.Column("input_sha256", sa.String(length=71), nullable=False),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("raw_evidence_id", sa.String(length=160), nullable=True),
        sa.Column("quarantine_reasons", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("normalized_record_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("coverage", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "batch_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_ingestion_batches_stable_id"),
        ),
        sa.CheckConstraint(
            "idempotency_key_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_ingestion_batches_idempotency_hash"),
        ),
        sa.CheckConstraint(
            "request_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_ingestion_batches_request_hash"),
        ),
        sa.CheckConstraint(
            "input_sha256 ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_ingestion_batches_input_sha256"),
        ),
        sa.CheckConstraint(
            "outcome IN ('accepted', 'quarantined')",
            name=op.f("ck_ingestion_batches_outcome"),
        ),
        sa.CheckConstraint(
            "record_count >= 0 AND record_count <= 5000",
            name=op.f("ck_ingestion_batches_record_count"),
        ),
        sa.CheckConstraint(
            "(outcome = 'accepted' AND raw_evidence_id IS NOT NULL) OR "
            "(outcome = 'quarantined' AND raw_evidence_id IS NULL)",
            name=op.f("ck_ingestion_batches_evidence_outcome"),
        ),
        sa.PrimaryKeyConstraint("batch_id", name=op.f("pk_ingestion_batches")),
        sa.UniqueConstraint(
            "source_id",
            "idempotency_key_hash",
            name=op.f("uq_ingestion_batches_source_id_idempotency_key_hash"),
        ),
        schema="goodboy_security",
    )
    op.create_index(
        "ix_ingestion_batches_source_completed",
        "ingestion_batches",
        ["source_id", "completed_at"],
        unique=False,
        schema="goodboy_security",
    )
    op.create_table(
        "review_audit_events",
        sa.Column("audit_event_id", sa.String(length=160), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=71), nullable=False),
        sa.Column("incident_id", sa.String(length=160), nullable=False),
        sa.Column("incident_revision", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("actor_type", sa.String(length=20), nullable=False),
        sa.Column("actor_id", sa.String(length=160), nullable=False),
        sa.Column("reason_code", sa.String(length=120), nullable=False),
        sa.Column("evidence_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("decision", sa.String(length=20), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "audit_event_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_review_audit_events_stable_id"),
        ),
        sa.CheckConstraint(
            "idempotency_key_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_review_audit_events_idempotency_hash"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_review_audit_events_record_hash"),
        ),
        sa.CheckConstraint(
            "incident_revision >= 1",
            name=op.f("ck_review_audit_events_positive_incident_revision"),
        ),
        sa.CheckConstraint(
            "event_type IN ('review_opened', 'review_decided', 'publication_approved', "
            "'publication_rejected', 'publication_recorded', 'publication_withdrawn')",
            name=op.f("ck_review_audit_events_event_type"),
        ),
        sa.CheckConstraint(
            "actor_type IN ('reviewer', 'publisher', 'system')",
            name=op.f("ck_review_audit_events_actor_type"),
        ),
        sa.CheckConstraint(
            "decision IN ('pending', 'approved', 'rejected', 'recorded', 'withdrawn')",
            name=op.f("ck_review_audit_events_decision"),
        ),
        sa.CheckConstraint(
            "actor_id ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{2,159}$'",
            name=op.f("ck_review_audit_events_actor_id"),
        ),
        sa.CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name=op.f("ck_review_audit_events_reason_code"),
        ),
        sa.PrimaryKeyConstraint("audit_event_id", name=op.f("pk_review_audit_events")),
        sa.UniqueConstraint(
            "idempotency_key_hash",
            name=op.f("uq_review_audit_events_idempotency_key_hash"),
        ),
        schema="goodboy_security",
    )
    op.create_index(
        "ix_review_audit_incident_revision_occurred",
        "review_audit_events",
        ["incident_id", "incident_revision", "occurred_at"],
        unique=False,
        schema="goodboy_security",
    )
    for table_name in IMMUTABLE_CP_0B2_TABLES:
        _protect(table_name)


def downgrade() -> None:
    """Safely reverse this migration in an ephemeral development database."""
    op.drop_index(
        "ix_review_audit_incident_revision_occurred",
        table_name="review_audit_events",
        schema="goodboy_security",
    )
    op.drop_table("review_audit_events", schema="goodboy_security")
    op.drop_index(
        "ix_ingestion_batches_source_completed",
        table_name="ingestion_batches",
        schema="goodboy_security",
    )
    op.drop_table("ingestion_batches", schema="goodboy_security")
    op.drop_index(
        "ix_incident_transitions_incident_sequence",
        table_name="incident_transitions",
        schema="goodboy_security",
    )
    op.drop_table("incident_transitions", schema="goodboy_security")
    op.drop_table("incident_seeds", schema="goodboy_security")
