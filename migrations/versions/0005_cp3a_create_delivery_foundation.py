"""create CP-3A event and disabled delivery foundation

Revision ID: 0005_cp3a
Revises: 0004_cp2b
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_cp3a"
down_revision: str | None = "0004_cp2b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Create CP-3A event and disabled delivery foundation"
rollback_mode: str = "safe_to_zero"


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
    """Create local delivery records without enabling an external transport."""
    op.create_table(
        "delivery_events",
        sa.Column(
            "sequence",
            sa.BigInteger(),
            sa.Identity(always=False),
            nullable=False,
        ),
        sa.Column("event_id", sa.String(length=160), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("incident_id", sa.String(length=160), nullable=False),
        sa.Column("incident_revision", sa.Integer(), nullable=False),
        sa.Column("data_classification", sa.String(length=40), nullable=False),
        sa.Column("project_alias", sa.String(length=100), nullable=True),
        sa.Column("recommended_action_level", sa.Integer(), nullable=False),
        sa.Column("deduplication_key", sa.String(length=200), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("incident_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(
            "event_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_delivery_events_event_id"),
        ),
        sa.CheckConstraint(
            "incident_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_delivery_events_incident_id"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_delivery_events_record_hash"),
        ),
        sa.CheckConstraint(
            "deduplication_key = event_id",
            name=op.f("ck_delivery_events_deduplication_key"),
        ),
        sa.CheckConstraint(
            "sequence >= 1",
            name=op.f("ck_delivery_events_sequence"),
        ),
        sa.CheckConstraint(
            "event_type IN ("
            "'incident_created', 'incident_updated', 'corrected', "
            "'disputed', 'expired', 'withdrawn'"
            ")",
            name=op.f("ck_delivery_events_event_type"),
        ),
        sa.CheckConstraint(
            "data_classification IN ('public', 'customer_local', 'hosted_watch_minimized')",
            name=op.f("ck_delivery_events_data_classification"),
        ),
        sa.CheckConstraint(
            "(data_classification = 'public' AND project_alias IS NULL) "
            "OR data_classification <> 'public'",
            name=op.f("ck_delivery_events_public_alias"),
        ),
        sa.CheckConstraint(
            "incident_revision >= 1",
            name=op.f("ck_delivery_events_incident_revision"),
        ),
        sa.CheckConstraint(
            "recommended_action_level BETWEEN 0 AND 4",
            name=op.f("ck_delivery_events_action_level"),
        ),
        sa.CheckConstraint(
            "incident_updated_at >= published_at",
            name=op.f("ck_delivery_events_incident_time_order"),
        ),
        sa.CheckConstraint(
            "occurred_at >= incident_updated_at",
            name=op.f("ck_delivery_events_event_time_order"),
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name=op.f("ck_delivery_events_record_time_order"),
        ),
        sa.PrimaryKeyConstraint("event_id", name=op.f("pk_delivery_events")),
        sa.UniqueConstraint(
            "sequence",
            name=op.f("uq_delivery_events_sequence"),
        ),
        schema="goodboy_security",
    )
    op.create_index(
        "ix_delivery_events_incident_revision",
        "delivery_events",
        ["incident_id", "incident_revision"],
        unique=False,
        schema="goodboy_security",
    )
    op.create_table(
        "delivery_destinations",
        sa.Column("destination_id", sa.String(length=160), nullable=False),
        sa.Column("adapter", sa.String(length=20), nullable=False),
        sa.Column("identity_hash", sa.String(length=71), nullable=False),
        sa.Column("secret_reference_hash", sa.String(length=71), nullable=False),
        sa.Column("activation_state", sa.String(length=20), nullable=False),
        sa.Column("synthetic_only", sa.Boolean(), nullable=False),
        sa.Column("event_types", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("severity_floor", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "destination_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_delivery_destinations_destination_id"),
        ),
        sa.CheckConstraint(
            "identity_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_delivery_destinations_identity_hash"),
        ),
        sa.CheckConstraint(
            "secret_reference_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_delivery_destinations_secret_reference_hash"),
        ),
        sa.CheckConstraint(
            "adapter IN ('webhook', 'agentmail', 'github')",
            name=op.f("ck_delivery_destinations_adapter"),
        ),
        sa.CheckConstraint(
            "activation_state IN ('disabled', 'synthetic')",
            name=op.f("ck_delivery_destinations_activation_state"),
        ),
        sa.CheckConstraint(
            "(activation_state = 'synthetic' AND synthetic_only) "
            "OR (activation_state = 'disabled' AND NOT synthetic_only)",
            name=op.f("ck_delivery_destinations_synthetic_state"),
        ),
        sa.CheckConstraint(
            "severity_floor IN ('unknown', 'low', 'moderate', 'high', 'critical')",
            name=op.f("ck_delivery_destinations_severity_floor"),
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name=op.f("ck_delivery_destinations_timestamp_order"),
        ),
        sa.PrimaryKeyConstraint(
            "destination_id",
            name=op.f("pk_delivery_destinations"),
        ),
        sa.UniqueConstraint(
            "adapter",
            "identity_hash",
            name=op.f("uq_delivery_destinations_adapter_identity_hash"),
        ),
        schema="goodboy_security",
    )
    op.create_table(
        "delivery_attempts",
        sa.Column("attempt_id", sa.String(length=160), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("event_id", sa.String(length=160), nullable=False),
        sa.Column("destination_id", sa.String(length=160), nullable=False),
        sa.Column("adapter", sa.String(length=20), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=30), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(length=120), nullable=True),
        sa.Column("request_hash", sa.String(length=71), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "attempt_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_delivery_attempts_attempt_id"),
        ),
        sa.CheckConstraint(
            "event_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_delivery_attempts_event_id"),
        ),
        sa.CheckConstraint(
            "destination_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_delivery_attempts_destination_id"),
        ),
        sa.CheckConstraint(
            "request_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_delivery_attempts_request_hash"),
        ),
        sa.CheckConstraint(
            "attempt_number >= 1 AND attempt_number <= 100",
            name=op.f("ck_delivery_attempts_attempt_number"),
        ),
        sa.CheckConstraint(
            "adapter IN ('webhook', 'agentmail', 'github')",
            name=op.f("ck_delivery_attempts_adapter"),
        ),
        sa.CheckConstraint(
            "outcome IN ('succeeded', 'retry_scheduled', 'dead_letter')",
            name=op.f("ck_delivery_attempts_outcome"),
        ),
        sa.CheckConstraint(
            "status_code IS NULL OR status_code BETWEEN 100 AND 599",
            name=op.f("ck_delivery_attempts_status_code"),
        ),
        sa.CheckConstraint(
            "error_code IS NULL OR error_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name=op.f("ck_delivery_attempts_error_code"),
        ),
        sa.CheckConstraint(
            "(outcome = 'succeeded' AND error_code IS NULL) "
            "OR (outcome <> 'succeeded' AND error_code IS NOT NULL)",
            name=op.f("ck_delivery_attempts_outcome_error"),
        ),
        sa.PrimaryKeyConstraint("attempt_id", name=op.f("pk_delivery_attempts")),
        sa.UniqueConstraint(
            "job_id",
            "attempt_number",
            name=op.f("uq_delivery_attempts_job_id_attempt_number"),
        ),
        schema="goodboy_security",
    )
    op.create_index(
        "ix_delivery_attempts_event_destination",
        "delivery_attempts",
        ["event_id", "destination_id"],
        unique=False,
        schema="goodboy_security",
    )
    op.create_table(
        "webhook_receipts",
        sa.Column("destination_id", sa.String(length=160), nullable=False),
        sa.Column("webhook_id", sa.String(length=160), nullable=False),
        sa.Column("webhook_timestamp", sa.BigInteger(), nullable=False),
        sa.Column("body_hash", sa.String(length=71), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "destination_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_webhook_receipts_destination_id"),
        ),
        sa.CheckConstraint(
            "webhook_id ~ '^[A-Za-z0-9_:-]{8,160}$'",
            name=op.f("ck_webhook_receipts_webhook_id"),
        ),
        sa.CheckConstraint(
            "body_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_webhook_receipts_body_hash"),
        ),
        sa.CheckConstraint(
            "expires_at > received_at",
            name=op.f("ck_webhook_receipts_expiry_order"),
        ),
        sa.PrimaryKeyConstraint(
            "destination_id",
            "webhook_id",
            name=op.f("pk_webhook_receipts"),
        ),
        schema="goodboy_security",
    )
    op.create_index(
        "ix_webhook_receipts_expiry",
        "webhook_receipts",
        ["expires_at"],
        unique=False,
        schema="goodboy_security",
    )
    _protect("delivery_events")
    _protect("delivery_attempts")


def downgrade() -> None:
    """Remove the unused local delivery foundation in an ephemeral database."""
    op.drop_index(
        "ix_webhook_receipts_expiry",
        table_name="webhook_receipts",
        schema="goodboy_security",
    )
    op.drop_table("webhook_receipts", schema="goodboy_security")
    op.drop_index(
        "ix_delivery_attempts_event_destination",
        table_name="delivery_attempts",
        schema="goodboy_security",
    )
    op.drop_table("delivery_attempts", schema="goodboy_security")
    op.drop_table("delivery_destinations", schema="goodboy_security")
    op.drop_index(
        "ix_delivery_events_incident_revision",
        table_name="delivery_events",
        schema="goodboy_security",
    )
    op.drop_table("delivery_events", schema="goodboy_security")
