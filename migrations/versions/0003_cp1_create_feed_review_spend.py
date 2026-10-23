"""create CP-1 feed, review, source, and spend state

Revision ID: 0003_cp1
Revises: 0002_cp0b2
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_cp1"
down_revision: str | None = "0002_cp0b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Create CP-1 feed, review, source, and spend state"
rollback_mode: str = "safe_to_zero"

IMMUTABLE_CP_1_TABLES = (
    "collector_checkpoints",
    "source_cluster_members",
    "review_queue_events",
    "spend_ledger_events",
    "snapshot_manifests",
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
    op.create_index(
        "ix_incidents_alias_ids",
        "incidents",
        ["alias_ids"],
        unique=False,
        schema="goodboy_security",
        postgresql_using="gin",
    )
    op.create_index(
        "ix_incidents_redirect_to",
        "incidents",
        ["redirect_to"],
        unique=False,
        schema="goodboy_security",
    )
    op.create_index(
        "ix_actions_evidence_ids",
        "recommended_actions",
        ["evidence_ids"],
        unique=False,
        schema="goodboy_security",
        postgresql_using="gin",
    )
    op.create_table(
        "collector_checkpoints",
        sa.Column("checkpoint_event_id", sa.String(length=160), nullable=False),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("checkpoint_token_hash", sa.String(length=71), nullable=True),
        sa.Column("result", sa.String(length=20), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("reason_code", sa.String(length=120), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "checkpoint_event_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_collector_checkpoints_stable_id"),
        ),
        sa.CheckConstraint(
            "source_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_collector_checkpoints_source_id"),
        ),
        sa.CheckConstraint(
            "checkpoint_token_hash IS NULL OR checkpoint_token_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_collector_checkpoints_checkpoint_hash"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_collector_checkpoints_record_hash"),
        ),
        sa.CheckConstraint(
            "sequence >= 1",
            name=op.f("ck_collector_checkpoints_sequence"),
        ),
        sa.CheckConstraint(
            "result IN ('accepted', 'quarantined', 'disabled')",
            name=op.f("ck_collector_checkpoints_result"),
        ),
        sa.CheckConstraint(
            "record_count >= 0 AND record_count <= 5000",
            name=op.f("ck_collector_checkpoints_record_count"),
        ),
        sa.CheckConstraint(
            "byte_count >= 0 AND byte_count <= 52428800",
            name=op.f("ck_collector_checkpoints_byte_count"),
        ),
        sa.CheckConstraint(
            "duration_ms >= 0 AND duration_ms <= 3600000",
            name=op.f("ck_collector_checkpoints_duration_ms"),
        ),
        sa.CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name=op.f("ck_collector_checkpoints_reason_code"),
        ),
        sa.PrimaryKeyConstraint(
            "checkpoint_event_id",
            name=op.f("pk_collector_checkpoints"),
        ),
        sa.UniqueConstraint(
            "source_id",
            "sequence",
            name=op.f("uq_collector_checkpoints_source_id_sequence"),
        ),
        schema="goodboy_security",
    )
    op.create_index(
        "ix_collector_checkpoints_source_occurred",
        "collector_checkpoints",
        ["source_id", "occurred_at"],
        unique=False,
        schema="goodboy_security",
    )
    op.create_table(
        "source_cluster_members",
        sa.Column("member_id", sa.String(length=160), nullable=False),
        sa.Column("cluster_id", sa.String(length=160), nullable=False),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("source_record_id", sa.String(length=512), nullable=False),
        sa.Column("evidence_id", sa.String(length=160), nullable=False),
        sa.Column("artifact_id", sa.String(length=160), nullable=False),
        sa.Column("independent_origin_id", sa.String(length=160), nullable=False),
        sa.Column("claim_fingerprint", sa.String(length=71), nullable=False),
        sa.Column("relation", sa.String(length=20), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "member_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_source_cluster_members_stable_id"),
        ),
        sa.CheckConstraint(
            "cluster_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_source_cluster_members_cluster_id"),
        ),
        sa.CheckConstraint(
            "source_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_source_cluster_members_source_id"),
        ),
        sa.CheckConstraint(
            "evidence_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_source_cluster_members_evidence_id"),
        ),
        sa.CheckConstraint(
            "artifact_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_source_cluster_members_artifact_id"),
        ),
        sa.CheckConstraint(
            "independent_origin_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_source_cluster_members_independent_origin_id"),
        ),
        sa.CheckConstraint(
            "claim_fingerprint ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_source_cluster_members_claim_fingerprint"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_source_cluster_members_record_hash"),
        ),
        sa.CheckConstraint(
            "relation IN ('origin', 'corroborates', 'conflicts', 'corrects', 'withdraws')",
            name=op.f("ck_source_cluster_members_relation"),
        ),
        sa.PrimaryKeyConstraint(
            "member_id",
            name=op.f("pk_source_cluster_members"),
        ),
        sa.UniqueConstraint(
            "cluster_id",
            "source_id",
            "source_record_id",
            name="uq_source_cluster_member_identity",
        ),
        schema="goodboy_security",
    )
    op.create_index(
        "ix_source_cluster_members_cluster_observed",
        "source_cluster_members",
        ["cluster_id", "observed_at"],
        unique=False,
        schema="goodboy_security",
    )
    op.create_index(
        "ix_source_cluster_members_artifact",
        "source_cluster_members",
        ["artifact_id", "claim_fingerprint"],
        unique=False,
        schema="goodboy_security",
    )
    op.create_table(
        "review_queue_events",
        sa.Column("event_id", sa.String(length=160), nullable=False),
        sa.Column("queue_item_id", sa.String(length=160), nullable=False),
        sa.Column("cluster_id", sa.String(length=160), nullable=False),
        sa.Column("incident_id", sa.String(length=160), nullable=True),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("state", sa.String(length=40), nullable=False),
        sa.Column("actor_type", sa.String(length=40), nullable=False),
        sa.Column("actor_id", sa.String(length=160), nullable=False),
        sa.Column("reason_code", sa.String(length=120), nullable=False),
        sa.Column("decision", sa.String(length=20), nullable=True),
        sa.Column("evidence_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "event_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_review_queue_events_stable_id"),
        ),
        sa.CheckConstraint(
            "queue_item_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_review_queue_events_queue_item_id"),
        ),
        sa.CheckConstraint(
            "cluster_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_review_queue_events_cluster_id"),
        ),
        sa.CheckConstraint(
            "incident_id IS NULL OR incident_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_review_queue_events_incident_id"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_review_queue_events_record_hash"),
        ),
        sa.CheckConstraint(
            "sequence >= 1 AND sequence <= 1000",
            name=op.f("ck_review_queue_events_sequence"),
        ),
        sa.CheckConstraint(
            "event_type IN ('opened', 'assigned', 'decided', 'disputed', 'appealed', "
            "'correction_requested', 'withdrawal_requested', 'expired', 'closed')",
            name=op.f("ck_review_queue_events_event_type"),
        ),
        sa.CheckConstraint(
            "state IN ('pending', 'in_review', 'approved', 'rejected', 'disputed', "
            "'correction_pending', 'withdrawal_pending', 'expired', 'closed')",
            name=op.f("ck_review_queue_events_state"),
        ),
        sa.CheckConstraint(
            "actor_type IN ('system', 'reviewer', 'maintainer', 'affected_party')",
            name=op.f("ck_review_queue_events_actor_type"),
        ),
        sa.CheckConstraint(
            "actor_id ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{2,159}$'",
            name=op.f("ck_review_queue_events_actor_id"),
        ),
        sa.CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name=op.f("ck_review_queue_events_reason_code"),
        ),
        sa.CheckConstraint(
            "decision IS NULL OR decision IN ('approved', 'rejected')",
            name=op.f("ck_review_queue_events_decision"),
        ),
        sa.PrimaryKeyConstraint("event_id", name=op.f("pk_review_queue_events")),
        sa.UniqueConstraint(
            "queue_item_id",
            "sequence",
            name=op.f("uq_review_queue_events_queue_item_id_sequence"),
        ),
        schema="goodboy_security",
    )
    op.create_index(
        "ix_review_queue_events_item_sequence",
        "review_queue_events",
        ["queue_item_id", "sequence"],
        unique=False,
        schema="goodboy_security",
    )
    op.create_index(
        "ix_review_queue_events_state_occurred",
        "review_queue_events",
        ["state", "occurred_at"],
        unique=False,
        schema="goodboy_security",
    )
    op.create_table(
        "spend_ledger_events",
        sa.Column("spend_event_id", sa.String(length=160), nullable=False),
        sa.Column("event_key_hash", sa.String(length=71), nullable=False),
        sa.Column("reservation_id", sa.String(length=160), nullable=False),
        sa.Column("billing_period", sa.String(length=7), nullable=False),
        sa.Column("event_type", sa.String(length=20), nullable=False),
        sa.Column("amount_microusd", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("provider_cost_id_hash", sa.String(length=71), nullable=True),
        sa.Column("provider_price_id_hash", sa.String(length=71), nullable=True),
        sa.Column("reason_code", sa.String(length=120), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "spend_event_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_spend_ledger_events_stable_id"),
        ),
        sa.CheckConstraint(
            "event_key_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_spend_ledger_events_event_key_hash"),
        ),
        sa.CheckConstraint(
            "reservation_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_spend_ledger_events_reservation_id"),
        ),
        sa.CheckConstraint(
            "provider_cost_id_hash IS NULL OR provider_cost_id_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_spend_ledger_events_provider_cost_id_hash"),
        ),
        sa.CheckConstraint(
            "provider_price_id_hash IS NULL OR provider_price_id_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_spend_ledger_events_provider_price_id_hash"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_spend_ledger_events_record_hash"),
        ),
        sa.CheckConstraint(
            "billing_period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'",
            name=op.f("ck_spend_ledger_events_billing_period"),
        ),
        sa.CheckConstraint(
            "currency = 'USD'",
            name=op.f("ck_spend_ledger_events_currency"),
        ),
        sa.CheckConstraint(
            "event_type IN ('reserved', 'settled', 'released', 'denied')",
            name=op.f("ck_spend_ledger_events_event_type"),
        ),
        sa.CheckConstraint(
            "amount_microusd >= 0 AND amount_microusd <= 75000000",
            name=op.f("ck_spend_ledger_events_amount_microusd"),
        ),
        sa.CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name=op.f("ck_spend_ledger_events_reason_code"),
        ),
        sa.PrimaryKeyConstraint(
            "spend_event_id",
            name=op.f("pk_spend_ledger_events"),
        ),
        sa.UniqueConstraint(
            "event_key_hash",
            name=op.f("uq_spend_ledger_events_event_key_hash"),
        ),
        schema="goodboy_security",
    )
    op.create_index(
        "ix_spend_ledger_period_reservation",
        "spend_ledger_events",
        ["billing_period", "reservation_id"],
        unique=False,
        schema="goodboy_security",
    )
    op.create_table(
        "snapshot_manifests",
        sa.Column("snapshot_id", sa.String(length=160), nullable=False),
        sa.Column("schema_version", sa.String(length=20), nullable=False),
        sa.Column("feed_version", sa.String(length=40), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content_sha256", sa.String(length=71), nullable=False),
        sa.Column("signature_base64", sa.String(length=128), nullable=False),
        sa.Column("public_key_id", sa.String(length=160), nullable=False),
        sa.Column("incident_count", sa.Integer(), nullable=False),
        sa.Column("max_revision", sa.Integer(), nullable=False),
        sa.Column("build_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "snapshot_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_snapshot_manifests_stable_id"),
        ),
        sa.CheckConstraint(
            "content_sha256 ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_snapshot_manifests_content_sha256"),
        ),
        sa.CheckConstraint(
            "public_key_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_snapshot_manifests_public_key_id"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_snapshot_manifests_record_hash"),
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name=op.f("ck_snapshot_manifests_schema_version"),
        ),
        sa.CheckConstraint(
            "expires_at > generated_at",
            name=op.f("ck_snapshot_manifests_expiry_order"),
        ),
        sa.CheckConstraint(
            "incident_count >= 0",
            name=op.f("ck_snapshot_manifests_incident_count"),
        ),
        sa.CheckConstraint(
            "max_revision >= 0",
            name=op.f("ck_snapshot_manifests_max_revision"),
        ),
        sa.PrimaryKeyConstraint(
            "snapshot_id",
            name=op.f("pk_snapshot_manifests"),
        ),
        schema="goodboy_security",
    )
    op.create_index(
        "ix_snapshot_manifests_generated",
        "snapshot_manifests",
        ["generated_at"],
        unique=False,
        schema="goodboy_security",
    )
    for table_name in IMMUTABLE_CP_1_TABLES:
        _protect(table_name)


def downgrade() -> None:
    """Safely reverse this migration in an ephemeral development database."""
    op.drop_index(
        "ix_snapshot_manifests_generated",
        table_name="snapshot_manifests",
        schema="goodboy_security",
    )
    op.drop_table("snapshot_manifests", schema="goodboy_security")
    op.drop_index(
        "ix_spend_ledger_period_reservation",
        table_name="spend_ledger_events",
        schema="goodboy_security",
    )
    op.drop_table("spend_ledger_events", schema="goodboy_security")
    op.drop_index(
        "ix_review_queue_events_state_occurred",
        table_name="review_queue_events",
        schema="goodboy_security",
    )
    op.drop_index(
        "ix_review_queue_events_item_sequence",
        table_name="review_queue_events",
        schema="goodboy_security",
    )
    op.drop_table("review_queue_events", schema="goodboy_security")
    op.drop_index(
        "ix_source_cluster_members_artifact",
        table_name="source_cluster_members",
        schema="goodboy_security",
    )
    op.drop_index(
        "ix_source_cluster_members_cluster_observed",
        table_name="source_cluster_members",
        schema="goodboy_security",
    )
    op.drop_table("source_cluster_members", schema="goodboy_security")
    op.drop_index(
        "ix_collector_checkpoints_source_occurred",
        table_name="collector_checkpoints",
        schema="goodboy_security",
    )
    op.drop_table("collector_checkpoints", schema="goodboy_security")
    op.drop_index(
        "ix_actions_evidence_ids",
        table_name="recommended_actions",
        schema="goodboy_security",
    )
    op.drop_index(
        "ix_incidents_redirect_to",
        table_name="incidents",
        schema="goodboy_security",
    )
    op.drop_index(
        "ix_incidents_alias_ids",
        table_name="incidents",
        schema="goodboy_security",
    )
