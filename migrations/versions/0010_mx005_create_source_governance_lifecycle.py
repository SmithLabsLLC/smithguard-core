"""create MX-005 source governance and publication lifecycle

Revision ID: 0010_mx005
Revises: 0009_mx003
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_mx005"
down_revision: str | None = "0009_mx003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = (
    "Create append-only source governance, publication lifecycle, and reconciliation state"
)
rollback_mode: str = "forward_only"

SCHEMA = "goodboy_security"
STABLE_ID = r"^gbsec:[a-z0-9][a-z0-9:._/-]+$"
SHA256 = r"^sha256:[a-f0-9]{64}$"


def _protect(table_name: str) -> None:
    op.execute(
        f"""
        CREATE TRIGGER reject_ledger_mutation
        BEFORE UPDATE OR DELETE ON {SCHEMA}.{table_name}
        FOR EACH ROW
        EXECUTE FUNCTION {SCHEMA}.reject_ledger_mutation()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER reject_ledger_truncate
        BEFORE TRUNCATE ON {SCHEMA}.{table_name}
        FOR EACH STATEMENT
        EXECUTE FUNCTION {SCHEMA}.reject_ledger_mutation()
        """
    )


def upgrade() -> None:
    """Add governed evidence decisions, lifecycle history, and source drift state."""
    op.add_column(
        "ingestion_batches",
        sa.Column("governance_decision_id", sa.String(length=160), nullable=True),
        schema=SCHEMA,
    )
    op.create_table(
        "source_governance_decisions",
        sa.Column("decision_id", sa.String(length=160), nullable=False),
        sa.Column("policy_id", sa.String(length=160), nullable=False),
        sa.Column("policy_version", sa.String(length=100), nullable=False),
        sa.Column("policy_sha256", sa.String(length=71), nullable=False),
        sa.Column("rights_register_id", sa.String(length=160), nullable=False),
        sa.Column(
            "authorized_disposition_adapter_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("connector_id", sa.String(length=160), nullable=False),
        sa.Column("source_record_id", sa.String(length=512), nullable=False),
        sa.Column("operating_mode", sa.String(length=40), nullable=False),
        sa.Column("acquisition_method", sa.String(length=40), nullable=False),
        sa.Column("field_policy_id", sa.String(length=160), nullable=False),
        sa.Column("accepted_sha256", sa.String(length=71), nullable=False),
        sa.Column("attribution_text", sa.String(length=500), nullable=False),
        sa.Column("license_expression", sa.String(length=200), nullable=True),
        sa.Column(
            "rights_evidence_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("rights_evidence_verified", sa.Boolean(), nullable=False),
        sa.Column("retention_behavior", sa.String(length=80), nullable=False),
        sa.Column("public_status_ceiling", sa.String(length=40), nullable=False),
        sa.Column("correction_behavior", sa.String(length=80), nullable=False),
        sa.Column("withdrawal_behavior", sa.String(length=80), nullable=False),
        sa.Column("rights_drift_behavior", sa.String(length=80), nullable=False),
        sa.Column(
            "qualified_publication_decision_id",
            sa.String(length=160),
            nullable=True,
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"decision_id ~ '{STABLE_ID}'",
            name=op.f("ck_source_governance_decisions_decision_id"),
        ),
        sa.CheckConstraint(
            f"policy_id ~ '{STABLE_ID}'",
            name=op.f("ck_source_governance_decisions_policy_id"),
        ),
        sa.CheckConstraint(
            f"policy_sha256 ~ '{SHA256}'",
            name=op.f("ck_source_governance_decisions_policy_sha256"),
        ),
        sa.CheckConstraint(
            f"rights_register_id ~ '{STABLE_ID}'",
            name=op.f("ck_source_governance_decisions_rights_register_id"),
        ),
        sa.CheckConstraint(
            f"source_id ~ '{STABLE_ID}'",
            name=op.f("ck_source_governance_decisions_source_id"),
        ),
        sa.CheckConstraint(
            f"connector_id ~ '{STABLE_ID}'",
            name=op.f("ck_source_governance_decisions_connector_id"),
        ),
        sa.CheckConstraint(
            f"field_policy_id ~ '{STABLE_ID}'",
            name=op.f("ck_source_governance_decisions_field_policy_id"),
        ),
        sa.CheckConstraint(
            f"accepted_sha256 ~ '{SHA256}'",
            name=op.f("ck_source_governance_decisions_accepted_sha256"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_source_governance_decisions_record_hash"),
        ),
        sa.CheckConstraint(
            "operating_mode IN ('historical', 'updates', 'exact_lookup', 'reconciliation')",
            name=op.f("ck_source_governance_decisions_operating_mode"),
        ),
        sa.CheckConstraint(
            "public_status_ceiling IN ('reported', 'corroborated', 'confirmed')",
            name=op.f("ck_source_governance_decisions_public_status_ceiling"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(rights_evidence_ids) = 'array' "
            "AND jsonb_array_length(rights_evidence_ids) BETWEEN 1 AND 20",
            name=op.f("ck_source_governance_decisions_rights_evidence_ids"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(authorized_disposition_adapter_ids) = 'array' "
            "AND jsonb_array_length(authorized_disposition_adapter_ids) <= 20",
            name=op.f("ck_source_governance_decisions_disposition_adapters"),
        ),
        sa.PrimaryKeyConstraint(
            "decision_id",
            name=op.f("pk_source_governance_decisions"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_source_governance_source_record_decided",
        "source_governance_decisions",
        ["source_id", "source_record_id", "decided_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_source_governance_connector_policy",
        "source_governance_decisions",
        ["connector_id", "policy_sha256"],
        unique=False,
        schema=SCHEMA,
    )

    op.create_table(
        "publication_lifecycle_events",
        sa.Column("lifecycle_event_id", sa.String(length=160), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=71), nullable=False),
        sa.Column("incident_id", sa.String(length=160), nullable=True),
        sa.Column("incident_revision", sa.Integer(), nullable=True),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("actor_type", sa.String(length=20), nullable=False),
        sa.Column("actor_id", sa.String(length=160), nullable=False),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("source_record_id", sa.String(length=512), nullable=False),
        sa.Column("evidence_id", sa.String(length=160), nullable=False),
        sa.Column("authority_decision_id", sa.String(length=160), nullable=True),
        sa.Column("governance_decision_id", sa.String(length=160), nullable=False),
        sa.Column("old_public_status", sa.String(length=40), nullable=True),
        sa.Column("new_public_status", sa.String(length=40), nullable=True),
        sa.Column("reason_code", sa.String(length=120), nullable=False),
        sa.Column("disposition_proof_sha256", sa.String(length=71), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"lifecycle_event_id ~ '{STABLE_ID}'",
            name=op.f("ck_publication_lifecycle_events_event_id"),
        ),
        sa.CheckConstraint(
            f"idempotency_key_hash ~ '{SHA256}'",
            name=op.f("ck_publication_lifecycle_events_idempotency_hash"),
        ),
        sa.CheckConstraint(
            f"source_id ~ '{STABLE_ID}'",
            name=op.f("ck_publication_lifecycle_events_source_id"),
        ),
        sa.CheckConstraint(
            f"evidence_id ~ '{STABLE_ID}'",
            name=op.f("ck_publication_lifecycle_events_evidence_id"),
        ),
        sa.CheckConstraint(
            f"governance_decision_id ~ '{STABLE_ID}'",
            name=op.f("ck_publication_lifecycle_events_governance_decision_id"),
        ),
        sa.CheckConstraint(
            f"authority_decision_id IS NULL OR authority_decision_id ~ '{STABLE_ID}'",
            name=op.f("ck_publication_lifecycle_events_authority_decision_id"),
        ),
        sa.CheckConstraint(
            "(incident_id IS NULL AND incident_revision IS NULL) OR "
            "(incident_id IS NOT NULL AND incident_revision >= 1)",
            name=op.f("ck_publication_lifecycle_events_incident_revision_pair"),
        ),
        sa.CheckConstraint(
            f"incident_id IS NULL OR incident_id ~ '{STABLE_ID}'",
            name=op.f("ck_publication_lifecycle_events_incident_id"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_publication_lifecycle_events_record_hash"),
        ),
        sa.CheckConstraint(
            "event_type IN ("
            "'published', 'corrected', 'disputed', 'withdrawn', 'source_deleted', "
            "'rights_tombstoned', 'rights_purge_requested', 'rights_purged', "
            "'purge_failed'"
            ")",
            name=op.f("ck_publication_lifecycle_events_event_type"),
        ),
        sa.CheckConstraint(
            "actor_type IN ('system', 'reviewer', 'publisher', 'maintenance')",
            name=op.f("ck_publication_lifecycle_events_actor_type"),
        ),
        sa.CheckConstraint(
            "actor_id ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{2,159}$'",
            name=op.f("ck_publication_lifecycle_events_actor_id"),
        ),
        sa.CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name=op.f("ck_publication_lifecycle_events_reason_code"),
        ),
        sa.CheckConstraint(
            f"disposition_proof_sha256 IS NULL OR disposition_proof_sha256 ~ '{SHA256}'",
            name=op.f("ck_publication_lifecycle_events_disposition_proof"),
        ),
        sa.CheckConstraint(
            "(old_public_status IS NULL OR old_public_status IN ("
            "'reported', 'corroborated', 'confirmed', 'contained', 'resolved', "
            "'disputed', 'withdrawn')) AND "
            "(new_public_status IS NULL OR new_public_status IN ("
            "'reported', 'corroborated', 'confirmed', 'contained', 'resolved', "
            "'disputed', 'withdrawn'))",
            name=op.f("ck_publication_lifecycle_events_public_statuses"),
        ),
        sa.CheckConstraint(
            "(event_type IN ("
            "'published', 'corrected', 'disputed', 'withdrawn', 'source_deleted'"
            ") AND incident_id IS NOT NULL AND incident_revision >= 1 "
            "AND new_public_status IS NOT NULL) OR "
            "(event_type IN ("
            "'rights_tombstoned', 'rights_purge_requested', 'rights_purged', "
            "'purge_failed'"
            ") AND incident_id IS NULL AND incident_revision IS NULL "
            "AND old_public_status IS NULL AND new_public_status IS NULL "
            "AND authority_decision_id IS NULL)",
            name=op.f("ck_publication_lifecycle_events_event_shape"),
        ),
        sa.CheckConstraint(
            "(event_type = 'published' AND old_public_status IS NULL) OR "
            "(event_type = 'corrected' AND old_public_status IS NOT NULL) OR "
            "(event_type = 'disputed' AND old_public_status IS NOT NULL "
            "AND new_public_status = 'disputed') OR "
            "(event_type = 'withdrawn' AND old_public_status IS NOT NULL "
            "AND new_public_status = 'withdrawn') OR "
            "(event_type = 'source_deleted' AND old_public_status IS NOT NULL "
            "AND old_public_status = new_public_status) OR "
            "event_type IN ("
            "'rights_tombstoned', 'rights_purge_requested', 'rights_purged', "
            "'purge_failed')",
            name=op.f("ck_publication_lifecycle_events_event_status_semantics"),
        ),
        sa.CheckConstraint(
            "(event_type IN ('rights_purged', 'purge_failed') "
            "AND disposition_proof_sha256 IS NOT NULL) OR "
            "(event_type NOT IN ('rights_purged', 'purge_failed') "
            "AND disposition_proof_sha256 IS NULL)",
            name=op.f("ck_publication_lifecycle_events_purge_proof_pair"),
        ),
        sa.PrimaryKeyConstraint(
            "lifecycle_event_id",
            name=op.f("pk_publication_lifecycle_events"),
        ),
        sa.UniqueConstraint(
            "idempotency_key_hash",
            name=op.f("uq_publication_lifecycle_events_idempotency_key_hash"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_publication_lifecycle_incident_occurred",
        "publication_lifecycle_events",
        ["incident_id", "occurred_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_publication_lifecycle_source_record",
        "publication_lifecycle_events",
        ["source_id", "source_record_id", "occurred_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_publication_lifecycle_evidence_occurred",
        "publication_lifecycle_events",
        ["evidence_id", "occurred_at"],
        unique=False,
        schema=SCHEMA,
    )

    op.create_table(
        "source_reconciliation_runs",
        sa.Column("reconciliation_event_id", sa.String(length=160), nullable=False),
        sa.Column("inventory_run_id", sa.String(length=160), nullable=False),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("connector_id", sa.String(length=160), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("page_index", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("complete_inventory", sa.Boolean(), nullable=False),
        sa.Column("scanned_count", sa.Integer(), nullable=False),
        sa.Column("observed_count", sa.Integer(), nullable=False),
        sa.Column(
            "observed_record_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "late_record_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "modified_record_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "deleted_record_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "missing_record_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "unresolved_record_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("drift_truncated", sa.Boolean(), nullable=False),
        sa.Column("continuation_in_hash", sa.String(length=71), nullable=True),
        sa.Column("continuation_out_hash", sa.String(length=71), nullable=True),
        sa.Column("has_more", sa.Boolean(), nullable=False),
        sa.Column("policy_id", sa.String(length=160), nullable=False),
        sa.Column("policy_sha256", sa.String(length=71), nullable=False),
        sa.Column("observation_sha256", sa.String(length=71), nullable=False),
        sa.Column("reason_code", sa.String(length=120), nullable=False),
        sa.Column("reconciled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"reconciliation_event_id ~ '{STABLE_ID}'",
            name=op.f("ck_source_reconciliation_runs_reconciliation_event_id"),
        ),
        sa.CheckConstraint(
            f"inventory_run_id ~ '{STABLE_ID}'",
            name=op.f("ck_source_reconciliation_runs_inventory_run_id"),
        ),
        sa.CheckConstraint(
            f"source_id ~ '{STABLE_ID}'",
            name=op.f("ck_source_reconciliation_runs_source_id"),
        ),
        sa.CheckConstraint(
            f"connector_id ~ '{STABLE_ID}'",
            name=op.f("ck_source_reconciliation_runs_connector_id"),
        ),
        sa.CheckConstraint(
            f"policy_id ~ '{STABLE_ID}'",
            name=op.f("ck_source_reconciliation_runs_policy_id"),
        ),
        sa.CheckConstraint(
            f"policy_sha256 ~ '{SHA256}'",
            name=op.f("ck_source_reconciliation_runs_policy_sha256"),
        ),
        sa.CheckConstraint(
            f"observation_sha256 ~ '{SHA256}'",
            name=op.f("ck_source_reconciliation_runs_observation_sha256"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_source_reconciliation_runs_record_hash"),
        ),
        sa.CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name=op.f("ck_source_reconciliation_runs_reason_code"),
        ),
        sa.CheckConstraint(
            "sequence >= 1",
            name=op.f("ck_source_reconciliation_runs_sequence"),
        ),
        sa.CheckConstraint(
            "page_index BETWEEN 1 AND 10000",
            name=op.f("ck_source_reconciliation_runs_page_index"),
        ),
        sa.CheckConstraint(
            "state IN ('in_progress', 'complete', 'unresolved', 'failed')",
            name=op.f("ck_source_reconciliation_runs_state"),
        ),
        sa.CheckConstraint(
            "(has_more AND state = 'in_progress') OR "
            "(NOT has_more AND state IN ('complete', 'unresolved', 'failed'))",
            name=op.f("ck_source_reconciliation_runs_state_continuation"),
        ),
        sa.CheckConstraint(
            "(page_index = 1 AND continuation_in_hash IS NULL) OR "
            "(page_index > 1 AND continuation_in_hash IS NOT NULL)",
            name=op.f("ck_source_reconciliation_runs_continuation_input"),
        ),
        sa.CheckConstraint(
            "(has_more AND continuation_out_hash IS NOT NULL) OR "
            "(NOT has_more AND continuation_out_hash IS NULL)",
            name=op.f("ck_source_reconciliation_runs_continuation_output"),
        ),
        sa.CheckConstraint(
            f"continuation_in_hash IS NULL OR continuation_in_hash ~ '{SHA256}'",
            name=op.f("ck_source_reconciliation_runs_continuation_in_hash"),
        ),
        sa.CheckConstraint(
            f"continuation_out_hash IS NULL OR continuation_out_hash ~ '{SHA256}'",
            name=op.f("ck_source_reconciliation_runs_continuation_out_hash"),
        ),
        sa.CheckConstraint(
            "NOT complete_inventory OR NOT has_more",
            name=op.f("ck_source_reconciliation_runs_complete_inventory_terminal"),
        ),
        sa.CheckConstraint(
            "scanned_count >= 0 AND scanned_count <= 5000",
            name=op.f("ck_source_reconciliation_runs_scanned_count"),
        ),
        sa.CheckConstraint(
            "observed_count >= 0 AND observed_count <= 100000",
            name=op.f("ck_source_reconciliation_runs_observed_count"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(observed_record_ids) = 'array' "
            "AND jsonb_array_length(observed_record_ids) <= 5000",
            name=op.f("ck_source_reconciliation_runs_observed_record_ids"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(late_record_ids) = 'array' "
            "AND jsonb_array_length(late_record_ids) <= 100",
            name=op.f("ck_source_reconciliation_runs_late_record_ids"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(modified_record_ids) = 'array' "
            "AND jsonb_array_length(modified_record_ids) <= 100",
            name=op.f("ck_source_reconciliation_runs_modified_record_ids"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(deleted_record_ids) = 'array' "
            "AND jsonb_array_length(deleted_record_ids) <= 100",
            name=op.f("ck_source_reconciliation_runs_deleted_record_ids"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(missing_record_ids) = 'array' "
            "AND jsonb_array_length(missing_record_ids) <= 100",
            name=op.f("ck_source_reconciliation_runs_missing_record_ids"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(unresolved_record_ids) = 'array' "
            "AND jsonb_array_length(unresolved_record_ids) <= 100",
            name=op.f("ck_source_reconciliation_runs_unresolved_record_ids"),
        ),
        sa.CheckConstraint(
            "next_due_at > reconciled_at",
            name=op.f("ck_source_reconciliation_runs_next_due"),
        ),
        sa.PrimaryKeyConstraint(
            "reconciliation_event_id",
            name=op.f("pk_source_reconciliation_runs"),
        ),
        sa.UniqueConstraint(
            "source_id",
            "sequence",
            name=op.f("uq_source_reconciliation_runs_source_id_sequence"),
        ),
        sa.UniqueConstraint(
            "source_id",
            "inventory_run_id",
            "page_index",
            name="uq_source_reconciliation_run_page",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_source_reconciliation_source_reconciled",
        "source_reconciliation_runs",
        ["source_id", "reconciled_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_source_reconciliation_state_due",
        "source_reconciliation_runs",
        ["state", "next_due_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_source_reconciliation_run_page",
        "source_reconciliation_runs",
        ["inventory_run_id", "page_index"],
        unique=False,
        schema=SCHEMA,
    )
    for table_name in (
        "source_governance_decisions",
        "publication_lifecycle_events",
        "source_reconciliation_runs",
    ):
        _protect(table_name)


def downgrade() -> None:
    """Refuse to erase source decisions, publication history, or drift evidence."""
    raise RuntimeError(
        "0010_mx005 is forward-only because source governance and lifecycle history is permanent"
    )
