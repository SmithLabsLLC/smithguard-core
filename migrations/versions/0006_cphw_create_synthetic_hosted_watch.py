"""create disabled synthetic Hosted Watch boundary

Revision ID: 0006_cphw
Revises: 0005_cp3a
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_cphw"
down_revision: str | None = "0005_cp3a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Create disabled synthetic Hosted Watch boundary"
rollback_mode: str = "safe_to_zero"

SCHEMA = "goodboy_hosted_watch"


def _protect(table_name: str) -> None:
    op.execute(
        f"""
        CREATE TRIGGER reject_ledger_mutation
        BEFORE UPDATE OR DELETE ON {SCHEMA}.{table_name}
        FOR EACH ROW
        EXECUTE FUNCTION goodboy_security.reject_ledger_mutation()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER reject_ledger_truncate
        BEFORE TRUNCATE ON {SCHEMA}.{table_name}
        FOR EACH STATEMENT
        EXECUTE FUNCTION goodboy_security.reject_ledger_mutation()
        """
    )


def _encrypted_columns(identifier: str) -> list[sa.Column[object]]:
    return [
        sa.Column("tenant_id", sa.String(length=160), nullable=False),
        sa.Column(identifier, sa.String(length=160), nullable=False),
        sa.Column("key_id", sa.String(length=160), nullable=False),
        sa.Column("nonce", sa.LargeBinary(length=32), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(length=65536), nullable=False),
        sa.Column("ciphertext_hash", sa.String(length=71), nullable=False),
        sa.Column("feature_state", sa.String(length=20), nullable=False),
        sa.Column("synthetic_only", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    ]


def _encrypted_constraints(table_name: str, identifier: str) -> list[object]:
    return [
        sa.CheckConstraint(
            "tenant_id ~ '^synthetic[_-][A-Za-z0-9_-]{6,150}$'",
            name=op.f(f"ck_{table_name}_tenant_id"),
        ),
        sa.CheckConstraint(
            f"{identifier} ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{{7,159}}$'",
            name=op.f(f"ck_{table_name}_record_id"),
        ),
        sa.CheckConstraint(
            "key_id ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{7,159}$'",
            name=op.f(f"ck_{table_name}_key_id"),
        ),
        sa.CheckConstraint(
            "octet_length(nonce) BETWEEN 12 AND 32",
            name=op.f(f"ck_{table_name}_nonce"),
        ),
        sa.CheckConstraint(
            "octet_length(ciphertext) BETWEEN 16 AND 65536",
            name=op.f(f"ck_{table_name}_ciphertext"),
        ),
        sa.CheckConstraint(
            "ciphertext_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f(f"ck_{table_name}_ciphertext_hash"),
        ),
        sa.CheckConstraint(
            "feature_state = 'disabled'",
            name=op.f(f"ck_{table_name}_feature_state"),
        ),
        sa.CheckConstraint(
            "synthetic_only",
            name=op.f(f"ck_{table_name}_synthetic_only"),
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name=op.f(f"ck_{table_name}_timestamp_order"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            [f"{SCHEMA}.tenants.tenant_id"],
            name=op.f(f"fk_{table_name}_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            identifier,
            name=op.f(f"pk_{table_name}"),
        ),
    ]


def upgrade() -> None:
    """Create a separate local schema with no enabled or real-data state."""
    op.execute(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}")
    op.create_table(
        "tenants",
        sa.Column("tenant_id", sa.String(length=160), nullable=False),
        sa.Column("feature_state", sa.String(length=20), nullable=False),
        sa.Column("synthetic_only", sa.Boolean(), nullable=False),
        sa.Column("inventory_revision", sa.String(length=160), nullable=False),
        sa.Column("contract_revision", sa.Integer(), nullable=False),
        sa.Column("current_set_hash", sa.String(length=71), nullable=False),
        sa.Column("current_entry_count", sa.Integer(), nullable=False),
        sa.Column("current_payload_bytes", sa.BigInteger(), nullable=False),
        sa.Column("expires_unconfirmed_after_days", sa.Integer(), nullable=False),
        sa.Column("backup_expiry_days", sa.Integer(), nullable=False),
        sa.Column("max_entries", sa.Integer(), nullable=False),
        sa.Column("max_payload_bytes", sa.BigInteger(), nullable=False),
        sa.Column("max_requests_per_minute", sa.Integer(), nullable=False),
        sa.Column("max_runtime_ms", sa.Integer(), nullable=False),
        sa.Column("max_concurrency", sa.Integer(), nullable=False),
        sa.Column("request_window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "tenant_id ~ '^synthetic[_-][A-Za-z0-9_-]{6,150}$'",
            name=op.f("ck_tenants_tenant_id"),
        ),
        sa.CheckConstraint(
            "feature_state = 'disabled'",
            name=op.f("ck_tenants_feature_state"),
        ),
        sa.CheckConstraint("synthetic_only", name=op.f("ck_tenants_synthetic_only")),
        sa.CheckConstraint(
            "current_set_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_tenants_current_set_hash"),
        ),
        sa.CheckConstraint(
            "contract_revision >= 1",
            name=op.f("ck_tenants_contract_revision"),
        ),
        sa.CheckConstraint(
            "current_entry_count >= 0",
            name=op.f("ck_tenants_current_entry_count"),
        ),
        sa.CheckConstraint(
            "current_payload_bytes >= 0",
            name=op.f("ck_tenants_current_payload_bytes"),
        ),
        sa.CheckConstraint(
            "expires_unconfirmed_after_days = 45",
            name=op.f("ck_tenants_stale_expiry"),
        ),
        sa.CheckConstraint(
            "backup_expiry_days = 35",
            name=op.f("ck_tenants_backup_expiry"),
        ),
        sa.CheckConstraint("max_entries = 1000", name=op.f("ck_tenants_max_entries")),
        sa.CheckConstraint(
            "max_payload_bytes = 1048576",
            name=op.f("ck_tenants_max_payload_bytes"),
        ),
        sa.CheckConstraint(
            "max_requests_per_minute = 60",
            name=op.f("ck_tenants_max_requests"),
        ),
        sa.CheckConstraint(
            "max_runtime_ms = 5000",
            name=op.f("ck_tenants_max_runtime"),
        ),
        sa.CheckConstraint(
            "max_concurrency = 1",
            name=op.f("ck_tenants_max_concurrency"),
        ),
        sa.CheckConstraint(
            "request_count >= 0 AND request_count <= max_requests_per_minute",
            name=op.f("ck_tenants_request_count"),
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name=op.f("ck_tenants_timestamp_order"),
        ),
        sa.PrimaryKeyConstraint("tenant_id", name=op.f("pk_tenants")),
        schema=SCHEMA,
    )
    op.create_table(
        "current_entries",
        sa.Column("tenant_id", sa.String(length=160), nullable=False),
        sa.Column("project_alias", sa.String(length=100), nullable=False),
        sa.Column("artifact_key", sa.String(length=71), nullable=False),
        sa.Column("ecosystem", sa.String(length=30), nullable=False),
        sa.Column("registry_host", sa.String(length=200), nullable=False),
        sa.Column("artifact_name", sa.String(length=300), nullable=False),
        sa.Column("version", sa.String(length=200), nullable=True),
        sa.Column("digest", sa.String(length=71), nullable=True),
        sa.Column("public_visibility", sa.String(length=30), nullable=False),
        sa.Column("visibility_verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("visibility_source_url", sa.Text(), nullable=False),
        sa.Column("directness", sa.String(length=20), nullable=False),
        sa.Column("inventory_revision", sa.String(length=160), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_confirmed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_incident_revision", sa.Integer(), nullable=False),
        sa.Column("delivery_state", sa.String(length=20), nullable=False),
        sa.CheckConstraint(
            "tenant_id ~ '^synthetic[_-][A-Za-z0-9_-]{6,150}$'",
            name=op.f("ck_current_entries_tenant_id"),
        ),
        sa.CheckConstraint(
            "project_alias ~ '^synthetic[._-][A-Za-z0-9._-]{1,89}$'",
            name=op.f("ck_current_entries_project_alias"),
        ),
        sa.CheckConstraint(
            "artifact_key ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_current_entries_artifact_key"),
        ),
        sa.CheckConstraint(
            "ecosystem IN ('npm', 'pypi', 'github-actions', 'oci', 'docker')",
            name=op.f("ck_current_entries_ecosystem"),
        ),
        sa.CheckConstraint(
            "registry_host IN ("
            "'registry.npmjs.org', 'pypi.org', 'github.com', 'docker.io', "
            "'ghcr.io', 'public.ecr.aws', 'quay.io'"
            ")",
            name=op.f("ck_current_entries_registry_host"),
        ),
        sa.CheckConstraint(
            "public_visibility = 'verified_public'",
            name=op.f("ck_current_entries_public_visibility"),
        ),
        sa.CheckConstraint(
            "directness IN ('direct', 'transitive')",
            name=op.f("ck_current_entries_directness"),
        ),
        sa.CheckConstraint(
            "(ecosystem IN ('oci', 'docker') AND version IS NULL "
            "AND digest ~ '^sha256:[a-f0-9]{64}$') "
            "OR (ecosystem NOT IN ('oci', 'docker') AND version IS NOT NULL "
            "AND digest IS NULL)",
            name=op.f("ck_current_entries_exact_identity"),
        ),
        sa.CheckConstraint(
            "first_seen_at <= last_confirmed_at",
            name=op.f("ck_current_entries_seen_order"),
        ),
        sa.CheckConstraint(
            "visibility_verified_at <= last_confirmed_at",
            name=op.f("ck_current_entries_visibility_order"),
        ),
        sa.CheckConstraint(
            "last_incident_revision >= 0",
            name=op.f("ck_current_entries_incident_revision"),
        ),
        sa.CheckConstraint(
            "delivery_state IN ('none', 'pending', 'delivered', 'corrected')",
            name=op.f("ck_current_entries_delivery_state"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            [f"{SCHEMA}.tenants.tenant_id"],
            name=op.f("fk_current_entries_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "project_alias",
            "artifact_key",
            name=op.f("pk_current_entries"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_hw_current_tenant_confirmed",
        "current_entries",
        ["tenant_id", "last_confirmed_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_table(
        "encrypted_contacts",
        *_encrypted_columns("contact_id"),
        *_encrypted_constraints("encrypted_contacts", "contact_id"),
        schema=SCHEMA,
    )
    op.create_table(
        "encrypted_destinations",
        *_encrypted_columns("destination_id"),
        sa.Column("adapter", sa.String(length=30), nullable=False),
        *_encrypted_constraints("encrypted_destinations", "destination_id"),
        sa.CheckConstraint(
            "adapter IN ('agentmail', 'webhook', 'slack', 'teams', 'github', 'agent_polling')",
            name=op.f("ck_encrypted_destinations_adapter"),
        ),
        schema=SCHEMA,
    )
    op.create_table(
        "admin_audit",
        sa.Column("audit_event_id", sa.String(length=160), nullable=False),
        sa.Column("tenant_ref_hash", sa.String(length=71), nullable=False),
        sa.Column("actor_ref_hash", sa.String(length=71), nullable=False),
        sa.Column("operation", sa.String(length=30), nullable=False),
        sa.Column("reason_code", sa.String(length=120), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("result_class", sa.String(length=20), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "audit_event_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_admin_audit_audit_event_id"),
        ),
        sa.CheckConstraint(
            "tenant_ref_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_admin_audit_tenant_ref_hash"),
        ),
        sa.CheckConstraint(
            "actor_ref_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_admin_audit_actor_ref_hash"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_admin_audit_record_hash"),
        ),
        sa.CheckConstraint(
            "operation IN ("
            "'replace_current', 'export_current', 'store_contact', "
            "'store_destination', 'expire_stale', 'hard_delete'"
            ")",
            name=op.f("ck_admin_audit_operation"),
        ),
        sa.CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name=op.f("ck_admin_audit_reason_code"),
        ),
        sa.CheckConstraint("row_count >= 0", name=op.f("ck_admin_audit_row_count")),
        sa.CheckConstraint("byte_count >= 0", name=op.f("ck_admin_audit_byte_count")),
        sa.CheckConstraint(
            "result_class IN ('accepted', 'idempotent', 'expired', 'deleted')",
            name=op.f("ck_admin_audit_result_class"),
        ),
        sa.PrimaryKeyConstraint("audit_event_id", name=op.f("pk_admin_audit")),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_hw_admin_audit_tenant_time",
        "admin_audit",
        ["tenant_ref_hash", "occurred_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_table(
        "deletion_receipts",
        sa.Column("receipt_id", sa.String(length=160), nullable=False),
        sa.Column("tenant_ref_hash", sa.String(length=71), nullable=False),
        sa.Column("deletion_state", sa.String(length=30), nullable=False),
        sa.Column("primary_deleted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("backup_expires_by", sa.DateTime(timezone=True), nullable=False),
        sa.Column("current_rows", sa.Integer(), nullable=False),
        sa.Column("contact_rows", sa.Integer(), nullable=False),
        sa.Column("destination_rows", sa.Integer(), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "receipt_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_deletion_receipts_receipt_id"),
        ),
        sa.CheckConstraint(
            "tenant_ref_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_deletion_receipts_tenant_ref_hash"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_deletion_receipts_record_hash"),
        ),
        sa.CheckConstraint(
            "deletion_state = 'primary_deleted'",
            name=op.f("ck_deletion_receipts_deletion_state"),
        ),
        sa.CheckConstraint(
            "backup_expires_by > primary_deleted_at",
            name=op.f("ck_deletion_receipts_backup_expiry"),
        ),
        sa.CheckConstraint(
            "current_rows >= 0",
            name=op.f("ck_deletion_receipts_current_rows"),
        ),
        sa.CheckConstraint(
            "contact_rows >= 0",
            name=op.f("ck_deletion_receipts_contact_rows"),
        ),
        sa.CheckConstraint(
            "destination_rows >= 0",
            name=op.f("ck_deletion_receipts_destination_rows"),
        ),
        sa.PrimaryKeyConstraint("receipt_id", name=op.f("pk_deletion_receipts")),
        schema=SCHEMA,
    )
    _protect("admin_audit")
    _protect("deletion_receipts")


def downgrade() -> None:
    """Remove the unused synthetic boundary from an ephemeral database."""
    op.drop_table("deletion_receipts", schema=SCHEMA)
    op.drop_index(
        "ix_hw_admin_audit_tenant_time",
        table_name="admin_audit",
        schema=SCHEMA,
    )
    op.drop_table("admin_audit", schema=SCHEMA)
    op.drop_table("encrypted_destinations", schema=SCHEMA)
    op.drop_table("encrypted_contacts", schema=SCHEMA)
    op.drop_index(
        "ix_hw_current_tenant_confirmed",
        table_name="current_entries",
        schema=SCHEMA,
    )
    op.drop_table("current_entries", schema=SCHEMA)
    op.drop_table("tenants", schema=SCHEMA)
    op.execute(f"DROP SCHEMA IF EXISTS {SCHEMA}")
