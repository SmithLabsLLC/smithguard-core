"""create CP-BETA1 preliminary warning archive

Revision ID: 0007_cpbeta1
Revises: 0006_cphw
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_cpbeta1"
down_revision: str | None = "0006_cphw"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = (
    "Create append-only collection progress, source linkage, and warning archives"
)
rollback_mode: str = "forward_only"

SCHEMA = "goodboy_security"


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
    """Create collection progress, source linkage, and warning history."""
    op.drop_constraint(
        op.f("ck_snapshot_manifests_schema_version"),
        "snapshot_manifests",
        schema=SCHEMA,
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_snapshot_manifests_schema_version"),
        "snapshot_manifests",
        "schema_version IN ('1.0.0', '1.1.0', '1.2.0')",
        schema=SCHEMA,
    )
    op.create_table(
        "collector_progress",
        sa.Column("progress_event_id", sa.String(length=160), nullable=False),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("lane", sa.String(length=20), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("cursor_value", sa.String(length=500), nullable=True),
        sa.Column("cursor_parameter", sa.String(length=10), nullable=True),
        sa.Column("page_count", sa.Integer(), nullable=False),
        sa.Column("source_record_count", sa.BigInteger(), nullable=False),
        sa.Column("normalized_record_count", sa.BigInteger(), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("oldest_published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("newest_published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason_code", sa.String(length=120), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "progress_event_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_collector_progress_progress_event_id"),
        ),
        sa.CheckConstraint(
            "source_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_collector_progress_source_id"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_collector_progress_record_hash"),
        ),
        sa.CheckConstraint(
            "lane IN ('historical', 'updates')",
            name=op.f("ck_collector_progress_lane"),
        ),
        sa.CheckConstraint(
            "state IN ('in_progress', 'complete', 'failed')",
            name=op.f("ck_collector_progress_state"),
        ),
        sa.CheckConstraint(
            "sequence >= 1",
            name=op.f("ck_collector_progress_sequence"),
        ),
        sa.CheckConstraint(
            "page_count >= 0",
            name=op.f("ck_collector_progress_page_count"),
        ),
        sa.CheckConstraint(
            "source_record_count >= 0",
            name=op.f("ck_collector_progress_source_record_count"),
        ),
        sa.CheckConstraint(
            "normalized_record_count >= 0",
            name=op.f("ck_collector_progress_normalized_record_count"),
        ),
        sa.CheckConstraint(
            "cursor_value IS NULL OR cursor_value ~ '^[A-Za-z0-9._~+=%/-]+$'",
            name=op.f("ck_collector_progress_cursor_value"),
        ),
        sa.CheckConstraint(
            "(cursor_value IS NULL AND cursor_parameter IS NULL) OR "
            "(cursor_value IS NOT NULL "
            "AND cursor_parameter IN ('before', 'after'))",
            name=op.f("ck_collector_progress_cursor_pair"),
        ),
        sa.CheckConstraint(
            "window_started_at IS NULL OR window_ended_at IS NOT NULL",
            name=op.f("ck_collector_progress_window_pair"),
        ),
        sa.CheckConstraint(
            "window_started_at IS NULL OR window_ended_at >= window_started_at",
            name=op.f("ck_collector_progress_window_order"),
        ),
        sa.CheckConstraint(
            "oldest_published_at IS NULL OR newest_published_at IS NOT NULL",
            name=op.f("ck_collector_progress_published_pair"),
        ),
        sa.CheckConstraint(
            "oldest_published_at IS NULL OR newest_published_at >= oldest_published_at",
            name=op.f("ck_collector_progress_published_order"),
        ),
        sa.CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name=op.f("ck_collector_progress_reason_code"),
        ),
        sa.PrimaryKeyConstraint(
            "progress_event_id",
            name=op.f("pk_collector_progress"),
        ),
        sa.UniqueConstraint(
            "source_id",
            "lane",
            "sequence",
            name=op.f("uq_collector_progress_source_id_lane_sequence"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_collector_progress_state_occurred",
        "collector_progress",
        ["state", "occurred_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_table(
        "source_incident_links",
        sa.Column("link_event_id", sa.String(length=160), nullable=False),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("upstream_record_id", sa.String(length=160), nullable=False),
        sa.Column("artifact_id", sa.String(length=160), nullable=False),
        sa.Column("incident_id", sa.String(length=160), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_id", sa.String(length=160), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "link_event_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_source_incident_links_link_event_id"),
        ),
        sa.CheckConstraint(
            "source_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_source_incident_links_source_id"),
        ),
        sa.CheckConstraint(
            "artifact_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_source_incident_links_artifact_id"),
        ),
        sa.CheckConstraint(
            "incident_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_source_incident_links_incident_id"),
        ),
        sa.CheckConstraint(
            "evidence_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_source_incident_links_evidence_id"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_source_incident_links_record_hash"),
        ),
        sa.CheckConstraint(
            "sequence >= 1",
            name=op.f("ck_source_incident_links_sequence"),
        ),
        sa.CheckConstraint(
            "state IN ('active', 'removed', 'withdrawn')",
            name=op.f("ck_source_incident_links_state"),
        ),
        sa.CheckConstraint(
            "upstream_record_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,159}$'",
            name=op.f("ck_source_incident_links_upstream_record_id"),
        ),
        sa.PrimaryKeyConstraint(
            "link_event_id",
            name=op.f("pk_source_incident_links"),
        ),
        sa.UniqueConstraint(
            "source_id",
            "upstream_record_id",
            "artifact_id",
            "sequence",
            name=op.f("uq_source_incident_link_identity_sequence"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_source_incident_links_source_record",
        "source_incident_links",
        ["source_id", "upstream_record_id", "source_updated_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_source_incident_links_incident",
        "source_incident_links",
        ["incident_id", "observed_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_table(
        "preliminary_warnings",
        sa.Column("id", sa.String(length=160), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(length=20), nullable=False),
        sa.Column("kind", sa.String(length=80), nullable=False),
        sa.Column("data_classification", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("state", sa.String(length=30), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recheck_count", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_preliminary_warnings_stable_id"),
        ),
        sa.CheckConstraint(
            "revision >= 1",
            name=op.f("ck_preliminary_warnings_positive_revision"),
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name=op.f("ck_preliminary_warnings_schema_version"),
        ),
        sa.CheckConstraint(
            "kind = 'preliminary_warning'",
            name=op.f("ck_preliminary_warnings_record_kind"),
        ),
        sa.CheckConstraint(
            "data_classification IN ("
            "'public', 'restricted_source', 'customer_local', "
            "'hosted_watch_minimized', 'internal_control'"
            ")",
            name=op.f("ck_preliminary_warnings_data_classification"),
        ),
        sa.CheckConstraint(
            "data_classification = 'public'",
            name=op.f("ck_preliminary_warnings_warning_classification"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_preliminary_warnings_record_hash"),
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name=op.f("ck_preliminary_warnings_timestamp_order"),
        ),
        sa.CheckConstraint(
            "state IN ('active', 'expired', 'withdrawn', 'promoted', 'contradicted')",
            name=op.f("ck_preliminary_warnings_state"),
        ),
        sa.CheckConstraint(
            "expires_at > observed_at",
            name=op.f("ck_preliminary_warnings_expiry_order"),
        ),
        sa.CheckConstraint(
            "last_checked_at >= observed_at",
            name=op.f("ck_preliminary_warnings_check_order"),
        ),
        sa.CheckConstraint(
            "recheck_count BETWEEN 0 AND 12",
            name=op.f("ck_preliminary_warnings_recheck_count"),
        ),
        sa.PrimaryKeyConstraint(
            "id",
            "revision",
            name=op.f("pk_preliminary_warnings"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_preliminary_warnings_state_expiry",
        "preliminary_warnings",
        ["state", "expires_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_preliminary_warnings_updated_id",
        "preliminary_warnings",
        ["updated_at", "id"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_table(
        "preliminary_warning_rechecks",
        sa.Column("recheck_id", sa.String(length=160), nullable=False),
        sa.Column("warning_id", sa.String(length=160), nullable=False),
        sa.Column("warning_revision", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=40), nullable=False),
        sa.Column("exact_cost_usd_ticks", sa.BigInteger(), nullable=False),
        sa.Column("provider_response_id_hash", sa.String(length=71), nullable=True),
        sa.Column("server_side_tool_calls", sa.Integer(), nullable=False),
        sa.Column("reservation_id", sa.String(length=160), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "recheck_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_preliminary_warning_rechecks_recheck_id"),
        ),
        sa.CheckConstraint(
            "warning_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_preliminary_warning_rechecks_warning_id"),
        ),
        sa.CheckConstraint(
            "reservation_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_preliminary_warning_rechecks_reservation_id"),
        ),
        sa.CheckConstraint(
            "provider_response_id_hash IS NULL "
            "OR provider_response_id_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_preliminary_warning_rechecks_provider_response_id_hash"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_preliminary_warning_rechecks_record_hash"),
        ),
        sa.CheckConstraint(
            "warning_revision >= 1",
            name=op.f("ck_preliminary_warning_rechecks_warning_revision"),
        ),
        sa.CheckConstraint(
            "sequence BETWEEN 1 AND 12",
            name=op.f("ck_preliminary_warning_rechecks_sequence"),
        ),
        sa.CheckConstraint(
            "outcome IN ("
            "'still_unverified', 'no_new_evidence', 'confirmation_candidate', "
            "'contradiction_candidate', 'budget_blocked', "
            "'provider_unavailable', 'expired'"
            ")",
            name=op.f("ck_preliminary_warning_rechecks_outcome"),
        ),
        sa.CheckConstraint(
            "exact_cost_usd_ticks >= 0 AND exact_cost_usd_ticks <= 750000000000",
            name=op.f("ck_preliminary_warning_rechecks_exact_cost_usd_ticks"),
        ),
        sa.CheckConstraint(
            "server_side_tool_calls BETWEEN 0 AND 64",
            name=op.f("ck_preliminary_warning_rechecks_server_side_tool_calls"),
        ),
        sa.PrimaryKeyConstraint(
            "recheck_id",
            name=op.f("pk_preliminary_warning_rechecks"),
        ),
        sa.UniqueConstraint(
            "warning_id",
            "sequence",
            name=op.f("uq_preliminary_warning_rechecks_warning_id_sequence"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_preliminary_warning_rechecks_warning_checked",
        "preliminary_warning_rechecks",
        ["warning_id", "checked_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_table(
        "preliminary_warning_approvals",
        sa.Column("approval_id", sa.String(length=160), nullable=False),
        sa.Column("warning_id", sa.String(length=160), nullable=False),
        sa.Column("warning_revision", sa.Integer(), nullable=False),
        sa.Column("reviewer_id", sa.String(length=160), nullable=False),
        sa.Column("independent_source_clusters", sa.Integer(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "approval_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_preliminary_warning_approvals_approval_id"),
        ),
        sa.CheckConstraint(
            "warning_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'",
            name=op.f("ck_preliminary_warning_approvals_warning_id"),
        ),
        sa.CheckConstraint(
            "record_hash ~ '^sha256:[a-f0-9]{64}$'",
            name=op.f("ck_preliminary_warning_approvals_record_hash"),
        ),
        sa.CheckConstraint(
            "warning_revision = 1",
            name=op.f("ck_preliminary_warning_approvals_initial_revision_only"),
        ),
        sa.CheckConstraint(
            "reviewer_id ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{2,159}$'",
            name=op.f("ck_preliminary_warning_approvals_reviewer_id"),
        ),
        sa.CheckConstraint(
            "independent_source_clusters BETWEEN 2 AND 20",
            name=op.f("ck_preliminary_warning_approvals_independent_source_clusters"),
        ),
        sa.PrimaryKeyConstraint(
            "approval_id",
            name=op.f("pk_preliminary_warning_approvals"),
        ),
        sa.UniqueConstraint(
            "warning_id",
            "warning_revision",
            name=op.f("uq_preliminary_warning_approvals_warning_id_warning_revision"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_preliminary_warning_approvals_reviewed",
        "preliminary_warning_approvals",
        ["reviewed_at"],
        unique=False,
        schema=SCHEMA,
    )
    _protect("collector_progress")
    _protect("source_incident_links")
    _protect("preliminary_warnings")
    _protect("preliminary_warning_rechecks")
    _protect("preliminary_warning_approvals")


def downgrade() -> None:
    """Refuse to erase the permanent warning investigation archive."""
    raise RuntimeError(
        "0007_cpbeta1 is forward-only because warning and recheck history is permanent"
    )
