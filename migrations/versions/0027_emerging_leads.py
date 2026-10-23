"""Preserve early software-security lead revisions independently of exact artifacts."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0027_emerging_leads"
down_revision: str | None = "0026_retire_spend_ledger"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Add append-only emerging lead lifecycle and bounded public projection"
rollback_mode: str = "forward_only"


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.create_table(
        "emerging_leads",
        sa.Column("lead_id", sa.String(64), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("reason", sa.String(80), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fingerprint", sa.String(71), nullable=False),
        sa.Column("public_eligible", sa.Boolean(), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("record_hash", sa.String(71), nullable=False),
        sa.PrimaryKeyConstraint("lead_id", "revision"),
        sa.CheckConstraint("lead_id ~ '^[a-f0-9]{64}$'", name="lead_id"),
        sa.CheckConstraint("revision >= 1", name="revision"),
        sa.CheckConstraint(
            "state IN ('unverified','needs_enrichment','rejected','withdrawn','expired')",
            name="state",
        ),
        sa.CheckConstraint(
            "expires_at > first_seen_at AND observed_at >= first_seen_at", name="times"
        ),
        sa.CheckConstraint("octet_length(document::text) <= 32768", name="document_size"),
        sa.CheckConstraint("record_hash ~ '^sha256:[a-f0-9]{64}$'", name="hash"),
        schema="smithguard",
    )
    op.create_index(
        "ix_emerging_leads_observed",
        "emerging_leads",
        ["observed_at", "lead_id"],
        schema="smithguard",
    )
    op.create_index(
        "ix_emerging_leads_fingerprint", "emerging_leads", ["fingerprint"], schema="smithguard"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_mutation BEFORE UPDATE OR DELETE ON smithguard.emerging_leads FOR EACH ROW EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_truncate BEFORE TRUNCATE ON smithguard.emerging_leads FOR EACH STATEMENT EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )


def downgrade() -> None:
    raise RuntimeError("0027_emerging_leads is forward-only")
