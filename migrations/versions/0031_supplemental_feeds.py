"""Add immutable exact-CVE context and direct Rust/Go source snapshots."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0031_supplemental_feeds"
down_revision: str | None = "0030_drop_unused_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Add immutable exact-CVE context and direct Rust/Go source snapshots"
rollback_mode: str = "forward_only"


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.drop_constraint(
        op.f("ck_advisory_catalog_records_source_type"),
        "advisory_catalog_records",
        schema="smithguard",
        type_="check",
    )
    op.create_check_constraint(
        "source_type",
        "advisory_catalog_records",
        "source_type IN ('malware','reviewed','unreviewed','openssf','rustsec','go')",
        schema="smithguard",
    )
    op.create_table(
        "supplemental_snapshots",
        sa.Column("snapshot_id", sa.String(160), nullable=False),
        sa.Column("source_id", sa.String(160), nullable=False),
        sa.Column("mode", sa.String(20), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_as_of", sa.DateTime(timezone=True)),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("record_hash", sa.String(71), nullable=False),
        sa.PrimaryKeyConstraint("snapshot_id"),
        sa.UniqueConstraint("source_id", "mode", "sequence"),
        sa.CheckConstraint("snapshot_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'", name="snapshot_id"),
        sa.CheckConstraint("source_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'", name="source_id"),
        sa.CheckConstraint("mode IN ('shadow','public')", name="mode"),
        sa.CheckConstraint("state IN ('complete','failed')", name="state"),
        sa.CheckConstraint("sequence >= 1 AND record_count >= 0", name="counts"),
        sa.CheckConstraint("record_hash ~ '^sha256:[a-f0-9]{64}$'", name="record_hash"),
        sa.CheckConstraint("jsonb_typeof(document) = 'object'", name="document"),
        schema="smithguard",
    )
    op.create_table(
        "supplemental_facts",
        sa.Column("snapshot_id", sa.String(160), nullable=False),
        sa.Column("subject_id", sa.String(160), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("record_hash", sa.String(71), nullable=False),
        sa.PrimaryKeyConstraint("snapshot_id", "subject_id"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["smithguard.supplemental_snapshots.snapshot_id"]),
        sa.CheckConstraint("char_length(subject_id) BETWEEN 1 AND 160", name="subject_id"),
        sa.CheckConstraint("jsonb_typeof(document) = 'object'", name="document"),
        sa.CheckConstraint("record_hash ~ '^sha256:[a-f0-9]{64}$'", name="record_hash"),
        schema="smithguard",
    )
    for table in ("supplemental_snapshots", "supplemental_facts"):
        op.execute(
            f"CREATE TRIGGER reject_ledger_mutation BEFORE UPDATE OR DELETE ON "
            f"smithguard.{table} FOR EACH ROW "
            "EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
        )
        op.execute(
            f"CREATE TRIGGER reject_ledger_truncate BEFORE TRUNCATE ON "
            f"smithguard.{table} FOR EACH STATEMENT "
            "EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
        )
    op.execute("""
        DO $grants$ BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-collector') THEN
                GRANT SELECT, INSERT ON smithguard.supplemental_snapshots, smithguard.supplemental_facts TO "smithguard-collector";
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-api') THEN
                GRANT SELECT ON smithguard.supplemental_snapshots, smithguard.supplemental_facts TO "smithguard-api";
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-health') THEN
                GRANT SELECT ON smithguard.supplemental_snapshots TO "smithguard-health";
            END IF;
        END $grants$;
    """)


def downgrade() -> None:
    raise RuntimeError("0031_supplemental_feeds is forward-only")
