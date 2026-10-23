"""Bounded private detail diagnostics and read-only hourly liveness evidence."""

from alembic import op

revision: str = "0037_bulletin_intake_health"
down_revision: str | None = "0036_bulletin_source_updates"
branch_labels = None
depends_on = None
migration_description: str = "Add bounded detail-failure diagnostics and intake health access"
rollback_mode: str = "forward_only"


def upgrade():
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute(
        "ALTER TABLE smithguard.official_notice_pending "
        "ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0, "
        "ADD COLUMN failure_category VARCHAR(24), "
        "ADD COLUMN first_failure_at TIMESTAMP WITH TIME ZONE, "
        "ADD COLUMN last_failure_at TIMESTAMP WITH TIME ZONE, "
        "ADD CONSTRAINT ck_official_notice_pending_failures "
        "CHECK (failure_count BETWEEN 0 AND 65535), "
        "ADD CONSTRAINT ck_official_notice_pending_failure_category "
        "CHECK (failure_category IN ('rights','timeout','transport','http_status',"
        "'source_dates','source_identity','source_shape','budget','storage','unknown'))"
    )
    # These receipts contain bounded run bindings/counts, never publisher prose.
    op.execute("""
        DO $grants$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-health') THEN
            GRANT SELECT ON smithguard.official_intake_runs TO "smithguard-health";
        END IF;
        END $grants$
    """)


def downgrade():
    raise RuntimeError("0037_bulletin_intake_health is forward-only")
