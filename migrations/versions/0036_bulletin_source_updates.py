"""Distinguish public source metadata updates from changed reported facts."""

from alembic import op

revision: str = "0036_bulletin_source_updates"
down_revision: str | None = "0035_bulletin_automation"
branch_labels = None
depends_on = None
migration_description: str = "Allow source update events without rewriting historical evidence"
rollback_mode: str = "forward_only"


def upgrade():
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute(
        "ALTER TABLE smithguard.bulletin_events DROP CONSTRAINT ck_bulletin_events_kind, "
        "ADD CONSTRAINT ck_bulletin_events_kind CHECK (kind IN "
        "('published','corrected','source_updated','disputed','withdrawn','expired',"
        "'freshness_stale','freshness_verified','public_tombstoned',"
        "'public_purge_requested','public_purged','public_purge_failed','associated'))"
    )


def downgrade():
    raise RuntimeError("0036_bulletin_source_updates is forward-only")
