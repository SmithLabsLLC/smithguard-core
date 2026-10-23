"""rename the live runtime schemas for SmithGuard

Revision ID: 0019_smithguard_rebrand
Revises: 0018_grok_audit_warning_origins
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0019_smithguard_rebrand"
down_revision: str | None = "0018_grok_audit_warning_origins"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Rename the live GoodBoy Watch schemas for SmithGuard"
rollback_mode: str = "forward_only"

OLD_MAIN_SCHEMA = "goodboy_watch"
NEW_MAIN_SCHEMA = "smithguard"
OLD_PRIVATE_SCHEMA = "goodboy_private_watchlists"
NEW_PRIVATE_SCHEMA = "smithguard_private_watchlists"


def _assert_exact_schema_boundary() -> None:
    connection = op.get_bind()
    rows = connection.execute(
        text(
            """
            SELECT nspname
            FROM pg_catalog.pg_namespace
            WHERE nspname IN (
                :old_main,
                :new_main,
                :old_private,
                :new_private
            )
            ORDER BY nspname
            """
        ),
        {
            "old_main": OLD_MAIN_SCHEMA,
            "new_main": NEW_MAIN_SCHEMA,
            "old_private": OLD_PRIVATE_SCHEMA,
            "new_private": NEW_PRIVATE_SCHEMA,
        },
    ).scalars()
    if set(rows) != {OLD_MAIN_SCHEMA, OLD_PRIVATE_SCHEMA}:
        raise RuntimeError("SmithGuard schema rename preflight found a mixed or incomplete state")


def upgrade() -> None:
    """Rename mutable live schemas without rewriting historical records."""
    op.execute("SET LOCAL lock_timeout = '5s'")
    _assert_exact_schema_boundary()
    op.execute("ALTER SCHEMA goodboy_watch RENAME TO smithguard")
    op.execute("ALTER SCHEMA goodboy_private_watchlists RENAME TO smithguard_private_watchlists")


def downgrade() -> None:
    """Refuse to blur the clean SmithGuard evidence boundary."""
    raise RuntimeError(
        "0019_smithguard_rebrand is forward-only so rollback requires the verified "
        "pre-migration backup"
    )
