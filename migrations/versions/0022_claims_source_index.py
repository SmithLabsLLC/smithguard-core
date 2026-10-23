"""index claim provenance and allocate collector checkpoint sequences

Revision ID: 0022_claims_source_index
Revises: 0021_catalog_append_only
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022_claims_source_index"
down_revision: str | None = "0021_catalog_append_only"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Index claim provenance and serialize checkpoint identities"
rollback_mode: str = "forward_only"

SCHEMA = "smithguard"
CHECKPOINT_SEQUENCE = "collector_checkpoint_sequence"


def upgrade() -> None:
    """Add the coverage lookup index and a database-backed checkpoint sequence."""
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.create_index(
        "ix_claims_provenance_source_id",
        "claims",
        [sa.text("(provenance ->> 'source_id')")],
        unique=False,
        schema=SCHEMA,
    )
    op.execute(f"CREATE SEQUENCE {SCHEMA}.{CHECKPOINT_SEQUENCE}")
    op.execute(
        f"SELECT setval('{SCHEMA}.{CHECKPOINT_SEQUENCE}', "
        f"GREATEST(COALESCE((SELECT MAX(sequence) FROM {SCHEMA}.collector_checkpoints), 0), 1), "
        f"COALESCE((SELECT MAX(sequence) FROM {SCHEMA}.collector_checkpoints), 0) > 0)"
    )
    op.execute(
        f"""
        DO $grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'smithguard-collector')
            THEN
                GRANT USAGE, SELECT ON SEQUENCE {SCHEMA}.{CHECKPOINT_SEQUENCE}
                    TO "smithguard-collector";
            END IF;
        END
        $grant$
        """
    )


def downgrade() -> None:
    """Refuse to remove a production query index or consumed sequence values."""
    raise RuntimeError(
        "0022_claims_source_index is forward-only; a verified pre-migration "
        "backup may be restored only before this migration"
    )
