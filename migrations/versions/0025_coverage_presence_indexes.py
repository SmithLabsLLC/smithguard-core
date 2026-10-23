"""Index coverage presence and retained source membership without rewriting evidence.

Revision ID: 0025_coverage_presence_indexes
Revises: 0024_nuget_lookup_indexes
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025_coverage_presence_indexes"
down_revision: str | None = "0024_nuget_lookup_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Index coverage presence and retained source ecosystem membership"
rollback_mode: str = "forward_only"


def upgrade() -> None:
    """Support bounded existence lookups through the approved quiesced migration."""
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.create_index(
        "ix_advisory_package_ecosystem_source",
        "advisory_package_records",
        ["ecosystem", "source_id"],
        unique=False,
        schema="smithguard",
    )
    op.create_index(
        "ix_advisory_package_active_ecosystem",
        "advisory_package_records",
        ["ecosystem"],
        unique=False,
        schema="smithguard",
        postgresql_where=sa.text("state = 'active'"),
    )


def downgrade() -> None:
    """Preserve the forward migration journal and retained evidence."""
    raise RuntimeError("0025_coverage_presence_indexes is forward-only")
