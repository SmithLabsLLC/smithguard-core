"""Add compatible NuGet lookup indexes without rewriting retained package identities.

Revision ID: 0024_nuget_lookup_indexes
Revises: 0023_warning_receipt_indexes
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024_nuget_lookup_indexes"
down_revision: str | None = "0023_warning_receipt_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Index compatible NuGet package lookup preserving retained identities"
rollback_mode: str = "forward_only"


def upgrade() -> None:
    """Derive the same ASCII-only lookup key for retained rows and future ingestion."""
    op.execute("SET LOCAL lock_timeout = '5s'")
    for table, index, tail in (
        ("advisory_package_records", "ix_advisory_package_nuget_lookup", "catalog_event_id"),
        ("artifacts", "ix_artifacts_nuget_lookup", "id"),
    ):
        op.create_index(
            index,
            table,
            [
                sa.text(
                    "translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"
                ),
                tail,
            ],
            unique=False,
            schema="smithguard",
            postgresql_where=sa.text("ecosystem = 'nuget'"),
        )


def downgrade() -> None:
    """Preserve the forward migration journal and retained evidence."""
    raise RuntimeError("0024_nuget_lookup_indexes is forward-only")
