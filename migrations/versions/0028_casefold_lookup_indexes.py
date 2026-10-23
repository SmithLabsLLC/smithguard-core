"""Index case-insensitive package lookup for more registries without rewriting names.

Revision ID: 0028_casefold_lookup_indexes
Revises: 0027_emerging_leads
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028_casefold_lookup_indexes"
down_revision: str | None = "0027_emerging_leads"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = (
    "Index case-insensitive package lookup for extension, Composer and crate names"
)
rollback_mode: str = "forward_only"

ASCII_KEY = "translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"
RUST_KEY = "translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ-', 'abcdefghijklmnopqrstuvwxyz_')"


def upgrade() -> None:
    """Derive the same ASCII lookup keys the service queries; names stay as retained."""
    op.execute("SET LOCAL lock_timeout = '5s'")
    for table, prefix, tail in (
        ("advisory_package_records", "ix_advisory_package", "catalog_event_id"),
        ("artifacts", "ix_artifacts", "id"),
    ):
        op.create_index(
            f"{prefix}_casefold_lookup",
            table,
            [sa.text(ASCII_KEY), tail],
            unique=False,
            schema="smithguard",
            postgresql_where=sa.text("ecosystem IN ('vscode', 'open-vsx', 'composer')"),
        )
        op.create_index(
            f"{prefix}_rust_lookup",
            table,
            [sa.text(RUST_KEY), tail],
            unique=False,
            schema="smithguard",
            postgresql_where=sa.text("ecosystem = 'rust'"),
        )


def downgrade() -> None:
    """Preserve the forward migration journal and retained evidence."""
    raise RuntimeError("0028_casefold_lookup_indexes is forward-only")
