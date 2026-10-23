"""index public incident artifact correlation

Revision ID: 0012_mx014
Revises: 0011_mx006
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0012_mx014"
down_revision: str | None = "0011_mx006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Index bounded public incident artifact correlation"
rollback_mode: str = "forward_only"

SCHEMA = "goodboy_security"


def upgrade() -> None:
    """Add the measured JSONB membership index used by public artifact assessment."""
    op.create_index(
        "ix_incidents_artifact_ids",
        "incidents",
        ["artifact_ids"],
        unique=False,
        schema=SCHEMA,
        postgresql_using="gin",
    )


def downgrade() -> None:
    """Refuse a partial downgrade across later forward-only releases."""
    raise RuntimeError(
        "0012_mx014 is forward-only so a failed downgrade cannot partially change head"
    )
