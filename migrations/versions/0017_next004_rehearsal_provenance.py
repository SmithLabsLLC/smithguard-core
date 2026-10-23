"""bind private public-fixture rehearsals to finalized review provenance

Revision ID: 0017_next004_provenance
Revises: 0016_next004_owner_basis
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_next004_provenance"
down_revision: str | None = "0016_next004_owner_basis"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Bind private public-fixture rehearsals to finalized review provenance"
rollback_mode: str = "forward_only"

SCHEMA = "goodboy_watch"
TABLE = "correlation_shadow_runs"
SHA256 = r"^sha256:[a-f0-9]{64}$"
OWNER_AUTHORIZATION = r"^[A-Z0-9][A-Z0-9._:-]{2,159}$"


def upgrade() -> None:
    """Add immutable finalized-input and owner-authorization provenance."""
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.add_column(
        TABLE,
        sa.Column("finalized_input_sha256", sa.String(length=71), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        TABLE,
        sa.Column("owner_authorization_id", sa.String(length=160), nullable=True),
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_correlation_shadow_runs_finalized_input_sha256"),
        TABLE,
        f"finalized_input_sha256 IS NULL OR finalized_input_sha256 ~ '{SHA256}'",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_correlation_shadow_runs_owner_authorization_id"),
        TABLE,
        f"owner_authorization_id IS NULL OR owner_authorization_id ~ '{OWNER_AUTHORIZATION}'",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_correlation_shadow_runs_provenance_shape"),
        TABLE,
        "(mode = 'synthetic_fixture' AND finalized_input_sha256 IS NULL "
        "AND owner_authorization_id IS NULL) OR "
        "(mode = 'public_fixture' AND finalized_input_sha256 IS NOT NULL)",
        schema=SCHEMA,
    )


def downgrade() -> None:
    """Refuse to discard immutable rehearsal provenance."""
    raise RuntimeError(
        "0017_next004_provenance is forward-only so rollback requires the verified "
        "pre-migration backup"
    )
