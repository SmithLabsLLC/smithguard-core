"""accept the owner-authorized model review basis in private shadow samples

Revision ID: 0016_next004_owner_basis
Revises: 0015_next004_shadow
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0016_next004_owner_basis"
down_revision: str | None = "0015_next004_shadow"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Accept owner-authorized model review in private shadow samples"
rollback_mode: str = "forward_only"

SCHEMA = "goodboy_watch"
TABLE = "correlation_shadow_samples"
CONSTRAINT = "ck_correlation_shadow_samples_review_basis"


def upgrade() -> None:
    """Add one truthful review basis without changing stored shadow rows."""
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.drop_constraint(op.f(CONSTRAINT), TABLE, schema=SCHEMA, type_="check")
    op.create_check_constraint(
        op.f(CONSTRAINT),
        TABLE,
        "review_basis IN ('synthetic_fixture', 'exact_source_identity', 'human_review', "
        "'owner_authorized_model_review')",
        schema=SCHEMA,
    )


def downgrade() -> None:
    """Refuse to invalidate truthful owner-authorized review history."""
    raise RuntimeError(
        "0016_next004_owner_basis is forward-only so rollback requires the verified "
        "pre-migration backup"
    )
