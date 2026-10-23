"""allow the CP-2B signed public-knowledge snapshot version

Revision ID: 0004_cp2b
Revises: 0003_cp1
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004_cp2b"
down_revision: str | None = "0003_cp1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Allow the CP-2B signed public-knowledge snapshot version"
rollback_mode: str = "forward_only"


def upgrade() -> None:
    """Permit old CP-1 manifests and new CP-2B manifests side by side."""
    op.drop_constraint(
        op.f("ck_snapshot_manifests_schema_version"),
        "snapshot_manifests",
        schema="goodboy_security",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_snapshot_manifests_schema_version"),
        "snapshot_manifests",
        "schema_version IN ('1.0.0', '1.1.0')",
        schema="goodboy_security",
    )


def downgrade() -> None:
    """Restore the old constraint only when no CP-2B manifest exists."""
    op.drop_constraint(
        op.f("ck_snapshot_manifests_schema_version"),
        "snapshot_manifests",
        schema="goodboy_security",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_snapshot_manifests_schema_version"),
        "snapshot_manifests",
        "schema_version = '1.0.0'",
        schema="goodboy_security",
    )
