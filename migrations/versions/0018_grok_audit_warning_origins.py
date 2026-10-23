"""allow one-origin emerging warning qualification

Revision ID: 0018_grok_audit_warning_origins
Revises: 0017_next004_provenance
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0018_grok_audit_warning_origins"
down_revision: str | None = "0017_next004_provenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = (
    "Allow one-origin Emerging/Unverified warning qualification and schema 1.1"
)
rollback_mode: str = "forward_only"

SCHEMA = "goodboy_watch"
TABLE = "preliminary_warning_approvals"
CONSTRAINT = "ck_preliminary_warning_approvals_independent_source_clusters"
WARNING_TABLE = "preliminary_warnings"
WARNING_SCHEMA_CONSTRAINT = "ck_preliminary_warnings_schema_version"


def upgrade() -> None:
    """Permit the audited single-origin preliminary-warning boundary."""
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.drop_constraint(op.f(CONSTRAINT), TABLE, schema=SCHEMA, type_="check")
    op.create_check_constraint(
        op.f(CONSTRAINT),
        TABLE,
        "independent_source_clusters BETWEEN 1 AND 20",
        schema=SCHEMA,
    )
    op.drop_constraint(
        op.f(WARNING_SCHEMA_CONSTRAINT),
        WARNING_TABLE,
        schema=SCHEMA,
        type_="check",
    )
    op.create_check_constraint(
        op.f(WARNING_SCHEMA_CONSTRAINT),
        WARNING_TABLE,
        "schema_version IN ('1.0.0', '1.1.0')",
        schema=SCHEMA,
    )


def downgrade() -> None:
    """Refuse to discard warning qualification history."""
    raise RuntimeError(
        "0018_grok_audit_warning_origins is forward-only so rollback requires the "
        "verified pre-migration backup"
    )
