"""protect the complete advisory catalog and bind migration recovery evidence

Revision ID: 0021_catalog_append_only
Revises: 0020_full_advisory_catalog
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0021_catalog_append_only"
down_revision: str | None = "0020_full_advisory_catalog"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Protect complete advisory catalog history and migration evidence"
rollback_mode: str = "forward_only"

SCHEMA = "smithguard"
CATALOG_TABLES = (
    "advisory_catalog_records",
    "advisory_package_records",
    "advisory_catalog_inventory",
    "advisory_catalog_manifests",
)
DUPLICATE_INDEXES = (
    ("ix_advisory_catalog_source_record_revision", "advisory_catalog_records"),
    ("ix_advisory_catalog_inventory_snapshot", "advisory_catalog_inventory"),
    ("ix_advisory_catalog_manifest_source_segment", "advisory_catalog_manifests"),
)


def _protect(table_name: str) -> None:
    op.execute(
        f"""
        CREATE TRIGGER reject_ledger_mutation
        BEFORE UPDATE OR DELETE ON {SCHEMA}.{table_name}
        FOR EACH ROW
        EXECUTE FUNCTION {SCHEMA}.reject_ledger_mutation()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER reject_ledger_truncate
        BEFORE TRUNCATE ON {SCHEMA}.{table_name}
        FOR EACH STATEMENT
        EXECUTE FUNCTION {SCHEMA}.reject_ledger_mutation()
        """
    )


def upgrade() -> None:
    """Protect every catalog ledger and retain recovery evidence in the journal."""
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.add_column(
        "migration_journal",
        sa.Column(
            "notes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_migration_journal_notes"),
        "migration_journal",
        "jsonb_typeof(notes) = 'object'",
        schema=SCHEMA,
    )
    for table_name in CATALOG_TABLES:
        _protect(table_name)
    for index_name, table_name in DUPLICATE_INDEXES:
        op.drop_index(index_name, table_name=table_name, schema=SCHEMA)


def downgrade() -> None:
    """Refuse to remove append-only catalog protection or recovery evidence."""
    raise RuntimeError(
        "0021_catalog_append_only is forward-only; a verified "
        "pre-migration backup may be restored only before this migration"
    )
