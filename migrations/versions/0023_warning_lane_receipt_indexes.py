"""bound warning-lane receipt scans and acknowledge dead letters

Revision ID: 0023_warning_receipt_indexes
Revises: 0022_claims_source_index
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023_warning_receipt_indexes"
down_revision: str | None = "0022_claims_source_index"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Bound warning receipts and acknowledge dead letters"
rollback_mode: str = "forward_only"

SCHEMA = "smithguard"


def upgrade() -> None:
    """Add bounded receipt and spend indexes plus acknowledged job state."""
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.drop_constraint(op.f("ck_jobs_completion_shape"), "jobs", schema=SCHEMA, type_="check")
    op.drop_constraint(op.f("ck_jobs_state"), "jobs", schema=SCHEMA, type_="check")
    op.create_check_constraint(
        op.f("ck_jobs_state"),
        "jobs",
        "state IN ('pending', 'running', 'retry_wait', 'succeeded', 'dead_letter', 'acknowledged')",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_jobs_completion_shape"),
        "jobs",
        "(state IN ('succeeded', 'dead_letter', 'acknowledged') AND completed_at IS NOT NULL) "
        "OR (state NOT IN ('succeeded', 'dead_letter', 'acknowledged') "
        "AND completed_at IS NULL)",
        schema=SCHEMA,
    )
    op.create_index(
        "ix_jobs_receipt_run_completed",
        "jobs",
        [sa.text("(payload ->> 'run_id')"), "completed_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_jobs_receipt_type_completed",
        "jobs",
        [sa.text("(payload ->> 'receipt_type')"), "completed_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_spend_ledger_reservation_latest",
        "spend_ledger_events",
        ["reservation_id", sa.text("occurred_at DESC"), sa.text("spend_event_id DESC")],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_spend_ledger_provider_cost",
        "spend_ledger_events",
        ["provider_cost_id_hash"],
        unique=False,
        schema=SCHEMA,
        postgresql_where=sa.text("provider_cost_id_hash IS NOT NULL"),
    )
    op.create_index(
        "ix_spend_ledger_integrity_denial",
        "spend_ledger_events",
        [
            "reason_code",
            "reservation_id",
            sa.text("occurred_at DESC"),
            sa.text("spend_event_id DESC"),
        ],
        unique=False,
        schema=SCHEMA,
        postgresql_where=sa.text("event_type = 'denied'"),
    )


def downgrade() -> None:
    """Refuse to remove consumed acknowledgment state or receipt indexes."""
    raise RuntimeError(
        "0023_warning_receipt_indexes is forward-only; a verified pre-migration "
        "backup may be restored only before this migration"
    )
