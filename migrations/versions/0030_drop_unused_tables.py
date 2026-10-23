"""Drop eighteen tables no code reads or writes.

Revision ID: 0030_drop_unused_tables
Revises: 0029_warning_lane_outputs
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0030_drop_unused_tables"
down_revision: str | None = "0029_warning_lane_outputs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Drop eighteen empty tables of retired features"
rollback_mode: str = "forward_only"

SCHEMA = "smithguard"
# Retired correlation shadow, outbound delivery, webhook and review-audit tables
# (audit item 44). All were empty in production on September 24, 2026; the
# snapshot manifest table is kept because it holds historical rows.
DROPPED_TABLES: tuple[str, ...] = (
    "review_audit_events",
    "correlation_source_observations",
    "correlation_shadow_runs",
    "correlation_shadow_samples",
    "correlation_observation_origins",
    "correlation_claim_observations",
    "correlation_advisory_identities",
    "correlation_vulnerability_identities",
    "correlation_security_events",
    "correlation_event_members",
    "correlation_candidates",
    "correlation_decisions",
    "correlation_incident_aliases",
    "correlation_warning_links",
    "delivery_events",
    "delivery_destinations",
    "delivery_attempts",
    "webhook_receipts",
)


def upgrade() -> None:
    """Lock every table, refuse if any has a row, then drop them all in one statement.

    Owner direction (September 24, 2026) is to drop only empty tables, so a row
    appearing since the read-only count stops the migration instead of losing it.
    The exclusive locks come first: no other transaction can add a row between the
    check and the drop (an uncommitted insert makes the lock wait, then the check
    sees the committed row). One DROP resolves the foreign keys among these tables;
    their triggers and indexes go with them.
    """
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute(
        "LOCK TABLE "
        + ", ".join(f"{SCHEMA}.{table}" for table in DROPPED_TABLES)
        + " IN ACCESS EXCLUSIVE MODE"
    )
    bind = op.get_bind()
    occupied = [
        table
        for table in DROPPED_TABLES
        if bind.scalar(text(f"SELECT EXISTS (SELECT 1 FROM {SCHEMA}.{table})"))
    ]
    if occupied:
        raise RuntimeError(
            "0030_drop_unused_tables refuses to drop tables with rows: " + ", ".join(occupied)
        )
    op.execute("DROP TABLE " + ", ".join(f"{SCHEMA}.{table}" for table in DROPPED_TABLES))


def downgrade() -> None:
    """Preserve the forward migration journal."""
    raise RuntimeError("0030_drop_unused_tables is forward-only")
