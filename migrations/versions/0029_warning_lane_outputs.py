"""Keep final warning-lane provider output privately for 30 days.

Revision ID: 0029_warning_lane_outputs
Revises: 0028_casefold_lookup_indexes
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0029_warning_lane_outputs"
down_revision: str | None = "0028_casefold_lookup_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Keep final warning-lane provider output privately for 30 days"
rollback_mode: str = "forward_only"


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.create_table(
        "warning_lane_outputs",
        sa.Column("output_id", sa.String(71), nullable=False),
        sa.Column("run_id", sa.String(512), nullable=False),
        sa.Column("job_id_sha256", sa.String(71), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("stage", sa.String(20), nullable=False),
        sa.Column("response_id_sha256", sa.String(71), nullable=False),
        sa.Column("output_text", sa.Text(), nullable=False),
        sa.Column("output_truncated", sa.Boolean(), nullable=False),
        sa.Column("output_encoding", sa.String(20), nullable=False),
        sa.Column("citation_urls", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("output_id"),
        sa.CheckConstraint("output_id ~ '^sha256:[a-f0-9]{64}$'", name="output_id"),
        sa.CheckConstraint("stage IN ('discovery','qualification')", name="stage"),
        sa.CheckConstraint("expires_at > created_at", name="times"),
        sa.CheckConstraint("char_length(output_text) <= 524288", name="output_size"),
        sa.CheckConstraint("output_encoding IN ('text','escaped')", name="output_encoding"),
        sa.CheckConstraint("jsonb_typeof(citation_urls) = 'array'", name="citations"),
        schema="smithguard",
    )
    op.create_index(
        "ix_warning_lane_outputs_expires",
        "warning_lane_outputs",
        ["expires_at"],
        schema="smithguard",
    )
    op.create_index(
        "ix_warning_lane_outputs_run", "warning_lane_outputs", ["run_id"], schema="smithguard"
    )
    # The migration owns the new table, so it grants the one runtime role directly
    # (no superuser step); the public API role gets nothing.
    op.execute(
        """
        DO $grants$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-signals') THEN
                GRANT SELECT, INSERT, DELETE ON TABLE smithguard.warning_lane_outputs
                    TO "smithguard-signals";
            END IF;
        END
        $grants$;
        """
    )


def downgrade() -> None:
    raise RuntimeError("0029_warning_lane_outputs is forward-only")
