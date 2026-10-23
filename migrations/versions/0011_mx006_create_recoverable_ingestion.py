"""create MX-006 recoverable ingestion state

Revision ID: 0011_mx006
Revises: 0010_mx005
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_mx006"
down_revision: str | None = "0010_mx005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = (
    "Create recoverable evidence finalization and bounded ingestion retry state"
)
rollback_mode: str = "forward_only"

SCHEMA = "goodboy_security"
STABLE_ID = r"^gbsec:[a-z0-9][a-z0-9:._/-]+$"
SHA256 = r"^sha256:[a-f0-9]{64}$"


def upgrade() -> None:
    """Add recoverable evidence, retry, rate-limit, and lease-scan state."""
    for _name, column in (
        (
            "idempotency_root_hash",
            sa.Column("idempotency_root_hash", sa.String(length=71), nullable=True),
        ),
        (
            "representation_hash",
            sa.Column("representation_hash", sa.String(length=71), nullable=True),
        ),
        (
            "processing_version",
            sa.Column("processing_version", sa.String(length=80), nullable=True),
        ),
        (
            "retry_of_batch_id",
            sa.Column("retry_of_batch_id", sa.String(length=160), nullable=True),
        ),
    ):
        op.add_column("ingestion_batches", column, schema=SCHEMA)
    op.create_check_constraint(
        op.f("ck_ingestion_batches_idempotency_root_hash"),
        "ingestion_batches",
        f"idempotency_root_hash ~ '{SHA256}'",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_ingestion_batches_representation_hash"),
        "ingestion_batches",
        f"representation_hash ~ '{SHA256}'",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_ingestion_batches_processing_version"),
        "ingestion_batches",
        "processing_version ~ '^[a-z0-9][a-z0-9._-]{1,79}$'",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_ingestion_batches_retry_of_batch_id"),
        "ingestion_batches",
        f"retry_of_batch_id IS NULL OR retry_of_batch_id ~ '{STABLE_ID}'",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_ingestion_batches_lineage_shape"),
        "ingestion_batches",
        "(idempotency_root_hash IS NULL "
        "AND representation_hash IS NULL "
        "AND processing_version IS NULL "
        "AND retry_of_batch_id IS NULL) "
        "OR (idempotency_root_hash IS NOT NULL "
        "AND representation_hash IS NOT NULL "
        "AND processing_version IS NOT NULL)",
        schema=SCHEMA,
    )
    op.create_index(
        "ix_ingestion_batches_root_completed",
        "ingestion_batches",
        ["source_id", "idempotency_root_hash", "completed_at"],
        unique=False,
        schema=SCHEMA,
    )

    op.add_column(
        "collector_progress",
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=True),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_collector_progress_not_before",
        "collector_progress",
        ["source_id", "lane", "not_before"],
        unique=False,
        schema=SCHEMA,
    )

    op.create_table(
        "evidence_finalizations",
        sa.Column("finalization_id", sa.String(length=160), nullable=False),
        sa.Column("evidence_id", sa.String(length=160), nullable=False),
        sa.Column("digest", sa.String(length=71), nullable=False),
        sa.Column("staging_key", sa.String(length=71), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_error_code", sa.String(length=120), nullable=True),
        sa.Column("staged_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            f"finalization_id ~ '{STABLE_ID}'",
            name=op.f("ck_evidence_finalizations_finalization_id"),
        ),
        sa.CheckConstraint(
            f"evidence_id ~ '{STABLE_ID}'",
            name=op.f("ck_evidence_finalizations_evidence_id"),
        ),
        sa.CheckConstraint(
            f"digest ~ '{SHA256}'",
            name=op.f("ck_evidence_finalizations_digest"),
        ),
        sa.CheckConstraint(
            f"staging_key ~ '{SHA256}'",
            name=op.f("ck_evidence_finalizations_staging_key"),
        ),
        sa.CheckConstraint(
            "state IN ('pending', 'finalized', 'failed')",
            name=op.f("ck_evidence_finalizations_state"),
        ),
        sa.CheckConstraint(
            "byte_count BETWEEN 0 AND 52428800",
            name=op.f("ck_evidence_finalizations_byte_count"),
        ),
        sa.CheckConstraint(
            "attempts BETWEEN 0 AND 100",
            name=op.f("ck_evidence_finalizations_attempts"),
        ),
        sa.CheckConstraint(
            "last_error_code IS NULL OR last_error_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name=op.f("ck_evidence_finalizations_last_error_code"),
        ),
        sa.CheckConstraint(
            "updated_at >= staged_at",
            name=op.f("ck_evidence_finalizations_timestamp_order"),
        ),
        sa.CheckConstraint(
            "(state = 'finalized' AND finalized_at IS NOT NULL) OR "
            "(state <> 'finalized' AND finalized_at IS NULL)",
            name=op.f("ck_evidence_finalizations_finalized_shape"),
        ),
        sa.PrimaryKeyConstraint(
            "finalization_id",
            name=op.f("pk_evidence_finalizations"),
        ),
        sa.UniqueConstraint(
            "digest",
            name=op.f("uq_evidence_finalizations_digest"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_evidence_finalizations_state_updated",
        "evidence_finalizations",
        ["state", "updated_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.execute(
        f"""
        INSERT INTO {SCHEMA}.evidence_finalizations (
            finalization_id,
            evidence_id,
            digest,
            staging_key,
            byte_count,
            state,
            attempts,
            last_error_code,
            staged_at,
            updated_at,
            finalized_at
        )
        SELECT
            'gbsec:evidence-finalization:legacy:' ||
                substr(replace(e.sha256, 'sha256:', ''), 1, 64),
            e.id,
            e.sha256,
            e.sha256,
            e.byte_count,
            'finalized',
            0,
            NULL,
            e.created_at,
            e.updated_at,
            e.updated_at
        FROM (
            SELECT DISTINCT ON (sha256)
                id,
                sha256,
                byte_count,
                created_at,
                updated_at
            FROM {SCHEMA}.evidence_objects
            WHERE storage_state = 'stored_immutable'
              AND storage_key IS NOT NULL
            ORDER BY sha256, id, revision DESC
        ) AS e
        """
    )

    op.create_index(
        "ix_jobs_expired_lease_scan",
        "jobs",
        ["queue", "state", "lease_expires_at", "job_id"],
        unique=False,
        schema=SCHEMA,
    )


def downgrade() -> None:
    """Refuse to erase evidence-finalization and retry lineage."""
    raise RuntimeError("0011_mx006 is forward-only because evidence and retry lineage is permanent")
