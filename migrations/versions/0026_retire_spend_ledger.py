"""Retire the exact-cost spend ledger and the recheck cost column.

Revision ID: 0026_retire_spend_ledger
Revises: 0025_coverage_presence_indexes
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0026_retire_spend_ledger"
down_revision: str | None = "0025_coverage_presence_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Retire the spend ledger and the recheck exact-cost column"
rollback_mode: str = "forward_only"

SCHEMA = "smithguard"
PROVIDER_QUEUES = ("ai-warning-discovery", "ai-warning-qualification")


def _refuse_open_provider_attempts() -> None:
    """Fail closed while any provider attempt is marked in flight only by the ledger.

    Before this migration an open ledger reservation was the sole durable sign that a
    discovery or qualification attempt had reached the provider. The retired runtime
    marks attempts with a dispatch receipt instead and cannot see the old marker, so
    a job that was leased under the old runtime and is still retryable could be
    dispatched a second time after the table is gone. Such jobs must finish, retry or
    dead-letter under the old runtime first; the migration refuses until they have.
    """
    count = op.get_bind().scalar(
        text(
            f"""
            SELECT count(*)
            FROM {SCHEMA}.jobs
            WHERE queue = ANY(:queues)
              AND attempts >= 1
              AND state IN ('pending', 'running', 'retry_wait')
            """
        ),
        {"queues": list(PROVIDER_QUEUES)},
    )
    if count:
        raise RuntimeError(
            f"0026_retire_spend_ledger preflight found {count} retryable provider "
            "attempt(s) whose only in-flight marker is the spend ledger; let the "
            "warning lane drain before retiring the ledger"
        )


def _refuse_open_recheck_sequences() -> None:
    """Fail closed while an active warning has a recheck sequence without its record.

    A recheck writes a dispatch revision (``recheck_count`` advances) before its
    provider call and its recheck record after it. Under the old runtime a
    known-uncharged retry of that sequence was marked in flight only by a ledger
    reservation; the retired runtime looks for a retry dispatch receipt instead and
    would send the retry again. Such sequences must complete, close or expire under
    the old runtime first; the migration refuses until they have.
    """
    count = op.get_bind().scalar(
        text(
            f"""
            SELECT count(*)
            FROM (
                SELECT DISTINCT ON (id) id, state, recheck_count
                FROM {SCHEMA}.preliminary_warnings
                ORDER BY id, revision DESC
            ) AS latest
            WHERE latest.state = 'active'
              AND latest.recheck_count >= 1
              AND NOT EXISTS (
                  SELECT 1
                  FROM {SCHEMA}.preliminary_warning_rechecks AS recheck
                  WHERE recheck.warning_id = latest.id
                    AND recheck.sequence = latest.recheck_count
              )
            """
        )
    )
    if count:
        raise RuntimeError(
            f"0026_retire_spend_ledger preflight found {count} active warning(s) with an "
            "open recheck sequence whose only in-flight marker is the spend ledger; let "
            "the recheck schedule close them before retiring the ledger"
        )


def upgrade() -> None:
    """Drop the pricing bookkeeping the September 18, 2026 owner direction removed.

    The owner monitors provider cost through billing. The ledger's rows were exact
    reservation and settlement events for a control that no longer exists; dropping
    the table drops its append-only triggers and indexes with it. The recheck table
    keeps every other column; its per-check cost is provider billing data the runtime
    no longer records. Both are forward-only: no restore path is provided or needed.
    """
    op.execute("SET LOCAL lock_timeout = '5s'")
    _refuse_open_provider_attempts()
    _refuse_open_recheck_sequences()
    op.execute(f"DROP TABLE {SCHEMA}.spend_ledger_events")
    op.execute(
        f"ALTER TABLE {SCHEMA}.preliminary_warning_rechecks DROP COLUMN exact_cost_usd_ticks"
    )


def downgrade() -> None:
    """Preserve the forward migration journal and retained evidence."""
    raise RuntimeError("0026_retire_spend_ledger is forward-only")
