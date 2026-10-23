"""Migration 0026 refuses to retire the ledger while it is the only in-flight marker."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from smithguard.db.jobs import dead_letter, enqueue, lease_next
from smithguard.signals import (
    PreliminaryWarningDraft,
    create_preliminary_warning,
    recheck_warning,
)
from smithguard.spend import load_spend_policy_path

from .support import LocalPostgres, migrate, migrated_database

NOW = datetime(2026, 9, 18, 12, tzinfo=UTC)
PRIOR_HEAD = "0025_coverage_presence_indexes"
HEAD = "0026_retire_spend_ledger"
POLICY_PATH = Path(__file__).resolve().parents[1] / "contracts/v1/xai-spend-policy.json"


def _active_policy():
    return replace(
        load_spend_policy_path(POLICY_PATH),
        # Historical API migration evidence, not current subscription authority.
        subscription_first=False,
        policy_state="active",
        external_calls_allowed=True,
        unattended_collection_allowed=True,
        all_required_controls_pass=True,
    )


def _create_warning(handle) -> str:
    draft = PreliminaryWarningDraft(
        title="Unverified synthetic warning for the ledger retirement",
        claim="Two independent public leads describe a possible package compromise.",
        affected_artifacts=("npm:synthetic-warning@1.0.0",),
        source_urls=(
            "https://example.com/source-retirement-one",
            "https://example.org/source-retirement-two",
        ),
        evidence_class="web_and_social",
        independent_source_clusters=2,
        observed_at=NOW,
        reviewer_id="reviewer:owner",
    )
    with Session(handle.engine) as session, session.begin():
        return create_preliminary_warning(session, draft=draft, reviewed_at=NOW)["id"]


def _ledger_table_exists(handle) -> bool:
    with handle.engine.connect() as connection:
        return (
            connection.scalar(text("SELECT to_regclass('smithguard.spend_ledger_events')"))
            is not None
        )


def test_retiring_the_ledger_refuses_retryable_provider_attempts(
    postgres_cluster: LocalPostgres,
) -> None:
    handle = migrated_database(postgres_cluster, revision=PRIOR_HEAD)
    try:
        with Session(handle.engine) as session, session.begin():
            enqueue(
                session,
                queue="ai-warning-discovery",
                job_type="scheduled_public_discovery",
                idempotency_key="leftover-discovery",
                payload={"run_id": "run-leftover"},
                max_attempts=2,
                now=NOW,
            )
            enqueue(
                session,
                queue="ai-warning-qualification",
                job_type="candidate_qualification",
                idempotency_key="never-dispatched",
                payload={"run_id": "run-leftover"},
                max_attempts=1,
                now=NOW,
            )
            leased = lease_next(
                session,
                queue="ai-warning-discovery",
                worker_id="old-runtime",
                lease_for=timedelta(minutes=5),
                now=NOW,
            )
        assert leased is not None
        assert leased.attempts == 1

        # A leased attempt under the old runtime may have reached the provider; the
        # ledger reservation was its only durable marker.
        with pytest.raises(RuntimeError, match="retryable provider attempt"):
            migrate(handle.url, HEAD)
        assert _ledger_table_exists(handle)

        with Session(handle.engine) as session, session.begin():
            dead_letter(
                session,
                job_id=leased.job_id,
                lease_token=leased.lease_token,
                error_code="old_runtime_drained",
                now=NOW,
            )
        # The never-dispatched pending qualification job does not block: it has no
        # attempt that could have reached the provider.
        migrate(handle.url, HEAD)
        assert not _ledger_table_exists(handle)
        with handle.engine.connect() as connection:
            columns = set(
                connection.scalars(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'smithguard' "
                        "AND table_name = 'preliminary_warning_rechecks'"
                    )
                )
            )
            assert "exact_cost_usd_ticks" not in columns
            assert "reservation_id" in columns
            assert connection.scalar(text("SELECT version_num FROM public.alembic_version")) == HEAD
    finally:
        handle.engine.dispose()


@pytest.mark.usefixtures("enabled_warning_dispatch")
def test_retiring_the_ledger_refuses_open_recheck_sequences(
    postgres_cluster: LocalPostgres,
) -> None:
    handle = migrated_database(postgres_cluster, revision=PRIOR_HEAD)
    try:
        warning_id = _create_warning(handle)
        factory = sessionmaker(handle.engine)

        def crashing_provider(_warning, _checked_at):
            raise ConnectionResetError("synthetic crash after the request was sent")

        # The dispatch revision advanced recheck_count to 1; no recheck record exists.
        # Under the old runtime only a ledger reservation marked this sequence.
        with pytest.raises(ConnectionResetError):
            recheck_warning(
                factory,
                warning_id=warning_id,
                policy=_active_policy(),
                provider=crashing_provider,
                now=NOW + timedelta(hours=1),
            )
        with pytest.raises(RuntimeError, match="open recheck sequence"):
            migrate(handle.url, HEAD)
        assert _ledger_table_exists(handle)

        # Once the warning is no longer active, nothing can retry that sequence.
        expired = recheck_warning(
            factory,
            warning_id=warning_id,
            policy=_active_policy(),
            provider=crashing_provider,
            now=NOW + timedelta(days=2),
        )
        assert expired.outcome == "expired"
        migrate(handle.url, HEAD)
        assert not _ledger_table_exists(handle)
    finally:
        handle.engine.dispose()
