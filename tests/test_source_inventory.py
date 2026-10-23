"""Authenticated source inventory reconciliation stays bounded and conservative."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.collectors import (
    GITHUB_ADVISORY,
    CollectorRunner,
    GitHubAdvisoryCollection,
    TransportResponse,
)
from smithguard.db.models import (
    CollectorProgressRecord,
    PublicationLifecycleEventRecord,
    SourceReconciliationRunRecord,
)
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.identifiers import canonical_json_bytes, sha256_id, stable_id, timestamp
from smithguard.publication import publish_github_malware_incidents
from smithguard.service import SmithGuardService
from smithguard.source_inventory import (
    SourceInventoryError,
    SourceInventoryObservation,
    SourceInventoryReplayConflict,
    reconcile_source_inventory,
)
from smithguard.source_rights import RightsRegistry

from .governance_fixtures import active_governance_policy

REPO_ROOT = Path(__file__).resolve().parents[1]
RIGHTS_REGISTER = REPO_ROOT / "contracts/v1/source-rights-register.json"
NOW = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
CONNECTOR = "gbsec:connector:github-advisory-rest-v1"
INVENTORY_URL = "https://api.github.com/advisories"


def _advisory(advisory_id: str, updated_at: datetime) -> dict:
    return {
        "ghsa_id": advisory_id,
        "type": "malware",
        "published_at": "2026-08-01T00:00:00Z",
        "updated_at": timestamp(updated_at),
        "withdrawn_at": None,
        "html_url": f"https://github.com/advisories/{advisory_id}",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": advisory_id.lower()},
                "vulnerable_version_range": "= 1.0.0",
            }
        ],
        "references": [],
        "identifiers": [{"type": "GHSA", "value": advisory_id}],
    }


def _collect_and_publish(
    session: Session,
    *,
    evidence_store: LocalImmutableEvidenceStore,
    advisory_id: str,
    updated_at: datetime,
) -> None:
    advisory = _advisory(advisory_id, updated_at)
    body = json.dumps([advisory], sort_keys=True, separators=(",", ":")).encode("ascii")

    def transport(_spec, _checkpoint):
        return TransportResponse(
            body=body,
            canonical_url=advisory["html_url"],
            media_type="application/json",
            retrieved_at=updated_at,
            source_record_id=f"{advisory_id}:{timestamp(updated_at)}",
            source_published_at=datetime(2026, 8, 1, tzinfo=UTC),
            source_modified_at=updated_at,
            declared_content_length=len(body),
        )

    policy = active_governance_policy()
    run = CollectorRunner(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        transport=transport,
        clock=lambda: updated_at,
        governance_policy=policy,
    ).run_public(
        session,
        source_id=GITHUB_ADVISORY,
        operating_mode="historical",
    )
    assert run.outcome is not None and run.outcome.outcome == "accepted"
    publish_github_malware_incidents(
        session,
        collection=GitHubAdvisoryCollection(
            advisory_id=advisory_id,
            published_at=datetime(2026, 8, 1, tzinfo=UTC),
            updated_at=updated_at,
            withdrawn=False,
            outcome=run.outcome,
        ),
        published_at=updated_at,
        governance_policy=policy,
    )


def _complete_historical_progress(session: Session, occurred_at: datetime) -> None:
    values = {
        "progress_event_id": stable_id("progress", GITHUB_ADVISORY, "historical-complete"),
        "source_id": GITHUB_ADVISORY,
        "lane": "historical",
        "sequence": 1,
        "state": "complete",
        "cursor_value": None,
        "cursor_parameter": None,
        "page_count": 1,
        "source_record_count": 1,
        "normalized_record_count": 1,
        "window_started_at": None,
        "window_ended_at": None,
        "oldest_published_at": datetime(2026, 8, 1, tzinfo=UTC),
        "newest_published_at": datetime(2026, 8, 1, tzinfo=UTC),
        "reason_code": "github_lane_complete",
        "occurred_at": occurred_at,
    }
    session.add(
        CollectorProgressRecord(
            **values,
            record_hash=sha256_id(
                canonical_json_bytes(
                    {
                        **values,
                        "oldest_published_at": timestamp(values["oldest_published_at"]),
                        "newest_published_at": timestamp(values["newest_published_at"]),
                        "occurred_at": timestamp(occurred_at),
                    }
                )
            ),
        )
    )
    session.flush()


def test_complete_paged_inventory_keeps_ordinary_omission_non_deleting_and_expires(
    database,
    tmp_path: Path,
) -> None:
    policy = active_governance_policy()
    run_id = stable_id("source-inventory-run", "synthetic-complete")
    with Session(database.engine) as session, session.begin():
        _collect_and_publish(
            session,
            evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
            advisory_id="GHSA-aaaa-bbbb-1111",
            updated_at=NOW,
        )
        _complete_historical_progress(session, NOW)

        first = reconcile_source_inventory(
            session,
            policy=policy,
            connector_id=CONNECTOR,
            source_id=GITHUB_ADVISORY,
            acquisition_method="rest_api",
            canonical_url=INVENTORY_URL,
            inventory_run_id=run_id,
            page_index=1,
            observations=(
                SourceInventoryObservation(
                    "GHSA-aaaa-bbbb-1111",
                    NOW,
                ),
            ),
            continuation_in=None,
            continuation_out="synthetic-next-page",
            has_more=True,
            inventory_complete=False,
            reconciled_at=NOW + timedelta(minutes=1),
            next_due_at=NOW + timedelta(days=1),
        )
        assert first.state == "in_progress"
        final = reconcile_source_inventory(
            session,
            policy=policy,
            connector_id=CONNECTOR,
            source_id=GITHUB_ADVISORY,
            acquisition_method="rest_api",
            canonical_url=INVENTORY_URL,
            inventory_run_id=run_id,
            page_index=2,
            observations=(),
            continuation_in="synthetic-next-page",
            continuation_out=None,
            has_more=False,
            inventory_complete=True,
            reconciled_at=NOW + timedelta(minutes=2),
            next_due_at=NOW + timedelta(days=1),
        )
        assert final.state == "complete"
        assert final.deleted_record_ids == ()
        assert final.missing_record_ids == ()
        repeated = reconcile_source_inventory(
            session,
            policy=policy,
            connector_id=CONNECTOR,
            source_id=GITHUB_ADVISORY,
            acquisition_method="rest_api",
            canonical_url=INVENTORY_URL,
            inventory_run_id=run_id,
            page_index=2,
            observations=(),
            continuation_in="synthetic-next-page",
            continuation_out=None,
            has_more=False,
            inventory_complete=True,
            reconciled_at=NOW + timedelta(minutes=2),
            next_due_at=NOW + timedelta(days=1),
        )
        assert not repeated.created
        service_report = SmithGuardService(
            clock=lambda: NOW + timedelta(hours=1),
            expected_governance_policy_sha256=policy.policy_sha256,
        ).get_source_coverage(session)
        assert len(service_report["source_lanes"]) == 11
        assert {
            "gbsec:source:first-epss",
            "gbsec:source:cisa-kev",
            "gbsec:source:rustsec-advisory-database",
            "gbsec:source:go-vulnerability-database",
        } <= {lane["source_id"] for lane in service_report["source_lanes"]}
        assert all(lane["state"] == "not_started" for lane in service_report["source_lanes"])
        assert (
            session.scalar(select(func.count()).select_from(PublicationLifecycleEventRecord)) == 1
        )


def test_modified_late_and_authoritative_deleted_records_remain_unresolved(
    database,
    tmp_path: Path,
) -> None:
    policy = active_governance_policy()
    with Session(database.engine) as session, session.begin():
        evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
        _collect_and_publish(
            session,
            evidence_store=evidence_store,
            advisory_id="GHSA-aaaa-bbbb-2222",
            updated_at=NOW,
        )
        _collect_and_publish(
            session,
            evidence_store=evidence_store,
            advisory_id="GHSA-aaaa-bbbb-3333",
            updated_at=NOW,
        )
        _complete_historical_progress(session, NOW)
        result = reconcile_source_inventory(
            session,
            policy=policy,
            connector_id=CONNECTOR,
            source_id=GITHUB_ADVISORY,
            acquisition_method="rest_api",
            canonical_url=INVENTORY_URL,
            inventory_run_id=stable_id("source-inventory-run", "synthetic-drift"),
            page_index=1,
            observations=(
                SourceInventoryObservation(
                    "GHSA-aaaa-bbbb-2222",
                    NOW - timedelta(hours=1),
                ),
                SourceInventoryObservation(
                    "GHSA-aaaa-bbbb-3333",
                    NOW,
                    state="deleted",
                ),
                SourceInventoryObservation(
                    "GHSA-aaaa-bbbb-4444",
                    NOW,
                ),
            ),
            continuation_in=None,
            continuation_out=None,
            has_more=False,
            inventory_complete=True,
            reconciled_at=NOW + timedelta(hours=2),
            next_due_at=NOW + timedelta(days=1),
        )
        assert result.state == "unresolved"
        assert result.modified_record_ids == ("GHSA-aaaa-bbbb-2222",)
        assert result.deleted_record_ids == ("GHSA-aaaa-bbbb-3333",)
        assert result.late_record_ids == ("GHSA-aaaa-bbbb-4444",)
        deleted_events = tuple(
            session.scalars(
                select(PublicationLifecycleEventRecord).where(
                    PublicationLifecycleEventRecord.event_type == "source_deleted"
                )
            )
        )
        assert len(deleted_events) == 1


def test_complete_inventory_marks_unseen_retained_record_missing_not_deleted(
    database,
    tmp_path: Path,
) -> None:
    policy = active_governance_policy()
    with Session(database.engine) as session, session.begin():
        evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
        _collect_and_publish(
            session,
            evidence_store=evidence_store,
            advisory_id="GHSA-aaaa-bbbb-6001",
            updated_at=NOW,
        )
        _collect_and_publish(
            session,
            evidence_store=evidence_store,
            advisory_id="GHSA-aaaa-bbbb-6002",
            updated_at=NOW,
        )
        result = reconcile_source_inventory(
            session,
            policy=policy,
            connector_id=CONNECTOR,
            source_id=GITHUB_ADVISORY,
            acquisition_method="rest_api",
            canonical_url=INVENTORY_URL,
            inventory_run_id=stable_id("source-inventory-run", "synthetic-missing"),
            page_index=1,
            observations=(
                SourceInventoryObservation(
                    "GHSA-aaaa-bbbb-6001",
                    NOW,
                ),
            ),
            continuation_in=None,
            continuation_out=None,
            has_more=False,
            inventory_complete=True,
            reconciled_at=NOW + timedelta(minutes=1),
            next_due_at=NOW + timedelta(days=1),
        )
        assert result.state == "unresolved"
        assert result.missing_record_ids == ("GHSA-aaaa-bbbb-6002",)
        assert result.deleted_record_ids == ()
        assert result.unresolved_record_ids == ("GHSA-aaaa-bbbb-6002",)
        assert (
            session.scalar(
                select(func.count())
                .select_from(PublicationLifecycleEventRecord)
                .where(PublicationLifecycleEventRecord.event_type == "source_deleted")
            )
            == 0
        )


def test_reconciliation_replay_and_continuation_mismatch_fail_closed(database) -> None:
    policy = active_governance_policy()
    run_id = stable_id("source-inventory-run", "synthetic-conflict")
    arguments = {
        "policy": policy,
        "connector_id": CONNECTOR,
        "source_id": GITHUB_ADVISORY,
        "acquisition_method": "rest_api",
        "canonical_url": INVENTORY_URL,
        "inventory_run_id": run_id,
        "page_index": 1,
        "observations": (),
        "continuation_in": None,
        "continuation_out": "next",
        "has_more": True,
        "inventory_complete": False,
        "reconciled_at": NOW,
        "next_due_at": NOW + timedelta(days=1),
    }
    with Session(database.engine) as session, session.begin():
        reconcile_source_inventory(session, **arguments)
        with pytest.raises(SourceInventoryReplayConflict, match="different input"):
            reconcile_source_inventory(
                session,
                **{
                    **arguments,
                    "observations": (SourceInventoryObservation("GHSA-aaaa-bbbb-5555", NOW),),
                },
            )
        with pytest.raises(SourceInventoryError, match="continuation"):
            reconcile_source_inventory(
                session,
                **{
                    **arguments,
                    "page_index": 2,
                    "continuation_in": "wrong",
                    "continuation_out": None,
                    "has_more": False,
                    "inventory_complete": True,
                },
            )
        assert session.scalar(select(func.count()).select_from(SourceReconciliationRunRecord)) == 1
