"""Retained GitHub evidence replay is bounded, local, and fail closed."""

from __future__ import annotations

import json
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.authority import load_authority_policy
from smithguard.collectors import (
    COLLECTOR_SPECS,
    GITHUB_ADVISORY,
)
from smithguard.db.models import (
    EvidenceFinalizationRecord,
    EvidenceRecord,
    IngestionBatchRecord,
    SourceGovernanceDecisionRecord,
    SourceIncidentLinkRecord,
)
from smithguard.db.repository import append_contract
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.identifiers import canonical_json_bytes, sha256_id, stable_id, timestamp
from smithguard.retained_replay import RetainedReplayError, replay_retained_github_evidence
from smithguard.source_inventory import (
    SourceInventoryObservation,
    reconcile_source_inventory,
)
from smithguard.source_rights import RightsRegistry

from .governance_fixtures import active_governance_policy

REPO_ROOT = Path(__file__).resolve().parents[1]
RIGHTS_REGISTER = REPO_ROOT / "contracts/v1/source-rights-register.json"
AUTHORITY_POLICY = REPO_ROOT / "contracts/v1/malware-authority-policy.json"
NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)
INVENTORY_URL = "https://api.github.com/advisories"


def _advisory(
    advisory_id: str,
    *,
    updated_at: datetime,
    summary: str | None = None,
) -> dict:
    advisory = {
        "ghsa_id": advisory_id,
        "type": "malware",
        "published_at": "2026-07-01T00:00:00Z",
        "updated_at": timestamp(updated_at),
        "withdrawn_at": None,
        "html_url": f"https://github.com/advisories/{advisory_id}",
        "identifiers": [{"type": "GHSA", "value": advisory_id}],
        "references": [],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": advisory_id.lower()},
                "vulnerable_version_range": "= 1.0.0",
            },
            {
                "package": {
                    "ecosystem": "swift",
                    "name": advisory_id.lower() + "-unsupported",
                },
                "vulnerable_version_range": "= 1.0.0",
            },
        ],
    }
    if summary is not None:
        advisory["summary"] = summary
    return advisory


def _seed_legacy_empty(
    database,
    *,
    evidence_root: Path,
    advisory_id: str,
    updated_at: datetime,
    batch_shape: str = "legacy",
    evidence_modified_at: datetime | None = None,
    omit_evidence_modified_at: bool = False,
    evidence_source_record_at: datetime | None = None,
    use_legacy_identity_idempotency: bool = False,
    idempotency_key_override: str | None = None,
    summary: str | None = None,
) -> str:
    advisory = _advisory(advisory_id, updated_at=updated_at, summary=summary)
    body = json.dumps(
        [advisory],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    digest = sha256_id(body)
    update_identity = f"{advisory_id}:{timestamp(updated_at)}"
    checkpoint = idempotency_key_override or (
        update_identity if use_legacy_identity_idempotency else f"{update_identity}:{digest}"
    )
    key_hash = sha256_id(checkpoint.encode("utf-8"))
    source_record_id = f"{advisory_id}:{timestamp(evidence_source_record_at or updated_at)}"
    canonical_url = advisory["html_url"]
    published_at = datetime(2026, 7, 1, tzinfo=UTC)
    registry = RightsRegistry.from_path(RIGHTS_REGISTER)
    source = registry.get(GITHUB_ADVISORY).source
    evidence_id = stable_id("evidence", GITHUB_ADVISORY, source_record_id, digest)
    with closing(LocalImmutableEvidenceStore(evidence_root)) as store:
        blob = store.put_bytes(body)
    assert blob.digest == digest
    recorded_modified_at = evidence_modified_at or updated_at
    raw_evidence = {
        "id": evidence_id,
        "kind": "raw_evidence",
        "schema_version": "1.0.0",
        "revision": 1,
        "created_at": timestamp(updated_at),
        "updated_at": timestamp(updated_at),
        "data_classification": "restricted_source",
        "source_id": GITHUB_ADVISORY,
        "source_record_id": source_record_id,
        "canonical_url": canonical_url,
        "retrieved_at": timestamp(updated_at),
        "source_published_at": timestamp(published_at),
        "source_modified_at": (
            None if omit_evidence_modified_at else timestamp(recorded_modified_at)
        ),
        "sha256": digest,
        "byte_count": len(body),
        "media_type": "application/json",
        "storage_state": "stored_immutable",
        "rights_decision": source["rights"]["decision"],
        "quarantine_reasons": [],
    }
    legacy_request_hash = sha256_id(
        canonical_json_bytes(
            {
                "source_record_id": source_record_id,
                "canonical_url": canonical_url,
                "source_published_at": timestamp(published_at),
                "media_type": "application/json",
                "declared_content_length": len(body),
                "redirect_count": 0,
                "input_sha256": digest,
            }
        )
    )
    versioned = batch_shape == "versioned"
    governed = batch_shape == "governed"
    nonempty = batch_shape == "nonempty"
    unfinalized = batch_shape == "unfinalized"
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Source", source)
        append_contract(session, "RawEvidence", raw_evidence, storage_key=digest)
        session.add(
            EvidenceFinalizationRecord(
                finalization_id=stable_id("evidence-finalization", digest),
                evidence_id=evidence_id,
                digest=digest,
                staging_key=digest,
                byte_count=len(body),
                state="failed" if unfinalized else "finalized",
                attempts=1,
                last_error_code="synthetic_unfinalized" if unfinalized else None,
                staged_at=updated_at,
                updated_at=updated_at,
                finalized_at=None if unfinalized else updated_at,
            )
        )
        session.add(
            IngestionBatchRecord(
                batch_id=stable_id("ingestion", GITHUB_ADVISORY, key_hash),
                source_id=GITHUB_ADVISORY,
                idempotency_key_hash=key_hash,
                request_hash=legacy_request_hash,
                input_sha256=digest,
                idempotency_root_hash=key_hash if versioned else None,
                representation_hash=digest if versioned else None,
                processing_version="synthetic-versioned" if versioned else None,
                retry_of_batch_id=None,
                outcome="accepted",
                raw_evidence_id=evidence_id,
                governance_decision_id=(
                    "gbsec:governance-decision:synthetic" if governed else None
                ),
                quarantine_reasons=[],
                record_count=1 if nonempty else 0,
                normalized_record_ids=["gbsec:claim:synthetic"] if nonempty else [],
                coverage=[],
                completed_at=updated_at,
            )
        )
        if batch_shape == "ambiguous":
            second_key_hash = sha256_id(b"synthetic-ambiguous-legacy-key")
            session.add(
                IngestionBatchRecord(
                    batch_id=stable_id("ingestion", GITHUB_ADVISORY, second_key_hash),
                    source_id=GITHUB_ADVISORY,
                    idempotency_key_hash=second_key_hash,
                    request_hash=legacy_request_hash,
                    input_sha256=digest,
                    idempotency_root_hash=None,
                    representation_hash=None,
                    processing_version=None,
                    retry_of_batch_id=None,
                    outcome="accepted",
                    raw_evidence_id=evidence_id,
                    governance_decision_id=None,
                    quarantine_reasons=[],
                    record_count=0,
                    normalized_record_ids=[],
                    coverage=[],
                    completed_at=updated_at,
                )
            )
    return evidence_id


def _inventory(
    database,
    *,
    observations: tuple[SourceInventoryObservation, ...],
    run_name: str,
    terminal: bool = True,
) -> str:
    run_id = stable_id("source-inventory-run", run_name)
    policy = active_governance_policy()
    with Session(database.engine) as session, session.begin():
        reconcile_source_inventory(
            session,
            policy=policy,
            connector_id=COLLECTOR_SPECS[GITHUB_ADVISORY].connector_id,
            source_id=GITHUB_ADVISORY,
            acquisition_method=COLLECTOR_SPECS[GITHUB_ADVISORY].collection_method,
            canonical_url=INVENTORY_URL,
            inventory_run_id=run_id,
            page_index=1,
            observations=observations,
            continuation_in=None,
            continuation_out=None if terminal else "synthetic-next-page",
            has_more=not terminal,
            inventory_complete=terminal,
            reconciled_at=NOW + timedelta(hours=1),
            next_due_at=NOW + timedelta(days=1),
        )
    return run_id


def _replay(
    session: Session,
    *,
    evidence_root: Path,
    inventory_run_id: str,
    limit: int = 100,
    after_evidence_id: str | None = None,
):
    registry = RightsRegistry.from_path(RIGHTS_REGISTER)
    return replay_retained_github_evidence(
        session,
        evidence_store=LocalImmutableEvidenceStore(evidence_root),
        registry=registry,
        governance_policy=active_governance_policy(),
        authority_policy=load_authority_policy(AUTHORITY_POLICY),
        inventory_run_id=inventory_run_id,
        limit=limit,
        after_evidence_id=after_evidence_id,
        replayed_at=NOW + timedelta(hours=2),
    )


def _database_counts(session: Session) -> tuple[int, int, int, int, int]:
    return (
        session.scalar(select(func.count()).select_from(IngestionBatchRecord)) or 0,
        session.scalar(select(func.count()).select_from(EvidenceRecord)) or 0,
        session.scalar(select(func.count()).select_from(EvidenceFinalizationRecord)) or 0,
        session.scalar(select(func.count()).select_from(SourceGovernanceDecisionRecord)) or 0,
        session.scalar(select(func.count()).select_from(SourceIncidentLinkRecord)) or 0,
    )


def test_preview_commit_and_repeat_reuse_finalized_evidence_without_network(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "retained-replay"
    advisory_id = "GHSA-aaaa-bbbb-1111"
    evidence_id = _seed_legacy_empty(
        database,
        evidence_root=evidence_root,
        advisory_id=advisory_id,
        updated_at=NOW,
    )
    run_id = _inventory(
        database,
        observations=(SourceInventoryObservation(advisory_id, NOW),),
        run_name="retained-preview-commit",
    )
    with Session(database.engine) as session:
        before = _database_counts(session)
        attempts_before = session.scalar(select(EvidenceFinalizationRecord.attempts))
    assert attempts_before == 1

    def unexpected_stage(_store, _body):
        raise AssertionError("finalized retained evidence must not be staged")

    monkeypatch.setattr(LocalImmutableEvidenceStore, "stage_bytes", unexpected_stage)
    with Session(database.engine) as session:
        transaction = session.begin_nested()
        preview = _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=run_id,
        )
        assert preview.inventory_observation_count == 1
        assert preview.eligible_candidate_count == 1
        assert preview.selected_count == preview.replayed_count == 1
        assert preview.normalized_record_count == 1
        assert preview.published_incident_count == 1
        assert not preview.has_more
        assert preview.next_after_evidence_id is None
        transaction.rollback()
        session.rollback()

    with Session(database.engine) as session:
        assert _database_counts(session) == before
        assert session.scalar(select(EvidenceFinalizationRecord.attempts)) == 1

    with Session(database.engine) as session, session.begin():
        committed = _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=run_id,
        )
        assert committed.replayed_count == 1
        assert committed.published_incident_count == 1

    store = LocalImmutableEvidenceStore(evidence_root)
    assert store.pending_manifest() == []
    assert len(store.manifest()) == 1
    with Session(database.engine) as session:
        assert session.scalar(select(EvidenceFinalizationRecord.attempts)) == 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(SourceIncidentLinkRecord)
                .where(SourceIncidentLinkRecord.upstream_record_id == advisory_id)
            )
            == 1
        )
        assert session.get(EvidenceRecord, {"id": evidence_id, "revision": 1}) is not None

    with Session(database.engine) as session, session.begin():
        repeated = _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=run_id,
        )
        assert repeated.eligible_candidate_count == 0
        assert repeated.replayed_count == 0


def test_replay_pagination_uses_only_the_opaque_evidence_position(
    database,
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "retained-pagination"
    advisory_ids = ("GHSA-aaaa-bbbb-2001", "GHSA-aaaa-bbbb-2002")
    for index, advisory_id in enumerate(advisory_ids):
        _seed_legacy_empty(
            database,
            evidence_root=evidence_root,
            advisory_id=advisory_id,
            updated_at=NOW + timedelta(minutes=index),
        )
    run_id = _inventory(
        database,
        observations=tuple(
            SourceInventoryObservation(advisory_id, NOW + timedelta(minutes=index))
            for index, advisory_id in enumerate(advisory_ids)
        ),
        run_name="retained-pagination",
    )
    with Session(database.engine) as session:
        transaction = session.begin_nested()
        first = _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=run_id,
            limit=1,
        )
        assert first.eligible_candidate_count == 2
        assert first.replayed_count == 1
        assert first.has_more
        assert first.next_after_evidence_id is not None
        assert first.next_after_evidence_id.startswith("gbsec:evidence:")
        continuation = first.next_after_evidence_id
        transaction.rollback()
        session.rollback()
    with Session(database.engine) as session:
        transaction = session.begin_nested()
        second = _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=run_id,
            limit=1,
            after_evidence_id=continuation,
        )
        assert second.replayed_count == 1
        assert not second.has_more
        assert second.next_after_evidence_id is None
        transaction.rollback()
        session.rollback()


@pytest.mark.parametrize(
    "excluded_state",
    ["versioned", "governed", "nonempty", "unfinalized", "ambiguous"],
)
def test_ineligible_legacy_shapes_are_excluded(
    database,
    tmp_path: Path,
    excluded_state: str,
) -> None:
    evidence_root = tmp_path / f"retained-excluded-{excluded_state}"
    advisory_id = "GHSA-aaaa-bbbb-3001"
    _seed_legacy_empty(
        database,
        evidence_root=evidence_root,
        advisory_id=advisory_id,
        updated_at=NOW,
        batch_shape=excluded_state,
    )
    run_id = _inventory(
        database,
        observations=(SourceInventoryObservation(advisory_id, NOW),),
        run_name=f"retained-excluded-{excluded_state}",
    )
    with Session(database.engine) as session, session.begin():
        report = _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=run_id,
        )
        assert report.eligible_candidate_count == 0
        assert report.replayed_count == 0


def test_equally_latest_evidence_objects_are_excluded_as_ambiguous(
    database,
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "retained-ambiguous-evidence"
    advisory_id = "GHSA-aaaa-bbbb-3002"
    _seed_legacy_empty(
        database,
        evidence_root=evidence_root,
        advisory_id=advisory_id,
        updated_at=NOW,
        summary="first retained representation",
    )
    _seed_legacy_empty(
        database,
        evidence_root=evidence_root,
        advisory_id=advisory_id,
        updated_at=NOW,
        summary="competing retained representation",
    )
    run_id = _inventory(
        database,
        observations=(SourceInventoryObservation(advisory_id, NOW),),
        run_name="retained-ambiguous-evidence",
    )
    with Session(database.engine) as session, session.begin():
        report = _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=run_id,
        )
        assert report.eligible_candidate_count == 0
        assert report.replayed_count == 0


def test_inventory_omission_and_nonterminal_runs_cannot_replay(
    database,
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "retained-inventory-gates"
    advisory_id = "GHSA-aaaa-bbbb-4001"
    _seed_legacy_empty(
        database,
        evidence_root=evidence_root,
        advisory_id=advisory_id,
        updated_at=NOW,
    )
    omitted_run = _inventory(
        database,
        observations=(),
        run_name="retained-omitted",
    )
    with Session(database.engine) as session, session.begin():
        omitted = _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=omitted_run,
        )
        assert omitted.inventory_observation_count == 0
        assert omitted.eligible_candidate_count == 0

    incomplete_run = _inventory(
        database,
        observations=(SourceInventoryObservation(advisory_id, NOW),),
        run_name="retained-incomplete",
        terminal=False,
    )
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(RetainedReplayError, match="not terminal"),
    ):
        _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=incomplete_run,
        )


def test_identity_mismatch_fails_the_page_before_ingestion(
    database,
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "retained-identity-mismatch"
    advisory_id = "GHSA-aaaa-bbbb-5001"
    _seed_legacy_empty(
        database,
        evidence_root=evidence_root,
        advisory_id=advisory_id,
        updated_at=NOW,
        evidence_modified_at=NOW + timedelta(seconds=1),
    )
    run_id = _inventory(
        database,
        observations=(SourceInventoryObservation(advisory_id, NOW),),
        run_name="retained-identity-mismatch",
    )
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(RetainedReplayError, match="source identity changed"),
    ):
        _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=run_id,
        )


def test_exact_legacy_null_modified_time_uses_verified_body_update_time(
    database,
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "retained-null-modified-time"
    advisory_id = "GHSA-aaaa-bbbb-5002"
    evidence_id = _seed_legacy_empty(
        database,
        evidence_root=evidence_root,
        advisory_id=advisory_id,
        updated_at=NOW,
        omit_evidence_modified_at=True,
    )
    run_id = _inventory(
        database,
        observations=(SourceInventoryObservation(advisory_id, NOW),),
        run_name="retained-null-modified-time",
    )
    with Session(database.engine) as session:
        evidence = session.get(EvidenceRecord, {"id": evidence_id, "revision": 1})
        assert evidence is not None
        assert evidence.source_modified_at is None

    with Session(database.engine) as session, session.begin():
        report = _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=run_id,
        )
        assert report.selected_count == report.replayed_count == 1
        assert report.published_incident_count == 1

    with Session(database.engine) as session:
        link = session.scalar(
            select(SourceIncidentLinkRecord).where(
                SourceIncidentLinkRecord.upstream_record_id == advisory_id
            )
        )
        assert link is not None
        assert link.source_updated_at == NOW
        evidence = session.get(EvidenceRecord, {"id": evidence_id, "revision": 1})
        assert evidence is not None
        assert evidence.source_modified_at is None


def test_exact_legacy_identity_idempotency_key_is_reused(
    database,
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "retained-legacy-identity-idempotency"
    advisory_id = "GHSA-aaaa-bbbb-5004"
    _seed_legacy_empty(
        database,
        evidence_root=evidence_root,
        advisory_id=advisory_id,
        updated_at=NOW,
        omit_evidence_modified_at=True,
        use_legacy_identity_idempotency=True,
    )
    run_id = _inventory(
        database,
        observations=(SourceInventoryObservation(advisory_id, NOW),),
        run_name="retained-legacy-identity-idempotency",
    )

    with Session(database.engine) as session, session.begin():
        report = _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=run_id,
        )
        assert report.selected_count == report.replayed_count == 1
        assert report.published_incident_count == 1
        batches = tuple(
            session.scalars(
                select(IngestionBatchRecord).order_by(IngestionBatchRecord.completed_at)
            )
        )
        assert len(batches) == 2
        assert batches[1].retry_of_batch_id == batches[0].batch_id
        assert batches[1].idempotency_root_hash == batches[0].idempotency_key_hash


def test_unknown_legacy_idempotency_key_remains_fatal(
    database,
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "retained-unknown-idempotency"
    advisory_id = "GHSA-aaaa-bbbb-5005"
    _seed_legacy_empty(
        database,
        evidence_root=evidence_root,
        advisory_id=advisory_id,
        updated_at=NOW,
        idempotency_key_override="unsupported-legacy-idempotency",
    )
    run_id = _inventory(
        database,
        observations=(SourceInventoryObservation(advisory_id, NOW),),
        run_name="retained-unknown-idempotency",
    )

    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(RetainedReplayError, match="legacy idempotency identity changed"),
    ):
        _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=run_id,
        )


def test_legacy_null_modified_time_does_not_weaken_source_record_identity(
    database,
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "retained-null-modified-time-wrong-source-record"
    advisory_id = "GHSA-aaaa-bbbb-5003"
    _seed_legacy_empty(
        database,
        evidence_root=evidence_root,
        advisory_id=advisory_id,
        updated_at=NOW,
        omit_evidence_modified_at=True,
        evidence_source_record_at=NOW + timedelta(seconds=1),
    )
    run_id = _inventory(
        database,
        observations=(SourceInventoryObservation(advisory_id, NOW),),
        run_name="retained-null-modified-time-wrong-source-record",
    )
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(RetainedReplayError, match="source identity changed"),
    ):
        _replay(
            session,
            evidence_root=evidence_root,
            inventory_run_id=run_id,
        )
