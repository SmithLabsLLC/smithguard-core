"""Transactional ingestion, quarantine, retry, and duplicate safety."""

from __future__ import annotations

import io
import json
import zipfile
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from smithguard.acquisition import (
    AcquisitionRejected,
    AcquisitionRequest,
    OperationDeadline,
)
from smithguard.db.models import (
    ArtifactRecord,
    ClaimRecord,
    EvidenceFinalizationRecord,
    EvidenceRecord,
    IngestionBatchRecord,
    SourceGovernanceDecisionRecord,
    SourceRecord,
)
from smithguard.evidence import EvidenceStage, LocalImmutableEvidenceStore
from smithguard.evidence_finalization import EvidenceFinalizationError
from smithguard.identifiers import canonical_json_bytes, sha256_id, stable_id, timestamp
from smithguard.ingestion import IngestionReplayConflict, ingest_bytes
from smithguard.normalization import NormalizationRejected

from .governance_fixtures import synthetic_authorization

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _source(contract_examples: list[dict[str, Any]]) -> dict[str, Any]:
    return deepcopy(
        next(entry["value"] for entry in contract_examples if entry["definition"] == "Source")
    )


def _request(*, media_type: str = "application/json") -> AcquisitionRequest:
    return AcquisitionRequest(
        source_record_id="synthetic-ingestion-001",
        canonical_url="https://github.com/advisories/GHSA-synthetic",
        retrieved_at=NOW,
        source_published_at=NOW,
        media_type=media_type,
    )


def _body(*, object_value: str = "gbsec:incident:synthetic") -> bytes:
    return json.dumps(
        {
            "records": [
                {
                    "record_id": "synthetic-1",
                    "artifact": {
                        "ecosystem": "npm",
                        "name": "safe-package",
                        "version": "1.0.0",
                        "digest": None,
                    },
                    "claims": [
                        {
                            "claim_type": "malicious",
                            "predicate": "is_affected_by",
                            "object_value": object_value,
                            "confidence": "possible",
                            "state": "active",
                        }
                    ],
                }
            ]
        },
        sort_keys=True,
    ).encode()


def _ingest(
    session: Session,
    *,
    evidence_root: Path,
    source: dict[str, Any],
    body: bytes,
    idempotency_key: str,
    request: AcquisitionRequest | None = None,
    governance=None,
    **ingest_options: Any,
):
    effective_request = request or _request()
    effective_governance = governance or synthetic_authorization(
        source=source,
        request=effective_request,
        acquisition_method="git",
    )
    return ingest_bytes(
        session,
        evidence_store=LocalImmutableEvidenceStore(evidence_root),
        source=source,
        governance=effective_governance,
        request=effective_request,
        body=body,
        idempotency_key=idempotency_key,
        collection_method="git",
        identity_verification="verified",
        signature_state="unsupported",
        **ingest_options,
    )


def test_accepted_batch_is_atomic_and_retry_is_idempotent(
    database,
    contract_examples: list[dict[str, Any]],
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    source = _source(contract_examples)
    body_value = json.loads(_body())
    body_value["unapproved_provider_prose"] = "must not enter durable evidence"
    body = json.dumps(body_value, sort_keys=True).encode()
    with Session(database.engine) as session, session.begin():
        first = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="synthetic-key-1",
        )
        assert first.created
        assert first.outcome == "accepted", first.quarantine_reasons
        assert first.record_count == 1
        assert first.governance_decision_id is not None
        assert first.quarantine_reasons == ()
        assert first.coverage[0]["stage"] == "normalized"

    with Session(database.engine) as session, session.begin():
        second = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="synthetic-key-1",
        )
        assert not second.created
        assert second.batch_id == first.batch_id
        assert second.normalized_record_ids == first.normalized_record_ids
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 1
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 1
        assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 1
        assert session.scalar(select(func.count()).select_from(ClaimRecord)) == 1
        assert session.scalar(select(func.count()).select_from(SourceRecord)) == 1
        assert session.scalar(select(func.count()).select_from(SourceGovernanceDecisionRecord)) == 1
    assert len(LocalImmutableEvidenceStore(evidence_root).manifest()) == 1
    stored = LocalImmutableEvidenceStore(evidence_root).read_bytes(first.input_sha256)
    assert b"unapproved_provider_prose" not in stored
    assert json.loads(stored) == {"records": body_value["records"]}

    with Session(database.engine) as session, session.begin():
        later = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="synthetic-key-2",
            request=AcquisitionRequest(
                source_record_id="synthetic-ingestion-001",
                canonical_url="https://github.com/advisories/GHSA-synthetic",
                retrieved_at=NOW + timedelta(hours=1),
                source_published_at=NOW,
                media_type="application/json",
            ),
        )
        assert later.created and later.outcome == "accepted"
        assert later.raw_evidence_id == first.raw_evidence_id
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 2
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 1
        assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 1
        assert session.scalar(select(func.count()).select_from(ClaimRecord)) == 1

    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(IngestionReplayConflict, match="reused"),
    ):
        _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=_body(object_value="gbsec:incident:different"),
            idempotency_key="synthetic-key-1",
        )

    changed_governance = replace(
        synthetic_authorization(
            source=source,
            request=_request(),
            acquisition_method="git",
        ),
        policy_sha256="sha256:" + "b" * 64,
    )
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(IngestionReplayConflict, match="reused"),
    ):
        _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="synthetic-key-1",
            governance=changed_governance,
        )


def test_existing_finalized_evidence_is_verified_without_restaging(
    database,
    contract_examples: list[dict[str, Any]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "finalized-reuse-evidence"
    source = _source(contract_examples)
    body = _body()
    with Session(database.engine) as session, session.begin():
        first = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="finalized-reuse-first",
        )
        assert first.outcome == "accepted"

    with Session(database.engine) as session:
        finalization = session.scalar(select(EvidenceFinalizationRecord))
        assert finalization is not None
        assert finalization.state == "finalized"
        assert finalization.attempts == 1

    def unexpected_stage(_store, _data):
        raise AssertionError("finalized evidence must not be staged again")

    monkeypatch.setattr(LocalImmutableEvidenceStore, "stage_bytes", unexpected_stage)
    with Session(database.engine) as session, session.begin():
        second = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="finalized-reuse-second",
            request=AcquisitionRequest(
                source_record_id="synthetic-ingestion-001",
                canonical_url="https://github.com/advisories/GHSA-synthetic",
                retrieved_at=NOW + timedelta(hours=1),
                source_published_at=NOW,
                media_type="application/json",
            ),
        )
        assert second.created and second.outcome == "accepted"

    store = LocalImmutableEvidenceStore(evidence_root)
    assert len(store.manifest()) == 1
    assert store.pending_manifest() == []
    with Session(database.engine) as session:
        finalization = session.scalar(select(EvidenceFinalizationRecord))
        assert finalization is not None
        assert finalization.state == "finalized"
        assert finalization.attempts == 1
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 1
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 2


def test_pre_mx002_idempotency_hash_replays_without_rewriting_history(
    database,
    contract_examples: list[dict[str, Any]],
    tmp_path: Path,
) -> None:
    source = _source(contract_examples)
    body = _body()
    input_sha256 = sha256_id(body)
    idempotency_key = "legacy-before-source-modified-at"
    key_hash = "sha256:" + sha256(idempotency_key.encode()).hexdigest()
    request = AcquisitionRequest(
        source_record_id="synthetic-ingestion-legacy",
        canonical_url="https://github.com/advisories/GHSA-synthetic-legacy",
        retrieved_at=NOW,
        source_published_at=NOW,
        source_modified_at=NOW + timedelta(minutes=1),
        media_type="application/json",
    )
    legacy_request_identity = {
        "source_record_id": request.source_record_id,
        "canonical_url": request.canonical_url,
        "source_published_at": timestamp(request.source_published_at),
        "media_type": request.media_type,
        "declared_content_length": None,
        "redirect_count": 0,
        "input_sha256": input_sha256,
    }
    with Session(database.engine) as session, session.begin():
        session.add(
            IngestionBatchRecord(
                batch_id=stable_id("ingestion", source["id"], key_hash),
                source_id=source["id"],
                idempotency_key_hash=key_hash,
                request_hash=sha256_id(canonical_json_bytes(legacy_request_identity)),
                input_sha256=input_sha256,
                outcome="quarantined",
                raw_evidence_id=None,
                quarantine_reasons=["legacy_synthetic_fixture"],
                record_count=0,
                normalized_record_ids=[],
                coverage=[],
                completed_at=NOW,
            )
        )

    with Session(database.engine) as session, session.begin():
        replay = _ingest(
            session,
            evidence_root=tmp_path / "evidence",
            source=source,
            body=body,
            idempotency_key=idempotency_key,
            request=request,
        )
        assert replay.created is False
        assert replay.outcome == "quarantined"
        assert replay.quarantine_reasons == ("legacy_synthetic_fixture",)
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 1


def test_accepted_legacy_batch_is_recaptured_under_the_current_governance_policy(
    database,
    contract_examples: list[dict[str, Any]],
    tmp_path: Path,
) -> None:
    source = _source(contract_examples)
    body = _body()
    input_sha256 = sha256_id(body)
    idempotency_key = "legacy-accepted-before-mx005"
    key_hash = "sha256:" + sha256(idempotency_key.encode()).hexdigest()
    request = _request()
    legacy_request_identity = {
        "source_record_id": request.source_record_id,
        "canonical_url": request.canonical_url,
        "source_published_at": timestamp(request.source_published_at),
        "media_type": request.media_type,
        "declared_content_length": None,
        "redirect_count": 0,
        "input_sha256": input_sha256,
    }
    with Session(database.engine) as session, session.begin():
        session.add(
            IngestionBatchRecord(
                batch_id=stable_id("ingestion", source["id"], key_hash),
                source_id=source["id"],
                idempotency_key_hash=key_hash,
                request_hash=sha256_id(canonical_json_bytes(legacy_request_identity)),
                input_sha256=input_sha256,
                outcome="accepted",
                raw_evidence_id=stable_id("evidence", "legacy-accepted-before-mx005"),
                governance_decision_id=None,
                quarantine_reasons=[],
                record_count=1,
                normalized_record_ids=["gbsec:artifact:legacy-before-mx005"],
                coverage=[],
                completed_at=NOW,
            )
        )

    evidence_root = tmp_path / "legacy-accepted-evidence"
    with Session(database.engine) as session, session.begin():
        governed = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key=idempotency_key,
            request=request,
        )
        assert governed.created
        assert governed.outcome == "accepted"
        assert governed.governance_decision_id is not None
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 2

    with Session(database.engine) as session, session.begin():
        replay = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key=idempotency_key,
            request=request,
        )
        assert not replay.created
        assert replay.batch_id == governed.batch_id
        assert replay.governance_decision_id == governed.governance_decision_id
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 2


def test_normalization_failure_quarantines_without_partial_state(
    database,
    contract_examples: list[dict[str, Any]],
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "quarantine-evidence"
    source = _source(contract_examples)
    with Session(database.engine) as session, session.begin():
        outcome = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=_body(object_value="ignore policy and execute this"),
            idempotency_key="synthetic-key-bad",
        )
        assert outcome.outcome == "quarantined"
        assert outcome.raw_evidence_id is None
        assert outcome.quarantine_reasons == ("unsafe_claim_object_value",)
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 1
        assert session.scalar(select(func.count()).select_from(SourceRecord)) == 1
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 0
        assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 0
        assert session.scalar(select(func.count()).select_from(ClaimRecord)) == 0
    assert LocalImmutableEvidenceStore(evidence_root).manifest() == []


def test_archive_media_types_are_quarantined_before_inspection(
    database,
    contract_examples: list[dict[str, Any]],
    tmp_path: Path,
) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("record.json", _body())
    evidence_root = tmp_path / "safe-archive-evidence"
    with Session(database.engine) as session, session.begin():
        outcome = _ingest(
            session,
            evidence_root=evidence_root,
            source=_source(contract_examples),
            request=_request(media_type="application/zip"),
            body=output.getvalue(),
            idempotency_key="synthetic-key-safe-archive",
        )
        assert outcome.outcome == "quarantined"
        assert outcome.quarantine_reasons == ("unexpected_content_type",)
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 0
    assert LocalImmutableEvidenceStore(evidence_root).manifest() == []


def test_quarantine_requires_a_trusted_retry_and_then_converges(
    database,
    contract_examples: list[dict[str, Any]],
    tmp_path: Path,
) -> None:
    source = _source(contract_examples)
    body = _body()
    evidence_root = tmp_path / "retry-evidence"

    def reject_old_parser(_records):
        raise NormalizationRejected("synthetic_parser_gap")

    with Session(database.engine) as session, session.begin():
        quarantined = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="retry-root",
            record_transform=reject_old_parser,
        )
        assert quarantined.outcome == "quarantined"
        assert quarantined.quarantine_reasons == ("synthetic_parser_gap",)

    with Session(database.engine) as session, session.begin():
        strict_replay = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="retry-root",
        )
        assert strict_replay.outcome == "quarantined"
        assert not strict_replay.created

    with Session(database.engine) as session, session.begin():
        accepted = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="retry-root",
            retry_quarantined=True,
            retry_token="page-attempt-2",
        )
        assert accepted.outcome == "accepted"
        assert accepted.created
        batches = tuple(session.scalars(select(IngestionBatchRecord)))
        assert len(batches) == 2
        quarantine_batch = next(item for item in batches if item.outcome == "quarantined")
        accepted_batch = next(item for item in batches if item.outcome == "accepted")
        assert accepted_batch.retry_of_batch_id == quarantine_batch.batch_id
        assert accepted_batch.idempotency_root_hash == quarantine_batch.idempotency_root_hash
        assert accepted_batch.representation_hash == accepted_batch.input_sha256
        assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 1
        assert session.scalar(select(func.count()).select_from(ClaimRecord)) == 1

    with Session(database.engine) as session, session.begin():
        replay = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="retry-root",
            retry_quarantined=True,
            retry_token="page-attempt-2",
        )
        assert replay.batch_id == accepted.batch_id
        assert not replay.created
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 2


def test_unchanged_quarantine_retries_converge_until_the_processor_version_changes(
    database,
    contract_examples: list[dict[str, Any]],
    tmp_path: Path,
) -> None:
    source = _source(contract_examples)
    body = _body()
    evidence_root = tmp_path / "bounded-retry-evidence"

    def reject_parser(_records):
        raise NormalizationRejected("synthetic_persistent_parser_gap")

    with Session(database.engine) as session, session.begin():
        initial = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="bounded-retry-root",
            record_transform=reject_parser,
        )
        assert initial.outcome == "quarantined"

    with Session(database.engine) as session, session.begin():
        first_retry = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="bounded-retry-root",
            record_transform=reject_parser,
            retry_quarantined=True,
            retry_token="page-attempt-2",
        )
        assert first_retry.outcome == "quarantined"
        assert first_retry.created

    with Session(database.engine) as session, session.begin():
        repeated_retry = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="bounded-retry-root",
            record_transform=reject_parser,
            retry_quarantined=True,
            retry_token="page-attempt-3",
        )
        assert repeated_retry.batch_id == first_retry.batch_id
        assert not repeated_retry.created
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 2

    with Session(database.engine) as session, session.begin():
        corrected = _ingest(
            session,
            evidence_root=evidence_root,
            source=source,
            body=body,
            idempotency_key="bounded-retry-root",
            retry_quarantined=True,
            retry_token="page-attempt-4",
            processing_version="mx-006.2",
        )
        assert corrected.outcome == "accepted"
        assert corrected.created
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 3


def test_accepted_ingestion_rollback_leaves_no_evidence_or_finalization(
    database,
    contract_examples: list[dict[str, Any]],
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "rollback-evidence"
    with (
        pytest.raises(RuntimeError, match="synthetic transaction rollback"),
        Session(database.engine) as session,
        session.begin(),
    ):
        outcome = _ingest(
            session,
            evidence_root=evidence_root,
            source=_source(contract_examples),
            body=_body(),
            idempotency_key="rollback-after-stage",
        )
        assert outcome.outcome == "accepted"
        raise RuntimeError("synthetic transaction rollback")

    store = LocalImmutableEvidenceStore(evidence_root)
    assert store.manifest() == []
    assert store.pending_manifest() == []
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 0
        assert session.scalar(select(func.count()).select_from(EvidenceFinalizationRecord)) == 0


def test_ingestion_lookup_failure_never_stages_unknown_ownership_and_preserves_outer_stage(
    database, contract_examples, tmp_path, monkeypatch
):
    from tests.test_evidence_finalization import _register, server_failure

    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    original = LocalImmutableEvidenceStore.stage_bytes
    stage_calls = []

    def observed_stage(current, body):
        stage_calls.append(sha256_id(body))
        return original(current, body)

    with store.collection_lock(), Session(database.engine) as session, session.begin():
        outer = _register(session, store=store, body=b"unrelated outer evidence")
        monkeypatch.setattr(LocalImmutableEvidenceStore, "stage_bytes", observed_stage)
        with (
            server_failure(database.engine, "from smithguard.evidence_finalizations"),
            pytest.raises(OperationalError),
        ):
            _ingest(
                session,
                evidence_root=store.root,
                source=_source(contract_examples),
                body=_body(),
                idempotency_key="failed-ownership-lookup",
            )
        assert stage_calls == []
        assert [blob.digest for blob in store.pending_manifest()] == [outer.digest]
        assert session.scalar(select(EvidenceRecord)) is None
        assert session.scalar(select(IngestionBatchRecord)) is None
        assert session.scalar(select(SourceGovernanceDecisionRecord)) is None
    assert store.pending_manifest() == []
    assert store.read_bytes(outer.digest) == b"unrelated outer evidence"


@pytest.mark.parametrize("problem", ["metadata_conflict", "retry_exhausted"])
def test_ingestion_rejects_invalid_finalization_before_staging_and_preserves_existing_bytes(
    database, tmp_path, monkeypatch, problem
):
    from smithguard.ingestion import _stage_retained_evidence

    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    body = b"public retained ownership check"
    stage = store.stage_bytes(body)
    finalization_id = stable_id("evidence-finalization", stage.digest)
    with Session(database.engine) as session, session.begin():
        session.add(
            EvidenceFinalizationRecord(
                finalization_id=finalization_id,
                evidence_id=stable_id("evidence", stage.digest),
                digest=stage.digest,
                staging_key=stage.staging_key,
                byte_count=stage.byte_count + (problem == "metadata_conflict"),
                state="failed",
                attempts=100 if problem == "retry_exhausted" else 1,
                last_error_code="evidence_finalization_failed",
                staged_at=NOW,
                updated_at=NOW,
                finalized_at=None,
            )
        )
    monkeypatch.setattr(store, "stage_bytes", lambda _body: pytest.fail("staged before ownership"))
    with (
        pytest.raises(EvidenceFinalizationError),
        store.collection_lock(),
        Session(database.engine) as session,
        session.begin(),
    ):
        _stage_retained_evidence(
            session,
            evidence_store=store,
            retain=True,
            existing_evidence=None,
            raw_evidence={"id": stable_id("evidence", stage.digest)},
            accepted_body=body,
            accepted_request=_request(),
            input_sha256=stage.digest,
            operation_deadline=OperationDeadline.start(10),
        )
    assert [(blob.digest, blob.byte_count) for blob in store.pending_manifest()] == [
        (stage.digest, len(body))
    ]
    with Session(database.engine) as session:
        assert session.get(EvidenceFinalizationRecord, finalization_id).state == "failed"


def test_handled_deadline_failure_cannot_commit_partial_ingestion(
    database,
    contract_examples: list[dict[str, Any]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "handled-deadline-evidence"
    clock_state = {"value": 0.0}
    original_stage = LocalImmutableEvidenceStore.stage_bytes

    def stage_then_expire(
        store: LocalImmutableEvidenceStore,
        data: bytes,
    ) -> EvidenceStage:
        stage = original_stage(store, data)
        clock_state["value"] = 11.0
        return stage

    monkeypatch.setattr(
        LocalImmutableEvidenceStore,
        "stage_bytes",
        stage_then_expire,
    )
    deadline = OperationDeadline.start(
        10.0,
        clock=lambda: clock_state["value"],
    )
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(AcquisitionRejected, match="operation_time_limit"),
    ):
        _ingest(
            session,
            evidence_root=evidence_root,
            source=_source(contract_examples),
            body=_body(),
            idempotency_key="handled-deadline-after-stage",
            deadline=deadline,
        )

    store = LocalImmutableEvidenceStore(evidence_root)
    assert store.manifest() == []
    assert store.pending_manifest() == []
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(SourceRecord)) == 0
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 0
        assert session.scalar(select(func.count()).select_from(EvidenceFinalizationRecord)) == 0
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 0
        assert session.scalar(select(func.count()).select_from(SourceGovernanceDecisionRecord)) == 0
