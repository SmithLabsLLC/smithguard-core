"""Transactional, retry-safe ingestion over bounded acquisition and normalization."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from functools import wraps
from hashlib import sha256
from typing import Any, Concatenate

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.acquisition import (
    JSON_MEDIA_TYPES,
    AcquisitionLimits,
    AcquisitionRejected,
    AcquisitionRequest,
    OperationDeadline,
    inspect_evidence,
)
from smithguard.contracts.runtime import parse_contract
from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import EvidenceRecord, IngestionBatchRecord
from smithguard.db.repository import RevisionConflict, append_contract, latest_contract
from smithguard.evidence import EvidenceStore
from smithguard.evidence_finalization import (
    EvidenceFinalizationError,
    _prepare_evidence_stage,
    _register_prepared_evidence_stage,
)
from smithguard.identifiers import canonical_json_bytes, sha256_id, stable_id, timestamp
from smithguard.normalization import (
    NormalizationContext,
    NormalizationRejected,
    NormalizedRecord,
    normalize_record,
)
from smithguard.source_governance import (
    SourceAuthorization,
    SourceGovernanceError,
    append_governance_decision,
)


class IngestionReplayConflict(ValueError):
    """An idempotency key was reused for a different bounded request."""


class IngestionSourceError(ValueError):
    """The source configuration cannot authorize this ingestion."""


DEFAULT_PROCESSING_VERSION = "mx-006.1"
PROCESSING_VERSION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,79}$")


def _atomic_ingestion[**P, R](
    function: Callable[Concatenate[Session, P], R],
) -> Callable[Concatenate[Session, P], R]:
    """Keep a handled ingestion failure from committing partial database state."""

    @wraps(function)
    def wrapped(session: Session, *args: P.args, **kwargs: P.kwargs) -> R:
        with session.begin_nested():
            return function(session, *args, **kwargs)

    return wrapped


@dataclass(frozen=True, slots=True)
class IngestionOutcome:
    batch_id: str
    outcome: str
    input_sha256: str
    raw_evidence_id: str | None
    governance_decision_id: str | None
    quarantine_reasons: tuple[str, ...]
    record_count: int
    normalized_record_ids: tuple[str, ...]
    coverage: tuple[dict[str, Any], ...]
    created: bool


def _hash_key(value: str) -> str:
    if not value or len(value) > 256:
        raise ValueError("idempotency key must contain between 1 and 256 characters")
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _outcome(record: IngestionBatchRecord, *, created: bool) -> IngestionOutcome:
    return IngestionOutcome(
        batch_id=record.batch_id,
        outcome=record.outcome,
        input_sha256=record.input_sha256,
        raw_evidence_id=record.raw_evidence_id,
        governance_decision_id=record.governance_decision_id,
        quarantine_reasons=tuple(record.quarantine_reasons),
        record_count=record.record_count,
        normalized_record_ids=tuple(record.normalized_record_ids),
        coverage=tuple(record.coverage),
        created=created,
    )


def _request_identity(
    request: AcquisitionRequest,
    input_sha256: str,
    *,
    include_source_modified_at: bool,
) -> dict[str, Any]:
    identity = {
        "source_record_id": request.source_record_id,
        "canonical_url": request.canonical_url,
        "source_published_at": (
            timestamp(request.source_published_at)
            if request.source_published_at is not None
            else None
        ),
        "media_type": request.media_type,
        "declared_content_length": request.declared_content_length,
        "redirect_count": request.redirect_count,
        "input_sha256": input_sha256,
    }
    if include_source_modified_at:
        identity["source_modified_at"] = (
            timestamp(request.source_modified_at)
            if request.source_modified_at is not None
            else None
        )
    return identity


def _request_hash(request: AcquisitionRequest, input_sha256: str) -> str:
    # Retrieval time and transport duration are observations of this fetch, not the
    # identity of the immutable upstream version. Excluding them lets a collector
    # safely replay one provider cursor page after a crash without creating a
    # conflicting idempotency request.
    return sha256_id(
        canonical_json_bytes(
            _request_identity(
                request,
                input_sha256,
                include_source_modified_at=True,
            )
        )
    )


def _compatible_request_hashes(
    request: AcquisitionRequest,
    input_sha256: str,
) -> set[str]:
    return {
        _request_hash(request, input_sha256),
        sha256_id(
            canonical_json_bytes(
                _request_identity(
                    request,
                    input_sha256,
                    include_source_modified_at=False,
                )
            )
        ),
    }


def _governed_request_hash(
    request: AcquisitionRequest,
    input_sha256: str,
    governance: SourceAuthorization,
    *,
    include_source_modified_at: bool,
) -> str:
    return sha256_id(
        canonical_json_bytes(
            {
                **_request_identity(
                    request,
                    input_sha256,
                    include_source_modified_at=include_source_modified_at,
                ),
                "governance": {
                    "policy_id": governance.policy_id,
                    "policy_version": governance.policy_version,
                    "policy_sha256": governance.policy_sha256,
                    "rights_register_id": governance.rights_register_id,
                    "authorized_disposition_adapter_ids": list(
                        governance.authorized_disposition_adapter_ids
                    ),
                    "connector_id": governance.connector_id,
                    "operating_mode": governance.operating_mode,
                    "acquisition_method": governance.acquisition_method,
                    "field_policy_id": governance.field_policy_id,
                    "rights_evidence_verified": governance.rights_evidence_verified,
                    "qualified_publication_decision_id": (
                        governance.qualified_publication_decision_id
                    ),
                },
            }
        )
    )


def _compatible_governed_request_hashes(
    request: AcquisitionRequest,
    input_sha256: str,
    governance: SourceAuthorization,
) -> set[str]:
    return {
        _governed_request_hash(
            request,
            input_sha256,
            governance,
            include_source_modified_at=True,
        ),
        _governed_request_hash(
            request,
            input_sha256,
            governance,
            include_source_modified_at=False,
        ),
    }


def _raw_evidence_document(
    *,
    source: Mapping[str, Any],
    request: AcquisitionRequest,
    input_sha256: str,
    byte_count: int,
    media_type: str,
) -> tuple[dict[str, Any], bool]:
    rights = source["rights"]
    retain = rights["raw_storage"] == "allowed" and rights["retention"] in {
        "immutable_permitted",
        "until_withdrawn",
    }
    if retain:
        storage_state = "stored_immutable"
    elif rights["raw_storage"] == "link_only":
        storage_state = "link_only"
    else:
        storage_state = "not_retained"
    recorded_at = timestamp(request.retrieved_at)
    evidence_id = stable_id(
        "evidence",
        source["id"],
        request.source_record_id,
        input_sha256,
    )
    document = {
        "id": evidence_id,
        "kind": "raw_evidence",
        "schema_version": "1.0.0",
        "revision": 1,
        "created_at": recorded_at,
        "updated_at": recorded_at,
        "data_classification": "restricted_source",
        "source_id": source["id"],
        "source_record_id": request.source_record_id,
        "canonical_url": request.canonical_url,
        "retrieved_at": recorded_at,
        "source_published_at": (
            timestamp(request.source_published_at)
            if request.source_published_at is not None
            else None
        ),
        "source_modified_at": (
            timestamp(request.source_modified_at)
            if request.source_modified_at is not None
            else None
        ),
        "sha256": input_sha256,
        "byte_count": byte_count,
        "media_type": media_type,
        "storage_state": storage_state,
        "rights_decision": rights["decision"],
        "quarantine_reasons": [],
    }
    return (
        parse_contract("RawEvidence", document).model_dump(mode="json", exclude_none=False),
        retain,
    )


def _normalize_all(
    *,
    records: tuple[Mapping[str, Any], ...],
    source: Mapping[str, Any],
    raw_evidence: Mapping[str, Any],
    collection_method: str,
    identity_verification: str,
    signature_state: str,
) -> tuple[NormalizedRecord, ...]:
    context = NormalizationContext(
        source=source,
        raw_evidence=raw_evidence,
        collection_method=collection_method,
        identity_verification=identity_verification,
        signature_state=signature_state,
    )
    return tuple(normalize_record(record, context=context) for record in records)


def _append_batch(
    session: Session,
    *,
    batch_id: str,
    source_id: str,
    idempotency_key_hash: str,
    idempotency_root_hash: str,
    request_hash: str,
    input_sha256: str,
    processing_version: str,
    retry_of_batch_id: str | None,
    outcome: str,
    raw_evidence_id: str | None,
    governance_decision_id: str | None,
    quarantine_reasons: list[str],
    record_count: int,
    normalized_record_ids: list[str],
    coverage: list[dict[str, Any]],
    completed_at: Any,
) -> IngestionBatchRecord:
    record = IngestionBatchRecord(
        batch_id=batch_id,
        source_id=source_id,
        idempotency_key_hash=idempotency_key_hash,
        idempotency_root_hash=idempotency_root_hash,
        request_hash=request_hash,
        input_sha256=input_sha256,
        representation_hash=input_sha256,
        processing_version=processing_version,
        retry_of_batch_id=retry_of_batch_id,
        outcome=outcome,
        raw_evidence_id=raw_evidence_id,
        governance_decision_id=governance_decision_id,
        quarantine_reasons=quarantine_reasons,
        record_count=record_count,
        normalized_record_ids=normalized_record_ids,
        coverage=coverage,
        completed_at=completed_at,
    )
    session.add(record)
    session.flush()
    return record


def _normalized_semantic_document(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in document.items()
        if key not in {"revision", "created_at", "updated_at", "provenance"}
    }


def _lineage_enrichment_revision(
    existing: Mapping[str, Any],
    current: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Append current provenance only when it fills a legacy lineage gap."""
    existing_provenance = existing.get("provenance")
    current_provenance = current.get("provenance")
    if not isinstance(existing_provenance, Mapping) or not isinstance(
        current_provenance,
        Mapping,
    ):
        return None
    if existing_provenance.get("claim_lineage") is not None:
        return None
    if not isinstance(current_provenance.get("claim_lineage"), Mapping):
        return None
    return {
        **current,
        "revision": int(existing["revision"]) + 1,
        "created_at": existing["created_at"],
    }


def _reuse_raw_evidence(
    session: Session,
    raw_evidence: dict[str, Any],
    retain: bool,
) -> tuple[EvidenceRecord | None, dict[str, Any], bool]:
    existing_evidence = latest_contract(
        session,
        "RawEvidence",
        raw_evidence["id"],
    )
    if existing_evidence is not None:
        comparable_fields = {
            "source_id",
            "source_record_id",
            "canonical_url",
            "source_published_at",
            "sha256",
            "byte_count",
            "media_type",
            "storage_state",
            "rights_decision",
        }
        if any(
            existing_evidence.document.get(field) != raw_evidence.get(field)
            for field in comparable_fields
        ) or (
            "source_modified_at" in existing_evidence.document
            and existing_evidence.document["source_modified_at"]
            != raw_evidence["source_modified_at"]
        ):
            raise IngestionReplayConflict(
                "raw evidence identity conflicts with an earlier acquisition"
            )
        raw_evidence = existing_evidence.document
        retain = raw_evidence["storage_state"] == "stored_immutable"
    return existing_evidence, raw_evidence, retain


def _stage_retained_evidence(
    session: Session,
    *,
    evidence_store: EvidenceStore,
    retain: bool,
    existing_evidence: EvidenceRecord | None,
    raw_evidence: dict[str, Any],
    accepted_body: bytes,
    accepted_request: AcquisitionRequest,
    input_sha256: str,
    operation_deadline: OperationDeadline,
) -> str | None:
    storage_key: str | None = None
    if retain:
        operation_deadline.check()
        preparation = _prepare_evidence_stage(
            session, digest=input_sha256, byte_count=len(accepted_body)
        )
        operation_deadline.check()
        if existing_evidence is not None:
            if existing_evidence.storage_key != input_sha256:
                raise EvidenceFinalizationError(
                    "stored evidence row has inconsistent immutable metadata"
                )
            finalization = preparation.existing
            if finalization is not None and finalization.state == "finalized":
                # Finalization owns a content digest, while several immutable
                # acquisition records may legitimately refer to that same blob.
                # Preserve the first owner's identity and validate its content.
                owner = (
                    existing_evidence
                    if finalization.evidence_id == existing_evidence.id
                    else latest_contract(session, "RawEvidence", finalization.evidence_id)
                )
                if (
                    owner is None
                    or owner.sha256 != input_sha256
                    or owner.byte_count != len(accepted_body)
                    or owner.storage_key != input_sha256
                    or finalization.byte_count != len(accepted_body)
                    or finalization.staging_key != input_sha256
                ):
                    raise EvidenceFinalizationError(
                        "finalized evidence metadata conflicts with the stored evidence row"
                    )
                verified = evidence_store.verify(input_sha256)
                if (
                    verified.digest != input_sha256
                    or verified.byte_count != len(accepted_body)
                    or verified.storage_key != input_sha256
                ):
                    raise EvidenceFinalizationError(
                        "finalized evidence adapter returned inconsistent metadata"
                    )
                storage_key = verified.storage_key
        if storage_key is None:
            stage = evidence_store.stage_bytes(accepted_body)
            if stage.digest != input_sha256 or stage.byte_count != len(accepted_body):
                evidence_store.discard_stage(stage)
                raise RuntimeError("immutable evidence adapter returned inconsistent metadata")
            _register_prepared_evidence_stage(
                session,
                preparation=preparation,
                store=evidence_store,
                stage=stage,
                evidence_id=raw_evidence["id"],
                staged_at=accepted_request.retrieved_at,
            )
            operation_deadline.check()
            storage_key = stage.storage_key
    return storage_key


def _persist_normalized_records(
    session: Session,
    normalized: tuple[NormalizedRecord, ...],
    operation_deadline: OperationDeadline,
) -> tuple[set[str], dict[str, dict[str, Any]]]:
    normalized_ids: set[str] = set()
    coverage_by_ecosystem: dict[str, dict[str, Any]] = {}
    for item in normalized:
        operation_deadline.check()
        for definition, document in item.contract_records:
            if definition == "Artifact":
                existing_artifact = latest_contract(session, definition, document["id"])
                if existing_artifact is not None:
                    identity_fields = {
                        "ecosystem",
                        "name",
                        "coordinate",
                        "version",
                        "digest",
                        "identity_state",
                    }
                    if any(
                        existing_artifact.document[field] != document[field]
                        for field in identity_fields
                    ):
                        raise RevisionConflict(
                            "normalized artifact identity conflicts with canonical state"
                        )
                else:
                    append_contract(session, definition, document)
            else:
                existing_normalized = latest_contract(session, definition, document["id"])
                if existing_normalized is None:
                    append_contract(session, definition, document)
                elif _normalized_semantic_document(
                    existing_normalized.document
                ) != _normalized_semantic_document(document):
                    raise RevisionConflict(
                        f"normalized {definition.lower()} identity conflicts with canonical state"
                    )
                else:
                    enriched = _lineage_enrichment_revision(
                        existing_normalized.document,
                        document,
                    )
                    if enriched is not None:
                        append_contract(session, definition, enriched)
            normalized_ids.add(document["id"])
        coverage_by_ecosystem[item.coverage["ecosystem"]] = item.coverage
    return normalized_ids, coverage_by_ecosystem


@dataclass(frozen=True, slots=True)
class _PreparedEvidence:
    accepted_body: bytes | None
    accepted_request: AcquisitionRequest | None
    raw_evidence: dict[str, Any] | None
    retain: bool
    records: tuple[Mapping[str, Any], ...]
    quarantine_reason: str | None


def _inspect_and_project_evidence(
    *,
    source_document: Mapping[str, Any],
    request: AcquisitionRequest,
    body: bytes,
    governance: SourceAuthorization,
    effective_limits: AcquisitionLimits,
    operation_deadline: OperationDeadline,
    record_transform: Callable[[tuple[Mapping[str, Any], ...]], tuple[Mapping[str, Any], ...]]
    | None,
    allow_empty_transformed_records: bool,
) -> _PreparedEvidence:
    accepted_body: bytes | None = None
    accepted_request: AcquisitionRequest | None = None
    raw_evidence: dict[str, Any] | None = None
    retain = False
    records: tuple[Mapping[str, Any], ...] = ()
    quarantine_reason: str | None = None
    try:
        inspected_input = inspect_evidence(
            source=source_document,
            request=request,
            body=body,
            limits=effective_limits,
            deadline=operation_deadline,
            allow_extra_json_envelope_fields=True,
        )
        if inspected_input.media_type not in JSON_MEDIA_TYPES:
            raise NormalizationRejected("source_governance_json_required")
        operation_deadline.check()
        accepted_body = governance.project_body(body)
        operation_deadline.check()
        accepted_request = replace(
            request,
            declared_content_length=len(accepted_body),
        )
        inspected = inspect_evidence(
            source=source_document,
            request=accepted_request,
            body=accepted_body,
            limits=effective_limits,
            deadline=operation_deadline,
        )
        raw_evidence, retain = _raw_evidence_document(
            source=source_document,
            request=accepted_request,
            input_sha256=inspected.digest,
            byte_count=inspected.byte_count,
            media_type=inspected.media_type,
        )
        operation_deadline.check()
        records = (
            record_transform(inspected.records)
            if record_transform is not None
            else inspected.records
        )
        operation_deadline.check()
        if not records and not allow_empty_transformed_records:
            raise NormalizationRejected("empty_transformed_record_set")
    except (AcquisitionRejected, NormalizationRejected) as error:
        quarantine_reason = error.code
    except SourceGovernanceError as error:
        raise IngestionSourceError(str(error)) from error
    return _PreparedEvidence(
        accepted_body, accepted_request, raw_evidence, retain, records, quarantine_reason
    )


@dataclass(frozen=True, slots=True)
class _IngestionIdentity:
    key_hash: str
    batch_id: str
    retry_of_batch_id: str | None


def _resolve_ingestion_identity(
    session: Session,
    *,
    source_document: Mapping[str, Any],
    key_hash: str,
    batch_id: str,
    root_key_hash: str,
    request_digest: str,
    identity_request: AcquisitionRequest,
    request: AcquisitionRequest,
    input_sha256: str,
    raw_input_sha256: str,
    governance: SourceAuthorization,
    retry_quarantined: bool,
    processing_version: str,
    operation_deadline: OperationDeadline,
) -> _IngestionIdentity | IngestionOutcome:
    retry_of_batch_id: str | None = None
    lock_name = f"ingestion:{source_document['id']}:{key_hash}"
    operation_deadline.check()
    advisory_xact_lock(session, lock_name)
    existing = session.scalar(
        select(IngestionBatchRecord).where(
            IngestionBatchRecord.source_id == source_document["id"],
            IngestionBatchRecord.idempotency_key_hash == key_hash,
        )
    )
    if existing is not None:
        compatible_hashes = _compatible_governed_request_hashes(
            identity_request,
            input_sha256,
            governance,
        )
        if existing.governance_decision_id is None:
            compatible_hashes |= _compatible_request_hashes(
                identity_request,
                input_sha256,
            ) | _compatible_request_hashes(request, raw_input_sha256)
        if existing.request_hash not in compatible_hashes:
            raise IngestionReplayConflict("idempotency key was reused for another request")
        if existing.outcome == "quarantined" and retry_quarantined:
            retry_of_batch_id = existing.batch_id
            # The token proves that a trusted scheduler requested another try. It is
            # deliberately not part of the attempt identity: unchanged governed
            # bytes under unchanged processor code must converge instead of growing
            # one quarantine row per timer invocation.
            key_hash = sha256_id(
                canonical_json_bytes(
                    {
                        "idempotency_root_hash": root_key_hash,
                        "processing_version": processing_version,
                        "request_hash": request_digest,
                    }
                )
            )
            batch_id = stable_id("ingestion", source_document["id"], key_hash)
            retry_lock_name = f"ingestion:{source_document['id']}:{key_hash}"
            advisory_xact_lock(session, retry_lock_name)
            retry_existing = session.scalar(
                select(IngestionBatchRecord).where(
                    IngestionBatchRecord.source_id == source_document["id"],
                    IngestionBatchRecord.idempotency_key_hash == key_hash,
                )
            )
            if retry_existing is not None:
                if retry_existing.request_hash not in compatible_hashes:
                    raise IngestionReplayConflict(
                        "quarantine retry key was reused for another request"
                    )
                return _outcome(retry_existing, created=False)
        elif existing.governance_decision_id is not None or existing.outcome == "quarantined":
            return _outcome(existing, created=False)
        else:
            retry_of_batch_id = existing.batch_id
            key_hash = sha256_id(
                canonical_json_bytes(
                    {
                        "legacy_idempotency_key_hash": key_hash,
                        "policy_sha256": governance.policy_sha256,
                    }
                )
            )
            batch_id = stable_id("ingestion", source_document["id"], key_hash)
            governed_lock_name = f"ingestion:{source_document['id']}:{key_hash}"
            advisory_xact_lock(session, governed_lock_name)
            governed_existing = session.scalar(
                select(IngestionBatchRecord).where(
                    IngestionBatchRecord.source_id == source_document["id"],
                    IngestionBatchRecord.idempotency_key_hash == key_hash,
                )
            )
            if governed_existing is not None:
                if governed_existing.request_hash not in _compatible_governed_request_hashes(
                    identity_request,
                    input_sha256,
                    governance,
                ):
                    raise IngestionReplayConflict(
                        "policy-scoped idempotency key was reused for another request"
                    )
                return _outcome(governed_existing, created=False)
    return _IngestionIdentity(key_hash, batch_id, retry_of_batch_id)


@_atomic_ingestion
def ingest_bytes(
    session: Session,
    *,
    evidence_store: EvidenceStore,
    source: Mapping[str, Any],
    governance: SourceAuthorization,
    request: AcquisitionRequest,
    body: bytes,
    idempotency_key: str,
    collection_method: str,
    identity_verification: str = "unverified",
    signature_state: str = "unknown",
    limits: AcquisitionLimits | None = None,
    record_transform: Callable[
        [tuple[Mapping[str, Any], ...]],
        tuple[Mapping[str, Any], ...],
    ]
    | None = None,
    allow_empty_transformed_records: bool = False,
    deadline: OperationDeadline | None = None,
    retry_quarantined: bool = False,
    retry_token: str | None = None,
    processing_version: str = DEFAULT_PROCESSING_VERSION,
) -> IngestionOutcome:
    """Validate a complete batch, then append all-or-no canonical database state."""
    if PROCESSING_VERSION_PATTERN.fullmatch(processing_version) is None:
        raise ValueError("processing version must be 2 to 80 lowercase ASCII characters")
    if retry_quarantined and (
        retry_token is None or not retry_token.isascii() or not 1 <= len(retry_token) <= 160
    ):
        raise ValueError("retryable quarantine requires a bounded ASCII retry token")
    if not retry_quarantined and retry_token is not None:
        raise ValueError("retry token is allowed only for retryable quarantine")
    effective_limits = limits or AcquisitionLimits()
    operation_deadline = deadline or OperationDeadline.start(
        effective_limits.max_elapsed_seconds,
    )
    operation_deadline.check()
    source_model: BaseModel = parse_contract("Source", source)
    source_document = source_model.model_dump(mode="json", exclude_none=False)
    if collection_method not in source_document["acquisition_methods"]:
        raise IngestionSourceError("collection method is not approved for the source")
    try:
        governance.validate_request(
            source_id=source_document["id"],
            source_record_id=request.source_record_id,
            canonical_url=request.canonical_url,
            acquisition_method=collection_method,
        )
    except SourceGovernanceError as error:
        raise IngestionSourceError(str(error)) from error

    key_hash = _hash_key(idempotency_key)
    root_key_hash = key_hash
    batch_id = stable_id("ingestion", source_document["id"], key_hash)
    raw_input_sha256 = sha256_id(body)
    prepared = _inspect_and_project_evidence(
        source_document=source_document,
        request=request,
        body=body,
        governance=governance,
        effective_limits=effective_limits,
        operation_deadline=operation_deadline,
        record_transform=record_transform,
        allow_empty_transformed_records=allow_empty_transformed_records,
    )
    accepted_body = prepared.accepted_body
    accepted_request = prepared.accepted_request
    raw_evidence = prepared.raw_evidence
    retain = prepared.retain
    records = prepared.records
    quarantine_reason = prepared.quarantine_reason

    input_sha256 = sha256_id(accepted_body) if accepted_body is not None else raw_input_sha256
    identity_request = accepted_request or request
    request_digest = _governed_request_hash(
        identity_request,
        input_sha256,
        governance,
        include_source_modified_at=True,
    )
    identity = _resolve_ingestion_identity(
        session,
        source_document=source_document,
        key_hash=key_hash,
        batch_id=batch_id,
        root_key_hash=root_key_hash,
        request_digest=request_digest,
        identity_request=identity_request,
        request=request,
        input_sha256=input_sha256,
        raw_input_sha256=raw_input_sha256,
        governance=governance,
        retry_quarantined=retry_quarantined,
        processing_version=processing_version,
        operation_deadline=operation_deadline,
    )
    if isinstance(identity, IngestionOutcome):
        return identity
    key_hash = identity.key_hash
    batch_id = identity.batch_id
    retry_of_batch_id = identity.retry_of_batch_id

    append_contract(session, "Source", source_document)
    if quarantine_reason is not None:
        record = _append_batch(
            session,
            batch_id=batch_id,
            source_id=source_document["id"],
            idempotency_key_hash=key_hash,
            idempotency_root_hash=root_key_hash,
            request_hash=request_digest,
            input_sha256=input_sha256,
            processing_version=processing_version,
            retry_of_batch_id=retry_of_batch_id,
            outcome="quarantined",
            raw_evidence_id=None,
            governance_decision_id=None,
            quarantine_reasons=[quarantine_reason],
            record_count=0,
            normalized_record_ids=[],
            coverage=[],
            completed_at=request.retrieved_at,
        )
        return _outcome(record, created=True)

    if accepted_body is None or accepted_request is None or raw_evidence is None:
        raise RuntimeError("accepted ingestion has no governed representation")
    existing_evidence, raw_evidence, retain = _reuse_raw_evidence(session, raw_evidence, retain)
    try:
        operation_deadline.check()
        normalized = _normalize_all(
            records=records,
            source=source_document,
            raw_evidence=raw_evidence,
            collection_method=collection_method,
            identity_verification=identity_verification,
            signature_state=signature_state,
        )
        operation_deadline.check()
    except NormalizationRejected as error:
        record = _append_batch(
            session,
            batch_id=batch_id,
            source_id=source_document["id"],
            idempotency_key_hash=key_hash,
            idempotency_root_hash=root_key_hash,
            request_hash=request_digest,
            input_sha256=input_sha256,
            processing_version=processing_version,
            retry_of_batch_id=retry_of_batch_id,
            outcome="quarantined",
            raw_evidence_id=None,
            governance_decision_id=None,
            quarantine_reasons=[error.code],
            record_count=0,
            normalized_record_ids=[],
            coverage=[],
            completed_at=request.retrieved_at,
        )
        return _outcome(record, created=True)
    operation_deadline.check()
    governance_decision, _created = append_governance_decision(
        session,
        authorization=governance,
        accepted_sha256=input_sha256,
        decided_at=accepted_request.retrieved_at,
    )
    operation_deadline.check()
    storage_key = _stage_retained_evidence(
        session,
        evidence_store=evidence_store,
        retain=retain,
        existing_evidence=existing_evidence,
        raw_evidence=raw_evidence,
        accepted_body=accepted_body,
        accepted_request=accepted_request,
        input_sha256=input_sha256,
        operation_deadline=operation_deadline,
    )
    append_contract(
        session,
        "RawEvidence",
        raw_evidence,
        storage_key=storage_key,
    )
    normalized_ids, coverage_by_ecosystem = _persist_normalized_records(
        session,
        normalized,
        operation_deadline,
    )
    record = _append_batch(
        session,
        batch_id=batch_id,
        source_id=source_document["id"],
        idempotency_key_hash=key_hash,
        idempotency_root_hash=root_key_hash,
        request_hash=request_digest,
        input_sha256=input_sha256,
        processing_version=processing_version,
        retry_of_batch_id=retry_of_batch_id,
        outcome="accepted",
        raw_evidence_id=raw_evidence["id"],
        governance_decision_id=governance_decision.decision_id,
        quarantine_reasons=[],
        record_count=len(normalized),
        normalized_record_ids=sorted(normalized_ids),
        coverage=[coverage_by_ecosystem[key] for key in sorted(coverage_by_ecosystem)],
        completed_at=request.retrieved_at,
    )
    operation_deadline.check()
    return _outcome(record, created=True)
