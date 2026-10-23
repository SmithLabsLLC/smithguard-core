"""Append-only persistence for validated canonical contract revisions."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.contracts.runtime import parse_contract
from smithguard.db.locks import advisory_xact_lock
from smithguard.identifiers import canonical_json_bytes, sha256_id

from .models import (
    AffectedRangeRecord,
    ArtifactRecord,
    AuthorityDecisionRecord,
    ClaimRecord,
    ContractRecordMixin,
    EvidenceRecord,
    IncidentEventRecord,
    IncidentRecord,
    PreliminaryWarningRecord,
    RecommendedActionRecord,
    RelationshipRecord,
    SourceRecord,
)


class RevisionConflict(ValueError):
    """The same stable ID and revision have different canonical content."""


class RevisionOrderError(ValueError):
    """A new revision is not greater than the stored head revision."""


class EvidenceStorageMismatch(ValueError):
    """Stored evidence metadata does not match immutable storage state."""


class LedgerClassificationError(ValueError):
    """A valid shared contract is outside the CP-0B1 public-ledger boundary."""


PERSISTED_DEFINITIONS: dict[str, type[ContractRecordMixin]] = {
    "Source": SourceRecord,
    "RawEvidence": EvidenceRecord,
    "AuthorityDecision": AuthorityDecisionRecord,
    "Artifact": ArtifactRecord,
    "Claim": ClaimRecord,
    "AffectedRange": AffectedRangeRecord,
    "Relationship": RelationshipRecord,
    "Incident": IncidentRecord,
    "IncidentEvent": IncidentEventRecord,
    "RecommendedAction": RecommendedActionRecord,
    "PreliminaryWarning": PreliminaryWarningRecord,
}

PUBLIC_ONLY_DEFINITIONS = {
    "Relationship",
    "RecommendedAction",
    "PreliminaryWarning",
}

LEGACY_WARNING_PROVENANCE_FIELDS = (
    "qualification_basis",
    "qualification_actor_id",
    "qualification_reason",
    "qualification_sha256",
    "source_origins",
    "latest_recheck_reason",
    "latest_recheck_source_urls",
    "terminal_actor_id",
    "terminal_evidence_urls",
    "terminal_expected_revision",
)


def _canonical_bytes(document: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(document)


def _record_hash(document: Mapping[str, Any]) -> str:
    return sha256_id(_canonical_bytes(document))


def _common(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": document["id"],
        "revision": document["revision"],
        "schema_version": document["schema_version"],
        "kind": document["kind"],
        "data_classification": document["data_classification"],
        "created_at": document["created_at"],
        "updated_at": document["updated_at"],
        "record_hash": _record_hash(document),
        "document": document,
    }


def _specific(
    definition: str,
    document: dict[str, Any],
    *,
    storage_key: str | None,
) -> dict[str, Any]:
    if definition == "Source":
        return {
            "name": document["name"],
            "source_class": document["source_class"],
            "canonical_url": document["canonical_url"],
            "operator": document["operator"],
            "rights": document["rights"],
            "kill_switch": document["kill_switch"],
        }
    if definition == "RawEvidence":
        if document["storage_state"] == "stored_immutable":
            if storage_key != document["sha256"]:
                raise EvidenceStorageMismatch(
                    "stored immutable evidence requires its verified digest as storage key"
                )
        elif storage_key is not None:
            raise EvidenceStorageMismatch(
                "non-retained or quarantined evidence cannot have an immutable storage key"
            )
        return {
            "source_id": document["source_id"],
            "source_record_id": document["source_record_id"],
            "canonical_url": document["canonical_url"],
            "retrieved_at": document["retrieved_at"],
            "source_published_at": document.get("source_published_at"),
            "source_modified_at": document.get("source_modified_at"),
            "sha256": document["sha256"],
            "storage_key": storage_key,
            "byte_count": document["byte_count"],
            "media_type": document["media_type"],
            "storage_state": document["storage_state"],
            "rights_decision": document["rights_decision"],
            "quarantine_reasons": document.get("quarantine_reasons") or [],
        }
    if definition == "AuthorityDecision":
        return {
            "incident_id": document["incident_id"],
            "claim_id": document["claim_id"],
            "artifact_id": document["artifact_id"],
            "evidence_ids": document["evidence_ids"],
            "public_status": document["public_status"],
            "confirmation_method": document["confirmation_method"],
            "transport_source_id": document["transport_source_id"],
            "assertion_source_id": document.get("assertion_source_id"),
            "confirming_authority_id": document.get("confirming_authority_id"),
            "authority_policy_id": document["authority_policy_id"],
            "authority_policy_version": document["authority_policy_version"],
            "authority_rule_id": document["authority_rule_id"],
            "source_rights_register_id": document["source_rights_register_id"],
            "attribution_policy_version": document["attribution_policy_version"],
            "reason_code": document["reason_code"],
            "automated": document["automated"],
            "independent_goodboy_analysis": document["independent_goodboy_analysis"],
            "upstream_ids": document["upstream_ids"],
            "source_references": document["source_references"],
            "exception_required": document["exception_required"],
            "exception_reason_code": document.get("exception_reason_code"),
            "decided_at": document["decided_at"],
        }
    if definition == "Artifact":
        return {
            "ecosystem": document["ecosystem"],
            "name": document["name"],
            "coordinate": document["coordinate"],
            "version": document.get("version"),
            "digest": document.get("digest"),
            "identity_state": document["identity_state"],
        }
    if definition == "Claim":
        return {
            "claim_type": document["claim_type"],
            "subject_id": document["subject_id"],
            "predicate": document["predicate"],
            "object_value": document.get("object_value"),
            "confidence": document["confidence"],
            "state": document["state"],
            "valid_from": document.get("valid_from"),
            "valid_until": document.get("valid_until"),
            "supersedes_claim_id": document.get("supersedes_claim_id"),
            "provenance": document["provenance"],
        }
    if definition == "AffectedRange":
        return {
            "artifact_id": document["artifact_id"],
            "range_type": document["range_type"],
            "expression": document["expression"],
            "introduced": document.get("introduced"),
            "fixed": document.get("fixed"),
            "last_affected": document.get("last_affected"),
            "evaluation_state": document["evaluation_state"],
            "provenance": document["provenance"],
        }
    if definition == "Relationship":
        return {
            "subject_id": document["subject_id"],
            "object_id": document["object_id"],
            "relationship_type": document["relationship_type"],
            "assertion_origin": document["assertion_origin"],
            "confidence": document["confidence"],
            "state": document["state"],
            "valid_from": document.get("valid_from"),
            "valid_until": document.get("valid_until"),
            "provenance": document["provenance"],
        }
    if definition == "Incident":
        return {
            "title": document["title"],
            "status": document["status"],
            "confidence": document["confidence"],
            "claim_ids": document["claim_ids"],
            "artifact_ids": document["artifact_ids"],
            "affected_range_ids": document["affected_range_ids"],
            "relationship_ids": document["relationship_ids"],
            "event_ids": document["event_ids"],
            "authority_decision_ids": document.get("authority_decision_ids") or [],
            "authority": document.get("authority"),
            "alias_ids": document["alias_ids"],
            "redirect_to": document.get("redirect_to"),
            "first_observed_at": document["first_observed_at"],
            "last_changed_at": document["last_changed_at"],
            "coverage": document["coverage"],
            "unknowns": document.get("unknowns") or [],
        }
    if definition == "IncidentEvent":
        return {
            "incident_id": document["incident_id"],
            "event_type": document["event_type"],
            "old_status": document.get("old_status"),
            "new_status": document.get("new_status"),
            "actor_type": document["actor_type"],
            "actor_id": document["actor_id"],
            "reason_code": document["reason_code"],
            "evidence_ids": document["evidence_ids"],
            "occurred_at": document["occurred_at"],
            "confidence": document["confidence"],
            "superseded_revision": document.get("superseded_revision"),
        }
    if definition == "RecommendedAction":
        return {
            "action_type": document["action_type"],
            "risk_level": document["risk_level"],
            "approval_required": document["approval_required"],
            "preconditions": document["preconditions"],
            "expected_result": document["expected_result"],
            "validation": document["validation"],
            "rollback": document["rollback"],
            "evidence_ids": document["evidence_ids"],
            "automation_allowed": document["automation_allowed"],
        }
    if definition == "PreliminaryWarning":
        return {
            "title": document["title"],
            "state": document["state"],
            "observed_at": document["observed_at"],
            "last_checked_at": document["last_checked_at"],
            "next_check_at": document.get("next_check_at"),
            "expires_at": document["expires_at"],
            "recheck_count": document["recheck_count"],
        }
    raise ValueError(f"definition is not persisted by the public ledger: {definition}")


def append_contract(
    session: Session,
    definition: str,
    payload: Mapping[str, Any],
    *,
    storage_key: str | None = None,
) -> tuple[ContractRecordMixin, bool]:
    """Append one validated revision or return an identical existing revision."""
    orm_type = PERSISTED_DEFINITIONS.get(definition)
    if orm_type is None:
        raise ValueError(f"definition is not persisted by CP-0B1: {definition}")
    validation_payload = dict(payload)
    if definition == "PreliminaryWarning" and validation_payload.get("schema_version") == "1.0.0":
        for field in LEGACY_WARNING_PROVENANCE_FIELDS:
            if validation_payload.get(field) is None:
                validation_payload.pop(field, None)
    contract: BaseModel = parse_contract(definition, validation_payload)
    document = contract.model_dump(mode="json", exclude_none=False)
    if definition == "RawEvidence" and "source_modified_at" not in validation_payload:
        document.pop("source_modified_at", None)
    if definition == "Incident":
        if "authority_decision_ids" not in validation_payload:
            document.pop("authority_decision_ids", None)
        if "authority" not in validation_payload:
            document.pop("authority", None)
    if definition == "PreliminaryWarning" and document["schema_version"] == "1.0.0":
        for field in LEGACY_WARNING_PROVENANCE_FIELDS:
            if field not in validation_payload:
                document.pop(field, None)
    if definition in PUBLIC_ONLY_DEFINITIONS and document["data_classification"] != "public":
        raise LedgerClassificationError(
            f"{definition} must be public to enter the CP-0B1 canonical ledger"
        )
    values = _common(document)
    values.update(_specific(definition, document, storage_key=storage_key))

    lock_name = f"{orm_type.__tablename__}:{document['id']}"
    advisory_xact_lock(session, lock_name)
    existing_row = session.execute(
        select(
            orm_type,
            func.max(orm_type.revision).over().label("head_revision"),
        )
        .where(orm_type.id == document["id"])
        .order_by(
            (orm_type.revision == document["revision"]).desc(),
            orm_type.revision.desc(),
        )
        .limit(1)
    ).one_or_none()
    existing = existing_row[0] if existing_row is not None else None
    head_revision = int(existing_row[1]) if existing_row is not None else None
    if existing is not None and existing.revision == document["revision"]:
        if existing.record_hash != values["record_hash"]:
            raise RevisionConflict(
                f"{definition} {document['id']} revision {document['revision']} conflicts"
            )
        return existing, False

    if head_revision is not None and document["revision"] <= head_revision:
        raise RevisionOrderError(
            f"{definition} {document['id']} revision must be greater than {head_revision}"
        )

    record = orm_type(**values)
    session.add(record)
    session.flush()
    return record, True


def latest_contract(
    session: Session,
    definition: str,
    stable_id: str,
) -> ContractRecordMixin | None:
    orm_type = PERSISTED_DEFINITIONS.get(definition)
    if orm_type is None:
        raise ValueError(f"definition is not persisted by CP-0B1: {definition}")
    return session.scalar(
        select(orm_type).where(orm_type.id == stable_id).order_by(orm_type.revision.desc()).limit(1)
    )


def canonical_row_counts(session: Session) -> dict[str, int]:
    return {
        orm_type.__tablename__: session.scalar(select(func.count()).select_from(orm_type)) or 0
        for orm_type in PERSISTED_DEFINITIONS.values()
    }
