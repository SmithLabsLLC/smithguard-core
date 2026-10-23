"""Deterministic source clustering without automated confirmation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.authority import (
    GITHUB_ADVISORY,
    AuthorityEvaluation,
    AuthorityPolicy,
    AuthorityPolicyError,
    authority_decision_document,
    evaluation_from_lineage,
    load_authority_policy,
)
from smithguard.collectors import (
    filter_github_advisory,
    transform_github_advisories,
)
from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import (
    ArtifactRecord,
    ClaimRecord,
    EvidenceRecord,
    SourceClusterMemberRecord,
)
from smithguard.db.repository import append_contract
from smithguard.evidence import EvidenceMissingError, EvidenceStore
from smithguard.identifiers import (
    SHA256,
    STABLE_ID,
    canonical_json_bytes,
    sha256_id,
    stable_id,
    timestamp,
)
from smithguard.incidents import apply_incident_event
from smithguard.normalization import NormalizationRejected
from smithguard.query import IncidentPosition, list_latest_incidents
from smithguard.review_queue import ReviewEvent, append_review_event

RELATIONS = {"origin", "corroborates", "conflicts", "corrects", "withdraws"}


class ReconciliationError(ValueError):
    """A source member conflicts with immutable cluster history."""


@dataclass(frozen=True, slots=True)
class SourceMember:
    source_id: str
    source_record_id: str
    evidence_id: str
    artifact_id: str
    independent_origin_id: str
    claim_fingerprint: str
    observed_at: datetime
    relation: str | None = None


@dataclass(frozen=True, slots=True)
class ClusterSummary:
    cluster_id: str
    member_count: int
    independent_origin_count: int
    claim_fingerprint_count: int
    has_conflict: bool
    has_correction: bool
    has_withdrawal: bool
    confirmation_state: str = "requires_human_review"


@dataclass(frozen=True, slots=True)
class HistoricalAuthorityItem:
    incident_id: str
    current_status: str
    proposed_status: str
    reason_code: str
    evidence_id: str
    exception_reason_code: str | None
    changed: bool


@dataclass(frozen=True, slots=True)
class HistoricalAuthorityReport:
    mode: str
    scanned_count: int
    eligible_count: int
    changed_count: int
    skipped_count: int
    items: tuple[HistoricalAuthorityItem, ...]
    has_more: bool
    next_after: IncidentPosition | None


def cluster_id_for(artifact_id: str) -> str:
    return stable_id("source-cluster", artifact_id)


def _infer_relation(
    existing: tuple[SourceClusterMemberRecord, ...],
    member: SourceMember,
) -> str:
    if not existing:
        return "origin"
    same_fingerprint = tuple(
        item for item in existing if item.claim_fingerprint == member.claim_fingerprint
    )
    if same_fingerprint and any(
        item.independent_origin_id != member.independent_origin_id for item in same_fingerprint
    ):
        return "corroborates"
    if same_fingerprint:
        return "origin"
    return "conflicts"


def append_source_member(
    session: Session,
    *,
    member: SourceMember,
) -> tuple[SourceClusterMemberRecord, bool]:
    """Append one logical member or return its evidence-only semantic replay."""
    stable_ids = (
        member.source_id,
        member.evidence_id,
        member.artifact_id,
        member.independent_origin_id,
    )
    if any(not STABLE_ID.fullmatch(value) for value in stable_ids):
        raise ReconciliationError("source member contains an invalid stable ID")
    if (
        not member.source_record_id
        or len(member.source_record_id) > 512
        or not member.source_record_id.isascii()
    ):
        raise ReconciliationError("source member record ID is invalid")
    if not SHA256.fullmatch(member.claim_fingerprint):
        raise ReconciliationError("source member claim fingerprint is invalid")
    if member.observed_at.tzinfo is None or member.observed_at.utcoffset() is None:
        raise ReconciliationError("source member time must be timezone-aware")
    cluster_id = cluster_id_for(member.artifact_id)
    lock_name = f"source-cluster:{cluster_id}"
    advisory_xact_lock(session, lock_name)
    member_id = stable_id(
        "source-cluster-member",
        cluster_id,
        member.source_id,
        member.source_record_id,
    )
    prior = session.get(SourceClusterMemberRecord, member_id)
    existing = tuple(
        session.scalars(
            select(SourceClusterMemberRecord)
            .where(SourceClusterMemberRecord.cluster_id == cluster_id)
            .order_by(SourceClusterMemberRecord.observed_at, SourceClusterMemberRecord.member_id)
        )
    )
    relation = member.relation or (
        prior.relation if prior is not None else _infer_relation(existing, member)
    )
    if relation not in RELATIONS:
        raise ReconciliationError("source relation is unsupported")
    common_values = {
        "cluster_id": cluster_id,
        "source_id": member.source_id,
        "source_record_id": member.source_record_id,
        "evidence_id": member.evidence_id,
        "artifact_id": member.artifact_id,
        "independent_origin_id": member.independent_origin_id,
        "claim_fingerprint": member.claim_fingerprint,
        "relation": relation,
        "observed_at": member.observed_at,
    }
    values = {"member_id": member_id, **common_values}
    record_hash = sha256_id(
        canonical_json_bytes({**values, "observed_at": timestamp(member.observed_at)})
    )
    if prior is not None:
        if prior.record_hash == record_hash:
            return prior, False
        nonsemantic_fields = {"evidence_id"}
        if any(
            getattr(prior, field) != value
            for field, value in common_values.items()
            if field not in nonsemantic_fields
        ):
            raise ReconciliationError("source member identity conflicts with history")
        return prior, False
    record = SourceClusterMemberRecord(**values, record_hash=record_hash)
    session.add(record)
    session.flush()
    return record, True


def summarize_cluster(session: Session, cluster_id: str) -> ClusterSummary:
    members = tuple(
        session.scalars(
            select(SourceClusterMemberRecord).where(
                SourceClusterMemberRecord.cluster_id == cluster_id
            )
        )
    )
    if not members:
        raise ReconciliationError("source cluster does not exist")
    relations = {member.relation for member in members}
    independent_origin_count = len({member.independent_origin_id for member in members})
    fingerprint_count = len({member.claim_fingerprint for member in members})
    if "conflicts" in relations:
        confirmation_state = "requires_human_review"
    elif "withdraws" in relations:
        confirmation_state = "withdrawn"
    elif fingerprint_count > 1:
        confirmation_state = "requires_human_review"
    elif independent_origin_count >= 2:
        confirmation_state = "corroborated"
    else:
        confirmation_state = "reported"
    return ClusterSummary(
        cluster_id=cluster_id,
        member_count=len(members),
        independent_origin_count=independent_origin_count,
        claim_fingerprint_count=fingerprint_count,
        has_conflict="conflicts" in relations,
        has_correction="corrects" in relations,
        has_withdrawal="withdraws" in relations,
        confirmation_state=confirmation_state,
    )


def _latest_claim(session: Session, claim_ids: list[str]) -> ClaimRecord | None:
    if not claim_ids:
        return None
    return session.scalar(
        select(ClaimRecord)
        .where(ClaimRecord.id.in_(claim_ids))
        .order_by(ClaimRecord.updated_at.desc(), ClaimRecord.revision.desc())
        .limit(1)
    )


def _latest_evidence(session: Session, evidence_id: str) -> EvidenceRecord | None:
    return session.scalar(
        select(EvidenceRecord)
        .where(EvidenceRecord.id == evidence_id)
        .order_by(EvidenceRecord.revision.desc())
        .limit(1)
    )


def _reported_historical(
    *,
    evidence: EvidenceRecord,
    upstream_id: str,
    status: str,
) -> AuthorityEvaluation:
    if status == "withdrawn":
        public_status = "withdrawn"
        method = "withdrawal"
        rule_id = "gbsec:authority-rule:upstream-withdrawal-v1"
        reason_code = "upstream_malware_claim_withdrawn"
    elif status == "disputed":
        public_status = "disputed"
        method = "dispute"
        rule_id = "gbsec:authority-rule:historical-dispute-v1"
        reason_code = "historical_malware_claim_disputed"
    else:
        public_status = "reported"
        method = "reported_source"
        rule_id = "gbsec:authority-rule:reported-historical-unresolved-v1"
        reason_code = "historical_source_identity_unresolved"
    return AuthorityEvaluation(
        public_status=public_status,
        confirmation_method=method,
        transport_source_id=GITHUB_ADVISORY,
        assertion_source_id=None,
        confirming_authority_id=None,
        authority_rule_id=rule_id,
        reason_code=reason_code,
        upstream_ids=(upstream_id,),
        source_references=(evidence.canonical_url,),
        exception_reason_code=("mixed_upstream_identity" if public_status == "reported" else None),
    )


def _historical_evaluation(
    *,
    evidence_store: EvidenceStore,
    evidence: EvidenceRecord,
    artifact: Mapping[str, Any],
    policy: AuthorityPolicy,
    current_status: str,
) -> AuthorityEvaluation:
    upstream_id = evidence.source_record_id.split(":", 1)[0]
    fallback = _reported_historical(
        evidence=evidence,
        upstream_id=upstream_id,
        status=current_status,
    )
    try:
        body = evidence_store.read_bytes(evidence.sha256)
        decoded = json.loads(body.decode("ascii"))
        if not isinstance(decoded, list) or not 1 <= len(decoded) <= 100:
            return fallback
        matches: list[AuthorityEvaluation] = []
        for raw in decoded:
            if not isinstance(raw, Mapping):
                continue
            vulnerabilities = raw.get("vulnerabilities")
            if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 500:
                continue
            for vulnerability in vulnerabilities:
                try:
                    filtered = filter_github_advisory(
                        {
                            **raw,
                            "vulnerabilities": [vulnerability],
                        }
                    )
                    transformed = transform_github_advisories(
                        (filtered,),
                        authority_policy=policy,
                    )
                except (AuthorityPolicyError, NormalizationRejected, ValueError):
                    continue
                for record in transformed:
                    candidate = record["artifact"]
                    if (
                        candidate["ecosystem"] == artifact["ecosystem"]
                        and candidate["name"] == artifact["name"]
                        and candidate["version"] == artifact["version"]
                    ):
                        lineage = record.get("source_lineage")
                        if isinstance(lineage, Mapping):
                            evaluation = evaluation_from_lineage(lineage, policy=policy)
                            if evaluation not in matches:
                                matches.append(evaluation)
        if len(matches) == 1:
            return matches[0]
        return fallback
    except (
        AuthorityPolicyError,
        EvidenceMissingError,
        json.JSONDecodeError,
        NormalizationRejected,
        UnicodeError,
        ValueError,
    ):
        # A malformed, unrecognised or never-stored historical record is legitimately
        # "reported". Any other EvidenceIntegrityError means the immutable blob itself
        # failed its boundary or digest check; that propagates and fails the run
        # instead of being recorded as an unresolved decision.
        return fallback


def _reconciliation_event(
    *,
    incident: Any,
    decision: Mapping[str, Any],
    evidence_id: str,
    occurred_at: datetime,
    confidence: str,
) -> dict[str, Any]:
    rendered = timestamp(occurred_at)
    return {
        "id": stable_id(
            "event",
            incident.id,
            "authority-reconciled",
            decision["id"],
        ),
        "kind": "incident_event",
        "schema_version": "1.0.0",
        "revision": 1,
        "created_at": rendered,
        "updated_at": rendered,
        "data_classification": "public",
        "incident_id": incident.id,
        "event_type": "corrected",
        "old_status": incident.status,
        "new_status": decision["public_status"],
        "actor_type": "system",
        "actor_id": "system-historical-authority-reconciler",
        "reason_code": decision["reason_code"],
        "evidence_ids": [evidence_id],
        "occurred_at": rendered,
        "confidence": confidence,
        "superseded_revision": incident.revision,
    }


def _open_historical_exception(
    session: Session,
    *,
    incident_id: str,
    artifact_id: str,
    evidence_id: str,
    reason_code: str,
    occurred_at: datetime,
) -> None:
    queue_item_id = stable_id(
        "review-item",
        "historical-authority",
        incident_id,
        reason_code,
    )
    append_review_event(
        session,
        event=ReviewEvent(
            event_id=stable_id("review-event", queue_item_id, "opened"),
            queue_item_id=queue_item_id,
            cluster_id=cluster_id_for(artifact_id),
            incident_id=incident_id,
            event_type="opened",
            actor_type="system",
            actor_id="system-historical-authority-reconciler",
            reason_code=reason_code,
            evidence_ids=(evidence_id,),
            occurred_at=occurred_at,
        ),
    )


def reconcile_historical_malware_authority(
    session: Session,
    *,
    evidence_store: EvidenceStore,
    reconciled_at: datetime,
    apply: bool = False,
    limit: int = 10_000,
    after: IncidentPosition | None = None,
    authority_policy: AuthorityPolicy | None = None,
) -> HistoricalAuthorityReport:
    """Plan or append deterministic authority decisions for pre-MX-002 incidents."""
    if reconciled_at.tzinfo is None or reconciled_at.utcoffset() is None:
        raise ReconciliationError("reconciliation time must be timezone-aware")
    if not 1 <= limit <= 10_000:
        raise ReconciliationError("reconciliation limit must be between 1 and 10000")
    if after is not None and (
        after.changed_at.tzinfo is None
        or after.changed_at.utcoffset() is None
        or not STABLE_ID.fullmatch(after.incident_id)
    ):
        raise ReconciliationError("reconciliation continuation is invalid")
    policy = authority_policy or load_authority_policy()
    selected = list_latest_incidents(
        session,
        public_only=True,
        limit=limit + 1,
        after=after,
    )
    has_more = len(selected) > limit
    incidents = selected[:limit]
    next_after = (
        IncidentPosition(
            changed_at=incidents[-1].last_changed_at,
            incident_id=incidents[-1].id,
        )
        if has_more and incidents
        else None
    )
    items: list[HistoricalAuthorityItem] = []
    eligible_count = 0
    changed_count = 0
    skipped_count = 0
    for incident in incidents:
        if incident.authority_decision_ids:
            skipped_count += 1
            continue
        if len(incident.artifact_ids) != 1:
            skipped_count += 1
            continue
        claim = _latest_claim(session, list(incident.claim_ids))
        if claim is None or claim.claim_type != "malicious":
            skipped_count += 1
            continue
        provenance = claim.provenance
        evidence_id = provenance.get("evidence_id")
        if provenance.get("source_id") != GITHUB_ADVISORY or not isinstance(
            evidence_id,
            str,
        ):
            skipped_count += 1
            continue
        evidence = _latest_evidence(session, evidence_id)
        if evidence is None or evidence.storage_state != "stored_immutable":
            skipped_count += 1
            continue
        artifact = session.scalar(
            select(ArtifactRecord)
            .where(ArtifactRecord.id == incident.artifact_ids[0])
            .order_by(ArtifactRecord.revision.desc())
            .limit(1)
        )
        if artifact is None:
            skipped_count += 1
            continue
        eligible_count += 1
        evaluation = _historical_evaluation(
            evidence_store=evidence_store,
            evidence=evidence,
            artifact=artifact.document,
            policy=policy,
            current_status=incident.status,
        )
        occurred_at = max(reconciled_at.astimezone(UTC), incident.last_changed_at)
        decision = authority_decision_document(
            evaluation=evaluation,
            policy=policy,
            incident_id=incident.id,
            claim_id=claim.id,
            artifact_id=artifact.id,
            evidence_id=evidence.id,
            decided_at=occurred_at,
        )
        changed = False
        if apply:
            append_contract(session, "AuthorityDecision", decision)
            applied = apply_incident_event(
                session,
                event=_reconciliation_event(
                    incident=incident,
                    decision=decision,
                    evidence_id=evidence.id,
                    occurred_at=occurred_at,
                    confidence=evaluation.claim_confidence,
                ),
                details={
                    "replacement_claim_ids": (claim.id,),
                    "add_authority_decision_ids": (decision["id"],),
                    "replace_authority": decision,
                    "add_unknowns": (
                        "Historical malware status was reconciled from retained evidence.",
                    ),
                },
            )
            changed = applied.created
            if evaluation.exception_required and evaluation.exception_reason_code is not None:
                _open_historical_exception(
                    session,
                    incident_id=incident.id,
                    artifact_id=artifact.id,
                    evidence_id=evidence.id,
                    reason_code=evaluation.exception_reason_code,
                    occurred_at=occurred_at,
                )
        if changed:
            changed_count += 1
        items.append(
            HistoricalAuthorityItem(
                incident_id=incident.id,
                current_status=incident.status,
                proposed_status=evaluation.public_status,
                reason_code=evaluation.reason_code,
                evidence_id=evidence.id,
                exception_reason_code=evaluation.exception_reason_code,
                changed=changed,
            )
        )
    return HistoricalAuthorityReport(
        mode="apply" if apply else "dry_run",
        scanned_count=len(incidents),
        eligible_count=eligible_count,
        changed_count=changed_count,
        skipped_count=skipped_count,
        items=tuple(items),
        has_more=has_more,
        next_after=next_after,
    )
