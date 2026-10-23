"""Bounded, append-only reconciliation of authenticated upstream identities."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import (
    EvidenceRecord,
    PublicationLifecycleEventRecord,
    SourceGovernanceDecisionRecord,
    SourceIncidentLinkRecord,
    SourceReconciliationRunRecord,
)
from smithguard.identifiers import (
    REASON_CODE_LONG,
    STABLE_ID,
    canonical_json_bytes,
    sha256_id,
    stable_id,
    timestamp,
)
from smithguard.publication_lifecycle import LifecycleEvent, append_lifecycle_event
from smithguard.query import latest_incident
from smithguard.source_governance import (
    SourceGovernancePolicy,
    append_governance_decision,
)

UPSTREAM_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,159}$")
REASON_CODE = REASON_CODE_LONG
MAX_PAGE_OBSERVATIONS = 5000
MAX_RUN_OBSERVATIONS = 100_000
MAX_DRIFT_IDS = 100
RECONCILIATION_ACTOR = "system-source-inventory-reconciler"


class SourceInventoryError(ValueError):
    """A source inventory page or its continuation is unsafe or inconsistent."""


class SourceInventoryReplayConflict(ValueError):
    """A reconciliation run page was replayed with different observations."""


@dataclass(frozen=True, slots=True)
class SourceInventoryObservation:
    source_record_id: str
    source_modified_at: datetime
    state: str = "active"


@dataclass(frozen=True, slots=True)
class SourceInventoryResult:
    reconciliation_event_id: str
    inventory_run_id: str
    page_index: int
    state: str
    late_record_ids: tuple[str, ...]
    modified_record_ids: tuple[str, ...]
    deleted_record_ids: tuple[str, ...]
    missing_record_ids: tuple[str, ...]
    unresolved_record_ids: tuple[str, ...]
    drift_truncated: bool
    created: bool


def _cursor_hash(value: str | None) -> str | None:
    if value is None:
        return None
    if not value or len(value) > 1000 or not value.isascii():
        raise SourceInventoryError("source reconciliation cursor is invalid")
    return "sha256:" + sha256(value.encode("ascii")).hexdigest()


def _validated_observations(
    observations: tuple[SourceInventoryObservation, ...],
) -> tuple[SourceInventoryObservation, ...]:
    if len(observations) > MAX_PAGE_OBSERVATIONS:
        raise SourceInventoryError("source reconciliation page exceeds its record limit")
    by_id: dict[str, SourceInventoryObservation] = {}
    for observation in observations:
        if not UPSTREAM_ID.fullmatch(observation.source_record_id):
            raise SourceInventoryError("source reconciliation record ID is invalid")
        if (
            observation.source_modified_at.tzinfo is None
            or observation.source_modified_at.utcoffset() is None
        ):
            raise SourceInventoryError("source reconciliation time must include a timezone")
        if observation.state not in {"active", "deleted"}:
            raise SourceInventoryError("source reconciliation record state is invalid")
        normalized = SourceInventoryObservation(
            source_record_id=observation.source_record_id,
            source_modified_at=observation.source_modified_at.astimezone(UTC),
            state=observation.state,
        )
        existing = by_id.get(normalized.source_record_id)
        if existing is not None and existing != normalized:
            raise SourceInventoryError("source reconciliation record is duplicated")
        by_id[normalized.source_record_id] = normalized
    return tuple(by_id[key] for key in sorted(by_id))


def _observation_sha256(
    observations: tuple[SourceInventoryObservation, ...],
) -> str:
    return sha256_id(
        canonical_json_bytes(
            [
                {
                    "source_record_id": item.source_record_id,
                    "source_modified_at": timestamp(item.source_modified_at),
                    "state": item.state,
                }
                for item in observations
            ]
        )
    )


def _latest_links(
    session: Session,
    *,
    source_id: str,
    record_ids: tuple[str, ...],
) -> dict[str, tuple[SourceIncidentLinkRecord, ...]]:
    if not record_ids:
        return {}
    rows = session.scalars(
        select(SourceIncidentLinkRecord)
        .where(
            SourceIncidentLinkRecord.source_id == source_id,
            SourceIncidentLinkRecord.upstream_record_id.in_(record_ids),
        )
        .order_by(
            SourceIncidentLinkRecord.upstream_record_id,
            SourceIncidentLinkRecord.artifact_id,
            SourceIncidentLinkRecord.sequence.desc(),
        )
    )
    latest: dict[tuple[str, str], SourceIncidentLinkRecord] = {}
    for row in rows:
        latest.setdefault((row.upstream_record_id, row.artifact_id), row)
    by_record: dict[str, list[SourceIncidentLinkRecord]] = {}
    for (record_id, _artifact_id), row in latest.items():
        by_record.setdefault(record_id, []).append(row)
    return {
        record_id: tuple(sorted(values, key=lambda item: item.artifact_id))
        for record_id, values in by_record.items()
    }


def _bounded_union(
    prior: list[str],
    current: set[str],
) -> tuple[list[str], bool]:
    values = sorted(set(prior) | current)
    return values[:MAX_DRIFT_IDS], len(values) > MAX_DRIFT_IDS


def _governance_for_evidence(
    session: Session,
    *,
    policy: SourceGovernancePolicy,
    connector_id: str,
    acquisition_method: str,
    evidence: EvidenceRecord,
    reconciled_at: datetime,
) -> SourceGovernanceDecisionRecord:
    existing = session.scalar(
        select(SourceGovernanceDecisionRecord)
        .where(
            SourceGovernanceDecisionRecord.policy_sha256 == policy.policy_sha256,
            SourceGovernanceDecisionRecord.source_id == evidence.source_id,
            SourceGovernanceDecisionRecord.source_record_id == evidence.source_record_id,
            SourceGovernanceDecisionRecord.accepted_sha256 == evidence.sha256,
        )
        .order_by(SourceGovernanceDecisionRecord.decided_at.desc())
        .limit(1)
    )
    if existing is not None:
        return existing
    authorization = policy.authorize_collection(
        connector_id=connector_id,
        source_id=evidence.source_id,
        acquisition_method=acquisition_method,
        operating_mode="reconciliation",
        canonical_url=evidence.canonical_url,
        source_record_id=evidence.source_record_id,
        authorized_at=reconciled_at,
    )
    record, _created = append_governance_decision(
        session,
        authorization=authorization,
        accepted_sha256=evidence.sha256,
        decided_at=reconciled_at,
    )
    return record


def _append_source_deleted_events(
    session: Session,
    *,
    policy: SourceGovernancePolicy,
    connector_id: str,
    acquisition_method: str,
    links: tuple[SourceIncidentLinkRecord, ...],
    reconciled_at: datetime,
) -> None:
    for link in links:
        current = latest_incident(session, link.incident_id, public_only=True)
        if current is None:
            raise SourceInventoryError(
                "source reconciliation link references a missing public incident"
            )
        evidence = session.scalar(
            select(EvidenceRecord)
            .where(EvidenceRecord.id == link.evidence_id)
            .order_by(EvidenceRecord.revision.desc())
            .limit(1)
        )
        if evidence is None:
            raise SourceInventoryError("source reconciliation link references missing evidence")
        governance = _governance_for_evidence(
            session,
            policy=policy,
            connector_id=connector_id,
            acquisition_method=acquisition_method,
            evidence=evidence,
            reconciled_at=reconciled_at,
        )
        existing = session.scalar(
            select(PublicationLifecycleEventRecord)
            .where(
                PublicationLifecycleEventRecord.event_type == "source_deleted",
                PublicationLifecycleEventRecord.incident_id == current.id,
                PublicationLifecycleEventRecord.evidence_id == evidence.id,
                PublicationLifecycleEventRecord.governance_decision_id == governance.decision_id,
            )
            .limit(1)
        )
        if existing is not None:
            continue
        append_lifecycle_event(
            session,
            event=LifecycleEvent(
                event_type="source_deleted",
                actor_type="system",
                actor_id=RECONCILIATION_ACTOR,
                source_id=evidence.source_id,
                source_record_id=evidence.source_record_id,
                evidence_id=evidence.id,
                governance_decision_id=governance.decision_id,
                reason_code="authoritative_source_deleted",
                occurred_at=reconciled_at,
                incident_id=current.id,
                incident_revision=current.revision,
                old_public_status=current.status,
                new_public_status=current.status,
            ),
            idempotency_key=(
                f"source-deleted:{current.id}:{current.revision}:"
                f"{evidence.id}:{governance.decision_id}"
            ),
        )


def reconcile_source_inventory(
    session: Session,
    *,
    policy: SourceGovernancePolicy,
    connector_id: str,
    source_id: str,
    acquisition_method: str,
    canonical_url: str,
    inventory_run_id: str,
    page_index: int,
    observations: tuple[SourceInventoryObservation, ...],
    continuation_in: str | None,
    continuation_out: str | None,
    has_more: bool,
    inventory_complete: bool,
    reconciled_at: datetime,
    next_due_at: datetime,
    failure_reason_code: str | None = None,
) -> SourceInventoryResult:
    """Append one authenticated inventory page and cumulative drift decision."""
    if len(inventory_run_id) > 160 or not STABLE_ID.fullmatch(inventory_run_id):
        raise SourceInventoryError("source reconciliation run ID is invalid")
    if not 1 <= page_index <= 10_000:
        raise SourceInventoryError("source reconciliation page index is invalid")
    if reconciled_at.tzinfo is None or reconciled_at.utcoffset() is None:
        raise SourceInventoryError("source reconciliation time must include a timezone")
    if next_due_at.tzinfo is None or next_due_at.utcoffset() is None:
        raise SourceInventoryError("source reconciliation due time must include a timezone")
    reconciled_at = reconciled_at.astimezone(UTC)
    next_due_at = next_due_at.astimezone(UTC)
    if next_due_at <= reconciled_at:
        raise SourceInventoryError("source reconciliation due time must be later")
    if has_more and (continuation_out is None or inventory_complete):
        raise SourceInventoryError("continued reconciliation has invalid terminal state")
    if not has_more and continuation_out is not None:
        raise SourceInventoryError("terminal reconciliation cannot contain a next cursor")
    if page_index == 1 and continuation_in is not None:
        raise SourceInventoryError("first reconciliation page cannot contain an input cursor")
    if page_index > 1 and continuation_in is None:
        raise SourceInventoryError("continued reconciliation requires an input cursor")
    if failure_reason_code is not None and (
        not REASON_CODE.fullmatch(failure_reason_code)
        or observations
        or has_more
        or inventory_complete
    ):
        raise SourceInventoryError("source reconciliation failure is invalid")

    policy.authorize_collection(
        connector_id=connector_id,
        source_id=source_id,
        acquisition_method=acquisition_method,
        operating_mode="reconciliation",
        canonical_url=canonical_url,
        source_record_id=f"inventory:{inventory_run_id}:page:{page_index}",
        authorized_at=reconciled_at,
    )
    normalized = _validated_observations(observations)
    observation_sha256 = _observation_sha256(normalized)
    input_hash = _cursor_hash(continuation_in)
    output_hash = _cursor_hash(continuation_out)

    lock_name = f"source-inventory:{source_id}"
    advisory_xact_lock(session, lock_name)
    existing = session.scalar(
        select(SourceReconciliationRunRecord).where(
            SourceReconciliationRunRecord.source_id == source_id,
            SourceReconciliationRunRecord.inventory_run_id == inventory_run_id,
            SourceReconciliationRunRecord.page_index == page_index,
        )
    )
    if existing is not None:
        replay_values = (
            existing.connector_id,
            existing.policy_id,
            existing.policy_sha256,
            existing.observation_sha256,
            existing.continuation_in_hash,
            existing.continuation_out_hash,
            existing.has_more,
            existing.complete_inventory,
        )
        expected_values = (
            connector_id,
            policy.policy_id,
            policy.policy_sha256,
            observation_sha256,
            input_hash,
            output_hash,
            has_more,
            inventory_complete,
        )
        if replay_values != expected_values:
            raise SourceInventoryReplayConflict(
                "source reconciliation page was replayed with different input"
            )
        return SourceInventoryResult(
            reconciliation_event_id=existing.reconciliation_event_id,
            inventory_run_id=existing.inventory_run_id,
            page_index=existing.page_index,
            state=existing.state,
            late_record_ids=tuple(existing.late_record_ids),
            modified_record_ids=tuple(existing.modified_record_ids),
            deleted_record_ids=tuple(existing.deleted_record_ids),
            missing_record_ids=tuple(existing.missing_record_ids),
            unresolved_record_ids=tuple(existing.unresolved_record_ids),
            drift_truncated=existing.drift_truncated,
            created=False,
        )

    prior_page = session.scalar(
        select(SourceReconciliationRunRecord).where(
            SourceReconciliationRunRecord.source_id == source_id,
            SourceReconciliationRunRecord.inventory_run_id == inventory_run_id,
            SourceReconciliationRunRecord.page_index == page_index - 1,
        )
    )
    if page_index == 1:
        if prior_page is not None:
            raise SourceInventoryError("first reconciliation page already has history")
    elif (
        prior_page is None
        or not prior_page.has_more
        or prior_page.continuation_out_hash != input_hash
    ):
        raise SourceInventoryError("source reconciliation continuation is not exact")

    latest_sequence = session.scalar(
        select(func.max(SourceReconciliationRunRecord.sequence)).where(
            SourceReconciliationRunRecord.source_id == source_id
        )
    )
    sequence = int(latest_sequence or 0) + 1
    prior_observed = prior_page.observed_count if prior_page is not None else 0
    observed_count = prior_observed + len(normalized)
    if observed_count > MAX_RUN_OBSERVATIONS:
        raise SourceInventoryError("source reconciliation run exceeds its record limit")

    record_ids = tuple(item.source_record_id for item in normalized)
    complete_run_ids: set[str] | None = None
    if not has_more:
        prior_rows = tuple(
            session.scalars(
                select(SourceReconciliationRunRecord)
                .where(
                    SourceReconciliationRunRecord.source_id == source_id,
                    SourceReconciliationRunRecord.inventory_run_id == inventory_run_id,
                    SourceReconciliationRunRecord.page_index < page_index,
                )
                .order_by(SourceReconciliationRunRecord.page_index)
            )
        )
        complete_ids = [
            record_id for row in prior_rows for record_id in row.observed_record_ids
        ] + list(record_ids)
        if len(complete_ids) != observed_count or len(set(complete_ids)) != len(complete_ids):
            raise SourceInventoryError(
                "source reconciliation traversal contains duplicated or missing page evidence"
            )
        complete_run_ids = set(complete_ids)
    links_by_record = _latest_links(
        session,
        source_id=source_id,
        record_ids=record_ids,
    )
    late: set[str] = set()
    modified: set[str] = set()
    deleted: set[str] = set()
    missing: set[str] = set()
    deleted_links: list[tuple[SourceIncidentLinkRecord, ...]] = []
    for observation in normalized:
        links = links_by_record.get(observation.source_record_id, ())
        if not links:
            if observation.state == "active":
                late.add(observation.source_record_id)
            continue
        if observation.state == "deleted":
            deleted.add(observation.source_record_id)
            deleted_links.append(links)
            continue
        latest_modified_at = max(link.source_updated_at for link in links)
        if observation.source_modified_at != latest_modified_at:
            modified.add(observation.source_record_id)
    known_record_count_exceeded = False
    if inventory_complete:
        known_record_ids = tuple(
            session.scalars(
                select(SourceIncidentLinkRecord.upstream_record_id)
                .where(SourceIncidentLinkRecord.source_id == source_id)
                .distinct()
                .order_by(SourceIncidentLinkRecord.upstream_record_id)
                .limit(MAX_RUN_OBSERVATIONS + 1)
            )
        )
        known_record_count_exceeded = len(known_record_ids) > MAX_RUN_OBSERVATIONS
        missing = set(known_record_ids[:MAX_RUN_OBSERVATIONS]) - (complete_run_ids or set())

    prior_late = prior_page.late_record_ids if prior_page is not None else []
    prior_modified = prior_page.modified_record_ids if prior_page is not None else []
    prior_deleted = prior_page.deleted_record_ids if prior_page is not None else []
    prior_missing = prior_page.missing_record_ids if prior_page is not None else []
    late_values, late_truncated = _bounded_union(prior_late, late)
    modified_values, modified_truncated = _bounded_union(prior_modified, modified)
    deleted_values, deleted_truncated = _bounded_union(prior_deleted, deleted)
    missing_values, missing_truncated = _bounded_union(prior_missing, missing)
    unresolved_values, unresolved_truncated = _bounded_union(
        prior_page.unresolved_record_ids if prior_page is not None else [],
        late | modified | deleted | missing,
    )
    drift_truncated = (
        (prior_page.drift_truncated if prior_page is not None else False)
        or late_truncated
        or modified_truncated
        or deleted_truncated
        or missing_truncated
        or unresolved_truncated
        or known_record_count_exceeded
    )

    if failure_reason_code is not None:
        state = "failed"
        reason_code = failure_reason_code
    elif has_more:
        state = "in_progress"
        reason_code = "inventory_page_accepted"
    elif not inventory_complete:
        state = "unresolved"
        reason_code = "inventory_incomplete"
    elif unresolved_values or drift_truncated:
        state = "unresolved"
        reason_code = "inventory_drift_detected"
    else:
        state = "complete"
        reason_code = "inventory_complete"

    values: dict[str, Any] = {
        "reconciliation_event_id": stable_id(
            "source-reconciliation",
            source_id,
            inventory_run_id,
            str(page_index),
        ),
        "inventory_run_id": inventory_run_id,
        "source_id": source_id,
        "connector_id": connector_id,
        "sequence": sequence,
        "page_index": page_index,
        "state": state,
        "complete_inventory": inventory_complete,
        "scanned_count": len(normalized),
        "observed_count": observed_count,
        "observed_record_ids": list(record_ids),
        "late_record_ids": late_values,
        "modified_record_ids": modified_values,
        "deleted_record_ids": deleted_values,
        "missing_record_ids": missing_values,
        "unresolved_record_ids": unresolved_values,
        "drift_truncated": drift_truncated,
        "continuation_in_hash": input_hash,
        "continuation_out_hash": output_hash,
        "has_more": has_more,
        "policy_id": policy.policy_id,
        "policy_sha256": policy.policy_sha256,
        "observation_sha256": observation_sha256,
        "reason_code": reason_code,
        "reconciled_at": reconciled_at,
        "next_due_at": next_due_at,
    }
    hash_values = {
        **values,
        "reconciled_at": timestamp(reconciled_at),
        "next_due_at": timestamp(next_due_at),
    }
    record = SourceReconciliationRunRecord(
        **values,
        record_hash=sha256_id(canonical_json_bytes(hash_values)),
    )
    session.add(record)
    session.flush()
    for links in deleted_links:
        _append_source_deleted_events(
            session,
            policy=policy,
            connector_id=connector_id,
            acquisition_method=acquisition_method,
            links=links,
            reconciled_at=reconciled_at,
        )
    return SourceInventoryResult(
        reconciliation_event_id=record.reconciliation_event_id,
        inventory_run_id=record.inventory_run_id,
        page_index=record.page_index,
        state=record.state,
        late_record_ids=tuple(record.late_record_ids),
        modified_record_ids=tuple(record.modified_record_ids),
        deleted_record_ids=tuple(record.deleted_record_ids),
        missing_record_ids=tuple(record.missing_record_ids),
        unresolved_record_ids=tuple(record.unresolved_record_ids),
        drift_truncated=record.drift_truncated,
        created=True,
    )
