"""Append-only record accounting; acquisition success never erases a coverage gap.

Callers hold the source accounting transaction lock before ingestion/catalog locks.
Outcomes refer to existing governed batches; no upstream payload is retained here.
Page membership commits in the same transaction as its progress receipt. A named
resolution is effective for readers only after replacement evidence is finalized.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import exists, func, or_, select
from sqlalchemy.orm import Session

from smithguard.db.models import (
    AdvisoryCatalogRecord,
    CollectionRecordMembership,
    CollectionRecordOutcome,
    CollectionRecordResolution,
    EvidenceFinalizationRecord,
)
from smithguard.identifiers import canonical_json_bytes, sha256_id, stable_id, timestamp
from smithguard.ingestion import IngestionOutcome


class RecordAccountingError(ValueError):
    """An exact accounting or resolution precondition did not hold."""


def append_outcome(
    session: Session,
    *,
    source_id: str,
    segment: str,
    record_key: str,
    input_sha256: str,
    processing_version: str,
    policy_sha256: str,
    rights_revision: int,
    outcome: IngestionOutcome,
    catalog_event_id: str | None,
    omissions: Mapping[str, int],
    source_updated_at: datetime | None,
    observed_at: datetime,
    acquisition_lane: str,
) -> CollectionRecordOutcome:
    disposition = (
        "quarantined"
        if outcome.outcome == "quarantined"
        else "excluded"
        if omissions
        else "accepted"
    )
    if outcome.outcome not in {"accepted", "quarantined"}:
        raise RecordAccountingError("record disposition is not accountable")
    values: dict[str, Any] = {
        "source_id": source_id,
        "segment": segment,
        "record_key": record_key,
        "disposition": disposition,
        "input_sha256": input_sha256,
        "processing_version": processing_version,
        "policy_sha256": policy_sha256,
        "batch_id": outcome.batch_id,
        "document": {
            "input_encoding": "parsed_json_array_sorted_ascii_nonfinite_v1",
            "governed_input_sha256": outcome.input_sha256 if outcome.raw_evidence_id else None,
            "rights_revision": rights_revision,
            "acquisition_lane": acquisition_lane,
            "evidence_id": outcome.raw_evidence_id,
            "governance_decision_id": outcome.governance_decision_id,
            "catalog_event_id": catalog_event_id,
            "omissions": dict(omissions),
            "quarantine_reasons": list(outcome.quarantine_reasons),
            "source_updated_at": timestamp(source_updated_at) if source_updated_at else None,
        },
    }
    # Retry ingestion batches are distinct receipts of the same processing case.
    # Keep the first batch on an open omission; fresh membership proves rereading.
    identity = (
        values
        if disposition == "accepted"
        else {key: value for key, value in values.items() if key not in {"batch_id", "document"}}
        | {
            "rights_revision": rights_revision,
            "acquisition_lane": acquisition_lane,
            "omissions": dict(omissions),
            "quarantine_reasons": list(outcome.quarantine_reasons),
        }
    )
    digest = sha256_id(canonical_json_bytes(identity))
    outcome_id = stable_id("collection-record-outcome", digest)
    previous = session.get(CollectionRecordOutcome, outcome_id)
    if previous is not None:
        if disposition == "accepted":
            return previous
        # A resolution closes one observed occurrence. If identical bad input
        # returns later, retain the old closure and append a new open occurrence.
        previous = (
            session.scalar(
                select(CollectionRecordOutcome)
                .where(
                    CollectionRecordOutcome.source_id == source_id,
                    CollectionRecordOutcome.segment == segment,
                    CollectionRecordOutcome.record_key == record_key,
                    CollectionRecordOutcome.disposition != "accepted",
                    CollectionRecordOutcome.document["processing_identity_sha256"].astext == digest,
                )
                .order_by(CollectionRecordOutcome.document["occurrence"].as_integer().desc())
                .limit(1)
            )
            or previous
        )
        resolution = session.get(CollectionRecordResolution, previous.outcome_id)
        if resolution is None:
            return previous
        occurrence = int(previous.document["occurrence"]) + 1
        values["document"]["recurrence_of"] = previous.outcome_id
        values["document"]["prior_resolution_sha256"] = resolution.record_hash
        outcome_id = stable_id("collection-record-outcome", digest, str(occurrence))
    else:
        occurrence = 0
    values["document"]["processing_identity_sha256"] = digest
    values["document"]["occurrence"] = occurrence
    record = CollectionRecordOutcome(
        outcome_id=outcome_id,
        **values,
        observed_at=observed_at,
        record_hash=sha256_id(
            canonical_json_bytes({**values, "observed_at": timestamp(observed_at)})
        ),
    )
    session.add(record)
    session.flush()
    return record


def append_page_membership(
    session: Session,
    *,
    progress_event_id: str,
    outcomes: Sequence[CollectionRecordOutcome],
    expected_count: int,
    transport_sha256: str,
    observed_at: datetime,
) -> None:
    if len(outcomes) != expected_count or not 0 <= expected_count <= 100:
        raise RecordAccountingError("page membership does not account for every record")
    for ordinal, outcome in enumerate(outcomes):
        values = {
            "progress_event_id": progress_event_id,
            "ordinal": ordinal,
            "outcome_id": outcome.outcome_id,
            "transport_sha256": transport_sha256,
            "acquisition_kind": "page",
            "observed_at": timestamp(observed_at),
        }
        digest = sha256_id(canonical_json_bytes(values))
        session.add(
            CollectionRecordMembership(
                **{**values, "observed_at": observed_at},
                membership_id=stable_id("collection-record-membership", digest),
                record_hash=digest,
            )
        )
    session.flush()


def append_replay_membership(
    session: Session,
    *,
    outcome: CollectionRecordOutcome,
    transport_sha256: str,
    observed_at: datetime,
) -> CollectionRecordMembership:
    """Prove a fresh exact read even when processing reuses an older outcome."""
    values = {
        "progress_event_id": None,
        "ordinal": 0,
        "outcome_id": outcome.outcome_id,
        "transport_sha256": transport_sha256,
        "acquisition_kind": "replay",
        "observed_at": timestamp(observed_at),
    }
    digest = sha256_id(canonical_json_bytes(values))
    membership_id = stable_id("collection-record-membership", digest)
    existing = session.get(CollectionRecordMembership, membership_id)
    if existing is not None:
        return existing
    record = CollectionRecordMembership(
        **{**values, "observed_at": observed_at},
        membership_id=membership_id,
        record_hash=digest,
    )
    session.add(record)
    session.flush()
    return record


def unresolved_statement(*, source_id: str, segment: str | None = None):
    # The existing finalization gate also blocks serving when staging failed. Keep
    # the gap explicitly open until its replacement's finalization is complete.
    replacement = CollectionRecordOutcome.__table__.alias("replacement_outcome")
    resolved = exists(
        select(1)
        .select_from(CollectionRecordResolution)
        .join(replacement, replacement.c.outcome_id == CollectionRecordResolution.replacement_id)
        .join(
            EvidenceFinalizationRecord,
            EvidenceFinalizationRecord.digest
            == replacement.c.document["governed_input_sha256"].astext,
        )
        .where(
            CollectionRecordResolution.outcome_id == CollectionRecordOutcome.outcome_id,
            EvidenceFinalizationRecord.state == "finalized",
        )
    )
    statement = select(CollectionRecordOutcome).where(
        CollectionRecordOutcome.source_id == source_id,
        CollectionRecordOutcome.disposition != "accepted",
        ~resolved,
    )
    if segment is not None:
        statement = statement.where(CollectionRecordOutcome.segment == segment)
    return statement


def unresolved_count(session: Session, *, source_id: str, segment: str) -> int:
    cases = unresolved_statement(source_id=source_id, segment=segment).subquery()
    return int(session.scalar(select(func.count(func.distinct(cases.c.record_key)))) or 0)


def actionable_quarantines_statement(*, source_id: str):
    """Current segment failures affect answers; earlier segments retain their gaps.

    A GitHub type transition must not let an old unreviewed quarantine suppress
    the current reviewed assertion. This does not resolve or rewrite that old
    segment's historical omission.
    """
    current_type = (
        select(AdvisoryCatalogRecord.source_type)
        .where(
            AdvisoryCatalogRecord.source_id == CollectionRecordOutcome.source_id,
            AdvisoryCatalogRecord.upstream_record_id == CollectionRecordOutcome.record_key,
        )
        .order_by(AdvisoryCatalogRecord.revision.desc())
        .limit(1)
        .correlate(CollectionRecordOutcome)
        .scalar_subquery()
    )
    return unresolved_statement(source_id=source_id).where(
        CollectionRecordOutcome.disposition == "quarantined",
        or_(current_type.is_(None), current_type == CollectionRecordOutcome.segment),
    )


def actionable_quarantine_count(session: Session, *, source_id: str) -> int:
    cases = actionable_quarantines_statement(source_id=source_id).subquery()
    return int(session.scalar(select(func.count(func.distinct(cases.c.record_key)))) or 0)


def require_resolution_target(
    session: Session, *, outcome_id: str, source_id: str, segment: str, record_key: str
) -> CollectionRecordOutcome:
    record = session.get(CollectionRecordOutcome, outcome_id)
    if (
        record is None
        or record.source_id != source_id
        or record.segment != segment
        or record.record_key != record_key
        or record.disposition == "accepted"
        or record_key.startswith("opaque:")
    ):
        raise RecordAccountingError("resolution target is not the exact unresolved source record")
    return record


def append_resolution(
    session: Session,
    *,
    prior: CollectionRecordOutcome,
    replacement: CollectionRecordOutcome,
    membership: CollectionRecordMembership,
    resolved_at: datetime,
) -> None:
    if (
        replacement.disposition != "accepted"
        or replacement.document["evidence_id"] is None
        or (prior.source_id, prior.segment, prior.record_key)
        != (replacement.source_id, replacement.segment, replacement.record_key)
        or (prior.input_sha256, prior.processing_version, prior.policy_sha256)
        == (replacement.input_sha256, replacement.processing_version, replacement.policy_sha256)
        or membership.outcome_id != replacement.outcome_id
        or membership.observed_at < prior.observed_at
        or membership.observed_at > resolved_at
    ):
        raise RecordAccountingError("resolution requires a corrected exact accepted record")
    old_time = prior.document["source_updated_at"]
    new_time = replacement.document["source_updated_at"]
    if old_time is not None and (new_time is None or new_time < old_time):
        raise RecordAccountingError("resolution cannot replace a newer upstream record")
    existing = session.get(CollectionRecordResolution, prior.outcome_id)
    if existing is not None:
        if existing.replacement_id != replacement.outcome_id:
            raise RecordAccountingError("resolution target already has a different replacement")
        return
    values = {
        "outcome_id": prior.outcome_id,
        "replacement_id": replacement.outcome_id,
        "membership_id": membership.membership_id,
        "resolved_at": timestamp(resolved_at),
    }
    session.add(
        CollectionRecordResolution(
            outcome_id=prior.outcome_id,
            replacement_id=replacement.outcome_id,
            membership_id=membership.membership_id,
            resolved_at=resolved_at,
            record_hash=sha256_id(canonical_json_bytes(values)),
        )
    )
    session.flush()
