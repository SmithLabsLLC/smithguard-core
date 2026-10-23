"""Bounded replay of finalized GitHub evidence accepted empty by a legacy parser."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.acquisition import AcquisitionLimits, AcquisitionRequest
from smithguard.authority import AuthorityPolicy
from smithguard.collectors import (
    COLLECTOR_SPECS,
    GITHUB_ADVISORY,
    GitHubAdvisoryCollection,
    GitHubAdvisoryRestCollector,
    project_github_advisory_publication_scope,
    transform_github_advisories,
)
from smithguard.db.models import (
    EvidenceFinalizationRecord,
    EvidenceRecord,
    IngestionBatchRecord,
    SourceIncidentLinkRecord,
    SourceReconciliationRunRecord,
)
from smithguard.evidence import EvidenceStore
from smithguard.identifiers import (
    INGEST_JSON_MAX_DEPTH,
    INGEST_JSON_MAX_NODES,
    DuplicateJsonKeyError,
    canonical_json_bytes,
    parse_timestamp,
    sha256_id,
    strict_json_loads,
    timestamp,
)
from smithguard.ingestion import ingest_bytes
from smithguard.publication import publish_github_malware_incidents
from smithguard.source_governance import SourceGovernancePolicy
from smithguard.source_inventory import MAX_RUN_OBSERVATIONS, STABLE_ID
from smithguard.source_rights import RightsRegistry

MAX_REPLAY_LIMIT = 100
MAX_REPLAY_BODY_BYTES = 8 * 1024 * 1024
QUERY_CHUNK_SIZE = 1000
GHSA_ID = re.compile(r"^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$")


class RetainedReplayError(ValueError):
    """The retained replay boundary is incomplete, ambiguous, or inconsistent."""


@dataclass(frozen=True, slots=True)
class RetainedReplayCandidate:
    upstream_id: str
    evidence_id: str
    source_record_id: str
    canonical_url: str
    retrieved_at: datetime
    source_published_at: datetime | None
    source_modified_at: datetime | None
    digest: str
    byte_count: int
    media_type: str
    legacy_batch_id: str
    legacy_idempotency_key_hash: str


@dataclass(frozen=True, slots=True)
class RetainedReplayReport:
    inventory_observation_count: int
    eligible_candidate_count: int
    selected_count: int
    replayed_count: int
    normalized_record_count: int
    published_incident_count: int
    has_more: bool
    next_after_evidence_id: str | None


def _chunks(values: tuple[str, ...]) -> Iterable[tuple[str, ...]]:
    for offset in range(0, len(values), QUERY_CHUNK_SIZE):
        yield values[offset : offset + QUERY_CHUNK_SIZE]


def _inventory_ids(
    session: Session,
    *,
    inventory_run_id: str,
    governance_policy: SourceGovernancePolicy,
) -> tuple[str, ...]:
    if not STABLE_ID.fullmatch(inventory_run_id):
        raise RetainedReplayError("inventory run ID is invalid")
    pages = tuple(
        session.scalars(
            select(SourceReconciliationRunRecord)
            .where(
                SourceReconciliationRunRecord.source_id == GITHUB_ADVISORY,
                SourceReconciliationRunRecord.inventory_run_id == inventory_run_id,
            )
            .order_by(SourceReconciliationRunRecord.page_index)
        )
    )
    if not pages:
        raise RetainedReplayError("inventory run is missing")
    if len(pages) > 10_000 or tuple(page.page_index for page in pages) != tuple(
        range(1, len(pages) + 1)
    ):
        raise RetainedReplayError("inventory run is not contiguous")
    cutoff = pages[0].reconciled_at
    observed: list[str] = []
    prior_output_hash: str | None = None
    for index, page in enumerate(pages, start=1):
        terminal = index == len(pages)
        if (
            page.connector_id != COLLECTOR_SPECS[GITHUB_ADVISORY].connector_id
            or page.policy_id != governance_policy.policy_id
            or page.policy_sha256 != governance_policy.policy_sha256
            or page.reconciled_at != cutoff
        ):
            raise RetainedReplayError("inventory run authority changed")
        if index == 1:
            if page.continuation_in_hash is not None:
                raise RetainedReplayError("inventory run has an invalid first page")
        elif page.continuation_in_hash != prior_output_hash:
            raise RetainedReplayError("inventory run continuation is inconsistent")
        if terminal:
            if (
                page.has_more
                or page.continuation_out_hash is not None
                or not page.complete_inventory
                or page.state not in {"complete", "unresolved"}
            ):
                raise RetainedReplayError("inventory run is not terminal and complete")
        elif (
            not page.has_more
            or page.continuation_out_hash is None
            or page.complete_inventory
            or page.state != "in_progress"
        ):
            raise RetainedReplayError("inventory run ended before its terminal page")
        page_ids = page.observed_record_ids
        if not isinstance(page_ids, list) or not all(
            isinstance(value, str) and GHSA_ID.fullmatch(value) for value in page_ids
        ):
            raise RetainedReplayError("inventory run contains an invalid advisory identity")
        observed.extend(page_ids)
        if page.observed_count != len(observed):
            raise RetainedReplayError("inventory run count is inconsistent")
        prior_output_hash = page.continuation_out_hash
    if (
        len(observed) > MAX_RUN_OBSERVATIONS
        or len(set(observed)) != len(observed)
        or pages[-1].observed_count != len(observed)
    ):
        raise RetainedReplayError("inventory run observations are duplicated or out of bounds")
    return tuple(sorted(observed))


def _latest_evidence_by_upstream(
    session: Session,
    upstream_ids: tuple[str, ...],
) -> dict[str, EvidenceRecord]:
    latest: dict[str, EvidenceRecord] = {}
    latest_effective_at: dict[str, datetime] = {}
    ambiguous: set[str] = set()
    source_identity = func.split_part(EvidenceRecord.source_record_id, ":", 1)
    for chunk in _chunks(upstream_ids):
        rows = session.scalars(
            select(EvidenceRecord)
            .where(
                EvidenceRecord.source_id == GITHUB_ADVISORY,
                source_identity.in_(chunk),
            )
            .order_by(
                source_identity,
                func.coalesce(
                    EvidenceRecord.source_modified_at,
                    EvidenceRecord.retrieved_at,
                ).desc(),
                EvidenceRecord.source_record_id.desc(),
                EvidenceRecord.revision.desc(),
                EvidenceRecord.id.desc(),
            )
        )
        for row in rows:
            upstream_id = row.source_record_id.split(":", 1)[0]
            effective_at = row.source_modified_at or row.retrieved_at
            current = latest.get(upstream_id)
            if current is None:
                latest[upstream_id] = row
                latest_effective_at[upstream_id] = effective_at
            elif row.id != current.id and effective_at == latest_effective_at[upstream_id]:
                ambiguous.add(upstream_id)
    for upstream_id in ambiguous:
        latest.pop(upstream_id, None)
    return latest


def _legacy_empty_batch(record: IngestionBatchRecord, evidence: EvidenceRecord) -> bool:
    return (
        record.outcome == "accepted"
        and record.raw_evidence_id == evidence.id
        and record.input_sha256 == evidence.sha256
        and record.processing_version is None
        and record.governance_decision_id is None
        and record.idempotency_root_hash is None
        and record.representation_hash is None
        and record.retry_of_batch_id is None
        and record.record_count == 0
        and record.normalized_record_ids == []
        and record.quarantine_reasons == []
        and record.coverage == []
    )


def _candidates(
    session: Session,
    *,
    upstream_ids: tuple[str, ...],
) -> tuple[RetainedReplayCandidate, ...]:
    linked: set[str] = set()
    for chunk in _chunks(upstream_ids):
        linked.update(
            session.scalars(
                select(SourceIncidentLinkRecord.upstream_record_id)
                .where(
                    SourceIncidentLinkRecord.source_id == GITHUB_ADVISORY,
                    SourceIncidentLinkRecord.upstream_record_id.in_(chunk),
                )
                .distinct()
            )
        )
    unlinked = tuple(value for value in upstream_ids if value not in linked)
    evidence_by_upstream = _latest_evidence_by_upstream(session, unlinked)
    evidence_ids = tuple(sorted({row.id for row in evidence_by_upstream.values()}))
    batches_by_evidence: dict[str, list[IngestionBatchRecord]] = {}
    finalizations_by_digest: dict[str, EvidenceFinalizationRecord] = {}
    for chunk in _chunks(evidence_ids):
        for batch in session.scalars(
            select(IngestionBatchRecord).where(IngestionBatchRecord.raw_evidence_id.in_(chunk))
        ):
            if batch.raw_evidence_id is not None:
                batches_by_evidence.setdefault(batch.raw_evidence_id, []).append(batch)
        chunk_digests = tuple(
            sorted(
                {
                    evidence.sha256
                    for evidence in evidence_by_upstream.values()
                    if evidence.id in chunk
                }
            )
        )
        if chunk_digests:
            for finalization in session.scalars(
                select(EvidenceFinalizationRecord).where(
                    EvidenceFinalizationRecord.digest.in_(chunk_digests)
                )
            ):
                finalizations_by_digest[finalization.digest] = finalization
    candidates: list[RetainedReplayCandidate] = []
    for upstream_id in unlinked:
        evidence = evidence_by_upstream.get(upstream_id)
        if evidence is None:
            continue
        batches = batches_by_evidence.get(evidence.id, [])
        finalization = finalizations_by_digest.get(evidence.sha256)
        if (
            evidence.storage_state != "stored_immutable"
            or evidence.storage_key != evidence.sha256
            or len(batches) != 1
            or not _legacy_empty_batch(batches[0], evidence)
            or finalization is None
            or finalization.state != "finalized"
            or finalization.evidence_id != evidence.id
            or finalization.digest != evidence.sha256
            or finalization.staging_key != evidence.sha256
            or finalization.byte_count != evidence.byte_count
        ):
            continue
        batch = batches[0]
        candidates.append(
            RetainedReplayCandidate(
                upstream_id=upstream_id,
                evidence_id=evidence.id,
                source_record_id=evidence.source_record_id,
                canonical_url=evidence.canonical_url,
                retrieved_at=evidence.retrieved_at,
                source_published_at=evidence.source_published_at,
                source_modified_at=evidence.source_modified_at,
                digest=evidence.sha256,
                byte_count=evidence.byte_count,
                media_type=evidence.media_type,
                legacy_batch_id=batch.batch_id,
                legacy_idempotency_key_hash=batch.idempotency_key_hash,
            )
        )
    return tuple(sorted(candidates, key=lambda item: item.evidence_id))


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.isascii():
        raise RetainedReplayError(f"{label} is invalid")
    try:
        return parse_timestamp(value, maximum=64)
    except ValueError as error:
        if getattr(error, "reason", None) == "naive":
            raise RetainedReplayError(f"{label} must include a timezone") from error
        raise RetainedReplayError(f"{label} is invalid") from error


def _decode_advisory(body: bytes) -> Mapping[str, Any]:
    if not body or len(body) > MAX_REPLAY_BODY_BYTES:
        raise RetainedReplayError("retained evidence body is out of bounds")

    try:
        # Retained evidence was accepted at ingestion under the collector's bound.
        document = strict_json_loads(
            body.decode("utf-8", errors="strict"),
            max_nodes=INGEST_JSON_MAX_NODES,
            max_depth=INGEST_JSON_MAX_DEPTH,
        )
    except (UnicodeDecodeError, RecursionError) as error:
        raise RetainedReplayError("retained evidence is not valid JSON") from error
    except DuplicateJsonKeyError as error:
        raise RetainedReplayError("retained evidence contains a duplicate JSON key") from error
    except ValueError as error:
        reason = getattr(error, "reason", None)
        if reason == "non_finite":
            raise RetainedReplayError(
                "retained evidence contains an invalid JSON number"
            ) from error
        if reason in {"too_many_nodes", "too_deep"}:
            raise RetainedReplayError("retained evidence exceeds its bounded shape") from error
        raise RetainedReplayError("retained evidence is not valid JSON") from error
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise RetainedReplayError("retained evidence must contain one advisory")
    try:
        canonical = canonical_json_bytes(document)
    except ValueError as error:
        raise RetainedReplayError("retained evidence is not the canonical advisory body") from error
    if canonical != body:
        raise RetainedReplayError("retained evidence is not the canonical advisory body")
    return document[0]


def _replay_candidate(
    session: Session,
    *,
    candidate: RetainedReplayCandidate,
    evidence_store: EvidenceStore,
    registry: RightsRegistry,
    governance_policy: SourceGovernancePolicy,
    authority_policy: AuthorityPolicy,
    replayed_at: datetime,
) -> tuple[int, int]:
    verified = evidence_store.verify(candidate.digest)
    if (
        verified.digest != candidate.digest
        or verified.byte_count != candidate.byte_count
        or verified.storage_key != candidate.digest
    ):
        raise RetainedReplayError("retained evidence verification metadata changed")
    body = evidence_store.read_bytes(candidate.digest)
    if len(body) != candidate.byte_count or sha256_id(body) != candidate.digest:
        raise RetainedReplayError("retained evidence bytes changed")
    advisory = _decode_advisory(body)
    advisory_id = advisory.get("ghsa_id")
    if (
        not isinstance(advisory_id, str)
        or GHSA_ID.fullmatch(advisory_id) is None
        or advisory_id != candidate.upstream_id
        or advisory.get("type") != "malware"
    ):
        raise RetainedReplayError("retained advisory identity is invalid")
    published_at = _parse_time(advisory.get("published_at"), label="advisory publish time")
    updated_at = _parse_time(advisory.get("updated_at"), label="advisory update time")
    if (
        candidate.source_record_id != f"{advisory_id}:{timestamp(updated_at)}"
        or candidate.canonical_url != advisory.get("html_url")
        or candidate.source_published_at != published_at
        or (candidate.source_modified_at is not None and candidate.source_modified_at != updated_at)
    ):
        raise RetainedReplayError("retained advisory source identity changed")
    withdrawn = advisory.get("withdrawn_at")
    if withdrawn is not None:
        _parse_time(withdrawn, label="advisory withdrawal time")
    update_identity = f"{advisory_id}:{timestamp(updated_at)}"
    idempotency_keys = (
        f"{update_identity}:{sha256_id(body)}",
        update_identity,
    )
    matching_idempotency_keys = tuple(
        value
        for value in idempotency_keys
        if "sha256:" + sha256(value.encode("utf-8")).hexdigest()
        == candidate.legacy_idempotency_key_hash
    )
    if len(matching_idempotency_keys) != 1:
        raise RetainedReplayError("retained advisory legacy idempotency identity changed")
    idempotency_key = matching_idempotency_keys[0]
    connector = COLLECTOR_SPECS[GITHUB_ADVISORY]
    governance = governance_policy.authorize_collection(
        connector_id=connector.connector_id,
        source_id=GITHUB_ADVISORY,
        acquisition_method=connector.collection_method,
        operating_mode="reconciliation",
        canonical_url=candidate.canonical_url,
        source_record_id=candidate.source_record_id,
        authorized_at=replayed_at,
    )

    def current_transform(
        records: tuple[Mapping[str, Any], ...],
    ) -> tuple[Mapping[str, Any], ...]:
        projected = tuple(
            project_github_advisory_publication_scope(record)[0] for record in records
        )
        return transform_github_advisories(
            projected,
            authority_policy=authority_policy,
        )

    outcome = ingest_bytes(
        session,
        evidence_store=evidence_store,
        source=registry.get(GITHUB_ADVISORY).source,
        governance=governance,
        request=AcquisitionRequest(
            source_record_id=candidate.source_record_id,
            canonical_url=candidate.canonical_url,
            retrieved_at=candidate.retrieved_at,
            source_published_at=published_at,
            source_modified_at=candidate.source_modified_at,
            media_type=candidate.media_type,
            declared_content_length=len(body),
            redirect_count=0,
            transport_elapsed_seconds=0.0,
        ),
        body=body,
        idempotency_key=idempotency_key,
        collection_method=connector.collection_method,
        identity_verification="verified",
        signature_state="unsupported",
        limits=AcquisitionLimits(max_input_bytes=MAX_REPLAY_BODY_BYTES),
        record_transform=current_transform,
        allow_empty_transformed_records=False,
        processing_version=GitHubAdvisoryRestCollector.PROCESSING_VERSION,
    )
    if not outcome.created or outcome.outcome != "accepted" or outcome.record_count < 1:
        raise RetainedReplayError("retained advisory did not create governed normalized output")
    governed_batch = session.get(IngestionBatchRecord, outcome.batch_id)
    if (
        governed_batch is None
        or governed_batch.retry_of_batch_id != candidate.legacy_batch_id
        or governed_batch.idempotency_root_hash != candidate.legacy_idempotency_key_hash
        or governed_batch.governance_decision_id is None
        or governed_batch.processing_version != GitHubAdvisoryRestCollector.PROCESSING_VERSION
    ):
        raise RetainedReplayError("retained advisory governed retry lineage is invalid")
    published = publish_github_malware_incidents(
        session,
        collection=GitHubAdvisoryCollection(
            advisory_id=advisory_id,
            published_at=published_at,
            updated_at=updated_at,
            withdrawn=withdrawn is not None,
            outcome=outcome,
        ),
        published_at=replayed_at,
        authority_policy=authority_policy,
        governance_policy=governance_policy,
    )
    if not published:
        raise RetainedReplayError("retained advisory created no source incident link")
    return outcome.record_count, len(published)


def replay_retained_github_evidence(
    session: Session,
    *,
    evidence_store: EvidenceStore,
    registry: RightsRegistry,
    governance_policy: SourceGovernancePolicy,
    authority_policy: AuthorityPolicy,
    inventory_run_id: str,
    limit: int = MAX_REPLAY_LIMIT,
    after_evidence_id: str | None = None,
    replayed_at: datetime | None = None,
) -> RetainedReplayReport:
    """Replay one transaction-bounded page of exact retained GitHub evidence."""
    if not 1 <= limit <= MAX_REPLAY_LIMIT:
        raise RetainedReplayError("retained replay limit is invalid")
    if after_evidence_id is not None and STABLE_ID.fullmatch(after_evidence_id) is None:
        raise RetainedReplayError("retained replay continuation is invalid")
    requested_at = replayed_at or datetime.now(UTC)
    if requested_at.tzinfo is None or requested_at.utcoffset() is None:
        raise RetainedReplayError("retained replay time must include a timezone")
    occurred_at = requested_at.astimezone(UTC)
    if authority_policy.source_rights_register_id != registry.register_id:
        raise RetainedReplayError("authority policy and source-rights register differ")
    upstream_ids = _inventory_ids(
        session,
        inventory_run_id=inventory_run_id,
        governance_policy=governance_policy,
    )
    eligible = _candidates(session, upstream_ids=upstream_ids)
    remaining = tuple(
        candidate
        for candidate in eligible
        if after_evidence_id is None or candidate.evidence_id > after_evidence_id
    )
    selected = remaining[:limit]
    has_more = len(remaining) > len(selected)
    normalized_count = 0
    published_count = 0
    for candidate in selected:
        normalized, published = _replay_candidate(
            session,
            candidate=candidate,
            evidence_store=evidence_store,
            registry=registry,
            governance_policy=governance_policy,
            authority_policy=authority_policy,
            replayed_at=occurred_at,
        )
        normalized_count += normalized
        published_count += published
    return RetainedReplayReport(
        inventory_observation_count=len(upstream_ids),
        eligible_candidate_count=len(eligible),
        selected_count=len(selected),
        replayed_count=len(selected),
        normalized_record_count=normalized_count,
        published_incident_count=published_count,
        has_more=has_more,
        next_after_evidence_id=(selected[-1].evidence_id if has_more and selected else None),
    )
