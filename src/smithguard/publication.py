"""Deterministic public incidents derived from canonical source classifications."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.authority import (
    AuthorityEvaluation,
    AuthorityPolicy,
    AuthorityPolicyError,
    authority_decision_document,
    evaluation_from_lineage,
    load_authority_policy,
)
from smithguard.collectors import (
    GITHUB_ADVISORY,
    GitHubAdvisoryCollection,
)
from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import (
    AffectedRangeRecord,
    ArtifactRecord,
    ClaimRecord,
    IncidentRecord,
    SourceGovernanceDecisionRecord,
    SourceIncidentLinkRecord,
)
from smithguard.db.repository import append_contract
from smithguard.identifiers import (
    canonical_json_bytes,
    sha256_id,
    stable_id,
    timestamp,
)
from smithguard.incidents import (
    IncidentSeed,
    apply_incident_event,
    create_incident,
)
from smithguard.publication_lifecycle import LifecycleEvent, append_lifecycle_event
from smithguard.query import latest_incident
from smithguard.range_evaluation import normalize_github_npm_advisory_range
from smithguard.reconciliation import (
    SourceMember,
    append_source_member,
    cluster_id_for,
)
from smithguard.review_queue import ReviewEvent, append_review_event
from smithguard.source_governance import (
    DEFAULT_GOVERNANCE_POLICY_PATH,
    SourceGovernanceError,
    SourceGovernancePolicy,
)
from smithguard.source_rights import RightsRegistry

COLLECTOR_ACTOR = "system-github-advisory-collector"
ATTRIBUTION_UNKNOWN = (
    "SmithGuard relays GitHub Advisory Database facts and does not claim original detection."
)
AUTOMATED_ANALYSIS_LIMIT = (
    "SmithGuard applied a source policy and did not independently analyze the package."
)


class PublicationError(ValueError):
    """Canonical source records cannot be published consistently."""


def _governance_decision(
    session: Session,
    *,
    outcome: Any,
    policy: SourceGovernancePolicy,
    public_status: str,
) -> SourceGovernanceDecisionRecord:
    decision_id = outcome.governance_decision_id
    if decision_id is None:
        raise PublicationError("accepted collection has no source governance decision")
    decision = session.get(SourceGovernanceDecisionRecord, decision_id)
    if decision is None:
        raise PublicationError("source governance decision is missing")
    try:
        policy.authorize_stored_publication(decision, public_status=public_status)
    except SourceGovernanceError as error:
        raise PublicationError(str(error)) from error
    return decision


def _append_publication_lifecycle(
    session: Session,
    *,
    incident: Any,
    event_type: str,
    governance: SourceGovernanceDecisionRecord,
    evidence_id: str,
    authority_decision_id: str,
    old_status: str | None,
    new_status: str,
    reason_code: str,
) -> None:
    document = incident.document
    incident_id = document["id"]
    incident_revision = document["revision"]
    changed_at = document["last_changed_at"]
    if isinstance(changed_at, str):
        changed_at = datetime.fromisoformat(changed_at.replace("Z", "+00:00"))
    append_lifecycle_event(
        session,
        event=LifecycleEvent(
            event_type=event_type,
            actor_type="system",
            actor_id=COLLECTOR_ACTOR,
            source_id=governance.source_id,
            source_record_id=governance.source_record_id,
            evidence_id=evidence_id,
            governance_decision_id=governance.decision_id,
            authority_decision_id=authority_decision_id,
            incident_id=incident_id,
            incident_revision=incident_revision,
            old_public_status=old_status,
            new_public_status=new_status,
            reason_code=reason_code,
            occurred_at=changed_at,
        ),
        idempotency_key=(
            f"automated:{incident_id}:{incident_revision}:{event_type}:"
            f"{governance.decision_id}:{authority_decision_id}"
        ),
    )


def _latest_links(
    session: Session,
    advisory_id: str,
) -> dict[str, SourceIncidentLinkRecord]:
    rows = session.scalars(
        select(SourceIncidentLinkRecord)
        .where(
            SourceIncidentLinkRecord.source_id == GITHUB_ADVISORY,
            SourceIncidentLinkRecord.upstream_record_id == advisory_id,
        )
        .order_by(
            SourceIncidentLinkRecord.artifact_id,
            SourceIncidentLinkRecord.sequence.desc(),
        )
    )
    latest: dict[str, SourceIncidentLinkRecord] = {}
    for row in rows:
        latest.setdefault(row.artifact_id, row)
    return latest


def _append_link(
    session: Session,
    *,
    advisory_id: str,
    artifact_id: str,
    incident_id: str,
    state: str,
    source_updated_at: datetime,
    evidence_id: str,
    observed_at: datetime,
) -> SourceIncidentLinkRecord:
    lock_name = f"source-incident-link:{GITHUB_ADVISORY}:{advisory_id}:{artifact_id}"
    advisory_xact_lock(session, lock_name)
    current = session.scalar(
        select(SourceIncidentLinkRecord)
        .where(
            SourceIncidentLinkRecord.source_id == GITHUB_ADVISORY,
            SourceIncidentLinkRecord.upstream_record_id == advisory_id,
            SourceIncidentLinkRecord.artifact_id == artifact_id,
        )
        .order_by(SourceIncidentLinkRecord.sequence.desc())
        .limit(1)
    )
    if (
        current is not None
        and current.state == state
        and current.source_updated_at == source_updated_at
        and current.evidence_id == evidence_id
        and current.incident_id == incident_id
    ):
        return current
    sequence = 1 if current is None else current.sequence + 1
    values = {
        "link_event_id": stable_id(
            "source-incident-link",
            GITHUB_ADVISORY,
            advisory_id,
            artifact_id,
            str(sequence),
        ),
        "source_id": GITHUB_ADVISORY,
        "upstream_record_id": advisory_id,
        "artifact_id": artifact_id,
        "incident_id": incident_id,
        "sequence": sequence,
        "state": state,
        "source_updated_at": source_updated_at,
        "evidence_id": evidence_id,
        "observed_at": observed_at,
    }
    record = SourceIncidentLinkRecord(
        **values,
        record_hash=sha256_id(
            canonical_json_bytes(
                {
                    **values,
                    "source_updated_at": timestamp(source_updated_at),
                    "observed_at": timestamp(observed_at),
                }
            )
        ),
    )
    session.add(record)
    session.flush()
    return record


def _records(
    session: Session,
    identifiers: Iterable[str],
) -> tuple[
    tuple[ArtifactRecord, ...],
    tuple[ClaimRecord, ...],
    tuple[AffectedRangeRecord, ...],
]:
    values = tuple(identifiers)
    if not values:
        return (), (), ()
    artifact_rows = tuple(
        session.scalars(
            select(ArtifactRecord)
            .where(ArtifactRecord.id.in_(values))
            .order_by(ArtifactRecord.id, ArtifactRecord.revision.desc())
        )
    )
    claim_rows = tuple(
        session.scalars(
            select(ClaimRecord)
            .where(ClaimRecord.id.in_(values))
            .order_by(ClaimRecord.id, ClaimRecord.revision.desc())
        )
    )
    range_rows = tuple(
        session.scalars(
            select(AffectedRangeRecord)
            .where(AffectedRangeRecord.id.in_(values))
            .order_by(AffectedRangeRecord.id, AffectedRangeRecord.revision.desc())
        )
    )

    def latest(rows: tuple[Any, ...]) -> tuple[Any, ...]:
        selected: dict[str, Any] = {}
        for row in rows:
            selected.setdefault(row.id, row)
        return tuple(selected.values())

    return latest(artifact_rows), latest(claim_rows), latest(range_rows)


def _event(
    *,
    event_id: str,
    incident_id: str,
    event_type: str,
    old_status: str | None,
    new_status: str,
    evidence_id: str,
    occurred_at: datetime,
    reason_code: str,
    superseded_revision: int | None,
    confidence: str,
) -> dict[str, Any]:
    value = timestamp(occurred_at)
    return {
        "id": event_id,
        "kind": "incident_event",
        "schema_version": "1.0.0",
        "revision": 1,
        "created_at": value,
        "updated_at": value,
        "data_classification": "public",
        "incident_id": incident_id,
        "event_type": event_type,
        "old_status": old_status,
        "new_status": new_status,
        "actor_type": "system",
        "actor_id": COLLECTOR_ACTOR,
        "reason_code": reason_code,
        "evidence_ids": [evidence_id],
        "occurred_at": value,
        "confidence": confidence,
        "superseded_revision": superseded_revision,
    }


def _lineage_evaluation(
    claim: ClaimRecord,
    *,
    policy: AuthorityPolicy,
) -> AuthorityEvaluation:
    lineage = claim.provenance.get("claim_lineage")
    if not isinstance(lineage, dict):
        raise PublicationError("malware claim has no validated authority lineage")
    try:
        return evaluation_from_lineage(lineage, policy=policy)
    except AuthorityPolicyError as error:
        raise PublicationError("malware claim authority lineage is invalid") from error


def _decision_note(
    evaluation: AuthorityEvaluation,
    *,
    range_backed: bool,
) -> str:
    if evaluation.public_status == "confirmed":
        return (
            "Confirmed under SmithGuard's automated source policy from the named "
            "authoritative source. " + AUTOMATED_ANALYSIS_LIMIT
        )
    if evaluation.public_status == "reported":
        subject = "this package range" if range_backed else "this exact artifact"
        return (
            f"An identified source reports {subject} as malware, but "
            "SmithGuard's confirmation policy has not passed."
        )
    if evaluation.public_status == "corroborated":
        subject = "this package range" if range_backed else "this exact artifact"
        return (
            f"Independent sources report {subject} as malware; no approved "
            "authority has confirmed it."
        )
    if evaluation.public_status == "withdrawn":
        return "The upstream malware claim is withdrawn and is not treated as active."
    if evaluation.public_status == "disputed":
        return "Credible evidence disputes this malware claim; disruptive automation is suspended."
    raise PublicationError("malware authority status is unsupported")


def _validated_github_ranges(
    artifact: ArtifactRecord,
    ranges: tuple[AffectedRangeRecord, ...],
) -> tuple[str, ...]:
    if artifact.identity_state == "exact":
        if (
            len(ranges) != 1
            or ranges[0].range_type != "EXACT"
            or ranges[0].expression != artifact.version
        ):
            raise PublicationError("GitHub exact malware record has an invalid range")
    elif (
        artifact.identity_state == "unresolved"
        and artifact.ecosystem == "npm"
        and artifact.version is None
        and artifact.digest is None
        and ranges
    ):
        for affected_range in ranges:
            normalized = normalize_github_npm_advisory_range(affected_range.expression)
            if (
                affected_range.range_type != "SEMVER"
                or affected_range.evaluation_state != "supported"
                or normalized is None
                or normalized != affected_range.expression
            ):
                raise PublicationError("GitHub npm malware record has an invalid range")
    else:
        raise PublicationError("GitHub malware record has an invalid artifact scope")
    return tuple(sorted(affected_range.id for affected_range in ranges))


def _append_exception_review(
    session: Session,
    *,
    incident_id: str,
    artifact_id: str,
    claim_id: str,
    evidence_id: str,
    evaluation: AuthorityEvaluation,
    occurred_at: datetime,
) -> None:
    if not evaluation.exception_required or evaluation.exception_reason_code is None:
        return
    queue_item_id = stable_id(
        "review-item",
        "malware-authority",
        incident_id,
        claim_id,
        evaluation.exception_reason_code,
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
            actor_id=COLLECTOR_ACTOR,
            reason_code=evaluation.exception_reason_code,
            evidence_ids=(evidence_id,),
            occurred_at=occurred_at,
        ),
    )


def _append_source_observation(
    session: Session,
    *,
    advisory_id: str,
    artifact: ArtifactRecord,
    claim: ClaimRecord,
    evidence_id: str,
    evaluation: AuthorityEvaluation,
    observed_at: datetime,
) -> None:
    append_source_member(
        session,
        member=SourceMember(
            source_id=evaluation.transport_source_id,
            source_record_id=f"{advisory_id}:{claim.id}",
            evidence_id=evidence_id,
            artifact_id=artifact.id,
            independent_origin_id=(
                evaluation.assertion_source_id or evaluation.transport_source_id
            ),
            claim_fingerprint=sha256_id(
                canonical_json_bytes(
                    {
                        "artifact_id": artifact.id,
                        "claim_type": claim.claim_type,
                        "predicate": claim.predicate,
                        "state": claim.state,
                    }
                )
            ),
            observed_at=observed_at,
            relation=("withdraws" if evaluation.public_status == "withdrawn" else None),
        ),
    )


def _withdrawal_evaluation(
    current: Any,
    *,
    advisory_id: str,
) -> AuthorityEvaluation:
    authority = current.document.get("authority")
    source_references: tuple[str, ...] = (f"https://github.com/advisories/{advisory_id}",)
    upstream_ids: tuple[str, ...] = (advisory_id,)
    transport_source_id = GITHUB_ADVISORY
    assertion_source_id = None
    confirming_authority_id = None
    if isinstance(authority, dict):
        prior_references = authority.get("source_references")
        prior_upstream_ids = authority.get("upstream_ids")
        prior_transport = authority.get("transport_source_id")
        if (
            isinstance(prior_references, list)
            and prior_references
            and all(isinstance(value, str) and value for value in prior_references)
        ):
            source_references = tuple(prior_references)
        if (
            isinstance(prior_upstream_ids, list)
            and prior_upstream_ids
            and all(isinstance(value, str) and value for value in prior_upstream_ids)
        ):
            upstream_ids = tuple(prior_upstream_ids)
        if isinstance(prior_transport, str) and prior_transport:
            transport_source_id = prior_transport
        if isinstance(authority.get("assertion_source_id"), str):
            assertion_source_id = authority["assertion_source_id"]
        if isinstance(authority.get("confirming_authority_id"), str):
            confirming_authority_id = authority["confirming_authority_id"]
    return AuthorityEvaluation(
        public_status="withdrawn",
        confirmation_method="withdrawal",
        transport_source_id=transport_source_id,
        assertion_source_id=assertion_source_id,
        confirming_authority_id=confirming_authority_id,
        authority_rule_id="gbsec:authority-rule:upstream-withdrawal-v1",
        reason_code="upstream_malware_claim_withdrawn",
        upstream_ids=upstream_ids,
        source_references=source_references,
    )


def _create_github_incident(
    session: Session,
    *,
    claim: ClaimRecord,
    artifact: ArtifactRecord,
    range_backed: bool,
    incident_id: str,
    evaluation: AuthorityEvaluation,
    affected_range_ids: tuple[str, ...],
    occurred_at: datetime,
    decision: dict[str, Any],
    evidence_id: str,
) -> IncidentRecord:
    source_published = claim.provenance.get("source_published_at")
    observed_at = (
        datetime.fromisoformat(source_published.replace("Z", "+00:00"))
        if source_published is not None
        else occurred_at
    )
    created = create_incident(
        session,
        seed=IncidentSeed(
            incident_id=incident_id,
            title=f"Malicious {artifact.ecosystem} package range: {artifact.name}"
            if range_backed
            else f"Malicious {artifact.ecosystem} package: {artifact.name}",
            initial_status=evaluation.public_status,
            initial_confidence=evaluation.claim_confidence,
            claim_ids=(claim.id,),
            artifact_ids=(artifact.id,),
            affected_range_ids=affected_range_ids,
            relationship_ids=(),
            coverage=(
                {
                    "ecosystem": artifact.ecosystem,
                    "stage": "matched",
                    "result": "supported",
                    "as_of": timestamp(occurred_at),
                },
            ),
            unknowns=(ATTRIBUTION_UNKNOWN, _decision_note(evaluation, range_backed=range_backed)),
            first_observed_at=min(observed_at, occurred_at),
            created_at=occurred_at,
            authority_decision_ids=(decision["id"],),
            authority=decision,
        ),
        event=_event(
            event_id=stable_id("event", incident_id, "created"),
            incident_id=incident_id,
            event_type="created",
            old_status=None,
            new_status=evaluation.public_status,
            evidence_id=evidence_id,
            occurred_at=occurred_at,
            reason_code=evaluation.reason_code,
            superseded_revision=None,
            confidence=evaluation.claim_confidence,
        ),
    )
    return created


def _update_github_incident(
    session: Session,
    *,
    current: IncidentRecord,
    evaluation: AuthorityEvaluation,
    claim: ClaimRecord,
    affected_range_ids: tuple[str, ...],
    decision: dict[str, Any],
    decision_at: datetime,
    range_backed: bool,
    evidence_id: str,
    incident_id: str,
) -> IncidentRecord:
    event_type = "withdrawn" if evaluation.public_status == "withdrawn" else "corrected"
    details: dict[str, Any] = {
        "add_authority_decision_ids": (decision["id"],),
        "replace_authority": decision,
        "add_unknowns": (_decision_note(evaluation, range_backed=range_backed),),
    }
    if event_type == "corrected":
        details["replacement_claim_ids"] = (claim.id,)
        details["add_affected_range_ids"] = tuple(
            value for value in affected_range_ids if value not in current.affected_range_ids
        )
        details["remove_affected_range_ids"] = tuple(
            value for value in current.affected_range_ids if value not in affected_range_ids
        )
    changed = apply_incident_event(
        session,
        event=_event(
            event_id=stable_id("event", incident_id, event_type, claim.id, decision["id"]),
            incident_id=incident_id,
            event_type=event_type,
            old_status=current.status,
            new_status=evaluation.public_status,
            evidence_id=evidence_id,
            occurred_at=max(decision_at, current.last_changed_at),
            reason_code=evaluation.reason_code,
            superseded_revision=current.revision,
            confidence=evaluation.claim_confidence,
        ),
        details=details,
    )
    return changed


def _publish_github_artifact(
    session: Session,
    *,
    collection: GitHubAdvisoryCollection,
    artifact: ArtifactRecord,
    claim: ClaimRecord | None,
    artifact_ranges: tuple[AffectedRangeRecord, ...],
    policy: AuthorityPolicy,
    source_policy: SourceGovernancePolicy,
    occurred_at: datetime,
) -> dict[str, Any] | None:
    outcome = collection.outcome
    if claim is None or not artifact_ranges:
        return None
    if claim.claim_type != "malicious":
        raise PublicationError("GitHub malware record has an invalid claim")
    affected_range_ids = _validated_github_ranges(artifact, artifact_ranges)
    range_backed = artifact.identity_state != "exact"
    incident_id = stable_id("incident", GITHUB_ADVISORY, collection.advisory_id, artifact.id)
    evaluation = _lineage_evaluation(claim, policy=policy)
    if claim.state == "withdrawn" and evaluation.public_status != "withdrawn":
        raise PublicationError("withdrawn malware claim has an active authority decision")
    if claim.state == "active" and evaluation.public_status == "withdrawn":
        raise PublicationError("active malware claim has a withdrawn authority decision")
    decision_at = claim.updated_at.astimezone(UTC)
    decision = authority_decision_document(
        evaluation=evaluation,
        policy=policy,
        incident_id=incident_id,
        claim_id=claim.id,
        artifact_id=artifact.id,
        evidence_id=outcome.raw_evidence_id,
        decided_at=decision_at,
    )
    governance = _governance_decision(
        session, outcome=outcome, policy=source_policy, public_status=evaluation.public_status
    )
    append_contract(session, "AuthorityDecision", decision)
    _append_source_observation(
        session,
        advisory_id=collection.advisory_id,
        artifact=artifact,
        claim=claim,
        evidence_id=outcome.raw_evidence_id,
        evaluation=evaluation,
        observed_at=decision_at,
    )
    _append_exception_review(
        session,
        incident_id=incident_id,
        artifact_id=artifact.id,
        claim_id=claim.id,
        evidence_id=outcome.raw_evidence_id,
        evaluation=evaluation,
        occurred_at=decision_at,
    )
    current = latest_incident(session, incident_id, public_only=True)
    if current is None:
        selected = _create_github_incident(
            session,
            claim=claim,
            artifact=artifact,
            range_backed=range_backed,
            incident_id=incident_id,
            evaluation=evaluation,
            affected_range_ids=affected_range_ids,
            occurred_at=occurred_at,
            decision=decision,
            evidence_id=outcome.raw_evidence_id,
        )
        lifecycle_type = "published"
        old_status = None
        new_status = evaluation.public_status
    else:
        current_authority = current.document.get("authority")
        current_authority_id = (
            current_authority.get("id") if isinstance(current_authority, dict) else None
        )
        if (
            current.status != evaluation.public_status
            or current.confidence != evaluation.claim_confidence
            or claim.id not in current.claim_ids
            or (tuple(sorted(current.affected_range_ids)) != affected_range_ids)
            or (current_authority_id != decision["id"])
        ):
            selected = _update_github_incident(
                session,
                current=current,
                evaluation=evaluation,
                claim=claim,
                affected_range_ids=affected_range_ids,
                decision=decision,
                decision_at=decision_at,
                range_backed=range_backed,
                evidence_id=outcome.raw_evidence_id,
                incident_id=incident_id,
            )
            lifecycle_type = (
                "withdrawn"
                if evaluation.public_status == "withdrawn"
                else "disputed"
                if evaluation.public_status == "disputed"
                else "corrected"
            )
            old_status = current.status
            new_status = evaluation.public_status
        else:
            selected = current
            lifecycle_type = "published"
            old_status = None
            new_status = current.status
    _append_publication_lifecycle(
        session,
        incident=selected,
        event_type=lifecycle_type,
        governance=governance,
        evidence_id=outcome.raw_evidence_id,
        authority_decision_id=decision["id"],
        old_status=old_status,
        new_status=new_status,
        reason_code=evaluation.reason_code,
    )
    return selected.document


def _reconcile_github_links(
    session: Session,
    *,
    collection: GitHubAdvisoryCollection,
    prior_links: dict[str, SourceIncidentLinkRecord],
    published: list[dict[str, Any]],
    policy: AuthorityPolicy,
    source_policy: SourceGovernancePolicy,
) -> None:
    outcome = collection.outcome
    current_by_artifact = {
        artifact_id: document for document in published for artifact_id in document["artifact_ids"]
    }
    current_artifact_ids = set(current_by_artifact)
    link_state = "withdrawn" if collection.withdrawn else "active"
    for artifact_id, document in current_by_artifact.items():
        _append_link(
            session,
            advisory_id=collection.advisory_id,
            artifact_id=artifact_id,
            incident_id=document["id"],
            state=link_state,
            source_updated_at=collection.updated_at,
            evidence_id=outcome.raw_evidence_id,
            observed_at=collection.updated_at,
        )
    for artifact_id, prior in prior_links.items():
        if artifact_id in current_artifact_ids:
            continue
        current = latest_incident(session, prior.incident_id, public_only=True)
        if current is None:
            raise PublicationError("source link references a missing public incident")
        desired_state = "withdrawn" if collection.withdrawn else "removed"
        if current.status != "withdrawn":
            if not current.claim_ids or not current.artifact_ids:
                raise PublicationError("source link incident is missing its public claim")
            evaluation = _withdrawal_evaluation(current, advisory_id=collection.advisory_id)
            decision_at = max(collection.updated_at, current.last_changed_at)
            decision = authority_decision_document(
                evaluation=evaluation,
                policy=policy,
                incident_id=prior.incident_id,
                claim_id=current.claim_ids[-1],
                artifact_id=artifact_id,
                evidence_id=outcome.raw_evidence_id,
                decided_at=decision_at,
            )
            governance = _governance_decision(
                session, outcome=outcome, policy=source_policy, public_status="withdrawn"
            )
            append_contract(session, "AuthorityDecision", decision)
            removed_artifact = session.scalar(
                select(ArtifactRecord)
                .where(ArtifactRecord.id == artifact_id)
                .order_by(ArtifactRecord.revision.desc())
                .limit(1)
            )
            if removed_artifact is None:
                raise PublicationError("source link references a missing artifact")
            changed = apply_incident_event(
                session,
                event=_event(
                    event_id=stable_id(
                        "event", prior.incident_id, desired_state, timestamp(collection.updated_at)
                    ),
                    incident_id=prior.incident_id,
                    event_type="withdrawn",
                    old_status=current.status,
                    new_status="withdrawn",
                    evidence_id=outcome.raw_evidence_id,
                    occurred_at=decision_at,
                    reason_code=evaluation.reason_code,
                    superseded_revision=current.revision,
                    confidence=evaluation.claim_confidence,
                ),
                details={
                    "add_authority_decision_ids": (decision["id"],),
                    "replace_authority": decision,
                    "add_unknowns": (
                        "GitHub now marks the upstream malware advisory withdrawn."
                        if collection.withdrawn
                        else "GitHub no longer lists this exact artifact in the advisory."
                        if removed_artifact.identity_state == "exact"
                        else "GitHub no longer lists this package range in the advisory.",
                    ),
                },
            )
            _append_publication_lifecycle(
                session,
                incident=changed,
                event_type="withdrawn",
                governance=governance,
                evidence_id=outcome.raw_evidence_id,
                authority_decision_id=decision["id"],
                old_status=current.status,
                new_status="withdrawn",
                reason_code=evaluation.reason_code,
            )
            published.append(changed.document)
        _append_link(
            session,
            advisory_id=collection.advisory_id,
            artifact_id=artifact_id,
            incident_id=prior.incident_id,
            state=desired_state,
            source_updated_at=collection.updated_at,
            evidence_id=outcome.raw_evidence_id,
            observed_at=collection.updated_at,
        )


def publish_github_malware_incidents(
    session: Session,
    *,
    collection: GitHubAdvisoryCollection,
    published_at: datetime,
    authority_policy: AuthorityPolicy | None = None,
    governance_policy: SourceGovernancePolicy | None = None,
) -> tuple[dict[str, Any], ...]:
    """Publish exact-version or npm-range incidents without copying source prose."""
    occurred_at = published_at.astimezone(UTC)
    policy = authority_policy or load_authority_policy()
    if governance_policy is None:
        source_registry = RightsRegistry.from_path(
            DEFAULT_GOVERNANCE_POLICY_PATH.parent / "source-rights-register.json"
        )
        source_policy = SourceGovernancePolicy.from_path(
            DEFAULT_GOVERNANCE_POLICY_PATH, registry=source_registry
        )
    else:
        source_policy = governance_policy
    outcome = collection.outcome
    if outcome.raw_evidence_id is None:
        raise PublicationError("accepted GitHub collection has no evidence identity")
    prior_links = _latest_links(session, collection.advisory_id)
    artifacts, claims, ranges = _records(session, outcome.normalized_record_ids)
    claim_by_artifact: dict[str, ClaimRecord] = {}
    for claim in claims:
        if claim.provenance["source_id"] != GITHUB_ADVISORY:
            continue
        if claim.subject_id in claim_by_artifact:
            raise PublicationError("GitHub malware artifact has multiple source claims")
        claim_by_artifact[claim.subject_id] = claim
    ranges_by_artifact: dict[str, list[AffectedRangeRecord]] = {}
    for affected_range in ranges:
        ranges_by_artifact.setdefault(affected_range.artifact_id, []).append(affected_range)
    published: list[dict[str, Any]] = []
    for artifact in artifacts:
        document = _publish_github_artifact(
            session,
            collection=collection,
            artifact=artifact,
            claim=claim_by_artifact.get(artifact.id),
            artifact_ranges=tuple(ranges_by_artifact.get(artifact.id, ())),
            policy=policy,
            source_policy=source_policy,
            occurred_at=occurred_at,
        )
        if document is not None:
            published.append(document)
    _reconcile_github_links(
        session,
        collection=collection,
        prior_links=prior_links,
        published=published,
        policy=policy,
        source_policy=source_policy,
    )
    return tuple(published)
