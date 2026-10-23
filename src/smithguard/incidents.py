"""Deterministic incident lifecycle over append-only event history."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.contracts.generated import CoverageState
from smithguard.contracts.runtime import parse_contract
from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import (
    AffectedRangeRecord,
    ArtifactRecord,
    AuthorityDecisionRecord,
    ClaimRecord,
    IncidentEventRecord,
    IncidentRecord,
    IncidentSeedRecord,
    IncidentTransitionRecord,
    RelationshipRecord,
)
from smithguard.db.repository import RevisionConflict, append_contract, latest_contract
from smithguard.identifiers import STABLE_ID, canonical_json_bytes, sha256_id, timestamp
from smithguard.query import incident_ids_for_alias, latest_incident

DETAIL_LIST_FIELDS = {
    "add_claim_ids",
    "remove_claim_ids",
    "add_artifact_ids",
    "remove_artifact_ids",
    "add_affected_range_ids",
    "remove_affected_range_ids",
    "add_relationship_ids",
    "remove_relationship_ids",
    "add_authority_decision_ids",
    "replacement_claim_ids",
    "split_incident_ids",
}
DETAIL_FIELDS = DETAIL_LIST_FIELDS | {
    "alias_id",
    "target_incident_id",
    "add_unknowns",
    "replace_coverage",
    "replace_authority",
}
STATUS_CLASSIFICATION_INTERNAL = {"internal_candidate", "emerging_unverified"}
EVENT_DETAIL_FIELDS = {
    "created": set(),
    "state_changed": {
        "add_authority_decision_ids",
        "add_unknowns",
        "replace_authority",
        "replace_coverage",
    },
    "alias_added": {"alias_id", "add_relationship_ids"},
    "redirected": {"target_incident_id", "add_relationship_ids"},
    "merged": {"target_incident_id", "add_relationship_ids"},
    "split": {
        "split_incident_ids",
        "remove_claim_ids",
        "remove_artifact_ids",
        "remove_affected_range_ids",
        "remove_relationship_ids",
        "add_relationship_ids",
        "add_unknowns",
    },
    "disputed": {
        "add_authority_decision_ids",
        "add_unknowns",
        "replace_authority",
    },
    "appealed": {
        "add_authority_decision_ids",
        "add_unknowns",
        "replace_authority",
    },
    "corrected": {
        "add_authority_decision_ids",
        "replacement_claim_ids",
        "add_affected_range_ids",
        "remove_affected_range_ids",
        "add_relationship_ids",
        "add_unknowns",
        "replace_authority",
        "replace_coverage",
    },
    "expired": {"add_unknowns"},
    "withdrawn": {
        "add_authority_decision_ids",
        "add_unknowns",
        "replace_authority",
    },
    "renewed": {
        "add_authority_decision_ids",
        "add_unknowns",
        "replace_authority",
        "replace_coverage",
    },
}


class IncidentLifecycleError(ValueError):
    """An incident event violates deterministic lifecycle rules."""


class IncidentRebuildError(RuntimeError):
    """Persisted append-only history is incomplete or inconsistent."""


@dataclass(frozen=True, slots=True)
class IncidentSeed:
    incident_id: str
    title: str
    initial_status: str
    initial_confidence: str
    claim_ids: tuple[str, ...]
    artifact_ids: tuple[str, ...]
    affected_range_ids: tuple[str, ...]
    relationship_ids: tuple[str, ...]
    coverage: tuple[Mapping[str, Any], ...]
    unknowns: tuple[str, ...]
    first_observed_at: datetime
    created_at: datetime
    authority_decision_ids: tuple[str, ...] = ()
    authority: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class IncidentWrite:
    document: dict[str, Any]
    created: bool


def _stable_ids(values: Sequence[Any], *, field: str, limit: int = 100) -> list[str]:
    if isinstance(values, str) or len(values) > limit:
        raise IncidentLifecycleError(f"{field} exceeds its limit")
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or not STABLE_ID.fullmatch(value):
            raise IncidentLifecycleError(f"{field} contains an invalid stable ID")
        if value not in result:
            result.append(value)
    return result


def _unknowns(values: Sequence[Any]) -> list[str]:
    if isinstance(values, str) or len(values) > 100:
        raise IncidentLifecycleError("unknowns exceed their limit")
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value or len(value) > 300:
            raise IncidentLifecycleError("unknowns contain an invalid value")
        try:
            value.encode("ascii")
        except UnicodeEncodeError as error:
            raise IncidentLifecycleError("unknowns must be ASCII") from error
        if value not in result:
            result.append(value)
    return result


def _validate_seed(seed: IncidentSeed) -> dict[str, Any]:
    if not STABLE_ID.fullmatch(seed.incident_id):
        raise IncidentLifecycleError("incident seed has an invalid stable ID")
    if not seed.title or len(seed.title) > 300:
        raise IncidentLifecycleError("incident seed has an invalid title")
    try:
        seed.title.encode("ascii")
    except UnicodeEncodeError as error:
        raise IncidentLifecycleError("incident title must be ASCII") from error
    coverage = [
        CoverageState.model_validate(dict(value)).model_dump(mode="json", exclude_none=False)
        for value in seed.coverage
    ]
    if not coverage or len(coverage) > 20:
        raise IncidentLifecycleError("incident coverage must contain between 1 and 20 entries")
    ecosystems = [item["ecosystem"] for item in coverage]
    if len(ecosystems) != len(set(ecosystems)):
        raise IncidentLifecycleError("incident coverage repeats an ecosystem")
    if timestamp(seed.first_observed_at) > timestamp(seed.created_at):
        raise IncidentLifecycleError("incident creation cannot precede first observation")
    authority_decision_ids = _stable_ids(
        seed.authority_decision_ids,
        field="authority_decision_ids",
    )
    authority = _authority(
        seed.authority,
        incident_id=seed.incident_id,
        authority_decision_ids=authority_decision_ids,
        expected_status=seed.initial_status,
    )
    state = {
        "incident_id": seed.incident_id,
        "title": seed.title,
        "initial_status": seed.initial_status,
        "initial_confidence": seed.initial_confidence,
        "claim_ids": _stable_ids(seed.claim_ids, field="claim_ids"),
        "artifact_ids": _stable_ids(seed.artifact_ids, field="artifact_ids"),
        "affected_range_ids": _stable_ids(
            seed.affected_range_ids,
            field="affected_range_ids",
        ),
        "relationship_ids": _stable_ids(
            seed.relationship_ids,
            field="relationship_ids",
        ),
        "authority_decision_ids": authority_decision_ids,
        "authority": authority,
        "coverage": coverage,
        "unknowns": _unknowns(seed.unknowns),
        "first_observed_at": seed.first_observed_at,
        "created_at": seed.created_at,
    }
    probe = {
        "id": seed.incident_id,
        "kind": "incident",
        "schema_version": "1.0.0",
        "revision": 1,
        "created_at": timestamp(seed.created_at),
        "updated_at": timestamp(seed.created_at),
        "data_classification": (
            "internal_control"
            if seed.initial_status in STATUS_CLASSIFICATION_INTERNAL
            else "public"
        ),
        "title": seed.title,
        "status": seed.initial_status,
        "confidence": seed.initial_confidence,
        "claim_ids": state["claim_ids"],
        "artifact_ids": state["artifact_ids"],
        "affected_range_ids": state["affected_range_ids"],
        "relationship_ids": state["relationship_ids"],
        "event_ids": [],
        "authority_decision_ids": state["authority_decision_ids"],
        "authority": state["authority"],
        "alias_ids": [],
        "redirect_to": None,
        "first_observed_at": timestamp(seed.first_observed_at),
        "last_changed_at": timestamp(seed.created_at),
        "coverage": coverage,
        "unknowns": state["unknowns"],
    }
    parse_contract("Incident", probe)
    return state


def _seed_hash(state: Mapping[str, Any]) -> str:
    serializable = {
        **state,
        "first_observed_at": timestamp(state["first_observed_at"]),
        "created_at": timestamp(state["created_at"]),
    }
    return sha256_id(canonical_json_bytes(serializable))


def _compatible_seed_hashes(state: Mapping[str, Any]) -> set[str]:
    hashes = {_seed_hash(state)}
    if not state.get("authority_decision_ids") and state.get("authority") is None:
        legacy_state = {
            key: value
            for key, value in state.items()
            if key not in {"authority_decision_ids", "authority"}
        }
        hashes.add(_seed_hash(legacy_state))
    return hashes


def _validate_public_references(
    session: Session,
    *,
    incident_id: str,
    claim_ids: Sequence[str],
    artifact_ids: Sequence[str],
    affected_range_ids: Sequence[str],
    relationship_ids: Sequence[str],
    authority_decision_ids: Sequence[str],
) -> None:
    def latest_public(model: Any, identifiers: set[str]) -> list[Any]:
        if not identifiers:
            return []
        latest = (
            select(
                model.id.label("record_id"),
                func.max(model.revision).label("record_revision"),
            )
            .where(model.id.in_(identifiers))
            .group_by(model.id)
            .subquery()
        )
        return list(
            session.scalars(
                select(model)
                .join(
                    latest,
                    (model.id == latest.c.record_id) & (model.revision == latest.c.record_revision),
                )
                .where(model.data_classification == "public")
            )
        )

    range_ids = set(affected_range_ids)
    ranges = latest_public(AffectedRangeRecord, range_ids)
    if {record.id for record in ranges} != range_ids:
        raise IncidentLifecycleError("public incident references unavailable public documents")

    claim_id_set = set(claim_ids)
    claims = latest_public(ClaimRecord, claim_id_set)
    if {record.id for record in claims} != claim_id_set:
        raise IncidentLifecycleError("public incident references unavailable public documents")

    relationship_id_set = set(relationship_ids)
    relationships = latest_public(RelationshipRecord, relationship_id_set)
    if {record.id for record in relationships} != relationship_id_set:
        raise IncidentLifecycleError("public incident references unavailable public documents")

    required_artifact_ids = (
        set(artifact_ids)
        | {record.artifact_id for record in ranges}
        | {record.subject_id for record in claims}
    )
    artifacts = latest_public(ArtifactRecord, required_artifact_ids)
    available_artifact_ids = {record.id for record in artifacts}
    if available_artifact_ids != required_artifact_ids:
        raise IncidentLifecycleError("public incident references unavailable public documents")

    required_authority_ids = set(authority_decision_ids)
    authorities = latest_public(AuthorityDecisionRecord, required_authority_ids)
    available_authority_ids = {record.id for record in authorities}
    if available_authority_ids != required_authority_ids:
        raise IncidentLifecycleError("public incident references unavailable authority decisions")

    relationship_endpoint_ids = {
        endpoint for record in relationships for endpoint in (record.subject_id, record.object_id)
    }
    directly_available = (
        required_artifact_ids
        | claim_id_set
        | range_ids
        | relationship_id_set
        | required_authority_ids
        | {incident_id}
    )
    unresolved_endpoints = relationship_endpoint_ids - directly_available
    if unresolved_endpoints:
        available_endpoints: set[str] = set()
        for model in (
            ArtifactRecord,
            ClaimRecord,
            AffectedRangeRecord,
            RelationshipRecord,
            AuthorityDecisionRecord,
            IncidentRecord,
        ):
            available_endpoints.update(
                record.id for record in latest_public(model, unresolved_endpoints)
            )
        if available_endpoints != unresolved_endpoints:
            raise IncidentLifecycleError(
                "public incident relationship references unavailable public documents"
            )


def _validate_public_incident_document(
    session: Session,
    document: Mapping[str, Any],
) -> None:
    if document["status"] in STATUS_CLASSIFICATION_INTERNAL:
        return
    _validate_public_references(
        session,
        incident_id=document["id"],
        claim_ids=document["claim_ids"],
        artifact_ids=document["artifact_ids"],
        affected_range_ids=document["affected_range_ids"],
        relationship_ids=document["relationship_ids"],
        authority_decision_ids=document.get("authority_decision_ids") or [],
    )


def _authority(
    value: Mapping[str, Any] | None,
    *,
    incident_id: str,
    authority_decision_ids: Sequence[str],
    expected_status: str,
) -> dict[str, Any] | None:
    if value is None:
        if authority_decision_ids:
            raise IncidentLifecycleError("incident authority decision has no current explanation")
        return None
    if not isinstance(value, Mapping):
        raise IncidentLifecycleError("incident authority explanation is invalid")
    try:
        document = parse_contract("AuthorityDecision", value).model_dump(
            mode="json",
            exclude_none=False,
        )
    except ValueError as error:
        raise IncidentLifecycleError("incident authority explanation is invalid") from error
    if document["incident_id"] != incident_id or document["id"] not in authority_decision_ids:
        raise IncidentLifecycleError("incident authority explanation does not match its state")
    if (
        expected_status in {"reported", "corroborated", "confirmed", "disputed", "withdrawn"}
        and document["public_status"] != expected_status
    ):
        raise IncidentLifecycleError("incident authority explanation does not match its state")
    return document


def _details(value: Mapping[str, Any]) -> dict[str, Any]:
    if set(value) - DETAIL_FIELDS:
        raise IncidentLifecycleError("transition details contain an unexpected field")
    result: dict[str, Any] = {}
    for field in DETAIL_LIST_FIELDS:
        if field in value:
            result[field] = _stable_ids(value[field], field=field)
    for field in ("alias_id", "target_incident_id"):
        item = value.get(field)
        if item is not None:
            if not isinstance(item, str) or not STABLE_ID.fullmatch(item):
                raise IncidentLifecycleError(f"{field} is not a stable ID")
            result[field] = item
    if "add_unknowns" in value:
        result["add_unknowns"] = _unknowns(value["add_unknowns"])
    if "replace_coverage" in value:
        coverage = value["replace_coverage"]
        if (
            isinstance(coverage, str)
            or not isinstance(coverage, Sequence)
            or not 1 <= len(coverage) <= 20
        ):
            raise IncidentLifecycleError("replacement coverage exceeds its limit")
        if not all(isinstance(item, Mapping) for item in coverage):
            raise IncidentLifecycleError("replacement coverage contains an invalid item")
        try:
            result["replace_coverage"] = [
                CoverageState.model_validate(dict(item)).model_dump(
                    mode="json",
                    exclude_none=False,
                )
                for item in coverage
            ]
        except ValueError as error:
            raise IncidentLifecycleError("replacement coverage contains an invalid item") from error
        ecosystems = [item["ecosystem"] for item in result["replace_coverage"]]
        if len(ecosystems) != len(set(ecosystems)):
            raise IncidentLifecycleError("replacement coverage repeats an ecosystem")
    if "replace_authority" in value:
        authority = value["replace_authority"]
        if not isinstance(authority, Mapping):
            raise IncidentLifecycleError("replacement authority is invalid")
        try:
            result["replace_authority"] = parse_contract(
                "AuthorityDecision",
                authority,
            ).model_dump(mode="json", exclude_none=False)
        except ValueError as error:
            raise IncidentLifecycleError("replacement authority is invalid") from error
    return result


def _validate_event(
    event: Mapping[str, Any],
    *,
    current: Mapping[str, Any] | None,
    details: Mapping[str, Any],
    prior_dispute_actor: str | None = None,
) -> dict[str, Any]:
    document = parse_contract("IncidentEvent", event).model_dump(mode="json", exclude_none=False)
    event_type = document["event_type"]
    if set(details) - EVENT_DETAIL_FIELDS[event_type]:
        raise IncidentLifecycleError("transition details are invalid for this event type")
    if current is None:
        if (
            event_type != "created"
            or document["old_status"] is not None
            or document["new_status"] is None
            or document["superseded_revision"] is not None
            or details
        ):
            raise IncidentLifecycleError("initial event must be a clean creation event")
        return document
    if event_type == "created":
        raise IncidentLifecycleError("creation can occur only once")
    if document["superseded_revision"] != current["revision"]:
        raise IncidentLifecycleError("event does not target the current incident revision")
    if document["old_status"] != current["status"]:
        raise IncidentLifecycleError("event old status differs from current incident state")
    occurred_at = datetime.fromisoformat(document["occurred_at"].replace("Z", "+00:00"))
    last_changed_at = datetime.fromisoformat(current["last_changed_at"].replace("Z", "+00:00"))
    if occurred_at < last_changed_at:
        raise IncidentLifecycleError("incident event time cannot move backwards")

    new_status = document["new_status"]
    if (
        event_type
        in {
            "state_changed",
            "disputed",
            "appealed",
            "corrected",
            "expired",
            "withdrawn",
            "renewed",
        }
        and new_status is None
    ):
        raise IncidentLifecycleError("state-changing event requires a new status")
    if event_type in {"alias_added", "redirected", "merged", "split"} and new_status not in {
        None,
        current["status"],
    }:
        raise IncidentLifecycleError("structural event cannot silently change status")
    if event_type == "alias_added" and "alias_id" not in details:
        raise IncidentLifecycleError("alias event requires alias_id")
    if event_type in {"redirected", "merged"} and "target_incident_id" not in details:
        raise IncidentLifecycleError("redirect or merge requires target_incident_id")
    if event_type == "split" and not details.get("split_incident_ids"):
        raise IncidentLifecycleError("split requires destination incident IDs")
    if event_type == "disputed" and new_status != "disputed":
        raise IncidentLifecycleError("dispute must enter disputed status")
    if event_type == "state_changed" and new_status in {"disputed", "expired", "withdrawn"}:
        raise IncidentLifecycleError("dedicated lifecycle event type is required")
    if event_type == "appealed":
        if current["status"] != "disputed" or new_status not in {"disputed", "investigating"}:
            raise IncidentLifecycleError("appeal must follow a dispute")
        if document["actor_type"] != "reviewer" or document["actor_id"] == prior_dispute_actor:
            raise IncidentLifecycleError("appeal requires an independent reviewer")
    if event_type == "corrected":
        if not details.get("replacement_claim_ids"):
            raise IncidentLifecycleError("correction requires a replacement claim ID")
        if details.get("remove_claim_ids"):
            raise IncidentLifecycleError("correction cannot erase superseded claim IDs")
    if event_type == "expired" and new_status != "expired":
        raise IncidentLifecycleError("expiry must enter expired status")
    if event_type == "withdrawn" and new_status != "withdrawn":
        raise IncidentLifecycleError("withdrawal must enter withdrawn status")
    if event_type == "renewed" and (
        current["status"] != "expired" or new_status in {"expired", "withdrawn"}
    ):
        raise IncidentLifecycleError("renewal must reactivate an expired incident")
    return document


def _add_unique(target: list[str], additions: Sequence[str]) -> None:
    for value in additions:
        if value not in target:
            target.append(value)


def _remove(target: list[str], removals: Sequence[str]) -> None:
    missing = set(removals) - set(target)
    if missing:
        raise IncidentRebuildError("transition removes an ID absent from prior state")
    target[:] = [value for value in target if value not in set(removals)]


def _transition_hash(event: Mapping[str, Any], details: Mapping[str, Any]) -> str:
    return sha256_id(canonical_json_bytes({"event": event, "details": details}))


def _load_history(
    session: Session,
    incident_id: str,
) -> tuple[IncidentSeedRecord, list[tuple[IncidentEventRecord, IncidentTransitionRecord]]]:
    seed = session.get(IncidentSeedRecord, incident_id)
    if seed is None:
        raise IncidentRebuildError("incident seed is missing")
    transitions = list(
        session.scalars(
            select(IncidentTransitionRecord)
            .where(IncidentTransitionRecord.incident_id == incident_id)
            .order_by(IncidentTransitionRecord.sequence)
        )
    )
    history: list[tuple[IncidentEventRecord, IncidentTransitionRecord]] = []
    for expected_sequence, transition in enumerate(transitions, start=1):
        if transition.sequence != expected_sequence:
            raise IncidentRebuildError("incident event sequence is not contiguous")
        event = session.get(
            IncidentEventRecord,
            (transition.event_id, transition.event_revision),
        )
        if event is None or event.incident_id != incident_id:
            raise IncidentRebuildError("incident transition has no matching public event")
        if _transition_hash(event.document, transition.details) != transition.record_hash:
            raise IncidentRebuildError("incident transition checksum mismatch")
        history.append((event, transition))
    if not history:
        raise IncidentRebuildError("incident has no creation event")
    return seed, history


def rebuild_incident(session: Session, incident_id: str) -> dict[str, Any]:
    """Recreate an Incident contract solely from its immutable seed and history."""
    seed, history = _load_history(session, incident_id)
    seed_state = {
        "incident_id": seed.incident_id,
        "title": seed.title,
        "initial_status": seed.initial_status,
        "initial_confidence": seed.initial_confidence,
        "claim_ids": list(seed.claim_ids),
        "artifact_ids": list(seed.artifact_ids),
        "affected_range_ids": list(seed.affected_range_ids),
        "relationship_ids": list(seed.relationship_ids),
        "authority_decision_ids": list(seed.authority_decision_ids),
        "authority": seed.authority,
        "coverage": list(seed.coverage),
        "unknowns": list(seed.unknowns),
        "first_observed_at": seed.first_observed_at,
        "created_at": seed.created_at,
    }
    if seed.record_hash not in _compatible_seed_hashes(seed_state):
        raise IncidentRebuildError("incident seed checksum mismatch")
    status = seed.initial_status
    confidence = seed.initial_confidence
    claims = list(seed.claim_ids)
    artifacts = list(seed.artifact_ids)
    ranges = list(seed.affected_range_ids)
    relationships = list(seed.relationship_ids)
    authority_decisions = list(seed.authority_decision_ids)
    authority = seed.authority
    unknowns = list(seed.unknowns)
    aliases: list[str] = []
    events: list[str] = []
    redirect_to: str | None = None
    coverage = list(seed.coverage)
    last_changed = seed.created_at

    mapping = {
        "claim_ids": claims,
        "artifact_ids": artifacts,
        "affected_range_ids": ranges,
        "relationship_ids": relationships,
        "authority_decision_ids": authority_decisions,
    }
    for event, transition in history:
        details = transition.details
        if event.event_type == "created":
            if transition.sequence != 1 or event.new_status != seed.initial_status:
                raise IncidentRebuildError("invalid creation history")
        else:
            for field, target in mapping.items():
                _add_unique(target, details.get(f"add_{field}", []))
                _remove(target, details.get(f"remove_{field}", []))
            _add_unique(claims, details.get("replacement_claim_ids", []))
            _add_unique(unknowns, details.get("add_unknowns", []))
            if len(unknowns) > 100:
                raise IncidentRebuildError("incident unknowns exceed their contract limit")
            if "replace_coverage" in details:
                coverage = list(details["replace_coverage"])
            if "replace_authority" in details:
                authority = details["replace_authority"]
            if event.event_type == "alias_added":
                _add_unique(aliases, [details["alias_id"]])
            elif event.event_type in {"redirected", "merged"}:
                redirect_to = details["target_incident_id"]
        if event.new_status is not None:
            status = event.new_status
        confidence = event.confidence
        events.append(event.id)
        last_changed = datetime.fromisoformat(event.document["occurred_at"].replace("Z", "+00:00"))

    revision = len(history)
    document: dict[str, Any] = {
        "id": incident_id,
        "kind": "incident",
        "schema_version": "1.0.0",
        "revision": revision,
        "created_at": timestamp(seed.created_at),
        "updated_at": timestamp(last_changed),
        "data_classification": (
            "internal_control" if status in STATUS_CLASSIFICATION_INTERNAL else "public"
        ),
        "title": seed.title,
        "status": status,
        "confidence": confidence,
        "claim_ids": claims,
        "artifact_ids": artifacts,
        "affected_range_ids": ranges,
        "relationship_ids": relationships,
        "event_ids": events,
        "alias_ids": aliases,
        "redirect_to": redirect_to,
        "first_observed_at": timestamp(seed.first_observed_at),
        "last_changed_at": timestamp(last_changed),
        "coverage": coverage,
        "unknowns": unknowns,
    }
    if authority_decisions or authority is not None:
        document["authority_decision_ids"] = authority_decisions
        document["authority"] = authority
    parsed = parse_contract("Incident", document).model_dump(mode="json", exclude_none=False)
    if "authority_decision_ids" not in document:
        parsed.pop("authority_decision_ids", None)
        parsed.pop("authority", None)
    _validate_public_incident_document(session, parsed)
    return parsed


def _store_seed(session: Session, seed: IncidentSeed) -> IncidentSeedRecord:
    state = _validate_seed(seed)
    record = IncidentSeedRecord(
        incident_id=state["incident_id"],
        title=state["title"],
        initial_status=state["initial_status"],
        initial_confidence=state["initial_confidence"],
        claim_ids=state["claim_ids"],
        artifact_ids=state["artifact_ids"],
        affected_range_ids=state["affected_range_ids"],
        relationship_ids=state["relationship_ids"],
        authority_decision_ids=state["authority_decision_ids"],
        authority=state["authority"],
        coverage=state["coverage"],
        unknowns=state["unknowns"],
        first_observed_at=state["first_observed_at"],
        created_at=state["created_at"],
        record_hash=_seed_hash(state),
    )
    session.add(record)
    session.flush()
    return record


def _store_transition(
    session: Session,
    *,
    event: Mapping[str, Any],
    details: Mapping[str, Any],
    sequence: int,
    expected_revision: int,
) -> IncidentTransitionRecord:
    record = IncidentTransitionRecord(
        event_id=event["id"],
        event_revision=event["revision"],
        incident_id=event["incident_id"],
        sequence=sequence,
        expected_incident_revision=expected_revision,
        details=dict(details),
        record_hash=_transition_hash(event, details),
        created_at=datetime.fromisoformat(event["occurred_at"].replace("Z", "+00:00")),
    )
    session.add(record)
    session.flush()
    return record


def create_incident(
    session: Session,
    *,
    seed: IncidentSeed,
    event: Mapping[str, Any],
) -> IncidentWrite:
    """Create an incident idempotently from an immutable seed and creation event."""
    lock_name = f"incident:{seed.incident_id}"
    advisory_xact_lock(session, lock_name)
    existing_seed = session.get(IncidentSeedRecord, seed.incident_id)
    if existing_seed is not None:
        rebuilt = rebuild_incident(session, seed.incident_id)
        supplied_state = _validate_seed(seed)
        if existing_seed.record_hash not in _compatible_seed_hashes(supplied_state):
            raise RevisionConflict("incident seed conflicts with existing immutable seed")
        event_document = _validate_event(event, current=None, details={})
        transition = session.get(
            IncidentTransitionRecord,
            (event_document["id"], event_document["revision"]),
        )
        if transition is None or transition.record_hash != _transition_hash(event_document, {}):
            raise RevisionConflict("incident creation event conflicts with existing history")
        _validate_public_incident_document(session, rebuilt)
        return IncidentWrite(document=rebuilt, created=False)

    state = _validate_seed(seed)
    event_document = _validate_event(event, current=None, details={})
    if (
        event_document["incident_id"] != seed.incident_id
        or event_document["new_status"] != state["initial_status"]
        or event_document["confidence"] != state["initial_confidence"]
    ):
        raise IncidentLifecycleError("creation event differs from the incident seed")
    created_event_time = datetime.fromisoformat(
        event_document["occurred_at"].replace("Z", "+00:00")
    )
    if timestamp(created_event_time) < timestamp(seed.created_at):
        raise IncidentLifecycleError("creation event cannot precede seed creation")
    if state["initial_status"] not in STATUS_CLASSIFICATION_INTERNAL:
        _validate_public_references(
            session,
            incident_id=state["incident_id"],
            claim_ids=state["claim_ids"],
            artifact_ids=state["artifact_ids"],
            affected_range_ids=state["affected_range_ids"],
            relationship_ids=state["relationship_ids"],
            authority_decision_ids=state["authority_decision_ids"],
        )
    _store_seed(session, seed)
    append_contract(session, "IncidentEvent", event_document)
    _store_transition(
        session,
        event=event_document,
        details={},
        sequence=1,
        expected_revision=0,
    )
    document = rebuild_incident(session, seed.incident_id)
    append_contract(session, "Incident", document)
    return IncidentWrite(document=document, created=True)


def apply_incident_event(
    session: Session,
    *,
    event: Mapping[str, Any],
    details: Mapping[str, Any] | None = None,
) -> IncidentWrite:
    """Append one lifecycle event and derive the next immutable Incident revision."""
    event_document = parse_contract("IncidentEvent", event).model_dump(
        mode="json",
        exclude_none=False,
    )
    incident_id = event_document["incident_id"]
    normalized_details = _details(details or {})
    lock_names = {f"incident:{incident_id}"}
    if event_document["event_type"] == "alias_added" and "alias_id" in normalized_details:
        lock_names.add(f"alias:{normalized_details['alias_id']}")
    if event_document["event_type"] in {"redirected", "merged"}:
        target = normalized_details.get("target_incident_id")
        if target is not None:
            lock_names.add(f"incident:{target}")
    if event_document["event_type"] == "split":
        lock_names.update(
            f"incident:{target}" for target in normalized_details.get("split_incident_ids", [])
        )
    for lock_name in sorted(lock_names):
        advisory_xact_lock(session, lock_name)
    current_record = latest_contract(session, "Incident", incident_id)
    if current_record is None:
        raise IncidentLifecycleError("incident must be created before applying an event")
    current = current_record.document
    existing = session.get(
        IncidentTransitionRecord,
        (event_document["id"], event_document["revision"]),
    )
    if existing is not None:
        if existing.record_hash != _transition_hash(event_document, normalized_details):
            raise RevisionConflict("incident event details conflict with existing history")
        append_contract(session, "IncidentEvent", event_document)
        rebuilt = rebuild_incident(session, incident_id)
        _validate_public_incident_document(session, rebuilt)
        return IncidentWrite(document=rebuilt, created=False)
    if event_document["id"] in current["event_ids"]:
        raise IncidentLifecycleError("incident event ID must be unique within its history")

    prior_dispute_actor = session.scalar(
        select(IncidentEventRecord.actor_id)
        .where(
            IncidentEventRecord.incident_id == incident_id,
            IncidentEventRecord.event_type == "disputed",
        )
        .order_by(IncidentEventRecord.occurred_at.desc())
        .limit(1)
    )
    event_document = _validate_event(
        event_document,
        current=current,
        details=normalized_details,
        prior_dispute_actor=prior_dispute_actor,
    )
    if event_document["event_type"] == "alias_added":
        alias_id = normalized_details["alias_id"]
        if session.get(IncidentSeedRecord, alias_id) is not None:
            raise IncidentLifecycleError("alias cannot be another canonical incident ID")
        if any(
            candidate_id != incident_id
            for candidate_id in incident_ids_for_alias(session, alias_id)
        ):
            raise IncidentLifecycleError("alias already belongs to another incident")
    if event_document["event_type"] in {"redirected", "merged"}:
        target = normalized_details["target_incident_id"]
        if current.get("redirect_to") is not None:
            raise IncidentLifecycleError("incident already has a durable redirect")
        if session.get(IncidentSeedRecord, target) is None:
            raise IncidentLifecycleError("redirect target incident does not exist")
        resolved_target, hops = resolve_incident_id(session, target)
        if resolved_target == incident_id or incident_id in hops:
            raise IncidentLifecycleError("incident redirect would create a cycle")
    if event_document["event_type"] == "split":
        missing = [
            target
            for target in normalized_details["split_incident_ids"]
            if session.get(IncidentSeedRecord, target) is None
        ]
        if missing:
            raise IncidentLifecycleError("split target incident does not exist")
    projected_artifact_ids = list(current["artifact_ids"])
    _add_unique(
        projected_artifact_ids,
        normalized_details.get("add_artifact_ids", []),
    )
    _remove(
        projected_artifact_ids,
        normalized_details.get("remove_artifact_ids", []),
    )
    projected_range_ids = list(current["affected_range_ids"])
    _add_unique(
        projected_range_ids,
        normalized_details.get("add_affected_range_ids", []),
    )
    _remove(
        projected_range_ids,
        normalized_details.get("remove_affected_range_ids", []),
    )
    projected_claim_ids = list(current["claim_ids"])
    _add_unique(projected_claim_ids, normalized_details.get("add_claim_ids", []))
    _remove(projected_claim_ids, normalized_details.get("remove_claim_ids", []))
    _add_unique(projected_claim_ids, normalized_details.get("replacement_claim_ids", []))
    projected_relationship_ids = list(current["relationship_ids"])
    _add_unique(
        projected_relationship_ids,
        normalized_details.get("add_relationship_ids", []),
    )
    _remove(
        projected_relationship_ids,
        normalized_details.get("remove_relationship_ids", []),
    )
    projected_authority_decision_ids = list(current.get("authority_decision_ids") or [])
    _add_unique(
        projected_authority_decision_ids,
        normalized_details.get("add_authority_decision_ids", []),
    )
    next_status = event_document["new_status"] or current["status"]
    projected_authority = normalized_details.get(
        "replace_authority",
        current.get("authority"),
    )
    _authority(
        projected_authority,
        incident_id=incident_id,
        authority_decision_ids=projected_authority_decision_ids,
        expected_status=next_status,
    )
    if next_status not in STATUS_CLASSIFICATION_INTERNAL:
        _validate_public_references(
            session,
            incident_id=incident_id,
            claim_ids=projected_claim_ids,
            artifact_ids=projected_artifact_ids,
            affected_range_ids=projected_range_ids,
            relationship_ids=projected_relationship_ids,
            authority_decision_ids=projected_authority_decision_ids,
        )
    append_contract(session, "IncidentEvent", event_document)
    next_sequence = current["revision"] + 1
    _store_transition(
        session,
        event=event_document,
        details=normalized_details,
        sequence=next_sequence,
        expected_revision=current["revision"],
    )
    document = rebuild_incident(session, incident_id)
    append_contract(session, "Incident", document)
    return IncidentWrite(document=document, created=True)


def resolve_incident_id(session: Session, supplied_id: str) -> tuple[str, tuple[str, ...]]:
    """Resolve a canonical ID or durable alias through redirects without hiding hops."""
    current = supplied_id
    record = latest_incident(session, current)
    if record is None:
        matches = incident_ids_for_alias(session, supplied_id)
        if len(matches) != 1:
            raise IncidentLifecycleError("incident ID or alias is unknown or ambiguous")
        current = matches[0]
        record = latest_incident(session, current)
    if record is None:
        raise IncidentRebuildError("incident latest revision is missing")
    hops = [current]
    for _ in range(20):
        target = record.redirect_to
        if target is None:
            return current, tuple(hops)
        if target in hops:
            raise IncidentRebuildError("incident redirect chain is invalid")
        record = latest_incident(session, target)
        if record is None:
            raise IncidentRebuildError("incident redirect chain is invalid")
        hops.append(target)
        current = target
    raise IncidentRebuildError("incident redirect chain exceeds its limit")
