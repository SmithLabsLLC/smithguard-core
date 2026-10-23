"""Deterministic lifecycle, alias, correction, and historical replay checks."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import smithguard.incidents as incident_module
from smithguard.db.models import IncidentRecord, IncidentTransitionRecord
from smithguard.db.repository import append_contract, latest_contract
from smithguard.identifiers import stable_id, timestamp
from smithguard.incidents import (
    IncidentLifecycleError,
    IncidentSeed,
    apply_incident_event,
    create_incident,
    rebuild_incident,
    resolve_incident_id,
)
from smithguard.normalization import normalize_artifact_identity

REPO_ROOT = Path(__file__).resolve().parents[1]
REPLAY_CATALOG = REPO_ROOT / "contracts/v1/historical-replay-catalog.json"
REPLAY_RESULTS = REPO_ROOT / "contracts/v1/historical-replay-results.json"
NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def verify_latest_incident_rebuild(session: Session, incident_id: str) -> dict:
    """Rebuild the incident and require it to equal the latest stored revision."""
    rebuilt = rebuild_incident(session, incident_id)
    latest = latest_contract(session, "Incident", incident_id)
    assert latest is not None and latest.document == rebuilt
    return rebuilt


def _coverage(ecosystem: str = "npm") -> tuple[dict[str, Any], ...]:
    return (
        {
            "ecosystem": ecosystem,
            "stage": "normalized",
            "result": "supported",
            "as_of": timestamp(NOW),
        },
    )


def _seed(
    incident_id: str,
    *,
    status: str = "confirmed",
    confidence: str = "confirmed",
    claim_ids: tuple[str, ...] = (),
    artifact_ids: tuple[str, ...] = (),
    relationship_ids: tuple[str, ...] = (),
    ecosystem: str = "npm",
) -> IncidentSeed:
    return IncidentSeed(
        incident_id=incident_id,
        title=f"Synthetic incident {incident_id.rsplit(':', 1)[-1]}",
        initial_status=status,
        initial_confidence=confidence,
        claim_ids=claim_ids,
        artifact_ids=artifact_ids,
        affected_range_ids=(),
        relationship_ids=relationship_ids,
        coverage=_coverage(ecosystem),
        unknowns=("Synthetic fixture only.",),
        first_observed_at=NOW,
        created_at=NOW,
    )


def _event(
    incident_id: str,
    event_id: str,
    event_type: str,
    *,
    old_status: str | None,
    new_status: str | None,
    superseded_revision: int | None,
    actor_type: str = "reviewer",
    actor_id: str = "reviewer-alpha",
    confidence: str = "confirmed",
    occurred_at: datetime = NOW,
) -> dict[str, Any]:
    internal = old_status in {"internal_candidate", "emerging_unverified"} or new_status in {
        "internal_candidate",
        "emerging_unverified",
    }
    return {
        "id": event_id,
        "kind": "incident_event",
        "schema_version": "1.0.0",
        "revision": 1,
        "created_at": timestamp(occurred_at),
        "updated_at": timestamp(occurred_at),
        "data_classification": "internal_control" if internal else "public",
        "incident_id": incident_id,
        "event_type": event_type,
        "old_status": old_status,
        "new_status": new_status,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "reason_code": f"synthetic_{event_type}",
        "evidence_ids": [],
        "occurred_at": timestamp(occurred_at),
        "confidence": confidence,
        "superseded_revision": superseded_revision,
    }


def _create(session: Session, incident_id: str, **seed_changes: Any) -> dict[str, Any]:
    seed = _seed(incident_id, **seed_changes)
    event = _event(
        incident_id,
        stable_id("event", incident_id, "created"),
        "created",
        old_status=None,
        new_status=seed.initial_status,
        superseded_revision=None,
        confidence=seed.initial_confidence,
    )
    return create_incident(session, seed=seed, event=event).document


def _append_public_artifact(session: Session, artifact_id: str) -> None:
    append_contract(
        session,
        "Artifact",
        {
            "id": artifact_id,
            "kind": "artifact",
            "schema_version": "1.0.0",
            "revision": 1,
            "created_at": timestamp(NOW),
            "updated_at": timestamp(NOW),
            "data_classification": "public",
            "ecosystem": "npm",
            "name": "synthetic-lifecycle",
            "coordinate": "pkg:npm/synthetic-lifecycle@1.0.0",
            "version": "1.0.0",
            "digest": None,
            "identity_state": "exact",
        },
    )


def _append_public_claim(
    session: Session,
    *,
    claim_id: str,
    artifact_id: str,
    incident_id: str,
    revision: int = 1,
    data_classification: str = "public",
    updated_at: datetime = NOW,
) -> None:
    append_contract(
        session,
        "Claim",
        {
            "id": claim_id,
            "kind": "claim",
            "schema_version": "1.0.0",
            "revision": revision,
            "created_at": timestamp(NOW),
            "updated_at": timestamp(updated_at),
            "data_classification": data_classification,
            "claim_type": "malicious",
            "subject_id": artifact_id,
            "predicate": "is_affected_by",
            "object_value": incident_id,
            "confidence": "confirmed",
            "state": "active",
            "valid_from": timestamp(NOW),
            "valid_until": None,
            "supersedes_claim_id": None,
            "provenance": {
                "source_id": "gbsec:source:synthetic",
                "source_record_id": claim_id,
                "source_url": "https://example.invalid/synthetic",
                "evidence_id": "gbsec:evidence:synthetic",
                "retrieved_at": timestamp(updated_at),
                "source_published_at": timestamp(NOW),
                "source_modified_at": None,
                "collection_method": "manual_replay",
                "assertion_origin": "declared_by_source",
                "identity_verification": "verified",
                "signature_state": "unsupported",
                "claim_lineage": None,
            },
        },
    )


def _append_public_relationship(
    session: Session,
    *,
    relationship_id: str,
    subject_id: str,
    object_id: str,
) -> None:
    append_contract(
        session,
        "Relationship",
        {
            "id": relationship_id,
            "kind": "relationship",
            "schema_version": "1.0.0",
            "revision": 1,
            "created_at": timestamp(NOW),
            "updated_at": timestamp(NOW),
            "data_classification": "public",
            "subject_id": subject_id,
            "object_id": object_id,
            "relationship_type": "affects",
            "assertion_origin": "declared_by_source",
            "confidence": "confirmed",
            "valid_from": timestamp(NOW),
            "valid_until": None,
            "state": "active",
            "provenance": {
                "source_id": "gbsec:source:synthetic",
                "source_record_id": relationship_id,
                "source_url": "https://example.invalid/synthetic",
                "evidence_id": "gbsec:evidence:synthetic",
                "retrieved_at": timestamp(NOW),
                "source_published_at": timestamp(NOW),
                "source_modified_at": None,
                "collection_method": "manual_replay",
                "assertion_origin": "declared_by_source",
                "identity_verification": "verified",
                "signature_state": "unsupported",
                "claim_lineage": None,
            },
        },
    )


def test_public_incident_references_must_exist_before_publication(database) -> None:
    missing_artifact_id = "gbsec:artifact:missing-public-reference"
    public_incident_id = "gbsec:incident:missing-public-reference"
    internal_incident_id = "gbsec:incident:internal-missing-reference"
    with Session(database.engine) as session, session.begin():
        with pytest.raises(IncidentLifecycleError, match="unavailable public"):
            _create(
                session,
                public_incident_id,
                artifact_ids=(missing_artifact_id,),
            )
        assert latest_contract(session, "Incident", public_incident_id) is None

        internal = _create(
            session,
            internal_incident_id,
            status="internal_candidate",
            confidence="unverified",
            artifact_ids=(missing_artifact_id,),
        )
        assert internal["status"] == "internal_candidate"
        with pytest.raises(IncidentLifecycleError, match="unavailable public"):
            apply_incident_event(
                session,
                event=_event(
                    internal_incident_id,
                    "gbsec:event:reject-dangling-publication",
                    "state_changed",
                    old_status="internal_candidate",
                    new_status="confirmed",
                    superseded_revision=1,
                    confidence="confirmed",
                    occurred_at=NOW + timedelta(minutes=1),
                ),
            )
        latest = latest_contract(session, "Incident", internal_incident_id)
        assert latest is not None
        assert latest.document["status"] == "internal_candidate"
        assert latest.document["revision"] == 1


def test_public_claim_and_relationship_references_fail_closed_everywhere(
    database,
) -> None:
    artifact_id = "gbsec:artifact:reference-integrity"
    claim_id = "gbsec:claim:reference-integrity"
    relationship_id = "gbsec:relationship:reference-integrity"
    incident_id = "gbsec:incident:reference-integrity"
    with Session(database.engine) as session, session.begin():
        with pytest.raises(IncidentLifecycleError, match="unavailable public"):
            _create(
                session,
                "gbsec:incident:missing-claim",
                claim_ids=("gbsec:claim:missing",),
            )

        _append_public_artifact(session, artifact_id)
        _append_public_claim(
            session,
            claim_id=claim_id,
            artifact_id=artifact_id,
            incident_id=incident_id,
        )
        _append_public_relationship(
            session,
            relationship_id=relationship_id,
            subject_id=incident_id,
            object_id=artifact_id,
        )
        created = _create(
            session,
            incident_id,
            claim_ids=(claim_id,),
            relationship_ids=(relationship_id,),
        )
        assert created["claim_ids"] == [claim_id]
        assert created["relationship_ids"] == [relationship_id]

        with pytest.raises(IncidentLifecycleError, match="unavailable public"):
            apply_incident_event(
                session,
                event=_event(
                    incident_id,
                    "gbsec:event:missing-claim-transition",
                    "corrected",
                    old_status="confirmed",
                    new_status="confirmed",
                    superseded_revision=1,
                    occurred_at=NOW + timedelta(minutes=1),
                ),
                details={
                    "replacement_claim_ids": ["gbsec:claim:missing-transition"],
                },
            )

        _append_public_claim(
            session,
            claim_id=claim_id,
            artifact_id=artifact_id,
            incident_id=incident_id,
            revision=2,
            data_classification="restricted_source",
            updated_at=NOW + timedelta(minutes=2),
        )
        seed = _seed(incident_id, claim_ids=(claim_id,), relationship_ids=(relationship_id,))
        event = _event(
            incident_id,
            stable_id("event", incident_id, "created"),
            "created",
            old_status=None,
            new_status="confirmed",
            superseded_revision=None,
        )
        with pytest.raises(IncidentLifecycleError, match="unavailable public"):
            create_incident(session, seed=seed, event=event)
        with pytest.raises(IncidentLifecycleError, match="unavailable public"):
            verify_latest_incident_rebuild(session, incident_id)


def test_public_relationship_requires_both_current_public_endpoints(database) -> None:
    incident_id = "gbsec:incident:missing-relationship-object"
    relationship_id = "gbsec:relationship:missing-object"
    with Session(database.engine) as session, session.begin():
        _append_public_relationship(
            session,
            relationship_id=relationship_id,
            subject_id=incident_id,
            object_id="gbsec:artifact:missing-relationship-object",
        )
        with pytest.raises(IncidentLifecycleError, match="relationship references"):
            _create(
                session,
                incident_id,
                relationship_ids=(relationship_id,),
            )


def test_structural_lifecycle_resolves_aliases_merges_and_splits(database) -> None:
    source_id = "gbsec:incident:synthetic-source"
    target_id = "gbsec:incident:synthetic-target"
    alias_id = "gbsec:alias:synthetic-source"
    split_id = "gbsec:incident:synthetic-split"
    with Session(database.engine) as session, session.begin():
        _create(session, source_id)
        _create(session, target_id)
        _create(session, split_id)
        alias_event = _event(
            source_id,
            "gbsec:event:synthetic-alias",
            "alias_added",
            old_status="confirmed",
            new_status="confirmed",
            superseded_revision=1,
            occurred_at=NOW + timedelta(minutes=1),
        )
        alias_state = apply_incident_event(
            session,
            event=alias_event,
            details={"alias_id": alias_id},
        )
        assert alias_state.document["alias_ids"] == [alias_id]
        assert (
            apply_incident_event(
                session,
                event=alias_event,
                details={"alias_id": alias_id},
            ).created
            is False
        )

        merge_state = apply_incident_event(
            session,
            event=_event(
                source_id,
                "gbsec:event:synthetic-merge",
                "merged",
                old_status="confirmed",
                new_status="confirmed",
                superseded_revision=2,
                occurred_at=NOW + timedelta(minutes=2),
            ),
            details={"target_incident_id": target_id},
        )
        assert merge_state.document["redirect_to"] == target_id
        resolved, hops = resolve_incident_id(session, alias_id)
        assert resolved == target_id
        assert hops == (source_id, target_id)

        split_state = apply_incident_event(
            session,
            event=_event(
                target_id,
                "gbsec:event:synthetic-split",
                "split",
                old_status="confirmed",
                new_status="confirmed",
                superseded_revision=1,
                occurred_at=NOW + timedelta(minutes=3),
            ),
            details={"split_incident_ids": [split_id]},
        )
        assert split_state.document["revision"] == 2
        assert verify_latest_incident_rebuild(session, source_id) == merge_state.document
        assert verify_latest_incident_rebuild(session, target_id) == split_state.document


def test_dispute_independent_appeal_correction_expiry_and_withdrawal(database) -> None:
    incident_id = "gbsec:incident:synthetic-lifecycle"
    artifact_id = "gbsec:artifact:synthetic-lifecycle"
    old_claim = "gbsec:claim:synthetic-old"
    new_claim = "gbsec:claim:synthetic-new"
    with Session(database.engine) as session, session.begin():
        _append_public_artifact(session, artifact_id)
        _append_public_claim(
            session,
            claim_id=old_claim,
            artifact_id=artifact_id,
            incident_id=incident_id,
        )
        _append_public_claim(
            session,
            claim_id=new_claim,
            artifact_id=artifact_id,
            incident_id=incident_id,
        )
        _create(
            session,
            incident_id,
            claim_ids=(old_claim,),
            artifact_ids=(artifact_id,),
        )
        disputed = apply_incident_event(
            session,
            event=_event(
                incident_id,
                "gbsec:event:synthetic-dispute",
                "disputed",
                old_status="confirmed",
                new_status="disputed",
                superseded_revision=1,
                actor_type="maintainer",
                actor_id="maintainer-opaque",
                confidence="disputed",
                occurred_at=NOW + timedelta(minutes=1),
            ),
        ).document
        assert disputed["status"] == "disputed"

        with pytest.raises(IncidentLifecycleError, match="independent reviewer"):
            apply_incident_event(
                session,
                event=_event(
                    incident_id,
                    "gbsec:event:synthetic-bad-appeal",
                    "appealed",
                    old_status="disputed",
                    new_status="investigating",
                    superseded_revision=2,
                    actor_id="maintainer-opaque",
                    confidence="possible",
                    occurred_at=NOW + timedelta(minutes=2),
                ),
            )
        appealed = apply_incident_event(
            session,
            event=_event(
                incident_id,
                "gbsec:event:synthetic-appeal",
                "appealed",
                old_status="disputed",
                new_status="investigating",
                superseded_revision=2,
                actor_id="reviewer-independent",
                confidence="possible",
                occurred_at=NOW + timedelta(minutes=2),
            ),
        ).document
        assert appealed["status"] == "investigating"

        corrected = apply_incident_event(
            session,
            event=_event(
                incident_id,
                "gbsec:event:synthetic-correction",
                "corrected",
                old_status="investigating",
                new_status="confirmed",
                superseded_revision=3,
                actor_id="reviewer-independent",
                occurred_at=NOW + timedelta(minutes=3),
            ),
            details={"replacement_claim_ids": [new_claim]},
        ).document
        assert corrected["claim_ids"] == [old_claim, new_claim]

        expired = apply_incident_event(
            session,
            event=_event(
                incident_id,
                "gbsec:event:synthetic-expiry",
                "expired",
                old_status="confirmed",
                new_status="expired",
                superseded_revision=4,
                occurred_at=NOW + timedelta(minutes=4),
            ),
        ).document
        renewed = apply_incident_event(
            session,
            event=_event(
                incident_id,
                "gbsec:event:synthetic-renewal",
                "renewed",
                old_status="expired",
                new_status="investigating",
                superseded_revision=5,
                confidence="possible",
                occurred_at=NOW + timedelta(minutes=5),
            ),
        ).document
        withdrawn = apply_incident_event(
            session,
            event=_event(
                incident_id,
                "gbsec:event:synthetic-withdrawal",
                "withdrawn",
                old_status="investigating",
                new_status="withdrawn",
                superseded_revision=6,
                confidence="confirmed",
                occurred_at=NOW + timedelta(minutes=6),
            ),
        ).document
        assert expired["status"] == "expired"
        assert renewed["status"] == "investigating"
        assert withdrawn["status"] == "withdrawn"
        assert withdrawn["claim_ids"] == [old_claim, new_claim]
        assert len(withdrawn["event_ids"]) == 7
        assert verify_latest_incident_rebuild(session, incident_id) == withdrawn


def test_rebuild_uses_event_document_with_retained_orm_instances(
    database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retained: list[Any] = []
    original = incident_module.append_contract

    def retaining_append(*args: Any, **kwargs: Any):
        result = original(*args, **kwargs)
        retained.append(result[0])
        return result

    monkeypatch.setattr(incident_module, "append_contract", retaining_append)
    with Session(database.engine) as session, session.begin():
        created = _create(session, "gbsec:incident:synthetic-retained")
        assert created["revision"] == 1
        assert retained
        assert verify_latest_incident_rebuild(session, created["id"]) == created


def test_dedicated_states_unknown_bounds_and_coverage_replacement(database) -> None:
    incident_id = "gbsec:incident:synthetic-coverage"
    with Session(database.engine) as session, session.begin():
        _create(session, incident_id)
        with pytest.raises(IncidentLifecycleError, match="dedicated lifecycle"):
            apply_incident_event(
                session,
                event=_event(
                    incident_id,
                    "gbsec:event:synthetic-state-side-door",
                    "state_changed",
                    old_status="confirmed",
                    new_status="disputed",
                    superseded_revision=1,
                    occurred_at=NOW + timedelta(minutes=1),
                ),
            )
        with pytest.raises(IncidentLifecycleError, match="invalid value"):
            apply_incident_event(
                session,
                event=_event(
                    incident_id,
                    "gbsec:event:synthetic-long-unknown",
                    "state_changed",
                    old_status="confirmed",
                    new_status="confirmed",
                    superseded_revision=1,
                    occurred_at=NOW + timedelta(minutes=1),
                ),
                details={"add_unknowns": ["x" * 301]},
            )
        changed = apply_incident_event(
            session,
            event=_event(
                incident_id,
                "gbsec:event:synthetic-coverage-change",
                "state_changed",
                old_status="confirmed",
                new_status="confirmed",
                superseded_revision=1,
                occurred_at=NOW + timedelta(minutes=1),
            ),
            details={
                "replace_coverage": [
                    {
                        "ecosystem": "npm",
                        "stage": "matched",
                        "result": "supported",
                        "as_of": timestamp(NOW + timedelta(minutes=1)),
                    }
                ]
            },
        ).document
        assert changed["coverage"][0]["stage"] == "matched"
        assert verify_latest_incident_rebuild(session, incident_id) == changed


def test_cross_incident_alias_and_redirect_invariants_are_concurrency_safe(database) -> None:
    alias_incidents = (
        "gbsec:incident:synthetic-alias-a",
        "gbsec:incident:synthetic-alias-b",
    )
    shared_alias = "gbsec:alias:synthetic-shared"
    with Session(database.engine) as session, session.begin():
        for incident_id in alias_incidents:
            _create(session, incident_id)

    alias_barrier = Barrier(2)

    def add_alias(incident_id: str) -> str:
        try:
            with Session(database.engine) as session, session.begin():
                alias_barrier.wait()
                apply_incident_event(
                    session,
                    event=_event(
                        incident_id,
                        stable_id("event", incident_id, "shared-alias"),
                        "alias_added",
                        old_status="confirmed",
                        new_status="confirmed",
                        superseded_revision=1,
                        occurred_at=NOW + timedelta(minutes=1),
                    ),
                    details={"alias_id": shared_alias},
                )
            return "accepted"
        except IncidentLifecycleError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as executor:
        alias_results = list(executor.map(add_alias, alias_incidents))
    assert sorted(alias_results) == ["accepted", "rejected"]
    with Session(database.engine) as session:
        resolved, _hops = resolve_incident_id(session, shared_alias)
        assert resolved in alias_incidents

    redirect_incidents = (
        "gbsec:incident:synthetic-redirect-a",
        "gbsec:incident:synthetic-redirect-b",
    )
    with Session(database.engine) as session, session.begin():
        for incident_id in redirect_incidents:
            _create(session, incident_id)
    redirect_barrier = Barrier(2)

    def add_redirect(pair: tuple[str, str]) -> str:
        source, target = pair
        try:
            with Session(database.engine) as session, session.begin():
                redirect_barrier.wait()
                apply_incident_event(
                    session,
                    event=_event(
                        source,
                        stable_id("event", source, "redirect"),
                        "redirected",
                        old_status="confirmed",
                        new_status="confirmed",
                        superseded_revision=1,
                        occurred_at=NOW + timedelta(minutes=1),
                    ),
                    details={"target_incident_id": target},
                )
            return "accepted"
        except IncidentLifecycleError:
            return "rejected"

    pairs = [
        (redirect_incidents[0], redirect_incidents[1]),
        (redirect_incidents[1], redirect_incidents[0]),
    ]
    with ThreadPoolExecutor(max_workers=2) as executor:
        redirect_results = list(executor.map(add_redirect, pairs))
    assert sorted(redirect_results) == ["accepted", "rejected"]
    with Session(database.engine) as session:
        latest = [
            verify_latest_incident_rebuild(session, incident_id)
            for incident_id in redirect_incidents
        ]
        assert sum(document["redirect_to"] is not None for document in latest) == 1


def test_clean_database_rebuilds_all_versioned_historical_replay_cases(database) -> None:
    catalog = json.loads(REPLAY_CATALOG.read_text(encoding="utf-8"))
    results = {
        item["case_id"]: item
        for item in json.loads(REPLAY_RESULTS.read_text(encoding="utf-8"))["results"]
    }
    defaults = catalog["defaults"]
    grouped: dict[str, dict[str, Any]] = {}
    processed_cases: list[str] = []
    with Session(database.engine) as session, session.begin():
        for replay in catalog["cases"]:
            expected = {**defaults, **replay}
            group = grouped.setdefault(
                expected["incident_group"],
                {
                    "status": expected["expected_incident_status"],
                    "ecosystem": replay["ecosystem"],
                    "artifact_ids": [],
                    "first_observed_at": None,
                    "case_ids": [],
                },
            )
            assert group["status"] == expected["expected_incident_status"]
            assert group["ecosystem"] == replay["ecosystem"]
            for artifact_input in replay["artifacts"]:
                identity = normalize_artifact_identity(artifact_input)
                artifact_id = stable_id("artifact", identity["coordinate"])
                artifact = {
                    "id": artifact_id,
                    "kind": "artifact",
                    "schema_version": "1.0.0",
                    "revision": 1,
                    "created_at": timestamp(NOW),
                    "updated_at": timestamp(NOW),
                    "data_classification": "public",
                    **identity,
                }
                append_contract(session, "Artifact", artifact)
                if artifact_id not in group["artifact_ids"]:
                    group["artifact_ids"].append(artifact_id)
            observed = datetime.fromisoformat(
                replay["expected_events"][0]["recorded_at"].replace("Z", "+00:00")
            )
            if group["first_observed_at"] is None or observed < group["first_observed_at"]:
                group["first_observed_at"] = observed
            group["case_ids"].append(replay["case_id"])
            processed_cases.append(replay["case_id"])

        incident_by_group: dict[str, dict[str, Any]] = {}
        for incident_group, group in sorted(grouped.items()):
            incident_id = stable_id("incident", incident_group)
            seed = IncidentSeed(
                incident_id=incident_id,
                title=f"Historical replay {group['case_ids'][0]}",
                initial_status=group["status"],
                initial_confidence=("confirmed" if group["status"] == "confirmed" else "possible"),
                claim_ids=(),
                artifact_ids=tuple(group["artifact_ids"]),
                affected_range_ids=(),
                relationship_ids=(),
                coverage=(
                    {
                        "ecosystem": group["ecosystem"],
                        "stage": "matched",
                        "result": "supported",
                        "as_of": timestamp(NOW),
                    },
                ),
                unknowns=("Historical fixture contains no customer data.",),
                first_observed_at=group["first_observed_at"],
                created_at=NOW,
            )
            event = _event(
                incident_id,
                stable_id("event", incident_group, "created"),
                "created",
                old_status=None,
                new_status=seed.initial_status,
                superseded_revision=None,
                confidence=seed.initial_confidence,
                occurred_at=NOW,
            )
            first = create_incident(session, seed=seed, event=event)
            second = create_incident(session, seed=seed, event=event)
            assert first.created and not second.created
            assert first.document == second.document
            assert verify_latest_incident_rebuild(session, incident_id) == first.document
            incident_by_group[incident_group] = first.document

        for replay in catalog["cases"]:
            if replay["case_id"] in results:
                assert (
                    incident_by_group[replay["incident_group"]]["status"]
                    == results[replay["case_id"]]["output"]["incident_status"]
                )
        assert len(processed_cases) == 26
        assert len(set(processed_cases)) == 26
        assert len(grouped) == 24
        assert session.scalar(select(func.count()).select_from(IncidentRecord)) == 24
        assert session.scalar(select(func.count()).select_from(IncidentTransitionRecord)) == 24
