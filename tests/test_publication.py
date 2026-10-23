"""Canonical public-source corrections never erase prior incident history."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import smithguard.publication as publication_module
from smithguard.collectors import (
    GITHUB_ADVISORY,
    CollectorRunner,
    GitHubAdvisoryCollection,
    TransportResponse,
)
from smithguard.db.models import (
    AffectedRangeRecord,
    ArtifactRecord,
    AuthorityDecisionRecord,
    ClaimRecord,
    ReviewQueueEventRecord,
    SourceClusterMemberRecord,
    SourceIncidentLinkRecord,
)
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.identifiers import sha256_id, stable_id, timestamp
from smithguard.incidents import IncidentSeed, apply_incident_event, create_incident
from smithguard.publication import _append_link, publish_github_malware_incidents
from smithguard.query import latest_incident
from smithguard.service import SmithGuardService
from smithguard.source_rights import RightsRegistry

from .governance_fixtures import active_governance_policy

REPO_ROOT = Path(__file__).resolve().parents[1]
RIGHTS_REGISTER = REPO_ROOT / "contracts/v1/source-rights-register.json"
NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _openssf_reference(identifier: str) -> str:
    return (
        "https://github.com/ossf/malicious-packages/blob/"
        + "a" * 40
        + f"/osv/malicious/pypi/historical-malware/{identifier}.json"
    )


def _advisory(
    *,
    updated_at: datetime,
    versions: tuple[str, ...],
    withdrawn: bool = False,
    ecosystem: str = "npm",
    published_at: str = "2020-01-01T00:00:00Z",
    references: tuple[str, ...] = (),
    range_expressions: tuple[str, ...] = (),
) -> dict:
    return {
        "ghsa_id": "GHSA-aaaa-bbbb-9999",
        "type": "malware",
        "published_at": published_at,
        "updated_at": timestamp(updated_at),
        "withdrawn_at": timestamp(updated_at) if withdrawn else None,
        "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-9999",
        "vulnerabilities": [
            {
                "package": {
                    "ecosystem": ecosystem,
                    "name": "historical-malware",
                },
                "vulnerable_version_range": f"= {version}",
                "first_patched_version": None,
            }
            for version in versions
        ]
        + [
            {
                "package": {
                    "ecosystem": ecosystem,
                    "name": "historical-malware",
                },
                "vulnerable_version_range": expression,
                "first_patched_version": None,
            }
            for expression in range_expressions
        ],
        "references": list(references),
    }


def _collect(
    session: Session,
    *,
    evidence_store: LocalImmutableEvidenceStore,
    updated_at: datetime,
    versions: tuple[str, ...],
    withdrawn: bool = False,
    ecosystem: str = "npm",
    published_at: str = "2020-01-01T00:00:00Z",
    references: tuple[str, ...] = (),
    range_expressions: tuple[str, ...] = (),
) -> GitHubAdvisoryCollection:
    advisory = _advisory(
        updated_at=updated_at,
        versions=versions,
        withdrawn=withdrawn,
        ecosystem=ecosystem,
        published_at=published_at,
        references=references,
        range_expressions=range_expressions,
    )
    body = json.dumps(
        [advisory],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")

    def transport(_spec, _checkpoint):
        return TransportResponse(
            body=body,
            canonical_url=advisory["html_url"],
            media_type="application/json",
            retrieved_at=updated_at,
            source_record_id=f"{advisory['ghsa_id']}:{timestamp(updated_at)}",
            source_published_at=datetime.fromisoformat(published_at.replace("Z", "+00:00")),
            declared_content_length=len(body),
            checkpoint_token=(f"{advisory['ghsa_id']}:{timestamp(updated_at)}:{sha256_id(body)}"),
        )

    run = CollectorRunner(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        transport=transport,
        clock=lambda: updated_at,
        governance_policy=active_governance_policy(),
    ).run_public(session, source_id=GITHUB_ADVISORY)
    assert run.outcome is not None
    assert run.outcome.outcome == "accepted"
    return GitHubAdvisoryCollection(
        advisory_id=advisory["ghsa_id"],
        published_at=datetime.fromisoformat(published_at.replace("Z", "+00:00")),
        updated_at=updated_at,
        withdrawn=withdrawn,
        outcome=run.outcome,
    )


@pytest.mark.parametrize("first_expression", ["> 0", "<= 1.3"])
def test_range_publication_is_reported_and_replaces_changed_range_ids_append_only(
    database,
    first_expression,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        initial = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW,
            versions=(),
            range_expressions=(first_expression, ">= 2.0.0, < 3.0.0"),
        )
        created = publish_github_malware_incidents(
            session,
            collection=initial,
            published_at=NOW,
            governance_policy=active_governance_policy(),
        )
        assert len(created) == 1
        assert created[0]["status"] == "reported"
        assert created[0]["title"] == "Malicious npm package range: historical-malware"
        assert len(created[0]["affected_range_ids"]) == 2
        assert "exact artifact" not in " ".join(created[0]["unknowns"])
        assert "package range" in " ".join(created[0]["unknowns"])
        incident_id = created[0]["id"]
        first_range_ids = set(created[0]["affected_range_ids"])

    with Session(database.engine) as session, session.begin():
        corrected = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW + timedelta(hours=1),
            versions=(),
            range_expressions=("< 2.0.0",),
        )
        changed = publish_github_malware_incidents(
            session,
            collection=corrected,
            published_at=NOW + timedelta(hours=1),
            governance_policy=active_governance_policy(),
        )
        assert len(changed) == 1
        current = latest_incident(session, incident_id, public_only=True)
        assert current is not None
        assert current.revision == 2
        assert len(current.affected_range_ids) == 1
        assert first_range_ids.isdisjoint(current.affected_range_ids)

        service = SmithGuardService(clock=lambda: NOW)

        def request(version: str, suffix: str) -> dict:
            return {
                "id": f"gbsec:request:range-{suffix}",
                "kind": "public_artifact_assessment_request",
                "schema_version": "1.0.0",
                "revision": 1,
                "created_at": timestamp(NOW),
                "updated_at": timestamp(NOW),
                "data_classification": "public",
                "artifact": {
                    "ecosystem": "npm",
                    "registry_host": "registry.npmjs.org",
                    "name": "historical-malware",
                    "version": version,
                    "digest": None,
                    "public_visibility": "asserted_public",
                },
            }

        inside = service.assess_public_artifact(session, request("1.9.9", "inside"))
        outside = service.assess_public_artifact(session, request("2.0.0", "outside"))
        assert inside["result"] == "possibly_affected"
        assert inside["incident_ids"] == [incident_id]
        assert outside["result"] == "not_affected"


def test_evidence_only_republication_reuses_the_source_member_append_only(
    database,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        initial = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW,
            versions=("1.0.0",),
        )
        first_evidence_id = initial.outcome.raw_evidence_id
        assert first_evidence_id is not None
        first = publish_github_malware_incidents(
            session,
            collection=initial,
            published_at=NOW,
            governance_policy=active_governance_policy(),
        )[0]
        incident_id = first["id"]
        first_status = first["status"]
        first_confidence = first["confidence"]

    with Session(database.engine) as session, session.begin():
        refreshed = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW,
            versions=("1.0.0",),
            references=("https://example.com/source-revision",),
        )
        second_evidence_id = refreshed.outcome.raw_evidence_id
        assert second_evidence_id is not None
        assert second_evidence_id != first_evidence_id

        republished = publish_github_malware_incidents(
            session,
            collection=refreshed,
            published_at=NOW,
            governance_policy=active_governance_policy(),
        )
        assert len(republished) == 1
        current = latest_incident(session, incident_id, public_only=True)
        assert current is not None
        assert current.revision == 2
        assert current.status == first_status
        assert current.confidence == first_confidence

        members = tuple(session.scalars(select(SourceClusterMemberRecord)))
        assert len(members) == 1
        assert members[0].evidence_id == first_evidence_id

        decisions = tuple(
            session.scalars(select(AuthorityDecisionRecord).order_by(AuthorityDecisionRecord.id))
        )
        assert len(decisions) == 2
        assert {tuple(decision.evidence_ids) for decision in decisions} == {
            (first_evidence_id,),
            (second_evidence_id,),
        }

        links = tuple(
            session.scalars(
                select(SourceIncidentLinkRecord).order_by(SourceIncidentLinkRecord.sequence)
            )
        )
        assert len(links) == 2
        assert [link.evidence_id for link in links] == [
            first_evidence_id,
            second_evidence_id,
        ]

    assert len(evidence_store.manifest()) == 2
    assert evidence_store.pending_manifest() == []
    evidence_store.close()


def test_source_correction_removal_withdrawal_and_reactivation_are_append_only(
    database,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        initial = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW,
            versions=("1.0.0", "2.0.0"),
        )
        created = publish_github_malware_incidents(
            session,
            collection=initial,
            published_at=NOW,
            governance_policy=active_governance_policy(),
        )
        initial_ids = {document["artifact_ids"][0]: document["id"] for document in created}
        assert len(initial_ids) == 2

    with Session(database.engine) as session, session.begin():
        corrected = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW + timedelta(hours=1),
            versions=("1.0.0",),
        )
        publish_github_malware_incidents(
            session,
            collection=corrected,
            published_at=NOW + timedelta(hours=1),
            governance_policy=active_governance_policy(),
        )
        current = {
            artifact_id: latest_incident(session, incident_id, public_only=True)
            for artifact_id, incident_id in initial_ids.items()
        }
        statuses = sorted(record.status for record in current.values() if record is not None)
        assert statuses == ["confirmed", "withdrawn"]

    with Session(database.engine) as session, session.begin():
        withdrawn = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW + timedelta(hours=2),
            versions=("1.0.0",),
            withdrawn=True,
        )
        publish_github_malware_incidents(
            session,
            collection=withdrawn,
            published_at=NOW + timedelta(hours=2),
            governance_policy=active_governance_policy(),
        )
        assert all(
            latest_incident(session, incident_id, public_only=True).status == "withdrawn"
            for incident_id in initial_ids.values()
        )

    with Session(database.engine) as session, session.begin():
        reactivated = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW + timedelta(hours=3),
            versions=("1.0.0",),
        )
        published = publish_github_malware_incidents(
            session,
            collection=reactivated,
            published_at=NOW + timedelta(hours=3),
            governance_policy=active_governance_policy(),
        )
        assert any(document["status"] == "confirmed" for document in published)
        links = list(
            session.scalars(
                select(SourceIncidentLinkRecord).order_by(
                    SourceIncidentLinkRecord.artifact_id,
                    SourceIncidentLinkRecord.sequence,
                )
            )
        )
        states_by_artifact: dict[str, list[str]] = {}
        for link in links:
            states_by_artifact.setdefault(link.artifact_id, []).append(link.state)
        assert {tuple(states) for states in states_by_artifact.values()} == {
            ("active", "removed", "withdrawn", "removed"),
            ("active", "active", "withdrawn", "active"),
        }


def test_removing_every_exact_artifact_withdraws_prior_incidents(
    database,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        initial = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW,
            versions=("1.0.0",),
        )
        created = publish_github_malware_incidents(
            session,
            collection=initial,
            published_at=NOW,
            governance_policy=active_governance_policy(),
        )
        incident_id = created[0]["id"]

    with Session(database.engine) as session, session.begin():
        empty = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW + timedelta(hours=1),
            versions=(),
        )
        assert empty.outcome.record_count == 0
        changed = publish_github_malware_incidents(
            session,
            collection=empty,
            published_at=NOW + timedelta(hours=1),
            governance_policy=active_governance_policy(),
        )
        assert changed[-1]["status"] == "withdrawn"
        current = latest_incident(session, incident_id, public_only=True)
        assert current is not None
        assert current.status == "withdrawn"
        assert [
            link.state
            for link in session.scalars(
                select(SourceIncidentLinkRecord).order_by(SourceIncidentLinkRecord.sequence)
            )
        ] == ["active", "removed"]


def test_publication_uses_the_contracts_second_level_time_resolution(
    database,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        collection = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW,
            versions=("3.0.0",),
        )
        published = publish_github_malware_incidents(
            session,
            collection=collection,
            published_at=NOW + timedelta(microseconds=123_456),
            governance_policy=active_governance_policy(),
        )

        assert len(published) == 1
        assert published[0]["created_at"] == timestamp(NOW)
        assert published[0]["last_changed_at"] == timestamp(NOW)


def test_publication_uses_injected_governance_when_default_contracts_are_absent(
    database,
    monkeypatch,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    governance_policy = active_governance_policy()
    with Session(database.engine) as session, session.begin():
        collection = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW,
            versions=("3.0.0",),
        )
        missing_default = tmp_path / "installed-wheel" / "source-governance-policy.json"
        assert not missing_default.exists()
        monkeypatch.setattr(
            publication_module,
            "DEFAULT_GOVERNANCE_POLICY_PATH",
            missing_default,
        )

        published = publish_github_malware_incidents(
            session,
            collection=collection,
            published_at=NOW,
            governance_policy=governance_policy,
        )

        assert len(published) == 1
        assert published[0]["status"] == "confirmed"


def test_publication_loads_reviewed_defaults_when_governance_is_not_injected(
    database,
    monkeypatch,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    governance_policy = active_governance_policy()
    default_registry = object()
    loaded: dict[str, object] = {}

    class RegistryLoader:
        @staticmethod
        def from_path(path: Path) -> object:
            loaded["rights_path"] = path
            return default_registry

    class PolicyLoader:
        @staticmethod
        def from_path(path: Path, *, registry: object) -> object:
            loaded["governance_path"] = path
            loaded["registry"] = registry
            return governance_policy

    with Session(database.engine) as session, session.begin():
        collection = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW,
            versions=("3.0.0",),
        )
        monkeypatch.setattr(publication_module, "RightsRegistry", RegistryLoader)
        monkeypatch.setattr(publication_module, "SourceGovernancePolicy", PolicyLoader)

        published = publish_github_malware_incidents(
            session,
            collection=collection,
            published_at=NOW,
        )

        assert len(published) == 1
        assert published[0]["status"] == "confirmed"
        assert loaded == {
            "rights_path": (
                publication_module.DEFAULT_GOVERNANCE_POLICY_PATH.parent
                / "source-rights-register.json"
            ),
            "governance_path": publication_module.DEFAULT_GOVERNANCE_POLICY_PATH,
            "registry": default_registry,
        }


def test_recent_source_statuses_preserve_authority_and_exception_boundaries(
    database,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        reported_collection = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW,
            versions=("1.0.0",),
            ecosystem="PyPI",
            published_at="2026-08-05T09:00:00Z",
        )
        reported = publish_github_malware_incidents(
            session,
            collection=reported_collection,
            published_at=NOW,
            governance_policy=active_governance_policy(),
        )[0]
        assert reported["status"] == "reported"
        assert reported["confidence"] == "unverified"
        assert reported["authority"]["confirming_authority_id"] is None
        assert reported["authority"]["independent_goodboy_analysis"] is False
        assert session.scalar(select(AuthorityDecisionRecord)).public_status == "reported"
        assert session.scalar(select(ReviewQueueEventRecord)) is None

    with Session(database.engine) as session, session.begin():
        confirmed_collection = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW + timedelta(hours=1),
            versions=("2.0.0",),
            ecosystem="PyPI",
            published_at="2026-08-05T09:00:00Z",
            references=(_openssf_reference("MAL-2026-123"),),
        )
        confirmed = publish_github_malware_incidents(
            session,
            collection=confirmed_collection,
            published_at=NOW + timedelta(hours=1),
            governance_policy=active_governance_policy(),
        )[0]
        assert confirmed["status"] == "confirmed"
        assert (
            confirmed["authority"]["confirming_authority_id"]
            == "gbsec:source:openssf-malicious-packages"
        )
        assert confirmed["authority"]["confirmation_method"] == "automated_source_policy"

        resolved_at = NOW + timedelta(hours=2)
        resolved = apply_incident_event(
            session,
            event={
                "id": stable_id("event", confirmed["id"], "resolved"),
                "kind": "incident_event",
                "schema_version": "1.0.0",
                "revision": 1,
                "created_at": timestamp(resolved_at),
                "updated_at": timestamp(resolved_at),
                "data_classification": "public",
                "incident_id": confirmed["id"],
                "event_type": "state_changed",
                "old_status": "confirmed",
                "new_status": "resolved",
                "actor_type": "system",
                "actor_id": "system-synthetic-resolution",
                "reason_code": "synthetic_resolution",
                "evidence_ids": confirmed["authority"]["evidence_ids"],
                "occurred_at": timestamp(resolved_at),
                "confidence": "confirmed",
                "superseded_revision": confirmed["revision"],
            },
        )
        assert resolved.document["status"] == "resolved"
        assert resolved.document["authority"] == confirmed["authority"]


def test_ambiguous_openssf_origins_open_exactly_one_review_item(
    database,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        collection = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW,
            versions=("3.0.0",),
            ecosystem="PyPI",
            published_at="2026-08-05T09:00:00Z",
            references=(
                _openssf_reference("MAL-2026-123"),
                _openssf_reference("MAL-2026-456"),
            ),
        )
        first = publish_github_malware_incidents(
            session,
            collection=collection,
            published_at=NOW,
            governance_policy=active_governance_policy(),
        )[0]
        second = publish_github_malware_incidents(
            session,
            collection=collection,
            published_at=NOW + timedelta(hours=6),
            governance_policy=active_governance_policy(),
        )[0]
        assert first == second
        assert first["status"] == "reported"
        assert first["authority"]["exception_reason_code"] == "ambiguous_openssf_origin"
        assert session.scalar(select(func.count()).select_from(ReviewQueueEventRecord)) == 1
        assert session.scalar(select(func.count()).select_from(AuthorityDecisionRecord)) == 1
        assert session.scalar(select(func.count()).select_from(SourceClusterMemberRecord)) == 1


def test_pre_authority_incident_can_be_withdrawn_conservatively(
    database,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        initial = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW,
            versions=("4.0.0",),
        )
        artifact = session.scalar(select(ArtifactRecord))
        claim = session.scalar(select(ClaimRecord))
        affected_range = session.scalar(select(AffectedRangeRecord))
        assert artifact is not None and claim is not None and affected_range is not None
        assert initial.outcome.raw_evidence_id is not None
        incident_id = stable_id(
            "incident",
            GITHUB_ADVISORY,
            initial.advisory_id,
            artifact.id,
        )
        create_incident(
            session,
            seed=IncidentSeed(
                incident_id=incident_id,
                title="Pre-authority malware fixture",
                initial_status="confirmed",
                initial_confidence="confirmed",
                claim_ids=(claim.id,),
                artifact_ids=(artifact.id,),
                affected_range_ids=(affected_range.id,),
                relationship_ids=(),
                coverage=(
                    {
                        "ecosystem": artifact.ecosystem,
                        "stage": "matched",
                        "result": "supported",
                        "as_of": timestamp(NOW),
                    },
                ),
                unknowns=("Pre-MX-002 incident without authority lineage.",),
                first_observed_at=NOW,
                created_at=NOW,
            ),
            event={
                "id": stable_id("event", incident_id, "created"),
                "kind": "incident_event",
                "schema_version": "1.0.0",
                "revision": 1,
                "created_at": timestamp(NOW),
                "updated_at": timestamp(NOW),
                "data_classification": "public",
                "incident_id": incident_id,
                "event_type": "created",
                "old_status": None,
                "new_status": "confirmed",
                "actor_type": "system",
                "actor_id": "system-pre-authority-fixture",
                "reason_code": "pre_authority_fixture",
                "evidence_ids": [initial.outcome.raw_evidence_id],
                "occurred_at": timestamp(NOW),
                "confidence": "confirmed",
                "superseded_revision": None,
            },
        )
        _append_link(
            session,
            advisory_id=initial.advisory_id,
            artifact_id=artifact.id,
            incident_id=incident_id,
            state="active",
            source_updated_at=initial.updated_at,
            evidence_id=initial.outcome.raw_evidence_id,
            observed_at=initial.updated_at,
        )

    with Session(database.engine) as session, session.begin():
        removed = _collect(
            session,
            evidence_store=evidence_store,
            updated_at=NOW + timedelta(hours=1),
            versions=(),
        )
        changed = publish_github_malware_incidents(
            session,
            collection=removed,
            published_at=NOW + timedelta(hours=8),
            governance_policy=active_governance_policy(),
        )
        assert changed[-1]["status"] == "withdrawn"
        authority = changed[-1]["authority"]
        assert authority["assertion_source_id"] is None
        assert authority["confirming_authority_id"] is None
        assert authority["upstream_ids"] == [removed.advisory_id]


def test_partial_comparator_incident_can_be_withdrawn(database, tmp_path: Path) -> None:
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        initial = _collect(
            session,
            evidence_store=store,
            updated_at=NOW,
            versions=(),
            range_expressions=("<= 1.3",),
        )
        incident = publish_github_malware_incidents(
            session,
            collection=initial,
            published_at=NOW,
            governance_policy=active_governance_policy(),
        )[0]
    with Session(database.engine) as session, session.begin():
        withdrawn = _collect(
            session,
            evidence_store=store,
            updated_at=NOW + timedelta(hours=1),
            versions=(),
            range_expressions=("<= 1.3",),
            withdrawn=True,
        )
        published = publish_github_malware_incidents(
            session,
            collection=withdrawn,
            published_at=NOW + timedelta(hours=1),
            governance_policy=active_governance_policy(),
        )
        assert published[0]["id"] == incident["id"]
        current = latest_incident(session, incident["id"], public_only=True)
        assert current is not None and current.status == "withdrawn"
