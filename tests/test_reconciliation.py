"""Source independence, conflict, correction, and withdrawal clustering."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.acquisition import AcquisitionRequest
from smithguard.collectors import (
    GITHUB_ADVISORY,
    CollectorRunner,
    TransportResponse,
    filter_github_advisory,
    transform_github_advisories,
)
from smithguard.db.models import (
    AffectedRangeRecord,
    ArtifactRecord,
    AuthorityDecisionRecord,
    ClaimRecord,
)
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.identifiers import stable_id, timestamp
from smithguard.incidents import IncidentSeed, create_incident
from smithguard.ingestion import ingest_bytes
from smithguard.query import latest_incident
from smithguard.reconciliation import (
    ReconciliationError,
    SourceMember,
    append_source_member,
    cluster_id_for,
    reconcile_historical_malware_authority,
    summarize_cluster,
)
from smithguard.source_rights import RightsRegistry

from .governance_fixtures import active_governance_policy

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
ARTIFACT_ID = "gbsec:artifact:synthetic-cluster"
REPO_ROOT = Path(__file__).resolve().parents[1]
RIGHTS_REGISTER = REPO_ROOT / "contracts/v1/source-rights-register.json"


def _member(
    suffix: str,
    *,
    origin: str,
    fingerprint: str,
    relation: str | None = None,
    minute: int = 0,
) -> SourceMember:
    return SourceMember(
        source_id=f"gbsec:source:{suffix}",
        source_record_id=f"synthetic-record-{suffix}",
        evidence_id=f"gbsec:evidence:{suffix}",
        artifact_id=ARTIFACT_ID,
        independent_origin_id=f"gbsec:origin:{origin}",
        claim_fingerprint="sha256:" + fingerprint * 64,
        observed_at=NOW + timedelta(minutes=minute),
        relation=relation,
    )


def test_clustering_distinguishes_reposts_independent_sources_and_conflicts(database) -> None:
    with Session(database.engine) as session, session.begin():
        first, created = append_source_member(
            session,
            member=_member("primary", origin="maintainer", fingerprint="a"),
        )
        assert created and first.relation == "origin"
        repost, created = append_source_member(
            session,
            member=_member(
                "repost",
                origin="maintainer",
                fingerprint="a",
                minute=1,
            ),
        )
        assert created and repost.relation == "origin"
        corroboration, created = append_source_member(
            session,
            member=_member(
                "independent",
                origin="researcher",
                fingerprint="a",
                minute=2,
            ),
        )
        assert created and corroboration.relation == "corroborates"
        conflict, created = append_source_member(
            session,
            member=_member(
                "conflict",
                origin="vendor",
                fingerprint="b",
                minute=3,
            ),
        )
        assert created and conflict.relation == "conflicts"
        replay, created = append_source_member(
            session,
            member=_member("primary", origin="maintainer", fingerprint="a"),
        )
        assert not created and replay.member_id == first.member_id

        summary = summarize_cluster(session, cluster_id_for(ARTIFACT_ID))
        assert summary.member_count == 4
        assert summary.independent_origin_count == 3
        assert summary.claim_fingerprint_count == 2
        assert summary.has_conflict
        assert summary.confirmation_state == "requires_human_review"


def test_new_evidence_for_the_same_source_claim_is_an_idempotent_semantic_replay(
    database,
) -> None:
    original = _member("revision", origin="maintainer", fingerprint="a")
    revision = replace(
        original,
        evidence_id="gbsec:evidence:revision-two",
    )
    with Session(database.engine) as session, session.begin():
        first, created = append_source_member(session, member=original)
        assert created
        second, created = append_source_member(session, member=revision)
        assert not created
        assert second.member_id == first.member_id
        assert second.evidence_id == original.evidence_id

        replay, created = append_source_member(session, member=revision)
        assert not created
        assert replay.member_id == first.member_id

        summary = summarize_cluster(session, cluster_id_for(ARTIFACT_ID))
        assert summary.member_count == 1
        assert summary.independent_origin_count == 1
        assert summary.claim_fingerprint_count == 1
        assert not summary.has_conflict


def test_new_evidence_cannot_hide_a_changed_source_claim(database) -> None:
    original = _member("semantic-change", origin="maintainer", fingerprint="a")
    changed = replace(
        original,
        evidence_id="gbsec:evidence:semantic-change-two",
        claim_fingerprint="sha256:" + "b" * 64,
        observed_at=NOW + timedelta(minutes=1),
    )
    with Session(database.engine) as session, session.begin():
        append_source_member(session, member=original)
        with pytest.raises(
            ReconciliationError,
            match="source member identity conflicts with history",
        ):
            append_source_member(session, member=changed)


def test_new_evidence_cannot_hide_changed_origin_relation_or_observation_time(
    database,
) -> None:
    changes = (
        (
            "origin-change",
            {"independent_origin_id": "gbsec:origin:other-maintainer"},
        ),
        ("relation-change", {"relation": "corrects"}),
        ("observation-change", {"observed_at": NOW + timedelta(minutes=1)}),
    )
    with Session(database.engine) as session, session.begin():
        for suffix, semantic_change in changes:
            original = _member(suffix, origin="maintainer", fingerprint="a")
            changed = replace(
                original,
                evidence_id=f"gbsec:evidence:{suffix}-two",
                **semantic_change,
            )
            append_source_member(session, member=original)
            with pytest.raises(
                ReconciliationError,
                match="source member identity conflicts with history",
            ):
                append_source_member(session, member=changed)


def test_corrections_and_withdrawals_remain_explicit_review_inputs(database) -> None:
    with Session(database.engine) as session, session.begin():
        append_source_member(
            session,
            member=_member("origin", origin="maintainer", fingerprint="a"),
        )
        append_source_member(
            session,
            member=_member(
                "correction",
                origin="maintainer",
                fingerprint="b",
                relation="corrects",
                minute=1,
            ),
        )
        append_source_member(
            session,
            member=_member(
                "withdrawal",
                origin="maintainer",
                fingerprint="b",
                relation="withdraws",
                minute=2,
            ),
        )
        summary = summarize_cluster(session, cluster_id_for(ARTIFACT_ID))
        assert summary.has_correction
        assert summary.has_withdrawal
        assert summary.confirmation_state == "withdrawn"


def test_two_independent_compatible_origins_are_corroborated(database) -> None:
    with Session(database.engine) as session, session.begin():
        append_source_member(
            session,
            member=_member("first", origin="maintainer", fingerprint="a"),
        )
        append_source_member(
            session,
            member=_member(
                "second",
                origin="researcher",
                fingerprint="a",
                minute=1,
            ),
        )
        summary = summarize_cluster(session, cluster_id_for(ARTIFACT_ID))
        assert summary.confirmation_state == "corroborated"


def _legacy_github_incident(
    session: Session,
    *,
    evidence_store: LocalImmutableEvidenceStore,
    suffix: str = "hist",
    ecosystem: str = "PyPI",
    published_at: datetime = NOW,
    sibling: dict | None = None,
) -> str:
    advisory_id = f"GHSA-aaaa-bbbb-{suffix}"
    package_name = f"historical-malware-{suffix}"
    advisory = {
        "ghsa_id": advisory_id,
        "type": "malware",
        "published_at": timestamp(published_at),
        "updated_at": timestamp(NOW),
        "withdrawn_at": None,
        "html_url": f"https://github.com/advisories/{advisory_id}",
        "vulnerabilities": [
            {
                "package": {
                    "ecosystem": ecosystem,
                    "name": package_name,
                },
                "vulnerable_version_range": "= 1.0.0",
                "first_patched_version": None,
            }
        ],
    }
    if sibling is not None:
        advisory["vulnerabilities"].append(sibling)
    body = json.dumps([advisory], sort_keys=True, separators=(",", ":")).encode("ascii")

    def transport(_spec, _checkpoint):
        return TransportResponse(
            body=body,
            canonical_url=advisory["html_url"],
            media_type="application/json",
            retrieved_at=NOW,
            source_record_id=f"{advisory['ghsa_id']}:{timestamp(NOW)}",
            source_published_at=published_at,
            source_modified_at=NOW,
            declared_content_length=len(body),
            checkpoint_token=f"{suffix}:{timestamp(NOW)}",
        )

    registry = RightsRegistry.from_path(RIGHTS_REGISTER)
    if sibling is None:
        outcome = (
            CollectorRunner(
                registry=registry,
                evidence_store=evidence_store,
                transport=transport,
                clock=lambda: NOW,
                governance_policy=active_governance_policy(),
            )
            .run_public(session, source_id=GITHUB_ADVISORY)
            .outcome
        )
    else:
        source = registry.get(GITHUB_ADVISORY).source

        def legacy_transform(records):
            scoped = {
                **records[0],
                "vulnerabilities": [records[0]["vulnerabilities"][0]],
            }
            return transform_github_advisories((filter_github_advisory(scoped),))

        request = AcquisitionRequest(
            source_record_id=f"{advisory_id}:{timestamp(NOW)}",
            canonical_url=advisory["html_url"],
            retrieved_at=NOW,
            source_published_at=published_at,
            source_modified_at=NOW,
            media_type="application/json",
            declared_content_length=len(body),
        )
        policy = active_governance_policy()
        outcome = ingest_bytes(
            session,
            evidence_store=evidence_store,
            source=source,
            governance=policy.authorize_collection(
                connector_id="gbsec:connector:github-advisory-rest-v1",
                source_id=GITHUB_ADVISORY,
                acquisition_method="rest_api",
                operating_mode="historical",
                canonical_url=request.canonical_url,
                source_record_id=request.source_record_id,
                authorized_at=NOW,
            ),
            request=request,
            body=body,
            idempotency_key=f"legacy-mixed:{suffix}",
            collection_method="rest_api",
            identity_verification="verified",
            signature_state="unsupported",
            record_transform=legacy_transform,
        )
    assert outcome is not None and outcome.outcome == "accepted"
    artifact = session.scalar(
        select(ArtifactRecord).where(ArtifactRecord.id.in_(outcome.normalized_record_ids))
    )
    claim = session.scalar(
        select(ClaimRecord).where(ClaimRecord.id.in_(outcome.normalized_record_ids))
    )
    affected_range = session.scalar(
        select(AffectedRangeRecord).where(AffectedRangeRecord.id.in_(outcome.normalized_record_ids))
    )
    assert artifact is not None and claim is not None and affected_range is not None
    incident_id = stable_id("incident", "legacy-authority", artifact.id)
    create_incident(
        session,
        seed=IncidentSeed(
            incident_id=incident_id,
            title="Historical malware authority fixture",
            initial_status="confirmed",
            initial_confidence="confirmed",
            claim_ids=(claim.id,),
            artifact_ids=(artifact.id,),
            affected_range_ids=(affected_range.id,),
            relationship_ids=(),
            coverage=(
                {
                    "ecosystem": "pypi",
                    "stage": "matched",
                    "result": "supported",
                    "as_of": timestamp(NOW),
                },
            ),
            unknowns=("Pre-MX-002 fixture without authority lineage.",),
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
            "actor_id": "system-legacy-fixture",
            "reason_code": "legacy_fixture",
            "evidence_ids": [outcome.raw_evidence_id],
            "occurred_at": timestamp(NOW),
            "confidence": "confirmed",
            "superseded_revision": None,
        },
    )
    return incident_id


def test_historical_authority_dry_run_apply_and_replay_are_deterministic(
    database,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        incident_id = _legacy_github_incident(
            session,
            evidence_store=evidence_store,
        )
        dry_run = reconcile_historical_malware_authority(
            session,
            evidence_store=evidence_store,
            reconciled_at=NOW + timedelta(hours=1),
        )
        assert dry_run.mode == "dry_run"
        assert dry_run.eligible_count == 1
        assert dry_run.changed_count == 0
        assert dry_run.items[0].current_status == "confirmed"
        assert dry_run.items[0].proposed_status == "reported"
        assert session.scalar(select(func.count()).select_from(AuthorityDecisionRecord)) == 0
        assert latest_incident(session, incident_id).revision == 1

        applied = reconcile_historical_malware_authority(
            session,
            evidence_store=evidence_store,
            reconciled_at=NOW + timedelta(hours=1),
            apply=True,
        )
        assert applied.changed_count == 1
        current = latest_incident(session, incident_id)
        assert current is not None
        assert current.status == "reported"
        assert current.revision == 2
        assert current.authority["independent_goodboy_analysis"] is False
        assert session.scalar(select(func.count()).select_from(AuthorityDecisionRecord)) == 1

        replay = reconcile_historical_malware_authority(
            session,
            evidence_store=evidence_store,
            reconciled_at=NOW + timedelta(hours=2),
            apply=True,
        )
        assert replay.changed_count == 0
        assert replay.skipped_count == 1
        assert session.scalar(select(func.count()).select_from(AuthorityDecisionRecord)) == 1


def test_historical_reconciliation_ignores_an_unrelated_nonexact_sibling(
    database,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        _legacy_github_incident(
            session,
            evidence_store=evidence_store,
            suffix="mixed",
            ecosystem="npm",
            published_at=datetime(2020, 1, 1, tzinfo=UTC),
            sibling={
                "package": {
                    "ecosystem": "PyPI",
                    "name": "unrelated-sibling",
                },
                "vulnerable_version_range": ">= 2.0.0",
                "first_patched_version": None,
            },
        )
    with Session(database.engine) as session, session.begin():
        report = reconcile_historical_malware_authority(
            session,
            evidence_store=evidence_store,
            reconciled_at=NOW + timedelta(hours=1),
        )
        assert report.eligible_count == 1
        assert report.items[0].proposed_status == "confirmed"
        assert report.items[0].reason_code == "github_legacy_npm_exact_malware"


def test_historical_reconciliation_returns_a_bounded_continuation(
    database,
    tmp_path: Path,
) -> None:
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        first_incident_id = _legacy_github_incident(
            session,
            evidence_store=evidence_store,
            suffix="page1",
        )
        second_incident_id = _legacy_github_incident(
            session,
            evidence_store=evidence_store,
            suffix="page2",
        )
        first = reconcile_historical_malware_authority(
            session,
            evidence_store=evidence_store,
            reconciled_at=NOW + timedelta(hours=1),
            limit=1,
        )
        assert first.scanned_count == 1
        assert first.has_more
        assert first.next_after is not None
        second = reconcile_historical_malware_authority(
            session,
            evidence_store=evidence_store,
            reconciled_at=NOW + timedelta(hours=1),
            limit=1,
            after=first.next_after,
        )
        assert second.scanned_count == 1
        assert not second.has_more
        assert second.next_after is None
        assert {first.items[0].incident_id, second.items[0].incident_id} == {
            first_incident_id,
            second_incident_id,
        }


def test_historical_evaluation_reports_missing_evidence_but_propagates_corruption() -> None:
    from types import SimpleNamespace

    from smithguard.authority import load_authority_policy
    from smithguard.evidence import EvidenceIntegrityError, EvidenceMissingError
    from smithguard.reconciliation import _historical_evaluation

    class _Store:
        def __init__(self, error: Exception) -> None:
            self.error = error

        def read_bytes(self, _digest: str) -> bytes:
            raise self.error

    evidence = SimpleNamespace(
        id=stable_id("evidence", "synthetic"),
        source_record_id="GHSA-aaaa-bbbb-cccc:synthetic",
        sha256="sha256:" + "a" * 64,
        canonical_url="https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
    )
    policy = load_authority_policy()
    reported = _historical_evaluation(
        evidence_store=_Store(EvidenceMissingError("immutable evidence is missing")),
        evidence=evidence,
        artifact={},
        policy=policy,
        current_status="confirmed",
    )
    assert reported.public_status == "reported"
    with pytest.raises(EvidenceIntegrityError, match="checksum mismatch"):
        _historical_evaluation(
            evidence_store=_Store(EvidenceIntegrityError("immutable evidence checksum mismatch")),
            evidence=evidence,
            artifact={},
            policy=policy,
            current_status="confirmed",
        )
