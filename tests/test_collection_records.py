"""Real PostgreSQL tests for collection conservation and durable omission repair."""

from copy import deepcopy
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from smithguard.advisory_catalog import AdvisoryCatalogError, catalog_evidence_for_package
from smithguard.collection_records import (
    RecordAccountingError,
    actionable_quarantine_count,
    unresolved_count,
)
from smithguard.collectors import (
    GITHUB_ADVISORY,
    CollectorBoundaryError,
    GitHubAdvisoryRestCollector,
)
from smithguard.coverage import build_coverage_report, refresh_coverage_report
from smithguard.db.models import (
    AdvisoryCatalogManifestRecord,
    AdvisoryCatalogRecord,
    CollectionRecordMembership,
    CollectionRecordOutcome,
    CollectionRecordResolution,
    CollectorProgressRecord,
    EvidenceFinalizationRecord,
    IngestionBatchRecord,
)
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.evidence_finalization import EvidenceFinalizationError, require_finalized
from smithguard.source_rights import RightsRegistry

from .governance_fixtures import active_governance_policy
from .test_collectors import NOW, RIGHTS_REGISTER, _github_advisory


def advisory(suffix="cfgh", name="accounting-package"):
    value = _github_advisory(
        advisory_id=f"GHSA-2345-6789-{suffix}",
        name=name,
        version="1.0.0",
        published_at="2026-08-01T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    value["type"] = "reviewed"
    return value


def collector(tmp_path, handler, *, advisory_type="reviewed"):
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    instance = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
        advisory_type=advisory_type,
        catalog_mode=True,
    )
    return instance, store


def response(request, records, *, next_page=False):
    headers = {"content-type": "application/json"}
    if next_page:
        headers["link"] = f'<{request.url.copy_add_param("after", "page2")}>; rel="next"'
    return httpx.Response(200, headers=headers, json=records, request=request)


def count(session, model):
    return session.scalar(select(func.count()).select_from(model))


@pytest.mark.audit_ids("COL-06")
def test_bad_record_does_not_block_good_siblings_or_next_page_and_gap_persists(database, tmp_path):
    bad = advisory()
    bad["published_at"] = "invalid"
    bad["description"] = "private field must never be retained"
    good = advisory("cfgj", "good-sibling")
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return response(request, [bad, good], next_page=True)
        return response(request, [advisory("cfgm", "later-page")])

    instance, store = collector(tmp_path, handler)
    with Session(database.engine) as session, session.begin():
        first = instance.run(session, lane="updates")
        assert first.state == "in_progress" and first.page_processed
        assert first.page_source_record_count == 2 and len(first.collections) == 1
    with Session(database.engine) as session, session.begin():
        second = instance.run(session, lane="updates")
        assert second.state == "complete" and second.source_record_count == 3
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 1
        assert count(session, CollectionRecordMembership) == 3
        failed = session.scalar(
            select(CollectionRecordOutcome).where(
                CollectionRecordOutcome.disposition == "quarantined"
            )
        )
        assert failed.document["evidence_id"] is None
        assert "private field" not in str(failed.document)
        assert failed.record_key == bad["ghsa_id"]
    assert requests[1].url.params["after"] == "page2"
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
    with Session(database.engine) as session:
        refresh_coverage_report(session, measured_at=NOW + timedelta(seconds=1))
        report = build_coverage_report(session, measured_at=NOW + timedelta(seconds=1))
        assert "1 source record(s) have unresolved collection omissions" in str(report)
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 1
    assert all(b"private field" not in store.read_bytes(blob.digest) for blob in store.manifest())
    assert not store.pending_manifest()


def test_repeated_excluded_record_counts_once_and_retains_supported_sibling(database, tmp_path):
    value = advisory()
    value["vulnerabilities"].append(
        {
            "package": {"ecosystem": "other", "name": "untyped-public-package"},
            "vulnerable_version_range": "= 1.0.0",
            "first_patched_version": None,
        }
    )
    instance, store = collector(tmp_path, lambda req: response(req, [value]))
    for _ in range(3):
        with Session(database.engine) as session, session.begin():
            assert instance.run(session, lane="updates").state == "complete"
    with Session(database.engine) as session:
        assert count(session, CollectionRecordOutcome) == 1
        assert count(session, CollectionRecordMembership) == 3
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 1
        result = catalog_evidence_for_package(
            session, ecosystem="npm", name="accounting-package", version="1.0.0"
        )
        assert result.families[0].evaluations == (True,)
        record = session.scalar(select(CollectionRecordOutcome))
        assert record.document["omissions"] == {"unsupported_ecosystem": 1}
    assert any(
        b"untyped-public-package" in store.read_bytes(blob.digest) for blob in store.manifest()
    )


@pytest.mark.audit_ids("COL-06")
def test_known_quarantine_invalidates_cache_and_only_named_repair_resolves_it(database, tmp_path):
    current = [advisory()]
    instance, store = collector(tmp_path, lambda req: response(req, current))
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
    with Session(database.engine) as session:
        before = catalog_evidence_for_package(
            session, ecosystem="npm", name="accounting-package", version="1.0.0"
        )
        old_hashes = tuple(session.scalars(select(AdvisoryCatalogRecord.record_hash)))
        assert before.families[0].evaluations == (True,)
    current[0]["vulnerabilities"][0]["package"] = 123
    current[0]["updated_at"] = "2026-08-05T11:01:00Z"
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
        failed = session.scalar(
            select(CollectionRecordOutcome).where(
                CollectionRecordOutcome.disposition == "quarantined"
            )
        )
        failed_id, failed_hash = failed.outcome_id, failed.record_hash
    with Session(database.engine) as session:
        blocked = catalog_evidence_for_package(
            session, ecosystem="npm", name="accounting-package", version="1.0.0"
        )
        assert blocked.fingerprint != before.fingerprint
        assert blocked.families[0].evaluations == (None,)
        assert blocked.families[0].fixed_versions == ()
    current[0]["vulnerabilities"][0]["package"] = {"ecosystem": "npm", "name": "accounting-package"}
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 1
    for _ in range(2):
        with Session(database.engine) as session, session.begin():
            instance.backfill_advisory(
                session, advisory_id=current[0]["ghsa_id"], resolve_outcome_id=failed_id
            )
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 0
        assert count(session, CollectionRecordResolution) == 1
        assert session.get(CollectionRecordOutcome, failed_id).record_hash == failed_hash
        assert set(old_hashes) <= set(session.scalars(select(AdvisoryCatalogRecord.record_hash)))
        repaired = catalog_evidence_for_package(
            session, ecosystem="npm", name="accounting-package", version="1.0.0"
        )
        assert repaired.fingerprint != blocked.fingerprint
        assert repaired.families[0].evaluations == (True,)
    assert not store.pending_manifest()


@pytest.mark.audit_ids("COL-06")
def test_repair_is_not_resolution_until_replacement_evidence_finalizes(
    database, tmp_path, monkeypatch
):
    current = [advisory()]
    current[0]["vulnerabilities"][0]["package"] = 123
    instance, store = collector(tmp_path, lambda req: response(req, current))
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
        failed_id = session.scalar(select(CollectionRecordOutcome.outcome_id))
    current[0]["vulnerabilities"][0]["package"] = {"ecosystem": "npm", "name": "accounting-package"}

    def fail(_stage):
        raise OSError("synthetic finalization failure")

    monkeypatch.setattr(store, "finalize_stage", fail)
    with Session(database.engine) as session:
        with session.begin():
            instance.backfill_advisory(
                session, advisory_id=current[0]["ghsa_id"], resolve_outcome_id=failed_id
            )
        with pytest.raises(EvidenceFinalizationError):
            require_finalized(session)
    with Session(database.engine) as session:
        assert count(session, CollectionRecordResolution) == 1
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 1
        assert session.scalar(select(EvidenceFinalizationRecord.state)) == "failed"


@pytest.mark.parametrize("initial_read", ["backfill", "historical"])
def test_fresh_replay_repairs_new_undated_failure_using_existing_accepted_bytes(
    database, tmp_path, initial_read
):
    good = advisory()
    current = [deepcopy(good)]
    instance, store = collector(tmp_path, lambda req: response(req, current))
    with Session(database.engine) as session, session.begin():
        if initial_read == "backfill":
            instance.backfill_advisory(session, advisory_id=good["ghsa_id"])
        else:
            instance.run(session, lane="historical")
        accepted_id = session.scalar(select(CollectionRecordOutcome.outcome_id))
    current[0]["updated_at"] = None
    instance._clock = lambda: NOW + timedelta(minutes=1)
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
        failure = session.scalar(
            select(CollectionRecordOutcome).where(
                CollectionRecordOutcome.disposition == "quarantined"
            )
        )
        assert failure.document["source_updated_at"] is None
        failed_id = failure.outcome_id
        progress_count = count(session, CollectorProgressRecord)
    current[:] = [good]
    instance._clock = lambda: NOW + timedelta(minutes=2)
    with Session(database.engine) as session:
        with session.begin():
            instance.backfill_advisory(
                session, advisory_id=good["ghsa_id"], resolve_outcome_id=failed_id
            )
        require_finalized(session)
    with Session(database.engine) as session:
        resolution = session.get(CollectionRecordResolution, failed_id)
        replacement = session.get(CollectionRecordOutcome, resolution.replacement_id)
        proof = session.get(CollectionRecordMembership, resolution.membership_id)
        assert proof.acquisition_kind == "replay" and proof.progress_event_id is None
        assert proof.observed_at == NOW + timedelta(minutes=2)
        assert count(session, CollectorProgressRecord) == progress_count
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 0
        if initial_read == "backfill":
            assert replacement.outcome_id == accepted_id and replacement.observed_at == NOW
        else:
            finalization = session.scalar(
                select(EvidenceFinalizationRecord).where(
                    EvidenceFinalizationRecord.digest
                    == replacement.document["governed_input_sha256"]
                )
            )
            assert finalization.state == "finalized"
            assert replacement.outcome_id != accepted_id
            assert count(session, EvidenceFinalizationRecord) == 1
    assert not store.pending_manifest()


def test_page_membership_failure_rolls_back_cursor_outcomes_and_owned_stages(
    database, tmp_path, monkeypatch
):
    import smithguard.collectors as module

    instance, store = collector(tmp_path, lambda req: response(req, [advisory()]))

    def fail(*args, **kwargs):
        raise RecordAccountingError("synthetic membership failure")

    monkeypatch.setattr(module, "append_page_membership", fail)
    with Session(database.engine) as session, session.begin():
        with pytest.raises(RecordAccountingError):
            instance.run(session, lane="updates")
        assert session.scalar(select(1)) == 1
    with Session(database.engine) as session:
        for model in (
            CollectorProgressRecord,
            CollectionRecordOutcome,
            CollectionRecordMembership,
            IngestionBatchRecord,
            AdvisoryCatalogRecord,
        ):
            assert count(session, model) == 0
    assert not store.manifest() and not store.pending_manifest()


@pytest.mark.parametrize("first_is_bad", [False, True])
@pytest.mark.parametrize("fault", ["rights", "deadline"])
def test_later_record_failure_rolls_back_whole_page_before_failed_progress(
    database, tmp_path, monkeypatch, first_is_bad, fault
):
    from smithguard.acquisition import AcquisitionRejected
    from smithguard.ingestion import IngestionSourceError

    first = advisory()
    if first_is_bad:
        first["published_at"] = "invalid"
    instance, store = collector(
        tmp_path, lambda req: response(req, [first, advisory("cfgj", "later-record")])
    )
    original = instance._ingest_advisory
    errors = {
        "rights": IngestionSourceError,
        "deadline": AcquisitionRejected,
    }

    def fail_second(session, *, advisory, **kwargs):
        if advisory["ghsa_id"].endswith("cfgj"):
            raise errors[fault]("synthetic later-record refusal")
        return original(session, advisory=advisory, **kwargs)

    monkeypatch.setattr(instance, "_ingest_advisory", fail_second)
    with Session(database.engine) as session, session.begin():
        result = instance.run(session, lane="updates")
        assert result.state == "failed" and not result.page_processed
        assert result.collections == ()
    with Session(database.engine) as session:
        for model in (
            CollectionRecordOutcome,
            CollectionRecordMembership,
            IngestionBatchRecord,
            AdvisoryCatalogRecord,
            EvidenceFinalizationRecord,
        ):
            assert count(session, model) == 0
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress.state == "failed" and progress.source_record_count == 0
        assert progress.cursor_value is None
    assert not store.manifest() and not store.pending_manifest()


def test_caught_repair_failure_does_not_commit_partial_replacement(database, tmp_path, monkeypatch):
    import smithguard.collectors as module

    current = [advisory()]
    current[0]["published_at"] = "invalid"
    instance, store = collector(tmp_path, lambda req: response(req, current))
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
        failed_id = session.scalar(select(CollectionRecordOutcome.outcome_id))
    current[:] = [advisory()]

    def refuse(*args, **kwargs):
        raise RecordAccountingError("synthetic resolution refusal")

    monkeypatch.setattr(module, "append_resolution", refuse)
    with Session(database.engine) as session, session.begin():
        with pytest.raises(RecordAccountingError):
            instance.backfill_advisory(
                session, advisory_id=current[0]["ghsa_id"], resolve_outcome_id=failed_id
            )
        assert session.scalar(select(1)) == 1
    with Session(database.engine) as session:
        assert count(session, CollectionRecordOutcome) == 1
        assert count(session, CollectionRecordMembership) == 1
        assert count(session, IngestionBatchRecord) == 1
        assert count(session, AdvisoryCatalogRecord) == 0
        assert count(session, CollectionRecordResolution) == 0
    assert not store.manifest() and not store.pending_manifest()


def test_resolved_bad_input_can_recur_with_real_ingestion_retry(database, tmp_path):

    bad = advisory()
    bad["published_at"] = "invalid"
    current = [bad]
    instance, _store = collector(tmp_path, lambda req: response(req, current))
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
        first = session.scalar(select(CollectionRecordOutcome))
        first_id = first.outcome_id
    current[:] = [advisory()]
    instance._clock = lambda: NOW + timedelta(minutes=1)
    with Session(database.engine) as session, session.begin():
        instance.backfill_advisory(
            session, advisory_id=current[0]["ghsa_id"], resolve_outcome_id=first_id
        )
    current[:] = [bad]
    for minute in (2, 3):
        instance._clock = lambda minute=minute: NOW + timedelta(minutes=minute)
        with Session(database.engine) as session, session.begin():
            instance.run(session, lane="updates")
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 1
        bad_rows = tuple(
            session.scalars(
                select(CollectionRecordOutcome).where(
                    CollectionRecordOutcome.disposition == "quarantined"
                )
            )
        )
        assert len(bad_rows) == 2
        recurrence = next(row for row in bad_rows if row.outcome_id != first_id)
        assert recurrence.document["recurrence_of"] == first_id
        assert recurrence.document["occurrence"] == 1
        recurrence_id = recurrence.outcome_id
        assert actionable_quarantine_count(session, source_id=GITHUB_ADVISORY) == 1
    current[:] = [advisory()]
    instance._clock = lambda: NOW + timedelta(minutes=4)
    with Session(database.engine) as session, session.begin():
        instance.backfill_advisory(
            session, advisory_id=current[0]["ghsa_id"], resolve_outcome_id=recurrence_id
        )
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 0
        assert count(session, CollectionRecordResolution) == 2


def test_type_transition_keeps_old_gap_without_withholding_current_segment(database, tmp_path):
    current = [advisory()]
    current[0]["type"] = "unreviewed"
    current[0]["published_at"] = "invalid"
    old, _store = collector(
        tmp_path, lambda req: response(req, current), advisory_type="unreviewed"
    )
    with Session(database.engine) as session, session.begin():
        old.run(session, lane="updates")
        assert actionable_quarantine_count(session, source_id=GITHUB_ADVISORY) == 1
    current[:] = [advisory()]
    reviewed, _store = collector(tmp_path, lambda req: response(req, current))
    reviewed._clock = lambda: NOW + timedelta(minutes=1)
    with Session(database.engine) as session, session.begin():
        reviewed.run(session, lane="updates")
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="unreviewed") == 1
        assert actionable_quarantine_count(session, source_id=GITHUB_ADVISORY) == 0
        assert count(session, CollectionRecordResolution) == 0
        packet = catalog_evidence_for_package(
            session, ecosystem="npm", name="accounting-package", version="1.0.0"
        )
        assert packet.families[0].evaluations == (True,)


@pytest.mark.parametrize("failure", ["missing", "wrong_id", "unchanged", "older"])
def test_exact_repair_rejects_unproven_resolution(database, tmp_path, failure):
    current = [advisory()]
    current[0]["vulnerabilities"].append({"package": None, "vulnerable_version_range": None})
    instance, _store = collector(tmp_path, lambda req: response(req, current))
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
        outcome_id = session.scalar(select(CollectionRecordOutcome.outcome_id))
    if failure == "missing":
        current.clear()
    elif failure == "wrong_id":
        current[0]["ghsa_id"] = "GHSA-2345-6789-cfgj"
    elif failure == "older":
        current[0]["vulnerabilities"].pop()
        current[0]["updated_at"] = "2026-08-05T10:00:00Z"
    with (
        pytest.raises((CollectorBoundaryError, RecordAccountingError, AdvisoryCatalogError)),
        Session(database.engine) as session,
        session.begin(),
    ):
        instance.backfill_advisory(
            session, advisory_id="GHSA-2345-6789-cfgh", resolve_outcome_id=outcome_id
        )
    with Session(database.engine) as session:
        assert count(session, CollectionRecordResolution) == 0
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 1


def test_opaque_identity_is_not_matched_to_a_later_known_record(database, tmp_path):
    current = [{"ghsa_id": None, "description": "do not retain"}]
    instance, _store = collector(tmp_path, lambda req: response(req, current))
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
        row = session.scalar(select(CollectionRecordOutcome))
        assert row.record_key.startswith("opaque:")
        outcome_id = row.outcome_id
    current[:] = [advisory()]
    with pytest.raises(RecordAccountingError), Session(database.engine) as session, session.begin():
        instance.backfill_advisory(
            session, advisory_id=current[0]["ghsa_id"], resolve_outcome_id=outcome_id
        )


def test_accounting_tables_reject_update_delete_and_truncate(database, tmp_path):
    instance, _store = collector(tmp_path, lambda req: response(req, [advisory()]))
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
    for table in (
        "collection_record_outcomes",
        "collection_record_memberships",
        "collection_record_resolutions",
    ):
        for statement in (
            f"UPDATE smithguard.{table} SET record_hash = record_hash",
            f"DELETE FROM smithguard.{table}",
            f"TRUNCATE TABLE smithguard.{table} CASCADE",
        ):
            # UPDATE/DELETE row triggers need a row; resolution immutability is also
            # checked by metadata trigger parity and the populated repair test.
            if table.endswith("resolutions") and not statement.startswith("TRUNCATE"):
                continue
            with (
                pytest.raises(DBAPIError, match="append-only"),
                database.engine.begin() as connection,
            ):
                connection.execute(text(statement))


def test_historical_bad_record_does_not_mint_a_complete_manifest(database, tmp_path):
    bad = deepcopy(advisory())
    bad.pop("published_at")
    instance, _store = collector(tmp_path, lambda req: response(req, [bad, advisory("cfgj")]))
    with Session(database.engine) as session, session.begin():
        result = instance.run(session, lane="historical")
        assert result.state == "failed" and result.page_processed
        assert count(session, CollectionRecordMembership) == 2
        assert count(session, AdvisoryCatalogManifestRecord) == 0


def test_gap_listing_is_read_only_bounded_and_resumable(database, tmp_path, monkeypatch, capsys):
    import json

    from smithguard import reconciliation_runtime as runtime

    values = [advisory(), advisory("cfgj")]
    for value in values:
        value.pop("published_at")
    instance, _store = collector(tmp_path, lambda req: response(req, values))
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
    monkeypatch.setattr(runtime, "load_runtime_config", lambda: object())
    monkeypatch.setattr(runtime, "_engine", lambda _config: database.engine)
    args = ["github-record-gaps", "--catalog-segment", "reviewed", "--limit", "1"]
    assert runtime.main(args) == 0
    first = json.loads(capsys.readouterr().out)
    assert len(first["outcomes"]) == 1 and first["next_outcome_id"]
    assert runtime.main([*args, "--after-outcome-id", first["next_outcome_id"]]) == 0
    second = json.loads(capsys.readouterr().out)
    assert len(second["outcomes"]) == 1 and second["next_outcome_id"] is None
    assert first["outcomes"][0]["outcome_id"] != second["outcomes"][0]["outcome_id"]
    assert (
        runtime.main(["github-record-gaps", "--catalog-segment", "reviewed", "--limit", "101"]) == 2
    )
    with Session(database.engine) as session:
        assert count(session, CollectionRecordOutcome) == 2
        assert count(session, CollectionRecordResolution) == 0


def test_concurrent_named_repair_converges_without_duplicate_resolution(database, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    current = [advisory()]
    current[0]["vulnerabilities"][0]["package"] = 123
    instance, store = collector(tmp_path, lambda req: response(req, current))
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
        target = session.scalar(select(CollectionRecordOutcome.outcome_id))
    current[0]["vulnerabilities"][0]["package"] = {"ecosystem": "npm", "name": "accounting-package"}
    barrier = Barrier(2)

    def repair():
        barrier.wait(timeout=10)
        with Session(database.engine) as session, session.begin():
            return instance.backfill_advisory(
                session, advisory_id=current[0]["ghsa_id"], resolve_outcome_id=target
            ).collection.outcome.batch_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _index: repair(), range(2)))
    assert len(set(results)) == 1
    with Session(database.engine) as session:
        assert count(session, CollectionRecordResolution) == 1
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 0
    assert not store.pending_manifest()


def test_rights_failure_does_not_become_an_accounted_skip(database, tmp_path, monkeypatch):
    from smithguard.ingestion import IngestionSourceError

    instance, store = collector(tmp_path, lambda req: response(req, [advisory()]))

    def reject(*args, **kwargs):
        raise IngestionSourceError("synthetic policy refusal")

    monkeypatch.setattr(instance, "_ingest_advisory", reject)
    with Session(database.engine) as session, session.begin():
        result = instance.run(session, lane="updates")
        assert not result.page_processed and result.state == "failed"
        assert count(session, CollectionRecordOutcome) == 0
        assert count(session, CollectionRecordMembership) == 0
    assert not store.manifest() and not store.pending_manifest()


def test_record_rights_refusal_without_outcome_retains_failed_diagnostic(
    database, tmp_path, monkeypatch
):
    from types import SimpleNamespace

    from smithguard.collectors import CollectorRunner

    instance, store = collector(tmp_path, lambda req: response(req, [advisory()]))
    monkeypatch.setattr(
        CollectorRunner, "run_public", lambda *args, **kwargs: SimpleNamespace(outcome=None)
    )
    with Session(database.engine) as session, session.begin():
        result = instance.run(session, lane="updates")
        assert result.state == "failed" and result.collections == ()
        assert result.reason_code == "github_source_governance_rejected"
    with Session(database.engine) as session:
        assert session.scalar(select(CollectorProgressRecord.reason_code)) == result.reason_code
        assert count(session, CollectionRecordOutcome) == 0
    assert not store.manifest() and not store.pending_manifest()


def test_older_collected_revision_is_quarantined_without_replacing_current_record(
    database, tmp_path
):
    current = [advisory()]
    instance, _store = collector(tmp_path, lambda req: response(req, current))
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
    current[0]["updated_at"] = "2026-08-05T10:00:00Z"
    with Session(database.engine) as session, session.begin():
        result = instance.run(session, lane="updates")
        assert result.page_processed and result.state == "complete"
        assert count(session, AdvisoryCatalogRecord) == 1
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 1
        prior = session.scalar(
            select(CollectionRecordOutcome).where(
                CollectionRecordOutcome.disposition == "quarantined"
            )
        )
        prior_id = prior.outcome_id
        assert prior.document["quarantine_reasons"] == ["github_advisory_stale_revision"]
        assert catalog_evidence_for_package(
            session, ecosystem="npm", name="accounting-package", version="1.0.0"
        ).families[0].evaluations == (None,)
    current[:] = [advisory()]
    instance._clock = lambda: NOW + timedelta(minutes=1)
    with Session(database.engine) as session, session.begin():
        instance.backfill_advisory(
            session, advisory_id=current[0]["ghsa_id"], resolve_outcome_id=prior_id
        )
        assert count(session, AdvisoryCatalogRecord) == 1
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 0


def test_coverage_gap_queries_can_use_partial_indexes(database, tmp_path):
    from sqlalchemy import event

    current = [advisory()]
    instance, _store = collector(tmp_path, lambda req: response(req, current))
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
    current[0]["vulnerabilities"][0]["package"] = 123
    with Session(database.engine) as session, session.begin():
        instance.run(session, lane="updates")
    queries = []

    def capture(_conn, _cursor, statement, parameters, _context, _many):
        if statement.startswith(("SELECT", "WITH")):
            queries.append((statement, parameters))

    event.listen(database.engine, "before_cursor_execute", capture)
    try:
        with Session(database.engine) as session:
            unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed")
            catalog_evidence_for_package(
                session, ecosystem="npm", name="accounting-package", version="1.0.0"
            )
    finally:
        event.remove(database.engine, "before_cursor_execute", capture)
    assert len(queries) == 2
    with database.engine.begin() as connection:
        connection.execute(text("SET LOCAL enable_seqscan = off"))
        for (query, parameters), expected in zip(
            queries,
            ("ix_collection_outcomes_case", "ix_collection_outcomes_quarantine"),
            strict=True,
        ):
            plan = connection.exec_driver_sql(
                "EXPLAIN (FORMAT JSON) " + query, parameters
            ).scalar_one()
            assert expected in str(plan)


def test_three_bad_reads_reuse_one_open_outcome_per_governance_lane(database, tmp_path):
    bad = advisory()
    bad["published_at"] = "invalid"
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        headers = {"content-type": "application/json"}
        if calls % 3 != 0:
            headers["link"] = (
                f'<{request.url.copy_set_param("after", f"page{calls + 1}")}>; rel="next"'
            )
        return httpx.Response(200, headers=headers, json=[bad], request=request)

    instance, _store = collector(tmp_path, handler)
    for lane in ("updates", "historical"):
        for minute in range(3):
            instance._clock = lambda minute=minute: NOW + timedelta(minutes=minute)
            with Session(database.engine) as session, session.begin():
                assert instance.run(session, lane=lane).page_processed
    with Session(database.engine) as session:
        assert count(session, CollectionRecordOutcome) == 2
        assert count(session, CollectionRecordMembership) == 6
        assert count(session, IngestionBatchRecord) == 4
        outcomes = tuple(session.scalars(select(CollectionRecordOutcome)))
        assert {row.document["acquisition_lane"] for row in outcomes} == {"historical", "updates"}
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 1


def test_update_omission_does_not_rewrite_completed_historical_display(database, tmp_path):
    from smithguard.coverage import _source_lane

    current = [advisory()]
    instance, _store = collector(tmp_path, lambda req: response(req, current))

    def lane(session):
        return _source_lane(
            session,
            source_id=GITHUB_ADVISORY,
            lane="historical",
            record_type="reviewed",
            segment="reviewed",
            measured_at=NOW + timedelta(minutes=1),
        )

    with Session(database.engine) as session, session.begin():
        assert instance.run(session, lane="historical").state == "complete"
        before = lane(session)
        assert before.state == "complete" and before.freshness_state == "complete"
        manifests = tuple(session.scalars(select(AdvisoryCatalogManifestRecord.record_hash)))
    current[0]["vulnerabilities"][0]["package"] = None
    current[0]["updated_at"] = "2026-08-05T11:01:00Z"
    with Session(database.engine) as session, session.begin():
        assert instance.run(session, lane="updates").page_processed
        after = lane(session)
        assert after.state == before.state and after.freshness_state == before.freshness_state
        assert after.page_count == before.page_count
        assert "unresolved collection omissions" in str(after.unknowns)
        assert (
            tuple(session.scalars(select(AdvisoryCatalogManifestRecord.record_hash))) == manifests
        )
