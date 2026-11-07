"""Synthetic pinned trees prove partial non-success and source-wide read barriers."""

from datetime import timedelta
from time import perf_counter

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from smithguard import openssf_catalog, openssf_resilience
from smithguard.advisory_catalog import OPENSSF_SOURCE_ID, catalog_evidence_for_package
from smithguard.catalog_health import write_catalog_health
from smithguard.collection_records import actionable_quarantine_count, unresolved_count
from smithguard.coverage import refresh_coverage_report
from smithguard.db.models import (
    AdvisoryCatalogManifestRecord,
    AdvisoryCatalogRecord,
    CollectionRecordMembership,
    CollectionRecordOutcome,
    CollectionRecordResolution,
    OpenSSFCatalogAttempt,
)
from smithguard.identifiers import strict_json_loads
from smithguard.service import SmithGuardService
from tests.fixture_clock import FIXTURE_NOW
from tests.test_catalog_health import receipt_boundary  # noqa: F401
from tests.test_openssf_catalog_validation import catalog_runner  # noqa: F401
from tests.test_openssf_git import _commit, _record, _write_record


@pytest.fixture
def resilience_runner(request, monkeypatch):
    monkeypatch.setattr(openssf_catalog, "partial_writes_enabled", lambda: True)
    return request.getfixturevalue("catalog_runner")


def set_tree(monkeypatch, document, *, withdrawn_tree=False):
    repository = openssf_catalog._state_root().parent / "openssf"
    for existing in repository.glob("osv/*/npm/example/MAL-2026-100.json"):
        existing.unlink()
    tree = "withdrawn" if withdrawn_tree else "malicious"
    _write_record(repository, f"osv/{tree}/npm/example/MAL-2026-100.json", document)
    commit = _commit(repository, "synthetic state transition")
    monkeypatch.setattr(openssf_catalog, "sync_official_repository", lambda _: (repository, commit))
    monkeypatch.setattr(openssf_catalog, "BOOTSTRAP_COMMIT", commit)
    return repository, commit


def bad_record(*, withdrawn=True):
    return _record("MAL-2026-100", ecosystem="npm", name="example", withdrawn=withdrawn)


def scalar_count(session, model):
    return session.scalar(select(func.count()).select_from(model))


@pytest.mark.parametrize("prior_withdrawn", [False, True])
def test_partial_preserves_complete_clock_and_suppresses_prior_active_or_withdrawn(
    database,
    resilience_runner,
    monkeypatch,
    prior_withdrawn,
):
    if prior_withdrawn:
        set_tree(monkeypatch, bad_record(withdrawn=True), withdrawn_tree=True)
    assert resilience_runner()["status"] == "complete"
    marker = (openssf_catalog._state_root() / "verification.json").read_bytes()
    with Session(database.engine) as session:
        before = [row.manifest_event_id for row in openssf_catalog._latest_complete_pair(session)]
        service = SmithGuardService(clock=lambda: FIXTURE_NOW)
        refresh_coverage_report(
            session,
            measured_at=FIXTURE_NOW,
            live_collector_uptime="not_measured_public_beta_collector",
            evidence_label="public",
        )
    doc = bad_record(withdrawn=not prior_withdrawn)
    # A contradictory revival can list new versions: no rejected field is ingested.
    doc["affected"][0]["versions"].append("99.0.0")
    repository, commit = set_tree(monkeypatch, doc, withdrawn_tree=not prior_withdrawn)
    # Set body/path mismatch: active -> body withdrawn; withdrawn -> body active.
    set_tree(monkeypatch, doc, withdrawn_tree=prior_withdrawn)
    with pytest.raises(openssf_catalog.OpenSSFCatalogPartial) as partial:
        resilience_runner()
    assert partial.value.result["accepted_record_count"] == 2
    assert partial.value.result["rejected_record_count"] == 1
    assert (openssf_catalog._state_root() / "verification.json").read_bytes() == marker
    with Session(database.engine) as session:
        assert [
            row.manifest_event_id for row in openssf_catalog._latest_complete_pair(session)
        ] == before
        assert unresolved_count(session, source_id=OPENSSF_SOURCE_ID) == 1
        assert actionable_quarantine_count(session, source_id=OPENSSF_SOURCE_ID) == 1
        receipt = session.scalar(
            select(OpenSSFCatalogAttempt).where(OpenSSFCatalogAttempt.state == "partial")
        )
        assert receipt.document["scanned_count"] == 3
        assert receipt.document["accepted_count"] == 2
        assert receipt.document["rejections"][0]["reason"] == "openssf_tree_withdrawal_mismatch"
        assert scalar_count(session, AdvisoryCatalogRecord) == 3
        local = catalog_evidence_for_package(
            session, ecosystem="npm", name="example", version="99.0.0"
        )
        assert local.openssf_unresolved_count == 1 and len(local.families) == 1
        report = local.families[0].source_reports[0]
        assert report["source_state_status"] == "historical_unresolved"
        assert report["applies_to_version"] is None and report["fixed_versions"] == []
        assert local.families[0].matched_range_ids == ()
        for ecosystem, name, version in [
            ("npm", "example", "99.0.0"),
            ("pypi", "unmapped", "1.0.0"),
            ("npm", "renamed", "1.0.0"),
        ]:
            answer = service.assess_public_artifact(
                session, {"ecosystem": ecosystem, "name": name, "version": version}
            )
            freshness = next(
                item
                for item in answer["source_freshness"]
                if item["source_id"] == OPENSSF_SOURCE_ID
            )
            assert freshness["freshness_state"] == "unresolved"
            assert freshness["unresolved_record_count"] == 1
            assert "source_unavailable" in answer["reason_codes"]
    # Same pinned bad bytes are re-read, cases deduplicate, attempts stay distinct.
    with pytest.raises(openssf_catalog.OpenSSFCatalogPartial):
        resilience_runner()
    with Session(database.engine) as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(CollectionRecordOutcome)
                .where(CollectionRecordOutcome.disposition == "quarantined")
            )
            == 1
        )
        assert scalar_count(session, OpenSSFCatalogAttempt) == 3


def test_valid_siblings_advance_after_durable_barrier_and_exact_repair(
    database, resilience_runner, monkeypatch
):
    resilience_runner()
    original_doc = strict_json_loads(
        (
            openssf_catalog._state_root().parent
            / "openssf/osv/malicious/npm/example/MAL-2026-100.json"
        ).read_text()
    )
    set_tree(monkeypatch, bad_record())
    repository = openssf_catalog._state_root().parent / "openssf"
    for identity, name in [("MAL-2026-103", "aaa"), ("MAL-2026-104", "zzz")]:
        _write_record(
            repository,
            f"osv/malicious/npm/{name}/{identity}.json",
            _record(identity, ecosystem="npm", name=name),
        )
    commit = _commit(repository, "valid A bad B valid C")
    monkeypatch.setattr(openssf_catalog, "sync_official_repository", lambda _: (repository, commit))
    original_append = openssf_catalog.append_openssf_advisory
    observed = []

    def append_after_barrier(session, **kwargs):
        with Session(database.engine) as reader:
            assert unresolved_count(reader, source_id=OPENSSF_SOURCE_ID) == 1
        observed.append(kwargs["document"]["id"])
        return original_append(session, **kwargs)

    monkeypatch.setattr(openssf_catalog, "append_openssf_advisory", append_after_barrier)
    with pytest.raises(openssf_catalog.OpenSSFCatalogPartial):
        resilience_runner()
    assert observed == ["MAL-2026-103", "MAL-2026-104"]
    with Session(database.engine) as session:
        service = SmithGuardService(clock=lambda: FIXTURE_NOW)
        positive = service.assess_public_artifact(
            session, {"ecosystem": "npm", "name": "aaa", "version": "1.0.0"}
        )
        negative = service.assess_public_artifact(
            session, {"ecosystem": "npm", "name": "aaa", "version": "2.0.0"}
        )
        assert positive["result"] == "affected"
        assert negative["result"] == "unknown"
        assert all(
            report["source_state_status"] == "current"
            for incident in positive["incidents"]
            for report in incident["source_reports"]
        )
    monkeypatch.setattr(openssf_catalog, "append_openssf_advisory", original_append)
    # Exact old accepted bytes are valid again; fresh governed acceptance resolves
    # the named gap despite no new advisory revision being necessary.
    set_tree(monkeypatch, original_doc)
    result = resilience_runner()
    assert result["status"] == "complete" and result["created_revision_count"] == 0
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=OPENSSF_SOURCE_ID) == 0
        assert scalar_count(session, CollectionRecordResolution) == 1
        assert len(openssf_catalog._latest_complete_pair(session)) == 2
        assert (
            catalog_evidence_for_package(session, ecosystem="npm", name="example", version="1.0.0")
            .families[0]
            .applies
            is True
        )


def test_cross_tree_move_of_identical_blob_resolves_only_with_fresh_acceptance(
    database, resilience_runner, monkeypatch
):
    set_tree(monkeypatch, bad_record())
    with pytest.raises(openssf_catalog.OpenSSFCatalogPartial):
        resilience_runner()
    set_tree(monkeypatch, bad_record(), withdrawn_tree=True)
    assert resilience_runner()["status"] == "complete"
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=OPENSSF_SOURCE_ID) == 0
        assert scalar_count(session, CollectionRecordResolution) == 1


@pytest.mark.parametrize("rejects", [10, 11])
def test_rejection_cap_never_publishes_truncated_partition(
    database, resilience_runner, monkeypatch, rejects
):
    repository = openssf_catalog._state_root().parent / "openssf"
    for number in range(rejects):
        identity = f"MAL-2026-{200 + number}"
        _write_record(
            repository,
            f"osv/malicious/npm/bad-{number}/{identity}.json",
            _record(identity, ecosystem="npm", name=f"bad-{number}", withdrawn=True),
        )
    commit = _commit(repository, "bounded rejection set")
    monkeypatch.setattr(openssf_catalog, "sync_official_repository", lambda _: (repository, commit))
    monkeypatch.setattr(openssf_catalog, "BOOTSTRAP_COMMIT", commit)
    with pytest.raises(
        openssf_catalog.OpenSSFCatalogPartial
        if rejects == 10
        else openssf_resilience.OpenSSFResilienceError
    ):
        resilience_runner()
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=OPENSSF_SOURCE_ID) == 10
        receipts = session.scalars(select(OpenSSFCatalogAttempt)).all()
        assert [row.state for row in receipts] == (["partial"] if rejects == 10 else ["failed"])
        assert len(receipts[0].document["rejections"]) == 10
        assert scalar_count(session, AdvisoryCatalogRecord) == (3 if rejects == 10 else 0)
        assert not openssf_catalog._latest_complete_pair(session)


@pytest.mark.parametrize("fault", ["malformed_json", "aliases", "source_time"])
def test_other_shape_failures_remain_whole_attempt_failures(
    database, resilience_runner, monkeypatch, fault
):
    doc = bad_record()
    if fault == "aliases":
        doc["aliases"] = [None]
    if fault == "source_time":
        doc["modified"] = "invalid"
    repository, commit = set_tree(monkeypatch, doc)
    if fault == "malformed_json":
        (repository / "osv/malicious/npm/example/MAL-2026-100.json").write_bytes(b'{"id":')
        commit = _commit(repository, "broken JSON")
        monkeypatch.setattr(
            openssf_catalog, "sync_official_repository", lambda _: (repository, commit)
        )
        monkeypatch.setattr(openssf_catalog, "BOOTSTRAP_COMMIT", commit)
    with pytest.raises(Exception) as raised:
        resilience_runner()
    assert not isinstance(raised.value, openssf_catalog.OpenSSFCatalogPartial)
    with Session(database.engine) as session:
        assert scalar_count(session, AdvisoryCatalogRecord) == 0
        assert scalar_count(session, CollectionRecordOutcome) == 0
        assert not openssf_catalog._latest_complete_pair(session)


@pytest.mark.parametrize("minutes", [1, 180])
def test_partial_health_stays_failed_before_or_after_complete_expiry(receipt_boundary, minutes):  # noqa: F811
    path, root, pair = receipt_boundary
    for row in pair:
        row.observed_at -= timedelta(minutes=minutes)
    receipt = write_catalog_health(
        path,
        state_root=root,
        complete_pair=pair,
        attempt={
            "commit": "b" * 40,
            "unresolved_record_count": 1,
            "accepted_progress_count": 2,
            "rejected_count": 1,
        },
        succeeded=False,
        started=perf_counter(),
    )
    assert receipt["schema_version"] == "3.0.0"
    assert receipt["status"] == "failure" and not receipt["healthy"]
    assert receipt["last_success_commit"] == "a" * 40
    assert receipt["accepted_progress_count"] == 2


def test_attempt_table_is_append_only(database, resilience_runner):
    resilience_runner()
    for mutation in [
        "UPDATE smithguard.openssf_catalog_attempts SET state = 'failed'",
        "DELETE FROM smithguard.openssf_catalog_attempts",
        "TRUNCATE smithguard.openssf_catalog_attempts",
    ]:
        with Session(database.engine) as session, session.begin(), pytest.raises(DBAPIError):
            session.execute(text(mutation))


def test_default_partial_writer_is_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(openssf_resilience, "CONTROL_PATH", tmp_path / "missing.json")
    assert not openssf_resilience.partial_writes_enabled()


@pytest.mark.parametrize(
    "fault", [None, "fallback_bytes", "missing_reader", "wrong_active", "writable_parent"]
)
def test_partial_writer_requires_bound_compatible_installed_fallback(tmp_path, monkeypatch, fault):
    import os

    from smithguard.identifiers import canonical_json_bytes, sha256_id

    root = tmp_path / "releases"
    root.mkdir()
    active, fallback = "a" * 40, "b" * 40
    content = b"synthetic identical installed reader\n"
    for release in (active, fallback):
        package = root / release / "app/.venv/lib/python3.12/site-packages/smithguard"
        package.mkdir(parents=True)
        for filename in openssf_resilience.READER_FILES:
            path = package / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o644)
    control = tmp_path / "control.json"
    document = {
        "schema_version": "1.0.0",
        "reader_protocol": openssf_resilience.READER_PROTOCOL,
        "active_release": active,
        "fallback_release": fallback,
        "readers": {filename: sha256_id(content) for filename in openssf_resilience.READER_FILES},
    }
    fallback_package = root / fallback / "app/.venv/lib/python3.12/site-packages/smithguard"
    if fault == "fallback_bytes":
        (fallback_package / "service.py").write_bytes(b"unaware predecessor")
    if fault == "missing_reader":
        (fallback_package / "service.py").unlink()
    if fault == "wrong_active":
        document["active_release"] = "c" * 40
    if fault == "writable_parent":
        (fallback_package / "db").chmod(0o777)
    control.write_bytes(canonical_json_bytes(document))
    control.chmod(0o644)
    monkeypatch.setattr(openssf_resilience, "CONTROL_PATH", control)
    monkeypatch.setattr(openssf_resilience, "RELEASE_ROOT", root)
    monkeypatch.setattr(openssf_resilience, "ROOT_UID", os.geteuid())
    monkeypatch.setattr(openssf_resilience, "_running_release", lambda: active)
    if fault:
        with pytest.raises((openssf_resilience.OpenSSFResilienceError, OSError)):
            openssf_resilience.partial_writes_enabled()
    else:
        assert openssf_resilience.partial_writes_enabled()


@pytest.mark.parametrize("boundary", ["accepted_append", "finalization", "terminal_receipt"])
def test_interrupted_progress_never_clears_rejection_or_renews_complete_proof(
    database, resilience_runner, monkeypatch, boundary
):
    resilience_runner()
    marker = (openssf_catalog._state_root() / "verification.json").read_bytes()
    set_tree(monkeypatch, bad_record())
    repository = openssf_catalog._state_root().parent / "openssf"
    _write_record(
        repository,
        "osv/malicious/npm/aaa/MAL-2026-105.json",
        _record("MAL-2026-105", ecosystem="npm", name="aaa"),
    )
    commit = _commit(repository, "new accepted progress with rejection")
    monkeypatch.setattr(openssf_catalog, "sync_official_repository", lambda _: (repository, commit))

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic boundary crash")

    if boundary == "accepted_append":
        monkeypatch.setattr(openssf_catalog, "append_openssf_advisory", fail)
    elif boundary == "finalization":
        monkeypatch.setattr(openssf_catalog, "require_finalized", fail)
    else:
        original = openssf_catalog.append_attempt

        def fail_partial(session, **kwargs):
            if kwargs["state"] == "partial":
                fail()
            return original(session, **kwargs)

        monkeypatch.setattr(openssf_catalog, "append_attempt", fail_partial)
    with pytest.raises(RuntimeError, match="synthetic boundary crash"):
        resilience_runner()
    assert (openssf_catalog._state_root() / "verification.json").read_bytes() == marker
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=OPENSSF_SOURCE_ID) == 1
        assert scalar_count(session, CollectionRecordResolution) == 0
        assert (
            session.scalar(
                select(func.count())
                .select_from(OpenSSFCatalogAttempt)
                .where(OpenSSFCatalogAttempt.state == "partial")
            )
            == 0
        )
        failed = session.scalar(
            select(OpenSSFCatalogAttempt).where(OpenSSFCatalogAttempt.state == "failed")
        )
        assert len(failed.document["rejections"]) == 1
        assert "accepted_count" not in failed.document


def test_failed_repair_finalization_keeps_named_gap_open(database, resilience_runner, monkeypatch):
    from smithguard.evidence import LocalImmutableEvidenceStore
    from smithguard.evidence_finalization import EvidenceFinalizationError

    set_tree(monkeypatch, bad_record())
    with pytest.raises(openssf_catalog.OpenSSFCatalogPartial):
        resilience_runner()
    corrected = bad_record(withdrawn=False)
    corrected["modified"] = "2026-08-12T00:00:00Z"
    set_tree(monkeypatch, corrected)

    def fail(self, stage):
        raise OSError("synthetic finalization failure")

    monkeypatch.setattr(LocalImmutableEvidenceStore, "finalize_stage", fail)
    with pytest.raises(EvidenceFinalizationError):
        resilience_runner()
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=OPENSSF_SOURCE_ID) == 1
        assert scalar_count(session, CollectionRecordResolution) == 1
        assert not openssf_catalog._latest_complete_pair(session)
        report = (
            catalog_evidence_for_package(session, ecosystem="npm", name="example", version="1.0.0")
            .families[0]
            .source_reports[0]
        )
        assert report["source_state_status"] == "historical_unresolved"
        assert report["applies_to_version"] is None


def test_signed_api_cache_invalidates_on_new_global_gap_and_resolution(
    database, resilience_runner, monkeypatch
):
    from tests.test_service_api import _public_client

    resilience_runner()
    repository = openssf_catalog._state_root().parent / "openssf"
    original = strict_json_loads(
        (repository / "osv/malicious/npm/example/MAL-2026-100.json").read_text()
    )
    request = {"ecosystem": "npm", "name": "never-mapped", "version": "5.0.0"}
    with _public_client(database) as client:
        before = client.post("/v1/artifacts/assess", json=request).json()
        assert before["signature"]
        set_tree(monkeypatch, bad_record())
        with pytest.raises(openssf_catalog.OpenSSFCatalogPartial):
            resilience_runner()
        blocked = client.post("/v1/artifacts/assess", json=request).json()
        assert blocked["feed_revision"] != before["feed_revision"]
        assert blocked["signature"] != before["signature"]
        openssf = next(
            item for item in blocked["source_freshness"] if item["source_id"] == OPENSSF_SOURCE_ID
        )
        assert openssf["freshness_state"] == "unresolved"
        assert openssf["unresolved_record_count"] == 1
        set_tree(monkeypatch, original)
        resilience_runner()
        repaired = client.post("/v1/artifacts/assess", json=request).json()
        assert repaired["feed_revision"] != blocked["feed_revision"]
        openssf = next(
            item for item in repaired["source_freshness"] if item["source_id"] == OPENSSF_SOURCE_ID
        )
        assert openssf["freshness_state"] != "unresolved"


def test_source_wide_gap_and_package_catalog_use_one_statement_snapshot(
    database, resilience_runner, monkeypatch
):
    from sqlalchemy import event

    resilience_runner()
    set_tree(monkeypatch, bad_record())
    queries = []

    def on_query(_connection, _cursor, statement, _parameters, _context, _many):
        if "catalog_snapshot_anchor" in statement:
            queries.append(statement)
            # The commit happens after this reader starts its statement callback,
            # before PostgreSQL takes the statement's actual MVCC snapshot.
            with pytest.raises(openssf_catalog.OpenSSFCatalogPartial):
                resilience_runner()

    event.listen(database.engine, "before_cursor_execute", on_query)
    try:
        with Session(database.engine) as session:
            evidence = catalog_evidence_for_package(
                session, ecosystem="npm", name="example", version="1.0.0"
            )
    finally:
        event.remove(database.engine, "before_cursor_execute", on_query)
    assert len(queries) == 1
    assert evidence.openssf_unresolved_count == 1
    assert evidence.families[0].applies is None


def test_process_refuses_a_returned_partial_success(database, catalog_runner, monkeypatch, capsys):  # noqa: F811
    monkeypatch.setattr(openssf_catalog, "collect_openssf_catalog", lambda: {"status": "partial"})
    assert openssf_catalog.main() == 3
    assert "openssf_catalog_complete" not in capsys.readouterr().out


def test_disabling_writer_cannot_renew_complete_proof_over_unresolved_state(
    database, resilience_runner, monkeypatch
):
    resilience_runner()
    marker = (openssf_catalog._state_root() / "verification.json").read_bytes()
    set_tree(monkeypatch, bad_record())
    with pytest.raises(openssf_catalog.OpenSSFCatalogPartial):
        resilience_runner()
    set_tree(monkeypatch, bad_record(withdrawn=False))
    monkeypatch.setattr(openssf_catalog, "partial_writes_enabled", lambda: False)
    with pytest.raises(openssf_catalog.OpenSSFCatalogError, match="unresolved records prohibit"):
        resilience_runner()
    assert (openssf_catalog._state_root() / "verification.json").read_bytes() == marker
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=OPENSSF_SOURCE_ID) == 1


def test_genuine_partial_process_exits_nonzero_and_preserves_failed_attempt(
    database, resilience_runner, monkeypatch, capsys
):
    set_tree(monkeypatch, bad_record())
    assert openssf_catalog.main() == 3
    output = capsys.readouterr()
    assert "openssf_catalog_complete" not in output.out
    assert "openssf_catalog_partial" in output.err
    with Session(database.engine) as session:
        manifests = session.scalars(select(AdvisoryCatalogManifestRecord)).all()
        assert [row.state for row in manifests].count("failed") == 2
        assert [row.state for row in manifests].count("complete") == 0


def test_late_structural_failure_retains_early_barrier_without_accepted_progress(
    database, resilience_runner, monkeypatch
):
    set_tree(monkeypatch, bad_record())
    repository = openssf_catalog._state_root().parent / "openssf"
    # The bad npm entry is observed before this pypi entry. Even though other
    # valid entries precede it, strict preflight must prevent their ingestion.
    path = repository / "osv/malicious/pypi/example-project/MAL-2026-101.json"
    path.write_bytes(b'{"id":')
    commit = _commit(repository, "late structural failure after named mismatch")
    monkeypatch.setattr(openssf_catalog, "sync_official_repository", lambda _: (repository, commit))
    monkeypatch.setattr(openssf_catalog, "BOOTSTRAP_COMMIT", commit)
    with pytest.raises(Exception) as raised:
        resilience_runner()
    assert not isinstance(raised.value, openssf_catalog.OpenSSFCatalogPartial)
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=OPENSSF_SOURCE_ID) == 1
        assert scalar_count(session, AdvisoryCatalogRecord) == 0
        receipt = session.scalar(select(OpenSSFCatalogAttempt))
        assert receipt.state == "failed"
        assert len(receipt.document["rejections"]) == 1
        assert "accepted_count" not in receipt.document
        assert not openssf_catalog._latest_complete_pair(session)


def test_rejection_outcome_and_membership_rollback_together(
    database, resilience_runner, monkeypatch
):
    set_tree(monkeypatch, bad_record())
    append = openssf_resilience.append_replay_membership

    def fail_after_membership(session, **kwargs):
        append(session, **kwargs)
        raise RuntimeError("synthetic rejection membership crash")

    monkeypatch.setattr(openssf_resilience, "append_replay_membership", fail_after_membership)
    with pytest.raises(RuntimeError, match="synthetic rejection membership crash"):
        resilience_runner()
    with Session(database.engine) as session:
        assert scalar_count(session, CollectionRecordOutcome) == 0
        assert scalar_count(session, CollectionRecordMembership) == 0
        assert scalar_count(session, AdvisoryCatalogRecord) == 0
        receipt = session.scalar(select(OpenSSFCatalogAttempt))
        assert receipt.state == "failed" and receipt.document["rejections"] == []
        assert not openssf_catalog._latest_complete_pair(session)


@pytest.mark.parametrize("field", ["accepted_count", "scanned_count", "tree_sha256"])
def test_failed_receipt_rejects_unearned_partition_claims(database, field):
    document = {"schema_version": "1.0.0", "commit": "a" * 40, "rejections": [], field: 0}
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(openssf_resilience.OpenSSFResilienceError, match="cannot claim"),
    ):
        openssf_resilience.append_attempt(
            session,
            run_id="gbsec:test:failed-partition",
            state="failed",
            observed_at=FIXTURE_NOW,
            document=document,
        )
    # The immutable database boundary also refuses a writer bypassing the helper.
    with Session(database.engine) as session, session.begin(), pytest.raises(DBAPIError):
        session.add(
            OpenSSFCatalogAttempt(
                run_id="gbsec:test:failed-partition",
                state="failed",
                observed_at=FIXTURE_NOW,
                document=document,
                record_hash="sha256:" + "a" * 64,
            )
        )
        session.flush()


@pytest.mark.parametrize("prior_withdrawn", [False, True])
def test_signed_25_rejected_own_package_has_only_historical_unknown_assertions(
    database, resilience_runner, monkeypatch, prior_withdrawn
):
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from smithguard.feeds import SnapshotSigner
    from smithguard.identifiers import canonical_json_bytes
    from tests.test_service_api import _public_client

    if prior_withdrawn:
        set_tree(monkeypatch, bad_record(), withdrawn_tree=True)
    resilience_runner()
    set_tree(monkeypatch, bad_record(withdrawn=not prior_withdrawn), withdrawn_tree=prior_withdrawn)
    with pytest.raises(openssf_catalog.OpenSSFCatalogPartial):
        resilience_runner()
    signer = SnapshotSigner.ephemeral()
    with _public_client(database, signer=signer) as client:
        response = client.post(
            "/v1/artifacts/assess",
            json={"ecosystem": "npm", "name": "example", "version": "99.0.0"},
        )
        assert response.status_code == 200
        answer = response.json()
    signature = answer.pop("signature")
    Ed25519PublicKey.from_public_bytes(signer.public_key_bytes).verify(
        base64.b64decode(signature["value"], validate=True), canonical_json_bytes(answer)
    )
    assert answer["schema_version"] == "2.5.0"
    assert answer["result"] == "possibly_affected"
    incident = answer["incidents"][0]
    assert incident["applies_to_version"] is None and incident["fixed_versions"] == []
    report = incident["source_reports"][0]
    assert report["source_id"] == OPENSSF_SOURCE_ID
    assert report["source_state_status"] == "historical_unresolved"
    assert report["state"] == ("withdrawn" if prior_withdrawn else "active")
    assert report["applies_to_version"] is None
    assert report["fixed_versions"] == report["source_fixed_versions"] == []
    source = next(
        row for row in answer["source_freshness"] if row["source_id"] == OPENSSF_SOURCE_ID
    )
    assert source["freshness_state"] == "unresolved" and source["unresolved_record_count"] == 1


def test_strict_preflight_keeps_unchanged_accepted_pass_incremental(
    database, resilience_runner, monkeypatch
):
    resilience_runner()
    seen = []
    parse = openssf_catalog.LocalOpenSSFGitRepository.parse_record

    def observe(self, entry, body):
        seen.append(entry.advisory_id)
        return parse(self, entry, body)

    monkeypatch.setattr(openssf_catalog.LocalOpenSSFGitRepository, "parse_record", observe)
    unchanged = resilience_runner()
    assert unchanged["full_verification"] is True
    assert unchanged["parsed_record_count"] == len(seen) == 3
    assert unchanged["physical_page_count"] == unchanged["created_revision_count"] == 0
    seen.clear()
    repository = openssf_catalog._state_root().parent / "openssf"
    path = repository / "osv/malicious/pypi/example-project/MAL-2026-101.json"
    document = strict_json_loads(path.read_bytes())
    document["affected"][0]["versions"].append("2.0.0")
    _write_record(repository, str(path.relative_to(repository)), document)
    commit = _commit(repository, "one independently changed valid record")
    monkeypatch.setattr(openssf_catalog, "sync_official_repository", lambda _: (repository, commit))
    changed = resilience_runner()
    assert changed["parsed_record_count"] == 3 and len(seen) == 4
    assert seen.count("MAL-2026-101") == 2
    assert changed["created_revision_count"] == changed["physical_page_count"] == 1


def test_incremental_accepted_pass_forces_exact_old_byte_repair(
    database, resilience_runner, monkeypatch
):
    resilience_runner()
    repository = openssf_catalog._state_root().parent / "openssf"
    original = strict_json_loads(
        (repository / "osv/malicious/npm/example/MAL-2026-100.json").read_bytes()
    )
    set_tree(monkeypatch, bad_record())
    with pytest.raises(openssf_catalog.OpenSSFCatalogPartial):
        resilience_runner()
    set_tree(monkeypatch, original)
    seen = []
    parse = openssf_catalog.LocalOpenSSFGitRepository.parse_record

    def observe(self, entry, body):
        seen.append(entry.advisory_id)
        return parse(self, entry, body)

    monkeypatch.setattr(openssf_catalog.LocalOpenSSFGitRepository, "parse_record", observe)
    result = resilience_runner()
    assert result["created_revision_count"] == 0
    assert len(seen) == 4 and seen.count("MAL-2026-100") == 2
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=OPENSSF_SOURCE_ID) == 0
        assert scalar_count(session, CollectionRecordResolution) == 1


def test_accepted_second_read_must_match_strict_preflight_identity(
    database, resilience_runner, monkeypatch
):
    from dataclasses import replace

    counts = {}
    parse = openssf_catalog.LocalOpenSSFGitRepository.parse_record

    def drift(self, entry, body):
        result = parse(self, entry, body)
        counts[entry.advisory_id] = counts.get(entry.advisory_id, 0) + 1
        if entry.advisory_id == "MAL-2026-100" and counts[entry.advisory_id] == 2:
            result.projected["affected"][0]["versions"].append("99.0.0")
            return replace(result, projected=result.projected)
        return result

    monkeypatch.setattr(openssf_catalog.LocalOpenSSFGitRepository, "parse_record", drift)
    with pytest.raises(openssf_catalog.OpenSSFCatalogError, match="changed after strict preflight"):
        resilience_runner()
    with Session(database.engine) as session:
        assert scalar_count(session, AdvisoryCatalogRecord) == 0
        assert not openssf_catalog._latest_complete_pair(session)
        assert session.scalar(select(OpenSSFCatalogAttempt)).state == "failed"


@pytest.mark.parametrize("previously_accepted", [False, True])
def test_upstream_disappearance_never_resolves_a_rejected_identity(
    database, resilience_runner, monkeypatch, previously_accepted
):
    resilience_runner()
    marker = (openssf_catalog._state_root() / "verification.json").read_bytes()
    repository = openssf_catalog._state_root().parent / "openssf"
    identity = "MAL-2026-100" if previously_accepted else "MAL-2026-103"
    path = repository / f"osv/malicious/npm/example/{identity}.json"
    _write_record(
        repository,
        str(path.relative_to(repository)),
        _record(identity, ecosystem="npm", name="example", withdrawn=True),
    )
    commit = _commit(repository, "rejected identity before disappearance")
    monkeypatch.setattr(openssf_catalog, "sync_official_repository", lambda _: (repository, commit))
    with pytest.raises(openssf_catalog.OpenSSFCatalogPartial):
        resilience_runner()
    path.unlink()
    commit = _commit(repository, "upstream removes rejected identity")
    monkeypatch.setattr(openssf_catalog, "sync_official_repository", lambda _: (repository, commit))
    expected = "upstream IDs missing" if previously_accepted else "unresolved identities differ"
    with pytest.raises(openssf_catalog.OpenSSFCatalogError, match=expected):
        resilience_runner()
    assert (openssf_catalog._state_root() / "verification.json").read_bytes() == marker
    with Session(database.engine) as session:
        assert unresolved_count(session, source_id=OPENSSF_SOURCE_ID) == 1
        assert scalar_count(session, CollectionRecordResolution) == 0


@pytest.mark.parametrize("bound", ["depth", "nodes", "escaped_bytes"])
@pytest.mark.parametrize("mode", ["disabled", "enabled", "mismatch"])
def test_mismatched_record_over_projected_bounds_is_whole_attempt_failure(
    database, resilience_runner, monkeypatch, bound, mode
):
    monkeypatch.setattr(openssf_catalog, "partial_writes_enabled", lambda: mode != "disabled")
    document = bad_record(withdrawn=mode == "mismatch")
    if bound == "depth":
        nested = "leaf"
        for _ in range(32):
            nested = [nested]
        document["affected"][0]["database_specific"] = {"nested": nested}
    elif bound == "nodes":
        document["affected"][0]["database_specific"] = {"many": [0] * 100_000}
    else:
        # Small UTF-8 raw blob but >8MiB canonical escaped page, below Git4MiB.
        document["affected"][0]["database_specific"] = {"escaped": "\U00010000" * 700_000}
    repository, _ = set_tree(
        monkeypatch,
        bad_record(withdrawn=mode == "mismatch") if bound == "escaped_bytes" else document,
    )
    if bound == "escaped_bytes":
        import json

        path = repository / "osv/malicious/npm/example/MAL-2026-100.json"
        path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        commit = _commit(repository, "bounded raw Unicode with oversized canonical projection")
        monkeypatch.setattr(
            openssf_catalog, "sync_official_repository", lambda _: (repository, commit)
        )
        monkeypatch.setattr(openssf_catalog, "BOOTSTRAP_COMMIT", commit)
    with pytest.raises(
        (openssf_catalog.OpenSSFGitError, openssf_catalog.OpenSSFCatalogError),
        match="acquisition budget",
    ):
        resilience_runner()
    with Session(database.engine) as session:
        assert scalar_count(session, CollectionRecordOutcome) == 0
        assert scalar_count(session, AdvisoryCatalogRecord) == 0
        assert not openssf_catalog._latest_complete_pair(session)


def test_signed_negative_keeps_cached_gap_barrier_after_live_resolution(
    database, resilience_runner, monkeypatch
):
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from smithguard.feeds import SnapshotSigner
    from smithguard.identifiers import canonical_json_bytes
    from tests.test_service_api import _public_client

    resilience_runner()
    repository = openssf_catalog._state_root().parent / "openssf"
    original = strict_json_loads(
        (repository / "osv/malicious/npm/example/MAL-2026-100.json").read_text()
    )
    set_tree(monkeypatch, bad_record())
    with pytest.raises(openssf_catalog.OpenSSFCatalogPartial):
        resilience_runner()
    with Session(database.engine) as session:
        refresh_coverage_report(
            session,
            measured_at=FIXTURE_NOW,
            live_collector_uptime="not_measured_public_beta_collector",
            evidence_label="public",
        )
        session.commit()
    signer = SnapshotSigner.ephemeral()
    request = {"ecosystem": "npm", "name": "never-mapped", "version": "5.0.0"}
    with _public_client(database, signer=signer) as client:
        before = client.post("/v1/artifacts/assess", json=request).json()
        set_tree(monkeypatch, original)
        resilience_runner()
        with Session(database.engine) as session:
            assert unresolved_count(session, source_id=OPENSSF_SOURCE_ID) == 0
        response = client.post("/v1/artifacts/assess", json=request)
        assert response.status_code == 200
        answer = response.json()
        assert answer["feed_revision"] != before["feed_revision"]
        assert answer["result"] == "unknown"
        lane = next(
            item for item in answer["source_freshness"] if item["source_id"] == OPENSSF_SOURCE_ID
        )
        assert lane["freshness_state"] == "unresolved" and lane["unresolved_record_count"] == 1
        signature = answer.pop("signature")
        Ed25519PublicKey.from_public_bytes(signer.public_key_bytes).verify(
            base64.b64decode(signature["value"], validate=True), canonical_json_bytes(answer)
        )


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("bound", ["depth", "nodes", "escaped_bytes"])
def test_ignored_top_level_metadata_has_same_page_bounds_in_both_modes(
    database, request, monkeypatch, enabled, bound
):
    runner = request.getfixturevalue("catalog_runner")
    monkeypatch.setattr(openssf_catalog, "partial_writes_enabled", lambda: enabled)
    document = bad_record(withdrawn=False)
    if bound == "depth":
        value = "leaf"
        for _ in range(32):
            value = [value]
    elif bound == "nodes":
        value = [0] * 100_000
    else:
        value = "\U00010000" * 700_000
    document["database_specific"] = {"ignored": value}
    repository, _ = set_tree(monkeypatch, bad_record(withdrawn=False))
    import json

    path = repository / "osv/malicious/npm/example/MAL-2026-100.json"
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    commit = _commit(repository, "large bounded ignored top-level source metadata")
    monkeypatch.setattr(openssf_catalog, "sync_official_repository", lambda _: (repository, commit))
    monkeypatch.setattr(openssf_catalog, "BOOTSTRAP_COMMIT", commit)
    assert runner()["status"] == "complete"
