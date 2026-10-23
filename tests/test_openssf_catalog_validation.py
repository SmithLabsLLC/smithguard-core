"""Complete latest-revision catalog checks across bounded SQL pages."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from smithguard import openssf_catalog
from smithguard.advisory_catalog import append_github_advisory, append_openssf_advisory
from smithguard.db.models import AdvisoryCatalogManifestRecord, AdvisoryCatalogRecord
from smithguard.runtime import DEFAULT_AUTHORITY_POLICY, RuntimeConfig
from smithguard.runtime import _engine as runtime_engine
from smithguard.source_governance import DEFAULT_GOVERNANCE_POLICY_PATH

from .governance_fixtures import RIGHTS_REGISTER
from .test_advisory_catalog import _github_event_stream
from .test_openssf_git import _repository

NOW = datetime(2026, 9, 14, tzinfo=UTC)


def _append(session, identity: str, *, state: str = "active", packages: int = 1):
    affected = [
        {
            "package": {"ecosystem": "npm", "name": f"synthetic-{index}"},
            "versions": ["1.0.0"],
        }
        for index in range(packages)
    ]
    if not packages:
        affected = [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://example.test/public.git",
                        "events": [{"introduced": "0"}],
                    }
                ]
            }
        ]
    return append_openssf_advisory(
        session,
        document={
            "id": identity,
            "published": "2026-09-01T00:00:00Z",
            "modified": "2026-09-14T00:00:00Z",
            "withdrawn": "2026-09-14T00:00:00Z" if state == "withdrawn" else None,
            "affected": affected,
        },
        canonical_url="https://github.com/ossf/malicious-packages/blob/" + "a" * 40 + "/test.json",
        source_state=state,
        evidence_id="gbsec:evidence:catalog-validation-test",
        governance_decision_id="gbsec:governance:catalog-validation-test",
        observed_at=NOW,
    )


@pytest.mark.parametrize("page_size", [1, 2, 3])
def test_complete_validation_keeps_latest_zero_and_multiple_packages_across_pages(
    database, monkeypatch, page_size
) -> None:
    expected = {"malicious": [], "withdrawn": []}
    counts = {"malicious": 0, "withdrawn": 0}
    inputs = [
        ("MAL-2026-9", "active", 2),
        ("MAL-2026-10", "withdrawn", 1),
        ("MAL-2026-20", "active", 0),
        ("MAL-2026-21", "withdrawn", 3),
        ("MAL-2026-999", "active", 1),
    ]
    with Session(database.engine) as session, session.begin():
        for identity, state, count in inputs:
            _append(session, identity, state="withdrawn" if state == "active" else "active")
            latest = _append(session, identity, state=state, packages=count)
            assert latest.revision == 2
            tree = "malicious" if state == "active" else "withdrawn"
            expected[tree].append([identity, latest.source_sha256])
            counts[tree] += count
        append_github_advisory(
            session,
            document=_github_event_stream(),
            evidence_id="gbsec:evidence:other-source",
            governance_decision_id="gbsec:governance:other-source",
            observed_at=NOW,
        )
    for records in expected.values():
        records.sort()
    monkeypatch.setattr(openssf_catalog, "CATALOG_VALIDATION_PAGE_SIZE", page_size)
    before_values = []
    query = openssf_catalog._openssf_catalog_validation_page

    def observe(before=None):
        before_values.append(before)
        return query(before)

    monkeypatch.setattr(openssf_catalog, "_openssf_catalog_validation_page", observe)
    with Session(database.engine) as session, session.begin():
        session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
        assert openssf_catalog._read_catalog_validation(session) == (expected, counts)
    assert before_values[0] is None
    assert len(before_values) == (len(inputs) + page_size - 1) // page_size + 1
    assert len(set(before_values)) == len(before_values)


def test_empty_catalog_has_no_records_and_zero_counts(database) -> None:
    with Session(database.engine) as session:
        assert openssf_catalog._read_catalog_validation(session) == (
            {"malicious": [], "withdrawn": []},
            {"malicious": 0, "withdrawn": 0},
        )


def test_keyset_canonical_order_handles_case_and_punctuation(database, monkeypatch) -> None:
    identities = ["MAL-2026-a", "MAL-2026-A", "MAL-2026-1.A", "MAL-2026-1-A"]
    expected = []
    with Session(database.engine) as session, session.begin():
        for identity in identities:
            result = _append(session, identity)
            expected.append([identity, result.source_sha256])
    monkeypatch.setattr(openssf_catalog, "CATALOG_VALIDATION_PAGE_SIZE", 1)
    with Session(database.engine) as session:
        records, counts = openssf_catalog._read_catalog_validation(session)
    assert records == {"malicious": sorted(expected), "withdrawn": []}
    assert counts == {"malicious": 4, "withdrawn": 0}


def test_repeatable_validation_snapshot_excludes_mid_scan_commits(database, monkeypatch) -> None:
    with Session(database.engine) as session, session.begin():
        first = _append(session, "MAL-2026-30")
        second = _append(session, "MAL-2026-10")
    monkeypatch.setattr(openssf_catalog, "CATALOG_VALIDATION_PAGE_SIZE", 1)
    query = openssf_catalog._openssf_catalog_validation_page
    appended = []

    def advance(before=None):
        if before is not None and not appended:
            with Session(database.engine) as writer, writer.begin():
                _append(writer, "MAL-2026-20")
                _append(writer, "MAL-2026-10", state="withdrawn", packages=2)
            appended.append(True)
        return query(before)

    monkeypatch.setattr(openssf_catalog, "_openssf_catalog_validation_page", advance)
    with Session(database.engine) as session, session.begin():
        session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
        records, counts = openssf_catalog._read_catalog_validation(session)
    assert appended == [True]
    assert records == {
        "malicious": [["MAL-2026-10", second.source_sha256], ["MAL-2026-30", first.source_sha256]],
        "withdrawn": [],
    }
    assert counts == {"malicious": 2, "withdrawn": 0}
    with Session(database.engine) as session:
        assert len(session.scalars(select(AdvisoryCatalogRecord)).all()) == 4


@pytest.fixture
def catalog_runner(database, tmp_path, monkeypatch):
    repository, commit, license_sha256 = _repository(tmp_path)
    state_root = tmp_path / "catalog-state"
    state_root.mkdir()
    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY_PATH,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
    )
    monkeypatch.setattr(openssf_catalog, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(openssf_catalog, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(openssf_catalog, "_state_root", lambda: state_root)
    monkeypatch.setattr(
        openssf_catalog, "sync_official_repository", lambda _paths: (repository, commit)
    )
    monkeypatch.setattr(openssf_catalog, "OPENSSF_LICENSE_SHA256", license_sha256)
    monkeypatch.setattr(openssf_catalog, "BOOTSTRAP_COMMIT", commit)
    monkeypatch.setattr(openssf_catalog, "MAX_PAGE_SIZE", 2)
    monkeypatch.setattr(openssf_catalog, "CATALOG_VALIDATION_PAGE_SIZE", 2)
    return openssf_catalog.collect_openssf_catalog


def test_full_runner_reuses_production_engine_with_ping_and_sql_limits(
    database, monkeypatch, catalog_runner
) -> None:
    engine = runtime_engine(openssf_catalog.load_runtime_config())
    original_ping = engine.dialect.do_ping
    pings = []
    read = openssf_catalog._read_catalog_validation
    settings = []

    def ping(connection):
        result = original_ping(connection)
        # The PostgreSQL dialect pings in autocommit mode, then restores it.
        assert connection.info.transaction_status.name == "IDLE"
        assert connection.autocommit is False
        pings.append(result)
        return result

    def read_with_settings(session):
        settings.append(
            (
                session.scalar(text("SHOW transaction_isolation")),
                session.scalar(text("SHOW statement_timeout")),
                session.scalar(text("SHOW lock_timeout")),
            )
        )
        return read(session)

    monkeypatch.setattr(engine.dialect, "do_ping", ping)
    monkeypatch.setattr(openssf_catalog, "_engine", lambda _config: engine)
    monkeypatch.setattr(openssf_catalog, "_read_catalog_validation", read_with_settings)
    try:
        # Warm and return a connection so the collector must exercise pre-ping.
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT 1")) == 1
        assert catalog_runner()["status"] == "complete"
        assert catalog_runner()["created_revision_count"] == 0
        assert len(pings) >= 2 and all(pings)
        assert settings == [("repeatable read", "10s", "5s")] * 4
        with Session(database.engine) as session:
            manifests = session.scalars(
                select(AdvisoryCatalogManifestRecord).order_by(
                    AdvisoryCatalogManifestRecord.segment,
                    AdvisoryCatalogManifestRecord.sequence,
                )
            ).all()
            assert [manifest.sequence for manifest in manifests] == [1, 2, 3, 4, 1, 2, 3, 4]
            assert [manifest.state for manifest in manifests] == [
                "in_progress",
                "complete",
                "in_progress",
                "complete",
            ] * 2
    finally:
        engine.dispose()


@pytest.mark.parametrize("mismatch", ["missing", "extra", "hash", "state", "count"])
def test_complete_manifest_still_refuses_catalog_or_package_mismatch(
    database, monkeypatch, catalog_runner, mismatch
) -> None:
    read = openssf_catalog._read_catalog_validation

    def change_result(session):
        assert session.scalar(text("SHOW transaction_isolation")) == "repeatable read"
        records, counts = deepcopy(read(session))
        if not records["malicious"]:
            return records, counts
        if mismatch == "missing":
            records["malicious"].pop()
        elif mismatch == "extra":
            records["malicious"].append(["MAL-2026-9999", "sha256:" + "b" * 64])
        elif mismatch == "hash":
            records["malicious"][0][1] = "sha256:" + "b" * 64
        elif mismatch == "state":
            records["withdrawn"].append(records["malicious"].pop())
        else:
            counts["withdrawn"] += 1
        return records, counts

    monkeypatch.setattr(openssf_catalog, "_read_catalog_validation", change_result)
    reason = "package count" if mismatch == "count" else "database identity"
    with pytest.raises(openssf_catalog.OpenSSFCatalogError, match=reason):
        catalog_runner()
    with Session(database.engine) as session:
        assert len(session.scalars(select(AdvisoryCatalogRecord)).all()) == 3
        # The count case fails in segment two and also rolls back segment one.
        assert [
            row.state
            for row in session.scalars(
                select(AdvisoryCatalogManifestRecord).order_by(
                    AdvisoryCatalogManifestRecord.segment, AdvisoryCatalogManifestRecord.sequence
                )
            )
        ] == ["in_progress", "failed"] * 2


@pytest.mark.parametrize("when", ["before", "after", "later_page"])
def test_validation_time_budget_refuses_without_complete_manifests(
    database, monkeypatch, catalog_runner, when
) -> None:
    elapsed = [0.0]
    page_queries = []
    query = openssf_catalog._openssf_catalog_validation_page
    read = openssf_catalog._read_catalog_validation

    def timed_query(before=None):
        page_queries.append(before)
        if when == "after" or (when == "later_page" and before is not None):
            elapsed[0] = 121.0
        return query(before)

    def timed_read(session):
        calls = [0]

        def monotonic():
            calls[0] += 1
            if when == "before" and calls[0] > 1:
                elapsed[0] = 121.0
            return elapsed[0]

        monkeypatch.setattr(openssf_catalog, "time", SimpleNamespace(monotonic=monotonic))
        return read(session)

    monkeypatch.setattr(openssf_catalog, "_read_catalog_validation", timed_read)
    monkeypatch.setattr(openssf_catalog, "_openssf_catalog_validation_page", timed_query)
    with pytest.raises(openssf_catalog.OpenSSFCatalogError, match="time budget"):
        catalog_runner()
    assert len(page_queries) == {"before": 0, "after": 1, "later_page": 3}[when]
    with Session(database.engine) as session:
        assert [
            row.state
            for row in session.scalars(
                select(AdvisoryCatalogManifestRecord).order_by(
                    AdvisoryCatalogManifestRecord.segment, AdvisoryCatalogManifestRecord.sequence
                )
            )
        ] == ["in_progress", "failed"] * 2


def _catalog_rows(database):
    from smithguard.db.models import CollectorCheckpointRecord, EvidenceRecord

    with Session(database.engine) as session:
        return tuple(
            session.query(model).count()
            for model in (AdvisoryCatalogRecord, EvidenceRecord, CollectorCheckpointRecord)
        )


@pytest.mark.audit_ids("COL-12", "COL-14")
def test_unchanged_and_full_verification_never_duplicate_pages(
    database, catalog_runner, monkeypatch
):
    first = catalog_runner()
    counts = _catalog_rows(database)
    original = openssf_catalog.LocalOpenSSFGitRepository.parse_record
    monkeypatch.setattr(
        openssf_catalog.LocalOpenSSFGitRepository,
        "parse_record",
        lambda *_a: pytest.fail("unchanged source parsed"),
    )
    second = catalog_runner()
    assert second["parsed_record_count"] == second["physical_page_count"] == 0
    assert not second["full_verification"]
    assert _catalog_rows(database) == counts
    monkeypatch.setattr(openssf_catalog.LocalOpenSSFGitRepository, "parse_record", original)
    (openssf_catalog._state_root() / "verification.json").unlink()
    third = catalog_runner()
    assert third["full_verification"]
    assert third["parsed_record_count"] == first["record_count"]
    assert third["physical_page_count"] == third["created_revision_count"] == 0
    assert _catalog_rows(database) == counts


@pytest.mark.parametrize(
    "marker_change", ("corrupt", "processing", "policy", "baseline", "expired", "future")
)
def test_invalid_or_expired_marker_forces_full_verification_without_new_evidence(
    database, catalog_runner, marker_change
):
    import json
    from datetime import timedelta

    catalog_runner()
    counts = _catalog_rows(database)
    path = openssf_catalog._state_root() / "verification.json"
    marker = json.loads(path.read_text())
    if marker_change == "processing":
        marker["processing_version"] = "old"
    elif marker_change == "policy":
        marker["policy_sha256"] = "sha256:" + "f" * 64
    elif marker_change == "baseline":
        marker["baseline_ids"] = []
    elif marker_change in {"expired", "future"}:
        marker["full_verified_at"] = (
            datetime.now(UTC) + timedelta(hours=-25 if marker_change == "expired" else 1)
        ).isoformat()
    path.write_text("not-json" if marker_change == "corrupt" else json.dumps(marker))
    result = catalog_runner()
    assert result["full_verification"] and result["parsed_record_count"] == 3
    assert result["physical_page_count"] == 0
    assert _catalog_rows(database) == counts


def test_noop_preserves_daily_verification_clock(catalog_runner):
    import json

    catalog_runner()
    path = openssf_catalog._state_root() / "verification.json"
    before = json.loads(path.read_text())
    catalog_runner()
    after = json.loads(path.read_text())
    assert after["baseline_ids"] != before["baseline_ids"]
    assert after["full_verified_at"] == before["full_verified_at"]


@pytest.mark.parametrize("change", ("version", "withdrawal", "metadata", "removed"))
@pytest.mark.audit_ids("COL-12")
def test_incremental_changes_and_missing_upstream_identity(
    database, catalog_runner, monkeypatch, change
):
    import json

    from .test_openssf_git import _commit

    catalog_runner()
    repository, _commit_id = openssf_catalog.sync_official_repository(None)
    path = repository / "osv/malicious/npm/example/MAL-2026-100.json"
    document = json.loads(path.read_text())
    if change == "version":
        document["affected"][0]["versions"].append("2.0.0")
    elif change == "withdrawal":
        document["withdrawn"] = "2026-09-01T00:00:00Z"
        path.unlink()
        path = repository / "osv/withdrawn/npm/example/MAL-2026-100.json"
        path.parent.mkdir(parents=True)
    elif change == "metadata":
        document["database_specific"] = {"large-unused": "x" * 1_522_666}
    if change == "removed":
        path.unlink()
        # A disappeared ID must not prevent accepting a different current change.
        other = repository / "osv/malicious/pypi/example-project/MAL-2026-101.json"
        other_document = json.loads(other.read_text())
        other_document["affected"][0]["versions"].append("2.0.0")
        other.write_text(json.dumps(other_document))
    else:
        path.write_text(json.dumps(document))
    commit = _commit(repository, "synthetic incremental change")
    monkeypatch.setattr(
        openssf_catalog, "sync_official_repository", lambda _paths: (repository, commit)
    )
    if change == "removed":
        with pytest.raises(openssf_catalog.OpenSSFCatalogError, match="upstream IDs missing"):
            catalog_runner()
        with Session(database.engine) as session:
            assert len(session.scalars(select(AdvisoryCatalogRecord)).all()) == 4
            latest = session.scalars(
                select(AdvisoryCatalogManifestRecord)
                .order_by(AdvisoryCatalogManifestRecord.sequence.desc())
                .limit(2)
            ).all()
            assert {row.state for row in latest} == {"failed"}
            assert openssf_catalog._latest_complete_pair(session)[0].source_snapshot.startswith(
                _commit_id
            )
        return
    result = catalog_runner()
    assert not result["full_verification"]
    assert result["parsed_record_count"] == 1
    assert (
        result["created_revision_count"]
        == result["physical_page_count"]
        == (0 if change == "metadata" else 1)
    )
    assert catalog_runner()["physical_page_count"] == 0


@pytest.mark.audit_ids("COL-12")
def test_partial_ingestion_resumes_without_recreating_completed_pages(
    database, catalog_runner, monkeypatch
):
    original = openssf_catalog.append_openssf_advisory
    calls = 0

    def interrupt(session, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise openssf_catalog.OpenSSFCatalogError("synthetic page interruption")
        return original(session, **kwargs)

    monkeypatch.setattr(openssf_catalog, "append_openssf_advisory", interrupt)
    with pytest.raises(openssf_catalog.OpenSSFCatalogError, match="page interruption"):
        catalog_runner()
    assert _catalog_rows(database)[0] == 2
    before = _catalog_rows(database)
    monkeypatch.setattr(openssf_catalog, "append_openssf_advisory", original)
    result = catalog_runner()
    after = _catalog_rows(database)
    assert result["created_revision_count"] == result["physical_page_count"] == 1
    assert after[0] == 3 and after[1] == before[1] + 1 and after[2] == before[2] + 1


@pytest.mark.audit_ids("COL-12")
def test_sigterm_finishes_current_page_and_resume_skips_it(database, catalog_runner, monkeypatch):
    import signal

    from smithguard.openssf_budget import CatalogStopped

    original = openssf_catalog.append_openssf_advisory
    sent = []

    def stop_during_page(session, **kwargs):
        result = original(session, **kwargs)
        if not sent:
            sent.append(True)
            signal.raise_signal(signal.SIGTERM)
        return result

    previous_handler = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(openssf_catalog, "append_openssf_advisory", stop_during_page)
    with pytest.raises(CatalogStopped, match="stop requested"):
        catalog_runner()
    assert signal.getsignal(signal.SIGTERM) == previous_handler
    assert _catalog_rows(database)[0] == 2
    monkeypatch.setattr(openssf_catalog, "append_openssf_advisory", original)
    result = catalog_runner()
    assert result["created_revision_count"] == result["physical_page_count"] == 1


def test_catalog_batches_split_bytes_and_semantic_nodes():
    from types import SimpleNamespace

    entries = [SimpleNamespace(byte_count=3 * 1024 * 1024) for _ in range(4)]
    assert [len(batch) for batch in openssf_catalog._raw_batches(entries)] == [2, 2]
    records = [SimpleNamespace(projected={"values": [0] * 60_000}) for _ in range(2)]
    assert [len(page) for page in openssf_catalog._semantic_pages(records)] == [1, 1]
    with pytest.raises(openssf_catalog.OpenSSFCatalogError, match="projected record"):
        list(
            openssf_catalog._semantic_pages([SimpleNamespace(projected={"values": [0] * 100_000})])
        )
    with pytest.raises(openssf_catalog.OpenSSFCatalogError, match="projected record"):
        list(
            openssf_catalog._semantic_pages(
                [SimpleNamespace(projected={"value": "x" * (8 * 1024 * 1024)})]
            )
        )


def test_preflight_failure_still_records_a_failed_attempt(database, catalog_runner, monkeypatch):
    def fail(_paths):
        raise openssf_catalog.OpenSSFCatalogError("synthetic fetch failure")

    monkeypatch.setattr(openssf_catalog, "sync_official_repository", fail)
    with pytest.raises(openssf_catalog.OpenSSFCatalogError, match="fetch failure"):
        catalog_runner()
    with Session(database.engine) as session:
        assert not openssf_catalog._latest_complete_pair(session)
        assert [
            row.state
            for row in session.scalars(
                select(AdvisoryCatalogManifestRecord).order_by(
                    AdvisoryCatalogManifestRecord.segment, AdvisoryCatalogManifestRecord.sequence
                )
            )
        ] == ["in_progress", "failed"] * 2


@pytest.mark.parametrize("resolved_state", ["malicious", "withdrawn"])
@pytest.mark.parametrize("stale", [False, True])
def test_provisional_snapshot_preserves_complete_evidence_until_finalized(
    database, catalog_runner, monkeypatch, tmp_path, resolved_state, stale
):
    import os
    from datetime import timedelta

    from smithguard import catalog_health
    from smithguard.coverage import build_coverage_report
    from smithguard.operational_health import public_readiness

    from .test_openssf_git import _commit, _record, _write_record

    parent = tmp_path / "health"
    parent.mkdir(mode=0o700)
    parent.chmod(0o2750)
    receipt_path = parent / "openssf.json"
    openssf_catalog._state_root().chmod(0o700)
    monkeypatch.setattr(
        catalog_health.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getegid())
    )
    monkeypatch.setattr(
        catalog_health.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.geteuid())
    )
    monkeypatch.setattr(openssf_catalog, "CATALOG_HEALTH_PATH", receipt_path)
    monkeypatch.setenv(catalog_health.CATALOG_HEALTH_VARIABLE, str(receipt_path))
    catalog_runner()
    success = catalog_health.load_catalog_health(receipt_path)
    before = _catalog_rows(database)
    marker = openssf_catalog._state_root() / "verification.json"
    marker_before = marker.read_bytes()
    repository, previous = openssf_catalog.sync_official_repository(None)
    relative = "osv/malicious/npm/pending/MAL-0000-amazon-inspector-a.json"
    _write_record(
        repository,
        relative,
        _record("MAL-0000-amazon-inspector-a", ecosystem="npm", name="pending"),
    )
    candidate = _commit(repository, "upstream has not assigned an ID")
    monkeypatch.setattr(
        openssf_catalog, "sync_official_repository", lambda _paths: (repository, candidate)
    )
    measured = datetime.now(UTC) + timedelta(hours=3 if stale else 0)

    class ReceiptClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return measured

    monkeypatch.setattr(catalog_health, "datetime", ReceiptClock)
    for _attempt_number in range(2):
        with pytest.raises(openssf_catalog.OpenSSFCatalogDeferred) as deferred:
            catalog_runner()
        assert deferred.value.commit == candidate
        assert _catalog_rows(database) == before
        assert marker.read_bytes() == marker_before
        receipt = catalog_health.load_catalog_health(receipt_path)
        assert receipt["checkpoint"] == candidate
        assert receipt["last_success_commit"] == previous
        assert receipt["last_success_at"] == success["last_success_at"]
        assert receipt["stale_after"] == success["stale_after"]
        assert receipt["status"] == ("failure" if stale else "degraded")
        assert receipt["healthy"] is (not stale)
        assert receipt["missing_upstream_count"] == 0
        with Session(database.engine) as session:
            latest = session.scalars(
                select(AdvisoryCatalogManifestRecord)
                .order_by(AdvisoryCatalogManifestRecord.sequence.desc())
                .limit(2)
            ).all()
            assert {row.state for row in latest} == {"failed"}
            assert {row.source_snapshot for row in latest} == {candidate}
            lane = next(
                row
                for row in build_coverage_report(session, measured_at=measured).source_lanes
                if row.source_id == openssf_catalog.OPENSSF_SOURCE_ID
            )
            assert lane.state == lane.freshness_state == "failed"
            ready, reasons = public_readiness(session, measured_at=measured)
            assert not ready and "openssf_catalog_failed" in reasons

    # Once upstream assigns an ID, both active and withdrawn records are ingestible.
    (repository / relative).unlink()
    _write_record(
        repository,
        f"osv/{resolved_state}/npm/pending/MAL-2026-9999.json",
        _record(
            "MAL-2026-9999",
            ecosystem="npm",
            name="pending",
            withdrawn=resolved_state == "withdrawn",
        ),
    )
    candidate = _commit(repository, "assign final identity")
    monkeypatch.setattr(catalog_health, "datetime", datetime)
    assert catalog_runner()["status"] == "complete"
    recovered = catalog_health.load_catalog_health(receipt_path)
    assert recovered["status"] == "success" and recovered["last_success_commit"] == candidate
    assert _catalog_rows(database)[0] == before[0] + 1


def test_empty_catalog_uses_fixed_bootstrap_despite_provisional_upstream_head(
    catalog_runner, monkeypatch
):
    from .test_openssf_git import _commit, _record, _write_record

    repository, bootstrap = openssf_catalog.sync_official_repository(None)
    repository = repository.rename(openssf_catalog._state_root() / "repository")
    _write_record(
        repository,
        "osv/malicious/npm/pending/MAL-0000-amazon-inspector-a.json",
        _record("MAL-0000-amazon-inspector-a", ecosystem="npm", name="pending"),
    )
    head = _commit(repository, "incomplete upstream during bootstrap")
    monkeypatch.setattr(
        openssf_catalog, "sync_official_repository", lambda _paths: (repository, head)
    )
    assert catalog_runner()["commit"] == bootstrap


def test_unrecognized_bad_id_remains_an_ordinary_catalog_failure(
    database, catalog_runner, monkeypatch
):
    from .test_openssf_git import _commit, _record, _write_record

    catalog_runner()
    repository, _ = openssf_catalog.sync_official_repository(None)
    _write_record(
        repository,
        "osv/malicious/npm/pending/NOT-AN-ID.json",
        _record("NOT-AN-ID", ecosystem="npm", name="pending"),
    )
    candidate = _commit(repository, "malformed identity")
    monkeypatch.setattr(
        openssf_catalog, "sync_official_repository", lambda _paths: (repository, candidate)
    )
    with pytest.raises(openssf_catalog.OpenSSFGitError):
        catalog_runner()
    with Session(database.engine) as session:
        assert len(openssf_catalog._latest_complete_pair(session)) == 2


def test_database_drift_forces_full_reconciliation_with_only_changed_evidence(
    database, catalog_runner
):
    catalog_runner()
    with Session(database.engine) as session, session.begin():
        _append(session, "MAL-2026-100", packages=2)
    result = catalog_runner()
    assert result["full_verification"] and result["parsed_record_count"] == 3
    assert result["physical_page_count"] == result["created_revision_count"] == 1
    assert result["package_entry_count"] == 3
    assert catalog_runner()["physical_page_count"] == 0


def test_unchanged_catalog_still_checks_current_collection_authorization(
    catalog_runner, monkeypatch
):
    catalog_runner()

    def deny(*_args, **_kwargs):
        raise openssf_catalog.OpenSSFCatalogError("synthetic collection policy refused")

    monkeypatch.setattr(openssf_catalog.SourceGovernancePolicy, "authorize_collection", deny)
    with pytest.raises(openssf_catalog.OpenSSFCatalogError, match="policy refused"):
        catalog_runner()


@pytest.mark.parametrize("rows", [[], [["a", "b"]], [{"z": "\u00e9", "a": [1, None]}, []]])
def test_streamed_manifest_digest_preserves_canonical_bytes(rows):
    from smithguard.identifiers import canonical_json_bytes, sha256_id

    assert openssf_catalog._array_digest(iter(rows)) == sha256_id(canonical_json_bytes(rows))


def test_tree_manifest_streaming_preserves_historical_identity(tmp_path):
    from smithguard.identifiers import canonical_json_bytes, sha256_id
    from smithguard.openssf_git import LocalOpenSSFGitRepository

    repository, commit, license_sha256 = _repository(tmp_path)
    snapshot = LocalOpenSSFGitRepository(repository).inspect_complete(
        commit, expected_license_sha256=license_sha256
    )
    for tree in (None, "malicious", "withdrawn"):
        rows = [
            {
                "advisory_id": entry.advisory_id,
                "blob_oid": entry.blob_oid,
                "byte_count": entry.byte_count,
                "ecosystem": entry.ecosystem,
                "package_path": entry.package_path,
                "path": entry.path,
                "source_state": entry.source_state,
            }
            for entry in snapshot.entries
            if tree is None or entry.source_tree == tree
        ]
        assert openssf_catalog._tree_manifest(snapshot, tree) == sha256_id(
            canonical_json_bytes(rows)
        )


def test_marker_write_failure_keeps_committed_complete_proof(
    database, catalog_runner, monkeypatch, capsys
):
    def fail(*_args, **_kwargs):
        raise OSError("synthetic marker write failure")

    monkeypatch.setattr(openssf_catalog, "atomic_write", fail)
    result = catalog_runner()
    assert result["status"] == "complete"
    assert "verification_marker_write_failed" in capsys.readouterr().err
    with Session(database.engine) as session:
        assert len(openssf_catalog._latest_complete_pair(session)) == 2
        assert not session.scalars(
            select(AdvisoryCatalogManifestRecord).where(
                AdvisoryCatalogManifestRecord.state == "failed"
            )
        ).all()
    assert catalog_runner()["full_verification"] is True


def test_semantic_page_invalid_number_keeps_classified_error():
    from smithguard.identifiers import strict_json_loads

    projected = strict_json_loads('{"affected":[{"database_specific":{"number":1e400}}]}')
    with pytest.raises(openssf_catalog.OpenSSFCatalogError, match="invalid JSON number"):
        list(openssf_catalog._semantic_pages([SimpleNamespace(projected=projected)]))


def test_catalog_lock_wait_obeys_page_and_run_deadlines(catalog_runner, monkeypatch):
    from contextlib import contextmanager

    waits = []
    original = openssf_catalog.LocalImmutableEvidenceStore.collection_lock

    @contextmanager
    def observe(store, *, timeout_seconds):
        waits.append(timeout_seconds)
        with original(store, timeout_seconds=timeout_seconds):
            yield

    monkeypatch.setenv("SMITHGUARD_OPENSSF_TIMEOUT_SECONDS", "600")
    monkeypatch.setattr(openssf_catalog.LocalImmutableEvidenceStore, "collection_lock", observe)
    assert catalog_runner()["status"] == "complete"
    assert 0 < waits[0] <= 240
    assert len(waits) > 1 and all(0 < wait <= 180 for wait in waits[1:])


def test_catalog_runner_writes_real_success_and_failure_health(
    catalog_runner, monkeypatch, tmp_path
):
    import os

    from smithguard import catalog_health

    parent = tmp_path / "health"
    parent.mkdir(mode=0o700)
    parent.chmod(0o2750)
    path = parent / "openssf.json"
    openssf_catalog._state_root().chmod(0o700)
    monkeypatch.setattr(
        catalog_health.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getegid())
    )
    monkeypatch.setattr(
        catalog_health.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.geteuid())
    )
    monkeypatch.setattr(openssf_catalog, "CATALOG_HEALTH_PATH", path)
    monkeypatch.setenv(catalog_health.CATALOG_HEALTH_VARIABLE, str(path))
    catalog_runner()
    success = catalog_health.load_catalog_health(path)
    assert success["healthy"] and success["record_count"] > 0

    def failed(*args):
        raise RuntimeError("synthetic acquisition failure")

    monkeypatch.setattr(openssf_catalog, "sync_official_repository", failed)
    with pytest.raises(RuntimeError, match="acquisition failure"):
        catalog_runner()
    failure = catalog_health.load_catalog_health(path)
    # One failed attempt while the last complete snapshot is fresh is degraded, not a
    # source failure: the served data is still inside its freshness window.
    assert success["status"] == "success"
    assert failure["healthy"] and failure["status"] == "degraded"
    assert failure["last_success_at"] == success["last_success_at"]
    assert failure["record_count"] == success["record_count"]


@pytest.mark.parametrize("primary", [False, True])
@pytest.mark.parametrize("fault", ["writer", "database"])
def test_catalog_health_failure_keeps_original_error(
    catalog_runner, monkeypatch, tmp_path, capsys, primary, fault
):
    monkeypatch.setattr(openssf_catalog, "CATALOG_HEALTH_PATH", tmp_path / "health.json")
    monkeypatch.setenv(openssf_catalog.CATALOG_HEALTH_VARIABLE, str(tmp_path / "health.json"))

    def collect(*args):
        if primary:
            raise RuntimeError("original acquisition failure")
        return {"synthetic": True}

    def failed(*args, **kwargs):
        raise ValueError("receipt unavailable")

    monkeypatch.setattr(openssf_catalog, "_collect_openssf_catalog", collect)
    monkeypatch.setattr(openssf_catalog, "_attempt", lambda *args: None)
    if fault == "writer":
        monkeypatch.setattr(openssf_catalog, "write_catalog_health", failed)
    else:
        monkeypatch.setattr(openssf_catalog, "_latest_complete_pair", failed)
    with pytest.raises(
        RuntimeError if primary else ValueError,
        match="original acquisition" if primary else "receipt unavailable",
    ):
        catalog_runner()
    assert "collection_diagnostic:catalog_health_receipt_failed" in capsys.readouterr().err


def test_catalog_receipt_override_refuses_before_loading_runtime(monkeypatch):
    monkeypatch.setenv(openssf_catalog.CATALOG_HEALTH_VARIABLE, "/tmp/wrong-receipt.json")
    monkeypatch.setattr(
        openssf_catalog, "load_runtime_config", lambda **kw: pytest.fail("runtime loaded")
    )
    with pytest.raises(openssf_catalog.CatalogHealthError, match="fixed boundary"):
        openssf_catalog.collect_openssf_catalog()


def test_complete_tree_accounts_for_untyped_record_and_preserves_exact_correction(
    database,
    catalog_runner,
    monkeypatch,
):
    from smithguard.coverage import build_coverage_report
    from smithguard.source_accounting import catalog_omissions

    from .test_openssf_git import _commit, _record, _write_record

    catalog_runner()
    repository, _ = openssf_catalog.sync_official_repository(None)
    path = "osv/malicious/future/example/MAL-2026-199.json"
    record = _record("MAL-2026-199", ecosystem="Future", name="example")
    _write_record(repository, path, record)
    commit = _commit(repository, "valid unknown ecosystem")
    monkeypatch.setattr(openssf_catalog, "sync_official_repository", lambda _: (repository, commit))
    result = catalog_runner()
    assert result["record_count"] == 4
    assert result["package_entry_count"] == 3
    assert result["unsupported_ecosystem_count"] == 1
    assert result["package_omission_counts"] == {"untyped_upstream_ecosystem": 1}
    assert catalog_runner()["package_omission_counts"] == result["package_omission_counts"]
    with Session(database.engine) as session:
        before = catalog_omissions(session, source="openssf")
        assert len(before["records"]) == 1
        report = build_coverage_report(session, measured_at=datetime.now(UTC))
        lane = next(
            row for row in report.source_lanes if row.record_type == "malicious_package_catalog"
        )
        assert lane.state == "complete"
        assert any("1 latest retained OpenSSF record(s)" in value for value in lane.unknowns)
    record["affected"][0]["versions"] = ["99.0.0"]
    _write_record(repository, path, record)
    commit = _commit(repository, "unknown coordinate correction")
    result = catalog_runner()
    assert result["created_revision_count"] == 1
    with Session(database.engine) as session:
        after = catalog_omissions(session, source="openssf", limit=1)
        assert after["has_more"]
        second = catalog_omissions(session, source="openssf", limit=1, after=after["next_cursor"])
        assert not second["has_more"]
        assert after["records"][0]["source_sha256"] != second["records"][0]["source_sha256"]
    (repository / path).unlink()
    record["affected"][0]["package"]["ecosystem"] = "npm"
    _write_record(repository, "osv/malicious/npm/example/MAL-2026-199.json", record)
    commit = _commit(repository, "known supported coordinate correction")
    repaired = catalog_runner()
    assert repaired["package_entry_count"] == 4
    assert repaired["unsupported_ecosystem_count"] == 0
    assert repaired["package_omission_counts"] == {}
    with Session(database.engine) as session:
        history = catalog_omissions(session, source="openssf")
        assert len(history["records"]) == 2
        assert all(row["latest_omissions"] == {} for row in history["records"])


def test_full_tree_git_tags_are_omissions_and_malformed_tags_still_fail(
    database,
    catalog_runner,
    monkeypatch,
):
    from smithguard.source_accounting import catalog_omissions

    from .test_openssf_git import _commit, _record, _write_record

    catalog_runner()
    repository, _ = openssf_catalog.sync_official_repository(None)
    path = "osv/malicious/git/example/MAL-2026-198.json"
    record = _record("MAL-2026-198", ecosystem="git", name="example")
    record["affected"] = [
        {
            "versions": ["release-2026", "v1.0"],
            "ranges": [
                {
                    "type": "GIT",
                    "repo": "https://github.com/example/public",
                    "events": [{"introduced": "0"}],
                }
            ],
        }
    ]
    _write_record(repository, path, record)
    commit = _commit(repository, "git-only tagged source")
    monkeypatch.setattr(openssf_catalog, "sync_official_repository", lambda _: (repository, commit))
    result = catalog_runner()
    assert result["record_count"] == 4 and result["package_entry_count"] == 3
    assert result["unsupported_ecosystem_count"] == 0
    assert result["package_omission_counts"] == {"unsupported_git_coordinate": 1}
    assert catalog_runner()["package_omission_counts"] == result["package_omission_counts"]
    with Session(database.engine) as session:
        before = catalog_omissions(session, source="openssf")
        assert before["records"][0]["omissions"] == {"unsupported_git_coordinate": 1}
    record["affected"][0]["versions"] = [7]
    _write_record(repository, path, record)
    commit = _commit(repository, "invalid tag type")
    with pytest.raises(ValueError, match="exact version"):
        catalog_runner()
    with Session(database.engine) as session:
        assert catalog_omissions(session, source="openssf") == before


def test_known_git_ecosystem_keeps_exact_path_case(catalog_runner, monkeypatch):
    from smithguard.openssf_git import OpenSSFGitError

    from .test_openssf_git import _commit, _record, _write_record

    catalog_runner()
    repository, _ = openssf_catalog.sync_official_repository(None)
    record = _record("MAL-2026-197", ecosystem="GIT", name="example")
    _write_record(repository, "osv/malicious/git/example/MAL-2026-197.json", record)
    commit = _commit(repository, "miscased known git label")
    monkeypatch.setattr(openssf_catalog, "sync_official_repository", lambda _: (repository, commit))
    with pytest.raises(OpenSSFGitError, match="path and affected package differ"):
        catalog_runner()
