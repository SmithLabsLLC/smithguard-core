"""Real local locks and transactions protect concurrent evidence collection."""

from __future__ import annotations

import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

import smithguard.evidence as evidence_module
from smithguard import openssf_catalog, reconciliation_runtime, runtime
from smithguard.db.models import EvidenceFinalizationRecord
from smithguard.evidence import (
    EvidenceCollectionBusy,
    EvidenceIntegrityError,
    LocalImmutableEvidenceStore,
    UnsafeEvidencePath,
)
from smithguard.evidence_finalization import register_evidence_stage
from smithguard.identifiers import stable_id


def _hold_process_lock(root: str, connection) -> None:
    store = LocalImmutableEvidenceStore(Path(root))
    try:
        with store.collection_lock():
            connection.send("locked")
            connection.recv()
    finally:
        store.close()
        connection.close()


def test_collection_lock_coordinates_processes_and_releases_after_process_death(tmp_path):
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(target=_hold_process_lock, args=(str(store.root), child))
    process.start()
    child.close()
    try:
        assert parent.poll(10)
        assert parent.recv() == "locked"
        with (
            pytest.raises(TimeoutError, match="lock wait exceeded"),
            store.collection_lock(timeout_seconds=0.05),
        ):
            pytest.fail("a second process entered the protected work")
        process.terminate()
        process.join(10)
        assert not process.is_alive()
        with store.collection_lock(timeout_seconds=1):
            assert list(store.root.iterdir()) == []
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        parent.close()
        store.close()


def test_same_store_lock_is_independent_and_exceptions_release_it(tmp_path):
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    try:
        with (
            pytest.raises(ValueError, match="synthetic transaction failure"),
            store.collection_lock(),
        ):
            with pytest.raises(TimeoutError), store.collection_lock(timeout_seconds=0):
                pytest.fail("same-store acquisition bypassed the lock")
            raise ValueError("synthetic transaction failure")
        with store.collection_lock(timeout_seconds=0):
            assert list(store.root.iterdir()) == []
    finally:
        store.close()


@pytest.mark.parametrize("timeout", [-1, 301, float("inf"), float("nan"), True])
def test_collection_lock_rejects_invalid_timeout(tmp_path, timeout):
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    try:
        with pytest.raises(ValueError), store.collection_lock(timeout_seconds=timeout):
            pytest.fail("invalid timeout accepted")
    finally:
        store.close()


@pytest.mark.parametrize(
    ("mutation", "error_type"),
    [
        ("replace", UnsafeEvidencePath),
        ("symlink", UnsafeEvidencePath),
        ("permissions", PermissionError),
        ("closed", EvidenceIntegrityError),
    ],
)
def test_collection_lock_rejects_unsafe_or_changed_root(tmp_path, mutation, error_type):
    root = tmp_path / "evidence"
    store = LocalImmutableEvidenceStore(root)
    if mutation in {"replace", "symlink"}:
        root.rename(tmp_path / "previous")
        if mutation == "replace":
            root.mkdir(mode=0o700)
        else:
            root.symlink_to(tmp_path / "previous", target_is_directory=True)
    elif mutation == "permissions":
        root.chmod(0o777)
    else:
        store.close()
    try:
        with (
            pytest.raises(error_type),
            store.collection_lock(timeout_seconds=0),
        ):
            pytest.fail("unsafe root accepted")
    finally:
        store.close()


@pytest.mark.parametrize("mutation", ["replace", "permissions"])
def test_collection_lock_revalidates_root_after_wait_and_releases_on_refusal(
    tmp_path, monkeypatch, mutation
):
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    original_flock = evidence_module.fcntl.flock
    changed = False

    def change_after_grant(descriptor, operation):
        nonlocal changed
        result = original_flock(descriptor, operation)
        if not changed:
            changed = True
            if mutation == "replace":
                store.root.rename(tmp_path / "previous")
                store.root.mkdir(mode=0o700)
            else:
                store.root.chmod(0o777)
        return result

    monkeypatch.setattr(evidence_module.fcntl, "flock", change_after_grant)
    try:
        error = UnsafeEvidencePath if mutation == "replace" else PermissionError
        with pytest.raises(error), store.collection_lock(timeout_seconds=0):
            pytest.fail("changed root accepted after locking")
        if mutation == "replace":
            store.root.rmdir()
            (tmp_path / "previous").rename(store.root)
        else:
            store.root.chmod(0o700)
        with store.collection_lock(timeout_seconds=0):
            pass
    finally:
        store.close()


def test_timed_out_waiter_cannot_enter_and_releases_its_late_grant(tmp_path, monkeypatch):
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    grant = Event()
    closed = Event()
    original_close = evidence_module.os.close
    original_flock = evidence_module.fcntl.flock
    waiter_fd = []

    def observe_flock(descriptor, operation):
        if operation == evidence_module.fcntl.LOCK_EX:
            waiter_fd.append(descriptor)
            original_flock(descriptor, operation)
            grant.set()
            return None
        return original_flock(descriptor, operation)

    def observe_close(descriptor):
        result = original_close(descriptor)
        if descriptor in waiter_fd:
            closed.set()
        return result

    monkeypatch.setattr(evidence_module.fcntl, "flock", observe_flock)
    monkeypatch.setattr(evidence_module.os, "close", observe_close)
    try:
        with store.collection_lock():
            with pytest.raises(EvidenceCollectionBusy), store.collection_lock(timeout_seconds=0.1):
                pytest.fail("expired acquisition entered collection")
            assert waiter_fd and not grant.is_set()
        assert grant.wait(5)
        assert closed.wait(5)
        with store.collection_lock(timeout_seconds=0):
            pass
    finally:
        store.close()


def test_multiple_kernel_waiters_progress_during_repeated_acquisition(tmp_path, monkeypatch):
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    ready = Event()
    guard = Lock()
    waiting = 0
    original_flock = evidence_module.fcntl.flock

    def queued_flock(descriptor, operation):
        nonlocal waiting
        if operation == evidence_module.fcntl.LOCK_EX:
            with guard:
                waiting += 1
                if waiting == 3:
                    ready.set()
        return original_flock(descriptor, operation)

    def collect_page():
        with store.collection_lock(timeout_seconds=5):
            return "collected"

    monkeypatch.setattr(evidence_module.fcntl, "flock", queued_flock)
    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            with store.collection_lock():
                futures = [executor.submit(collect_page) for _ in range(3)]
                assert ready.wait(5)
            for _ in range(20):
                with store.collection_lock(timeout_seconds=5):
                    pass
            assert [future.result(timeout=5) for future in futures] == ["collected"] * 3
    finally:
        store.close()


def _config(database, tmp_path):
    return runtime.RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=runtime.DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=runtime.DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=runtime.DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
    )


def _register(session, store, body=b"synthetic concurrent public evidence"):
    stage = store.stage_bytes(body)
    register_evidence_stage(
        session,
        store=store,
        stage=stage,
        evidence_id=stable_id("evidence", stage.digest),
        staged_at=datetime.now(UTC),
    )
    return stage


def _assert_locked(store):
    with pytest.raises(TimeoutError), store.collection_lock(timeout_seconds=0):
        pytest.fail("evidence transaction released its lock too early")


def test_flush_cleanup_holds_collection_lock_until_a_second_writer_can_reuse_digest(
    database, tmp_path
):
    from tests.test_evidence_finalization import server_failure

    cleanup_started, allow_cleanup, second_entered = Event(), Event(), Event()

    class ObservedStore(LocalImmutableEvidenceStore):
        def discard_stage(self, stage):
            _assert_locked(self)
            cleanup_started.set()
            assert allow_cleanup.wait(5)
            super().discard_stage(stage)

    writer = ObservedStore(tmp_path / "evidence")
    second = LocalImmutableEvidenceStore(writer.root)
    body = b"shared synthetic public retry bytes"

    def failing_writer():
        with (
            pytest.raises(OperationalError),
            writer.collection_lock(),
            Session(database.engine) as session,
            session.begin(),
        ):
            _register(session, writer, body)
            _register(session, writer, b"second interrupted stage")

    def next_writer():
        with (
            second.collection_lock(timeout_seconds=5),
            Session(database.engine) as session,
            session.begin(),
        ):
            second_entered.set()
            return _register(session, second, body)

    try:
        with (
            server_failure(
                database.engine, "insert into smithguard.evidence_finalizations", occurrence=2
            ),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(failing_writer)
            assert cleanup_started.wait(5)
            next_run = executor.submit(next_writer)
            assert not second_entered.wait(0.1)
            allow_cleanup.set()
            first.result(timeout=5)
            stage = next_run.result(timeout=5)
        assert second_entered.is_set()
        assert second.pending_manifest() == []
        assert second.read_bytes(stage.digest) == body
        with Session(database.engine) as session:
            records = list(session.scalars(select(EvidenceFinalizationRecord)))
            assert len(records) == 1 and records[0].state == "finalized"
    finally:
        allow_cleanup.set()
        writer.close()
        second.close()


def _patch_entry(monkeypatch, entry, database, tmp_path, store_type):
    module = {
        "github": runtime,
        "openssf": openssf_catalog,
        "range": reconciliation_runtime,
    }[entry]
    config = _config(database, tmp_path)
    monkeypatch.setattr(module, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(module, "LocalImmutableEvidenceStore", store_type)
    if entry == "github":
        monkeypatch.setattr(runtime, "_github_token", lambda _path: None)

        class Collector:
            def __init__(self, **_kwargs):
                pass

            def run(self, _session, **_kwargs):
                return SimpleNamespace(
                    page_processed=False,
                    page_source_record_count=0,
                    page_normalized_record_count=0,
                    state="complete",
                )

        monkeypatch.setattr(runtime, "GitHubAdvisoryRestCollector", Collector)
        return runtime.collect_main
    if entry == "openssf":
        (tmp_path / "catalog").mkdir(mode=0o700, exist_ok=True)
        monkeypatch.setattr(openssf_catalog, "_state_root", lambda: tmp_path / "catalog")

        def stop_before_network(_paths):
            raise ReachedNetworkBoundary

        monkeypatch.setattr(openssf_catalog, "sync_official_repository", stop_before_network)

        def run_openssf():
            with pytest.raises(ReachedNetworkBoundary):
                openssf_catalog.collect_openssf_catalog()
            return 0

        return run_openssf
    monkeypatch.setattr(reconciliation_runtime, "_github_token", lambda: None)

    class RangeCollector:
        def __init__(self, **_kwargs):
            raise ReachedNetworkBoundary

    monkeypatch.setattr(reconciliation_runtime, "GitHubAdvisoryRestCollector", RangeCollector)

    def run_range():
        arguments = reconciliation_runtime._parser().parse_args(
            ["github-range-backfill", "--advisory-id", "GHSA-aaaa-bbbb-1111", "--commit"]
        )
        with pytest.raises(ReachedNetworkBoundary):
            reconciliation_runtime._range_backfill_main(arguments)
        return 0

    return run_range


class ReachedNetworkBoundary(Exception):
    """Stop after real precheck without calling a source."""


@pytest.mark.parametrize("entry", ["github", "openssf", "range"])
@pytest.mark.parametrize("outcome", ["commit", "rollback"])
def test_collectors_wait_for_live_transaction_before_global_inspection(
    database, tmp_path, monkeypatch, entry, outcome
):
    writer = LocalImmutableEvidenceStore(tmp_path / "evidence", allow_group_read=True)
    attempted = Event()

    class ObservedStore(LocalImmutableEvidenceStore):
        @contextmanager
        def collection_lock(self, **kwargs):
            attempted.set()
            with super().collection_lock(**kwargs):
                yield

    collect = _patch_entry(monkeypatch, entry, database, tmp_path, ObservedStore)
    with ThreadPoolExecutor(max_workers=1) as executor:
        try:
            with writer.collection_lock(), Session(database.engine) as session, session.begin():
                _register(session, writer)
                future = executor.submit(collect)
                assert attempted.wait(5)
                with pytest.raises(FutureTimeout):
                    future.result(timeout=0.1)
                assert len(writer.pending_manifest()) == 1
                if outcome == "rollback":
                    session.rollback()
            assert future.result(timeout=10) == 0
            assert writer.pending_manifest() == []
            assert len(writer.manifest()) == (1 if outcome == "commit" else 0)
            with Session(database.engine) as session:
                rows = list(session.scalars(select(EvidenceFinalizationRecord)))
                assert len(rows) == (1 if outcome == "commit" else 0)
                assert all(row.state == "finalized" for row in rows)
        finally:
            writer.close()


def test_github_page_holds_lock_through_after_commit_and_releases_between_pages(
    database, tmp_path, monkeypatch
):
    probe = LocalImmutableEvidenceStore(tmp_path / "evidence", allow_group_read=True)
    calls = []
    acquisitions = []
    finalized = []

    class ObservedStore(LocalImmutableEvidenceStore):
        @contextmanager
        def collection_lock(self, **kwargs):
            # A new acquisition must find the preceding page fully unlocked.
            with probe.collection_lock(timeout_seconds=0):
                acquisitions.append("entered")
            with super().collection_lock(**kwargs):
                yield

        def finalize_stage(self, stage):
            _assert_locked(probe)
            finalized.append(stage.digest)
            return super().finalize_stage(stage)

    _patch_entry(monkeypatch, "github", database, tmp_path, ObservedStore)

    class Collector:
        def __init__(self, *, evidence_store, **_kwargs):
            self.store = evidence_store

        def run(self, session, **_kwargs):
            _assert_locked(probe)
            calls.append("page")
            _register(session, self.store, f"synthetic page {len(calls)}".encode())
            return SimpleNamespace(
                page_processed=True,
                page_source_record_count=1,
                page_normalized_record_count=0,
                state="complete",
            )

    monkeypatch.setattr(runtime, "GitHubAdvisoryRestCollector", Collector)
    try:
        assert runtime.collect_main() == 0
        assert len(calls) == len(finalized) == 6
        assert len(acquisitions) == 7
        with probe.collection_lock(timeout_seconds=0):
            assert probe.pending_manifest() == []
    finally:
        probe.close()


def test_github_rate_limit_wait_releases_collection_lock(database, tmp_path, monkeypatch):
    probe = LocalImmutableEvidenceStore(tmp_path / "evidence", allow_group_read=True)
    _patch_entry(monkeypatch, "github", database, tmp_path, LocalImmutableEvidenceStore)
    monkeypatch.setenv("SMITHGUARD_GITHUB_RATE_LIMIT_WAIT", "1")
    calls = []
    waits = []

    class Collector:
        def __init__(self, **_kwargs):
            pass

        def run(self, _session, **_kwargs):
            calls.append("called")
            return SimpleNamespace(
                page_processed=False,
                page_source_record_count=0,
                page_normalized_record_count=0,
                state="failed" if len(calls) == 1 else "complete",
                reason_code="github_rate_limited",
                not_before=datetime.now(UTC) + timedelta(seconds=60),
            )

    def wait(seconds):
        with probe.collection_lock(timeout_seconds=0):
            waits.append(seconds)

    monkeypatch.setattr(runtime, "GitHubAdvisoryRestCollector", Collector)
    monkeypatch.setattr(runtime.time, "sleep", wait)
    try:
        assert runtime.collect_main() == 0
        assert len(calls) == 7
        assert len(waits) == 1 and 0 < waits[0] <= 60
    finally:
        probe.close()


@pytest.mark.parametrize("entry", ["github", "openssf", "range"])
def test_entrypoints_report_only_fixed_contention_diagnostics(
    database, tmp_path, monkeypatch, capsys, entry
):
    class BusyStore(LocalImmutableEvidenceStore):
        @contextmanager
        def collection_lock(self, **kwargs):
            raise EvidenceCollectionBusy("synthetic private exception detail")
            yield

    _patch_entry(monkeypatch, entry, database, tmp_path, BusyStore)
    if entry == "github":
        result = runtime.collect_main()
        diagnostic = "runtime_error:collection_failed stage=evidence_coordination_timeout\n"
    elif entry == "openssf":
        result = openssf_catalog.main()
        diagnostic = "runtime_error:openssf_catalog_failed reason=evidence_coordination_timeout\n"
    else:
        result = reconciliation_runtime.main(
            ["github-range-backfill", "--advisory-id", "GHSA-aaaa-bbbb-1111"]
        )
        diagnostic = "reconciliation_error:evidence_coordination_timeout\n"
    assert result == 3
    captured = capsys.readouterr()
    assert captured.err == diagnostic
    if entry == "openssf":
        assert captured.out.startswith("openssf_catalog_resources ")
        assert len(captured.out.splitlines()) == 1
        fields = dict(value.split("=", 1) for value in captured.out.split()[1:])
        assert fields.pop("cgroup_peak_status") in {
            "measured",
            "unavailable",
            "not_catalog_service",
        }
        peak = fields.pop("cgroup_peak_bytes")
        assert peak == "None" or (peak.isdecimal() and int(peak) > 0)
        assert set(fields) == {
            "children_peak_rss_bytes",
            "conservative_process_peak_bytes",
            "elapsed_seconds",
            "self_peak_rss_bytes",
        }
        assert all(float(value) >= 0 for value in fields.values())
    else:
        assert captured.out == ""


@pytest.mark.parametrize("entry", ["openssf", "range"])
@pytest.mark.parametrize("outcome", ["commit", "rollback"])
def test_other_collectors_hold_lock_through_finalization_or_rollback(
    database, tmp_path, monkeypatch, entry, outcome
):
    probe = LocalImmutableEvidenceStore(tmp_path / "evidence", allow_group_read=True)
    finished = []

    class ObservedStore(LocalImmutableEvidenceStore):
        def finalize_stage(self, stage):
            _assert_locked(probe)
            finished.append("commit")
            return super().finalize_stage(stage)

        def discard_stage(self, stage):
            _assert_locked(probe)
            finished.append("rollback")
            return super().discard_stage(stage)

    _patch_entry(monkeypatch, entry, database, tmp_path, ObservedStore)

    class Collector:
        def __init__(self, *, evidence_store, **_kwargs):
            self.store = evidence_store

        def backfill_advisory(self, session, **_kwargs):
            _assert_locked(probe)
            _register(session, self.store)
            return SimpleNamespace(
                collection=SimpleNamespace(outcome=SimpleNamespace(record_count=1)),
                scope_exclusion_reasons=(),
            )

        def run_public(self, session, **_kwargs):
            self.backfill_advisory(session)
            return SimpleNamespace(
                outcome=SimpleNamespace(
                    outcome="accepted",
                    raw_evidence_id="synthetic",
                    governance_decision_id="synthetic",
                )
            )

    try:
        if entry == "range":
            monkeypatch.setattr(reconciliation_runtime, "GitHubAdvisoryRestCollector", Collector)
            monkeypatch.setattr(
                reconciliation_runtime, "publish_github_malware_incidents", lambda *a, **k: ()
            )
            arguments = ["github-range-backfill", "--advisory-id", "GHSA-aaaa-bbbb-1111"]
            if outcome == "commit":
                arguments.append("--commit")
            assert (
                reconciliation_runtime._range_backfill_main(
                    reconciliation_runtime._parser().parse_args(arguments)
                )
                == 0
            )
        else:
            entry_row = SimpleNamespace(
                advisory_id="MAL-2026-1",
                blob_oid="a" * 40,
                byte_count=2,
                ecosystem="npm",
                package_path="npm/synthetic",
                path="malicious/npm/synthetic/MAL-2026-1.json",
                source_state="active",
                source_tree="malicious",
                canonical_url="https://example.test/synthetic",
            )

            class Reader:
                def __init__(self, _path):
                    pass

                def inspect_complete(self, *_args, **_kwargs):
                    return SimpleNamespace(
                        entries=[entry_row],
                        ignored_nonrecord_count=0,
                        unsupported_counts=(),
                        skipped_counts=(),
                    )

                def commit_time(self, _commit):
                    return datetime.now(UTC)

                def read_blobs(self, _entries):
                    return [b"{}"]

                def parse_record(self, entry, _body):
                    return openssf_catalog.OpenSSFRecord(entry, b"{}", {}, None, None)

            def append(*_args, **_kwargs):
                if outcome == "rollback":
                    raise openssf_catalog.OpenSSFCatalogError("synthetic append rejection")
                return SimpleNamespace(package_entry_count=1, created=True, source_sha256="a" * 64)

            monkeypatch.setattr(
                openssf_catalog,
                "sync_official_repository",
                lambda _paths: (tmp_path / "synthetic-git", "b" * 40),
            )
            monkeypatch.setattr(
                openssf_catalog, "openssf_advisory_identity", lambda *_a, **_k: ("a" * 64, 1)
            )
            monkeypatch.setattr(openssf_catalog, "LocalOpenSSFGitRepository", Reader)
            monkeypatch.setattr(openssf_catalog, "ensure_commit_available", lambda *_a, **_k: None)
            monkeypatch.setattr(openssf_catalog, "CollectorRunner", Collector)
            monkeypatch.setattr(openssf_catalog, "append_openssf_advisory", append)
            # The synthetic append intentionally leaves no catalog projection;
            # commit must finalize before the unchanged final count check refuses it.
            reason = "database identity" if outcome == "commit" else "synthetic append rejection"
            with pytest.raises(openssf_catalog.OpenSSFCatalogError, match=reason):
                openssf_catalog.collect_openssf_catalog()
        assert finished == [outcome]
        with probe.collection_lock(timeout_seconds=0):
            assert probe.pending_manifest() == []
            assert len(probe.manifest()) == (1 if outcome == "commit" else 0)
    finally:
        probe.close()


@pytest.mark.parametrize("entry", ["openssf", "range"])
def test_ingest_runs_refuse_completion_after_a_post_commit_finalization_failure(
    database, tmp_path, monkeypatch, entry
):
    from smithguard.evidence_finalization import EvidenceFinalizationError

    _patch_entry(monkeypatch, entry, database, tmp_path, LocalImmutableEvidenceStore)

    def fail_finalization(_store, _stage):
        raise OSError("raw finalization exception must remain private")

    monkeypatch.setattr(LocalImmutableEvidenceStore, "finalize_stage", fail_finalization)

    class Collector:
        def __init__(self, *, evidence_store, **_kwargs):
            self.store = evidence_store

        def backfill_advisory(self, session, **_kwargs):
            _register(session, self.store)
            return SimpleNamespace(
                collection=SimpleNamespace(outcome=SimpleNamespace(record_count=1)),
                scope_exclusion_reasons=(),
            )

        def run_public(self, session, **_kwargs):
            self.backfill_advisory(session)
            return SimpleNamespace(
                outcome=SimpleNamespace(
                    outcome="accepted",
                    raw_evidence_id="synthetic",
                    governance_decision_id="synthetic",
                )
            )

    if entry == "range":
        monkeypatch.setattr(reconciliation_runtime, "GitHubAdvisoryRestCollector", Collector)
        monkeypatch.setattr(
            reconciliation_runtime, "publish_github_malware_incidents", lambda *a, **k: ()
        )
        arguments = reconciliation_runtime._parser().parse_args(
            ["github-range-backfill", "--advisory-id", "GHSA-aaaa-bbbb-1111", "--commit"]
        )
        with pytest.raises(EvidenceFinalizationError, match="require reconciliation"):
            reconciliation_runtime._range_backfill_main(arguments)
    else:
        entry_row = SimpleNamespace(
            advisory_id="MAL-2026-1",
            blob_oid="a" * 40,
            byte_count=2,
            ecosystem="npm",
            package_path="npm/synthetic",
            path="malicious/npm/synthetic/MAL-2026-1.json",
            source_state="active",
            source_tree="malicious",
            canonical_url="https://example.test/synthetic",
        )

        class Reader:
            def __init__(self, _path):
                pass

            def inspect_complete(self, *_args, **_kwargs):
                return SimpleNamespace(
                    entries=[entry_row],
                    ignored_nonrecord_count=0,
                    unsupported_counts=(),
                    skipped_counts=(),
                )

            def commit_time(self, _commit):
                return datetime.now(UTC)

            def read_blobs(self, _entries):
                return [b"{}"]

            def parse_record(self, entry, _body):
                return openssf_catalog.OpenSSFRecord(entry, b"{}", {}, None, None)

        manifests = []
        monkeypatch.setattr(
            openssf_catalog,
            "sync_official_repository",
            lambda _paths: (tmp_path / "synthetic-git", "b" * 40),
        )
        monkeypatch.setattr(
            openssf_catalog, "openssf_advisory_identity", lambda *_a, **_k: ("a" * 64, 1)
        )
        monkeypatch.setattr(openssf_catalog, "LocalOpenSSFGitRepository", Reader)
        monkeypatch.setattr(openssf_catalog, "ensure_commit_available", lambda *_a, **_k: None)
        monkeypatch.setattr(openssf_catalog, "CollectorRunner", Collector)
        monkeypatch.setattr(
            openssf_catalog,
            "append_openssf_advisory",
            lambda *_a, **_k: SimpleNamespace(
                package_entry_count=1, created=True, source_sha256="a" * 64
            ),
        )
        monkeypatch.setattr(
            openssf_catalog,
            "append_catalog_manifest",
            lambda *_a, **k: manifests.append(k),
        )
        with pytest.raises(EvidenceFinalizationError, match="require reconciliation"):
            openssf_catalog.collect_openssf_catalog()
        assert [row["state"] for row in manifests] == [
            "in_progress",
            "in_progress",
            "failed",
            "failed",
        ]
    # The committed rows and the failed finalization record are durable for reconcile.
    with Session(database.engine) as session:
        record = session.scalar(select(EvidenceFinalizationRecord))
        assert record is not None and record.state == "failed"


def _stage_then_wait_for_hard_kill(root, database_url, pipe):
    from sqlalchemy import create_engine

    engine = create_engine(database_url)
    store = LocalImmutableEvidenceStore(Path(root))
    with store.collection_lock(), Session(engine) as session, session.begin():
        stage = _register(session, store, b"synthetic hard-kill orphan")
        session.flush()
        pipe.send((stage.digest, stage.byte_count))
        pipe.recv()


def test_hard_kill_rolls_back_db_blocks_collectors_and_preserves_orphan_in_quarantine(
    database,
    tmp_path,
    monkeypatch,
):
    import signal

    from sqlalchemy.orm import sessionmaker

    from smithguard.evidence_quarantine import quarantine_orphan_stages

    root = tmp_path / "evidence"
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(
        target=_stage_then_wait_for_hard_kill,
        args=(str(root), database.url.render_as_string(hide_password=False), child),
    )
    process.start()
    child.close()
    try:
        assert parent.poll(15)
        digest, size = parent.recv()
        process.kill()
        process.join(10)
        assert process.exitcode == -signal.SIGKILL
        with Session(database.engine) as session:
            assert (
                session.scalar(
                    select(EvidenceFinalizationRecord).where(
                        EvidenceFinalizationRecord.digest == digest
                    )
                )
                is None
            )
        _patch_entry(monkeypatch, "github", database, tmp_path, LocalImmutableEvidenceStore)
        assert runtime.collect_main() == 3
        quarantine = tmp_path / "quarantine"
        quarantine.mkdir(mode=0o700)
        store = LocalImmutableEvidenceStore(root)
        checks = []
        result = quarantine_orphan_stages(
            sessionmaker(database.engine),
            store=store,
            parent=quarantine,
            operation_id="20260924-" + "a" * 32,
            approved={digest: size},
            verify_quiescence=lambda: checks.append(True),
        )
        assert result["status"] == "quarantined" and len(checks) >= 3
        preserved = quarantine / result["operation_id"] / digest.removeprefix("sha256:")
        assert preserved.read_bytes() == b"synthetic hard-kill orphan"
        assert store.pending_manifest() == []
        assert runtime.collect_main() == 0
        store.close()
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        parent.close()


def test_catalog_filesystem_lock_blocks_a_racing_manual_run(
    database, tmp_path, monkeypatch, capsys
):
    from smithguard.openssf_shadow import _exclusive_lock

    _patch_entry(monkeypatch, "openssf", database, tmp_path, LocalImmutableEvidenceStore)
    with _exclusive_lock(tmp_path / "catalog/run.lock"):
        assert openssf_catalog.main() == openssf_catalog.OPENSSF_CATALOG_ALREADY_RUNNING
    assert capsys.readouterr().err == "openssf_catalog_already_running\n"
    with _exclusive_lock(tmp_path / "catalog/run.lock"):
        pass
