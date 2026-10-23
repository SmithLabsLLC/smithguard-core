"""Daily collection uses real migrated storage and controlled public provider fixtures."""

from __future__ import annotations

import gzip
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import smithguard.evidence_finalization as finalization
import smithguard.supplemental_runtime as runtime
from smithguard.cve_enrichment import parse_epss_csv_gzip, parse_kev
from smithguard.db.models import (
    AdvisoryCatalogRecord,
    AdvisoryPackageRecord,
    EvidenceFinalizationRecord,
    EvidenceRecord,
    SupplementalFactRecord,
    SupplementalSnapshotRecord,
)
from smithguard.db.repository import append_contract
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.identifiers import canonical_json_bytes, sha256_id
from smithguard.source_governance import SourceGovernancePolicy
from smithguard.source_rights import RightsRegistry
from smithguard.supplemental_store import (
    EPSS_SOURCE,
    KEV_SOURCE,
    cve_context,
    latest_snapshot,
    snapshot_facts,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 7, 19, tzinfo=UTC)
A, B, C = "CVE-2021-44228", "CVE-2023-34362", "CVE-2026-999999"


def seed_catalog(
    session, aliases, identity="test", *, supported=True, state="active", revision=1, upstream=None
):
    session.add(
        AdvisoryCatalogRecord(
            catalog_event_id="gbsec:catalog-event:" + identity,
            source_id="gbsec:source:github-security-advisories",
            upstream_record_id=upstream or identity,
            revision=revision,
            source_type="reviewed",
            claim_type="vulnerable",
            confidence="confirmed",
            state=state,
            cwe_ids=[],
            aliases=aliases,
            package_omission_counts={},
            canonical_url="https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
            evidence_id="gbsec:evidence:synthetic-catalog",
            governance_decision_id="gbsec:governance:synthetic-catalog",
            source_published_at=NOW,
            source_updated_at=NOW,
            observed_at=NOW,
            source_sha256="sha256:" + "a" * 64,
            record_hash="sha256:" + "b" * 64,
        )
    )

    session.flush()
    if supported:
        session.add(
            AdvisoryPackageRecord(
                package_event_id="gbsec:package-event:" + identity,
                catalog_event_id="gbsec:catalog-event:" + identity,
                source_id="gbsec:source:github-security-advisories",
                upstream_record_id=upstream or identity,
                entry_key="gbsec:entry:" + identity,
                revision=revision,
                ecosystem="npm",
                raw_ecosystem="npm",
                name="synthetic-package",
                exact_versions=["1.0.0"],
                affected_ranges=[],
                state=state,
                claim_type="vulnerable",
                confidence="confirmed",
                source_updated_at=NOW,
                observed_at=NOW,
                source_sha256="sha256:" + "a" * 64,
                record_hash="sha256:" + "b" * 64,
            )
        )


@pytest.fixture
def environment(database, tmp_path, monkeypatch):
    registry = RightsRegistry.from_path(ROOT / "contracts/v1/source-rights-register.json")
    policy = SourceGovernancePolicy.from_path(
        ROOT / "contracts/v1/source-governance-policy.json",
        registry=registry,
    )
    with Session(database.engine) as session, session.begin():
        seed_catalog(session, [A, B, C])
    clock = [NOW]
    monkeypatch.setattr(finalization, "_now", lambda: clock[0])
    store = LocalImmutableEvidenceStore(tmp_path / "evidence", allow_group_read=True)
    original_statvfs = runtime.os.statvfs
    monkeypatch.setattr(
        runtime.os,
        "statvfs",
        lambda path: (
            SimpleNamespace(f_bavail=64 * 1024**3, f_frsize=1, f_favail=100_000)
            if Path(path) == store.root
            else original_statvfs(path)
        ),
    )
    result = {
        "clock": clock,
        "factory": lambda: Session(database.engine),
        "store": store,
        "registry": registry,
        "policy": policy,
    }
    try:
        yield result
    finally:
        result["store"].close()


class Providers:
    def __init__(self):
        self.calls = []
        self.epss_rows = [f"{A},0.99999,1", f"{B},0.99934,0.99971"]
        self.kev_rows = [
            {"cveID": A, "dateAdded": "2021-12-10"},
            {"cveID": B, "dateAdded": "2023-06-02"},
        ]
        self.epss_score_date = None
        self.epss_failure = False
        self.kev_failure = False
        self.kev_released = NOW - timedelta(hours=1)

    def epss(self, requested, *, profile, observed_at):
        score_date = self.epss_score_date or observed_at.date()
        self.calls.append((EPSS_SOURCE, tuple(requested), score_date))
        if self.epss_failure:
            raise RuntimeError("opaque-provider-message-must-not-enter-receipt")
        body = gzip.compress(
            (
                f"#model_version:v2026.06.15,score_date:{score_date}T12:00:00Z\n"
                + "cve,epss,percentile\n"
                + "\n".join(self.epss_rows)
                + "\n"
            ).encode(),
            mtime=0,
        )
        return parse_epss_csv_gzip(
            body,
            requested,
            score_date=score_date,
            observed_at=observed_at,
        )

    def kev(self, *, profile, observed_at):
        self.calls.append((KEV_SOURCE,))
        if self.kev_failure:
            raise RuntimeError("opaque-provider-message-must-not-enter-receipt")
        body = canonical_json_bytes(
            {
                "catalogVersion": self.kev_released.strftime("%Y.%m.%d"),
                "dateReleased": self.kev_released.isoformat(),
                "count": len(self.kev_rows),
                "vulnerabilities": self.kev_rows,
            }
        )
        return parse_kev(body, observed_at=observed_at)


def collect(
    environment,
    providers,
    *,
    mode="public",
    now=NOW,
    sources=(EPSS_SOURCE, KEV_SOURCE),
    retry_failed_snapshot=None,
):
    environment["clock"][0] = now + timedelta(seconds=1)
    return runtime.collect_sources(
        **{key: value for key, value in environment.items() if key != "clock"},
        mode=mode,
        now=now,
        sources=sources,
        fetch_epss=providers.epss,
        fetch_cisa=providers.kev,
        fetch_origin=lambda *args, **kwargs: pytest.fail("unexpected origin provider fetch"),
        retry_failed_snapshot=retry_failed_snapshot,
    )


@pytest.mark.parametrize(
    "failure_statement",
    [
        "insert into smithguard.evidence_finalizations",
        "insert into smithguard.advisory_catalog_records",
        "from smithguard.evidence_finalizations",
    ],
)
def test_go_database_failure_cleans_new_stages_and_preserves_exact_retry(
    environment, database, failure_statement
):
    from smithguard.origin_advisories import parse_go_archive
    from tests.test_evidence_finalization import server_failure
    from tests.test_origin_advisories import archive, document, go_files

    values = [
        document("go", identifier=f"GO-2026-{index:04d}", name=f"example.org/public/module{index}")
        for index in range(1, 4)
    ]
    snapshot = parse_go_archive(archive(go_files(values)), observed_at=NOW)
    calls = []

    def invoke(now, retry=None):
        environment["clock"][0] = now + timedelta(seconds=1)

        def fetch(origin, **kwargs):
            assert origin == "go"
            calls.append(snapshot.transport_sha256)
            return snapshot

        return runtime.collect_sources(
            **{key: value for key, value in environment.items() if key != "clock"},
            mode="public",
            sources=(runtime.GO_SOURCE,),
            now=now,
            fetch_origin=fetch,
            retry_failed_snapshot=retry,
        )

    with server_failure(database.engine, failure_statement, occurrence=3):
        assert invoke(NOW) == {runtime.GO_SOURCE: "failed"}
    store = environment["store"]
    assert store.pending_manifest() == store.manifest() == []
    with environment["factory"]() as session:
        failed = latest_snapshot(session, runtime.GO_SOURCE)
        failed_id, failed_hash = failed.snapshot_id, failed.record_hash
        assert failed.state == "failed" and failed.record_count == 0
        assert failed.document["error_type"] == "OperationalError"
        assert session.scalar(select(EvidenceRecord)) is None
        assert session.scalar(select(EvidenceFinalizationRecord)) is None
        assert (
            session.scalar(
                select(AdvisoryCatalogRecord).where(
                    AdvisoryCatalogRecord.source_id == runtime.GO_SOURCE
                )
            )
            is None
        )
    assert invoke(NOW + timedelta(minutes=1), failed_id) == {runtime.GO_SOURCE: "complete"}
    assert calls == [snapshot.transport_sha256] * 2
    assert store.pending_manifest() == []
    assert len(store.manifest()) == 3
    for blob in store.manifest():
        assert store.verify(blob.digest).byte_count == blob.byte_count
    with environment["factory"]() as session:
        preserved = session.get(SupplementalSnapshotRecord, failed_id)
        assert preserved.state == "failed" and preserved.record_hash == failed_hash
        complete = latest_snapshot(session, runtime.GO_SOURCE)
        assert complete.state == "complete" and complete.record_count == 3
        assert complete.document["retry_of"] == failed_id
        assert session.scalar(select(func.count()).select_from(SupplementalSnapshotRecord)) == 2
        assert set(session.scalars(select(EvidenceFinalizationRecord.state))) == {"finalized"}


def test_known_cves_sql_is_distinct_sorted_and_exact(database):
    with Session(database.engine) as session, session.begin():
        seed_catalog(session, [B, A, A.lower(), A + "-extra", "GHSA-xxxx-yyyy-zzzz"], "one")
        seed_catalog(session, [A, C, "CVE-2021-123", " CVE-2021-44228"], "two")
    with Session(database.engine) as session:
        assert runtime.known_cves(session) == (A, B, C)


def test_shadow_is_private_then_public_matches_and_retained_evidence_reads_back(environment):
    providers = Providers()
    assert collect(environment, providers, mode="shadow") == {
        EPSS_SOURCE: "complete",
        KEV_SOURCE: "complete",
    }
    with environment["factory"]() as session:
        shadow = latest_snapshot(session, EPSS_SOURCE, mode="shadow")
        assert shadow is not None
        context, _ = cve_context(session, [A], now=NOW)
        assert context[0]["epss"]["state"] == "missing"
        assert context[0]["epss"]["value"] is None
        assert context[0]["kev"]["listed"] is None
    assert collect(environment, providers) == {EPSS_SOURCE: "complete", KEV_SOURCE: "complete"}
    with environment["factory"]() as session:
        context, _ = cve_context(session, [A, C], now=NOW)
        assert context[0]["epss"]["value"]["epss"] == "0.99999"
        assert context[0]["epss"]["value"]["model_version"] == "v2026.06.15"
        assert context[0]["kev"]["listed"] is True
        assert context[1]["epss"]["value"] is None
        assert context[1]["kev"]["listed"] is False
        for source in (EPSS_SOURCE, KEV_SOURCE):
            snapshot = latest_snapshot(session, source)
            assert (
                snapshot.document["rights_revision"]
                == environment["registry"].get(source).source["revision"]
            )
            assert snapshot.document["policy_sha256"] == environment["policy"].policy_sha256
            assert snapshot.document["transport_sha256"].startswith("sha256:")
            for evidence_id in snapshot.document["evidence_ids"]:
                row = session.get(EvidenceRecord, (evidence_id, 1))
                assert row.source_id == source
                body = environment["store"].read_bytes(row.storage_key)
                assert sha256_id(body) == row.sha256
                records = json.loads(body)
                expected = (
                    {"cve", "epss", "percentile", "date", "model_version"}
                    if source == EPSS_SOURCE
                    else {"cve", "date_added"}
                )
                if evidence_id in snapshot.document.get("missing_subject_evidence_ids", []):
                    expected = {"cve", "date"}
                assert all(set(record) == expected for record in records)


@pytest.mark.parametrize("gate", ["rights_activation", "governance_disabled"])
def test_rights_refusal_is_durable_and_precedes_provider_fetch(environment, gate):
    if gate == "rights_activation":
        registry = environment["registry"]
        registry._profiles[EPSS_SOURCE] = replace(
            registry.get(EPSS_SOURCE), activation="enrichment_only"
        )
    else:
        document = json.loads((ROOT / "contracts/v1/source-governance-policy.json").read_text())
        for source in document["sources"]:
            if source["source_id"] == EPSS_SOURCE:
                source["enabled"] = False
        environment["policy"] = SourceGovernancePolicy(document, registry=environment["registry"])
    providers = Providers()
    assert collect(environment, providers, sources=(EPSS_SOURCE,)) == {EPSS_SOURCE: "failed"}
    assert providers.calls == []
    with environment["factory"]() as session:
        attempt = latest_snapshot(session, EPSS_SOURCE)
        assert attempt.state == "failed" and attempt.record_count == 0
        assert list(session.scalars(select(EvidenceRecord))) == []


def test_failure_durable_no_fake_zero_and_other_source_still_completes(environment):
    providers = Providers()
    providers.epss_failure = True
    assert collect(environment, providers) == {EPSS_SOURCE: "failed", KEV_SOURCE: "complete"}
    with environment["factory"]() as session:
        result, _ = cve_context(session, [A], now=NOW)
        assert result[0]["epss"]["state"] == "failed" and result[0]["epss"]["value"] is None
        assert result[0]["kev"]["listed"] is True
        failure = latest_snapshot(session, EPSS_SOURCE)
        assert failure.document["error_type"] == "RuntimeError"
        assert "opaque-provider-message" not in json.dumps(failure.document)
    calls = list(providers.calls)
    assert collect(environment, providers, now=NOW + timedelta(minutes=1)) == {
        EPSS_SOURCE: "recent_failed",
        KEV_SOURCE: "not_due",
    }
    assert providers.calls == calls


def test_daily_corrections_removals_and_repeated_payload_reuse_evidence(environment):
    providers = Providers()
    assert all(state == "complete" for state in collect(environment, providers).values())
    with environment["factory"]() as session:
        old_kev = latest_snapshot(session, KEV_SOURCE)
        old_epss = latest_snapshot(session, EPSS_SOURCE)
        _, fingerprint = cve_context(session, [A, B], now=NOW)
        epss_evidence = old_epss.document["evidence_ids"]
    providers.kev_rows = [{"cveID": A, "dateAdded": "2021-12-11"}]
    tomorrow = NOW + timedelta(days=1)
    providers.kev_released = tomorrow - timedelta(hours=1)
    assert all(
        state == "complete" for state in collect(environment, providers, now=tomorrow).values()
    )
    with environment["factory"]() as session:
        context, updated_fingerprint = cve_context(session, [A, B], now=tomorrow)
        assert updated_fingerprint != fingerprint
        assert context[0]["kev"]["value"]["date_added"] == "2021-12-11"
        assert context[1]["kev"]["listed"] is False
        assert session.get(SupplementalFactRecord, (old_kev.snapshot_id, B)) is not None
        current = latest_snapshot(session, EPSS_SOURCE)
        assert current.document["evidence_ids"] != epss_evidence  # Score date also changed.
        records_before = session.scalar(select(func.count()).select_from(EvidenceRecord))
    # Deliberately serve the same still-fresh dated file to verify content reuse.
    providers.epss_score_date = tomorrow.date()
    repeated = collect(environment, providers, now=tomorrow + timedelta(hours=21))
    with environment["factory"]() as session:
        diagnostics = latest_snapshot(session, EPSS_SOURCE).document
    assert repeated == {EPSS_SOURCE: "complete", KEV_SOURCE: "complete"}, diagnostics
    with environment["factory"]() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == records_before
        assert latest_snapshot(session, EPSS_SOURCE).sequence == 3


def test_failed_refresh_keeps_last_good_facts_without_claiming_fresh_success(environment):
    providers = Providers()
    collect(environment, providers)
    providers.epss_failure = True
    tomorrow = NOW + timedelta(days=1)
    assert collect(environment, providers, now=tomorrow)[EPSS_SOURCE] == "failed"
    with environment["factory"]() as session:
        result, _ = cve_context(session, [A], now=tomorrow)
        assert result[0]["epss"]["state"] == "failed"
        assert result[0]["epss"]["value"]["epss"] == "0.99999"
        assert latest_snapshot(session, EPSS_SOURCE).state == "failed"
        assert latest_snapshot(session, EPSS_SOURCE, complete_only=True).sequence == 1


def test_catalog_capacity_failure_does_not_block_kev(environment, monkeypatch):
    monkeypatch.setattr(runtime, "MAX_FACTS", 1)
    providers = Providers()
    assert collect(environment, providers) == {EPSS_SOURCE: "failed", KEV_SOURCE: "complete"}
    assert providers.calls == [(KEV_SOURCE,)]


def test_source_history_conflict_does_not_block_other_source(environment):
    source = deepcopy(environment["registry"].get(EPSS_SOURCE).source)
    source["name"] = "Synthetic conflicting source history"
    with environment["factory"]() as session, session.begin():
        append_contract(session, "Source", source)
    providers = Providers()
    assert collect(environment, providers) == {EPSS_SOURCE: "failed", KEV_SOURCE: "complete"}
    assert providers.calls == [(KEV_SOURCE,)]


def test_before_utc18_uses_latest_provider_date_without_guessing_yesterday(environment):
    providers = Providers()
    morning = NOW.replace(hour=13)
    assert collect(environment, providers, now=morning, sources=(EPSS_SOURCE,)) == {
        EPSS_SOURCE: "complete"
    }
    assert providers.calls == [(EPSS_SOURCE, (A, B, C), morning.date())]


def test_busy_real_collection_lock_records_failure_without_partial_evidence(
    environment, monkeypatch
):
    monkeypatch.setattr(runtime, "RUN_SECONDS", 0.01)
    providers = Providers()
    with environment["store"].collection_lock():
        assert collect(environment, providers, sources=(EPSS_SOURCE,)) == {EPSS_SOURCE: "failed"}
    assert len(providers.calls) == 1
    with environment["factory"]() as session:
        assert latest_snapshot(session, EPSS_SOURCE).state == "failed"
        assert list(session.scalars(select(EvidenceRecord))) == []
        assert list(session.scalars(select(SupplementalFactRecord))) == []
    assert environment["store"].manifest() == []
    assert environment["store"].pending_manifest() == []


def test_persistence_failure_rolls_back_staging_and_preserves_failed_attempt(
    environment, monkeypatch
):
    original = runtime.append_snapshot

    def refuse_complete(session, **kwargs):
        if kwargs["state"] == "complete":
            raise RuntimeError("synthetic persistence failure after evidence staging")
        return original(session, **kwargs)

    monkeypatch.setattr(runtime, "append_snapshot", refuse_complete)
    assert collect(environment, Providers(), sources=(EPSS_SOURCE,)) == {EPSS_SOURCE: "failed"}
    with environment["factory"]() as session:
        assert latest_snapshot(session, EPSS_SOURCE).state == "failed"
        assert list(session.scalars(select(EvidenceRecord))) == []
        assert list(session.scalars(select(SupplementalFactRecord))) == []
    assert environment["store"].manifest() == []
    assert environment["store"].pending_manifest() == []


def test_concurrent_due_runs_dispatch_once_and_do_not_append_busy_receipt(environment):
    entered = threading.Event()
    finish = threading.Event()

    class BlockingProviders(Providers):
        def epss(self, *args, **kwargs):
            entered.set()
            assert finish.wait(timeout=5), "bounded fixture synchronization timed out"
            return super().epss(*args, **kwargs)

    providers = BlockingProviders()
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(collect, environment, providers, sources=(EPSS_SOURCE,))
        assert entered.wait(timeout=5), "first fixture provider was not dispatched"
        try:
            second = Providers()
            assert collect(environment, second, sources=(EPSS_SOURCE,)) == {
                EPSS_SOURCE: "already_running",
            }
            assert second.calls == []
            with environment["factory"]() as session:
                assert latest_snapshot(session, EPSS_SOURCE) is None
        finally:
            finish.set()
        assert first.result(timeout=5) == {EPSS_SOURCE: "complete"}
    assert len(providers.calls) == 1
    with environment["factory"]() as session:
        assert latest_snapshot(session, EPSS_SOURCE).sequence == 1
    assert collect(environment, providers, sources=(EPSS_SOURCE,)) == {EPSS_SOURCE: "not_due"}


@pytest.mark.parametrize("retry_succeeds", [True, False])
def test_exact_failed_snapshot_allows_one_bounded_recovery_and_is_consumed(
    environment, retry_succeeds
):
    providers = Providers()
    providers.epss_failure = True
    assert collect(environment, providers, sources=(EPSS_SOURCE,)) == {EPSS_SOURCE: "failed"}
    with environment["factory"]() as session:
        failed_id = latest_snapshot(session, EPSS_SOURCE).snapshot_id
    providers.epss_failure = not retry_succeeds
    later = NOW + timedelta(minutes=1)
    assert collect(
        environment, providers, sources=(EPSS_SOURCE,), now=later, retry_failed_snapshot=failed_id
    ) == {
        EPSS_SOURCE: "complete" if retry_succeeds else "failed",
    }
    with environment["factory"]() as session:
        successor = latest_snapshot(session, EPSS_SOURCE)
        assert successor.sequence == 2
        assert successor.document["retry_of"] == failed_id
    calls = len(providers.calls)
    assert collect(
        environment, providers, sources=(EPSS_SOURCE,), now=later, retry_failed_snapshot=failed_id
    ) == {EPSS_SOURCE: "retry_refused"}
    assert len(providers.calls) == calls
    with environment["factory"]() as session:
        assert latest_snapshot(session, EPSS_SOURCE).sequence == 2


def test_wrong_failed_identity_refused_without_dispatch_or_new_receipt(environment):
    providers = Providers()
    providers.epss_failure = True
    collect(environment, providers, sources=(EPSS_SOURCE,))
    calls = len(providers.calls)
    assert collect(
        environment,
        providers,
        sources=(EPSS_SOURCE,),
        retry_failed_snapshot="gbsec:supplemental-snapshot:wrong",
    ) == {
        EPSS_SOURCE: "retry_refused",
    }
    assert len(providers.calls) == calls
    with environment["factory"]() as session:
        assert latest_snapshot(session, EPSS_SOURCE).sequence == 1


def test_retry_without_failure_or_with_multiple_sources_refused(environment):
    providers = Providers()
    assert collect(
        environment,
        providers,
        sources=(EPSS_SOURCE,),
        retry_failed_snapshot="gbsec:supplemental-snapshot:none",
    ) == {
        EPSS_SOURCE: "retry_refused",
    }
    assert providers.calls == []
    with pytest.raises(ValueError, match="mode/sources"):
        collect(environment, providers, retry_failed_snapshot="gbsec:supplemental-snapshot:none")
    assert providers.calls == []


@pytest.mark.parametrize("low", ["bytes", "inodes"])
def test_capacity_guard_rejects_before_evidence_staging(environment, monkeypatch, low):
    capacity = SimpleNamespace(
        f_bavail=runtime.MIN_FREE_BYTES + 128 * 1024**2,
        f_frsize=1,
        f_favail=runtime.MIN_FREE_INODES + 2000,
    )
    if low == "bytes":
        capacity.f_bavail -= 1
    else:
        capacity.f_favail -= 1
    monkeypatch.setattr(runtime.os, "statvfs", lambda path: capacity)
    providers = Providers()
    assert collect(environment, providers, sources=(EPSS_SOURCE,)) == {EPSS_SOURCE: "failed"}
    assert len(providers.calls) == 1
    with environment["factory"]() as session:
        attempt = latest_snapshot(session, EPSS_SOURCE)
        assert attempt.state == "failed" and attempt.record_count == 0
        assert list(session.scalars(select(EvidenceRecord))) == []
        assert list(session.scalars(select(SupplementalFactRecord))) == []
    assert environment["store"].manifest() == []
    assert environment["store"].pending_manifest() == []


def test_capacity_guard_accepts_exact_byte_and_inode_reserve(environment, monkeypatch):
    capacity = SimpleNamespace(
        f_bavail=runtime.MIN_FREE_BYTES + 128 * 1024**2,
        f_frsize=1,
        f_favail=runtime.MIN_FREE_INODES + 2000,
    )
    monkeypatch.setattr(runtime.os, "statvfs", lambda path: capacity)
    assert collect(environment, Providers(), sources=(EPSS_SOURCE,)) == {EPSS_SOURCE: "complete"}


def test_known_cves_selects_only_current_supported_active_package_aliases(database):
    with Session(database.engine) as session, session.begin():
        seed_catalog(session, [A], "old", upstream="revised")
        seed_catalog(session, [B], "new", upstream="revised", revision=2)
        seed_catalog(session, [A], "unsupported", supported=False)
        seed_catalog(session, [C], "withdrawn", state="withdrawn")
    with Session(database.engine) as session:
        assert runtime.known_cves(session) == (B,)


@pytest.mark.parametrize(
    "aliases,state,supported",
    [
        ([], "active", True),
        (["GHSA-xxxx-yyyy-zzzz"], "active", True),
        ([A.lower()], "active", True),
        (["CVE-not-an-id"], "active", True),
        ([B], "withdrawn", True),
        ([B], "active", False),
    ],
)
def test_known_cves_prefilter_never_resurrects_superseded_aliases(
    database, aliases, state, supported
):
    with Session(database.engine) as session, session.begin():
        seed_catalog(session, [A], "old", upstream="revised")
        seed_catalog(
            session,
            aliases,
            "new",
            upstream="revised",
            revision=2,
            state=state,
            supported=supported,
        )
        seed_catalog(session, ["GHSA-xxxx-yyyy-zzzz", C], "still-current")
    with Session(database.engine) as session:
        assert runtime.known_cves(session) == (C,)


def test_aging_epss_refreshes_before_normal_holdoff_without_replaying_other_sources(environment):
    providers = Providers()
    providers.epss_score_date = (NOW - timedelta(days=1)).date()
    assert collect(environment, providers) == {EPSS_SOURCE: "complete", KEV_SOURCE: "complete"}
    providers.calls.clear()
    # Previously acquired EPSS is 31h old. At its 36h data-age threshold it
    # must refresh even though collection was recent. KEV keeps its holdoff.
    providers.epss_score_date = NOW.date()
    later = NOW + timedelta(hours=6)
    assert collect(environment, providers, now=later) == {
        EPSS_SOURCE: "complete",
        KEV_SOURCE: "not_due",
    }
    assert len(providers.calls) == 1 and providers.calls[0][0] == EPSS_SOURCE
    with environment["factory"]() as session:
        epss = latest_snapshot(session, EPSS_SOURCE)
        assert epss.observed_at == later
        assert epss.source_as_of == NOW.replace(hour=12)
    providers.calls.clear()
    assert collect(environment, providers, now=later + timedelta(minutes=1)) == {
        EPSS_SOURCE: "not_due",
        KEV_SOURCE: "not_due",
    }
    assert providers.calls == []


@pytest.mark.parametrize("target_scope", ["crates", "rust"])
def test_rust_origin_location_recovers_exact_failure_without_fabricating_withdrawal(
    environment,
    target_scope,
):
    from smithguard.advisory_catalog import catalog_evidence_for_package
    from smithguard.origin_advisories import parse_rustsec_archive
    from tests.test_origin_advisories import COMMIT, archive, document, rust_archive

    value = document()
    source = runtime.RUST_SOURCE
    initial = parse_rustsec_archive(rust_archive([value]), commit=COMMIT, observed_at=NOW)
    calls = []

    def invoke(snapshot, now, retry=None):
        environment["clock"][0] = now + timedelta(seconds=1)

        def fetch(origin, **kwargs):
            assert origin == "rustsec"
            calls.append(snapshot.transport_sha256)
            return snapshot

        return runtime.collect_sources(
            **{key: item for key, item in environment.items() if key != "clock"},
            mode="public",
            sources=(source,),
            now=now,
            fetch_origin=fetch,
            retry_failed_snapshot=retry,
        )

    assert invoke(initial, NOW) == {source: "complete"}
    with environment["factory"]() as session:
        original = latest_snapshot(session, source)
        original_id = original.snapshot_id
        before = catalog_evidence_for_package(
            session, ecosystem="rust", name="decompress", version="0.1.0"
        )
        assert len(before.families) == 1
    tomorrow = NOW + timedelta(days=1)
    unrelated = document()
    unrelated["id"] = "RUSTSEC-2026-9999"
    absent = parse_rustsec_archive(rust_archive([unrelated]), commit=COMMIT, observed_at=tomorrow)
    assert invoke(absent, tomorrow) == {source: "failed"}
    with environment["factory"]() as session:
        failure = latest_snapshot(session, source)
        failure_id = failure.snapshot_id
        assert failure.state == "failed"
        assert latest_snapshot(session, source, complete_only=True).snapshot_id == original_id
        assert (
            len(
                catalog_evidence_for_package(
                    session, ecosystem="rust", name="decompress", version="0.1.0"
                ).families
            )
            == 1
        )
    # An exact represented upstream move provides evidence for a scope correction.
    # The genuinely absent ID above was never acknowledged or silently removed.
    next_commit = "b" * 40
    moved_path = f"advisory-db-{next_commit}/{target_scope}/{value['id']}.json"
    moved = parse_rustsec_archive(
        archive({moved_path: canonical_json_bytes(value)}),
        commit=next_commit,
        observed_at=tomorrow + timedelta(minutes=1),
    )
    assert invoke(moved, tomorrow + timedelta(minutes=1), retry=failure_id) == {source: "complete"}
    with environment["factory"]() as session:
        current = latest_snapshot(session, source)
        assert current.document["retry_of"] == failure_id
        assert current.document["created_catalog_revisions"] == int(target_scope == "rust")
        assert current.document["checkpoint_token"] == moved.checkpoint_token
        assert current.document["manifest_sha256"] == moved.manifest_sha256
        assert session.query(AdvisoryCatalogRecord).filter_by(source_id=source).count() == (
            2 if target_scope == "rust" else 1
        )
        assert session.query(AdvisoryPackageRecord).filter_by(source_id=source).count() == 1
        assert (
            snapshot_facts(session, current.snapshot_id, [value["id"]])[value["id"]]["state"]
            == "active"
        )
        assert session.get(SupplementalFactRecord, (original_id, value["id"])) is not None
        assert latest_snapshot(session, source).sequence == 3
        assert bool(
            catalog_evidence_for_package(
                session, ecosystem="rust", name="decompress", version="0.1.0"
            ).families
        ) == (target_scope == "crates")
        old_fact = snapshot_facts(session, original_id, [value["id"]])[value["id"]]
        new_fact = snapshot_facts(session, current.snapshot_id, [value["id"]])[value["id"]]
        assert old_fact["evidence_id"] != new_fact["evidence_id"]
        old_evidence = session.scalar(
            select(EvidenceRecord).where(EvidenceRecord.id == old_fact["evidence_id"])
        )
        new_evidence = session.scalar(
            select(EvidenceRecord).where(EvidenceRecord.id == new_fact["evidence_id"])
        )
        assert old_evidence.storage_key == new_evidence.storage_key
        assert old_evidence.document["canonical_url"] != new_evidence.document["canonical_url"]
        assert moved.records[0].canonical_url in new_fact["attribution_urls"]
        retained = session.scalars(
            select(AdvisoryCatalogRecord)
            .where(AdvisoryCatalogRecord.source_id == source)
            .order_by(AdvisoryCatalogRecord.revision)
        ).all()
        assert retained[0].canonical_url == initial.records[0].canonical_url
        if target_scope == "crates":
            after = catalog_evidence_for_package(
                session, ecosystem="rust", name="decompress", version="0.1.0"
            )
            assert after.fingerprint == before.fingerprint
            assert after.families == before.families
    assert len(calls) == 3
    assert invoke(moved, tomorrow + timedelta(minutes=2), retry=failure_id) == {
        source: "retry_refused"
    }
    assert len(calls) == 3
    # A later due scan of the same moved commit reuses its second provenance
    # member, while finalization still belongs to the first acquisition.
    with environment["factory"]() as session:
        old_members = {
            row.id: canonical_json_bytes(row.document)
            for row in session.scalars(select(EvidenceRecord))
        }
        old_finalizations = {
            row.finalization_id: (row.evidence_id, row.digest, row.byte_count, row.attempts)
            for row in session.scalars(select(EvidenceFinalizationRecord))
        }
    assert invoke(moved, tomorrow + timedelta(days=1)) == {source: "complete"}
    assert len(calls) == 4
    with environment["factory"]() as session:
        assert {
            row.id: canonical_json_bytes(row.document)
            for row in session.scalars(select(EvidenceRecord))
        } == old_members
        assert {
            row.finalization_id: (row.evidence_id, row.digest, row.byte_count, row.attempts)
            for row in session.scalars(select(EvidenceFinalizationRecord))
        } == old_finalizations
        assert latest_snapshot(session, source).sequence == 4
        assert session.get(SupplementalSnapshotRecord, failure_id).state == "failed"
    assert environment["store"].pending_manifest() == []


def test_missing_score_identity_is_pinned_and_repair_preserves_old_receipt(environment):
    from smithguard.coverage import _supplemental_coverage_lanes
    from smithguard.source_accounting import epss_missing

    providers = Providers()
    assert collect(environment, providers, sources=(EPSS_SOURCE,)) == {EPSS_SOURCE: "complete"}
    with environment["factory"]() as session:
        before = epss_missing(session, read_evidence=environment["store"].read_bytes)
        assert before["subjects"] == [C]
        assert before["missing_count"] == 1
        assert before["requested_count"] == 3
        assert before["identity_accounting"] == "complete"
        lane = next(
            row
            for row in _supplemental_coverage_lanes(session, measured_at=NOW)
            if row.source_id == EPSS_SOURCE
        )
        assert lane.normalized_record_count == 2
        assert any("1 requested CVEs had no EPSS score" in value for value in lane.unknowns)
        context, _ = cve_context(session, [C], now=NOW)
        assert context[0]["epss"]["value"] is None
    tomorrow = NOW + timedelta(days=1)
    environment["clock"][0] = tomorrow
    providers.epss_rows.append(f"{C},0.25,0.5")
    assert collect(environment, providers, sources=(EPSS_SOURCE,), now=tomorrow) == {
        EPSS_SOURCE: "complete"
    }
    with environment["factory"]() as session:
        assert (
            epss_missing(session, read_evidence=environment["store"].read_bytes)["subjects"] == []
        )
        assert (
            epss_missing(
                session,
                snapshot_id=before["snapshot_id"],
                read_evidence=environment["store"].read_bytes,
            )
            == before
        )
        context, _ = cve_context(session, [C], now=tomorrow)
        assert context[0]["epss"]["value"]["epss"] == "0.25"


@pytest.mark.parametrize("origin", ["rustsec", "go"])
def test_origin_snapshot_omissions_have_exact_catalog_evidence(environment, origin):
    from smithguard.origin_advisories import parse_go_archive, parse_rustsec_archive
    from smithguard.source_accounting import catalog_omissions
    from tests.test_origin_advisories import COMMIT, archive, document, go_files, rust_archive

    value = document("go" if origin == "go" else "rustsec")
    if origin == "go":
        value["affected"][0]["package"]["name"] = "stdlib"
        snapshot = parse_go_archive(archive(go_files([value])), observed_at=NOW)
        source = runtime.GO_SOURCE
    else:
        value["affected"][0]["database_specific"]["informational"] = "unmaintained"
        snapshot = parse_rustsec_archive(rust_archive([value]), commit=COMMIT, observed_at=NOW)
        source = runtime.RUST_SOURCE
    assert runtime.collect_sources(
        **{key: item for key, item in environment.items() if key != "clock"},
        mode="public",
        sources=(source,),
        now=NOW,
        fetch_origin=lambda *a, **k: snapshot,
    ) == {source: "complete"}
    with environment["factory"]() as session:
        receipt = latest_snapshot(session, source)
        fact = snapshot_facts(session, receipt.snapshot_id, [value["id"]])[value["id"]]
        report = catalog_omissions(session, source=origin)
        assert len(report["records"]) == 1
        row = report["records"][0]
        assert row["catalog_event_id"] == fact["catalog_event_id"]
        assert row["evidence_id"] == fact["evidence_id"]
        assert row["omissions"] == fact["package_omission_counts"]
        assert row["omissions"]


def test_missing_subject_evidence_preserves_previous_public_reader(environment):
    from smithguard.contracts.generated import PublicEpssContext

    assert collect(environment, Providers(), sources=(EPSS_SOURCE,)) == {EPSS_SOURCE: "complete"}
    with environment["factory"]() as session:
        snapshot = latest_snapshot(session, EPSS_SOURCE)
        # Small EPSS facts remain inline. The public context shape and coverage
        # record_count remain unchanged; schema 0033 is required for rollback.
        assert snapshot.record_count == 2
        facts = tuple(
            session.scalars(
                select(SupplementalFactRecord).where(
                    SupplementalFactRecord.snapshot_id == snapshot.snapshot_id
                )
            )
        )
        assert {row.subject_id for row in facts} == {A, B}
        assert snapshot.document["missing_subject_evidence_ids"]
        context, _ = cve_context(session, [A, B, C], now=NOW)
        for item in context:
            PublicEpssContext.model_validate(item["epss"])
        assert context[-1]["epss"]["value"] is None


def test_missing_inventory_chunks_paginate_and_refuse_unavailable_bytes(environment):
    from smithguard.source_accounting import epss_missing

    missing = [f"CVE-2026-{index:07d}" for index in range(1, 1251)]
    with environment["factory"]() as session, session.begin():
        for offset in range(0, len(missing), 100):
            seed_catalog(session, missing[offset : offset + 100], identity=f"missing-{offset}")
    assert collect(environment, Providers(), sources=(EPSS_SOURCE,)) == {EPSS_SOURCE: "complete"}
    with environment["factory"]() as session:
        snapshot = latest_snapshot(session, EPSS_SOURCE)
        assert snapshot.record_count == 2
        assert len(snapshot.document["missing_subject_evidence_ids"]) == 2
        expected = sorted([*missing, C])
        page = epss_missing(
            session, limit=100, after=expected[949], read_evidence=environment["store"].read_bytes
        )
        assert page["subjects"] == expected[950:1050]
        assert page["has_more"] and page["next_cursor"] == expected[1049]
        with pytest.raises(ValueError, match="unavailable"):
            epss_missing(session)
        with pytest.raises(ValueError, match="identity differs"):
            epss_missing(session, read_evidence=lambda _: b"[]")


def test_missing_inventory_cli_reads_only_existing_finalized_evidence(
    environment, database, monkeypatch, capsys
):
    import smithguard.reconciliation_runtime as cli

    assert collect(environment, Providers(), sources=(EPSS_SOURCE,)) == {EPSS_SOURCE: "complete"}
    before = environment["store"].manifest()
    monkeypatch.setattr(
        cli, "load_runtime_config", lambda: SimpleNamespace(evidence_root=environment["store"].root)
    )
    monkeypatch.setattr(cli, "_engine", lambda _: database.engine)
    assert cli.main(["source-omissions", "--source", "epss", "--limit", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["subjects"] == [C]
    assert environment["store"].manifest() == before
    assert environment["store"].pending_manifest() == []


@pytest.mark.parametrize("bad_owner", ["missing", "different_content"])
def test_shared_content_reuse_rejects_an_invalid_original_owner(environment, bad_owner):
    from smithguard.origin_advisories import parse_rustsec_archive
    from tests.test_origin_advisories import COMMIT, document, rust_archive

    value = document()
    unrelated = document()
    unrelated["id"] = "RUSTSEC-2026-9999"
    snapshot = parse_rustsec_archive(
        rust_archive([value, unrelated]), commit=COMMIT, observed_at=NOW
    )

    def invoke(now):
        environment["clock"][0] = now + timedelta(seconds=1)
        return runtime.collect_sources(
            **{key: item for key, item in environment.items() if key != "clock"},
            mode="public",
            sources=(runtime.RUST_SOURCE,),
            now=now,
            fetch_origin=lambda *args, **kwargs: snapshot,
        )

    assert invoke(NOW) == {runtime.RUST_SOURCE: "complete"}
    before_manifest = environment["store"].manifest()
    with environment["factory"]() as session, session.begin():
        members = list(session.scalars(select(EvidenceRecord).order_by(EvidenceRecord.id)))
        assert len(members) == 2 and members[0].sha256 != members[1].sha256
        owner = session.scalar(
            select(EvidenceFinalizationRecord).where(
                EvidenceFinalizationRecord.digest == members[0].sha256
            )
        )
        owner.evidence_id = (
            "gbsec:evidence:missing-owner" if bad_owner == "missing" else members[1].id
        )
        prior_bytes = {row.id: canonical_json_bytes(row.document) for row in members}
    assert invoke(NOW + timedelta(days=1)) == {runtime.RUST_SOURCE: "failed"}
    with environment["factory"]() as session:
        assert (
            latest_snapshot(session, runtime.RUST_SOURCE).document["error_type"]
            == "EvidenceFinalizationError"
        )
        assert {
            row.id: canonical_json_bytes(row.document)
            for row in session.scalars(select(EvidenceRecord))
        } == prior_bytes
    assert environment["store"].manifest() == before_manifest
    assert environment["store"].pending_manifest() == []
