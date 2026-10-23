"""Coverage stays ecosystem-specific and does not imply live monitoring."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from smithguard.collectors import GITHUB_ADVISORY
from smithguard.coverage import _COVERAGE_REPORT_CACHE, build_coverage_report
from smithguard.db.models import AdvisoryCatalogManifestRecord, CollectorProgressRecord
from smithguard.db.repository import append_contract

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
OPENSSF_SOURCE_ID = "gbsec:source:openssf-malicious-packages"


@pytest.fixture(autouse=True)
def _clear_coverage_cache() -> None:
    _COVERAGE_REPORT_CACHE.clear()


def _example(
    contract_examples: list[dict[str, Any]],
    definition: str,
) -> dict[str, Any]:
    return deepcopy(
        next(entry["value"] for entry in contract_examples if entry["definition"] == definition)
    )


def test_empty_coverage_is_honest_and_agent_extensions_remain_research(database) -> None:
    with Session(database.engine) as session:
        report = build_coverage_report(session, measured_at=NOW)
    assert report.live_collector_uptime == "not_measured_no_live_collectors"
    assert report.human_review_hours == 0
    assert all(not lane.continuous_monitoring_claimed for lane in report.lanes)
    assert len(report.source_lanes) == 11
    openssf = next(
        lane
        for lane in report.source_lanes
        if lane.source_id == "gbsec:source:openssf-malicious-packages"
    )
    assert openssf.record_type == "malicious_package_catalog"
    assert openssf.state == "not_started"
    assert openssf.freshness_state == "missing"
    assert {lane.ecosystem: (lane.stage, lane.result) for lane in report.lanes} == {
        "npm": ("intake", "unknown"),
        "pypi": ("intake", "unknown"),
        "github-actions": ("intake", "unknown"),
        "oci": ("intake", "unknown"),
        "docker": ("intake", "unknown"),
        "go": ("research", "unknown"),
        "rust": ("research", "unknown"),
        "composer": ("intake", "unknown"),
        "erlang": ("intake", "unknown"),
        "git": ("intake", "unknown"),
        "maven": ("intake", "unknown"),
        "nuget": ("intake", "unknown"),
        "open-vsx": ("intake", "unknown"),
        "pub": ("intake", "unknown"),
        "rubygems": ("intake", "unknown"),
        "swift": ("intake", "unknown"),
        "vscode": ("intake", "unknown"),
        "developer-agent-extensions": ("research", "unknown"),
    }


def test_empty_coverage_uses_a_bounded_grouped_statement_budget(database) -> None:
    statement_count = 0

    def count_statement(*_args) -> None:
        nonlocal statement_count
        statement_count += 1

    event.listen(database.engine, "before_cursor_execute", count_statement)
    try:
        with Session(database.engine) as session:
            build_coverage_report(session, measured_at=NOW)
    finally:
        event.remove(database.engine, "before_cursor_execute", count_statement)
    # Seven legacy grouped reads plus one batch for all four supplementary sources.
    assert statement_count <= 8


@pytest.mark.audit_ids("API-02")
def test_coverage_report_cache_reuses_one_database_read_for_five_minutes(database) -> None:
    statement_count = 0

    def count_statement(*_args) -> None:
        nonlocal statement_count
        statement_count += 1

    event.listen(database.engine, "before_cursor_execute", count_statement)
    try:
        with Session(database.engine) as session:
            first = build_coverage_report(session, measured_at=NOW)
            first_statement_count = statement_count
            second = build_coverage_report(
                session,
                measured_at=NOW + timedelta(seconds=299),
            )
            assert second is first
            assert statement_count == first_statement_count
            third = build_coverage_report(
                session,
                measured_at=NOW + timedelta(seconds=300),
            )
            assert third is not first
            assert statement_count > first_statement_count
    finally:
        event.remove(database.engine, "before_cursor_execute", count_statement)


def _openssf_manifest(
    *,
    segment: str,
    sequence: int = 1,
    state: str = "complete",
    commit: str = "a" * 40,
    record_count: int = 0,
    package_entry_count: int = 0,
) -> AdvisoryCatalogManifestRecord:
    identity = sequence + (1 if segment == "openssf-withdrawn" else 0)
    return AdvisoryCatalogManifestRecord(
        manifest_event_id=(f"gbsec:advisory-catalog-manifest:openssf-{segment}-{sequence}"),
        source_id=OPENSSF_SOURCE_ID,
        segment=segment,
        sequence=sequence,
        state=state,
        source_snapshot=f"{commit}:sha256:{identity:064x}",
        cursor_value=None,
        record_count=record_count,
        package_entry_count=package_entry_count,
        manifest_sha256="sha256:" + f"{identity + 10:064x}",
        observed_at=NOW + timedelta(minutes=sequence - 1),
        record_hash="sha256:" + f"{identity + 20:064x}",
    )


def _openssf_lane(database):
    with Session(database.engine) as session:
        return next(
            item
            for item in build_coverage_report(session, measured_at=NOW).source_lanes
            if item.source_id == OPENSSF_SOURCE_ID
        )


def test_openssf_source_coverage_requires_both_catalog_trees_at_one_snapshot(database) -> None:
    with Session(database.engine) as session, session.begin():
        session.add_all(
            (
                _openssf_manifest(
                    segment="openssf-malicious",
                    record_count=1_200,
                    package_entry_count=1_199,
                ),
                _openssf_manifest(
                    segment="openssf-withdrawn",
                    record_count=2,
                    package_entry_count=2,
                ),
            )
        )
    lane = _openssf_lane(database)
    assert lane.lane == "historical"
    assert lane.record_type == "malicious_package_catalog"
    assert lane.state == "complete"
    assert lane.freshness_state == "complete"
    assert lane.page_count == 2
    assert lane.source_record_count == 1_202
    assert lane.normalized_record_count == 1_201
    assert lane.last_attempt_at == "2026-08-05T12:00:00Z"
    assert lane.last_success_at == "2026-08-05T12:00:00Z"
    assert "No supported exact artifact ecosystem has been accepted." in lane.unknowns


def test_openssf_source_coverage_fails_closed_when_a_tree_is_missing(database) -> None:
    with Session(database.engine) as session, session.begin():
        session.add(_openssf_manifest(segment="openssf-malicious", record_count=10))
    lane = _openssf_lane(database)
    assert lane.state == "in_progress"
    assert lane.freshness_state == "missing"
    assert lane.page_count == 0
    assert "openssf-withdrawn" in lane.unknowns[0]


def test_openssf_source_coverage_uses_the_latest_failed_manifest(database) -> None:
    with Session(database.engine) as session, session.begin():
        session.add_all(
            (
                _openssf_manifest(segment="openssf-malicious"),
                _openssf_manifest(segment="openssf-withdrawn"),
                _openssf_manifest(
                    segment="openssf-malicious",
                    sequence=2,
                    state="failed",
                ),
            )
        )
    lane = _openssf_lane(database)
    assert lane.state == "failed"
    assert lane.freshness_state == "failed"
    assert lane.last_success_at == "2026-08-05T12:00:00Z"
    assert "latest OpenSSF catalog collection attempt failed" in lane.unknowns[0]


def test_openssf_source_coverage_keeps_fresh_success_during_next_attempt(database) -> None:
    with Session(database.engine) as session, session.begin():
        session.add_all(
            (
                _openssf_manifest(segment="openssf-malicious"),
                _openssf_manifest(segment="openssf-withdrawn"),
                _openssf_manifest(
                    segment="openssf-withdrawn",
                    sequence=2,
                    state="in_progress",
                ),
            )
        )
    lane = _openssf_lane(database)
    assert lane.state == "complete"
    assert lane.freshness_state == "complete"
    assert lane.last_success_at == "2026-08-05T12:00:00Z"


def test_openssf_source_coverage_rejects_mismatched_complete_snapshots(database) -> None:
    with Session(database.engine) as session, session.begin():
        session.add_all(
            (
                _openssf_manifest(segment="openssf-malicious", commit="a" * 40),
                _openssf_manifest(segment="openssf-withdrawn", commit="b" * 40),
            )
        )
    lane = _openssf_lane(database)
    assert lane.state == "failed"
    assert lane.freshness_state == "failed"
    assert lane.page_count == 0
    assert "do not describe one source snapshot" in lane.unknowns[0]


def test_matched_claims_require_ranges_and_immutable_image_digests(
    database,
    contract_examples: list[dict[str, Any]],
) -> None:
    npm_artifact = _example(contract_examples, "Artifact")
    npm_range = _example(contract_examples, "AffectedRange")
    oci_artifact = {
        **npm_artifact,
        "id": "gbsec:artifact:oci:synthetic",
        "ecosystem": "oci",
        "name": "registry.example.invalid/smithguard/synthetic",
        "coordinate": "pkg:oci/registry.example.invalid/smithguard/synthetic@sha256%3A" + "a" * 64,
        "version": None,
        "digest": "sha256:" + "a" * 64,
    }
    oci_range = {
        **npm_range,
        "id": "gbsec:range:oci:synthetic",
        "artifact_id": oci_artifact["id"],
        "range_type": "DIGEST",
        "expression": oci_artifact["digest"],
        "introduced": oci_artifact["digest"],
        "last_affected": oci_artifact["digest"],
    }
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Artifact", npm_artifact)
        append_contract(session, "AffectedRange", npm_range)
        append_contract(session, "Artifact", oci_artifact)
        append_contract(session, "AffectedRange", oci_range)
        report = build_coverage_report(
            session,
            measured_at=NOW,
            human_review_hours=2.5,
        )
    lanes = {lane.ecosystem: lane for lane in report.lanes}
    assert (lanes["npm"].stage, lanes["npm"].result) == ("matched", "supported")
    assert (lanes["oci"].stage, lanes["oci"].result) == ("matched", "supported")
    assert (lanes["docker"].stage, lanes["docker"].result) == ("intake", "unknown")
    assert report.human_review_hours == 2.5


def _progress(
    sequence: int,
    *,
    state: str,
    occurred_at: datetime,
    reason_code: str = "synthetic_coverage_progress",
) -> CollectorProgressRecord:
    return CollectorProgressRecord(
        progress_event_id=f"gbsec:collector-progress:coverage-{sequence}",
        source_id=GITHUB_ADVISORY,
        segment="malware",
        lane="updates",
        sequence=sequence,
        state=state,
        cursor_value=None,
        cursor_parameter=None,
        page_count=sequence,
        source_record_count=sequence,
        normalized_record_count=sequence,
        window_started_at=occurred_at - timedelta(hours=1),
        window_ended_at=occurred_at,
        oldest_published_at=None,
        newest_published_at=None,
        reason_code=reason_code,
        occurred_at=occurred_at,
        record_hash="sha256:" + f"{sequence + 100:064x}",
    )


def test_source_coverage_exposes_attempt_success_deadline_and_failure(database) -> None:
    with Session(database.engine) as session, session.begin():
        session.add(_progress(1, state="complete", occurred_at=NOW))
    with Session(database.engine) as session:
        lane = next(
            item
            for item in build_coverage_report(
                session,
                measured_at=NOW + timedelta(hours=1),
            ).source_lanes
            if item.lane == "updates"
        )
        assert lane.last_attempt_at == "2026-08-05T12:00:00Z"
        assert lane.last_success_at == "2026-08-05T12:00:00Z"
        assert lane.stale_after == "2026-08-05T14:30:00Z"
        assert lane.freshness_state == "fresh"

    with Session(database.engine) as session, session.begin():
        session.add(
            _progress(
                2,
                state="failed",
                occurred_at=NOW + timedelta(hours=1),
            )
        )
    _COVERAGE_REPORT_CACHE.clear()
    with Session(database.engine) as session:
        lane = next(
            item
            for item in build_coverage_report(
                session,
                measured_at=NOW + timedelta(hours=1),
            ).source_lanes
            if item.lane == "updates"
        )
        assert lane.last_attempt_at == "2026-08-05T13:00:00Z"
        assert lane.last_success_at == "2026-08-05T12:00:00Z"
        assert lane.freshness_state == "failed"
        assert "The latest collection attempt failed." in lane.unknowns


def test_retryable_quarantine_unknown_clears_after_successful_retry(database) -> None:
    quarantine_unknown = (
        "One or more source records were quarantined, so this lane has an unresolved coverage gap."
    )
    with Session(database.engine) as session, session.begin():
        session.add(
            _progress(
                1,
                state="failed",
                occurred_at=NOW,
                reason_code="github_page_quarantined_retryable",
            )
        )
    with Session(database.engine) as session:
        lane = next(
            item
            for item in build_coverage_report(session, measured_at=NOW).source_lanes
            if item.lane == "updates"
        )
        assert quarantine_unknown in lane.unknowns

    with Session(database.engine) as session, session.begin():
        session.add(
            _progress(
                2,
                state="in_progress",
                occurred_at=NOW + timedelta(minutes=5),
                reason_code="github_page_accepted_after_quarantine",
            )
        )
    with Session(database.engine) as session:
        lane = next(
            item
            for item in build_coverage_report(
                session,
                measured_at=NOW + timedelta(minutes=5),
            ).source_lanes
            if item.lane == "updates"
        )
        assert quarantine_unknown not in lane.unknowns


@pytest.mark.parametrize("minutes, expected", ((135, "complete"), (136, "stale")))
def test_openssf_complete_proof_expires_after_finite_catalog_budget(database, minutes, expected):
    with Session(database.engine) as session, session.begin():
        session.add_all(
            (
                _openssf_manifest(segment="openssf-malicious", record_count=12),
                _openssf_manifest(segment="openssf-withdrawn", record_count=2),
            )
        )
    with Session(database.engine) as session:
        lane = next(
            item
            for item in build_coverage_report(
                session, measured_at=NOW + timedelta(minutes=minutes)
            ).source_lanes
            if item.source_id == OPENSSF_SOURCE_ID
        )
    assert lane.freshness_state == expected
    assert lane.source_record_count == 14
    assert lane.last_success_at == "2026-08-05T12:00:00Z"
    # Two hourly intervals, the timer's five-minute delay and one 600-second run.
    assert lane.stale_after == "2026-08-05T14:15:00Z"


def test_openssf_failed_attempt_remains_visible_during_retry(database):
    with Session(database.engine) as session, session.begin():
        session.add_all(
            [
                _openssf_manifest(segment="openssf-malicious"),
                _openssf_manifest(segment="openssf-withdrawn"),
                _openssf_manifest(segment="openssf-malicious", sequence=2, state="failed"),
                _openssf_manifest(segment="openssf-malicious", sequence=3, state="in_progress"),
                _openssf_manifest(segment="openssf-withdrawn", sequence=2, state="in_progress"),
            ]
        )
    lane = _openssf_lane(database)
    assert lane.state == lane.freshness_state == "failed"
    assert lane.last_success_at == "2026-08-05T12:00:00Z"
    assert "latest OpenSSF catalog collection attempt failed" in lane.unknowns[0]


def test_an_in_progress_update_window_is_not_counted_as_caught_up(database) -> None:
    """Freshness is how far the data caught up (the newest completed window's end)."""
    with Session(database.engine) as session, session.begin():
        session.add(_progress(1, state="complete", occurred_at=NOW))
        session.add(_progress(2, state="in_progress", occurred_at=NOW + timedelta(hours=3)))
    with Session(database.engine) as session:
        lane = next(
            item
            for item in build_coverage_report(
                session, measured_at=NOW + timedelta(hours=3)
            ).source_lanes
            if item.lane == "updates"
        )
    assert lane.last_attempt_at == "2026-08-05T15:00:00Z"
    assert lane.last_success_at == "2026-08-05T12:00:00Z"
    # Pages are still arriving: publicly stale, with the backlog stated.
    assert lane.freshness_state == "stale"
    assert any("working through a backlog" in value for value in lane.unknowns)
    assert not any("outside its freshness target" in value for value in lane.unknowns)
