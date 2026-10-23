"""Operational health distinguishes readable, stale, degraded, and critical state."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

import smithguard.operational_health as operational_health_module
from smithguard.collectors import GITHUB_ADVISORY
from smithguard.coverage import CollectionFreshness, catalog_collection_freshness
from smithguard.db.models import CollectorProgressRecord, EvidenceFinalizationRecord
from smithguard.deploy import release as runtime_release
from smithguard.operational_health import (
    EXPECTED_MIGRATION,
    REQUIRED_ACTIVE_UNITS,
    REQUIRED_SUCCESSFUL_JOBS,
    HealthConfig,
    HealthConfigurationError,
    OpenSSFMonitorReceipt,
    OperationalHealthError,
    OperationalHealthInputs,
    _warning_deadlines,
    build_metric_receipt,
    build_warning_lane_metric_receipt,
    collect_operational_inputs,
    evaluate_operational_health,
    load_health_config,
    load_openssf_monitor_receipt,
    public_readiness,
    write_health_report,
    write_metric_receipt,
)
from smithguard.signals import PreliminaryWarningDraft, create_preliminary_warning
from smithguard.warning_lane_health import WarningLaneHealth
from tests.support import openssf_manifest_pair

NOW = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
MIGRATION_JOURNAL = Path(__file__).resolve().parents[1] / "migrations/journal.json"
REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_ROOT = REPO_ROOT / "contracts/v1"


def _freshness(lane: str, state: str) -> CollectionFreshness:
    last_success = NOW - timedelta(minutes=30) if state != "missing" else None
    return CollectionFreshness(
        lane=lane,
        latest_state="complete" if state == "complete" else "in_progress",
        last_attempt_at=last_success,
        last_success_at=last_success,
        stale_after=NOW + timedelta(hours=2) if last_success is not None else None,
        state=state,
    )


def _healthy_inputs() -> OperationalHealthInputs:
    return OperationalHealthInputs(
        measured_at=NOW,
        database_available=True,
        migration_current=True,
        updates=_freshness("updates", "fresh"),
        historical=_freshness("historical", "complete"),
        active_units={unit: True for unit in REQUIRED_ACTIVE_UNITS},
        job_results={unit: "success" for unit in REQUIRED_SUCCESSFUL_JOBS},
        failed_unit_count=0,
        external_probe_ok=True,
        disk_used_percent=20.0,
        database_bytes=1024,
        overdue_warning_count=0,
        warning_lane_health=WarningLaneHealth(
            schedule_expected=False,
            policy_active=0,
            provider_failures_24h=0,
            oldest_pending_age_seconds=0,
            dead_letters_24h=0,
            last_discovery_success_age_seconds=0,
            candidates_sampled_24h=0,
            windows_completed_24h=0,
            validation_rejection_basis_points=0,
            technical_envelope_breaches_24h=0,
            recheck_failures_24h=0,
            expiry_failures=0,
        ),
    )


@pytest.mark.parametrize(
    "quarantined,expected", [(0, "healthy"), (1, "critical"), (None, "critical")]
)
@pytest.mark.audit_ids("COL-06")
def test_unresolved_current_quarantines_use_existing_health_alarm(quarantined, expected):
    inputs = replace(_healthy_inputs(), github_quarantined_records=quarantined)
    report = evaluate_operational_health(inputs)
    check = next(item for item in report.checks if item.code == "github_record_quarantine")
    assert check.status == expected
    metrics = {item.name: item.value for item in build_metric_receipt(inputs, report).metrics}
    assert metrics["HealthCritical"] == (0 if expected == "healthy" else 1)


def _openssf_monitor(*, age: timedelta = timedelta(minutes=30)) -> OpenSSFMonitorReceipt:
    return OpenSSFMonitorReceipt(
        measured_at=NOW - age,
        healthy=True,
        status="success",
        checkpoint="a" * 40,
        state_apparent_bytes=1024,
        state_entry_count=10,
        filesystem_available_bytes=30 * 1024**3,
        filesystem_used_percent=40,
    )


def test_health_states_are_deterministic_and_actionable() -> None:
    healthy = evaluate_operational_health(_healthy_inputs())
    assert healthy.status == "healthy"
    assert all(check.status == "healthy" for check in healthy.checks)
    assert not any(check.code == "xai_cost_integrity" for check in healthy.checks)

    base = _healthy_inputs()
    degraded = evaluate_operational_health(
        replace(
            base,
            historical=_freshness("historical", "stale"),
            disk_used_percent=80.0,
        )
    )
    assert degraded.status == "degraded"
    assert {check.code for check in degraded.checks if check.status == "degraded"} >= {
        "historical_progress",
        "root_disk_usage",
    }

    critical = evaluate_operational_health(
        replace(
            base,
            updates=_freshness("updates", "stale"),
            overdue_warning_count=1,
        )
    )
    assert critical.status == "critical"
    critical_codes = {check.code for check in critical.checks if check.status == "critical"}
    assert {"updates_freshness", "warning_deadlines"} <= critical_codes

    failed = evaluate_operational_health(replace(base, failed_unit_count=None))
    assert failed.status == "critical"
    assert "failed_smithguard_units" in {
        check.code for check in failed.checks if check.status == "critical"
    }


@pytest.mark.parametrize(
    ("size", "expected"),
    [
        (8 * 1024**3, "healthy"),
        (10 * 1024**3 - 1, "healthy"),
        (10 * 1024**3, "degraded"),
        (12 * 1024**3 - 1, "degraded"),
        (12 * 1024**3, "critical"),
        (None, "critical"),
    ],
)
def test_database_capacity_policy_boundaries(size, expected):
    health = evaluate_operational_health(replace(_healthy_inputs(), database_bytes=size))
    assert health.status == expected


def test_metric_receipt_uses_exact_healthy_and_fail_closed_values() -> None:
    healthy = build_metric_receipt(_healthy_inputs()).as_dict()
    assert healthy["namespace"] == "SmithLabs/SmithGuard"
    assert healthy["measured_at"] == "2026-08-06T12:00:00Z"
    assert healthy["metrics"] == [
        {"name": "CollectorAgeSeconds", "unit": "Seconds", "value": 1800},
        {"name": "FailedUnits", "unit": "Count", "value": 0},
        {"name": "ExternalTunnelHealthy", "unit": "Count", "value": 1},
        {"name": "OpenSSFHealthy", "unit": "Count", "value": 1},
        {"name": "OpenSSFStateBytes", "unit": "Bytes", "value": 0},
        {"name": "OpenSSFFilesystemHealthy", "unit": "Count", "value": 1},
        {"name": "HealthCritical", "unit": "Count", "value": 0},
        {"name": "RootDiskUsedPercent", "unit": "Percent", "value": 20},
        {"name": "DatabaseBytes", "unit": "Bytes", "value": 1024},
    ]

    failed = build_metric_receipt(
        replace(
            _healthy_inputs(),
            updates=_freshness("updates", "stale"),
            failed_unit_count=None,
            external_probe_ok=False,
        )
    ).as_dict()
    assert [metric["value"] for metric in failed["metrics"]] == [
        5401,
        1,
        0,
        1,
        0,
        1,
        1,
        20,
        1024,
    ]
    # An unmeasured database and a nearly full disk: the database fails closed at
    # the critical size, the disk percent rounds up, and the decision is critical.
    capacity = build_metric_receipt(
        replace(_healthy_inputs(), disk_used_percent=85.3, database_bytes=None)
    ).as_dict()
    assert [metric["value"] for metric in capacity["metrics"][-3:]] == [
        1,
        86,
        operational_health_module.DATABASE_CRITICAL_BYTES,
    ]

    warning_lane = build_warning_lane_metric_receipt(_healthy_inputs()).as_dict()
    assert warning_lane["namespace"] == "SmithLabs/SmithGuardWarningLane"
    assert len(warning_lane["metrics"]) == 10
    assert [metric["value"] for metric in warning_lane["metrics"]] == [0] * 10
    fail_closed_warning_lane = build_warning_lane_metric_receipt(
        replace(_healthy_inputs(), warning_lane_health=None)
    ).as_dict()
    assert [metric["value"] for metric in fail_closed_warning_lane["metrics"]] == [
        0,
        1,
        901,
        1,
        2701,
        0,
        7501,
        1,
        1,
        1,
    ]


@pytest.mark.audit_ids("WL-10")
def test_warning_lane_summary_uses_the_schedule_state_not_policy_state() -> None:
    inactive = evaluate_operational_health(
        replace(
            _healthy_inputs(),
            warning_lane_health=replace(
                _healthy_inputs().warning_lane_health,
                schedule_expected=False,
                policy_active=1,
            ),
        )
    )
    inactive_check = next(
        check for check in inactive.checks if check.code == "scheduled_warning_lane"
    )
    assert inactive_check.status == "healthy"
    assert "paused" in inactive_check.summary

    expected_but_inactive = evaluate_operational_health(
        replace(
            _healthy_inputs(),
            warning_lane_health=replace(
                _healthy_inputs().warning_lane_health,
                schedule_expected=True,
                dispatch_enabled=True,
                discovery_timer_active=True,
                policy_active=0,
            ),
        )
    )
    expected_check = next(
        check for check in expected_but_inactive.checks if check.code == "scheduled_warning_lane"
    )
    assert expected_check.status == "degraded"
    assert "breached" in expected_check.summary


def test_scheduled_openssf_health_and_capacity_fail_closed() -> None:
    healthy = replace(
        _healthy_inputs(),
        active_units={
            **_healthy_inputs().active_units,
            "smithguard-openssf-shadow.timer": True,
        },
        job_results={
            **_healthy_inputs().job_results,
            "smithguard-openssf-shadow.service": "success",
        },
        openssf_monitor=_openssf_monitor(),
        openssf_schedule_expected=True,
    )
    assert evaluate_operational_health(healthy).status == "healthy"
    assert [metric.value for metric in build_metric_receipt(healthy).metrics[3:6]] == [
        1,
        1024,
        1,
    ]

    catalog_scheduled = replace(
        healthy,
        active_units={
            **healthy.active_units,
            "smithguard-openssf-catalog.timer": True,
        },
        job_results={
            **healthy.job_results,
            "smithguard-openssf-catalog.service": "success",
        },
        openssf_catalog_schedule_expected=True,
    )
    assert evaluate_operational_health(catalog_scheduled).status == "healthy"
    missing_catalog_timer = replace(
        catalog_scheduled,
        active_units={
            **catalog_scheduled.active_units,
            "smithguard-openssf-catalog.timer": False,
        },
    )
    assert evaluate_operational_health(missing_catalog_timer).status == "critical"

    stale = replace(
        healthy,
        openssf_monitor=_openssf_monitor(age=timedelta(minutes=91)),
    )
    report = evaluate_operational_health(stale)
    assert report.status == "critical"
    assert "openssf_source_health" in {
        check.code for check in report.checks if check.status == "critical"
    }
    assert [metric.value for metric in build_metric_receipt(stale).metrics[3:6]] == [
        0,
        1024,
        1,
    ]

    low_disk = replace(
        healthy,
        openssf_monitor=replace(
            _openssf_monitor(),
            filesystem_available_bytes=19 * 1024**3,
        ),
    )
    low_disk_report = evaluate_operational_health(low_disk)
    assert low_disk_report.status == "critical"
    assert "openssf_filesystem_capacity" in {
        check.code for check in low_disk_report.checks if check.status == "critical"
    }
    assert [metric.value for metric in build_metric_receipt(low_disk).metrics[3:6]] == [
        1,
        1024,
        0,
    ]


def _progress(
    sequence: int,
    *,
    state: str,
    occurred_at: datetime,
    segment: str = "malware",
) -> CollectorProgressRecord:
    return CollectorProgressRecord(
        progress_event_id=f"gbsec:collector-progress:health-{segment}-{sequence}",
        source_id=GITHUB_ADVISORY,
        segment=segment,
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
        reason_code="synthetic_health_progress",
        occurred_at=occurred_at,
        record_hash="sha256:" + f"{sequence:064x}",
    )


def _catalog_progress(
    sequence: int, *, state: str, occurred_at: datetime
) -> tuple[CollectorProgressRecord, ...]:
    return tuple(
        _progress(sequence, state=state, occurred_at=occurred_at, segment=segment)
        for segment in ("malware", "reviewed", "unreviewed")
    )


def test_public_readiness_requires_current_migration_and_fresh_updates(
    public_runtime_database,
) -> None:
    with Session(public_runtime_database.engine) as session, session.begin():
        ready, reasons = public_readiness(session, measured_at=NOW)
        assert not ready
        assert reasons == ("updates_missing", "openssf_catalog_missing")
        session.add_all(_catalog_progress(1, state="complete", occurred_at=NOW))
        session.add_all(openssf_manifest_pair(observed_at=NOW))

    with Session(public_runtime_database.engine) as session, session.begin():
        ready, reasons = public_readiness(session, measured_at=NOW + timedelta(hours=1))
        assert ready
        assert reasons == ()
        session.add(
            EvidenceFinalizationRecord(
                finalization_id="gbsec:evidence-finalization:health-pending",
                evidence_id="gbsec:evidence:health-pending",
                digest="sha256:" + "a" * 64,
                staging_key="sha256:" + "a" * 64,
                byte_count=10,
                state="pending",
                attempts=0,
                last_error_code=None,
                staged_at=NOW,
                updated_at=NOW,
                finalized_at=None,
            )
        )

    with Session(public_runtime_database.engine) as session, session.begin():
        ready, reasons = public_readiness(session, measured_at=NOW + timedelta(hours=1))
        assert not ready
        assert reasons == ("evidence_finalization_incomplete",)
        finalization = session.get_one(
            EvidenceFinalizationRecord,
            "gbsec:evidence-finalization:health-pending",
        )
        finalization.state = "finalized"
        finalization.updated_at = NOW + timedelta(hours=1)
        finalization.finalized_at = NOW + timedelta(hours=1)
        session.add_all(_catalog_progress(2, state="failed", occurred_at=NOW + timedelta(hours=1)))

    with Session(public_runtime_database.engine) as session, session.begin():
        ready, reasons = public_readiness(session, measured_at=NOW + timedelta(hours=1))
        assert not ready
        assert reasons == ("updates_failed",)
        session.add_all(
            _catalog_progress(3, state="complete", occurred_at=NOW + timedelta(hours=1))
        )

    with Session(public_runtime_database.engine) as session:
        ready, reasons = public_readiness(session, measured_at=NOW + timedelta(hours=4))
        assert not ready
        assert reasons == ("updates_stale", "openssf_catalog_stale")


def test_public_readiness_requires_a_current_openssf_catalog(public_runtime_database) -> None:
    with Session(public_runtime_database.engine) as session, session.begin():
        session.add_all(_catalog_progress(1, state="complete", occurred_at=NOW))
        session.add_all(openssf_manifest_pair(observed_at=NOW))
        session.add_all(openssf_manifest_pair(observed_at=NOW, sequence=2, state="failed"))
    with Session(public_runtime_database.engine) as session:
        ready, reasons = public_readiness(session, measured_at=NOW + timedelta(minutes=30))
    assert not ready
    assert reasons == ("openssf_catalog_failed",)


def test_reviewed_migration_matches_the_candidate_runtime_release() -> None:
    journal = json.loads(MIGRATION_JOURNAL.read_text(encoding="ascii"))
    assert journal["migrations"][-1]["revision"] == "0036_bulletin_source_updates"
    assert EXPECTED_MIGRATION == "0036_bulletin_source_updates"
    files = {"app/migrations/journal.json": MIGRATION_JOURNAL.read_bytes()}
    for entry in journal["migrations"]:
        files[f"app/migrations/{entry['file']}"] = (
            MIGRATION_JOURNAL.parent / entry["file"]
        ).read_bytes()
    assert runtime_release._verify_migration_journal(files) == EXPECTED_MIGRATION


def test_public_readiness_rejects_the_prior_production_migration_head(database) -> None:
    with Session(database.engine) as session, session.begin():
        session.add_all(_catalog_progress(1, state="complete", occurred_at=NOW))
        session.add_all(openssf_manifest_pair(observed_at=NOW))
        session.execute(
            text("UPDATE public.alembic_version SET version_num = '0013_watch_rebrand'")
        )

    with Session(database.engine) as session:
        ready, reasons = public_readiness(session, measured_at=NOW)
    assert not ready
    assert reasons == ("database_revision_incomplete",)


def test_warning_deadline_query_uses_only_the_latest_active_revision(database) -> None:
    with Session(database.engine) as session, session.begin():
        create_preliminary_warning(
            session,
            draft=PreliminaryWarningDraft(
                title="Synthetic operational deadline",
                claim="Two synthetic sources describe a possible package compromise.",
                affected_artifacts=("npm:synthetic-deadline@1.0.0",),
                source_urls=(
                    "https://first.example/deadline-one",
                    "https://second.example/deadline-two",
                ),
                evidence_class="web_and_social",
                independent_source_clusters=2,
                observed_at=NOW,
                reviewer_id="reviewer:synthetic",
            ),
            reviewed_at=NOW,
        )

    with Session(database.engine) as session:
        assert (
            _warning_deadlines(
                session,
                measured_at=NOW + timedelta(minutes=30),
            )
            == 0
        )
        assert (
            _warning_deadlines(
                session,
                measured_at=NOW + timedelta(hours=1, minutes=11),
            )
            == 1
        )


def test_receipts_and_health_reports_are_bounded_and_permission_safe(
    tmp_path: Path,
) -> None:
    openssf_receipt = tmp_path / "openssf-monitor.json"
    openssf_receipt.write_text(
        json.dumps(
            {
                "checkpoint": "a" * 40,
                "filesystem_available_bytes": 30 * 1024**3,
                "filesystem_used_percent": 40,
                "healthy": True,
                "measured_at": "2026-08-06T12:00:00Z",
                "schema_version": "1.0.0",
                "source_id": "gbsec:source:openssf-malicious-packages",
                "state_apparent_bytes": 1024,
                "state_entry_count": 10,
                "status": "success",
            }
        ),
        encoding="ascii",
    )
    openssf_receipt.chmod(0o640)
    assert load_openssf_monitor_receipt(tmp_path / "absent-openssf.json") is None
    loaded_openssf = load_openssf_monitor_receipt(openssf_receipt)
    assert loaded_openssf is not None
    assert loaded_openssf.checkpoint == "a" * 40
    assert loaded_openssf.state_apparent_bytes == 1024

    openssf_receipt.chmod(0o646)
    with pytest.raises(OperationalHealthError, match="permissions"):
        load_openssf_monitor_receipt(openssf_receipt)

    report_root = tmp_path / "health"
    report_root.mkdir(mode=0o750)
    report_root.chmod(0o2750)
    report_path = report_root / "latest.json"
    report = evaluate_operational_health(_healthy_inputs())
    write_health_report(report_path, report)
    assert stat.S_IMODE(report_path.stat().st_mode) == 0o640
    assert json.loads(report_path.read_text(encoding="ascii"))["status"] == "healthy"
    metric_path = report_root / "metrics-latest.json"
    write_metric_receipt(metric_path, build_metric_receipt(_healthy_inputs()))
    assert stat.S_IMODE(metric_path.stat().st_mode) == 0o640
    assert json.loads(metric_path.read_text(encoding="ascii"))["namespace"] == (
        "SmithLabs/SmithGuard"
    )

    report_root.chmod(0o750)
    with pytest.raises(OperationalHealthError, match="unsafe"):
        write_metric_receipt(
            report_root / "without-setgid.json", build_metric_receipt(_healthy_inputs())
        )


def test_health_probe_origin_is_fixed_to_smithguard(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "SMITHGUARD_DATABASE_URL",
        "postgresql+psycopg://smithguard-health@/smithguard?host=/run/postgresql",
    )
    monkeypatch.setenv("SMITHGUARD_BASE_URL", "https://untrusted.example")
    for name in (
        "SMITHGUARD_HEALTH_REPORT_PATH",
        "SMITHGUARD_METRIC_RECEIPT_PATH",
        "SMITHGUARD_WARNING_LANE_METRIC_RECEIPT_PATH",
        "SMITHGUARD_DISK_PATH",
        "SMITHGUARD_RIGHTS_REGISTER_PATH",
        "SMITHGUARD_GOVERNANCE_POLICY_PATH",
    ):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    with pytest.raises(HealthConfigurationError, match="HTTPS origin"):
        load_health_config()


def test_catalog_schedule_expectation_flag_is_exact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "SMITHGUARD_DATABASE_URL",
        "postgresql+psycopg://smithguard-health@/smithguard?host=/run/postgresql",
    )
    monkeypatch.setenv("SMITHGUARD_BASE_URL", "https://guard.smithlabs.ai")
    for name in (
        "SMITHGUARD_HEALTH_REPORT_PATH",
        "SMITHGUARD_METRIC_RECEIPT_PATH",
        "SMITHGUARD_WARNING_LANE_METRIC_RECEIPT_PATH",
        "SMITHGUARD_DISK_PATH",
        "SMITHGUARD_RIGHTS_REGISTER_PATH",
        "SMITHGUARD_GOVERNANCE_POLICY_PATH",
    ):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    monkeypatch.setenv("SMITHGUARD_OPENSSF_CATALOG_SCHEDULE_EXPECTED", "1")
    assert load_health_config().openssf_catalog_schedule_expected
    monkeypatch.setenv("SMITHGUARD_API_PRESSURE_EXPECTED", "1")
    assert load_health_config().api_pressure_expected
    monkeypatch.setenv("SMITHGUARD_API_PRESSURE_EXPECTED", "yes")
    with pytest.raises(HealthConfigurationError, match="must be exactly 0 or 1"):
        load_health_config()
    monkeypatch.setenv("SMITHGUARD_API_PRESSURE_EXPECTED", "0")
    monkeypatch.setenv("SMITHGUARD_OPENSSF_CATALOG_SCHEDULE_EXPECTED", "yes")
    with pytest.raises(HealthConfigurationError, match="must be exactly 0 or 1"):
        load_health_config()


def test_health_report_and_metric_receipt_cannot_overwrite_each_other(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "SMITHGUARD_DATABASE_URL",
        "postgresql+psycopg://smithguard-health@/smithguard?host=/run/postgresql",
    )
    monkeypatch.setenv("SMITHGUARD_BASE_URL", "https://guard.smithlabs.ai")
    same_path = tmp_path / "latest.json"
    for name in (
        "SMITHGUARD_HEALTH_REPORT_PATH",
        "SMITHGUARD_METRIC_RECEIPT_PATH",
    ):
        monkeypatch.setenv(name, str(same_path))
    for name in (
        "SMITHGUARD_DISK_PATH",
        "SMITHGUARD_RIGHTS_REGISTER_PATH",
        "SMITHGUARD_GOVERNANCE_POLICY_PATH",
    ):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    with pytest.raises(HealthConfigurationError, match="distinct"):
        load_health_config()


def test_failed_unit_measurement_is_bounded_and_fail_closed() -> None:
    observed: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object):
        observed.append(command)
        return operational_health_module.subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                "smithguard-health.service loaded failed failed SmithGuard health\n"
                "smithguard-metrics-publisher.service loaded failed failed metrics\n"
            ),
            stderr="",
        )

    assert operational_health_module.failed_unit_count(runner=runner) == 2
    # Only the product's own units are measured; an old operator unit never pages.
    assert observed[0][-len(operational_health_module.PRODUCT_UNITS) :] == list(
        operational_health_module.PRODUCT_UNITS
    )
    assert not any("*" in argument for argument in observed[0])

    def malformed(command: list[str], **_kwargs: object):
        return operational_health_module.subprocess.CompletedProcess(
            command,
            0,
            stdout="unrelated.service loaded failed failed unrelated\n",
            stderr="",
        )

    assert operational_health_module.failed_unit_count(runner=malformed) is None

    def rejected(command: list[str], **_kwargs: object):
        return operational_health_module.subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="failed",
        )

    assert operational_health_module.failed_unit_count(runner=rejected) is None

    def oversized(command: list[str], **_kwargs: object):
        return operational_health_module.subprocess.CompletedProcess(
            command,
            0,
            stdout="x" * 32_769,
            stderr="",
        )

    assert operational_health_module.failed_unit_count(runner=oversized) is None


def test_external_probe_requires_the_exact_health_document(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        status_code = 200

        def __init__(self, document: object) -> None:
            self.document = document

        def json(self) -> object:
            return self.document

    monkeypatch.setattr(
        operational_health_module.httpx,
        "get",
        lambda *_args, **_kwargs: Response({"status": "ok", "service_state": "public-beta"}),
    )
    assert operational_health_module._default_probe("https://guard.smithlabs.ai/healthz")
    monkeypatch.setattr(
        operational_health_module.httpx,
        "get",
        lambda *_args, **_kwargs: Response({"status": "ok", "extra": True}),
    )
    assert not operational_health_module._default_probe("https://guard.smithlabs.ai/healthz")


def test_health_main_writes_human_and_metric_documents(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    health_root = tmp_path / "health-main"
    health_root.mkdir(mode=0o750)
    health_root.chmod(0o2750)
    config = HealthConfig(
        database_url="postgresql+psycopg://smithguard-health@/smithguard?host=/run/postgresql",
        base_url="https://guard.smithlabs.ai",
        report_path=health_root / "latest.json",
        metric_receipt_path=health_root / "metrics-latest.json",
        warning_lane_metric_receipt_path=(health_root / "warning-lane-metrics-latest.json"),
        disk_path=tmp_path,
        spend_policy_path=POLICY_ROOT / "xai-spend-policy.json",
        rights_register_path=POLICY_ROOT / "source-rights-register.json",
        governance_policy_path=POLICY_ROOT / "source-governance-policy.json",
    )
    monkeypatch.setattr(operational_health_module, "load_health_config", lambda: config)
    monkeypatch.setattr(
        operational_health_module,
        "collect_operational_inputs",
        lambda *_args, **_kwargs: _healthy_inputs(),
    )
    assert operational_health_module.health_main() == 0
    assert json.loads(config.report_path.read_text(encoding="ascii"))["status"] == "healthy"
    metric = json.loads(config.metric_receipt_path.read_text(encoding="ascii"))
    assert metric["namespace"] == "SmithLabs/SmithGuard"
    assert len(metric["metrics"]) == 9
    warning_lane_metric = json.loads(
        config.warning_lane_metric_receipt_path.read_text(encoding="ascii")
    )
    assert warning_lane_metric["namespace"] == "SmithLabs/SmithGuardWarningLane"
    assert len(warning_lane_metric["metrics"]) == 10


def test_health_main_returns_success_for_a_critical_decision(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    health_root = tmp_path / "health-main-critical"
    health_root.mkdir(mode=0o750)
    health_root.chmod(0o2750)
    config = HealthConfig(
        database_url="postgresql+psycopg://smithguard-health@/smithguard?host=/run/postgresql",
        base_url="https://guard.smithlabs.ai",
        report_path=health_root / "latest.json",
        metric_receipt_path=health_root / "metrics-latest.json",
        warning_lane_metric_receipt_path=(health_root / "warning-lane-metrics-latest.json"),
        disk_path=tmp_path,
        spend_policy_path=POLICY_ROOT / "xai-spend-policy.json",
        rights_register_path=POLICY_ROOT / "source-rights-register.json",
        governance_policy_path=POLICY_ROOT / "source-governance-policy.json",
    )
    monkeypatch.setattr(operational_health_module, "load_health_config", lambda: config)
    monkeypatch.setattr(
        operational_health_module,
        "collect_operational_inputs",
        lambda *_args, **_kwargs: replace(_healthy_inputs(), failed_unit_count=1),
    )

    assert operational_health_module.health_main() == 0
    assert json.loads(config.report_path.read_text(encoding="ascii"))["status"] == "critical"
    assert "status=critical decision_code=2" in capsys.readouterr().out


def test_operational_health_uses_the_release_governance_digest(
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[str | None] = []
    original = operational_health_module.catalog_collection_freshness

    def capture(*args, **kwargs):
        observed.append(kwargs["expected_governance_policy_sha256"])
        return original(*args, **kwargs)

    monkeypatch.setattr(operational_health_module, "catalog_collection_freshness", capture)
    monkeypatch.setattr(operational_health_module, "_unit_active", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        operational_health_module,
        "_unit_result",
        lambda *_args, **_kwargs: "success",
    )
    config = HealthConfig(
        database_url=database.url.render_as_string(hide_password=False),
        base_url="https://guard.smithlabs.ai",
        report_path=tmp_path / "health.json",
        metric_receipt_path=tmp_path / "metrics.json",
        warning_lane_metric_receipt_path=tmp_path / "warning-metrics.json",
        disk_path=tmp_path,
        spend_policy_path=POLICY_ROOT / "xai-spend-policy.json",
        rights_register_path=POLICY_ROOT / "source-rights-register.json",
        governance_policy_path=POLICY_ROOT / "source-governance-policy.json",
    )
    collect_operational_inputs(config, measured_at=NOW, probe=lambda _url: True)
    assert len(observed) == 2
    assert observed[0] is not None
    assert observed[0] == observed[1]


def test_pressure_freshness_uses_read_time_after_slow_health_checks(
    database, monkeypatch, tmp_path
):
    import smithguard.api_pressure as pressure_module

    clock = [NOW]

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0]

    monkeypatch.setattr(pressure_module, "datetime", Clock)
    parent = tmp_path / "pressure"
    parent.mkdir(mode=0o2750)
    parent.chmod(0o2750)
    path = parent / "latest.json"
    monkeypatch.setattr(operational_health_module, "PRESSURE_PATH", path)
    monkeypatch.setattr(operational_health_module, "_unit_active", lambda *a, **k: True)
    monkeypatch.setattr(operational_health_module, "_unit_result", lambda *a, **k: "success")
    config = HealthConfig(
        database_url=database.url.render_as_string(hide_password=False),
        base_url="https://guard.smithlabs.ai",
        report_path=tmp_path / "health.json",
        metric_receipt_path=tmp_path / "metrics.json",
        warning_lane_metric_receipt_path=tmp_path / "warning-metrics.json",
        disk_path=tmp_path,
        spend_policy_path=POLICY_ROOT / "xai-spend-policy.json",
        rights_register_path=POLICY_ROOT / "source-rights-register.json",
        governance_policy_path=POLICY_ROOT / "source-governance-policy.json",
        api_pressure_expected=True,
    )

    def slow_probe(_url):
        clock[0] = NOW + timedelta(seconds=30)
        pressure_module.ApiPressure().write(path, now=clock[0])
        return True

    result = collect_operational_inputs(config, measured_at=NOW, probe=slow_probe)
    assert result.measured_at == NOW
    assert result.api_pressure == "healthy"
    clock[0] += timedelta(seconds=181)
    assert pressure_module.pressure_status(path) == "unavailable"
    clock[0] = NOW
    assert pressure_module.pressure_status(path) == "unavailable"


def test_health_report_carries_the_owner_backup_policy_without_recovery_checks():
    report = evaluate_operational_health(_healthy_inputs())
    assert report.status == "healthy"
    assert report.as_dict()["backup_restore_policy"] == "not_required_by_owner_20260911"
    codes = {check.code for check in report.checks}
    assert not any(
        code.startswith(("backup_", "restore_", "retention_", "measured_rp", "measured_rt"))
        for code in codes
    )
    for name in ("backup", "restore-drill", "retention", "snapshot-retention"):
        assert f"unit_active:smithguard-{name}.timer" not in codes
        assert f"job_result:smithguard-{name}.service" not in codes
    assert {
        "database_connectivity",
        "updates_freshness",
        "failed_smithguard_units",
        "root_disk_usage",
    } <= codes


@pytest.mark.parametrize(
    ("base_url", "accepted"),
    [
        ("https://api.smithguard.io", True),
        ("https://guard.smithlabs.ai", True),
        ("https://smithguard.io", False),
        ("http://api.smithguard.io", False),
    ],
)
def test_health_base_url_accepts_the_canonical_and_legacy_hosts_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, base_url: str, accepted: bool
) -> None:
    monkeypatch.setenv(
        "SMITHGUARD_DATABASE_URL",
        "postgresql+psycopg://smithguard-health@/smithguard?host=/run/postgresql",
    )
    monkeypatch.setenv("SMITHGUARD_BASE_URL", base_url)
    for name in (
        "SMITHGUARD_HEALTH_REPORT_PATH",
        "SMITHGUARD_METRIC_RECEIPT_PATH",
        "SMITHGUARD_WARNING_LANE_METRIC_RECEIPT_PATH",
        "SMITHGUARD_DISK_PATH",
        "SMITHGUARD_RIGHTS_REGISTER_PATH",
        "SMITHGUARD_GOVERNANCE_POLICY_PATH",
    ):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    if accepted:
        assert load_health_config().base_url == base_url
    else:
        with pytest.raises(HealthConfigurationError):
            load_health_config()


def test_health_documents_keep_group_read_under_a_restrictive_umask(tmp_path: Path) -> None:
    previous = os.umask(0o077)
    try:
        report_root = tmp_path / "health"
        report_root.mkdir(mode=0o750)
        report_root.chmod(0o2750)
        metric_path = report_root / "metrics.json"
        write_metric_receipt(metric_path, build_metric_receipt(_healthy_inputs()))
        assert stat.S_IMODE(metric_path.stat().st_mode) == 0o640
    finally:
        os.umask(previous)


@pytest.mark.parametrize("invalid_status", ({}, []))
def test_unhashable_monitor_status_is_a_health_error(
    tmp_path: Path, invalid_status: object
) -> None:
    path = tmp_path / "openssf.json"
    path.write_text(
        json.dumps(
            {
                "checkpoint": "a" * 40,
                "filesystem_available_bytes": 30 * 1024**3,
                "filesystem_used_percent": 40,
                "healthy": True,
                "measured_at": "2026-08-06T12:00:00Z",
                "schema_version": "1.0.0",
                "source_id": "gbsec:source:openssf-malicious-packages",
                "state_apparent_bytes": 1024,
                "state_entry_count": 10,
                "status": invalid_status,
            }
        ),
        encoding="ascii",
    )
    path.chmod(0o640)
    with pytest.raises(OperationalHealthError, match="identity or status"):
        load_openssf_monitor_receipt(path)


def test_degraded_catalog_receipt_keeps_the_alarm_metric_healthy() -> None:
    """One failed catalog attempt with a fresh snapshot is degraded in the report and
    does not trip the OpenSSF alarm metric; an expired or unhealthy receipt does."""
    base = replace(
        _healthy_inputs(),
        active_units={
            **_healthy_inputs().active_units,
            "smithguard-openssf-catalog.timer": True,
        },
        job_results={
            **_healthy_inputs().job_results,
            "smithguard-openssf-catalog.service": "exit-code",
        },
        openssf_catalog_schedule_expected=True,
        openssf_monitor_source="catalog",
    )
    fresh = replace(
        _openssf_monitor(),
        status="degraded",
        monitor_source="catalog",
        stale_after=NOW + timedelta(hours=1),
    )
    degraded = replace(base, openssf_monitor=fresh)
    report = evaluate_operational_health(degraded)
    checks = {check.code: check.status for check in report.checks}
    assert checks["openssf_source_health"] == "degraded"
    assert checks["job_result:smithguard-openssf-catalog.service"] == "degraded"
    assert report.status == "degraded"
    metrics = {metric.name: metric.value for metric in build_metric_receipt(degraded).metrics}
    assert metrics["OpenSSFHealthy"] == 1

    for receipt in (
        replace(fresh, stale_after=NOW - timedelta(minutes=1)),  # expired snapshot
        replace(fresh, healthy=False, status="failure"),
    ):
        failing = replace(base, openssf_monitor=receipt)
        assert {check.code: check.status for check in evaluate_operational_health(failing).checks}[
            "openssf_source_health"
        ] == "critical"
        failing_metrics = {m.name: m.value for m in build_metric_receipt(failing).metrics}
        assert failing_metrics["OpenSSFHealthy"] == 0


def test_external_probe_measures_reachability_not_data_freshness() -> None:
    """The tunnel metric probes liveness: a data backlog must never read as a tunnel
    outage (data freshness has its own collector-age metric)."""
    import inspect

    source = inspect.getsource(operational_health_module)
    assert 'probe(f"{config.base_url}/healthz")' in source
    assert "/readyz" not in source


def test_product_units_match_the_packaged_units() -> None:
    from smithguard.deploy.release import SYSTEMD_UNITS

    assert set(operational_health_module.PRODUCT_UNITS) == {
        *SYSTEMD_UNITS,
        "smithguard-cloudflared.service",
    }


def test_a_lane_working_through_a_backlog_is_catching_up_not_stale(
    public_runtime_database,
) -> None:
    """Newest completed window is old, but pages are still accepted: readiness holds,
    health is degraded (not critical) and collector age preserves coverage lag."""
    with Session(public_runtime_database.engine) as session, session.begin():
        session.add_all(_catalog_progress(1, state="complete", occurred_at=NOW))
        session.add_all(
            _progress(2, state="in_progress", occurred_at=NOW + timedelta(days=3), segment=segment)
            for segment in ("malware", "reviewed", "unreviewed")
        )
        session.add_all(openssf_manifest_pair(observed_at=NOW + timedelta(days=3)))
    later = NOW + timedelta(days=3, minutes=10)
    with Session(public_runtime_database.engine) as session:
        updates = catalog_collection_freshness(session, lane="updates", measured_at=later)
        ready, reasons = public_readiness(session, measured_at=later)
    assert updates.state == "catching_up"
    assert ready and reasons == ()
    with Session(public_runtime_database.engine) as session:
        stopped = catalog_collection_freshness(
            session, lane="updates", measured_at=NOW + timedelta(days=4)
        )
    assert stopped.state == "stale"
    # Completing the old window is progress too: still catching up, not an outage.
    with Session(public_runtime_database.engine) as session, session.begin():
        for segment in ("malware", "reviewed", "unreviewed"):
            row = _progress(
                3, state="complete", occurred_at=NOW + timedelta(days=4), segment=segment
            )
            row.window_started_at = NOW  # an old window, completed now
            row.window_ended_at = NOW + timedelta(days=1)
            session.add(row)
        session.add_all(openssf_manifest_pair(observed_at=NOW + timedelta(days=4), sequence=2))
    with Session(public_runtime_database.engine) as session:
        completed = catalog_collection_freshness(
            session, lane="updates", measured_at=NOW + timedelta(days=4, minutes=5)
        )
        ready, reasons = public_readiness(session, measured_at=NOW + timedelta(days=4, minutes=5))
    assert completed.state == "catching_up"
    assert ready and reasons == ()
    # A failed page is never progress.
    with Session(public_runtime_database.engine) as session, session.begin():
        session.add(_progress(4, state="failed", occurred_at=NOW + timedelta(days=4, minutes=6)))
    with Session(public_runtime_database.engine) as session:
        failed = catalog_collection_freshness(
            session, lane="updates", measured_at=NOW + timedelta(days=4, minutes=7)
        )
    assert failed.state == "failed"
    inputs = replace(_healthy_inputs(), measured_at=later, updates=updates)
    checks = {check.code: check.status for check in evaluate_operational_health(inputs).checks}
    assert checks["updates_freshness"] == "degraded"
    metrics = {metric.name: metric.value for metric in build_metric_receipt(inputs).metrics}
    assert metrics["CollectorAgeSeconds"] == 3 * 86400 + 600


def test_coverage_alarm_age_does_not_drop_at_catching_up_boundary(public_runtime_database):
    with Session(public_runtime_database.engine) as session, session.begin():
        session.add_all(_catalog_progress(1, state="complete", occurred_at=NOW))
        session.add_all(
            _progress(2, state="in_progress", occurred_at=NOW + timedelta(hours=2), segment=segment)
            for segment in ("malware", "reviewed", "unreviewed")
        )
    values = []
    states = []
    for seconds in (149 * 60, 150 * 60, 150 * 60 + 1, 151 * 60):
        measured = NOW + timedelta(seconds=seconds)
        with Session(public_runtime_database.engine) as session:
            updates = catalog_collection_freshness(session, lane="updates", measured_at=measured)
        inputs = replace(_healthy_inputs(), measured_at=measured, updates=updates)
        values.append(
            next(
                m.value
                for m in build_metric_receipt(inputs).metrics
                if m.name == "CollectorAgeSeconds"
            )
        )
        states.append(updates.state)
    assert states == ["fresh", "fresh", "catching_up", "catching_up"]
    assert values == [8940, 9000, 9001, 9060]


@pytest.mark.parametrize(
    "changes",
    [
        {"discovery_timer_active": True},
        {"discovery_service_active": None},
        {"control_valid": False},
        {"dispatch_latched": True},
    ],
)
def test_dispatch_mismatch_or_latch_is_actionable_even_while_paused(changes):
    baseline = _healthy_inputs()
    lane = replace(baseline.warning_lane_health, **changes)
    report = evaluate_operational_health(replace(baseline, warning_lane_health=lane))
    assert report.status == "critical"
    assert (
        next(item for item in report.checks if item.code == "warning_dispatch_control").status
        == "critical"
    )
    assert report.as_dict()["warning_lane"][next(iter(changes))] == next(iter(changes.values()))


@pytest.mark.parametrize(
    "code,state,expected",
    [
        (3, "inactive", False),
        (0, "active", True),
        (3, "failed", True),
        (3, "activating", True),
        (3, "deactivating", True),
        (4, "unknown", None),
        (0, "", None),
        (0, "inactive", None),
    ],
)
def test_warning_activity_does_not_treat_unknown_as_paused(code, state, expected):
    import subprocess

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, code, stdout=state + "\n")

    assert (
        operational_health_module._warning_unit_active("synthetic.service", runner=runner)
        is expected
    )


@pytest.mark.parametrize("state", ["missing", "failed", "stale"])
def test_each_supplemental_failure_is_critical(state):
    from smithguard.supplemental_store import SOURCE_NAMES

    for source_id in SOURCE_NAMES:
        states = dict.fromkeys(SOURCE_NAMES, "fresh")
        states[source_id] = state
        report = evaluate_operational_health(
            replace(_healthy_inputs(), supplemental_sources=states)
        )
        selected = [
            check for check in report.checks if check.code.startswith("supplemental_source:")
        ]
        assert len(selected) == 4
        assert sum(check.status == "critical" for check in selected) == 1
        assert report.status == "critical"
        assert any(state in check.summary for check in selected)


def test_all_four_fresh_supplemental_sources_are_healthy():
    from smithguard.supplemental_store import SOURCE_NAMES

    report = evaluate_operational_health(
        replace(_healthy_inputs(), supplemental_sources=dict.fromkeys(SOURCE_NAMES, "fresh"))
    )
    assert report.status == "healthy"
    assert all(check.status == "healthy" for check in report.checks)


@pytest.mark.parametrize(
    "state, expected",
    [
        ("fresh", "healthy"),
        ("paused", "healthy"),
        ("incomplete", "degraded"),
        ("publication_paused", "degraded"),
        ("unavailable", "critical"),
    ],
)
def test_bulletin_status_uses_existing_health_alarm(state, expected):
    from dataclasses import replace

    report = evaluate_operational_health(replace(_healthy_inputs(), bulletin_status=state))
    assert (
        next(check.status for check in report.checks if check.code == "bulletin_publication")
        == expected
    )
