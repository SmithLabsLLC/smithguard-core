"""Private, bounded operational health decisions for the public beta."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, aliased

from smithguard.api_pressure import PRESSURE_PATH, host_pressure_status, pressure_status
from smithguard.catalog_health import CATALOG_HEALTH_PATH, CatalogHealthError, load_catalog_health
from smithguard.collection_records import actionable_quarantine_count
from smithguard.collectors import GITHUB_ADVISORY
from smithguard.coverage import (
    CollectionFreshness,
    catalog_collection_freshness,
    openssf_catalog_freshness,
)
from smithguard.db.models import (
    EvidenceFinalizationRecord,
    MigrationJournalRecord,
    PreliminaryWarningRecord,
)
from smithguard.deploy.release import SYSTEMD_UNITS
from smithguard.diagnostics import write_exception_diagnostic
from smithguard.execution_policy import BACKUP_RESTORE_POLICY
from smithguard.fsio import FsioError, atomic_write, read_private_file
from smithguard.identifiers import parse_timestamp, pretty_json_bytes, timestamp
from smithguard.migration_head import EXPECTED_MIGRATION as _EXPECTED_MIGRATION
from smithguard.openssf_budget import CATALOG_FRESHNESS_MAX_AGE
from smithguard.openssf_git import COMMIT, OPENSSF_MALICIOUS
from smithguard.source_governance import SourceGovernancePolicy
from smithguard.source_rights import RightsRegistry
from smithguard.spend import load_spend_policy_path
from smithguard.supplemental_store import SOURCE_NAMES, source_state
from smithguard.warning_dispatch import (
    DispatchControlError,
    generation_paused,
    read_runtime_control,
)
from smithguard.warning_lane_health import (
    WARNING_LANE_FAIL_CLOSED_VALUES,
    WARNING_LANE_METRIC_NAMESPACE,
    WARNING_LANE_METRIC_SCHEMA_VERSION,
    WARNING_LANE_METRICS,
    WarningLaneHealth,
    collect_warning_lane_health,
)

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SPEND_POLICY = PACKAGE_ROOT / "contracts/v1/xai-spend-policy.json"
# The canonical public API host and the legacy production host it replaced.
PUBLIC_API_HOSTNAMES = frozenset({"api.smithguard.io", "guard.smithlabs.ai"})
EXPECTED_MIGRATION = _EXPECTED_MIGRATION
HEALTH_SCHEMA_VERSION = "1.0.0"
METRIC_RECEIPT_SCHEMA_VERSION = "1.0.0"
METRIC_NAMESPACE = "SmithLabs/SmithGuard"
DEFAULT_WARNING_LANE_METRIC_RECEIPT_PATH = Path(
    "/var/lib/smithguard/health/warning-lane-metrics-latest.json"
)
OPENSSF_MAX_AGE = timedelta(minutes=90)
DISK_WARNING_PERCENT = 75.0
DISK_CRITICAL_PERCENT = 85.0
DATABASE_WARNING_BYTES = 10 * 1024**3
DATABASE_CRITICAL_BYTES = 12 * 1024**3
# The published database size is bounded at 1 TiB (the root disk is far smaller).
DATABASE_METRIC_MAXIMUM_BYTES = 1024**4
WARNING_DEADLINE_GRACE = timedelta(minutes=10)
MAX_RECEIPT_BYTES = 65_536
MAX_METRIC_VALUE = 10**9
OPENSSF_STATE_WARNING_BYTES = 4 * 1024**3
OPENSSF_STATE_CRITICAL_BYTES = 5 * 1024**3
OPENSSF_FILESYSTEM_MIN_AVAILABLE_BYTES = 20 * 1024**3
OPENSSF_FILESYSTEM_MAX_USED_PERCENT = 75
SYSTEMCTL_TIMEOUT_SECONDS = 10
COLLECTOR_ALARM_THRESHOLD_SECONDS = 5_400
FAIL_CLOSED_COLLECTOR_AGE_SECONDS = COLLECTOR_ALARM_THRESHOLD_SECONDS + 1
FAILED_UNIT = re.compile(r"^smithguard-[a-z0-9-]+\.(?:service|timer)$")

REQUIRED_ACTIVE_UNITS = (
    "smithguard-api.service",
    "smithguard-collect.timer",
    "smithguard-supplemental.timer",
    "smithguard-signals.timer",
    "smithguard-health.timer",
    "smithguard-metrics-publisher.timer",
    "smithguard-cloudflared.service",
)
REQUIRED_SUCCESSFUL_JOBS = (
    "smithguard-collect.service",
    "smithguard-supplemental.service",
    "smithguard-signals.service",
)


class OperationalHealthError(RuntimeError):
    """Operational evidence is missing, unsafe, or invalid."""


class HealthConfigurationError(ValueError):
    """Health configuration is absent or outside the fixed local boundary."""


@dataclass(frozen=True, slots=True)
class OpenSSFMonitorReceipt:
    measured_at: datetime
    healthy: bool
    status: str
    checkpoint: str | None
    state_apparent_bytes: int
    state_entry_count: int
    filesystem_available_bytes: int
    filesystem_used_percent: int
    monitor_source: str = "shadow"
    stale_after: datetime | None = None


@dataclass(frozen=True, slots=True)
class OperationalHealthInputs:
    measured_at: datetime
    database_available: bool
    migration_current: bool
    updates: CollectionFreshness
    historical: CollectionFreshness
    active_units: Mapping[str, bool]
    job_results: Mapping[str, str]
    failed_unit_count: int | None
    external_probe_ok: bool
    disk_used_percent: float
    database_bytes: int | None
    overdue_warning_count: int | None
    openssf_monitor: OpenSSFMonitorReceipt | None = None
    openssf_schedule_expected: bool = False
    openssf_catalog_schedule_expected: bool = False
    openssf_monitor_source: str = "shadow"
    warning_lane_health: WarningLaneHealth | None = None
    api_pressure_expected: bool = False
    api_pressure: str = "unavailable"
    host_pressure: str = "unavailable"
    supplemental_sources: Mapping[str, str] | None = None
    github_quarantined_records: int | None = 0
    bulletin_status: str | None = None


@dataclass(frozen=True, slots=True)
class HealthCheck:
    code: str
    status: str
    summary: str


@dataclass(frozen=True, slots=True)
class OperationalHealthReport:
    schema_version: str
    status: str
    measured_at: str
    checks: tuple[HealthCheck, ...]
    warning_lane: WarningLaneHealth | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "backup_restore_policy": BACKUP_RESTORE_POLICY,
            "measured_at": self.measured_at,
            "checks": [asdict(check) for check in self.checks],
            "warning_lane": asdict(self.warning_lane) if self.warning_lane is not None else None,
        }


@dataclass(frozen=True, slots=True)
class MetricDatum:
    name: str
    unit: str
    value: int


@dataclass(frozen=True, slots=True)
class MetricReceipt:
    schema_version: str
    namespace: str
    measured_at: str
    metrics: tuple[MetricDatum, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "namespace": self.namespace,
            "measured_at": self.measured_at,
            "metrics": [asdict(metric) for metric in self.metrics],
        }


@dataclass(frozen=True, slots=True)
class HealthConfig:
    database_url: str
    base_url: str
    report_path: Path
    metric_receipt_path: Path
    warning_lane_metric_receipt_path: Path
    disk_path: Path
    spend_policy_path: Path
    rights_register_path: Path
    governance_policy_path: Path
    openssf_monitor_receipt_path: Path = Path("/var/lib/smithguard/openssf-health/latest.json")
    openssf_schedule_expected: bool = False
    openssf_catalog_schedule_expected: bool = False
    openssf_monitor_source: str = "shadow"
    warning_lane_schedule_expected: bool = False
    api_pressure_expected: bool = False


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
Probe = Callable[[str], bool]


def _missing_freshness(lane: str) -> CollectionFreshness:
    return CollectionFreshness(
        lane=lane,
        latest_state=None,
        last_attempt_at=None,
        last_success_at=None,
        stale_after=None,
        state="missing",
    )


def public_readiness(
    session: Session,
    *,
    measured_at: datetime,
    expected_governance_policy_sha256: str | None = None,
) -> tuple[bool, tuple[str, ...]]:
    """Decide database, migration, and current-data (updates and catalog) readiness."""
    reasons: list[str] = []
    if session.get(MigrationJournalRecord, EXPECTED_MIGRATION) is None:
        reasons.append("migration_journal_incomplete")
    alembic_revision = session.scalar(text("SELECT version_num FROM public.alembic_version"))
    if alembic_revision != EXPECTED_MIGRATION:
        reasons.append("database_revision_incomplete")
    unresolved_evidence = session.scalar(
        select(func.count())
        .select_from(EvidenceFinalizationRecord)
        .where(EvidenceFinalizationRecord.state != "finalized")
    )
    if unresolved_evidence:
        reasons.append("evidence_finalization_incomplete")
    updates = catalog_collection_freshness(
        session,
        lane="updates",
        measured_at=measured_at,
        expected_governance_policy_sha256=expected_governance_policy_sha256,
    )
    if updates.state == "missing":
        reasons.append("updates_missing")
    elif updates.state == "failed":
        reasons.append("updates_failed")
    elif updates.state == "stale":
        reasons.append("updates_stale")
    # The malware catalog decides most "affected" answers; stale or failed data is
    # not ready even though the API itself is up.
    catalog = openssf_catalog_freshness(session, measured_at=measured_at)
    if catalog != "complete":
        reasons.append(f"openssf_catalog_{catalog}")
    return not reasons, tuple(reasons)


def _add(
    checks: list[HealthCheck],
    *,
    code: str,
    status: str,
    summary: str,
) -> None:
    checks.append(HealthCheck(code=code, status=status, summary=summary))


def _openssf_current(inputs, receipt, age) -> bool:
    if receipt.monitor_source != inputs.openssf_monitor_source:
        return False
    if receipt.monitor_source == "catalog":
        return bool(
            inputs.openssf_catalog_schedule_expected
            and timedelta(0) <= age <= CATALOG_FRESHNESS_MAX_AGE
            and receipt.stale_after is not None
            and inputs.measured_at <= receipt.stale_after
        )
    return inputs.openssf_schedule_expected and timedelta(0) <= age <= OPENSSF_MAX_AGE


def _openssf_receipt_current(inputs, receipt) -> bool:
    """One rule for the health check and the alarm metric: a successful or degraded
    (latest attempt failed, snapshot still fresh) receipt that is current."""
    if receipt is None:
        return False
    return bool(
        receipt.healthy
        and receipt.status in {"healthy", "success", "degraded"}
        and _openssf_current(inputs, receipt, inputs.measured_at - receipt.measured_at)
    )


def evaluate_operational_health(inputs: OperationalHealthInputs) -> OperationalHealthReport:
    """Turn bounded observations into one deterministic alert-ready decision."""
    checks: list[HealthCheck] = []
    if inputs.api_pressure_expected:
        for code, status in (
            ("api_pressure", inputs.api_pressure),
            ("host_pressure", inputs.host_pressure),
        ):
            _add(
                checks,
                code=code,
                status="healthy" if status == "healthy" else "critical",
                summary=f"Service capacity observation: {status}.",
            )
    _add(
        checks,
        code="database_connectivity",
        status="healthy" if inputs.database_available else "critical",
        summary=(
            "The operational database check succeeded."
            if inputs.database_available
            else "The operational database check failed."
        ),
    )
    _add(
        checks,
        code="database_migration",
        status="healthy" if inputs.migration_current else "critical",
        summary=(
            "The expected migration is present."
            if inputs.migration_current
            else "The expected migration is missing."
        ),
    )
    if inputs.bulletin_status is not None:
        _add(
            checks,
            code="bulletin_publication",
            status="healthy"
            if inputs.bulletin_status in {"fresh", "paused"}
            else "degraded"
            if inputs.bulletin_status in {"incomplete", "publication_paused"}
            else "critical",
            summary=f"Bulletin publication status is {inputs.bulletin_status}.",
        )
    if inputs.supplemental_sources is not None:
        for source_id in SOURCE_NAMES:
            state = inputs.supplemental_sources.get(source_id, "missing")
            _add(
                checks,
                code="supplemental_source:" + source_id.rsplit(":", 1)[-1],
                status="healthy" if state == "fresh" else "critical",
                summary=f"{SOURCE_NAMES[source_id]} collection is {state}.",
            )
    quarantine_count = inputs.github_quarantined_records
    _add(
        checks,
        code="github_record_quarantine",
        status="healthy" if quarantine_count == 0 else "critical",
        summary=(
            f"{quarantine_count} current-segment GitHub record(s) need named quarantine repair."
            if quarantine_count is not None
            else "GitHub record quarantine count is unavailable."
        ),
    )
    required_active_units = (
        REQUIRED_ACTIVE_UNITS
        + (("smithguard-openssf-shadow.timer",) if inputs.openssf_schedule_expected else ())
        + (
            ("smithguard-openssf-catalog.timer",)
            if inputs.openssf_catalog_schedule_expected
            else ()
        )
    )
    required_successful_jobs = (
        REQUIRED_SUCCESSFUL_JOBS
        + (("smithguard-openssf-shadow.service",) if inputs.openssf_schedule_expected else ())
        + (
            ("smithguard-openssf-catalog.service",)
            if inputs.openssf_catalog_schedule_expected
            else ()
        )
    )
    for unit in required_active_units:
        active = inputs.active_units.get(unit, False)
        _add(
            checks,
            code=f"unit_active:{unit}",
            status="healthy" if active else "critical",
            summary=f"{unit} is {'active' if active else 'not active'}.",
        )
    for unit in required_successful_jobs:
        # Collection jobs retry themselves (Restart=on-failure) and their data freshness
        # checks decide criticality; a failed last result alone is degraded. A unit that
        # exhausts its retries is still counted by failed_smithguard_units.
        result = inputs.job_results.get(unit, "unknown")
        _add(
            checks,
            code=f"job_result:{unit}",
            status="healthy" if result == "success" else "degraded",
            summary=f"{unit} last result is {result}.",
        )
    failed_units = inputs.failed_unit_count
    _add(
        checks,
        code="failed_smithguard_units",
        status="healthy" if failed_units == 0 else "critical",
        summary=(
            "No SmithGuard systemd unit is failed."
            if failed_units == 0
            else "One or more SmithGuard systemd units are failed or could not be measured."
        ),
    )
    _add(
        checks,
        code="external_tunnel_probe",
        status="healthy" if inputs.external_probe_ok else "critical",
        summary=(
            "The fixed public liveness probe succeeded through the tunnel."
            if inputs.external_probe_ok
            else "The fixed public liveness probe failed through the tunnel."
        ),
    )
    openssf = inputs.openssf_monitor
    if not (inputs.openssf_schedule_expected or inputs.openssf_catalog_schedule_expected):
        _add(
            checks,
            code="openssf_schedule",
            status="healthy",
            summary="The OpenSSF schedule is intentionally disabled.",
        )
    else:
        openssf_current = _openssf_receipt_current(inputs, openssf)
        degraded = openssf_current and openssf is not None and openssf.status == "degraded"
        _add(
            checks,
            code="openssf_source_health",
            status="degraded" if degraded else "healthy" if openssf_current else "critical",
            summary=(
                "The last OpenSSF catalog attempt failed; the served snapshot is still fresh."
                if degraded
                else "The OpenSSF source receipt is successful and current."
                if openssf_current
                else "The OpenSSF source receipt is missing, stale, or unsuccessful."
            ),
        )
        openssf_bytes = openssf.state_apparent_bytes if openssf is not None else None
        openssf_capacity_status = (
            "critical"
            if openssf_bytes is None or openssf_bytes >= OPENSSF_STATE_CRITICAL_BYTES
            else "degraded"
            if openssf_bytes >= OPENSSF_STATE_WARNING_BYTES
            else "healthy"
        )
        _add(
            checks,
            code="openssf_state_capacity",
            status=openssf_capacity_status,
            summary=(
                "The OpenSSF state size could not be measured."
                if openssf_bytes is None
                else f"OpenSSF private state uses {openssf_bytes} apparent bytes."
            ),
        )
        openssf_filesystem_healthy = (
            openssf is not None
            and openssf.filesystem_available_bytes >= OPENSSF_FILESYSTEM_MIN_AVAILABLE_BYTES
            and openssf.filesystem_used_percent < OPENSSF_FILESYSTEM_MAX_USED_PERCENT
        )
        _add(
            checks,
            code="openssf_filesystem_capacity",
            status="healthy" if openssf_filesystem_healthy else "critical",
            summary=(
                "The OpenSSF filesystem has the required capacity headroom."
                if openssf_filesystem_healthy
                else "The OpenSSF filesystem capacity is missing or outside its boundary."
            ),
        )
    # A lane working through a backlog is visible but not an outage.
    update_status = (
        "healthy"
        if inputs.updates.state == "fresh"
        else "degraded"
        if inputs.updates.state == "catching_up"
        else "critical"
    )
    _add(
        checks,
        code="updates_freshness",
        status=update_status,
        summary=f"The current update lane is {inputs.updates.state}.",
    )
    historical_status = (
        "healthy" if inputs.historical.state in {"fresh", "complete"} else "degraded"
    )
    _add(
        checks,
        code="historical_progress",
        status=historical_status,
        summary=f"The historical lane is {inputs.historical.state}.",
    )
    disk_status = (
        "critical"
        if inputs.disk_used_percent >= DISK_CRITICAL_PERCENT
        else "degraded"
        if inputs.disk_used_percent >= DISK_WARNING_PERCENT
        else "healthy"
    )
    _add(
        checks,
        code="root_disk_usage",
        status=disk_status,
        summary=f"Root disk use is {inputs.disk_used_percent:.1f} percent.",
    )
    database_status = (
        "critical"
        if inputs.database_bytes is None or inputs.database_bytes >= DATABASE_CRITICAL_BYTES
        else "degraded"
        if inputs.database_bytes >= DATABASE_WARNING_BYTES
        else "healthy"
    )
    _add(
        checks,
        code="database_size",
        status=database_status,
        summary=(
            "Database size could not be measured."
            if inputs.database_bytes is None
            else f"Database size is {inputs.database_bytes} bytes."
        ),
    )
    warning_count = inputs.overdue_warning_count
    _add(
        checks,
        code="warning_deadlines",
        status="healthy" if warning_count == 0 else "critical",
        summary=(
            "No active warning deadline is overdue."
            if warning_count == 0
            else "One or more active warning deadlines are overdue or unknown."
        ),
    )
    if inputs.warning_lane_health is not None:
        lane = inputs.warning_lane_health
        _add(
            checks,
            code="warning_dispatch_control",
            status="healthy" if lane.control_healthy and not lane.dispatch_latched else "critical",
            summary=(
                "Automatic containment is latched; a new checked restart is required."
                if lane.dispatch_latched
                else "Durable dispatch authority agrees with the observed warning units."
                if lane.control_healthy
                else "Dispatch authority is invalid or disagrees with warning activity."
            ),
        )
        _add(
            checks,
            code="scheduled_warning_lane",
            status="healthy" if lane.healthy else "degraded",
            summary=(
                "The warning lane is paused; retained failure history and expiry remain measured."
                if not lane.dispatch_enabled
                else "Automatic containment is latched; a new checked restart is required."
                if lane.dispatch_latched
                else "The active scheduled warning lane is inside its fail-closed "
                "source thresholds."
                if lane.healthy
                else "The active scheduled warning lane breached a fail-closed source threshold."
            )
            + (
                " Last recorded credential routes: "
                + ", ".join(f"{stage}={route}" for stage, route in lane.credential_routes)
                + "."
                if lane.credential_routes
                else ""
            ),
        )
    overall = (
        "critical"
        if any(check.status == "critical" for check in checks)
        else "degraded"
        if any(check.status == "degraded" for check in checks)
        else "healthy"
    )
    return OperationalHealthReport(
        schema_version=HEALTH_SCHEMA_VERSION,
        status=overall,
        measured_at=timestamp(inputs.measured_at),
        checks=tuple(checks),
        warning_lane=inputs.warning_lane_health,
    )


def build_metric_receipt(
    inputs: OperationalHealthInputs,
    report: OperationalHealthReport | None = None,
) -> MetricReceipt:
    """Produce the current metric batch from the evaluated inputs."""
    if report is None:
        report = evaluate_operational_health(inputs)
    disk_percent = min(max(math.ceil(inputs.disk_used_percent), 0), 100)
    database_bytes = (
        DATABASE_CRITICAL_BYTES
        if inputs.database_bytes is None
        else min(max(inputs.database_bytes, 0), DATABASE_METRIC_MAXIMUM_BYTES)
    )

    collector_age = FAIL_CLOSED_COLLECTOR_AGE_SECONDS
    # Coverage age has one meaning even while the collector accepts newer pages.
    # Progress remains visible through catching_up/degraded health, but must not
    # clear a coverage-lag alarm without advancing the completed window cutoff.
    if (
        inputs.updates.state in {"fresh", "stale", "catching_up"}
        and inputs.updates.last_success_at is not None
    ):
        age = (inputs.measured_at - inputs.updates.last_success_at).total_seconds()
        if age >= 0 and (
            inputs.updates.state == "fresh" or age > COLLECTOR_ALARM_THRESHOLD_SECONDS
        ):
            collector_age = min(math.ceil(age), MAX_METRIC_VALUE)

    failed_units = inputs.failed_unit_count
    if failed_units is None or isinstance(failed_units, bool) or not 0 <= failed_units <= 1_000:
        failed_units = 1

    openssf_healthy = 1
    openssf_state_bytes = 0
    openssf_filesystem_healthy = 1
    if inputs.openssf_schedule_expected or inputs.openssf_catalog_schedule_expected:
        openssf = inputs.openssf_monitor
        openssf_healthy = 0
        openssf_state_bytes = OPENSSF_STATE_CRITICAL_BYTES
        openssf_filesystem_healthy = 0
        if openssf is not None:
            openssf_state_bytes = min(
                openssf.state_apparent_bytes,
                OPENSSF_STATE_CRITICAL_BYTES,
            )
            if _openssf_receipt_current(inputs, openssf):
                openssf_healthy = 1
            if (
                openssf.filesystem_available_bytes >= OPENSSF_FILESYSTEM_MIN_AVAILABLE_BYTES
                and openssf.filesystem_used_percent < OPENSSF_FILESYSTEM_MAX_USED_PERCENT
            ):
                openssf_filesystem_healthy = 1

    return MetricReceipt(
        schema_version=METRIC_RECEIPT_SCHEMA_VERSION,
        namespace=METRIC_NAMESPACE,
        measured_at=timestamp(inputs.measured_at),
        metrics=(
            MetricDatum("CollectorAgeSeconds", "Seconds", collector_age),
            MetricDatum("FailedUnits", "Count", failed_units),
            MetricDatum("ExternalTunnelHealthy", "Count", int(inputs.external_probe_ok)),
            MetricDatum("OpenSSFHealthy", "Count", openssf_healthy),
            MetricDatum("OpenSSFStateBytes", "Bytes", openssf_state_bytes),
            MetricDatum("OpenSSFFilesystemHealthy", "Count", openssf_filesystem_healthy),
            MetricDatum("HealthCritical", "Count", int(report.status == "critical")),
            MetricDatum("RootDiskUsedPercent", "Percent", disk_percent),
            MetricDatum("DatabaseBytes", "Bytes", database_bytes),
        ),
    )


def build_warning_lane_metric_receipt(inputs: OperationalHealthInputs) -> MetricReceipt:
    """Produce the ten exact warning-lane values, breaching when collection failed."""

    values = (
        inputs.warning_lane_health.metric_values
        if inputs.warning_lane_health is not None
        else WARNING_LANE_FAIL_CLOSED_VALUES
    )
    return MetricReceipt(
        schema_version=WARNING_LANE_METRIC_SCHEMA_VERSION,
        namespace=WARNING_LANE_METRIC_NAMESPACE,
        measured_at=timestamp(inputs.measured_at),
        metrics=tuple(
            MetricDatum(name, unit, value)
            for (name, unit), value in zip(WARNING_LANE_METRICS, values, strict=True)
        ),
    )


def _parse_time(value: Any) -> datetime:
    try:
        return parse_timestamp(value, maximum=40)
    except ValueError as error:
        raise OperationalHealthError("operation receipt timestamp is invalid") from error


def load_openssf_monitor_receipt(
    path: Path, *, source: str = "shadow"
) -> OpenSSFMonitorReceipt | None:
    """Load only the explicitly selected bounded OpenSSF health format."""
    if source == "catalog":
        try:
            document = load_catalog_health(path)
        except CatalogHealthError as error:
            raise OperationalHealthError("catalog monitor receipt is invalid") from error
        if document is None:
            return None
        return OpenSSFMonitorReceipt(
            measured_at=_parse_time(document["measured_at"]),
            healthy=document["healthy"],
            status=document["status"],
            checkpoint=document["checkpoint"],
            state_apparent_bytes=document["state_apparent_bytes"],
            state_entry_count=document["state_entry_count"],
            filesystem_available_bytes=document["filesystem_available_bytes"],
            filesystem_used_percent=document["filesystem_used_percent"],
            monitor_source="catalog",
            stale_after=_parse_time(document["stale_after"]) if document["stale_after"] else None,
        )
    if source != "shadow":
        raise OperationalHealthError("OpenSSF monitor source is invalid")
    try:
        body = read_private_file(path, maximum=MAX_RECEIPT_BYTES, mode_mask=0o027, minimum=0)
    except FsioError as error:
        if error.code == "missing":
            return None
        raise OperationalHealthError(
            "OpenSSF monitor receipt path or permissions are unsafe"
        ) from error
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OperationalHealthError("OpenSSF monitor receipt JSON is invalid") from error
    required = {
        "checkpoint",
        "filesystem_available_bytes",
        "filesystem_used_percent",
        "healthy",
        "measured_at",
        "schema_version",
        "source_id",
        "state_apparent_bytes",
        "state_entry_count",
        "status",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise OperationalHealthError("OpenSSF monitor receipt shape is invalid")
    checkpoint = document["checkpoint"]
    if checkpoint is not None and (
        not isinstance(checkpoint, str) or COMMIT.fullmatch(checkpoint) is None
    ):
        raise OperationalHealthError("OpenSSF monitor checkpoint is invalid")
    status = document["status"]
    healthy = document["healthy"]
    if (
        document["schema_version"] != "1.0.0"
        or document["source_id"] != OPENSSF_MALICIOUS
        or not isinstance(status, str)
        or status not in {"critical", "disabled", "failure", "healthy", "quarantined", "success"}
        or not isinstance(healthy, bool)
        or healthy != (status in {"healthy", "success"})
    ):
        raise OperationalHealthError("OpenSSF monitor identity or status is invalid")

    def bounded_integer(name: str, maximum: int) -> int:
        value = document[name]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            raise OperationalHealthError(f"OpenSSF monitor {name} is invalid")
        return value

    return OpenSSFMonitorReceipt(
        measured_at=_parse_time(document["measured_at"]),
        healthy=healthy,
        status=status,
        checkpoint=checkpoint,
        state_apparent_bytes=bounded_integer("state_apparent_bytes", OPENSSF_STATE_CRITICAL_BYTES),
        state_entry_count=bounded_integer("state_entry_count", 2_000_000),
        filesystem_available_bytes=bounded_integer("filesystem_available_bytes", 10**16),
        filesystem_used_percent=bounded_integer("filesystem_used_percent", 100),
    )


def load_health_config() -> HealthConfig:
    def required(name: str) -> str:
        value = os.environ.get(name)
        if not value:
            raise HealthConfigurationError(f"{name} is required")
        return value

    def path(name: str, *, default: Path | None = None) -> Path:
        raw = os.environ.get(name)
        value = Path(raw) if raw is not None else default
        if value is None or not value.is_absolute():
            raise HealthConfigurationError(f"{name} must be an absolute path")
        return value

    database_url = required("SMITHGUARD_DATABASE_URL")
    try:
        parsed_database = make_url(database_url)
    except Exception as error:
        raise HealthConfigurationError("database URL is invalid") from error
    if (
        parsed_database.drivername != "postgresql+psycopg"
        or not parsed_database.database
        or parsed_database.host not in {None, "localhost", "127.0.0.1", "::1"}
    ):
        raise HealthConfigurationError("health database must be local PostgreSQL")
    query_host = parsed_database.query.get("host")
    if query_host is not None and (
        not isinstance(query_host, str) or not query_host.startswith("/")
    ):
        raise HealthConfigurationError("PostgreSQL socket host must be absolute")
    base_url = required("SMITHGUARD_BASE_URL")
    parsed_base = urlsplit(base_url)
    if (
        parsed_base.scheme != "https"
        or parsed_base.hostname not in PUBLIC_API_HOSTNAMES
        or parsed_base.username is not None
        or parsed_base.password is not None
        or parsed_base.path not in {"", "/"}
        or parsed_base.query
        or parsed_base.fragment
    ):
        raise HealthConfigurationError("health base URL must be an HTTPS origin")
    report_path = path("SMITHGUARD_HEALTH_REPORT_PATH")
    metric_receipt_path = path("SMITHGUARD_METRIC_RECEIPT_PATH")
    warning_lane_metric_receipt_path = path(
        "SMITHGUARD_WARNING_LANE_METRIC_RECEIPT_PATH",
        default=DEFAULT_WARNING_LANE_METRIC_RECEIPT_PATH,
    )
    health_documents = {
        report_path,
        metric_receipt_path,
        warning_lane_metric_receipt_path,
    }
    if len(health_documents) != 3 or len({item.parent for item in health_documents}) != 1:
        raise HealthConfigurationError(
            "health report and metric receipts must be distinct files in one directory"
        )

    def expected_flag(name: str) -> bool:
        value = os.environ.get(name, "0")
        if value not in {"0", "1"}:
            raise HealthConfigurationError(f"{name} must be exactly 0 or 1")
        return value == "1"

    openssf_schedule_expected = expected_flag("SMITHGUARD_OPENSSF_SCHEDULE_EXPECTED")
    openssf_catalog_schedule_expected = expected_flag(
        "SMITHGUARD_OPENSSF_CATALOG_SCHEDULE_EXPECTED"
    )
    monitor_source = os.environ.get("SMITHGUARD_OPENSSF_MONITOR_SOURCE", "shadow")
    if monitor_source not in {"catalog", "shadow"}:
        raise HealthConfigurationError("OpenSSF monitor source must be catalog or shadow")
    if monitor_source == "catalog" and not openssf_catalog_schedule_expected:
        raise HealthConfigurationError("catalog monitoring requires its expected schedule")
    monitor_path = path(
        "SMITHGUARD_OPENSSF_MONITOR_RECEIPT_PATH",
        default=CATALOG_HEALTH_PATH
        if monitor_source == "catalog"
        else Path("/var/lib/smithguard/openssf-health/latest.json"),
    )
    if monitor_source == "catalog" and monitor_path != CATALOG_HEALTH_PATH:
        raise HealthConfigurationError("catalog monitoring requires the fixed catalog receipt path")
    warning_lane_schedule_expected = expected_flag("SMITHGUARD_WARNING_LANE_SCHEDULE_EXPECTED")
    return HealthConfig(
        database_url=database_url,
        base_url=base_url.rstrip("/"),
        report_path=report_path,
        metric_receipt_path=metric_receipt_path,
        warning_lane_metric_receipt_path=warning_lane_metric_receipt_path,
        disk_path=path("SMITHGUARD_DISK_PATH"),
        spend_policy_path=path(
            "SMITHGUARD_SPEND_POLICY_PATH",
            default=DEFAULT_SPEND_POLICY,
        ),
        rights_register_path=path("SMITHGUARD_RIGHTS_REGISTER_PATH"),
        governance_policy_path=path("SMITHGUARD_GOVERNANCE_POLICY_PATH"),
        openssf_monitor_receipt_path=monitor_path,
        openssf_monitor_source=monitor_source,
        openssf_schedule_expected=openssf_schedule_expected,
        openssf_catalog_schedule_expected=openssf_catalog_schedule_expected,
        warning_lane_schedule_expected=warning_lane_schedule_expected,
        api_pressure_expected=expected_flag("SMITHGUARD_API_PRESSURE_EXPECTED"),
    )


def _unit_active(
    unit: str,
    *,
    runner: CommandRunner,
) -> bool:
    try:
        result = runner(
            ["/usr/bin/systemctl", "is-active", "--quiet", unit],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=SYSTEMCTL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _unit_result(
    unit: str,
    *,
    runner: CommandRunner,
) -> str:
    try:
        result = runner(
            ["/usr/bin/systemctl", "show", "--property=Result", "--value", unit],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=SYSTEMCTL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    value = result.stdout.strip() if result.returncode == 0 else "unknown"
    return value if value in {"success", "exit-code", "timeout", "signal"} else "unknown"


def _warning_unit_active(unit: str, *, runner: CommandRunner) -> bool | None:
    """Unlike ordinary active checks, unknown must not be mistaken for containment."""
    try:
        result = runner(
            ["/usr/bin/systemctl", "is-active", unit],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=SYSTEMCTL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    state = result.stdout.strip()
    if result.returncode == 3 and state == "inactive":
        return False
    if result.returncode in {0, 3} and state in {"active", "activating", "deactivating", "failed"}:
        return True
    return None


# Only the product's own units count; one-off operator units (for example an old
# maintenance or observation unit) never page as a production failure.
PRODUCT_UNITS = (*SYSTEMD_UNITS, "smithguard-cloudflared.service")


def failed_unit_count(*, runner: CommandRunner) -> int | None:
    try:
        result = runner(
            [
                "/usr/bin/systemctl",
                "list-units",
                "--failed",
                "--all",
                "--no-legend",
                "--plain",
                "--no-pager",
                *PRODUCT_UNITS,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=SYSTEMCTL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or len(result.stdout) > 32_768:
        return None
    units: set[str] = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if not fields or not FAILED_UNIT.fullmatch(fields[0]):
            return None
        units.add(fields[0])
    return len(units)


def _default_probe(url: str) -> bool:
    try:
        response = httpx.get(
            url,
            timeout=5.0,
            follow_redirects=False,
            headers={"Accept": "application/json", "User-Agent": "SmithGuard-Health/1"},
        )
        return response.status_code == 200 and response.json() == {
            "status": "ok",
            "service_state": "public-beta",
        }
    except (httpx.HTTPError, ValueError, AttributeError):
        return False


def _warning_deadlines(session: Session, *, measured_at: datetime) -> int:
    ranked = select(
        PreliminaryWarningRecord.id.label("warning_id"),
        PreliminaryWarningRecord.revision.label("warning_revision"),
        func.row_number()
        .over(
            partition_by=PreliminaryWarningRecord.id,
            order_by=PreliminaryWarningRecord.revision.desc(),
        )
        .label("position"),
    ).subquery()
    latest = aliased(PreliminaryWarningRecord)
    return int(
        session.scalar(
            select(func.count())
            .select_from(latest)
            .join(
                ranked,
                (latest.id == ranked.c.warning_id)
                & (latest.revision == ranked.c.warning_revision)
                & (ranked.c.position == 1),
            )
            .where(
                latest.state == "active",
                (latest.expires_at <= measured_at)
                | (
                    latest.next_check_at.is_not(None)
                    & (latest.next_check_at + WARNING_DEADLINE_GRACE <= measured_at)
                ),
            )
        )
        or 0
    )


def collect_operational_inputs(
    config: HealthConfig,
    *,
    measured_at: datetime,
    runner: CommandRunner = subprocess.run,
    probe: Probe = _default_probe,
) -> OperationalHealthInputs:
    """Collect fixed local and SmithGuard-origin observations without printing secrets."""
    try:
        registry = RightsRegistry.from_path(config.rights_register_path)
        governance_policy = SourceGovernancePolicy.from_path(
            config.governance_policy_path,
            registry=registry,
        )
    except Exception as error:
        raise HealthConfigurationError("source governance policy cannot be loaded") from error
    expected_governance_policy_sha256 = governance_policy.policy_sha256
    required_active_units = (
        REQUIRED_ACTIVE_UNITS
        + (("smithguard-openssf-shadow.timer",) if config.openssf_schedule_expected else ())
        + (
            ("smithguard-openssf-catalog.timer",)
            if config.openssf_catalog_schedule_expected
            else ()
        )
    )
    required_successful_jobs = (
        REQUIRED_SUCCESSFUL_JOBS
        + (("smithguard-openssf-shadow.service",) if config.openssf_schedule_expected else ())
        + (
            ("smithguard-openssf-catalog.service",)
            if config.openssf_catalog_schedule_expected
            else ()
        )
    )
    active_units = {unit: _unit_active(unit, runner=runner) for unit in required_active_units}
    job_results = {unit: _unit_result(unit, runner=runner) for unit in required_successful_jobs}
    current_failed_unit_count = failed_unit_count(runner=runner)
    warning_activity = {
        unit: _warning_unit_active(unit, runner=runner)
        for unit in (
            "smithguard-discovery.timer",
            "smithguard-discovery.service",
            "smithguard-warning-recheck.timer",
            "smithguard-warning-recheck.service",
        )
    }
    try:
        dispatch_control = read_runtime_control()
    except (DispatchControlError, OSError):
        dispatch_control = None
    usage = os.statvfs(config.disk_path)
    total_bytes = usage.f_blocks * usage.f_frsize
    available_bytes = usage.f_bavail * usage.f_frsize
    disk_percent = (
        100.0 if total_bytes <= 0 else (total_bytes - available_bytes) * 100 / total_bytes
    )
    supplemental_sources = dict.fromkeys(SOURCE_NAMES, "missing")
    bulletin_status = "unavailable"
    database_available = False
    migration_current = False
    updates = _missing_freshness("updates")
    historical = _missing_freshness("historical")
    database_bytes: int | None = None
    warning_count: int | None = None
    warning_lane_health: WarningLaneHealth | None = None
    github_quarantined_records: int | None = None
    engine = create_engine(
        config.database_url,
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={"options": "-c statement_timeout=10000 -c lock_timeout=5000"},
    )
    try:
        with Session(engine) as session:
            session.execute(select(1))
            database_available = True
            migration_current = (
                session.get(MigrationJournalRecord, EXPECTED_MIGRATION) is not None
                and session.scalar(text("SELECT version_num FROM public.alembic_version"))
                == EXPECTED_MIGRATION
            )
            if migration_current:
                from smithguard.bulletin_intake_status import health as bulletin_health

                bulletin_status = bulletin_health(session, now=measured_at)
                github_quarantined_records = actionable_quarantine_count(
                    session, source_id=GITHUB_ADVISORY
                )
                supplemental_sources = {
                    source_id: source_state(session, source_id, now=measured_at)[0]
                    for source_id in SOURCE_NAMES
                }
            updates = catalog_collection_freshness(
                session,
                lane="updates",
                measured_at=measured_at,
                expected_governance_policy_sha256=expected_governance_policy_sha256,
            )
            historical = catalog_collection_freshness(
                session,
                lane="historical",
                measured_at=measured_at,
                expected_governance_policy_sha256=expected_governance_policy_sha256,
            )
            database_bytes = int(
                session.scalar(select(func.pg_database_size(func.current_database()))) or 0
            )
            warning_count = _warning_deadlines(session, measured_at=measured_at)
            spend_policy = load_spend_policy_path(config.spend_policy_path)
            warning_lane_health = collect_warning_lane_health(
                session,
                policy=spend_policy,
                measured_at=measured_at,
                expiry_job_success=job_results.get("smithguard-signals.service") == "success",
                schedule_expected=config.warning_lane_schedule_expected,
                dispatch_enabled=bool(dispatch_control and dispatch_control.discovery_enabled),
                recheck_dispatch_enabled=bool(
                    dispatch_control and dispatch_control.recheck_enabled
                ),
                control_valid=dispatch_control is not None,
                discovery_timer_active=warning_activity["smithguard-discovery.timer"],
                discovery_service_active=warning_activity["smithguard-discovery.service"],
                recheck_timer_active=warning_activity["smithguard-warning-recheck.timer"],
                recheck_service_active=warning_activity["smithguard-warning-recheck.service"],
                dispatch_latched=(
                    generation_paused(session, control=dispatch_control)
                    if dispatch_control is not None
                    else False
                ),
            )
    except Exception as error:
        # The health decision stays critical; the cause goes to the journal so the
        # operator does not have to reproduce the failure by hand.
        write_exception_diagnostic(error)
        database_available = False
    finally:
        engine.dispose()
    try:
        openssf_monitor = load_openssf_monitor_receipt(
            config.openssf_monitor_receipt_path, source=config.openssf_monitor_source
        )
    except OperationalHealthError:
        openssf_monitor = None
    return OperationalHealthInputs(
        measured_at=measured_at,
        database_available=database_available,
        migration_current=migration_current,
        updates=updates,
        historical=historical,
        active_units=active_units,
        job_results=job_results,
        failed_unit_count=current_failed_unit_count,
        # The tunnel metric measures reachability of the API process only; data
        # freshness has its own collector-age metric, so a backlog never reads as a
        # tunnel outage.
        external_probe_ok=probe(f"{config.base_url}/healthz"),
        disk_used_percent=disk_percent,
        database_bytes=database_bytes,
        overdue_warning_count=warning_count,
        supplemental_sources=supplemental_sources,
        bulletin_status=bulletin_status,
        github_quarantined_records=github_quarantined_records,
        openssf_monitor=openssf_monitor,
        openssf_monitor_source=config.openssf_monitor_source,
        openssf_schedule_expected=config.openssf_schedule_expected,
        openssf_catalog_schedule_expected=config.openssf_catalog_schedule_expected,
        warning_lane_health=warning_lane_health,
        api_pressure_expected=config.api_pressure_expected,
        api_pressure=pressure_status(PRESSURE_PATH)
        if config.api_pressure_expected
        else "unavailable",
        host_pressure=host_pressure_status() if config.api_pressure_expected else "unavailable",
    )


def _write_health_document(path: Path, document: Mapping[str, Any]) -> None:
    parent = path.parent
    metadata = os.lstat(parent)
    if (
        parent.resolve(strict=True) != parent
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or not metadata.st_mode & stat.S_ISGID
        or stat.S_IMODE(metadata.st_mode) & 0o027
    ):
        raise OperationalHealthError("health report parent is unsafe")
    if path.is_symlink():
        raise OperationalHealthError("health report path cannot be a symbolic link")
    body = pretty_json_bytes(document)
    try:
        # pid-suffixed temporary and the pre-existence refusal preserve the prior
        # behaviour; the writer applies the mode with fchmod, so the group-readable
        # receipt is durable before the rename regardless of umask.
        atomic_write(path, body, mode=0o640, random_suffix=False)
    except FsioError as error:
        if error.code != "exists":
            raise
        raise OperationalHealthError("temporary health report already exists") from error


def write_health_report(path: Path, report: OperationalHealthReport) -> None:
    _write_health_document(path, report.as_dict())


def write_metric_receipt(path: Path, receipt: MetricReceipt) -> None:
    _write_health_document(path, receipt.as_dict())


def health_main() -> int:
    try:
        config = load_health_config()
        measured_at = datetime.now(UTC)
        inputs = collect_operational_inputs(config, measured_at=measured_at)
        report = evaluate_operational_health(inputs)
        write_health_report(config.report_path, report)
        write_metric_receipt(config.metric_receipt_path, build_metric_receipt(inputs, report))
        write_metric_receipt(
            config.warning_lane_metric_receipt_path,
            build_warning_lane_metric_receipt(inputs),
        )
        decision_code = {"healthy": 0, "degraded": 1, "critical": 2}[report.status]
        sys.stdout.write(
            f"operational_health status={report.status} decision_code={decision_code} "
            f"checks={len(report.checks)}\n"
        )
        return 0
    except (HealthConfigurationError, OperationalHealthError) as error:
        write_exception_diagnostic(error)
        sys.stderr.write("configuration_error:operational_health_failed\n")
        return 3
    except Exception as error:
        write_exception_diagnostic(error)
        sys.stderr.write("runtime_error:operational_health_failed\n")
        return 3
