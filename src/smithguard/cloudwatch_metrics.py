"""Publish one fail-closed SmithGuard metric batch with instance-role credentials."""

from __future__ import annotations

import grp
import os
import pwd
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from smithguard.fsio import FsioError, read_private_file
from smithguard.identifiers import (
    DuplicateJsonKeyError,
    canonical_json_bytes,
    parse_timestamp,
    strict_json_loads,
    timestamp,
)
from smithguard.operational_health import (
    DATABASE_CRITICAL_BYTES,
    DATABASE_METRIC_MAXIMUM_BYTES,
    DEFAULT_WARNING_LANE_METRIC_RECEIPT_PATH,
    FAIL_CLOSED_COLLECTOR_AGE_SECONDS,
    MAX_METRIC_VALUE,
    METRIC_NAMESPACE,
    METRIC_RECEIPT_SCHEMA_VERSION,
    OPENSSF_STATE_CRITICAL_BYTES,
    failed_unit_count,
)
from smithguard.warning_lane_health import (
    WARNING_LANE_FAIL_CLOSED_VALUES,
    WARNING_LANE_METRIC_MAXIMUMS,
    WARNING_LANE_METRIC_NAMESPACE,
    WARNING_LANE_METRIC_SCHEMA_VERSION,
    WARNING_LANE_METRICS,
    MetricSpec,
)

AWS_PATH = Path("/usr/bin/aws")
AWS_REGION = "us-east-1"
DEFAULT_RECEIPT_PATH = Path("/var/lib/smithguard/health/metrics-latest.json")
DEFAULT_WARNING_LANE_RECEIPT_PATH = DEFAULT_WARNING_LANE_METRIC_RECEIPT_PATH
EXPECTED_RECEIPT_OWNER = "smithguard-health"
EXPECTED_RECEIPT_GROUP = "smithguard-ops-read"
MAX_RECEIPT_BYTES = 16_384
MAX_RECEIPT_AGE = timedelta(minutes=10)
PUBLISH_TIMEOUT_SECONDS = 45
# The six core metrics. ``fail_closed`` is the value published when the health
# receipt is unusable; ``contained`` is the schedule-disabled value. The OpenSSF
# metrics fail closed only while their schedule is expected (see _fail_closed_receipt).
CORE_METRIC_SPECS: tuple[MetricSpec, ...] = (
    MetricSpec(
        "CollectorAgeSeconds",
        "Seconds",
        MAX_METRIC_VALUE,
        FAIL_CLOSED_COLLECTOR_AGE_SECONDS,
        None,
        "collector_age_seconds",
        "collector-stale",
    ),
    MetricSpec("FailedUnits", "Count", 1_000, 1, None, "failed_units", "failed-units"),
    MetricSpec(
        "ExternalTunnelHealthy", "Count", 1, 0, None, "external_tunnel_healthy", "tunnel-unhealthy"
    ),
    MetricSpec(
        "OpenSSFHealthy", "Count", 1, 0, 1, "openssf_healthy", "openssf-unhealthy", openssf=True
    ),
    MetricSpec(
        "OpenSSFStateBytes",
        "Bytes",
        OPENSSF_STATE_CRITICAL_BYTES,
        OPENSSF_STATE_CRITICAL_BYTES,
        0,
        "openssf_state_bytes",
        "openssf-state-large",
        openssf=True,
    ),
    MetricSpec(
        "OpenSSFFilesystemHealthy",
        "Count",
        1,
        0,
        1,
        "openssf_filesystem_healthy",
        "openssf-filesystem-capacity",
        openssf=True,
    ),
    # Added September 24, 2026 (audit item 19): the overall health decision and the
    # two capacity measures, so a database outage or a full disk pages directly.
    MetricSpec("HealthCritical", "Count", 1, 1, None, "health_critical", "health-critical"),
    MetricSpec(
        "RootDiskUsedPercent", "Percent", 100, 100, None, "root_disk_used_percent", "root-disk-high"
    ),
    MetricSpec(
        "DatabaseBytes",
        "Bytes",
        DATABASE_METRIC_MAXIMUM_BYTES,
        DATABASE_CRITICAL_BYTES,
        None,
        "database_bytes",
        "database-large",
    ),
)
# Kept as a hand-written literal on purpose: the release topology generator reads this
# tuple from the module source with ast.literal_eval. A test proves it equals the specs.
EXPECTED_METRICS = (
    ("CollectorAgeSeconds", "Seconds"),
    ("FailedUnits", "Count"),
    ("ExternalTunnelHealthy", "Count"),
    ("OpenSSFHealthy", "Count"),
    ("OpenSSFStateBytes", "Bytes"),
    ("OpenSSFFilesystemHealthy", "Count"),
    ("HealthCritical", "Count"),
    ("RootDiskUsedPercent", "Percent"),
    ("DatabaseBytes", "Bytes"),
)
# Metrics a previous release still writes into its receipt. They are dropped on read
# for one release so the cutover never publishes fail-closed values from a receipt
# the old health binary left behind.
RETIRED_METRICS = frozenset({"BackupAgeSeconds"})
# Metrics this release added. A receipt the previous health binary left behind lacks
# them; for one release such a receipt is still valid and only its metrics are sent,
# so the cutover never publishes fail-closed values (which would page).
ADDED_METRICS = frozenset({"HealthCritical", "RootDiskUsedPercent", "DatabaseBytes"})
EXPECTED_METRIC_MAXIMUMS = tuple(spec.maximum for spec in CORE_METRIC_SPECS)


def _metric_index(name: str) -> int:
    return next(index for index, spec in enumerate(CORE_METRIC_SPECS) if spec.name == name)


FAILED_UNITS_INDEX = _metric_index("FailedUnits")


class MetricPublisherError(RuntimeError):
    """The metric batch could not be safely published."""


class MetricReceiptError(ValueError):
    """The local metric receipt is absent, stale, unsafe, or malformed."""


@dataclass(frozen=True, slots=True)
class ValidatedMetricReceipt:
    measured_at: datetime
    # None marks an added metric that an older receipt does not carry (not sent).
    values: tuple[int | None, ...]


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _read_bounded_receipt(path: Path, *, expected_uid: int, expected_gid: int) -> bytes:
    parent = path.parent
    try:
        parent_metadata = os.lstat(parent)
    except OSError as error:
        raise MetricReceiptError("metric receipt parent is unavailable") from error
    if (
        parent.resolve(strict=True) != parent
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
        or parent_metadata.st_uid != expected_uid
        or parent_metadata.st_gid != expected_gid
        or stat.S_IMODE(parent_metadata.st_mode) != 0o2750
    ):
        raise MetricReceiptError("metric receipt parent is unsafe")
    try:
        return read_private_file(
            path,
            maximum=MAX_RECEIPT_BYTES,
            mode_mask=None,
            exact_mode=0o640,
            uid=expected_uid,
            gid=expected_gid,
        )
    except FsioError as error:
        if error.code in {"missing", "unsafe"}:
            raise MetricReceiptError("metric receipt is unavailable") from error
        if error.code == "changed":
            raise MetricReceiptError("metric receipt size changed while reading") from error
        raise MetricReceiptError("metric receipt identity or permissions are unsafe") from error


def _parse_time(value: Any) -> datetime:
    try:
        parsed = parse_timestamp(value, maximum=40)
    except ValueError as error:
        raise MetricReceiptError("metric receipt time is invalid") from error
    if timestamp(parsed) != value:
        raise MetricReceiptError("metric receipt time is not canonical UTC")
    return parsed


def _load_metric_receipt(
    path: Path,
    *,
    now: datetime,
    expected_uid: int,
    expected_gid: int,
    schema_version: str,
    namespace: str,
    expected_metrics: tuple[tuple[str, str], ...],
    metric_maximums: tuple[int, ...],
    added_metrics: frozenset[str] = frozenset(),
) -> ValidatedMetricReceipt:
    """Load one exact, fresh, race-bounded receipt without following links."""
    body = _read_bounded_receipt(path, expected_uid=expected_uid, expected_gid=expected_gid)
    try:
        document = strict_json_loads(body.decode("ascii"))
    except DuplicateJsonKeyError as error:
        raise MetricReceiptError("metric receipt contains a duplicate key") from error
    except (UnicodeDecodeError, ValueError) as error:
        raise MetricReceiptError("metric receipt is not valid ASCII JSON") from error
    if not isinstance(document, Mapping) or set(document) != {
        "measured_at",
        "metrics",
        "namespace",
        "schema_version",
    }:
        raise MetricReceiptError("metric receipt has an unexpected shape")
    if document["schema_version"] != schema_version or document["namespace"] != namespace:
        raise MetricReceiptError("metric receipt identity is invalid")
    measured_at = _parse_time(document["measured_at"])
    now = now.astimezone(UTC)
    age = now - measured_at
    if age < timedelta(0) or age > MAX_RECEIPT_AGE:
        raise MetricReceiptError("metric receipt is future-dated or stale")
    metrics = document["metrics"]
    if not isinstance(metrics, list):
        raise MetricReceiptError("metric receipt metric count is invalid")
    metrics = [
        metric
        for metric in metrics
        if not (
            isinstance(metric, Mapping)
            and isinstance(metric.get("name"), str)
            and metric["name"] in RETIRED_METRICS
        )
    ]
    present = tuple(
        (expected, maximum)
        for expected, maximum in zip(expected_metrics, metric_maximums, strict=True)
        if len(metrics) == len(expected_metrics) or expected[0] not in added_metrics
    )
    if len(metrics) != len(present):
        raise MetricReceiptError("metric receipt metric count is invalid")
    found: dict[str, int] = {}
    for metric, (expected, maximum) in zip(metrics, present, strict=True):
        if not isinstance(metric, Mapping) or set(metric) != {"name", "unit", "value"}:
            raise MetricReceiptError("metric receipt metric has an unexpected shape")
        if (metric["name"], metric["unit"]) != expected:
            raise MetricReceiptError("metric receipt metric identity is invalid")
        value = metric["value"]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            raise MetricReceiptError("metric receipt metric value is invalid")
        found[expected[0]] = value
    return ValidatedMetricReceipt(
        measured_at=measured_at,
        values=tuple(found.get(name) for name, _unit in expected_metrics),
    )


def load_metric_receipt(
    path: Path,
    *,
    now: datetime,
    expected_uid: int,
    expected_gid: int,
) -> ValidatedMetricReceipt:
    return _load_metric_receipt(
        path,
        now=now,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        schema_version=METRIC_RECEIPT_SCHEMA_VERSION,
        namespace=METRIC_NAMESPACE,
        expected_metrics=EXPECTED_METRICS,
        metric_maximums=EXPECTED_METRIC_MAXIMUMS,
        added_metrics=ADDED_METRICS,
    )


def load_warning_lane_metric_receipt(
    path: Path,
    *,
    now: datetime,
    expected_uid: int,
    expected_gid: int,
) -> ValidatedMetricReceipt:
    return _load_metric_receipt(
        path,
        now=now,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        schema_version=WARNING_LANE_METRIC_SCHEMA_VERSION,
        namespace=WARNING_LANE_METRIC_NAMESPACE,
        expected_metrics=WARNING_LANE_METRICS,
        metric_maximums=WARNING_LANE_METRIC_MAXIMUMS,
    )


def _fail_closed_receipt(
    now: datetime,
    *,
    openssf_schedule_expected: bool,
) -> ValidatedMetricReceipt:
    return ValidatedMetricReceipt(
        measured_at=now.astimezone(UTC),
        values=tuple(
            spec.contained
            if spec.openssf and not openssf_schedule_expected and spec.contained is not None
            else spec.fail_closed
            for spec in CORE_METRIC_SPECS
        ),
    )


def _aws_metric_data(
    receipt: ValidatedMetricReceipt,
    *,
    expected_metrics: tuple[tuple[str, str], ...],
) -> str:
    measured_at = timestamp(receipt.measured_at)
    data = [
        {
            "MetricName": name,
            "Timestamp": measured_at,
            "Unit": unit,
            "Value": value,
        }
        for (name, unit), value in zip(expected_metrics, receipt.values, strict=True)
        if value is not None
    ]
    return canonical_json_bytes(data).decode("ascii")


def _last_line(text: str | None, *, limit: int = 200) -> str:
    lines = (text or "").strip().splitlines()
    if not lines:
        return "no detail"
    return "".join(ch if ch.isprintable() else " " for ch in lines[-1])[:limit]


def _publish_metrics(
    receipt: ValidatedMetricReceipt,
    *,
    namespace: str,
    expected_metrics: tuple[tuple[str, str], ...],
    runner: CommandRunner = subprocess.run,
) -> None:
    """Send one exact metric batch in one bounded AWS CLI request."""
    command = [
        str(AWS_PATH),
        "cloudwatch",
        "put-metric-data",
        "--region",
        AWS_REGION,
        "--namespace",
        namespace,
        "--metric-data",
        _aws_metric_data(receipt, expected_metrics=expected_metrics),
        "--cli-connect-timeout",
        "5",
        "--cli-read-timeout",
        "10",
        "--no-cli-pager",
        "--no-cli-auto-prompt",
    ]
    safe_environment = {
        "AWS_CONFIG_FILE": "/nonexistent/smithguard-telemetry-config",
        "AWS_SHARED_CREDENTIALS_FILE": "/nonexistent/smithguard-telemetry-credentials",
        "AWS_EC2_METADATA_V1_DISABLED": "true",
        "AWS_MAX_ATTEMPTS": "2",
        "AWS_METADATA_SERVICE_NUM_ATTEMPTS": "2",
        "AWS_METADATA_SERVICE_TIMEOUT": "2",
        "AWS_PAGER": "",
        "AWS_REGION": AWS_REGION,
        "AWS_RETRY_MODE": "standard",
        "LANG": "C",
    }
    try:
        result = runner(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=PUBLISH_TIMEOUT_SECONDS,
            env=safe_environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise MetricPublisherError("CloudWatch metric publication did not complete") from error
    if result.returncode != 0:
        # Keep one bounded, printable line of the AWS error (for example the error code)
        # in the journal; the command carries no credentials.
        detail = _last_line(result.stderr)
        sys.stderr.write(f"metric_publish_diagnostic:{detail}\n")
        raise MetricPublisherError("CloudWatch metric publication was rejected")


def publish_metrics(
    receipt: ValidatedMetricReceipt,
    *,
    runner: CommandRunner = subprocess.run,
) -> None:
    """Send every core metric the receipt carries in one bounded request."""
    _publish_metrics(
        receipt,
        namespace=METRIC_NAMESPACE,
        expected_metrics=EXPECTED_METRICS,
        runner=runner,
    )


def publish_warning_lane_metrics(
    receipt: ValidatedMetricReceipt,
    *,
    schedule_expected: bool = True,
    runner: CommandRunner = subprocess.run,
) -> None:
    """Send warning metrics, omitting policy state while scheduling is disabled."""
    metrics = WARNING_LANE_METRICS if schedule_expected else WARNING_LANE_METRICS[1:]
    values = receipt.values if schedule_expected else receipt.values[1:]
    _publish_metrics(
        ValidatedMetricReceipt(measured_at=receipt.measured_at, values=values),
        namespace=WARNING_LANE_METRIC_NAMESPACE,
        expected_metrics=metrics,
        runner=runner,
    )


def publish_latest_metrics(
    path: Path,
    *,
    now: datetime,
    expected_uid: int,
    expected_gid: int,
    runner: CommandRunner = subprocess.run,
    system_runner: CommandRunner = subprocess.run,
    openssf_schedule_expected: bool = False,
) -> bool:
    """Publish valid values, or publish one complete breaching batch and return false."""
    valid = True
    try:
        receipt = load_metric_receipt(
            path,
            now=now,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    except MetricReceiptError:
        valid = False
        receipt = _fail_closed_receipt(
            now,
            openssf_schedule_expected=openssf_schedule_expected,
        )
    current_failed_units = failed_unit_count(runner=system_runner)
    if current_failed_units is None:
        valid = False
        current_failed_units = 1
    values = list(receipt.values)
    values[FAILED_UNITS_INDEX] = max(values[FAILED_UNITS_INDEX], current_failed_units)
    receipt = ValidatedMetricReceipt(
        measured_at=receipt.measured_at,
        values=tuple(values),
    )
    publish_metrics(receipt, runner=runner)
    return valid


def publish_latest_warning_lane_metrics(
    path: Path,
    *,
    now: datetime,
    expected_uid: int,
    expected_gid: int,
    schedule_expected: bool = True,
    runner: CommandRunner = subprocess.run,
) -> bool:
    """Publish valid warning metrics, or one complete breaching batch."""
    valid = True
    try:
        receipt = load_warning_lane_metric_receipt(
            path,
            now=now,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    except MetricReceiptError:
        valid = False
        receipt = ValidatedMetricReceipt(
            measured_at=now.astimezone(UTC),
            values=WARNING_LANE_FAIL_CLOSED_VALUES,
        )
    publish_warning_lane_metrics(
        receipt,
        schedule_expected=schedule_expected,
        runner=runner,
    )
    return valid


def metric_publisher_main() -> int:
    try:
        openssf_expected_value = os.environ.get("SMITHGUARD_OPENSSF_SCHEDULE_EXPECTED", "0")
        if openssf_expected_value not in {"0", "1"}:
            raise MetricPublisherError(
                "SMITHGUARD_OPENSSF_SCHEDULE_EXPECTED must be exactly 0 or 1"
            )
        catalog_expected_value = os.environ.get("SMITHGUARD_OPENSSF_CATALOG_SCHEDULE_EXPECTED", "0")
        if catalog_expected_value not in {"0", "1"}:
            raise MetricPublisherError(
                "SMITHGUARD_OPENSSF_CATALOG_SCHEDULE_EXPECTED must be exactly 0 or 1"
            )
        warning_lane_expected_value = os.environ.get(
            "SMITHGUARD_WARNING_LANE_METRICS_EXPECTED",
            "0",
        )
        if warning_lane_expected_value not in {"0", "1"}:
            raise MetricPublisherError(
                "SMITHGUARD_WARNING_LANE_METRICS_EXPECTED must be exactly 0 or 1"
            )
        warning_lane_schedule_value = os.environ.get(
            "SMITHGUARD_WARNING_LANE_SCHEDULE_EXPECTED",
            "0",
        )
        if warning_lane_schedule_value not in {"0", "1"}:
            raise MetricPublisherError(
                "SMITHGUARD_WARNING_LANE_SCHEDULE_EXPECTED must be exactly 0 or 1"
            )
        expected_uid = pwd.getpwnam(EXPECTED_RECEIPT_OWNER).pw_uid
        expected_gid = grp.getgrnam(EXPECTED_RECEIPT_GROUP).gr_gid
        now = datetime.now(UTC)
        valid = publish_latest_metrics(
            DEFAULT_RECEIPT_PATH,
            now=now,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            openssf_schedule_expected=(
                openssf_expected_value == "1" or catalog_expected_value == "1"
            ),
        )
        count = len(EXPECTED_METRICS)
        if warning_lane_expected_value == "1":
            warning_lane_valid = publish_latest_warning_lane_metrics(
                DEFAULT_WARNING_LANE_RECEIPT_PATH,
                now=now,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                schedule_expected=warning_lane_schedule_value == "1",
            )
            valid = valid and warning_lane_valid
            count += len(WARNING_LANE_METRICS) - (0 if warning_lane_schedule_value == "1" else 1)
        if not valid:
            sys.stderr.write("metric_receipt_invalid:fail_closed_metrics_published\n")
            return 2
        sys.stdout.write(f"cloudwatch_metrics status=published count={count}\n")
        return 0
    except Exception:
        sys.stderr.write("runtime_error:cloudwatch_metric_publication_failed\n")
        return 3


if __name__ == "__main__":
    raise SystemExit(metric_publisher_main())
