"""CloudWatch publication is one complete, fail-closed, non-secret batch."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

import smithguard.cloudwatch_metrics as cloudwatch_metrics_module
from smithguard.cloudwatch_metrics import (
    EXPECTED_METRICS,
    PUBLISH_TIMEOUT_SECONDS,
    MetricPublisherError,
    MetricReceiptError,
    load_metric_receipt,
    load_warning_lane_metric_receipt,
    publish_latest_metrics,
    publish_latest_warning_lane_metrics,
)
from smithguard.operational_health import SYSTEMCTL_TIMEOUT_SECONDS
from smithguard.warning_lane_health import (
    WARNING_LANE_FAIL_CLOSED_VALUES,
    WARNING_LANE_METRIC_SCHEMA_VERSION,
    WARNING_LANE_METRICS,
)

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)


def _receipt(*, measured_at: str = "2026-08-14T12:00:00Z") -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "namespace": "SmithLabs/SmithGuard",
        "measured_at": measured_at,
        "metrics": [
            {"name": "CollectorAgeSeconds", "unit": "Seconds", "value": 900},
            {"name": "FailedUnits", "unit": "Count", "value": 0},
            {"name": "ExternalTunnelHealthy", "unit": "Count", "value": 1},
            {"name": "OpenSSFHealthy", "unit": "Count", "value": 1},
            {"name": "OpenSSFStateBytes", "unit": "Bytes", "value": 1024},
            {"name": "OpenSSFFilesystemHealthy", "unit": "Count", "value": 1},
            {"name": "HealthCritical", "unit": "Count", "value": 0},
            {"name": "RootDiskUsedPercent", "unit": "Percent", "value": 59},
            {"name": "DatabaseBytes", "unit": "Bytes", "value": 2_000_000_000},
        ],
    }


def _receipt_path(tmp_path: Path, body: bytes | None = None) -> Path:
    root = tmp_path / "health"
    root.mkdir(mode=0o750, parents=True)
    root.chmod(0o2750)
    path = root / "metrics-latest.json"
    if body is not None:
        path.write_bytes(body)
        path.chmod(0o640)
    return path


def _warning_lane_receipt(*, measured_at: str = "2026-08-14T12:00:00Z") -> dict[str, object]:
    values = (1, 0, 0, 0, 900, 4, 2500, 0, 0, 0)
    return {
        "schema_version": WARNING_LANE_METRIC_SCHEMA_VERSION,
        "namespace": "SmithLabs/SmithGuardWarningLane",
        "measured_at": measured_at,
        "metrics": [
            {"name": name, "unit": unit, "value": value}
            for (name, unit), value in zip(WARNING_LANE_METRICS, values, strict=True)
        ],
    }


def _warning_lane_receipt_path(tmp_path: Path, body: bytes | None = None) -> Path:
    root = tmp_path / "health"
    root.mkdir(mode=0o750, parents=True)
    root.chmod(0o2750)
    path = root / "warning-lane-metrics-latest.json"
    if body is not None:
        path.write_bytes(body)
        path.chmod(0o640)
    return path


def _encoded(document: dict[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True) + "\n").encode("ascii")


def _identity() -> tuple[int, int]:
    return os.geteuid(), os.getegid()


def _healthy_systemctl(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 0, stdout="", stderr="")


def test_valid_receipt_publishes_all_nine_metrics_in_one_request(tmp_path: Path) -> None:
    path = _receipt_path(tmp_path, _encoded(_receipt()))
    calls: list[tuple[list[str], dict[str, object]]] = []

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    uid, gid = _identity()
    assert publish_latest_metrics(
        path,
        now=NOW,
        expected_uid=uid,
        expected_gid=gid,
        runner=runner,
        system_runner=_healthy_systemctl,
    )
    assert len(calls) == 1
    command, options = calls[0]
    assert command[:3] == ["/usr/bin/aws", "cloudwatch", "put-metric-data"]
    assert command[command.index("--namespace") + 1] == "SmithLabs/SmithGuard"
    payload = json.loads(command[command.index("--metric-data") + 1])
    assert tuple((item["MetricName"], item["Unit"]) for item in payload) == EXPECTED_METRICS
    assert [item["Value"] for item in payload] == [900, 0, 1, 1, 1024, 1, 0, 59, 2_000_000_000]
    assert all(item["Timestamp"] == "2026-08-14T12:00:00Z" for item in payload)
    environment = options["env"]
    assert environment["AWS_EC2_METADATA_V1_DISABLED"] == "true"
    assert environment["AWS_MAX_ATTEMPTS"] == "2"
    assert "AWS_ACCESS_KEY_ID" not in environment
    assert options["timeout"] == PUBLISH_TIMEOUT_SECONDS == 45
    service = (
        Path(__file__).resolve().parents[1] / "deploy/systemd/smithguard-metrics-publisher.service"
    ).read_text(encoding="ascii")
    assert SYSTEMCTL_TIMEOUT_SECONDS + (2 * PUBLISH_TIMEOUT_SECONDS) < 120
    assert "TimeoutStartSec=120s" in service


def test_valid_warning_lane_receipt_publishes_all_metrics_in_one_request(
    tmp_path: Path,
) -> None:
    path = _warning_lane_receipt_path(tmp_path, _encoded(_warning_lane_receipt()))
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    uid, gid = _identity()
    assert publish_latest_warning_lane_metrics(
        path,
        now=NOW,
        expected_uid=uid,
        expected_gid=gid,
        runner=runner,
    )
    assert len(calls) == 1
    command = calls[0]
    assert command[command.index("--namespace") + 1] == ("SmithLabs/SmithGuardWarningLane")
    payload = json.loads(command[command.index("--metric-data") + 1])
    assert tuple((item["MetricName"], item["Unit"]) for item in payload) == (WARNING_LANE_METRICS)
    assert [item["Value"] for item in payload] == [1, 0, 0, 0, 900, 4, 2500, 0, 0, 0]


def test_disabled_warning_schedule_omits_only_policy_active(tmp_path: Path) -> None:
    path = _warning_lane_receipt_path(tmp_path, _encoded(_warning_lane_receipt()))
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    uid, gid = _identity()
    assert publish_latest_warning_lane_metrics(
        path,
        now=NOW,
        expected_uid=uid,
        expected_gid=gid,
        schedule_expected=False,
        runner=runner,
    )
    payload = json.loads(calls[0][calls[0].index("--metric-data") + 1])
    assert [item["MetricName"] for item in payload] == [
        name for name, _unit in WARNING_LANE_METRICS[1:]
    ]
    assert payload[0]["MetricName"] == "WarningLaneProviderFailures24h"
    assert payload[0]["Value"] == 0


@pytest.mark.parametrize(
    "body",
    (
        None,
        b"not-json\n",
        _encoded(_warning_lane_receipt(measured_at="2026-08-14T11:49:59Z")),
    ),
)
def test_invalid_warning_lane_receipt_publishes_complete_breaching_batch(
    tmp_path: Path,
    body: bytes | None,
) -> None:
    path = _warning_lane_receipt_path(tmp_path, body)
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    uid, gid = _identity()
    assert not publish_latest_warning_lane_metrics(
        path,
        now=NOW,
        expected_uid=uid,
        expected_gid=gid,
        runner=runner,
    )
    assert len(calls) == 1
    payload = json.loads(calls[0][calls[0].index("--metric-data") + 1])
    assert tuple(item["Value"] for item in payload) == WARNING_LANE_FAIL_CLOSED_VALUES


def test_invalid_warning_lane_receipt_still_fails_closed_when_schedule_disabled(
    tmp_path: Path,
) -> None:
    path = _warning_lane_receipt_path(tmp_path, b"not-json\n")
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    uid, gid = _identity()
    assert not publish_latest_warning_lane_metrics(
        path,
        now=NOW,
        expected_uid=uid,
        expected_gid=gid,
        schedule_expected=False,
        runner=runner,
    )
    payload = json.loads(calls[0][calls[0].index("--metric-data") + 1])
    assert tuple(item["Value"] for item in payload) == WARNING_LANE_FAIL_CLOSED_VALUES[1:]


def test_warning_lane_loader_rejects_reordered_or_over_range_metrics(tmp_path: Path) -> None:
    document = _warning_lane_receipt()
    metrics = document["metrics"]
    assert isinstance(metrics, list)
    metrics[0], metrics[1] = metrics[1], metrics[0]
    path = _warning_lane_receipt_path(tmp_path, _encoded(document))
    uid, gid = _identity()
    with pytest.raises(MetricReceiptError, match="identity"):
        load_warning_lane_metric_receipt(path, now=NOW, expected_uid=uid, expected_gid=gid)

    document = _warning_lane_receipt()
    metrics = document["metrics"]
    assert isinstance(metrics, list)
    metrics[6]["value"] = 10_001
    path.write_bytes(_encoded(document))
    path.chmod(0o640)
    with pytest.raises(MetricReceiptError, match="value"):
        load_warning_lane_metric_receipt(path, now=NOW, expected_uid=uid, expected_gid=gid)


@pytest.mark.parametrize(
    "body",
    (
        None,
        b"not-json\n",
        _encoded(_receipt(measured_at="2026-08-14T11:49:59Z")),
        _encoded(_receipt(measured_at="2026-08-14T12:00:01Z")),
        (
            b'{"schema_version":"1.0.0","schema_version":"1.0.0",'
            b'"namespace":"SmithLabs/SmithGuard","measured_at":"2026-08-14T12:00:00Z",'
            b'"metrics":[]}\n'
        ),
    ),
)
def test_missing_malformed_stale_future_and_duplicate_receipts_publish_breaching_batch(
    tmp_path: Path,
    body: bytes | None,
) -> None:
    path = _receipt_path(tmp_path, body)
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    uid, gid = _identity()
    assert not publish_latest_metrics(
        path,
        now=NOW,
        expected_uid=uid,
        expected_gid=gid,
        runner=runner,
        system_runner=_healthy_systemctl,
    )
    assert len(calls) == 1
    payload = json.loads(calls[0][calls[0].index("--metric-data") + 1])
    assert [item["Value"] for item in payload] == [5401, 1, 0, 1, 0, 1, 1, 100, 12 * 1024**3]
    assert all(item["Timestamp"] == "2026-08-14T12:00:00Z" for item in payload)


def test_invalid_receipt_breaches_openssf_metrics_only_when_schedule_is_expected(
    tmp_path: Path,
) -> None:
    path = _receipt_path(tmp_path)
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    uid, gid = _identity()
    assert not publish_latest_metrics(
        path,
        now=NOW,
        expected_uid=uid,
        expected_gid=gid,
        runner=runner,
        system_runner=_healthy_systemctl,
        openssf_schedule_expected=True,
    )
    payload = json.loads(calls[0][calls[0].index("--metric-data") + 1])
    assert [item["Value"] for item in payload[3:6]] == [0, 5 * 1024**3, 0]


def test_metric_receipt_uses_exact_per_metric_maximums(tmp_path: Path) -> None:
    document = _receipt()
    document["metrics"][0]["value"] = 10**9 + 1  # type: ignore[index]
    path = _receipt_path(tmp_path, _encoded(document))
    uid, gid = _identity()
    with pytest.raises(MetricReceiptError, match="metric value"):
        load_metric_receipt(path, now=NOW, expected_uid=uid, expected_gid=gid)

    document = _receipt()
    document["metrics"][5]["value"] = 5 * 1024**3 + 1  # type: ignore[index]
    path.write_bytes(_encoded(document))
    path.chmod(0o640)
    with pytest.raises(MetricReceiptError, match="metric value"):
        load_metric_receipt(path, now=NOW, expected_uid=uid, expected_gid=gid)


def test_unsafe_receipt_permissions_fail_closed_without_reading_values(tmp_path: Path) -> None:
    path = _receipt_path(tmp_path, _encoded(_receipt()))
    path.chmod(0o644)
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    uid, gid = _identity()
    assert not publish_latest_metrics(
        path,
        now=NOW,
        expected_uid=uid,
        expected_gid=gid,
        runner=runner,
        system_runner=_healthy_systemctl,
    )
    assert len(calls) == 1
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_receipt_loader_rejects_wrong_owner_or_group(tmp_path: Path) -> None:
    path = _receipt_path(tmp_path, _encoded(_receipt()))
    uid, gid = _identity()
    with pytest.raises(MetricReceiptError, match="unsafe"):
        load_metric_receipt(path, now=NOW, expected_uid=uid + 1, expected_gid=gid)
    with pytest.raises(MetricReceiptError, match="unsafe"):
        load_metric_receipt(path, now=NOW, expected_uid=uid, expected_gid=gid + 1)


def test_receipt_loader_rejects_symlink_oversize_and_unsafe_parent(tmp_path: Path) -> None:
    uid, gid = _identity()

    real = _receipt_path(tmp_path / "symlink", _encoded(_receipt()))
    link = real.with_name("linked.json")
    link.symlink_to(real)
    with pytest.raises(MetricReceiptError, match="unavailable"):
        load_metric_receipt(link, now=NOW, expected_uid=uid, expected_gid=gid)

    oversized = _receipt_path(tmp_path / "oversize", b"x" * 16_385)
    with pytest.raises(MetricReceiptError, match="unsafe"):
        load_metric_receipt(oversized, now=NOW, expected_uid=uid, expected_gid=gid)

    unsafe_parent = _receipt_path(tmp_path / "parent", _encoded(_receipt()))
    unsafe_parent.parent.chmod(0o2755)
    with pytest.raises(MetricReceiptError, match="parent is unsafe"):
        load_metric_receipt(unsafe_parent, now=NOW, expected_uid=uid, expected_gid=gid)


def test_aws_rejection_and_timeout_never_retry_as_partial_metric_calls(tmp_path: Path) -> None:
    path = _receipt_path(tmp_path, _encoded(_receipt()))
    uid, gid = _identity()
    rejected_calls = 0

    def rejected(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal rejected_calls
        rejected_calls += 1
        return subprocess.CompletedProcess(command, 7)

    with pytest.raises(MetricPublisherError, match="rejected"):
        publish_latest_metrics(
            path,
            now=NOW,
            expected_uid=uid,
            expected_gid=gid,
            runner=rejected,
            system_runner=_healthy_systemctl,
        )
    assert rejected_calls == 1

    timed_out_calls = 0

    def timed_out(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal timed_out_calls
        timed_out_calls += 1
        raise subprocess.TimeoutExpired(command, PUBLISH_TIMEOUT_SECONDS)

    with pytest.raises(MetricPublisherError, match="did not complete"):
        publish_latest_metrics(
            path,
            now=NOW,
            expected_uid=uid,
            expected_gid=gid,
            runner=timed_out,
            system_runner=_healthy_systemctl,
        )
    assert timed_out_calls == 1


def test_publisher_uses_the_worse_live_failed_unit_count(tmp_path: Path) -> None:
    path = _receipt_path(tmp_path, _encoded(_receipt()))
    calls: list[list[str]] = []

    def aws_runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    def failed_systemctl(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="smithguard-health.service loaded failed failed health\n",
            stderr="",
        )

    uid, gid = _identity()
    assert publish_latest_metrics(
        path,
        now=NOW,
        expected_uid=uid,
        expected_gid=gid,
        runner=aws_runner,
        system_runner=failed_systemctl,
    )
    payload = json.loads(calls[0][calls[0].index("--metric-data") + 1])
    assert payload[1]["MetricName"] == "FailedUnits"
    assert payload[1]["Value"] == 1


@pytest.mark.audit_ids("WL-10")
def test_publisher_main_gates_and_orders_the_warning_lane_batch(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []
    monkeypatch.setenv("SMITHGUARD_OPENSSF_SCHEDULE_EXPECTED", "0")
    monkeypatch.setenv("SMITHGUARD_WARNING_LANE_METRICS_EXPECTED", "1")
    monkeypatch.setenv("SMITHGUARD_WARNING_LANE_SCHEDULE_EXPECTED", "1")
    monkeypatch.setattr(
        cloudwatch_metrics_module.pwd,
        "getpwnam",
        lambda _name: type("Identity", (), {"pw_uid": 1000})(),
    )
    monkeypatch.setattr(
        cloudwatch_metrics_module.grp,
        "getgrnam",
        lambda _name: type("Identity", (), {"gr_gid": 1000})(),
    )

    def publish_core(*_args: object, **_kwargs: object) -> bool:
        calls.append("core")
        return True

    def publish_warning(*_args: object, **_kwargs: object) -> bool:
        calls.append("warning")
        return True

    monkeypatch.setattr(cloudwatch_metrics_module, "publish_latest_metrics", publish_core)
    monkeypatch.setattr(
        cloudwatch_metrics_module,
        "publish_latest_warning_lane_metrics",
        publish_warning,
    )
    assert cloudwatch_metrics_module.metric_publisher_main() == 0
    assert calls == ["core", "warning"]
    assert "count=19" in capsys.readouterr().out

    calls.clear()
    monkeypatch.setenv("SMITHGUARD_WARNING_LANE_SCHEDULE_EXPECTED", "0")
    assert cloudwatch_metrics_module.metric_publisher_main() == 0
    assert calls == ["core", "warning"]
    assert "count=18" in capsys.readouterr().out

    calls.clear()
    monkeypatch.setenv("SMITHGUARD_WARNING_LANE_METRICS_EXPECTED", "0")
    assert cloudwatch_metrics_module.metric_publisher_main() == 0
    assert calls == ["core"]
    assert "count=9" in capsys.readouterr().out


def test_leftover_receipt_with_a_retired_metric_publishes_the_current_metrics(
    tmp_path: Path,
) -> None:
    """A receipt that still carries the retired BackupAgeSeconds drops it on read."""
    receipt = _receipt()
    receipt["metrics"].insert(1, {"name": "BackupAgeSeconds", "unit": "Seconds", "value": 3600})
    payload = _published(tmp_path, receipt)
    assert tuple((item["MetricName"], item["Unit"]) for item in payload) == EXPECTED_METRICS
    assert [item["Value"] for item in payload] == [900, 0, 1, 1, 1024, 1, 0, 59, 2_000_000_000]
    assert not any(item["MetricName"] == "BackupAgeSeconds" for item in payload)


def test_previous_release_receipt_publishes_its_six_metrics_without_failing_closed(
    tmp_path: Path,
) -> None:
    """The previous health binary writes six metrics. During the cutover that receipt
    stays valid and only its six values are sent: no fail-closed batch, no page."""
    receipt = _receipt()
    receipt["metrics"] = receipt["metrics"][:6]
    payload = _published(tmp_path, receipt)
    assert [item["MetricName"] for item in payload] == [name for name, _ in EXPECTED_METRICS[:6]]
    assert [item["Value"] for item in payload] == [900, 0, 1, 1, 1024, 1]


def test_receipt_with_only_some_added_metrics_fails_closed(tmp_path: Path) -> None:
    receipt = _receipt()
    receipt["metrics"] = receipt["metrics"][:7]
    path = _receipt_path(tmp_path, _encoded(receipt))
    uid, gid = _identity()
    with pytest.raises(MetricReceiptError, match="metric count"):
        load_metric_receipt(path, now=NOW, expected_uid=uid, expected_gid=gid)


def _published(tmp_path: Path, receipt: dict[str, object]) -> list[dict[str, object]]:
    path = _receipt_path(tmp_path, _encoded(receipt))
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    uid, gid = _identity()
    assert publish_latest_metrics(
        path,
        now=NOW,
        expected_uid=uid,
        expected_gid=gid,
        runner=runner,
        system_runner=_healthy_systemctl,
    )
    assert len(calls) == 1
    return json.loads(calls[0][calls[0].index("--metric-data") + 1])


def test_metric_receipt_loader_refuses_non_finite_and_over_depth_bodies(tmp_path: Path) -> None:
    uid, gid = _identity()
    path = _receipt_path(tmp_path, b'{"measured_at": NaN}')
    with pytest.raises(MetricReceiptError, match="not valid ASCII JSON"):
        load_metric_receipt(path, now=NOW, expected_uid=uid, expected_gid=gid)
    path.write_bytes(b"[" * 40 + b"]" * 40)
    path.chmod(0o640)
    with pytest.raises(MetricReceiptError, match="not valid ASCII JSON"):
        load_metric_receipt(path, now=NOW, expected_uid=uid, expected_gid=gid)


@pytest.mark.parametrize("invalid_name", ({}, []))
def test_unhashable_metric_name_publishes_failure_batch(
    tmp_path: Path, invalid_name: object
) -> None:
    document = _receipt()
    document["metrics"][0]["name"] = invalid_name
    test_missing_malformed_stale_future_and_duplicate_receipts_publish_breaching_batch(
        tmp_path, _encoded(document)
    )


@pytest.mark.parametrize("catalog_expected", ["0", "1", "invalid"])
def test_catalog_only_schedule_keeps_missing_receipt_alerts(
    monkeypatch, tmp_path, catalog_expected
):
    from types import SimpleNamespace

    uid, gid = _identity()
    monkeypatch.setattr(
        cloudwatch_metrics_module.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=uid)
    )
    monkeypatch.setattr(
        cloudwatch_metrics_module.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=gid)
    )
    monkeypatch.setenv("SMITHGUARD_OPENSSF_SCHEDULE_EXPECTED", "0")
    monkeypatch.setenv("SMITHGUARD_OPENSSF_CATALOG_SCHEDULE_EXPECTED", catalog_expected)
    monkeypatch.setenv("SMITHGUARD_WARNING_LANE_METRICS_EXPECTED", "0")
    monkeypatch.setattr(
        cloudwatch_metrics_module, "DEFAULT_RECEIPT_PATH", tmp_path / "missing.json"
    )
    published = []
    monkeypatch.setattr(
        cloudwatch_metrics_module,
        "publish_metrics",
        lambda receipt, **kw: published.append(receipt),
    )
    assert cloudwatch_metrics_module.metric_publisher_main() == (
        3 if catalog_expected == "invalid" else 2
    )
    if catalog_expected == "invalid":
        assert not published
    else:
        values = dict(
            zip((name for name, _unit in EXPECTED_METRICS), published[0].values, strict=True)
        )
        assert values["OpenSSFHealthy"] == (0 if catalog_expected == "1" else 1)
