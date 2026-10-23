"""The catalog handover preserves failure, freshness, and filesystem boundaries."""

import os
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from time import perf_counter
from types import SimpleNamespace

import pytest

from smithguard import catalog_health
from smithguard.catalog_health import CatalogHealthError, load_catalog_health, write_catalog_health
from smithguard.openssf_budget import CATALOG_FRESHNESS_MAX_AGE
from smithguard.openssf_shadow import OpenSSFShadowError, measure_state_capacity
from smithguard.operational_health import (
    build_metric_receipt,
    evaluate_operational_health,
    load_openssf_monitor_receipt,
)
from tests.test_operational_health import NOW, _healthy_inputs, _openssf_monitor


@pytest.fixture
def receipt_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(
        catalog_health.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getegid())
    )
    monkeypatch.setattr(
        catalog_health.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.geteuid())
    )
    parent = tmp_path / "health"
    parent.mkdir(mode=0o700)
    parent.chmod(0o2750)
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    (root / "git-object").write_bytes(b"retained")
    (root / "git-object").chmod(0o640)
    pair = [
        SimpleNamespace(
            segment="openssf-" + tree,
            observed_at=datetime.now(UTC) - timedelta(minutes=1),
            source_snapshot="a" * 40 + ":tree",
            record_count=1,
            package_entry_count=1,
        )
        for tree in ("malicious", "withdrawn")
    ]
    pair[1].observed_at = pair[0].observed_at
    return parent / "openssf.json", root, pair


def test_catalog_receipt_preserves_success_then_failure_and_missing_ids(receipt_boundary):
    path, root, pair = receipt_boundary
    first = write_catalog_health(
        path,
        state_root=root,
        complete_pair=pair,
        attempt={"commit": "a" * 40},
        succeeded=True,
        started=perf_counter(),
    )
    assert first["healthy"] and first["record_count"] == 2
    assert load_catalog_health(path) == first
    assert load_openssf_monitor_receipt(path, source="catalog").monitor_source == "catalog"
    failed = write_catalog_health(
        path,
        state_root=root,
        complete_pair=pair,
        attempt={
            "commit": "b" * 40,
            "missing_upstream_count": 1,
            "missing_upstream_ids": ["MAL-2026-1"],
        },
        succeeded=False,
        started=perf_counter(),
    )
    assert not failed["healthy"]
    assert failed["last_success_at"] == first["last_success_at"]
    assert failed["missing_upstream_ids"] == ["MAL-2026-1"]
    assert path.stat().st_mode & 0o777 == 0o640


def test_catalog_capacity_opt_in_does_not_relax_shadow(receipt_boundary):
    path, root, pair = receipt_boundary
    with pytest.raises(OpenSSFShadowError, match="boundary"):
        measure_state_capacity(root)
    assert measure_state_capacity(root, allow_group_read=True).state_entry_count == 1
    (root / "git-object").chmod(0o660)
    receipt = write_catalog_health(
        path,
        state_root=root,
        complete_pair=pair,
        attempt={"commit": "a" * 40},
        succeeded=True,
        started=perf_counter(),
    )
    assert not receipt["healthy"] and not receipt["capacity_valid"]


@pytest.mark.parametrize(
    "fault", ["symlink", "parent_mode", "file_mode", "schema", "stale", "resource", "missing"]
)
def test_catalog_receipt_refuses_unsafe_or_inconsistent_proof(receipt_boundary, fault):
    path, root, pair = receipt_boundary
    receipt = write_catalog_health(
        path,
        state_root=root,
        complete_pair=pair,
        attempt={"commit": "a" * 40},
        succeeded=True,
        started=perf_counter(),
    )
    if fault == "symlink":
        path.unlink()
        path.symlink_to(root / "git-object")
    elif fault == "parent_mode":
        path.parent.chmod(0o2770)
    elif fault == "file_mode":
        path.chmod(0o644)
    else:
        bad = deepcopy(receipt)
        if fault == "schema":
            bad["schema_version"] = "1.0.0"
        elif fault == "stale":
            bad["stale_after"] = bad["last_success_at"]
        elif fault == "resource":
            bad["resources"]["conservative_process_peak_bytes"] += 1
        else:
            bad["missing_upstream_count"] = 1
        path.write_bytes(catalog_health.canonical_json_bytes(bad))
    with pytest.raises(CatalogHealthError):
        load_catalog_health(path)


def test_catalog_only_monitoring_never_defaults_to_constant_success():
    inputs = replace(
        _healthy_inputs(),
        openssf_catalog_schedule_expected=True,
        openssf_monitor_source="catalog",
        openssf_schedule_expected=False,
    )

    def metric(value):
        return {datum.name: datum.value for datum in build_metric_receipt(value).metrics}[
            "OpenSSFHealthy"
        ]

    assert metric(inputs) == 0
    assert any(
        c.code == "openssf_source_health" and c.status == "critical"
        for c in evaluate_operational_health(inputs).checks
    )
    receipt = replace(
        _openssf_monitor(), monitor_source="catalog", stale_after=NOW + CATALOG_FRESHNESS_MAX_AGE
    )
    assert metric(replace(inputs, openssf_monitor=receipt)) == 1
    assert (
        metric(
            replace(
                inputs, openssf_monitor=replace(receipt, stale_after=NOW - timedelta(seconds=1))
            )
        )
        == 0
    )
    assert metric(replace(inputs, openssf_monitor=_openssf_monitor())) == 0


@pytest.mark.parametrize("fault", [None, "other", "traversal", "missing", "oversized", "invalid"])
def test_live_cgroup_peak_is_bounded_and_only_reads_the_catalog_service(monkeypatch, fault):
    calls = []

    def read(path, maximum):
        calls.append(str(path))
        if str(path) == "/proc/self/cgroup":
            if fault == "other":
                return b"0::/user.slice/session.scope\n"
            if fault == "traversal":
                return b"0::/system.slice/../smithguard-openssf-catalog.service\n"
            return b"0::/system.slice/smithguard-openssf-catalog.service\n"
        assert str(path) == (
            "/sys/fs/cgroup/system.slice/smithguard-openssf-catalog.service/memory.peak"
        )
        assert maximum == 32
        if fault == "missing":
            raise FileNotFoundError
        if fault == "oversized":
            raise ValueError
        return b"invalid" if fault == "invalid" else b"123456789\n"

    monkeypatch.setattr(catalog_health, "_read_bounded", read)
    result = catalog_health.cgroup_memory_peak()
    assert result["cgroup_peak_bytes"] == (123456789 if fault is None else None)
    assert result["cgroup_peak_status"] == (
        "measured"
        if fault is None
        else "not_catalog_service"
        if fault in {"other", "traversal"}
        else "unavailable"
    )
    assert len(calls) == (1 if fault in {"other", "traversal"} else 2)


def test_resource_file_reads_have_a_hard_size_limit(tmp_path):
    path = tmp_path / "resource"
    path.write_bytes(b"1" * 33)
    with pytest.raises(ValueError, match="bound"):
        catalog_health._read_bounded(path, 32)


@pytest.mark.parametrize(
    "source,expected,path,fails",
    [
        (None, "0", None, False),
        ("catalog", "1", None, False),
        ("invalid", "1", None, True),
        ("catalog", "0", None, True),
        ("catalog", "1", "/tmp/other.json", True),
    ],
)
def test_health_monitor_configuration_boundary(
    monkeypatch, tmp_path, source, expected, path, fails
):
    from smithguard.operational_health import HealthConfigurationError, load_health_config

    monkeypatch.setenv(
        "SMITHGUARD_DATABASE_URL",
        "postgresql+psycopg://smithguard-health@/smithguard?host=/run/postgresql",
    )
    monkeypatch.setenv("SMITHGUARD_BASE_URL", "https://api.smithguard.io")
    for key in (
        "HEALTH_REPORT_PATH",
        "METRIC_RECEIPT_PATH",
        "WARNING_LANE_METRIC_RECEIPT_PATH",
        "DISK_PATH",
        "RIGHTS_REGISTER_PATH",
        "GOVERNANCE_POLICY_PATH",
    ):
        monkeypatch.setenv("SMITHGUARD_" + key, str(tmp_path / key.lower()))
    monkeypatch.setenv("SMITHGUARD_OPENSSF_CATALOG_SCHEDULE_EXPECTED", expected)
    monkeypatch.delenv("SMITHGUARD_OPENSSF_MONITOR_SOURCE", raising=False)
    monkeypatch.delenv("SMITHGUARD_OPENSSF_MONITOR_RECEIPT_PATH", raising=False)
    if source is not None:
        monkeypatch.setenv("SMITHGUARD_OPENSSF_MONITOR_SOURCE", source)
    if path is not None:
        monkeypatch.setenv("SMITHGUARD_OPENSSF_MONITOR_RECEIPT_PATH", path)
    if fails:
        with pytest.raises(HealthConfigurationError):
            load_health_config()
    else:
        config = load_health_config()
        assert config.openssf_monitor_source == (source or "shadow")
        assert str(config.openssf_monitor_receipt_path) == (
            str(catalog_health.CATALOG_HEALTH_PATH)
            if source == "catalog"
            else "/var/lib/smithguard/openssf-health/latest.json"
        )


def test_collected_health_inputs_read_the_selected_catalog_receipt(
    database, receipt_boundary, tmp_path
):
    import subprocess

    from smithguard.operational_health import HealthConfig, collect_operational_inputs
    from tests.test_operational_health import POLICY_ROOT

    path, root, pair = receipt_boundary
    write_catalog_health(
        path,
        state_root=root,
        complete_pair=pair,
        attempt={"commit": "a" * 40},
        succeeded=True,
        started=perf_counter(),
    )
    config = HealthConfig(
        database_url=database.url.render_as_string(hide_password=False),
        base_url="https://api.smithguard.io",
        report_path=tmp_path / "health.json",
        metric_receipt_path=tmp_path / "metrics.json",
        warning_lane_metric_receipt_path=tmp_path / "warning.json",
        disk_path=tmp_path,
        spend_policy_path=POLICY_ROOT / "xai-spend-policy.json",
        rights_register_path=POLICY_ROOT / "source-rights-register.json",
        governance_policy_path=POLICY_ROOT / "source-governance-policy.json",
        openssf_monitor_source="catalog",
        openssf_catalog_schedule_expected=True,
        openssf_monitor_receipt_path=path,
    )

    def runner(command, **kwargs):
        result = "active" if "is-active" in command else "success" if "show" in command else ""
        return subprocess.CompletedProcess(command, 0, result, "")

    inputs = collect_operational_inputs(
        config, measured_at=datetime.now(UTC), runner=runner, probe=lambda _: True
    )
    assert inputs.openssf_monitor_source == "catalog"
    assert inputs.openssf_monitor.monitor_source == "catalog"
    assert inputs.openssf_monitor.healthy
    assert {m.name: m.value for m in build_metric_receipt(inputs).metrics}["OpenSSFHealthy"] == 1
