"""Private catalog health receipts, independent of the retained shadow format."""

from __future__ import annotations

import grp
import os
import pwd
import resource
import stat
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from smithguard.fsio import FsioError, atomic_write, read_private_file
from smithguard.identifiers import (
    canonical_json_bytes,
    parse_timestamp,
    strict_json_loads,
    timestamp,
)
from smithguard.openssf_budget import (
    CATALOG_FRESHNESS_MAX_AGE,
    LEGACY_CATALOG_FRESHNESS_MAX_AGE,
)
from smithguard.openssf_git import ADVISORY_ID, COMMIT, OPENSSF_MALICIOUS
from smithguard.openssf_shadow import (
    MAX_STATE_APPARENT_BYTES,
    MAX_STATE_ENTRIES,
    measure_state_capacity,
)

CATALOG_HEALTH_PATH = Path("/var/lib/smithguard/catalog-health/openssf.json")
CATALOG_HEALTH_VARIABLE = "SMITHGUARD_OPENSSF_CATALOG_RECEIPT_PATH"
MAX_RECEIPT_BYTES = 16384


class CatalogHealthError(ValueError):
    """The selected catalog receipt could not be safely written or interpreted."""


def _read_bounded(path: Path, maximum: int) -> bytes:
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("resource file exceeds bound")
    return value


def cgroup_memory_peak() -> dict[str, int | str | None]:
    """Read this live service's kernel peak before systemd removes its cgroup."""
    expected = b"0::/system.slice/smithguard-openssf-catalog.service"
    try:
        membership = _read_bounded(Path("/proc/self/cgroup"), 8192).splitlines()
        if membership != [expected]:
            return {"cgroup_peak_bytes": None, "cgroup_peak_status": "not_catalog_service"}
        raw = _read_bounded(
            Path("/sys/fs/cgroup/system.slice/smithguard-openssf-catalog.service/memory.peak"),
            32,
        ).strip()
        if not raw or not raw.isdigit() or not 0 < int(raw) <= 10**12:
            raise ValueError("invalid cgroup memory peak")
        return {"cgroup_peak_bytes": int(raw), "cgroup_peak_status": "measured"}
    except (OSError, ValueError):
        return {"cgroup_peak_bytes": None, "cgroup_peak_status": "unavailable"}


def resource_measurement(started: float) -> dict[str, int | float | str | None]:
    self_peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    children_peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024
    return {
        **cgroup_memory_peak(),
        "elapsed_seconds": round(perf_counter() - started, 3),
        "self_peak_rss_bytes": self_peak,
        "children_peak_rss_bytes": children_peak,
        "conservative_process_peak_bytes": self_peak + children_peak,
    }


def write_catalog_health(
    path: Path,
    *,
    state_root: Path,
    complete_pair,
    attempt: dict,
    succeeded: bool,
    started: float,
) -> dict:
    """Write a small operator receipt after a terminal attempt; never certify a marker."""
    metadata = path.parent.lstat()
    group = grp.getgrnam("smithguard-ops-read").gr_gid
    if (
        not path.is_absolute()
        or path.parent.resolve(strict=True) != path.parent
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o2750
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != group
    ):
        raise CatalogHealthError("catalog receipt directory is unsafe")
    if path.exists() or path.is_symlink():
        read_private_file(
            path,
            maximum=MAX_RECEIPT_BYTES,
            exact_mode=0o640,
            mode_mask=0o027,
            minimum=0,
            uid=os.geteuid(),
            gid=group,
        )
    now = datetime.now(UTC)
    valid_pair = (
        len(complete_pair) == 2
        and {row.segment for row in complete_pair} == {"openssf-malicious", "openssf-withdrawn"}
        and len({row.observed_at for row in complete_pair}) == 1
        and len({row.source_snapshot.partition(":")[0] for row in complete_pair}) == 1
    )
    last_success = complete_pair[0].observed_at if valid_pair else None
    last_commit = complete_pair[0].source_snapshot.partition(":")[0] if valid_pair else None
    stale_after = last_success + CATALOG_FRESHNESS_MAX_AGE if last_success else None
    capacity_valid = True
    try:
        # New explicit opt-in; the shadow caller keeps the default strict private mode.
        capacity = measure_state_capacity(state_root, clamp_overflow=True, allow_group_read=True)
        values = {
            "state_apparent_bytes": capacity.state_apparent_bytes,
            "state_entry_count": capacity.state_entry_count,
            "filesystem_available_bytes": capacity.filesystem_available_bytes,
            "filesystem_used_percent": capacity.filesystem_used_percent,
        }
        capacity_valid = not capacity.capacity_exceeded
    except (OSError, ValueError, RuntimeError):
        capacity_valid = False
        values = {
            "state_apparent_bytes": MAX_STATE_APPARENT_BYTES,
            "state_entry_count": MAX_STATE_ENTRIES,
            "filesystem_available_bytes": 0,
            "filesystem_used_percent": 100,
        }
    # Healthy means the served catalog is fresh and complete. A failed attempt while
    # the last complete snapshot is still fresh is "degraded", not a failure.
    healthy = bool(
        capacity_valid
        and last_success
        and last_success <= now <= stale_after
        and not attempt.get("missing_upstream_count")
    )
    status = ("success" if succeeded else "degraded") if healthy else "failure"
    checkpoint = attempt.get("commit")
    if not isinstance(checkpoint, str) or COMMIT.fullmatch(checkpoint) is None:
        checkpoint = None
    receipt = {
        "schema_version": "2.0.0",
        "monitor_source": "catalog",
        "source_id": OPENSSF_MALICIOUS,
        "measured_at": timestamp(now),
        "healthy": healthy,
        "status": status,
        "checkpoint": checkpoint,
        "last_success_at": timestamp(last_success) if last_success else None,
        "last_success_commit": last_commit,
        "stale_after": timestamp(stale_after) if stale_after else None,
        "record_count": sum(row.record_count for row in complete_pair) if valid_pair else 0,
        "package_entry_count": sum(row.package_entry_count for row in complete_pair)
        if valid_pair
        else 0,
        "missing_upstream_count": attempt.get("missing_upstream_count", 0),
        "missing_upstream_ids": attempt.get("missing_upstream_ids", []),
        "capacity_valid": capacity_valid,
        "resources": resource_measurement(started),
        **values,
    }
    validate_catalog_health(receipt)
    atomic_write(path, canonical_json_bytes(receipt), mode=0o640)
    written = read_private_file(
        path,
        maximum=MAX_RECEIPT_BYTES,
        exact_mode=0o640,
        mode_mask=0o027,
        minimum=0,
        uid=os.geteuid(),
        gid=group,
    )
    if strict_json_loads(written.decode("ascii")) != receipt:
        raise CatalogHealthError("catalog receipt readback differs")
    return receipt


def validate_catalog_health(document) -> dict:
    fields = {
        "schema_version",
        "monitor_source",
        "source_id",
        "measured_at",
        "healthy",
        "status",
        "checkpoint",
        "last_success_at",
        "last_success_commit",
        "stale_after",
        "missing_upstream_count",
        "missing_upstream_ids",
        "capacity_valid",
        "resources",
        "record_count",
        "package_entry_count",
        "state_apparent_bytes",
        "state_entry_count",
        "filesystem_available_bytes",
        "filesystem_used_percent",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise CatalogHealthError("catalog receipt shape is invalid")
    if (
        document["schema_version"] != "2.0.0"
        or document["monitor_source"] != "catalog"
        or document["source_id"] != OPENSSF_MALICIOUS
        or type(document["healthy"]) is not bool
        or type(document["capacity_valid"]) is not bool
        or not isinstance(document["status"], str)
        or document["status"] not in {"success", "degraded", "failure"}
        or document["healthy"] != (document["status"] != "failure")
    ):
        raise CatalogHealthError("catalog receipt identity is invalid")

    def number(value, maximum):
        if type(value) is not int or not 0 <= value <= maximum:
            raise CatalogHealthError("catalog receipt numeric bound is invalid")

    for key, maximum in (
        ("record_count", 1000000),
        ("package_entry_count", 10000000),
        ("missing_upstream_count", 500000),
        ("state_apparent_bytes", MAX_STATE_APPARENT_BYTES),
        ("state_entry_count", MAX_STATE_ENTRIES),
        ("filesystem_available_bytes", 10**16),
        ("filesystem_used_percent", 100),
    ):
        number(document[key], maximum)
    for key in ("checkpoint", "last_success_commit"):
        value = document[key]
        if value is not None and (not isinstance(value, str) or COMMIT.fullmatch(value) is None):
            raise CatalogHealthError("catalog receipt commit is invalid")
    sample = document["missing_upstream_ids"]
    if (
        not isinstance(sample, list)
        or len(sample) != min(5, document["missing_upstream_count"])
        or any(
            not isinstance(value, str) or ADVISORY_ID.fullmatch(value) is None for value in sample
        )
        or len(set(sample)) != len(sample)
    ):
        raise CatalogHealthError("catalog receipt missing-ID sample is invalid")
    measured = parse_timestamp(document["measured_at"])
    last = document["last_success_at"]
    stale = document["stale_after"]
    if (last is None) != (stale is None) or (last is None) != (
        document["last_success_commit"] is None
    ):
        raise CatalogHealthError("catalog receipt last-success proof is incomplete")
    if last is not None:
        last, stale = parse_timestamp(last), parse_timestamp(stale)
        if stale not in (
            last + CATALOG_FRESHNESS_MAX_AGE,
            last + LEGACY_CATALOG_FRESHNESS_MAX_AGE,
        ):
            raise CatalogHealthError("catalog receipt freshness policy differs")
    if document["healthy"] and (
        last is None
        or not last <= measured <= stale
        or not document["capacity_valid"]
        or document["missing_upstream_count"]
        or (
            document["status"] == "success"
            and document["checkpoint"] != document["last_success_commit"]
        )
    ):
        raise CatalogHealthError("catalog receipt success is unproved")
    values = document["resources"]
    if not isinstance(values, dict) or set(values) != {
        "cgroup_peak_bytes",
        "cgroup_peak_status",
        "elapsed_seconds",
        "self_peak_rss_bytes",
        "children_peak_rss_bytes",
        "conservative_process_peak_bytes",
    }:
        raise CatalogHealthError("catalog resource receipt is invalid")
    for key in (
        "self_peak_rss_bytes",
        "children_peak_rss_bytes",
        "conservative_process_peak_bytes",
    ):
        number(values[key], 10**12)
    peak = values["cgroup_peak_bytes"]
    peak_status = values["cgroup_peak_status"]
    if not isinstance(peak_status, str) or peak_status not in {
        "measured",
        "unavailable",
        "not_catalog_service",
    }:
        raise CatalogHealthError("catalog cgroup peak status is invalid")
    if peak_status == "measured":
        number(peak, 10**12)
        if peak == 0:
            raise CatalogHealthError("catalog cgroup peak is invalid")
    elif peak is not None:
        raise CatalogHealthError("catalog unavailable cgroup peak must be absent")
    elapsed = values["elapsed_seconds"]
    if type(elapsed) not in (int, float) or not 0 <= elapsed <= 3600:
        raise CatalogHealthError("catalog elapsed-time receipt is invalid")
    if (
        values["conservative_process_peak_bytes"]
        != values["self_peak_rss_bytes"] + values["children_peak_rss_bytes"]
    ):
        raise CatalogHealthError("catalog resource estimate is inconsistent")
    return document


def load_catalog_health(path: Path) -> dict | None:
    """Read the separate catalog format with the collector/operator trust boundary."""
    try:
        group = grp.getgrnam("smithguard-ops-read").gr_gid
        owner = pwd.getpwnam("smithguard-collector").pw_uid
        metadata = path.parent.lstat()
        if (
            not path.is_absolute()
            or path.parent.resolve(strict=True) != path.parent
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o2750
            or metadata.st_uid != owner
            or metadata.st_gid != group
        ):
            raise CatalogHealthError("catalog receipt directory is unsafe")
        body = read_private_file(
            path, maximum=MAX_RECEIPT_BYTES, mode_mask=0o027, exact_mode=0o640, uid=owner, gid=group
        )
        return validate_catalog_health(strict_json_loads(body.decode("ascii")))
    except FsioError as error:
        if error.code == "missing":
            return None
        raise CatalogHealthError("catalog receipt cannot be safely read") from error
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise CatalogHealthError("catalog receipt is unavailable or invalid") from error
