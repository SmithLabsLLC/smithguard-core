"""Durable, root-owned dispatch authority, independent of monitoring expectations.

Workers hold a shared lock on the policy directory through provider work. The
deployment controller takes its exclusive counterpart before changing authority.
The directory inode is stable across atomic control-file replacements, so a new
process cannot use an environment snapshot taken before a pause.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.db.models import JobRecord
from smithguard.identifiers import stable_id, strict_json_loads
from smithguard.warning_lane_budget import WORKER_LOCK, collect_dispatch_budget
from smithguard.warning_lane_receipts import RECEIPT_QUEUE, append_warning_lane_receipt
from smithguard.warning_trial_gate import dispatch_allowed

CONTROL_DIRECTORY = Path("/etc/SmithGuard/policies")
CONTROL_PATH = CONTROL_DIRECTORY / "warning-dispatch.json"
CONTROL_UID = 0
CURRENT_RELEASE = Path("/opt/SmithGuard/current")
DISPATCH_FLAG = "SMITHGUARD_WARNING_DISPATCH_ENABLED"
PAUSE_RECEIPT = "dispatch_contained"


class DispatchControlError(ValueError):
    """Missing, unsafe or inconsistent control state never permits dispatch."""


@dataclass(frozen=True, slots=True)
class DispatchControl:
    schema_version: str
    operation_id: str
    artifact_commit: str
    discovery_enabled: bool
    recheck_enabled: bool

    def enabled(self, stage: str) -> bool:
        if stage not in {"discovery", "recheck"}:
            raise DispatchControlError("unknown dispatch stage")
        return self.discovery_enabled if stage == "discovery" else self.recheck_enabled

    @property
    def run_id(self) -> str:
        return stable_id("warning-dispatch-control", self.operation_id)


def parse_control(document: Mapping) -> DispatchControl:
    if (
        not isinstance(document, Mapping)
        or set(document) != set(DispatchControl.__dataclass_fields__)
        or document.get("schema_version") != "1.0.0"
        or not isinstance(document.get("operation_id"), str)
        or re.fullmatch(r"[0-9]{8}-[a-f0-9]{32}", document["operation_id"]) is None
        or not isinstance(document.get("artifact_commit"), str)
        or re.fullmatch(r"[a-f0-9]{40}", document["artifact_commit"]) is None
        or type(document.get("discovery_enabled")) is not bool
        or type(document.get("recheck_enabled")) is not bool
        or (document["recheck_enabled"] and not document["discovery_enabled"])
    ):
        raise DispatchControlError("invalid dispatch control")
    return DispatchControl(**document)


def control_bytes(
    *, operation_id: str, artifact_commit: str, discovery: bool = False, recheck: bool = False
) -> bytes:
    control = parse_control(
        {
            "schema_version": "1.0.0",
            "operation_id": operation_id,
            "artifact_commit": artifact_commit,
            "discovery_enabled": discovery,
            "recheck_enabled": recheck,
        }
    )
    return (json.dumps(asdict(control), sort_keys=True) + "\n").encode("ascii")


def read_control() -> DispatchControl:
    try:
        directory = CONTROL_DIRECTORY.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != CONTROL_UID
            or directory.st_mode & 0o022
            or CONTROL_PATH.parent != CONTROL_DIRECTORY
        ):
            raise DispatchControlError("unsafe dispatch control directory")
        fd = os.open(CONTROL_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != CONTROL_UID
                or stat.S_IMODE(metadata.st_mode) != 0o644
                or metadata.st_nlink != 1
                or metadata.st_size > 4096
            ):
                raise DispatchControlError("unsafe dispatch control")
            return parse_control(strict_json_loads(stream.read(4097)))
    except (OSError, ValueError, TypeError) as error:
        raise DispatchControlError("dispatch control unavailable") from error


def _running_release() -> str:
    try:
        root = CURRENT_RELEASE.resolve(strict=True)
    except OSError as error:
        raise DispatchControlError("active dispatch release unavailable") from error
    if (
        not CURRENT_RELEASE.is_symlink()
        or re.fullmatch(r"[a-f0-9]{40}", root.name) is None
        or not Path(__file__).resolve().is_relative_to(root)
    ):
        raise DispatchControlError("dispatch runtime is not the active installed release")
    return root.name


def read_runtime_control() -> DispatchControl:
    control = read_control()
    if (
        control.discovery_enabled or control.recheck_enabled
    ) and control.artifact_commit != _running_release():
        raise DispatchControlError("dispatch authority belongs to a different release")
    return control


@contextmanager
def dispatch_guard(stage: str) -> Iterator[DispatchControl | None]:
    """Keep one admitted command ordered before a concurrent controller pause.

    Containment is an ordinary no-work outcome. Invalid/missing file state also
    refuses work; the independent health reader reports that configuration error.
    """
    if os.environ.get(DISPATCH_FLAG) != "1":
        yield None
        return
    descriptor: int | None = None
    control: DispatchControl | None = None
    try:
        descriptor = os.open(CONTROL_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if metadata.st_uid != CONTROL_UID or metadata.st_mode & 0o022:
            raise DispatchControlError("unsafe dispatch control directory")
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        value = read_control()
        if (
            value.enabled(stage)
            and value.artifact_commit == _running_release()
            and dispatch_allowed(value)
        ):
            control = value
    except (OSError, DispatchControlError):
        control = None
    try:
        yield control
    finally:
        if descriptor is not None:
            os.close(descriptor)


def generation_paused(session: Session, *, control: DispatchControl) -> bool:
    return (
        session.scalar(
            select(JobRecord.job_id)
            .where(
                JobRecord.queue == RECEIPT_QUEUE,
                JobRecord.state == "succeeded",
                JobRecord.payload["receipt_type"].as_string() == PAUSE_RECEIPT,
                JobRecord.payload["run_id"].as_string() == control.run_id,
            )
            .limit(1)
        )
        is not None
    )


def dispatch_budget_clear(
    session: Session, *, control: DispatchControl, now: datetime, latch: bool = True
) -> bool:
    """Called under the worker lock, before leasing or consuming a recheck sequence.

    A budget trip appends one immutable control receipt, not a failed provider job.
    It stays latched to this restart identity even after old failures age out. Only
    a new checked restart identity can resume; old receipts are never removed.
    """
    if generation_paused(session, control=control):
        return False
    budget = collect_dispatch_budget(session, now=now)
    if budget.allowed:
        return True
    if latch:
        append_warning_lane_receipt(
            session,
            receipt_type=PAUSE_RECEIPT,
            reason_code="warning_lane_failure_budget",
            run_id=control.run_id,
            occurred_at=now,
            public_metadata={"operation_id": control.operation_id, **asdict(budget)},
        )
    return False


@contextmanager
def provider_guard(factory: Callable[[], Session], *, stage: str, now: datetime) -> Iterator[bool]:
    """Use the same serialization for legacy recheck and scheduled provider work."""
    with dispatch_guard(stage) as control:
        if control is None:
            yield False
            return
        with factory() as bootstrap:
            bind = bootstrap.get_bind()
        with bind.connect() as connection, Session(bind=connection) as guard:
            acquired = (
                guard.scalar(
                    select(func.pg_try_advisory_lock(func.hashtextextended(WORKER_LOCK, 0)))
                )
                is True
            )
            try:
                allowed = acquired and dispatch_budget_clear(guard, control=control, now=now)
                guard.commit()
                yield allowed
            finally:
                if acquired:
                    guard.scalar(
                        select(func.pg_advisory_unlock(func.hashtextextended(WORKER_LOCK, 0)))
                    )
                guard.rollback()
