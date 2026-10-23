"""Optional root-owned trial lease and irreversible stop latch.

Absent trial policy preserves the ordinary deployment contract. A present but
invalid policy, stale lease, or consumed containment identity denies trial work.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from smithguard.identifiers import strict_json_loads

GRANT = Path("/etc/SmithGuard/policies/warning-trial.json")
RUN = Path("/run/smithguard-warning-trial")
ROOT = Path("/var/lib/smithguard/warning-trials")
OWNER = 0
LEASE_SECONDS = 30


class TrialGateError(ValueError):
    """Trial authority is unavailable; no new warning work may begin."""


def _exists(path):
    """Only confirmed absence is optional; inaccessible authority fails closed."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _read(path):
    for parent in path.parents:
        m = parent.lstat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid != OWNER or m.st_mode & 0o022:
            raise TrialGateError("unsafe trial parent")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        m = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(m.st_mode)
            or m.st_uid != OWNER
            or stat.S_IMODE(m.st_mode) != 0o644
            or m.st_nlink != 1
            or m.st_size > 16384
        ):
            raise TrialGateError("unsafe trial file")
        body = stream.read(16385)
        if len(body) > 16384:
            raise TrialGateError("trial file too large")
        value = strict_json_loads(body)
        if not isinstance(value, dict):
            raise TrialGateError("trial input is not an object")
        return body, value


def _lease(operation_id, commit, *, dispatch):
    body, grant = _read(GRANT)
    identity = grant.get("operation_id")
    if not isinstance(identity, str) or not re.fullmatch(r"[0-9]{8}-[a-f0-9]{32}", identity):
        raise TrialGateError("invalid containment identity")
    if (
        grant.get("principal") != "smithguard-warning-supervisor"
        or grant.get("startup_operation_id") != operation_id
        or grant.get("release_commit") != commit
        or _exists(ROOT / identity / "containment-started.json")
    ):
        raise TrialGateError("trial is not allowed")
    _, lease = _read(RUN / "lease.json")
    now, monotonic = time.time(), time.monotonic()
    if (
        lease.get("grant_sha256") != hashlib.sha256(body).hexdigest()
        or lease.get("boot_id") != grant.get("boot_id")
        # ProcSubset=pid hides /proc/sys in the provider worker. The root broker
        # checks the live boot before issuing a lease; /run and CLOCK_MONOTONIC
        # make that lease boot-local. The root activation path also checks here.
        or (
            not dispatch
            and lease.get("boot_id") != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        )
        or type(lease.get("monotonic")) not in {int, float}
        or not 0 <= monotonic - lease["monotonic"] <= LEASE_SECONDS
        or type(grant.get("starts_at")) not in {int, float}
        or type(grant.get("cutoff")) not in {int, float}
        or not grant["starts_at"] <= now < grant["cutoff"]
        or lease.get("allow_activation") is not True
        or (dispatch and lease.get("allow_dispatch") is not True)
    ):
        raise TrialGateError("trial lease is unavailable")


def dispatch_allowed(control):
    try:
        if not _exists(GRANT):
            return True
        _lease(control.operation_id, control.artifact_commit, dispatch=True)
        return True
    except (OSError, ValueError, TypeError, KeyError):
        return False


@contextmanager
def activation_guard(operation_id, commit):
    """Serialize only the short enable/start section with stop-only containment."""
    descriptor = None
    try:
        try:
            if _exists(GRANT):
                descriptor = os.open(RUN, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                m = os.fstat(descriptor)
                if m.st_uid != OWNER or m.st_mode & 0o022:
                    raise TrialGateError("unsafe trial lock")
                deadline = time.monotonic() + 5
                while True:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise TrialGateError("trial stop owns startup") from None
                        time.sleep(0.05)
                _lease(operation_id, commit, dispatch=False)
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise TrialGateError("trial activation refused") from error
        # Preserve errors from the native enable/start body, including no-grant
        # ordinary startup. Only this guard's own failures are trial refusals.
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
