"""Host interactions for the SmithGuard deployment controller."""

from __future__ import annotations

import ctypes
import fcntl
import grp
import http.client
import math
import os
import pwd
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from smithguard.fsio import fsync_directory
from smithguard.identifiers import strict_json_loads

CONTROLLED_DIRECTORY_MODES = {
    "/etc/systemd/system/smithguard-discovery.service.d": 0o755,
    "/etc/systemd/system/smithguard-warning-recheck.service.d": 0o755,
    "/var/lib/smithguard/catalog-health": 0o2750,
    "/var/lib/smithguard/api-health": 0o2750,
    "/var/lib/smithguard/grok-auth": 0o700,
    "/var/lib/smithguard/claude-auth": 0o700,
}


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    def require_success(self, context: str) -> str:
        if self.returncode != 0:
            raise HostError(f"{context} failed with exit code {self.returncode}")
        return self.stdout


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    body: bytes = b""


@dataclass(frozen=True, slots=True)
class HostFileMetadata:
    exists: bool
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    mtime_ns: int | None = None


class HostError(RuntimeError):
    """A bounded host interaction failed."""


class HostAdapter(Protocol):
    def verify_release(
        self, commit: str, release_root: str, current_link: str | None = None
    ) -> Mapping[str, Any]: ...

    def systemctl(self, args: Sequence[str]) -> CommandResult: ...

    def official_notice_outcome(self, invocation_id: str) -> Mapping[str, Any]: ...

    def unit_conditions(self, unit: str) -> CommandResult: ...

    def retain_unit_state(self, unit: str) -> AbstractContextManager[None]: ...

    def psql(self, sql: str) -> CommandResult: ...

    def count_regular_files(self, path: str) -> int: ...

    def collection_lock(
        self, path: str, *, timeout_seconds: float
    ) -> AbstractContextManager[None]: ...

    def http_get(
        self,
        url: str,
        host_header: str,
        unix_socket: str | None = None,
        *,
        timeout_seconds: float = 20.0,
    ) -> HttpResult: ...

    def aws(self, args: Sequence[str]) -> CommandResult: ...

    def read_file(self, path: str) -> bytes: ...

    def write_file(self, path: str, body: bytes, mode: int) -> None: ...

    def file_metadata(self, path: str) -> HostFileMetadata: ...

    def lookup_ids(self, user: str, group: str) -> tuple[int, int]: ...

    def install_file(self, path: str, body: bytes, mode: int, uid: int, gid: int) -> None: ...

    def ensure_directory(self, path: str, mode: int, uid: int, gid: int) -> None: ...

    def remove_file(self, path: str) -> None: ...

    def list_releases(self, release_root: str) -> list[tuple[str, int]]: ...

    def remove_release(self, release_root: str, commit: str) -> None: ...

    def validate_systemd(self, paths: Sequence[str]) -> CommandResult: ...

    def validate_sysusers(self, path: str) -> CommandResult: ...

    def validate_nginx(self, path: str) -> CommandResult: ...

    def set_file_mtime(self, path: str, epoch: int) -> None: ...

    def set_file_mtime_ns(self, path: str, mtime_ns: int) -> None: ...

    def calendar_next(self, expression: str, base_epoch: int) -> int: ...

    def timer_next_epoch(self, unit: str) -> int: ...

    def timer_last_trigger_usec(self, unit: str) -> int: ...


def _run(arguments: Sequence[str], *, stdin: str | None = None) -> CommandResult:
    completed = subprocess.run(  # noqa: S603 - callers supply argument lists only
        list(arguments),
        check=False,
        capture_output=True,
        text=True,
        input=stdin,
        timeout=120,
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass(slots=True)
class RealHost:
    """Execute deployment checks on the local production host."""

    region: str = "us-east-1"

    def verify_release(
        self, commit: str, release_root: str, current_link: str | None = None
    ) -> Mapping[str, Any]:
        from smithguard.deploy.release import verify_installed_release

        root = Path(release_root)
        if current_link is not None and (
            not Path(current_link).is_symlink()
            or Path(current_link).resolve(strict=True) != root / commit
        ):
            raise HostError("active link does not select the approved installed release")
        proof = dict(verify_installed_release(commit, release_root=root))
        # Read the candidate's actual readiness requirement only after its complete
        # installed-byte proof. Isolated Python ignores caller import paths.
        result = _run(
            (
                str(root / commit / "app/.venv/bin/python"),
                "-I",
                "-B",
                "-c",
                "from smithguard.operational_health import EXPECTED_MIGRATION; "
                "print(EXPECTED_MIGRATION)",
            )
        )
        head = result.require_success("candidate readiness schema").strip()
        if re.fullmatch(r"[0-9]{4}_[A-Za-z0-9_]+", head) is None:
            raise HostError("candidate readiness schema is invalid")
        proof["required_migration_head"] = head
        return proof

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        fsync_directory(path)

    def systemctl(self, args: Sequence[str]) -> CommandResult:
        return _run(("/usr/bin/systemctl", *args))

    def official_notice_outcome(self, invocation_id: str) -> Mapping[str, Any]:
        """Read only this worker's single result, never another invocation's success."""
        if re.fullmatch(r"[a-f0-9]{32}", invocation_id) is None:
            raise HostError("official notice invocation is invalid")
        unit = "smithguard-official-notices.service"
        for attempt in range(3):
            completed = subprocess.run(  # noqa: S603 - fixed unit and validated invocation
                (
                    "/usr/bin/journalctl",
                    "--quiet",
                    "--no-pager",
                    "--output=json",
                    # journalctl otherwise replaces fields over 4096 bytes with null.
                    # Keep our independent 32 KiB output limit and exact binding checks.
                    "--all",
                    "--output-fields=MESSAGE,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID",
                    "--lines=2",
                    "_SYSTEMD_UNIT=" + unit,
                    "_SYSTEMD_INVOCATION_ID=" + invocation_id,
                ),
                check=False,
                capture_output=True,
                text=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                timeout=5,
            )
            if completed.returncode != 0 or len(completed.stdout) > 32768:
                raise HostError("official notice invocation output is unavailable")
            lines = completed.stdout.splitlines()
            if not lines and attempt < 2:
                # Journald may still be receiving stdout just after the unit exits.
                time.sleep(0.1)
                continue
            try:
                if len(lines) != 1:
                    raise ValueError("ambiguous output")
                row = strict_json_loads(lines[0])
                if (
                    row["_SYSTEMD_UNIT"] != unit
                    or row["_SYSTEMD_INVOCATION_ID"] != invocation_id
                    or not isinstance(row["MESSAGE"], str)
                ):
                    raise ValueError("output binding differs")
                result = strict_json_loads(row["MESSAGE"])
                if not isinstance(result, dict):
                    raise ValueError("output is not an object")
                return result
            except (ValueError, TypeError, KeyError) as error:
                raise HostError("official notice invocation output is invalid") from error
        raise HostError("official notice invocation output is unavailable")

    def unit_conditions(self, unit: str) -> CommandResult:
        if re.fullmatch(r"smithguard-[a-z-]+\.service", unit) is None:
            raise HostError("invalid policy service name")
        escaped = "".join(c if c.isalnum() else f"_{ord(c):02x}" for c in unit)
        with self.retain_unit_state(unit):
            return _run(
                (
                    "/usr/bin/busctl",
                    "--json=short",
                    "get-property",
                    "org.freedesktop.systemd1",
                    "/org/freedesktop/systemd1/unit/" + escaped,
                    "org.freedesktop.systemd1.Unit",
                    "Conditions",
                )
            )

    @contextmanager
    def retain_unit_state(self, unit: str) -> Iterator[None]:
        """Keep a successful oneshot's result loaded until its caller verifies it.

        RefUnit belongs to this live bus connection. Separate busctl processes
        would release their references on exit before the systemctl reads. Closing
        this connection releases the reference on success, failure or process loss;
        it never starts, stops or changes the referenced unit.
        """
        if re.fullmatch(r"[a-z0-9][a-z0-9@_.-]{0,240}\.service", unit) is None:
            raise HostError("retained systemd unit name is invalid")
        try:
            library = ctypes.CDLL("libsystemd.so.0")
            library.sd_bus_open_system.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
            library.sd_bus_open_system.restype = ctypes.c_int
            library.sd_bus_set_method_call_timeout.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
            library.sd_bus_set_method_call_timeout.restype = ctypes.c_int
            # sd_bus_call_method's first eight arguments are fixed; the final
            # c_char_p below is the one variadic string named by signature "s".
            library.sd_bus_call_method.argtypes = [
                ctypes.c_void_p,
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_char_p,
            ]
            library.sd_bus_call_method.restype = ctypes.c_int
            library.sd_bus_close.argtypes = [ctypes.c_void_p]
            library.sd_bus_close.restype = None
            library.sd_bus_unref.argtypes = [ctypes.c_void_p]
            library.sd_bus_unref.restype = ctypes.c_void_p
        except (OSError, AttributeError) as error:
            raise HostError("systemd state retention is unavailable") from error
        bus = ctypes.c_void_p()
        try:
            if library.sd_bus_open_system(ctypes.byref(bus)) < 0 or not bus.value:
                raise HostError("systemd state retention connection failed")
            if library.sd_bus_set_method_call_timeout(bus, 30_000_000) < 0:
                raise HostError("systemd state retention timeout failed")
            result = library.sd_bus_call_method(
                bus,
                b"org.freedesktop.systemd1",
                b"/org/freedesktop/systemd1",
                b"org.freedesktop.systemd1.Manager",
                b"RefUnit",
                None,
                None,
                b"s",
                ctypes.c_char_p(unit.encode("ascii")),
            )
            if result < 0:
                raise HostError("systemd state retention was refused")
            yield
        finally:
            if bus.value:
                library.sd_bus_close(bus)
                library.sd_bus_unref(bus)

    def psql(self, sql: str) -> CommandResult:
        return _run(
            (
                "/usr/sbin/runuser",
                "--user",
                "postgres",
                "--",
                "/usr/bin/psql",
                "--host=/run/postgresql",
                "--dbname=smithguard",
                "--no-psqlrc",
                "--tuples-only",
                "--no-align",
                "--set=ON_ERROR_STOP=1",
                "--file=-",
            ),
            stdin=sql,
        )

    @contextmanager
    def collection_lock(self, path: str, *, timeout_seconds: float) -> Iterator[None]:
        """Serialize evidence access or a root-owned warning-authority transition.

        Warning workers hold a shared lock on the stable policy directory inode;
        only the deployment controller may acquire its exclusive transition lock.
        """
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if path == "/etc/SmithGuard/policies":
                metadata = os.fstat(descriptor)
                if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                    raise HostError("warning control directory is unsafe")
            deadline = time.monotonic() + timeout_seconds
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise HostError("evidence collection lock stayed busy") from None
                    time.sleep(1)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def count_regular_files(self, path: str) -> int:
        root = Path(path)
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise HostError("evidence root is unavailable or unsafe")
        count = 0
        try:
            for shard in os.scandir(root):
                if shard.is_symlink() or not shard.is_dir(follow_symlinks=False):
                    raise HostError("evidence root contains an unsafe shard")
                for item in os.scandir(shard.path):
                    if item.is_symlink() or not item.is_file(follow_symlinks=False):
                        raise HostError("evidence shard contains an unsafe entry")
                    count += 1
        except OSError as error:
            raise HostError("evidence files cannot be inventoried") from error
        return count

    def http_get(
        self,
        url: str,
        host_header: str,
        unix_socket: str | None = None,
        *,
        timeout_seconds: float = 20.0,
    ) -> HttpResult:
        if (
            isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 20
        ):
            raise HostError("HTTP preflight timeout is invalid")
        if urlsplit(url).scheme not in {"http", "https"}:
            raise HostError("HTTP preflight URL scheme is invalid")
        if unix_socket is not None:
            if urlsplit(url).scheme != "http" or not unix_socket.startswith("/run/"):
                raise HostError("Unix-socket HTTP preflight target is invalid")

            class UnixSocketConnection(http.client.HTTPConnection):
                def connect(self) -> None:
                    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    connection.settimeout(self.timeout)
                    connection.connect(unix_socket)
                    self.sock = connection

            connection = UnixSocketConnection("localhost", timeout=timeout_seconds)
            try:
                target = urlsplit(url)
                path = target.path or "/"
                if target.query:
                    path = f"{path}?{target.query}"
                connection.request(
                    "GET",
                    path,
                    headers={"Host": host_header, "User-Agent": "smithguard-deploy/1"},
                )
                response = connection.getresponse()
                return HttpResult(response.status, response.read(1_048_577))
            except (OSError, http.client.HTTPException) as error:
                raise HostError("Unix-socket HTTP preflight request failed") from error
            finally:
                connection.close()
        request = urllib.request.Request(  # noqa: S310 - scheme is restricted above
            url,
            headers={"Host": host_header, "User-Agent": "smithguard-deploy/1"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
                return HttpResult(response.status, response.read(1_048_577))
        except urllib.error.HTTPError as error:
            return HttpResult(error.code, error.read(1_048_577))
        except (OSError, urllib.error.URLError) as error:
            raise HostError("HTTP preflight request failed") from error

    def aws(self, args: Sequence[str]) -> CommandResult:
        executable = shutil.which("aws")
        if executable is None:
            raise HostError("AWS CLI is unavailable")
        return _run((executable, *args, "--region", self.region))

    def read_file(self, path: str) -> bytes:
        candidate = Path(path)
        try:
            body = candidate.read_bytes()
        except OSError as error:
            raise HostError(f"cannot read required host file: {path}") from error
        if len(body) > 4_194_304:
            raise HostError(f"required host file is too large: {path}")
        return body

    def write_file(self, path: str, body: bytes, mode: int) -> None:
        if mode not in {0o600, 0o640, 0o644}:
            raise HostError("unsupported deployment receipt mode")
        destination = Path(path)
        if not destination.is_absolute() or not destination.parent.is_dir():
            raise HostError("deployment receipt destination is unavailable")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            self._fsync_directory(destination.parent)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def _absolute_path(path: str) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute() or ".." in candidate.parts:
            raise HostError("configuration path is invalid")
        return candidate

    def file_metadata(self, path: str) -> HostFileMetadata:
        candidate = self._absolute_path(path)
        try:
            metadata = os.lstat(candidate)
        except FileNotFoundError:
            return HostFileMetadata(False)
        except OSError as error:
            raise HostError("configuration file metadata is unavailable") from error
        if not os.path.isfile(candidate) or os.path.islink(candidate):
            raise HostError("configuration target is not a regular file")
        return HostFileMetadata(
            True,
            mode=metadata.st_mode & 0o7777,
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            mtime_ns=metadata.st_mtime_ns,
        )

    def lookup_ids(self, user: str, group: str) -> tuple[int, int]:
        try:
            return pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid
        except KeyError as error:
            raise HostError("configuration file identity is unavailable") from error

    def ensure_directory(self, path: str, mode: int, uid: int, gid: int) -> None:
        """Create only exact reviewed directory/mode pairs; preserve existing state."""
        if CONTROLLED_DIRECTORY_MODES.get(path) != mode:
            raise HostError("directory is outside the controlled configuration boundary")
        candidate = self._absolute_path(path)
        if candidate.parent.resolve(strict=True) != candidate.parent:
            raise HostError("controlled directory ancestor is unsafe")
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            pass
        else:
            os.chown(candidate, uid, gid, follow_symlinks=False)
            os.chmod(candidate, mode, follow_symlinks=False)
            self._fsync_directory(candidate.parent)
        metadata = candidate.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise HostError("controlled directory differs from its approved boundary")

    def install_file(self, path: str, body: bytes, mode: int, uid: int, gid: int) -> None:
        if mode not in {0o600, 0o640, 0o644} or len(body) > 4_194_304:
            raise HostError("configuration file attributes are invalid")
        destination = self._absolute_path(path)
        parent = destination.parent
        if parent.is_symlink() or not parent.is_dir():
            raise HostError("configuration file parent is unavailable")
        current = self.file_metadata(path)
        if current.exists and (current.mode is None or current.uid is None or current.gid is None):
            raise HostError("configuration target metadata is incomplete")
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, mode)
            os.fchown(descriptor, uid, gid)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            self._fsync_directory(parent)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    def list_releases(self, release_root: str) -> list[tuple[str, int]]:
        """Installed releases (a 40-hex directory with INSTALLATION.json) and the
        install time as the INSTALLATION.json modification time in nanoseconds."""
        root = Path(release_root)
        releases: list[tuple[str, int]] = []
        for entry in sorted(root.iterdir()):
            if not re.fullmatch(r"[a-f0-9]{40}", entry.name) or entry.is_symlink():
                continue
            marker = entry / "INSTALLATION.json"
            if entry.is_dir() and marker.is_file() and not marker.is_symlink():
                releases.append((entry.name, marker.stat().st_mtime_ns))
        return releases

    def remove_release(self, release_root: str, commit: str) -> None:
        root = Path(release_root).resolve()
        candidate = root / commit
        if (
            not re.fullmatch(r"[a-f0-9]{40}", commit)
            or candidate.is_symlink()
            or not candidate.is_dir()
            or candidate.resolve().parent != root
        ):
            raise HostError("release directory is not a removable installed release")
        try:
            shutil.rmtree(candidate)
            self._fsync_directory(root)
        except OSError as error:
            raise HostError("release directory cannot be removed") from error

    def remove_file(self, path: str) -> None:
        candidate = self._absolute_path(path)
        metadata = self.file_metadata(path)
        if not metadata.exists:
            return
        try:
            candidate.unlink()
            self._fsync_directory(candidate.parent)
        except OSError as error:
            raise HostError("configuration file cannot be removed") from error

    def validate_systemd(self, paths: Sequence[str]) -> CommandResult:
        if not paths:
            raise HostError("systemd validation paths are empty")
        return _run(("/usr/bin/systemd-analyze", "verify", *paths))

    def validate_sysusers(self, path: str) -> CommandResult:
        return _run(("/usr/bin/systemd-sysusers", "--dry-run", path))

    def validate_nginx(self, path: str) -> CommandResult:
        return _run(("/usr/sbin/nginx", "-t", "-c", path))

    def set_file_mtime(self, path: str, epoch: int) -> None:
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            raise HostError("timer stamp epoch is invalid")
        candidate = self._absolute_path(path)
        if not self.file_metadata(path).exists:
            raise HostError("timer stamp is unavailable")
        try:
            os.utime(candidate, ns=(epoch * 1_000_000_000, epoch * 1_000_000_000))
        except OSError as error:
            raise HostError("timer stamp cannot be advanced") from error

    def set_file_mtime_ns(self, path: str, mtime_ns: int) -> None:
        if isinstance(mtime_ns, bool) or not isinstance(mtime_ns, int) or mtime_ns < 0:
            raise HostError("timer stamp nanoseconds are invalid")
        candidate = self._absolute_path(path)
        if not self.file_metadata(path).exists:
            raise HostError("timer stamp is unavailable")
        try:
            os.utime(candidate, ns=(mtime_ns, mtime_ns))
        except OSError as error:
            raise HostError("timer stamp cannot be restored") from error

    @staticmethod
    def _date_epoch(value: str) -> int:
        completed = subprocess.run(  # noqa: S603 - fixed binary and argument vector
            ("/usr/bin/date", "-u", "--date", value, "+%s"),
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=10,
        )
        try:
            epoch = int(completed.stdout.strip())
        except ValueError as error:
            raise HostError("systemd timer timestamp is invalid") from error
        if completed.returncode != 0 or epoch < 0:
            raise HostError("systemd timer timestamp is invalid")
        return epoch

    def calendar_next(self, expression: str, base_epoch: int) -> int:
        if (
            not expression
            or not expression.isascii()
            or len(expression) > 200
            or isinstance(base_epoch, bool)
            or not isinstance(base_epoch, int)
            or base_epoch < 0
        ):
            raise HostError("systemd calendar expression is invalid")
        completed = subprocess.run(  # noqa: S603 - fixed binary and argument vector
            (
                "/usr/bin/systemd-analyze",
                "calendar",
                "--iterations=1",
                f"--base-time=@{base_epoch}",
                expression,
            ),
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=10,
        )
        if completed.returncode != 0 or len(completed.stdout) > 4096:
            raise HostError("systemd calendar calculation failed")
        matches = re.findall(r"^\s*\(in UTC\):\s+(.+ UTC)$", completed.stdout, re.MULTILINE)
        if len(matches) != 1:
            raise HostError("systemd calendar calculation is ambiguous")
        return self._date_epoch(matches[0])

    def timer_next_epoch(self, unit: str) -> int:
        if re.fullmatch(r"smithguard-[a-z0-9-]+\.timer", unit) is None:
            raise HostError("systemd timer unit is invalid")
        result = self.systemctl(("show", unit, "--property=NextElapseUSecRealtime", "--value"))
        value = result.require_success("read timer next elapse").strip()
        if not value or value == "n/a":
            raise HostError("systemd timer has no next elapse")
        return self._date_epoch(value)

    def timer_last_trigger_usec(self, unit: str) -> int:
        if re.fullmatch(r"smithguard-[a-z0-9-]+\.timer", unit) is None:
            raise HostError("systemd timer unit is invalid")
        escaped = "".join(c if c.isalnum() else f"_{ord(c):02x}" for c in unit)
        completed = subprocess.run(  # noqa: S603 - fixed binary and validated unit path
            (
                "/usr/bin/busctl",
                "--system",
                "get-property",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1/unit/" + escaped,
                "org.freedesktop.systemd1.Timer",
                "LastTriggerUSec",
            ),
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=10,
        )
        if completed.returncode != 0 or len(completed.stdout) > 24:
            raise HostError("systemd timer last trigger read failed")
        match = re.fullmatch(r"t ([0-9]{1,20})\n?", completed.stdout)
        if match is None or not 0 < int(match[1]) < (1 << 64) - 1:
            raise HostError("systemd timer last trigger is invalid")
        return int(match[1])
