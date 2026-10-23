"""Inactive, commit-pinned local Git reader for OpenSSF Malicious Packages."""

from __future__ import annotations

import bisect
import hashlib
import os
import re
import stat
import subprocess
import unicodedata
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import quote

from smithguard.identifiers import (
    INGEST_JSON_MAX_DEPTH,
    INGEST_JSON_MAX_NODES,
    SHA1_HEX,
    DuplicateJsonKeyError,
    canonical_json_bytes,
    parse_timestamp,
    strict_json_loads,
)
from smithguard.openssf_budget import bounded_timeout

if TYPE_CHECKING:
    from smithguard.collectors import CollectorSpec, TransportResponse

OPENSSF_REPOSITORY_URL = "https://github.com/ossf/malicious-packages"
OPENSSF_MALICIOUS = "gbsec:source:openssf-malicious-packages"
OPENSSF_CONNECTOR_ID = "gbsec:connector:openssf-git-v1"
OPENSSF_LICENSE_SHA256 = "sha256:c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
OPENSSF_REVIEWED_COMMIT = "f94d3c298d2a9658982a99894c2f440906257d14"
GIT_EXECUTABLE = "/usr/bin/git"

COMMIT = SHA1_HEX
OBJECT_ID = re.compile(r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")
ADVISORY_ID = re.compile(r"^MAL-[0-9]{4}-[0-9]+$")
PROVISIONAL_ADVISORY_ID = re.compile(r"^MAL-0000-[A-Za-z0-9][A-Za-z0-9._:+-]{0,150}$")
ECOSYSTEM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,79}$")

# This is the retained private-shadow scope, not the complete public catalog scope.
# The public catalog must call inspect_complete(), which cannot apply this filter.
LEGACY_SHADOW_ECOSYSTEMS = frozenset({"npm", "pypi"})
ACCEPTED_FIELDS = frozenset(
    {
        "affected",
        "aliases",
        "database_specific",
        "id",
        "modified",
        "published",
        "references",
        "withdrawn",
    }
)
MAX_TREE_BYTES = 67_108_864
MAX_TREE_RECORDS = 500_000
MAX_BLOB_BYTES = 4 * 1024 * 1024
MAX_RAW_BATCH_BYTES = 8 * 1024 * 1024
MAX_TOTAL_REVIEWED_BYTES = 68_719_476_736
MAX_PAGE_SIZE = 1_000
MAX_DIFF_CHANGES = 100_000
GIT_TIMEOUT_SECONDS = 120
MAX_PACKAGE_COMPONENT_CHARACTERS = 300
MAX_PACKAGE_COMPONENT_UTF8_BYTES = 900
MAX_PACKAGE_PATH_CHARACTERS = 400
MAX_PACKAGE_PATH_UTF8_BYTES = 1_200
MAX_PAGE_CURSOR_CHARACTERS = 1_000
MAX_PAGE_CURSOR_UTF8_BYTES = 3_000
MAX_CACHED_ECOSYSTEM_LABELS = 256
ASCII_PACKAGE_COMPONENT_PUNCTUATION = "._%+@:-"
FIRST_ASCII_PACKAGE_COMPONENT_CHARACTERS = frozenset({"@", "-"})
FIRST_UNICODE_PACKAGE_COMPONENT_CATEGORIES = frozenset({"L", "N"})
UNICODE_PACKAGE_COMPONENT_CATEGORIES = frozenset({"L", "M", "N"})
# Current source policy; historical NEXT-002/readiness records retain Unicode 15.
OPENSSF_PATH_POLICY_ID = "smithguard-openssf-path-unicode16-v1"
REVIEWED_UNICODE_DATA_VERSION = "16.0.0"


class OpenSSFGitError(ValueError):
    """A local OpenSSF Git snapshot crossed its reviewed boundary."""


class OpenSSFProvisionalIDError(OpenSSFGitError):
    """An otherwise reviewed OpenSSF path still has a temporary advisory identity."""


def _nul_records(body: bytes):
    """Iterate Git's NUL-delimited output without retaining a second full tree."""
    offset = 0
    while True:
        end = body.find(b"\0", offset)
        if end < 0:
            yield body[offset:]
            return
        yield body[offset:end]
        offset = end + 1


def raw_batches(entries, *, maximum_records: int = MAX_PAGE_SIZE):
    """Bound each Git batch by both declared raw bytes and record count."""
    batch = []
    byte_count = 0
    for entry in entries:
        if entry.byte_count > MAX_RAW_BATCH_BYTES:
            raise OpenSSFGitError("OpenSSF single raw record exceeds batch budget")
        if batch and (
            len(batch) >= maximum_records or byte_count + entry.byte_count > MAX_RAW_BATCH_BYTES
        ):
            yield tuple(batch)
            batch, byte_count = [], 0
        batch.append(entry)
        byte_count += entry.byte_count
    if batch:
        yield tuple(batch)


@dataclass(frozen=True, slots=True)
class OpenSSFGitEntry:
    commit: str
    path: str
    blob_oid: str
    byte_count: int
    source_state: Literal["active", "withdrawn"]
    source_tree: Literal["malicious", "withdrawn"]
    ecosystem: str
    package_path: str
    advisory_id: str

    @property
    def canonical_url(self) -> str:
        """Link to the advisory at the exact repository commit that supplied it."""
        encoded_path = quote(self.path, safe="/:@._+-")
        return f"{OPENSSF_REPOSITORY_URL}/blob/{self.commit}/{encoded_path}"

    @property
    def checkpoint_token(self) -> str:
        return f"{self.commit}:{self.blob_oid}"


@dataclass(frozen=True, slots=True)
class OpenSSFSnapshot:
    commit: str
    license_sha256: str
    entries: tuple[OpenSSFGitEntry, ...]
    active_count: int
    withdrawn_count: int
    unsupported_counts: tuple[tuple[str, int], ...]
    ignored_nonrecord_count: int
    total_reviewed_bytes: int


@dataclass(frozen=True, slots=True)
class OpenSSFPage:
    commit: str
    entries: tuple[OpenSSFGitEntry, ...]
    has_more: bool
    next_after_path: str | None


@dataclass(frozen=True, slots=True)
class OpenSSFRecord:
    entry: OpenSSFGitEntry
    raw_body: bytes
    projected: Mapping[str, Any]
    source_published_at: datetime | None
    source_modified_at: datetime | None


@dataclass(frozen=True, slots=True)
class OpenSSFChange:
    kind: Literal["added", "modified", "removed", "renamed", "withdrawn", "restored"]
    advisory_id: str
    before: OpenSSFGitEntry | None
    after: OpenSSFGitEntry | None


@dataclass(frozen=True, slots=True)
class OpenSSFDiff:
    before_commit: str
    after_commit: str
    changes: tuple[OpenSSFChange, ...]


def _source_time(value: Any, *, field: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.isascii():
        raise OpenSSFGitError(f"OpenSSF {field} time is invalid")
    try:
        return parse_timestamp(value, maximum=40)
    except ValueError as error:
        raise OpenSSFGitError(f"OpenSSF {field} time is invalid") from error


def _safe_package_component(value: str) -> bool:
    try:
        utf8_bytes = len(value.encode("utf-8")) if isinstance(value, str) else 0
    except UnicodeEncodeError:
        return False
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_PACKAGE_COMPONENT_CHARACTERS
        or utf8_bytes > MAX_PACKAGE_COMPONENT_UTF8_BYTES
        or value in {".", ".."}
    ):
        return False
    first = value[0]
    if first.isascii():
        if not (first.isalnum() or first in FIRST_ASCII_PACKAGE_COMPONENT_CHARACTERS):
            return False
    elif unicodedata.category(first)[0] not in FIRST_UNICODE_PACKAGE_COMPONENT_CATEGORIES:
        return False
    for character in value[1:]:
        if character.isascii():
            if not (character.isalnum() or character in ASCII_PACKAGE_COMPONENT_PUNCTUATION):
                return False
        elif unicodedata.category(character)[0] not in UNICODE_PACKAGE_COMPONENT_CATEGORIES:
            return False
    return True


def _path_names_exact_package(entry: OpenSSFGitEntry, ecosystem: object, name: object) -> bool:
    """Verify upstream tree naming without normalizing the stored package identity."""
    known_labels = {
        "crates.io": "crates.io",
        "git": "git",
        "go": "Go",
        "maven": "Maven",
        "npm": "npm",
        "nuget": "NuGet",
        "packagist": "Packagist",
        "pypi": "PyPI",
        "rubygems": "RubyGems",
        "vscode": "VSCode",
        "vscode:open-vsx.org": "VSCode:https://open-vsx.org",
    }
    expected_ecosystem = known_labels.get(entry.ecosystem, entry.ecosystem)
    if not isinstance(ecosystem, str) or not isinstance(name, str):
        return False
    # Unknown labels may use title case while directories are lowercase. Preserve
    # their exact package path and do not invent a public ecosystem mapping.
    if ecosystem != expected_ecosystem and (
        entry.ecosystem in known_labels or ecosystem.casefold() != entry.ecosystem
    ):
        return False
    if name == entry.package_path:
        return True
    if entry.ecosystem in {
        "npm",
        "nuget",
        "go",
        "maven",
        "packagist",
        "rubygems",
        "vscode",
        "vscode:open-vsx.org",
    }:
        return entry.package_path.casefold() == name.casefold()
    if entry.ecosystem == "pypi":
        canonical_tree_name = re.sub(r"[-_.]+", "-", name).lower()
        return entry.package_path == canonical_tree_name
    if entry.ecosystem == "crates.io":
        return entry.package_path.replace("_", "-").casefold() == name.replace("_", "-").casefold()
    return False


def _path_entry(
    *,
    commit: str,
    mode: str,
    object_type: str,
    blob_oid: str,
    byte_count: int,
    path: str,
    ecosystem_labels: dict[str, str] | None = None,
) -> OpenSSFGitEntry | None:
    if not path.endswith(".json"):
        return None
    if mode != "100644" or object_type != "blob":
        raise OpenSSFGitError("OpenSSF JSON tree entry is not a regular blob")
    if not OBJECT_ID.fullmatch(blob_oid):
        raise OpenSSFGitError("OpenSSF blob identity is invalid")
    if not 1 <= byte_count <= MAX_BLOB_BYTES:
        raise OpenSSFGitError("OpenSSF JSON blob exceeds the reviewed size limit")
    parts = path.split("/")
    if (
        len(parts) < 5
        or parts[0] != "osv"
        or parts[1] not in {"malicious", "withdrawn"}
        or not ECOSYSTEM.fullmatch(parts[2])
        or any(not _safe_package_component(part) for part in parts[3:-1])
    ):
        raise OpenSSFGitError("OpenSSF JSON path is outside the reviewed tree shape")
    advisory_id = parts[-1][:-5]
    provisional_advisory = PROVISIONAL_ADVISORY_ID.fullmatch(advisory_id) is not None
    if not provisional_advisory and not ADVISORY_ID.fullmatch(advisory_id):
        raise OpenSSFGitError("OpenSSF JSON path is outside the reviewed tree shape")
    package_path = "/".join(parts[3:-1])
    if (
        not package_path
        or len(package_path) > MAX_PACKAGE_PATH_CHARACTERS
        or len(package_path.encode("utf-8")) > MAX_PACKAGE_PATH_UTF8_BYTES
    ):
        raise OpenSSFGitError("OpenSSF package path is invalid")
    if provisional_advisory:
        raise OpenSSFProvisionalIDError(
            "OpenSSF tree contains a recognized provisional advisory identity"
        )
    tree = parts[1]
    ecosystem = parts[2].lower()
    if ecosystem_labels is not None:
        cached = ecosystem_labels.get(ecosystem)
        if cached is not None:
            ecosystem = cached
        elif len(ecosystem_labels) < MAX_CACHED_ECOSYSTEM_LABELS:
            ecosystem_labels[ecosystem] = ecosystem
    return OpenSSFGitEntry(
        commit=commit,
        path=path,
        blob_oid=blob_oid,
        byte_count=byte_count,
        source_state="withdrawn" if tree == "withdrawn" else "active",
        source_tree="withdrawn" if tree == "withdrawn" else "malicious",
        ecosystem=ecosystem,
        package_path=package_path,
        advisory_id=advisory_id,
    )


class LocalOpenSSFGitRepository:
    """Read one operator-supplied local repository without fetching or mutating it."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        try:
            metadata = self.root.lstat()
        except OSError as error:
            raise OpenSSFGitError("OpenSSF local repository is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise OpenSSFGitError("OpenSSF local repository must be a real directory")
        if self._git_text("rev-parse", "--is-inside-work-tree", maximum=64) != "true":
            raise OpenSSFGitError("OpenSSF local repository is not a Git work tree")
        partial_clone = self._git_optional_text(
            "config",
            "--local",
            "--no-includes",
            "--get",
            "extensions.partialClone",
            maximum=512,
        )
        promisor_remotes = self._git_optional_text(
            "config",
            "--local",
            "--no-includes",
            "--get-regexp",
            r"^remote\..*\.promisor$",
            maximum=4_096,
        )
        if partial_clone or promisor_remotes:
            raise OpenSSFGitError("OpenSSF local repository must contain complete local objects")

    def _git(
        self,
        *arguments: str,
        maximum: int,
        allowed_returncodes: Sequence[int] = (0,),
    ) -> tuple[int, bytes]:
        environment = self._git_environment()
        try:
            completed = subprocess.run(  # noqa: S603 - fixed Git command, no shell
                (
                    GIT_EXECUTABLE,
                    "-c",
                    "core.hooksPath=/dev/null",
                    "--no-replace-objects",
                    "-C",
                    str(self.root),
                    *arguments,
                ),
                check=False,
                capture_output=True,
                env=environment,
                timeout=bounded_timeout(GIT_TIMEOUT_SECONDS),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise OpenSSFGitError("bounded local Git command failed") from error
        if completed.returncode not in allowed_returncodes:
            raise OpenSSFGitError("local Git repository rejected the requested object")
        if len(completed.stdout) > maximum or len(completed.stderr) > 4096:
            raise OpenSSFGitError("local Git command exceeded its output limit")
        return completed.returncode, completed.stdout

    def _git_environment(self) -> dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.root),
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }

    def _git_text(self, *arguments: str, maximum: int) -> str:
        _returncode, body = self._git(*arguments, maximum=maximum)
        try:
            return body.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise OpenSSFGitError("local Git command returned non-ASCII metadata") from error

    def _git_optional_text(self, *arguments: str, maximum: int) -> str:
        _returncode, body = self._git(
            *arguments,
            maximum=maximum,
            allowed_returncodes=(0, 1),
        )
        try:
            return body.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise OpenSSFGitError("local Git command returned non-ASCII metadata") from error

    def _resolve_commit(self, commit: str) -> str:
        if not isinstance(commit, str) or COMMIT.fullmatch(commit) is None:
            raise OpenSSFGitError("OpenSSF commit must be one full SHA-1 identity")
        resolved = self._git_text("rev-parse", "--verify", f"{commit}^{{commit}}", maximum=128)
        if resolved != commit:
            raise OpenSSFGitError("OpenSSF commit resolution changed the requested identity")
        return resolved

    def _blob(self, object_id: str, *, maximum: int) -> bytes:
        if OBJECT_ID.fullmatch(object_id) is None:
            raise OpenSSFGitError("OpenSSF blob identity is invalid")
        _returncode, body = self._git("cat-file", "blob", object_id, maximum=maximum)
        return body

    def _license_sha256(self, commit: str) -> str:
        license_oid = self._git_text("rev-parse", f"{commit}:LICENSE", maximum=128)
        body = self._blob(license_oid, maximum=65_536)
        return "sha256:" + hashlib.sha256(body).hexdigest()

    def commit_time(self, commit: str) -> datetime:
        """Return the exact UTC committer time for one validated local commit."""
        resolved = self._resolve_commit(commit)
        value = self._git_text("show", "-s", "--format=%cI", resolved, maximum=128)
        parsed = _source_time(value, field="commit")
        if parsed is None:
            raise OpenSSFGitError("OpenSSF commit time is absent")
        return parsed

    def inspect(
        self,
        commit: str,
        *,
        expected_license_sha256: str = OPENSSF_LICENSE_SHA256,
        supported_ecosystems: frozenset[str] | None = LEGACY_SHADOW_ECOSYSTEMS,
    ) -> OpenSSFSnapshot:
        if unicodedata.unidata_version != REVIEWED_UNICODE_DATA_VERSION:
            raise OpenSSFGitError("OpenSSF Unicode data version differs from the reviewed runtime")
        resolved = self._resolve_commit(commit)
        license_sha256 = self._license_sha256(resolved)
        if license_sha256 != expected_license_sha256:
            raise OpenSSFGitError("OpenSSF license bytes differ from the reviewed snapshot")
        _returncode, tree = self._git(
            "ls-tree",
            "-r",
            "-z",
            "--long",
            resolved,
            "--",
            "osv/malicious",
            "osv/withdrawn",
            maximum=MAX_TREE_BYTES,
        )
        entries: list[OpenSSFGitEntry] = []
        unsupported: Counter[str] = Counter()
        ignored = 0
        total_bytes = 0
        total_records = 0
        seen_paths: set[str] = set()
        seen_advisory_ids: set[str] = set()
        # Share repeated validated labels only within this bounded inspection.
        # Do not intern arbitrary upstream strings in process-global storage.
        ecosystem_labels: dict[str, str] = {}
        for raw in _nul_records(tree):
            if not raw:
                continue
            try:
                metadata, path_bytes = raw.split(b"\t", 1)
                mode, object_type, blob_oid, size_value = metadata.decode("ascii").split()
                path = path_bytes.decode("utf-8")
                byte_count = int(size_value)
            except (ValueError, UnicodeDecodeError) as error:
                raise OpenSSFGitError("OpenSSF tree metadata is invalid") from error
            if "\x00" in path or path in seen_paths:
                raise OpenSSFGitError("OpenSSF tree path is invalid or duplicated")
            seen_paths.add(path)
            entry = _path_entry(
                commit=resolved,
                mode=mode,
                object_type=object_type,
                blob_oid=blob_oid,
                byte_count=byte_count,
                path=path,
                ecosystem_labels=ecosystem_labels,
            )
            if entry is None:
                ignored += 1
                continue
            total_records += 1
            total_bytes += entry.byte_count
            if total_records > MAX_TREE_RECORDS or total_bytes > MAX_TOTAL_REVIEWED_BYTES:
                raise OpenSSFGitError("OpenSSF reviewed tree exceeds its bounded capacity")
            if entry.advisory_id in seen_advisory_ids:
                raise OpenSSFGitError("OpenSSF advisory identity appears in more than one path")
            seen_advisory_ids.add(entry.advisory_id)
            if supported_ecosystems is not None and entry.ecosystem not in supported_ecosystems:
                unsupported[entry.ecosystem] += 1
                continue
            entries.append(entry)
        entries.sort(key=lambda item: item.path)
        return OpenSSFSnapshot(
            commit=resolved,
            license_sha256=license_sha256,
            entries=tuple(entries),
            active_count=sum(entry.source_state == "active" for entry in entries),
            withdrawn_count=sum(entry.source_state == "withdrawn" for entry in entries),
            unsupported_counts=tuple(sorted(unsupported.items())),
            ignored_nonrecord_count=ignored,
            total_reviewed_bytes=total_bytes,
        )

    def inspect_complete(
        self,
        commit: str,
        *,
        expected_license_sha256: str = OPENSSF_LICENSE_SHA256,
    ) -> OpenSSFSnapshot:
        """Inspect both complete source trees without an ecosystem allowlist."""
        snapshot = self.inspect(
            commit,
            expected_license_sha256=expected_license_sha256,
            supported_ecosystems=None,
        )
        if snapshot.unsupported_counts:
            raise OpenSSFGitError("complete OpenSSF inspection filtered an ecosystem")
        return snapshot

    def page(
        self,
        snapshot: OpenSSFSnapshot,
        *,
        after_path: str | None = None,
        limit: int = 500,
    ) -> OpenSSFPage:
        """Return one page; after a snapshot change, restart with no cursor."""
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_PAGE_SIZE:
            raise OpenSSFGitError("OpenSSF page limit is invalid")
        paths = [entry.path for entry in snapshot.entries]
        start = 0
        if after_path is not None:
            try:
                cursor_utf8_bytes = (
                    len(after_path.encode("utf-8")) if isinstance(after_path, str) else 0
                )
            except UnicodeEncodeError as error:
                raise OpenSSFGitError("OpenSSF page cursor is invalid") from error
            if (
                not isinstance(after_path, str)
                or not after_path
                or len(after_path) > MAX_PAGE_CURSOR_CHARACTERS
                or cursor_utf8_bytes > MAX_PAGE_CURSOR_UTF8_BYTES
            ):
                raise OpenSSFGitError("OpenSSF page cursor is invalid")
            cursor_index = bisect.bisect_left(paths, after_path)
            if cursor_index >= len(paths) or paths[cursor_index] != after_path:
                raise OpenSSFGitError("OpenSSF page cursor is invalid")
            start = cursor_index + 1
        selected = snapshot.entries[start : start + limit]
        has_more = start + len(selected) < len(snapshot.entries)
        return OpenSSFPage(
            commit=snapshot.commit,
            entries=selected,
            has_more=has_more,
            next_after_path=selected[-1].path if selected and has_more else None,
        )

    def read_blobs(self, entries: Sequence[OpenSSFGitEntry]) -> tuple[bytes, ...]:
        """Read one bounded page of local blobs with one non-network Git process."""
        if not entries or len(entries) > MAX_PAGE_SIZE:
            raise OpenSSFGitError("OpenSSF blob batch size is invalid")
        if (
            any(not 1 <= entry.byte_count <= MAX_BLOB_BYTES for entry in entries)
            or sum(entry.byte_count for entry in entries) > MAX_RAW_BATCH_BYTES
        ):
            raise OpenSSFGitError("OpenSSF blob batch exceeds its raw byte budget")
        commits = {entry.commit for entry in entries}
        if len(commits) != 1:
            raise OpenSSFGitError("OpenSSF blob batch spans more than one commit")
        self._resolve_commit(next(iter(commits)))
        request = b"".join(entry.blob_oid.encode("ascii") + b"\n" for entry in entries)
        maximum = sum(entry.byte_count for entry in entries) + len(entries) * 100 + 4096
        command = (
            GIT_EXECUTABLE,
            "-c",
            "core.hooksPath=/dev/null",
            "--no-replace-objects",
            "-C",
            str(self.root),
            "cat-file",
            "--batch",
        )
        timeout = bounded_timeout(GIT_TIMEOUT_SECONDS)
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed Git command, no shell
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._git_environment(),
            )
            output, errors = process.communicate(request, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.communicate()
            raise OpenSSFGitError("bounded local Git blob batch timed out") from error
        except OSError as error:
            raise OpenSSFGitError("bounded local Git blob batch failed") from error
        if process.returncode != 0 or len(errors) > 4096 or len(output) > maximum:
            raise OpenSSFGitError("local Git blob batch crossed its reviewed boundary")
        bodies: list[bytes] = []
        cursor = 0
        for entry in entries:
            newline = output.find(b"\n", cursor)
            if newline < 0:
                raise OpenSSFGitError("local Git blob batch header is incomplete")
            try:
                object_id, object_type, size_value = output[cursor:newline].decode("ascii").split()
                byte_count = int(size_value)
            except (UnicodeDecodeError, ValueError) as error:
                raise OpenSSFGitError("local Git blob batch header is invalid") from error
            if (
                object_id != entry.blob_oid
                or object_type != "blob"
                or byte_count != entry.byte_count
            ):
                raise OpenSSFGitError("local Git blob batch identity or size differs")
            start = newline + 1
            end = start + byte_count
            if end >= len(output) or output[end : end + 1] != b"\n":
                raise OpenSSFGitError("local Git blob batch body is incomplete")
            bodies.append(output[start:end])
            cursor = end + 1
        if cursor != len(output):
            raise OpenSSFGitError("local Git blob batch returned trailing bytes")
        return tuple(bodies)

    def parse_record(self, entry: OpenSSFGitEntry, raw_body: bytes) -> OpenSSFRecord:
        """Validate one already-read source blob against its immutable tree entry."""
        if len(raw_body) != entry.byte_count:
            raise OpenSSFGitError("OpenSSF blob size differs from the reviewed tree")
        try:
            # A reviewed-tree blob of up to MAX_BLOB_BYTES: keep the ingest headroom.
            document = strict_json_loads(
                raw_body.decode("utf-8"),
                max_nodes=INGEST_JSON_MAX_NODES,
                max_depth=INGEST_JSON_MAX_DEPTH,
            )
        except UnicodeDecodeError as error:
            # RecursionError is deliberately not caught here: the pre-consolidation clause
            # caught only decode and JSON errors, so it propagates exactly as before.
            raise OpenSSFGitError("OpenSSF record is not valid bounded JSON") from error
        except DuplicateJsonKeyError as error:
            raise OpenSSFGitError("OpenSSF record contains a duplicate JSON key") from error
        except ValueError as error:
            reason = getattr(error, "reason", None)
            if reason == "non_finite":
                raise OpenSSFGitError("OpenSSF record contains a non-finite number") from error
            if reason in {"too_many_nodes", "too_deep"}:
                raise OpenSSFGitError("OpenSSF record exceeds its bounded shape") from error
            raise OpenSSFGitError("OpenSSF record is not valid bounded JSON") from error
        if not isinstance(document, Mapping):
            raise OpenSSFGitError("OpenSSF record root is not an object")
        projected = {key: document[key] for key in sorted(ACCEPTED_FIELDS) if key in document}
        if projected.get("id") != entry.advisory_id:
            raise OpenSSFGitError("OpenSSF path and record identities differ")
        withdrawn = projected.get("withdrawn")
        if (entry.source_state == "withdrawn") != (withdrawn is not None):
            raise OpenSSFGitError("OpenSSF tree and record withdrawal states differ")
        _source_time(withdrawn, field="withdrawn")
        affected = projected.get("affected")
        if not isinstance(affected, list) or not affected:
            raise OpenSSFGitError("OpenSSF record has no affected package")
        matched_path = False
        package_less_git = False
        for item in affected:
            package = item.get("package") if isinstance(item, Mapping) else None
            if not isinstance(package, Mapping):
                ranges = item.get("ranges") if isinstance(item, Mapping) else None
                if (
                    entry.ecosystem == "git"
                    and isinstance(ranges, list)
                    and ranges
                    and all(
                        isinstance(value, Mapping)
                        and value.get("type") == "GIT"
                        and isinstance(value.get("repo"), str)
                        for value in ranges
                    )
                ):
                    package_less_git = True
                continue
            if _path_names_exact_package(
                entry,
                package.get("ecosystem"),
                package.get("name"),
            ):
                matched_path = True
                break
        if not matched_path and not package_less_git:
            raise OpenSSFGitError("OpenSSF path and affected package differ")
        return OpenSSFRecord(
            entry=entry,
            raw_body=raw_body,
            projected=projected,
            source_published_at=_source_time(projected.get("published"), field="published"),
            source_modified_at=_source_time(projected.get("modified"), field="modified"),
        )

    def read_record(self, entry: OpenSSFGitEntry) -> OpenSSFRecord:
        self._resolve_commit(entry.commit)
        raw_body = self._blob(entry.blob_oid, maximum=MAX_BLOB_BYTES)
        return self.parse_record(entry, raw_body)

    def diff(
        self,
        before: OpenSSFSnapshot,
        after: OpenSSFSnapshot,
        *,
        maximum_changes: int = MAX_DIFF_CHANGES,
    ) -> OpenSSFDiff:
        if not isinstance(maximum_changes, int) or not 1 <= maximum_changes <= MAX_DIFF_CHANGES:
            raise OpenSSFGitError("OpenSSF diff limit is invalid")
        returncode, _body = self._git(
            "merge-base",
            "--is-ancestor",
            before.commit,
            after.commit,
            maximum=0,
            allowed_returncodes=(0, 1),
        )
        if returncode != 0:
            raise OpenSSFGitError("OpenSSF update is not a forward commit transition")
        before_by_path = {entry.path: entry for entry in before.entries}
        after_by_path = {entry.path: entry for entry in after.entries}
        changes: list[OpenSSFChange] = []
        removed = {
            path: entry for path, entry in before_by_path.items() if path not in after_by_path
        }
        added = {path: entry for path, entry in after_by_path.items() if path not in before_by_path}
        for path in sorted(set(before_by_path) & set(after_by_path)):
            old = before_by_path[path]
            new = after_by_path[path]
            if old.blob_oid != new.blob_oid or old.byte_count != new.byte_count:
                changes.append(OpenSSFChange("modified", new.advisory_id, old, new))
        removed_by_id = {entry.advisory_id: entry for entry in removed.values()}
        added_by_id = {entry.advisory_id: entry for entry in added.values()}
        for advisory_id in sorted(set(removed_by_id) & set(added_by_id)):
            old = removed_by_id.pop(advisory_id)
            new = added_by_id.pop(advisory_id)
            removed.pop(old.path)
            added.pop(new.path)
            if old.source_state == "active" and new.source_state == "withdrawn":
                kind: Literal["renamed", "withdrawn", "restored"] = "withdrawn"
            elif old.source_state == "withdrawn" and new.source_state == "active":
                kind = "restored"
            else:
                kind = "renamed"
            changes.append(OpenSSFChange(kind, advisory_id, old, new))
        changes.extend(
            OpenSSFChange("removed", entry.advisory_id, entry, None)
            for entry in sorted(removed.values(), key=lambda item: item.path)
        )
        changes.extend(
            OpenSSFChange("added", entry.advisory_id, None, entry)
            for entry in sorted(added.values(), key=lambda item: item.path)
        )
        changes.sort(
            key=lambda item: (
                item.after.path if item.after is not None else item.before.path,  # type: ignore[union-attr]
                item.kind,
            )
        )
        if len(changes) > maximum_changes:
            raise OpenSSFGitError("OpenSSF update exceeds the reviewed change limit")
        return OpenSSFDiff(before.commit, after.commit, tuple(changes))


@dataclass(frozen=True, slots=True)
class OpenSSFEntryTransport:
    """One explicit validated local record adapted to the injected collector boundary."""

    record: OpenSSFRecord
    retrieved_at: datetime
    expected_previous_checkpoint: str | None = None

    def __call__(
        self,
        spec: CollectorSpec,
        previous_checkpoint: str | None,
    ) -> TransportResponse:
        from smithguard.collectors import TransportResponse

        if spec.source_id != OPENSSF_MALICIOUS or spec.connector_id != OPENSSF_CONNECTOR_ID:
            raise OpenSSFGitError("OpenSSF record was given to another connector")
        if previous_checkpoint != self.expected_previous_checkpoint:
            raise OpenSSFGitError("OpenSSF checkpoint differs from the reviewed sequence")
        if self.retrieved_at.tzinfo is None or self.retrieved_at.utcoffset() is None:
            raise OpenSSFGitError("OpenSSF retrieval time must include a timezone")
        return TransportResponse(
            body=self.record.raw_body,
            canonical_url=self.record.entry.canonical_url,
            media_type="application/json",
            retrieved_at=self.retrieved_at.astimezone(UTC),
            source_record_id=self.record.entry.advisory_id,
            source_published_at=self.record.source_published_at,
            source_modified_at=self.record.source_modified_at,
            declared_content_length=len(self.record.raw_body),
            redirect_count=0,
            elapsed_seconds=0.0,
            checkpoint_token=self.record.entry.checkpoint_token,
        )


def canonical_projected_record(record: OpenSSFRecord) -> bytes:
    """Expose exact accepted bytes for deterministic fixtures and shadow comparison."""
    return canonical_json_bytes(dict(record.projected))
