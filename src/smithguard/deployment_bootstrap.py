"""Root-operated filesystem preparation and unprivileged release preflight."""

from __future__ import annotations

import grp
import os
import pwd
import stat
import sys
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from smithguard.evidence import DEFAULT_MAX_BYTES, LocalImmutableEvidenceStore
from smithguard.identifiers import SHA256_HEX, SHARD

EVIDENCE_ROOT = Path("/var/lib/smithguard/evidence")
EVIDENCE_OWNER = "smithguard-collector"
EVIDENCE_GROUP = "smithguard-evidence"
EVIDENCE_DIRECTORY_MODE = 0o2750
EVIDENCE_FILE_MODE = 0o440
# One million evidence objects was the retired recovery point's ceiling; the tree
# bound keeps the same envelope plus shard directories.
MAX_EVIDENCE_TREE_ENTRIES = 1_000_000 + 1024
SHARD_NAME = SHARD
OBJECT_NAME = SHA256_HEX
EVIDENCE_PREPARATION_REASON_BY_MESSAGE = {
    "evidence tree contains an unsafe entry": "evidence_tree_unsafe_entry",
    "evidence directory cannot be read safely": "evidence_tree_unreadable",
    "evidence tree contains an unsafe name": "evidence_tree_unsafe_name",
    "evidence entry cannot be inspected": "evidence_entry_inspection_failed",
    "evidence tree exceeds its entry limit": "evidence_entry_limit_exceeded",
    "evidence directory changed during preflight": "evidence_directory_changed",
    "evidence file changed during preflight": "evidence_file_changed",
    "evidence file failed preflight verification": "evidence_file_integrity_failed",
    "evidence entry changed during preparation": "evidence_entry_changed",
    "evidence root must be an absolute real directory": "evidence_root_invalid",
    "evidence root is unavailable": "evidence_root_unavailable",
    "evidence root is unsafe": "evidence_root_unsafe",
    "evidence root changed during preflight": "evidence_root_changed",
    "prepared evidence ownership or mode differs": "evidence_metadata_mismatch",
    "prepared evidence tree verification is incomplete": "evidence_verification_incomplete",
    "evidence preparation requires root": "evidence_preparation_requires_root",
}


class DeploymentBootstrapError(RuntimeError):
    """A deployment filesystem boundary could not be prepared safely."""


def _evidence_preparation_reason(error: Exception) -> str:
    if isinstance(error, DeploymentBootstrapError):
        return EVIDENCE_PREPARATION_REASON_BY_MESSAGE.get(
            str(error),
            "evidence_preparation_unclassified",
        )
    if isinstance(error, KeyError):
        return "evidence_identity_lookup_failed"
    return "evidence_preparation_unclassified"


@dataclass(frozen=True, slots=True)
class _EvidenceEntry:
    parts: tuple[str, ...]
    device: int
    inode: int
    is_directory: bool


def _valid_evidence_entry(parts: tuple[str, ...], *, is_directory: bool) -> bool:
    normalized = parts[1:] if parts and parts[0] == ".staging" else parts
    if parts and parts[0] == ".staging" and len(parts) == 1:
        return is_directory
    if normalized == ("sha256",):
        return is_directory
    if len(normalized) == 2:
        return (
            is_directory and normalized[0] == "sha256" and bool(SHARD_NAME.fullmatch(normalized[1]))
        )
    if len(normalized) == 3:
        return (
            not is_directory
            and normalized[0] == "sha256"
            and bool(SHARD_NAME.fullmatch(normalized[1]))
            and bool(OBJECT_NAME.fullmatch(normalized[2]))
            and normalized[2].startswith(normalized[1])
        )
    return not parts and is_directory


def _open_child(parent: int, name: str, *, directory: bool) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        return os.open(name, flags, dir_fd=parent)
    except OSError as error:
        raise DeploymentBootstrapError("evidence tree contains an unsafe entry") from error


def _scan_directory(
    descriptor: int,
    *,
    parts: tuple[str, ...],
    root_device: int,
    entries: list[_EvidenceEntry],
) -> None:
    try:
        names = sorted(os.listdir(descriptor))
    except OSError as error:
        raise DeploymentBootstrapError("evidence directory cannot be read safely") from error
    for name in names:
        if not name.isascii() or "/" in name or name in {"", ".", ".."}:
            raise DeploymentBootstrapError("evidence tree contains an unsafe name")
        child_parts = (*parts, name)
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
            raise DeploymentBootstrapError("evidence entry cannot be inspected") from error
        is_directory = stat.S_ISDIR(metadata.st_mode)
        special_mode = stat.S_IMODE(metadata.st_mode) & 0o7000
        if (
            metadata.st_dev != root_device
            or (not is_directory and not stat.S_ISREG(metadata.st_mode))
            or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1)
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or special_mode not in ({0, 0o2000} if is_directory else {0})
            or not _valid_evidence_entry(child_parts, is_directory=is_directory)
        ):
            raise DeploymentBootstrapError("evidence tree contains an unsafe entry")
        entries.append(
            _EvidenceEntry(
                parts=child_parts,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                is_directory=is_directory,
            )
        )
        if len(entries) > MAX_EVIDENCE_TREE_ENTRIES:
            raise DeploymentBootstrapError("evidence tree exceeds its entry limit")
        if is_directory:
            child = _open_child(descriptor, name, directory=True)
            try:
                opened = os.fstat(child)
                if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
                    raise DeploymentBootstrapError("evidence directory changed during preflight")
                _scan_directory(
                    child,
                    parts=child_parts,
                    root_device=root_device,
                    entries=entries,
                )
            finally:
                os.close(child)
        else:
            child = _open_child(descriptor, name, directory=False)
            try:
                opened = os.fstat(child)
                if (
                    opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                    or opened.st_size != metadata.st_size
                    or opened.st_size > DEFAULT_MAX_BYTES
                ):
                    raise DeploymentBootstrapError("evidence file changed during preflight")
                digest = sha256()
                while chunk := os.read(child, 1024 * 1024):
                    digest.update(chunk)
                final = os.fstat(child)
                if (
                    final.st_dev != metadata.st_dev
                    or final.st_ino != metadata.st_ino
                    or final.st_size != metadata.st_size
                    or final.st_mode != metadata.st_mode
                    or digest.hexdigest() != name
                ):
                    raise DeploymentBootstrapError("evidence file failed preflight verification")
            finally:
                os.close(child)


def _open_entry(root: int, entry: _EvidenceEntry) -> int:
    parent = os.dup(root)
    try:
        for index, name in enumerate(entry.parts):
            final = index == len(entry.parts) - 1
            child = _open_child(
                parent,
                name,
                directory=entry.is_directory if final else True,
            )
            os.close(parent)
            parent = child
        metadata = os.fstat(parent)
        if (
            metadata.st_dev != entry.device
            or metadata.st_ino != entry.inode
            or stat.S_ISDIR(metadata.st_mode) is not entry.is_directory
            or (not entry.is_directory and metadata.st_nlink != 1)
        ):
            raise DeploymentBootstrapError("evidence entry changed during preparation")
        return parent
    except Exception:
        os.close(parent)
        raise


def prepare_evidence_tree(
    root: Path,
    *,
    owner_uid: int,
    group_gid: int,
) -> tuple[int, int]:
    """Convert one stopped legacy evidence tree to the exact shared-read boundary."""
    root = root.absolute()
    if not root.is_absolute() or root.is_symlink():
        raise DeploymentBootstrapError("evidence root must be an absolute real directory")
    try:
        root_metadata = os.lstat(root)
    except OSError as error:
        raise DeploymentBootstrapError("evidence root is unavailable") from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root.resolve(strict=True) != root
        or stat.S_IMODE(root_metadata.st_mode) & 0o022
    ):
        raise DeploymentBootstrapError("evidence root is unsafe")
    root_descriptor = os.open(
        root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    entries: list[_EvidenceEntry] = []
    try:
        opened_root = os.fstat(root_descriptor)
        if opened_root.st_dev != root_metadata.st_dev or opened_root.st_ino != root_metadata.st_ino:
            raise DeploymentBootstrapError("evidence root changed during preflight")
        _scan_directory(
            root_descriptor,
            parts=(),
            root_device=opened_root.st_dev,
            entries=entries,
        )
        entries.append(
            _EvidenceEntry(
                parts=(),
                device=opened_root.st_dev,
                inode=opened_root.st_ino,
                is_directory=True,
            )
        )
        file_count = 0
        directory_count = 0
        for entry in sorted(entries, key=lambda value: (value.is_directory, -len(value.parts))):
            descriptor = (
                os.dup(root_descriptor) if not entry.parts else _open_entry(root_descriptor, entry)
            )
            try:
                os.fchown(descriptor, owner_uid, group_gid)
                os.fchmod(
                    descriptor,
                    EVIDENCE_DIRECTORY_MODE if entry.is_directory else EVIDENCE_FILE_MODE,
                )
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if entry.is_directory:
                directory_count += 1
            else:
                file_count += 1
        for entry in entries:
            descriptor = (
                os.dup(root_descriptor) if not entry.parts else _open_entry(root_descriptor, entry)
            )
            try:
                metadata = os.fstat(descriptor)
                expected_mode = (
                    EVIDENCE_DIRECTORY_MODE if entry.is_directory else EVIDENCE_FILE_MODE
                )
                if (
                    metadata.st_uid != owner_uid
                    or metadata.st_gid != group_gid
                    or stat.S_IMODE(metadata.st_mode) != expected_mode
                ):
                    raise DeploymentBootstrapError("prepared evidence ownership or mode differs")
            finally:
                os.close(descriptor)
    finally:
        os.close(root_descriptor)

    store = LocalImmutableEvidenceStore(
        root,
        create=False,
        allow_group_read=True,
    )
    try:
        final_count = len(store.manifest())
        pending_count = len(store.pending_manifest())
    finally:
        store.close()
    if final_count + pending_count != file_count:
        raise DeploymentBootstrapError("prepared evidence tree verification is incomplete")
    return directory_count, file_count


def runtime_preflight_main() -> int:
    """Prove one separated identity can traverse and execute this exact release."""
    try:
        prefix = Path(sys.prefix).resolve(strict=True)
        module = Path(__file__).resolve(strict=True)
        if not module.is_relative_to(prefix):
            raise DeploymentBootstrapError("runtime module is outside its environment")
    except Exception:
        sys.stderr.write("runtime_error:release_identity_preflight_failed\n")
        return 2
    sys.stdout.write("release_identity_preflight outcome=succeeded\n")
    return 0


def prepare_evidence_main() -> int:
    try:
        if os.geteuid() != 0:
            raise DeploymentBootstrapError("evidence preparation requires root")
        owner = pwd.getpwnam(EVIDENCE_OWNER).pw_uid
        group = grp.getgrnam(EVIDENCE_GROUP).gr_gid
        directories, files = prepare_evidence_tree(
            EVIDENCE_ROOT,
            owner_uid=owner,
            group_gid=group,
        )
    except Exception as error:
        reason = _evidence_preparation_reason(error)
        sys.stderr.write(f"runtime_error:evidence_preparation_failed reason={reason}\n")
        return 2
    sys.stdout.write(
        f"evidence_preparation_complete outcome=succeeded directories={directories} files={files}\n"
    )
    return 0
