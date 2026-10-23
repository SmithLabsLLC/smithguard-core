"""Deployment bootstrap converts only one verified immutable evidence tree."""

from __future__ import annotations

import ast
import inspect
import os
import stat
from pathlib import Path

import pytest

from smithguard import deployment_bootstrap
from smithguard.deployment_bootstrap import (
    DeploymentBootstrapError,
    prepare_evidence_main,
    prepare_evidence_tree,
)
from smithguard.evidence import LocalImmutableEvidenceStore


def _legacy_tree(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "evidence"
    store = LocalImmutableEvidenceStore(root, allow_group_read=True)
    try:
        blob = store.put_bytes(b"synthetic legacy immutable evidence")
    finally:
        store.close()
    for directory, _names, files in os.walk(root):
        current = Path(directory)
        current.chmod(0o750)
        for name in files:
            (current / name).chmod(0o640)
    return root, blob.digest


def test_evidence_preparation_applies_exact_modes_and_reverifies_content(
    tmp_path: Path,
) -> None:
    root, digest = _legacy_tree(tmp_path)
    directory_count, file_count = prepare_evidence_tree(
        root,
        owner_uid=os.geteuid(),
        group_gid=os.getegid(),
    )
    assert directory_count == sum(1 for _directory, _names, _files in os.walk(root))
    assert file_count == 1
    for directory, _names, files in os.walk(root):
        current = Path(directory)
        metadata = current.stat()
        assert metadata.st_uid == os.geteuid()
        assert metadata.st_gid == os.getegid()
        assert stat.S_IMODE(metadata.st_mode) == 0o2750
        for name in files:
            file_metadata = (current / name).stat()
            assert file_metadata.st_uid == os.geteuid()
            assert file_metadata.st_gid == os.getegid()
            assert stat.S_IMODE(file_metadata.st_mode) == 0o440
    verified = LocalImmutableEvidenceStore(
        root,
        create=False,
        allow_group_read=True,
    )
    try:
        assert verified.read_bytes(digest) == b"synthetic legacy immutable evidence"
        assert verified.pending_manifest() == []
    finally:
        verified.close()


@pytest.mark.parametrize(
    "unsafe_kind",
    ("symbolic_link", "hard_link", "special_file", "digest_mismatch"),
)
def test_evidence_preparation_rejects_the_entire_tree_before_changing_it(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    root, digest = _legacy_tree(tmp_path)
    hexadecimal = digest.removeprefix("sha256:")
    original = root / "sha256" / hexadecimal[:2] / hexadecimal
    if unsafe_kind == "symbolic_link":
        (root / "unexpected").symlink_to(tmp_path)
    elif unsafe_kind == "hard_link":
        os.link(original, root / "unexpected")
    elif unsafe_kind == "special_file":
        os.mkfifo(root / "unexpected", mode=0o600)
    else:
        original.write_bytes(b"synthetic changed immutable evidence")
        original.chmod(0o640)

    with pytest.raises(DeploymentBootstrapError, match="unsafe|preflight"):
        prepare_evidence_tree(
            root,
            owner_uid=os.geteuid(),
            group_gid=os.getegid(),
        )

    assert stat.S_IMODE(root.stat().st_mode) == 0o750
    assert stat.S_IMODE(original.stat().st_mode) == 0o640


def test_evidence_preparation_cli_reports_only_an_allowlisted_failure_category(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        "smithguard.deployment_bootstrap.os.geteuid",
        lambda: 0,
    )
    monkeypatch.setattr(
        "smithguard.deployment_bootstrap.pwd.getpwnam",
        lambda _name: type("Owner", (), {"pw_uid": 1001})(),
    )
    monkeypatch.setattr(
        "smithguard.deployment_bootstrap.grp.getgrnam",
        lambda _name: type("Group", (), {"gr_gid": 1002})(),
    )
    monkeypatch.setattr(
        "smithguard.deployment_bootstrap.prepare_evidence_tree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            DeploymentBootstrapError("evidence tree contains an unsafe entry")
        ),
    )
    assert prepare_evidence_main() == 2
    assert capsys.readouterr().err == (
        "runtime_error:evidence_preparation_failed reason=evidence_tree_unsafe_entry\n"
    )


def test_every_evidence_preparation_error_has_a_reason_code() -> None:
    """Reasons are looked up by message, so a reworded message must fail here rather
    than silently become ``evidence_preparation_unclassified``."""
    tree = ast.parse(inspect.getsource(deployment_bootstrap))
    runtime = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "runtime_preflight_main"
    )
    runtime_raises = {id(node) for node in ast.walk(runtime)}
    messages = [
        node.exc.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Raise)
        and id(node) not in runtime_raises
        and isinstance(node.exc, ast.Call)
        and getattr(node.exc.func, "id", None) == "DeploymentBootstrapError"
    ]
    assert len(messages) >= 17
    reasons = deployment_bootstrap.EVIDENCE_PREPARATION_REASON_BY_MESSAGE
    assert [message for message in messages if message not in reasons] == []
