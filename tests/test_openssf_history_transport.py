"""History recovery uses real shallow Git transport against a loopback bare remote."""

from __future__ import annotations

import json
import socket
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import smithguard.openssf_shadow as shadow


def _git(repository: Path, *arguments: str) -> str:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(repository),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": "Synthetic History",
        "GIT_AUTHOR_EMAIL": "history@example.test",
        "GIT_COMMITTER_NAME": "Synthetic History",
        "GIT_COMMITTER_EMAIL": "history@example.test",
        "GIT_AUTHOR_DATE": "2026-10-09T12:00:00Z",
        "GIT_COMMITTER_DATE": "2026-10-09T12:00:00Z",
    }
    return subprocess.run(
        (shadow.GIT_EXECUTABLE, "-C", str(repository), *arguments),
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        timeout=15,
    ).stdout.strip()


@dataclass
class _Remote:
    worktree: Path
    bare: Path
    url: str
    commits: list[str] = field(default_factory=list)
    network_commands: list[tuple[str, ...]] = field(default_factory=list)

    def append(self, count: int) -> None:
        for _ in range(count):
            index = len(self.commits)
            (self.worktree / "history.txt").write_text(f"synthetic commit {index}\n")
            _git(self.worktree, "add", "history.txt")
            _git(self.worktree, "commit", "--quiet", "-m", f"synthetic {index}")
            self.commits.append(_git(self.worktree, "rev-parse", "HEAD"))
        _git(self.worktree, "push", "--quiet", str(self.bare), "main")

    def fetch_arguments(self) -> list[tuple[str, ...]]:
        return [command[command.index("fetch") + 1 :] for command in self.network_commands]


@pytest.fixture
def remote(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Remote]:
    worktree = tmp_path / "upstream"
    worktree.mkdir()
    _git(worktree, "init", "--quiet", "--initial-branch=main")
    export = tmp_path / "export"
    export.mkdir()
    bare = export / "official.git"
    bare.mkdir()
    _git(bare, "init", "--quiet", "--bare", "--initial-branch=main")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    daemon = subprocess.Popen(
        (
            shadow.GIT_EXECUTABLE,
            "daemon",
            "--reuseaddr",
            "--export-all",
            f"--base-path={export}",
            "--listen=127.0.0.1",
            f"--port={port}",
            str(export),
        ),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=shadow._git_environment(tmp_path),
    )
    try:
        deadline = time.monotonic() + 5
        while True:
            if daemon.poll() is not None:
                pytest.fail("loopback Git daemon failed to start")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    pytest.fail("loopback Git daemon did not become ready")
                time.sleep(0.01)
        result = _Remote(worktree, bare, f"git://127.0.0.1:{port}/official.git")
        result.append(12)
        monkeypatch.setattr(shadow, "OPENSSF_REPOSITORY_URL", result.url)
        monkeypatch.setattr(shadow, "FETCH_DEPTH", 1)
        monkeypatch.setattr(shadow, "FETCH_DEEPEN_STEPS", (2, 3))
        # Record real subprocess arguments, delegating every operation to Git.
        # No transport result, commit presence or ancestry check is simulated.
        original_run = subprocess.run

        def record_run(command, *arguments, **kwargs):
            if "--no-replace-objects" in command and any(
                action in command for action in ("clone", "fetch")
            ):
                result.network_commands.append(tuple(command))
            return original_run(command, *arguments, **kwargs)

        monkeypatch.setattr(subprocess, "run", record_run)
        yield result
        for command in result.network_commands:
            assert "protocol.file.allow=never" in command
            assert "protocol.ext.allow=never" in command
            assert "core.hooksPath=/dev/null" in command
            assert "credential.helper=" in command
            assert "--no-replace-objects" in command
            assert result.url in command
            assert "--unshallow" not in command
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait(timeout=5)
        if daemon.stderr is not None:
            daemon.stderr.close()


def _clone(tmp_path: Path, remote: _Remote) -> shadow.ShadowPaths:
    paths = shadow._prepare_paths(tmp_path / "state")
    repository, commit = shadow.sync_official_repository(paths)
    assert repository == paths.repository
    assert commit == remote.commits[-1]
    assert _git(paths.repository, "rev-parse", "--is-shallow-repository") == "true"
    remote.network_commands.clear()
    return paths


def _checkpoint(paths: shadow.ShadowPaths, commit: str) -> bytes:
    body = json.dumps(
        {
            "commit": commit,
            "last_full_validation_at": "2026-10-09T12:00:00.000000Z",
            "manifest_path": f"manifests/{commit}.json.gz",
            "manifest_sha256": "sha256:" + "0" * 64,
            "schema_version": shadow.SCHEMA_VERSION,
            "successful_at": "2026-10-09T12:00:00.000000Z",
        }
    ).encode("ascii")
    paths.checkpoint.write_bytes(body)
    paths.checkpoint.chmod(0o600)
    return body


@pytest.mark.audit_ids("COL-04")
def test_real_transport_clones_shallow_from_bare_and_fetches_fixed_branch(
    tmp_path: Path, remote: _Remote
) -> None:
    paths = _clone(tmp_path, remote)
    assert _git(remote.bare, "rev-parse", "--is-bare-repository") == "true"
    assert not shadow._commit_present(paths.repository, remote.commits[-2])
    assert not (paths.repository / "history.txt").exists()
    remote.append(1)
    assert shadow.sync_official_repository(paths) == (paths.repository, remote.commits[-1])
    assert remote.fetch_arguments() == [
        (
            "--no-tags",
            "--prune",
            "--depth=1",
            remote.url,
            "+refs/heads/main:refs/remotes/origin/main",
        )
    ]


@pytest.mark.parametrize(("offset", "steps"), [(3, [2]), (6, [2, 3])])
@pytest.mark.audit_ids("COL-04")
def test_real_missing_commit_recovers_on_each_bounded_deepen_step(
    tmp_path: Path, remote: _Remote, offset: int, steps: list[int]
) -> None:
    paths = _clone(tmp_path, remote)
    target = remote.commits[-offset]
    assert not shadow._commit_present(paths.repository, target)
    shadow.ensure_commit_available(paths, target)
    assert shadow._commit_present(paths.repository, target)
    assert [arguments[2] for arguments in remote.fetch_arguments()] == [
        f"--deepen={step}" for step in steps
    ]


@pytest.mark.audit_ids("COL-04")
def test_real_trusted_bootstrap_exact_fetch_follows_bounded_exhaustion(
    tmp_path: Path, remote: _Remote, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _clone(tmp_path, remote)
    target = remote.commits[0]
    monkeypatch.setattr(shadow, "BOOTSTRAP_COMMIT", target)
    shadow.ensure_commit_available(paths, target, allow_bootstrap_fetch=True)
    assert shadow._commit_present(paths.repository, target)
    assert [arguments[2] for arguments in remote.fetch_arguments()[:2]] == [
        "--deepen=2",
        "--deepen=3",
    ]
    assert remote.fetch_arguments()[2:] == [("--no-tags", "--depth=1", remote.url, target)]
    assert _git(paths.repository, "rev-parse", "FETCH_HEAD") == target
    assert _git(paths.repository, "rev-parse", "refs/remotes/origin/main") == remote.commits[-1]
    assert _git(paths.repository, "rev-parse", "HEAD") == remote.commits[-1]
    assert _git(paths.repository, "rev-parse", "--is-shallow-repository") == "true"
    assert not paths.checkpoint.exists()


@pytest.mark.parametrize(
    ("trusted", "allow_bootstrap_fetch"), [(False, False), (False, True), (True, False)]
)
@pytest.mark.audit_ids("COL-04")
def test_real_exact_fetch_requires_both_trusted_commit_and_bootstrap_permission(
    tmp_path: Path,
    remote: _Remote,
    monkeypatch: pytest.MonkeyPatch,
    trusted: bool,
    allow_bootstrap_fetch: bool,
) -> None:
    paths = _clone(tmp_path, remote)
    target = remote.commits[0]
    if trusted:
        monkeypatch.setattr(shadow, "BOOTSTRAP_COMMIT", target)
    with pytest.raises(shadow.OpenSSFShadowError, match="unavailable after bounded history"):
        shadow.ensure_commit_available(paths, target, allow_bootstrap_fetch=allow_bootstrap_fetch)
    assert not shadow._commit_present(paths.repository, target)
    assert [arguments[2] for arguments in remote.fetch_arguments()] == ["--deepen=2", "--deepen=3"]
    assert not paths.checkpoint.exists()


@pytest.mark.audit_ids("COL-04")
def test_real_unavailable_trusted_commit_refuses_without_reset(
    tmp_path: Path, remote: _Remote, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git(remote.worktree, "checkout", "--quiet", "--orphan", "hidden")
    _git(remote.worktree, "commit", "--quiet", "-m", "hidden unrelated root")
    hidden = _git(remote.worktree, "rev-parse", "HEAD")
    _git(remote.worktree, "push", "--quiet", str(remote.bare), "hidden")
    assert shadow._commit_present(remote.bare, hidden)
    _git(remote.bare, "update-ref", "-d", "refs/heads/hidden")
    _git(remote.bare, "prune", "--expire=now")
    assert not shadow._commit_present(remote.bare, hidden)
    paths = _clone(tmp_path, remote)
    monkeypatch.setattr(shadow, "BOOTSTRAP_COMMIT", hidden)
    with pytest.raises(shadow.OpenSSFShadowError, match="Git retrieval was rejected"):
        shadow.ensure_commit_available(paths, hidden, allow_bootstrap_fetch=True)
    assert len(remote.fetch_arguments()) == 3
    assert remote.fetch_arguments()[-1] == ("--no-tags", "--depth=1", remote.url, hidden)
    assert not shadow._commit_present(paths.repository, hidden)
    assert _git(paths.repository, "rev-parse", "refs/remotes/origin/main") == remote.commits[-1]
    assert not paths.checkpoint.exists()


@pytest.mark.audit_ids("COL-04")
def test_real_missing_trusted_bootstrap_exact_fetch_refuses_without_reset(
    tmp_path: Path, remote: _Remote, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _clone(tmp_path, remote)
    missing = "0" * 40
    monkeypatch.setattr(shadow, "BOOTSTRAP_COMMIT", missing)
    with pytest.raises(shadow.OpenSSFShadowError, match="Git retrieval was rejected"):
        shadow.ensure_commit_available(paths, missing, allow_bootstrap_fetch=True)
    assert len(remote.fetch_arguments()) == 3
    assert remote.fetch_arguments()[-1] == ("--no-tags", "--depth=1", remote.url, missing)
    assert not shadow._commit_present(paths.repository, missing)
    assert _git(paths.repository, "rev-parse", "refs/remotes/origin/main") == remote.commits[-1]
    assert not paths.checkpoint.exists()


@pytest.mark.parametrize(("added", "steps"), [(2, [2]), (5, [2, 3])])
@pytest.mark.audit_ids("COL-04")
def test_real_forward_checkpoint_transition_recovers_on_each_deepen_step(
    tmp_path: Path, remote: _Remote, added: int, steps: list[int]
) -> None:
    paths = _clone(tmp_path, remote)
    previous = remote.commits[-1]
    checkpoint_body = _checkpoint(paths, previous)
    shadow._pin_checkpoint(paths.repository, previous)
    remote.append(added)
    assert shadow.sync_official_repository(paths) == (paths.repository, remote.commits[-1])
    assert [arguments[2] for arguments in remote.fetch_arguments()] == [
        "--depth=1",
        *(f"--deepen={step}" for step in steps),
    ]
    assert shadow._forward_transition_present(paths.repository, previous, remote.commits[-1])
    assert paths.checkpoint.read_bytes() == checkpoint_body
    assert (
        _git(paths.repository, "rev-parse", f"refs/smithguard/checkpoints/{previous}") == previous
    )


@pytest.mark.audit_ids("COL-04")
def test_real_checkpoint_gap_exhaustion_preserves_checkpoint_then_recovers_forward(
    tmp_path: Path, remote: _Remote, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _clone(tmp_path, remote)
    previous = remote.commits[-1]
    checkpoint_body = _checkpoint(paths, previous)
    shadow._pin_checkpoint(paths.repository, previous)
    # Even the trusted bootstrap identity cannot enable exact checkpoint fetches.
    monkeypatch.setattr(shadow, "BOOTSTRAP_COMMIT", previous)
    remote.append(8)
    with pytest.raises(shadow.OpenSSFShadowError, match="not a forward commit transition"):
        shadow.sync_official_repository(paths)
    assert paths.checkpoint.read_bytes() == checkpoint_body
    assert [arguments[2] for arguments in remote.fetch_arguments()] == [
        "--depth=1",
        "--deepen=2",
        "--deepen=3",
    ]
    assert not shadow._forward_transition_present(paths.repository, previous, remote.commits[-1])
    # A later reviewed bound can prove the same forward transition; no reset occurs.
    monkeypatch.setattr(shadow, "FETCH_DEEPEN_STEPS", (2, 8))
    remote.network_commands.clear()
    assert shadow.sync_official_repository(paths) == (paths.repository, remote.commits[-1])
    assert shadow._forward_transition_present(paths.repository, previous, remote.commits[-1])
    assert paths.checkpoint.read_bytes() == checkpoint_body
    assert [arguments[2] for arguments in remote.fetch_arguments()] == [
        "--depth=1",
        "--deepen=2",
        "--deepen=8",
    ]


@pytest.mark.audit_ids("COL-04")
def test_real_rewritten_branch_refuses_checkpoint_transition(
    tmp_path: Path, remote: _Remote
) -> None:
    paths = _clone(tmp_path, remote)
    previous = remote.commits[-1]
    checkpoint_body = _checkpoint(paths, previous)
    shadow._pin_checkpoint(paths.repository, previous)
    _git(remote.worktree, "checkout", "--quiet", "--orphan", "replacement")
    _git(remote.worktree, "commit", "--quiet", "-m", "unrelated root")
    replacement = _git(remote.worktree, "rev-parse", "HEAD")
    _git(remote.worktree, "push", "--quiet", "--force", str(remote.bare), "HEAD:main")
    with pytest.raises(shadow.OpenSSFShadowError, match="not a forward commit transition"):
        shadow.sync_official_repository(paths)
    assert paths.checkpoint.read_bytes() == checkpoint_body
    assert not shadow._forward_transition_present(paths.repository, previous, replacement)
    assert [arguments[2] for arguments in remote.fetch_arguments()] == [
        "--depth=1",
        "--deepen=2",
        "--deepen=3",
    ]
    assert (
        _git(paths.repository, "rev-parse", f"refs/smithguard/checkpoints/{previous}") == previous
    )


@pytest.mark.parametrize("protocol", ["file", "ext"])
@pytest.mark.audit_ids("COL-04")
def test_real_network_flags_keep_local_file_and_ext_transports_forbidden(
    tmp_path: Path, remote: _Remote, protocol: str
) -> None:
    target = str(remote.bare) if protocol == "file" else "ext::/bin/false"
    with pytest.raises(shadow.OpenSSFShadowError, match="Git retrieval was rejected"):
        shadow._network_git(tmp_path, ("ls-remote", target))


@pytest.mark.audit_ids("COL-04")
def test_real_complete_history_missing_commit_refuses_without_transport(
    tmp_path: Path, remote: _Remote, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _clone(tmp_path, remote)
    monkeypatch.setattr(shadow, "FETCH_DEEPEN_STEPS", (32,))
    shadow.ensure_commit_available(paths, remote.commits[0], allow_bootstrap_fetch=False)
    assert _git(paths.repository, "rev-parse", "--is-shallow-repository") == "false"
    remote.network_commands.clear()
    with pytest.raises(shadow.OpenSSFShadowError, match="unavailable after bounded history"):
        shadow.ensure_commit_available(paths, "0" * 40)
    assert remote.network_commands == []
