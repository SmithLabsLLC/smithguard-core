"""The OpenSSF shadow runtime stays isolated, reproducible, and fail closed."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import smithguard.openssf_shadow as shadow
from smithguard.openssf_shadow import check_health, run_shadow

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RIGHTS_REGISTER = REPOSITORY_ROOT / "contracts/v1/source-rights-register.json"
NOW = datetime(2026, 8, 16, 15, 0, tzinfo=UTC)


def _git(repository: Path, *arguments: str) -> str:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(repository),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": "Synthetic Test",
        "GIT_AUTHOR_EMAIL": "synthetic@example.test",
        "GIT_COMMITTER_NAME": "Synthetic Test",
        "GIT_COMMITTER_EMAIL": "synthetic@example.test",
        "GIT_AUTHOR_DATE": "2026-08-16T14:00:00Z",
        "GIT_COMMITTER_DATE": "2026-08-16T14:00:00Z",
    }
    completed = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        capture_output=True,
        text=True,
        encoding="ascii",
        env=environment,
    )
    return completed.stdout.strip()


def _record(
    advisory_id: str,
    *,
    ecosystem: str = "npm",
    name: str = "example",
    withdrawn: bool = False,
) -> dict[str, object]:
    document: dict[str, object] = {
        "id": advisory_id,
        "published": "2026-08-16T13:00:00Z",
        "modified": "2026-08-16T14:00:00Z",
        "aliases": [],
        "affected": [{"package": {"ecosystem": ecosystem, "name": name}}],
        "references": [],
        "database_specific": {},
    }
    if withdrawn:
        document["withdrawn"] = "2026-08-16T14:30:00Z"
    return document


def _write(repository: Path, relative: str, document: dict[str, object]) -> None:
    destination = repository / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, sort_keys=True), encoding="ascii")


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", "--all")
    _git(repository, "commit", "--quiet", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "upstream"
    repository.mkdir()
    _git(repository, "init", "--quiet", "--initial-branch=main")
    (repository / "LICENSE").write_text("Synthetic Apache License\n", encoding="ascii")
    readme = repository / "osv/malicious/README.md"
    readme.parent.mkdir(parents=True)
    readme.write_text("synthetic\n", encoding="ascii")
    _write(
        repository,
        "osv/malicious/npm/example/MAL-2026-100.json",
        _record("MAL-2026-100"),
    )
    _write(
        repository,
        "osv/malicious/pypi/project/MAL-2026-101.json",
        _record("MAL-2026-101", ecosystem="PyPI", name="project"),
    )
    _write(
        repository,
        "osv/malicious/nuget/Example/MAL-2026-102.json",
        _record("MAL-2026-102", ecosystem="NuGet", name="Example"),
    )
    return repository, _commit(repository, "initial tree")


def _license_digest(repository: Path) -> str:
    return "sha256:" + hashlib.sha256((repository / "LICENSE").read_bytes()).hexdigest()


def _fetch(repository: Path):
    def fetch(_paths: shadow.ShadowPaths) -> tuple[Path, str]:
        return repository, _git(repository, "rev-parse", "HEAD")

    return fetch


def test_kill_switch_writes_observable_receipt_without_fetching(tmp_path: Path) -> None:
    called = False

    def forbidden_fetch(_paths: shadow.ShadowPaths) -> tuple[Path, str]:
        nonlocal called
        called = True
        raise AssertionError("kill switch attempted a fetch")

    root = tmp_path / "shadow"
    receipt = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=False,
        now=lambda: NOW,
        fetcher=forbidden_fetch,
    )

    assert receipt["status"] == "disabled"
    assert receipt["network_attempted"] is False
    assert receipt["public_effect"] is False
    assert called is False
    assert not (root / "repository").exists()
    assert stat.S_IMODE((root / "latest.json").stat().st_mode) == 0o600
    assert check_health(state_root=root, enabled=False)["status"] == "disabled"


def test_rights_failure_occurs_before_any_network_attempt(tmp_path: Path) -> None:
    called = False

    def forbidden_fetch(_paths: shadow.ShadowPaths) -> tuple[Path, str]:
        nonlocal called
        called = True
        raise AssertionError("stale rights attempted a fetch")

    receipt = run_shadow(
        state_root=tmp_path / "shadow",
        rights_path=tmp_path / "missing-rights.json",
        enabled=True,
        now=lambda: NOW,
        fetcher=forbidden_fetch,
    )

    assert receipt["status"] == "failure"
    assert receipt["network_attempted"] is False
    assert called is False


def test_recognized_provisional_identity_settles_to_a_forward_stable_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _initial_commit = _repository(tmp_path)
    monkeypatch.setattr(shadow, "OPENSSF_LICENSE_SHA256", _license_digest(repository))
    provisional_path = (
        repository / "osv/malicious/npm/example/MAL-0000-amazon-inspector-0123456789abcdef.json"
    )
    _write(
        repository,
        provisional_path.relative_to(repository).as_posix(),
        _record("MAL-0000-amazon-inspector-0123456789abcdef"),
    )
    provisional_commit = _commit(repository, "provisional upstream transaction")
    provisional_path.unlink()
    _write(
        repository,
        "osv/malicious/npm/example/MAL-2026-103.json",
        _record("MAL-2026-103"),
    )
    stable_commit = _commit(repository, "stable upstream transaction")
    commits = iter((provisional_commit, stable_commit))
    fetched: list[str] = []
    waits: list[float] = []

    def fetch(_paths: shadow.ShadowPaths) -> tuple[Path, str]:
        commit = next(commits)
        fetched.append(commit)
        return repository, commit

    receipt = run_shadow(
        state_root=tmp_path / "shadow",
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW,
        fetcher=fetch,
        sleeper=waits.append,
    )

    assert receipt["status"] == "success"
    assert receipt["checkpoint"] == stable_commit
    assert receipt["provisional_observation_count"] == 1
    assert receipt["provisional_settle_wait_seconds"] == 90
    assert fetched == [provisional_commit, stable_commit]
    assert waits == [90]
    for commit in fetched:
        assert (repository / f".git/refs/smithguard/observations/{commit}").is_file()


def test_two_wait_settle_preserves_checkpoint_then_reconciles_incrementally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, accepted_commit = _repository(tmp_path)
    monkeypatch.setattr(shadow, "OPENSSF_LICENSE_SHA256", _license_digest(repository))
    root = tmp_path / "shadow"
    first = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW,
        fetcher=_fetch(repository),
    )
    assert first["status"] == "success"
    assert first["checkpoint"] == accepted_commit

    provisional_path = (
        repository / "osv/malicious/npm/example/MAL-0000-amazon-inspector-0123456789abcdef.json"
    )
    _write(
        repository,
        provisional_path.relative_to(repository).as_posix(),
        _record("MAL-0000-amazon-inspector-0123456789abcdef"),
    )
    provisional_commit = _commit(repository, "provisional incremental transaction")
    provisional_path.unlink()
    _write(
        repository,
        "osv/malicious/npm/added/MAL-2026-103.json",
        _record("MAL-2026-103", name="added"),
    )
    stable_commit = _commit(repository, "stable incremental transaction")
    commits = iter((provisional_commit, provisional_commit, stable_commit))
    waits: list[float] = []

    def fetch(_paths: shadow.ShadowPaths) -> tuple[Path, str]:
        return repository, next(commits)

    def wait(seconds: float) -> None:
        waits.append(seconds)
        checkpoint = json.loads((root / "checkpoint.json").read_text(encoding="ascii"))
        assert checkpoint["commit"] == accepted_commit

    settled = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW + timedelta(hours=1),
        fetcher=fetch,
        sleeper=wait,
    )

    assert settled["status"] == "success"
    assert settled["previous_checkpoint"] == accepted_commit
    assert settled["checkpoint"] == stable_commit
    assert settled["validation_scope"] == "incremental"
    assert settled["transition"]["added"] == 1
    assert settled["provisional_observation_count"] == 2
    assert settled["provisional_settle_wait_seconds"] == 180
    assert waits == [90, 90]
    checkpoint = json.loads((root / "checkpoint.json").read_text(encoding="ascii"))
    assert checkpoint["commit"] == stable_commit


def test_provisional_settle_exhaustion_fails_closed_without_a_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _initial_commit = _repository(tmp_path)
    monkeypatch.setattr(shadow, "OPENSSF_LICENSE_SHA256", _license_digest(repository))
    _write(
        repository,
        "osv/malicious/pypi/project/MAL-0000-amazon-inspector-0123456789abcdef.json",
        _record(
            "MAL-0000-amazon-inspector-0123456789abcdef",
            ecosystem="PyPI",
            name="project",
        ),
    )
    provisional_commit = _commit(repository, "persistent provisional upstream transaction")
    fetched: list[str] = []
    waits: list[float] = []

    def fetch(_paths: shadow.ShadowPaths) -> tuple[Path, str]:
        fetched.append(provisional_commit)
        return repository, provisional_commit

    root = tmp_path / "shadow"
    receipt = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW,
        fetcher=fetch,
        sleeper=waits.append,
    )

    assert receipt["status"] == "failure"
    assert receipt["error_class"] == "OpenSSFProvisionalIDError"
    assert "after 3 bounded observations" in receipt["error_message"]
    assert receipt["provisional_observation_count"] == 3
    assert receipt["provisional_settle_wait_seconds"] == 180
    assert fetched == [provisional_commit] * 3
    assert waits == [90, 90]
    assert not (root / "checkpoint.json").exists()
    assert (repository / f".git/refs/smithguard/observations/{provisional_commit}").is_file()


def test_unrecognized_tree_shape_error_does_not_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _initial_commit = _repository(tmp_path)
    monkeypatch.setattr(shadow, "OPENSSF_LICENSE_SHA256", _license_digest(repository))
    _write(
        repository,
        "osv/malicious/npm/example/MAL-0000-!unreviewed.json",
        _record("MAL-0000-!unreviewed"),
    )
    malformed_commit = _commit(repository, "unrecognized tree shape")
    fetched: list[str] = []
    waits: list[float] = []

    def fetch(_paths: shadow.ShadowPaths) -> tuple[Path, str]:
        fetched.append(malformed_commit)
        return repository, malformed_commit

    receipt = run_shadow(
        state_root=tmp_path / "shadow",
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW,
        fetcher=fetch,
        sleeper=waits.append,
    )

    assert receipt["status"] == "failure"
    assert receipt["error_class"] == "OpenSSFGitError"
    assert receipt["provisional_observation_count"] == 0
    assert receipt["provisional_settle_wait_seconds"] == 0
    assert fetched == [malformed_commit]
    assert waits == []


def test_provisional_settle_rejects_non_forward_retry_and_pins_both_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _initial_commit = _repository(tmp_path)
    monkeypatch.setattr(shadow, "OPENSSF_LICENSE_SHA256", _license_digest(repository))
    provisional_relative = (
        "osv/malicious/npm/example/MAL-0000-amazon-inspector-0123456789abcdef.json"
    )
    _write(repository, provisional_relative, _record("MAL-0000-amazon-inspector-a"))
    first_commit = _commit(repository, "first provisional history")
    _git(repository, "checkout", "--quiet", "--orphan", "rewritten")
    _write(repository, provisional_relative, _record("MAL-0000-amazon-inspector-b"))
    second_commit = _commit(repository, "rewritten provisional history")
    commits = iter((first_commit, second_commit))
    waits: list[float] = []

    def fetch(_paths: shadow.ShadowPaths) -> tuple[Path, str]:
        return repository, next(commits)

    receipt = run_shadow(
        state_root=tmp_path / "shadow",
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW,
        fetcher=fetch,
        sleeper=waits.append,
    )

    assert receipt["status"] == "failure"
    assert "not a forward commit transition" in receipt["error_message"]
    assert receipt["provisional_observation_count"] == 1
    assert receipt["provisional_settle_wait_seconds"] == 90
    assert waits == [90]
    for commit in (first_commit, second_commit):
        assert (repository / f".git/refs/smithguard/observations/{commit}").is_file()


def test_existing_mirror_fetch_uses_only_the_fixed_official_https_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, commit = _repository(tmp_path)
    root = tmp_path / "shadow"
    paths = shadow._prepare_paths(root)
    repository.rename(paths.repository)
    _git(paths.repository, "update-ref", "refs/remotes/origin/main", commit)
    calls: list[tuple[str, ...]] = []

    def observe(_home: Path, arguments: tuple[str, ...]) -> bytes:
        calls.append(arguments)
        return b""

    monkeypatch.setattr(shadow, "_network_git", observe)
    selected_repository, selected_commit = shadow.sync_official_repository(paths)

    assert selected_repository == paths.repository
    assert selected_commit == commit
    assert calls == [
        (
            "-C",
            str(paths.repository),
            "fetch",
            "--no-tags",
            "--prune",
            f"--depth={shadow.FETCH_DEPTH}",
            shadow.OPENSSF_REPOSITORY_URL,
            "+refs/heads/main:refs/remotes/origin/main",
        )
    ]
    assert shadow.OPENSSF_REPOSITORY_URL == "https://github.com/ossf/malicious-packages"


def test_initial_clone_uses_only_the_fixed_official_https_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, commit = _repository(tmp_path)
    paths = shadow._prepare_paths(tmp_path / "shadow")
    calls: list[tuple[str, ...]] = []

    def observe(_home: Path, arguments: tuple[str, ...]) -> bytes:
        calls.append(arguments)
        destination = Path(arguments[-1])
        shutil.copytree(repository, destination)
        _git(destination, "update-ref", "refs/remotes/origin/main", commit)
        return b""

    monkeypatch.setattr(shadow, "_network_git", observe)
    selected_repository, selected_commit = shadow.sync_official_repository(paths)

    assert selected_repository == paths.repository
    assert selected_commit == commit
    assert calls == [
        (
            "clone",
            "--no-checkout",
            f"--depth={shadow.FETCH_DEPTH}",
            "--single-branch",
            "--branch",
            "main",
            "--no-tags",
            shadow.OPENSSF_REPOSITORY_URL,
            calls[0][-1],
        )
    ]


def test_shallow_gap_uses_only_bounded_official_deepen_fetches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, first_commit = _repository(tmp_path)
    _write(
        repository,
        "osv/malicious/npm/second/MAL-2026-103.json",
        _record("MAL-2026-103", name="second"),
    )
    current_commit = _commit(repository, "second tree")
    paths = shadow._prepare_paths(tmp_path / "shadow")
    repository.rename(paths.repository)
    _git(paths.repository, "update-ref", "refs/remotes/origin/main", current_commit)
    paths.checkpoint.write_text(
        json.dumps(
            {
                "commit": first_commit,
                "last_full_validation_at": "2026-08-16T14:00:00.000000Z",
                "manifest_path": f"manifests/{first_commit}.json.gz",
                "manifest_sha256": "sha256:" + "0" * 64,
                "schema_version": shadow.SCHEMA_VERSION,
                "successful_at": "2026-08-16T14:00:00.000000Z",
            }
        ),
        encoding="ascii",
    )
    paths.checkpoint.chmod(0o600)
    calls: list[tuple[str, ...]] = []
    transition_results = iter((False, False, True))
    original_local_git = shadow._local_git

    def observe(_home: Path, arguments: tuple[str, ...]) -> bytes:
        calls.append(arguments)
        return b""

    def local_git(repository_path: Path, *arguments: str, maximum: int = 512) -> str:
        if arguments == ("rev-parse", "--is-shallow-repository"):
            return "true"
        return original_local_git(repository_path, *arguments, maximum=maximum)

    monkeypatch.setattr(shadow, "_network_git", observe)
    monkeypatch.setattr(shadow, "_local_git", local_git)
    monkeypatch.setattr(
        shadow,
        "_forward_transition_present",
        lambda *_arguments: next(transition_results),
    )

    selected_repository, selected_commit = shadow.sync_official_repository(paths)

    assert selected_repository == paths.repository
    assert selected_commit == current_commit
    assert [call[5] for call in calls[1:]] == [
        f"--deepen={shadow.FETCH_DEEPEN_STEPS[0]}",
        f"--deepen={shadow.FETCH_DEEPEN_STEPS[1]}",
    ]
    assert all(call[6] == shadow.OPENSSF_REPOSITORY_URL for call in calls[1:])


def test_full_initial_and_incremental_runs_reconcile_without_public_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, first_commit = _repository(tmp_path)
    monkeypatch.setattr(shadow, "OPENSSF_LICENSE_SHA256", _license_digest(repository))
    root = tmp_path / "shadow"

    initial = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW,
        fetcher=_fetch(repository),
    )
    assert initial["status"] == "success"
    assert initial["checkpoint"] == first_commit
    assert initial["validation_scope"] == "full_initial"
    assert initial["validated_count"] == initial["accepted_count"] == 2
    assert initial["quarantined_count"] == 0
    assert initial["unsupported_ecosystem_counts"] == {"nuget": 1}
    assert initial["raw_count"] == 4
    assert initial["public_effect"] is False
    assert initial["full_tree_reconciliation"] == "passed"

    modified = _record("MAL-2026-100", name="example")
    modified["modified"] = "2026-08-16T14:10:00Z"
    _write(
        repository,
        "osv/malicious/npm/example/MAL-2026-100.json",
        modified,
    )
    active = repository / "osv/malicious/pypi/project/MAL-2026-101.json"
    active.unlink()
    _write(
        repository,
        "osv/withdrawn/pypi/project/MAL-2026-101.json",
        _record("MAL-2026-101", ecosystem="PyPI", name="project", withdrawn=True),
    )
    second_commit = _commit(repository, "modify and withdraw")
    later = NOW + timedelta(hours=1)
    incremental = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: later,
        fetcher=_fetch(repository),
    )

    assert incremental["status"] == "success"
    assert incremental["checkpoint"] == second_commit
    assert incremental["previous_checkpoint"] == first_commit
    assert incremental["validation_scope"] == "incremental"
    assert incremental["transition"]["modified"] == 1
    assert incremental["transition"]["withdrawn"] == 1
    assert incremental["current_withdrawal_count"] == 1
    assert incremental["validated_count"] == 2
    assert incremental["accepted_count"] == 2
    assert incremental["full_tree_reconciliation"] == "passed"
    checkpoint = json.loads((root / "checkpoint.json").read_text(encoding="ascii"))
    assert checkpoint["commit"] == second_commit
    assert (repository / f".git/refs/smithguard/checkpoints/{first_commit}").is_file()
    assert (repository / f".git/refs/smithguard/checkpoints/{second_commit}").is_file()


def test_unchanged_and_periodic_full_validation_scopes_are_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _commit_id = _repository(tmp_path)
    monkeypatch.setattr(shadow, "OPENSSF_LICENSE_SHA256", _license_digest(repository))
    root = tmp_path / "shadow"
    assert (
        run_shadow(
            state_root=root,
            rights_path=RIGHTS_REGISTER,
            enabled=True,
            now=lambda: NOW,
            fetcher=_fetch(repository),
        )["validation_scope"]
        == "full_initial"
    )

    unchanged = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW + timedelta(hours=1),
        fetcher=_fetch(repository),
    )
    periodic = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW + timedelta(hours=25),
        fetcher=_fetch(repository),
    )

    assert unchanged["validation_scope"] == "unchanged"
    assert unchanged["validated_count"] == 0
    assert periodic["validation_scope"] == "full_periodic"
    assert periodic["validated_count"] == periodic["supported_count"] == 2


def test_removal_only_transition_is_not_labeled_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _commit_id = _repository(tmp_path)
    monkeypatch.setattr(shadow, "OPENSSF_LICENSE_SHA256", _license_digest(repository))
    root = tmp_path / "shadow"
    run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW,
        fetcher=_fetch(repository),
    )
    (repository / "osv/malicious/pypi/project/MAL-2026-101.json").unlink()
    removed_commit = _commit(repository, "remove one record")

    removed = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW + timedelta(hours=1),
        fetcher=_fetch(repository),
    )

    assert removed["status"] == "success"
    assert removed["checkpoint"] == removed_commit
    assert removed["validation_scope"] == "incremental_removals_only"
    assert removed["validated_count"] == 0
    assert removed["transition"]["removed"] == 1


def test_malformed_supported_record_is_quarantined_and_does_not_advance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _commit_id = _repository(tmp_path)
    monkeypatch.setattr(shadow, "OPENSSF_LICENSE_SHA256", _license_digest(repository))
    _write(
        repository,
        "osv/malicious/npm/example/MAL-2026-100.json",
        _record("MAL-2026-999"),
    )
    observed = _commit(repository, "malformed identity")
    root = tmp_path / "shadow"

    receipt = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW,
        fetcher=_fetch(repository),
    )

    assert receipt["status"] == "quarantined"
    assert receipt["checkpoint"] == observed
    assert receipt["quarantined_count"] == 1
    assert receipt["accepted_count"] == 1
    assert receipt["quarantine_samples"][0]["advisory_id"] == "MAL-2026-100"
    assert "identities differ" in receipt["quarantine_samples"][0]["error"]
    assert not (root / "checkpoint.json").exists()
    assert (repository / f".git/refs/smithguard/observations/{observed}").is_file()


def test_rewritten_history_fails_without_replacing_last_good_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, accepted_commit = _repository(tmp_path)
    monkeypatch.setattr(shadow, "OPENSSF_LICENSE_SHA256", _license_digest(repository))
    root = tmp_path / "shadow"
    first = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW,
        fetcher=_fetch(repository),
    )
    assert first["status"] == "success"

    _git(repository, "checkout", "--quiet", "--orphan", "rewritten")
    (repository / "LICENSE").write_text("Synthetic Apache License\n", encoding="ascii")
    _write(
        repository,
        "osv/malicious/npm/rewrite/MAL-2026-200.json",
        _record("MAL-2026-200", name="rewrite"),
    )
    rewritten_commit = _commit(repository, "rewritten history")
    failure = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW + timedelta(hours=1),
        fetcher=_fetch(repository),
    )

    assert rewritten_commit != accepted_commit
    assert failure["status"] == "failure"
    assert "not a forward" in failure["error_message"]
    assert (repository / f".git/refs/smithguard/observations/{rewritten_commit}").is_file()
    checkpoint = json.loads((root / "checkpoint.json").read_text(encoding="ascii"))
    assert checkpoint["commit"] == accepted_commit


def test_oversized_change_set_fails_without_replacing_last_good_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, accepted_commit = _repository(tmp_path)
    monkeypatch.setattr(shadow, "OPENSSF_LICENSE_SHA256", _license_digest(repository))
    root = tmp_path / "shadow"
    first = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW,
        fetcher=_fetch(repository),
    )
    assert first["status"] == "success"

    _write(
        repository,
        "osv/malicious/npm/added/MAL-2026-103.json",
        _record("MAL-2026-103", name="added"),
    )
    observed_commit = _commit(repository, "oversized synthetic transition")

    def reject_oversized_change(*_args, **_kwargs):
        raise shadow.OpenSSFGitError("OpenSSF change limit exceeds its reviewed boundary")

    monkeypatch.setattr(shadow.LocalOpenSSFGitRepository, "diff", reject_oversized_change)
    failure = run_shadow(
        state_root=root,
        rights_path=RIGHTS_REGISTER,
        enabled=True,
        now=lambda: NOW + timedelta(hours=1),
        fetcher=_fetch(repository),
    )

    assert failure["status"] == "failure"
    assert "change limit" in failure["error_message"]
    assert (repository / f".git/refs/smithguard/observations/{observed_commit}").is_file()
    checkpoint = json.loads((root / "checkpoint.json").read_text(encoding="ascii"))
    assert checkpoint["commit"] == accepted_commit


def test_health_fails_closed_for_stale_or_tampered_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _commit_id = _repository(tmp_path)
    monkeypatch.setattr(shadow, "OPENSSF_LICENSE_SHA256", _license_digest(repository))
    root = tmp_path / "shadow"
    assert (
        run_shadow(
            state_root=root,
            rights_path=RIGHTS_REGISTER,
            enabled=True,
            now=lambda: NOW,
            fetcher=_fetch(repository),
        )["status"]
        == "success"
    )

    healthy = check_health(state_root=root, enabled=True, now=NOW + timedelta(hours=2))
    stale = check_health(state_root=root, enabled=True, now=NOW + timedelta(hours=4))
    assert healthy["status"] == "healthy"
    assert stale["status"] == "critical"

    (root / "latest.json").chmod(0o644)
    unsafe = check_health(state_root=root, enabled=True, now=NOW)
    assert unsafe["status"] == "critical"
    assert "unsafe boundary" in unsafe["error"]


def test_cli_requires_an_explicit_boolean_kill_switch() -> None:
    with pytest.raises(shadow.OpenSSFShadowError, match="exactly 0 or 1"):
        shadow._enabled_from_environment({})
    with pytest.raises(shadow.OpenSSFShadowError, match="exactly 0 or 1"):
        shadow._enabled_from_environment({shadow.ENABLED_VARIABLE: "true"})
    assert shadow._enabled_from_environment({shadow.ENABLED_VARIABLE: "0"}) is False
    assert shadow._enabled_from_environment({shadow.ENABLED_VARIABLE: "1"}) is True


def test_default_rights_path_matches_the_closed_release_layout() -> None:
    environment = (REPOSITORY_ROOT / "deploy/env/openssf-shadow.env.example").read_text(
        encoding="ascii"
    )
    health_environment = (REPOSITORY_ROOT / "deploy/env/health.env.example").read_text(
        encoding="ascii"
    )
    expected = "/opt/SmithGuard/current/contracts/v1/source-rights-register.json"

    assert Path(expected) == shadow.DEFAULT_RIGHTS_REGISTER
    assert f"SMITHGUARD_RIGHTS_REGISTER_PATH={expected}" in environment
    assert f"SMITHGUARD_RIGHTS_REGISTER_PATH={expected}" in health_environment


def test_cumulative_state_and_filesystem_capacity_fail_closed(tmp_path: Path) -> None:
    root = shadow._prepare_paths(tmp_path / "shadow").root
    # Limits no real filesystem can meet, so parallel tests changing free space between
    # measurement and check cannot make this flaky.
    with pytest.raises(shadow.OpenSSFShadowError, match="insufficient"):
        shadow.require_state_capacity(
            root,
            limits=shadow.ShadowCapacityLimits(
                maximum_state_apparent_bytes=shadow.MAX_STATE_APPARENT_BYTES,
                minimum_filesystem_available_bytes=2**62,
                maximum_filesystem_used_percent=100,
            ),
        )
    with pytest.raises(shadow.OpenSSFShadowError, match="filesystem use"):
        shadow.require_state_capacity(
            root,
            limits=shadow.ShadowCapacityLimits(
                maximum_state_apparent_bytes=shadow.MAX_STATE_APPARENT_BYTES,
                minimum_filesystem_available_bytes=0,
                maximum_filesystem_used_percent=0,
            ),
        )

    oversized = root / "oversized-state"
    with oversized.open("wb") as stream:
        stream.truncate(shadow.MAX_STATE_APPARENT_BYTES + 1)
    oversized.chmod(0o600)
    with pytest.raises(shadow.OpenSSFShadowError, match="cumulative capacity"):
        shadow.measure_state_capacity(root)


def test_run_rechecks_capacity_after_writing_its_receipt(tmp_path: Path) -> None:
    paths = shadow._prepare_paths(tmp_path / "shadow")
    paths.lock.write_bytes(b"")
    paths.lock.chmod(0o600)
    root = paths.root
    before = shadow.measure_state_capacity(root)
    limits = shadow.ShadowCapacityLimits(
        maximum_state_apparent_bytes=before.state_apparent_bytes + 1,
        minimum_filesystem_available_bytes=0,
        maximum_filesystem_used_percent=100,
    )

    with pytest.raises(shadow.OpenSSFShadowError, match="cumulative capacity"):
        shadow.run_shadow(
            state_root=root,
            rights_path=tmp_path / "unused-rights.json",
            enabled=False,
            capacity_limits=limits,
        )


def test_non_secret_monitor_receipt_is_group_readable_and_bounded(tmp_path: Path) -> None:
    root = shadow._prepare_paths(tmp_path / "shadow").root
    monitor_root = tmp_path / "monitor"
    monitor_root.mkdir(mode=0o750)
    monitor_root.chmod(0o2750)
    path = monitor_root / "latest.json"

    shadow._write_monitor_receipt(
        path,
        {
            "checkpoint": "a" * 40,
            "completed_at": "2026-08-16T15:00:00.000000Z",
            "status": "success",
        },
        state_root=root,
    )
    document = json.loads(path.read_text(encoding="ascii"))
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert document["healthy"] is True
    assert document["checkpoint"] == "a" * 40
    assert document["state_apparent_bytes"] > 0
    assert document["filesystem_available_bytes"] > 0


def test_capacity_breach_still_writes_an_unhealthy_monitor_receipt(tmp_path: Path) -> None:
    root = shadow._prepare_paths(tmp_path / "shadow").root
    oversized = root / "oversized-state"
    with oversized.open("wb") as stream:
        stream.truncate(shadow.MAX_STATE_APPARENT_BYTES + 1)
    oversized.chmod(0o600)
    monitor_root = tmp_path / "monitor"
    monitor_root.mkdir(mode=0o750)
    monitor_root.chmod(0o2750)
    path = monitor_root / "latest.json"

    shadow._write_monitor_receipt(
        path,
        {"status": "success"},
        state_root=root,
    )

    document = json.loads(path.read_text(encoding="ascii"))
    assert document["healthy"] is False
    assert document["status"] == "failure"
    assert document["state_apparent_bytes"] == shadow.MAX_STATE_APPARENT_BYTES


def _monitor_root(tmp_path: Path) -> Path:
    monitor_root = tmp_path / "monitor"
    monitor_root.mkdir(mode=0o750)
    monitor_root.chmod(0o2750)
    return monitor_root


def test_disabled_lane_with_a_monitor_path_writes_its_receipt_and_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monitor = _monitor_root(tmp_path) / "latest.json"
    monkeypatch.setenv(shadow.ENABLED_VARIABLE, "0")
    monkeypatch.setenv("SMITHGUARD_OPENSSF_STATE_ROOT", str(tmp_path / "never-created"))
    monkeypatch.setenv(shadow.MONITOR_RECEIPT_VARIABLE, str(monitor))

    assert shadow.main(["--check-health"]) == 0

    printed = json.loads(capsys.readouterr().out)
    assert printed["status"] == "disabled" and "monitor_receipt_error" not in printed
    document = json.loads(monitor.read_text(encoding="ascii"))
    assert document["status"] == "disabled"
    assert document["state_entry_count"] == 0 and document["state_apparent_bytes"] == 0
    assert isinstance(document["filesystem_available_bytes"], int)
    assert not (tmp_path / "never-created").exists()


def test_monitor_receipt_failure_is_reported_beside_a_successful_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    state_root = shadow._prepare_paths(tmp_path / "shadow").root
    monkeypatch.setenv(shadow.ENABLED_VARIABLE, "1")
    monkeypatch.setenv("SMITHGUARD_OPENSSF_STATE_ROOT", str(state_root))
    monkeypatch.setenv(shadow.MONITOR_RECEIPT_VARIABLE, str(tmp_path / "missing-parent/x.json"))
    monkeypatch.setattr(
        shadow,
        "run_shadow",
        lambda **_kwargs: {"status": "success", "healthy": True, "checkpoint": "c" * 40},
    )

    assert shadow.main([]) == 1

    printed = json.loads(capsys.readouterr().out)
    # The durable run outcome is preserved; the monitor write problem is a separate field.
    assert printed["status"] == "success" and printed["checkpoint"] == "c" * 40
    assert printed["monitor_receipt_error"] == "OpenSSF monitor receipt parent is unavailable"


def test_ensure_commit_available_skips_the_network_when_the_commit_is_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, commit = _repository(tmp_path)
    paths = shadow._prepare_paths(tmp_path / "shadow")
    repository.rename(paths.repository)
    monkeypatch.setattr(
        shadow, "_network_git", lambda *_a: pytest.fail("no fetch when the commit resolves")
    )
    shadow.ensure_commit_available(paths, commit)


def test_ensure_commit_available_deepens_in_bounded_steps_until_the_commit_resolves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _commit_value = _repository(tmp_path)
    paths = shadow._prepare_paths(tmp_path / "shadow")
    repository.rename(paths.repository)
    calls: list[tuple[str, ...]] = []
    presence = iter((False, False, True))
    original_local_git = shadow._local_git

    def observe(_home: Path, arguments: tuple[str, ...]) -> bytes:
        calls.append(arguments)
        return b""

    def local_git(repository_path: Path, *arguments: str, maximum: int = 512) -> str:
        if arguments == ("rev-parse", "--is-shallow-repository"):
            return "true"
        return original_local_git(repository_path, *arguments, maximum=maximum)

    monkeypatch.setattr(shadow, "_network_git", observe)
    monkeypatch.setattr(shadow, "_local_git", local_git)
    monkeypatch.setattr(shadow, "_commit_present", lambda *_a: next(presence))

    shadow.ensure_commit_available(paths, "7" * 40)

    assert [call[5] for call in calls] == [
        f"--deepen={shadow.FETCH_DEEPEN_STEPS[0]}",
        f"--deepen={shadow.FETCH_DEEPEN_STEPS[1]}",
    ]
    assert all(call[6] == shadow.OPENSSF_REPOSITORY_URL for call in calls)


def test_ensure_commit_available_refuses_once_history_is_complete_without_the_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _commit_value = _repository(tmp_path)
    paths = shadow._prepare_paths(tmp_path / "shadow")
    repository.rename(paths.repository)
    monkeypatch.setattr(
        shadow, "_network_git", lambda *_a: pytest.fail("a complete repository is not deepened")
    )
    # The fixture repository is not shallow, so no deepen step is attempted.
    with pytest.raises(shadow.OpenSSFShadowError, match="unavailable after bounded history"):
        shadow.ensure_commit_available(paths, "7" * 40)


def test_ensure_commit_available_rejects_an_invalid_commit_before_any_git_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = shadow._prepare_paths(tmp_path / "shadow")
    with pytest.raises(shadow.OpenSSFShadowError, match="commit is invalid"):
        shadow.ensure_commit_available(paths, "not-a-commit")
