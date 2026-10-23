"""Publication authority is checked on disk, release and time before each use."""

import os
from copy import deepcopy

import pytest

from smithguard import bulletin_policy as policy
from smithguard.bulletin_contract import BulletinError
from smithguard.identifiers import sha256_id
from tests.test_bulletins import GRANT, NOW


@pytest.fixture
def grant_files(tmp_path, monkeypatch):
    directory = tmp_path / "policies"
    directory.mkdir(mode=0o755)
    register = tmp_path / "register.json"
    register.write_text("synthetic public rights bytes")
    path = directory / "bulletins.json"
    grant = {**deepcopy(GRANT), "rights_register_hash": sha256_id(register.read_bytes())}
    path.write_bytes(policy.grant_bytes(grant))
    path.chmod(0o644)
    monkeypatch.setattr(policy, "CONTROL_DIRECTORY", directory)
    monkeypatch.setattr(policy, "CONTROL_PATH", path)
    monkeypatch.setattr(policy, "CONTROL_UID", os.getuid())
    return path, register, grant


@pytest.mark.parametrize(
    "fault",
    [
        "release",
        "registry",
        "expired",
        "future",
        "mode",
        "directory",
        "symlink",
        "hardlink",
        "closed",
    ],
)
def test_grant_cannot_survive_binding_damage_or_expiry(grant_files, fault):
    path, register, grant = grant_files
    release = "a" * 40
    assert policy.read_grant(release=release, registry_path=register, now=NOW) == grant
    if fault == "release":
        release = "b" * 40
    elif fault == "registry":
        register.write_text("changed rights")
    elif fault == "expired":
        grant["review_due_at"] = "2026-10-21T12:00:00Z"
        path.write_bytes(policy.grant_bytes(grant))
    elif fault == "future":
        grant["effective_at"] = "2026-10-21T13:00:00Z"
        path.write_bytes(policy.grant_bytes(grant))
    elif fault == "mode":
        path.chmod(0o666)
    elif fault == "directory":
        path.parent.chmod(0o777)
    elif fault == "symlink":
        target = path.with_suffix(".target")
        path.rename(target)
        path.symlink_to(target)
    elif fault == "hardlink":
        os.link(path, path.with_suffix(".link"))
    else:
        path.write_text('{"schema_version":1,"mode":"paused"}')
    with pytest.raises((BulletinError, OSError)):
        policy.read_grant(release=release, registry_path=register, now=NOW)
