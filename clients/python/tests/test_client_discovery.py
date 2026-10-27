import json
import os

import pytest

from smithguard_client.discovery import artifact, discover, open_directory


def package(scope, name="pip", version="25.2", extra="", folder=None):
    path = scope / (folder or f"{name}-{version}.dist-info")
    path.mkdir()
    (path / "METADATA").write_text(
        f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n{extra}\n"
    )
    return path


def test_explicit_preview_no_network_deduplicates_preserves_installations(tmp_path, monkeypatch):
    import socket

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: pytest.fail("network in preview"))
    scopes = [tmp_path / "active-unknown", tmp_path / "old-unknown"]
    for s in scopes:
        s.mkdir()
        package(s)
    result = discover([str(s) for s in scopes], approved_public=[artifact("pip", "25.2")])
    assert len(result["coordinates"]) == 1 and len(result["installations"]) == 2
    assert all(x["activity"] == "unknown" for x in result["installations"])
    assert all(
        x["identity_assurance"] == "unverified_local_metadata" for x in result["installations"]
    )
    assert len(result["approval_sha256"]) == 64


def test_private_collision_direct_origin_and_no_probe(tmp_path):
    p = package(tmp_path)
    (p / "direct_url.json").write_text('{"url":"https://private.example/secret-canary"}')
    result = discover([str(tmp_path)], approved_public=[artifact("pip", "25.2")])
    assert not result["coordinates"]
    assert result["installations"][0]["reason"] == "direct_or_editable_origin"
    assert "secret-canary" not in json.dumps(result)


def test_not_allowlisted_stays_local_and_metadata_changes_revoke_preview(tmp_path):
    p = package(tmp_path, name="private-canary")
    first = discover([str(tmp_path)], approved_public=[])
    assert (
        not first["coordinates"]
        and first["installations"][0]["coordinate"]["name"] == "private-canary"
    )
    assert first["installations"][0]["coordinate"]["public_visibility"] == "not_asserted_public"
    (p / "METADATA").write_text("Name: private-canary\nVersion: 2\n")
    second = discover([str(tmp_path)], approved_public=[])
    assert first["approval_sha256"] != second["approval_sha256"]


@pytest.mark.parametrize("kind", ["directory", "metadata", "ancestor", "direct_url"])
def test_symlinks_never_followed(tmp_path, kind):
    scope = tmp_path / "scope"
    scope.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    p = package(scope)
    if kind == "directory":
        p.rename(outside / p.name)
        p.symlink_to(outside / p.name)
    elif kind == "metadata":
        (p / "METADATA").unlink()
        (outside / "secret").write_text("Name: secret\nVersion: 1\n")
        (p / "METADATA").symlink_to(outside / "secret")
    elif kind == "ancestor":
        alias = tmp_path / "alias"
        alias.symlink_to(scope)
        scope = alias
    else:
        (p / "direct_url.json").symlink_to(outside / "missing")
    result = discover([str(scope)], approved_public=[artifact("pip", "25.2")])
    assert not result["coordinates"]


@pytest.mark.parametrize("extra", ["Name: other\n", "Version: 26\n"])
def test_ambiguous_headers(tmp_path, extra):
    package(tmp_path, extra=extra)
    assert not discover([str(tmp_path)], approved_public=[artifact("pip", "25.2")])["coordinates"]


def test_no_path_hook_execution(tmp_path):
    marker = tmp_path / "executed"
    (tmp_path / "evil.pth").write_text(f"import pathlib; pathlib.Path({str(marker)!r}).touch()")
    result = discover([str(tmp_path)], approved_public=[])
    assert not marker.exists() and not result["discovery_complete"]


def test_graph_keeps_conditional_dependencies_uncertain(tmp_path):
    package(
        tmp_path,
        name="app",
        version="1",
        extra='Requires-Dist: direct>=1\nRequires-Dist: target; sys_platform == "win32"\n',
    )
    package(tmp_path, name="direct", version="1", extra="Requires-Dist: child>=1\n")
    package(tmp_path, name="child", version="1")
    package(tmp_path, name="target", version="1")
    result = discover(
        [str(tmp_path)], approved_public=[], application_roots={str(tmp_path): ["app"]}
    )
    items = {x["coordinate"]["name"]: x for x in result["installations"]}
    assert items["direct"]["application_memberships"][0]["relation"] == "direct"
    assert items["child"]["application_memberships"][0]["relation"] == "transitive"
    assert not items["target"].get("application_memberships")
    assert any(e["state"] == "conditional_or_origin_uncertain" for e in result["relationships"])


def test_fifo_and_oversize_do_not_block(tmp_path):
    p = package(tmp_path)
    (p / "METADATA").unlink()
    os.mkfifo(p / "METADATA")
    assert not discover([str(tmp_path)], approved_public=[artifact("pip", "25.2")])["coordinates"]
    (p / "METADATA").unlink()
    (p / "METADATA").write_bytes(b"x" * 131073)
    assert not discover([str(tmp_path)], approved_public=[artifact("pip", "25.2")])["coordinates"]


def test_explicit_paths_and_local_versions_rejected():
    with pytest.raises(ValueError):
        open_directory("relative")
    with pytest.raises(ValueError):
        open_directory("/tmp/../home")
    with pytest.raises(ValueError):
        artifact("pip", "25.2+private")


def test_entry_budget_accounts_unvisited_scopes(tmp_path, monkeypatch):
    import smithguard_client.discovery as module

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    for n in range(4):
        (first / str(n)).write_text("irrelevant")
    package(second)
    monkeypatch.setattr(module, "MAX_ENTRIES", 2)
    result = discover([str(first), str(second)], approved_public=[])
    assert not result["discovery_complete"]
    assert {"scope": str(second), "reason": "not_scanned_directory_entry_limit"} in result["gaps"]


def test_equivalent_scopes_do_not_double_count_installations(tmp_path):
    package(tmp_path)
    with pytest.raises(ValueError):
        discover([str(tmp_path), str(tmp_path) + "/"], approved_public=[])
    result = discover(
        [str(tmp_path) + "/"], approved_public=[], application_roots={str(tmp_path) + "/": ["pip"]}
    )
    assert result["scopes"] == [str(tmp_path)]
    assert result["installations"][0]["application_memberships"][0]["relation"] == "root"


def test_metadata_budget_explicitly_skips_every_remaining_installation(tmp_path, monkeypatch):
    import smithguard_client.discovery as module

    package(tmp_path, name="one")
    package(tmp_path, name="two")
    monkeypatch.setattr(module, "MAX_TOTAL_BYTES", 0)
    result = discover([str(tmp_path)], approved_public=[])
    assert len(result["installations"]) == 2 and not result["discovery_complete"]
    assert {x["reason"] for x in result["installations"]} == {"metadata_byte_budget_exhausted"}


def test_application_membership_limit_is_an_explicit_discovery_gap(tmp_path, monkeypatch):
    import smithguard_client.discovery as module

    monkeypatch.setattr(module, "MAX_MEMBERSHIPS", 1)
    package(tmp_path, name="app", version="1", extra="Requires-Dist: child>=1\n")
    package(tmp_path, name="child", version="1")
    result = discover(
        [str(tmp_path)], approved_public=[], application_roots={str(tmp_path): ["app"]}
    )
    assert not result["discovery_complete"]
    assert {"reason": "relationship_limit"} in result["gaps"]
    assert sum(len(x.get("application_memberships", [])) for x in result["installations"]) == 1
