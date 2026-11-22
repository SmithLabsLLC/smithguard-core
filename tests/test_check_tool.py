"""Audit SG22-31: the contributor check refuses an insufficient temporary location clearly."""

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location(
    "check_tool", Path(__file__).resolve().parents[1] / "tools/check.py"
)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def fake_statvfs(free_bytes, free_inodes, total_inodes=10**9):
    return lambda path: SimpleNamespace(
        f_bavail=free_bytes, f_frsize=1, f_favail=free_inodes, f_files=total_inodes
    )


def test_insufficient_location_is_rejected_with_guidance(monkeypatch):
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 10))
    with pytest.raises(SystemExit, match="free file slots"):
        check.require_capacity("/somewhere", check.MINIMUM)
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10, 10**7))
    with pytest.raises(SystemExit, match="SMITHGUARD_CHECK_TMP"):
        check.require_capacity("/somewhere", check.MINIMUM)


def test_sufficient_location_passes_and_task_folder_is_short(monkeypatch, tmp_path):
    # pytest's own tmp_path can exceed the socket budget; that check is tested below.
    monkeypatch.setattr(check, "SOCKET_PATH_MAX", 10**6)
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 10**7))
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", str(tmp_path))
    folder = check.task_temp()
    assert Path(folder).parent == tmp_path and Path(folder).name.startswith("sgc-")
    assert len(Path(folder).name) < 16


def test_refusal_leaves_no_task_folder(monkeypatch, tmp_path):
    # pytest's own tmp_path can exceed the socket budget; that check is tested below.
    monkeypatch.setattr(check, "SOCKET_PATH_MAX", 10**6)
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10, 10))
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", str(tmp_path))
    with pytest.raises(SystemExit, match="Insufficient temporary capacity"):
        check.task_temp()
    assert list(tmp_path.iterdir()) == []


def test_missing_base_is_refused_clearly(monkeypatch, tmp_path):
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", str(tmp_path / "absent"))
    with pytest.raises(SystemExit, match="does not exist"):
        check.task_temp()


def test_relative_base_gives_an_absolute_task_folder(monkeypatch, tmp_path):
    # pytest's own tmp_path can exceed the socket budget; that check is tested below.
    monkeypatch.setattr(check, "SOCKET_PATH_MAX", 10**6)
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 10**7))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rel").mkdir()
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", "rel")
    folder = check.task_temp()
    assert Path(folder).is_absolute() and Path(folder).parent == tmp_path / "rel"


def test_unreported_inode_totals_are_not_exhaustion(monkeypatch):
    """GPT review round 2: Btrfs reports f_files 0; only the byte check applies."""
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 0, total_inodes=0))
    check.require_capacity("/somewhere", check.MINIMUM)
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10, 0, total_inodes=0))
    with pytest.raises(SystemExit, match="Insufficient"):
        check.require_capacity("/somewhere", check.MINIMUM)


def test_tmp_shortage_names_tmp_not_the_task_setting(monkeypatch):
    """GPT review round 3: SMITHGUARD_CHECK_TMP cannot fix a full /tmp."""
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10, 10**7))
    with pytest.raises(SystemExit, match="free space or file slots in /tmp") as raised:
        check.require_capacity("/tmp", check.MINIMUM_SYSTEM_TMP)
    assert "SMITHGUARD_CHECK_TMP" not in str(raised.value)


def test_base_too_long_for_the_database_socket_is_refused_first(monkeypatch, tmp_path):
    """GPT review round 10: PostgreSQL's socket path must stay under 108 bytes."""
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 10**7))
    deep = tmp_path / ("d" * max(1, 108 - check.SOCKET_SUFFIX - len(str(tmp_path))))
    deep.mkdir()
    assert len(os.fsencode(str(deep))) + check.SOCKET_SUFFIX > check.SOCKET_PATH_MAX
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", str(deep))
    with pytest.raises(SystemExit, match="too long for the test database socket"):
        check.task_temp()
    assert list(deep.iterdir()) == []


def test_socket_suffix_matches_the_suite_layout():
    """The budget covers <base>/sgc-XXXXXXXX/sg-pg-XXXXXXXX/socket/.s.PGSQL.5432."""
    example = "/sgc-abcdefgh/sg-pg-abcdefgh/socket/.s.PGSQL.5432"
    assert len(example) == check.SOCKET_SUFFIX
    support = (Path(__file__).resolve().parent / "support.py").read_text()
    assert 'prefix="sg-pg-"' in support and 'self.root / "socket"' in support
    assert "self.port = 5432" in support
    check.require_socket_room("/var/tmp")


@pytest.mark.parametrize("name", ["with space", "with,comma", "quote'd", "semi;colon"])
def test_base_with_unsupported_characters_is_refused_first(monkeypatch, tmp_path, name):
    """GPT review round 11: PostgreSQL gets the socket folder unquoted."""
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 10**7))
    base = Path("/tmp") / name if len(str(tmp_path)) > 40 else tmp_path / name
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", str(base))
    with pytest.raises(SystemExit, match="characters the test database cannot use"):
        check.require_socket_room(str(base))
