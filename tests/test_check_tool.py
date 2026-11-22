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
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 10**7))
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", str(tmp_path))
    folder = check.task_temp()
    assert Path(folder).parent == tmp_path and Path(folder).name.startswith("sgc-")
    assert len(Path(folder).name) < 16


def test_refusal_leaves_no_task_folder(monkeypatch, tmp_path):
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
