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


def fake_statvfs(free_bytes, free_inodes):
    return lambda path: SimpleNamespace(f_bavail=free_bytes, f_frsize=1, f_favail=free_inodes)


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
