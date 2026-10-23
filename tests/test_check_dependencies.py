"""The dependency gate derives runtime companion extras from the lock, not a copied dict."""

from __future__ import annotations

import importlib.util
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _tool():
    spec = importlib.util.spec_from_file_location(
        "check_dependencies", ROOT / "tools/check_dependencies.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_runtime_extras_come_from_the_locked_optional_dependencies() -> None:
    tool = _tool()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    extras = tool._runtime_extras(project, lock)
    assert set(extras) == {"psycopg-binary", "psycopg-pool"}
    locked = {package["name"]: package["version"] for package in lock["package"]}
    assert extras == {name: locked[name] for name in extras}


def test_runtime_extras_refuse_an_unlocked_companion_and_ignore_third_party_extras() -> None:
    tool = _tool()
    project = {"project": {"dependencies": ["example[fast,format]==1.0"]}}
    lock = {
        "package": [
            {
                "name": "example",
                "version": "1.0",
                "optional-dependencies": {
                    "fast": [{"name": "example-fast"}],
                    "format": [{"name": "fqdn"}],
                },
            },
            {"name": "example-fast", "version": "1.0"},
            {"name": "fqdn", "version": "2.0"},
        ]
    }
    assert tool._runtime_extras(project, lock) == {"example-fast": "1.0"}
    lock["package"].pop(1)
    with pytest.raises(SystemExit, match="not locked"):
        tool._runtime_extras(project, lock)
