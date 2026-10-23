#!/usr/bin/env python3
"""Create or verify the deterministic migration source journal."""

from __future__ import annotations

import argparse
import ast
from hashlib import sha256
from pathlib import Path
from typing import Any

from smithguard.identifiers import pretty_json_bytes

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = PROJECT_ROOT / "migrations"
JOURNAL = MIGRATIONS / "journal.json"


def _assignment(tree: ast.Module, name: str) -> Any:
    for node in tree.body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            return ast.literal_eval(node.value)
    raise ValueError(f"migration is missing {name}")


def migration_entry(path: Path) -> dict[str, Any]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    revision = _assignment(tree, "revision")
    down_revision = _assignment(tree, "down_revision")
    description = _assignment(tree, "migration_description")
    rollback_mode = _assignment(tree, "rollback_mode")
    if not isinstance(description, str) or not description:
        raise ValueError(f"migration has an invalid description: {path.name}")
    if rollback_mode not in {"safe_to_zero", "forward_only"}:
        raise ValueError(f"migration has an invalid rollback mode: {path.name}")
    return {
        "revision": revision,
        "down_revision": down_revision,
        "file": str(path.relative_to(MIGRATIONS)),
        "source_sha256": "sha256:" + sha256(path.read_bytes()).hexdigest(),
        "description": description,
        "rollback_mode": rollback_mode,
    }


def expected() -> dict[str, Any]:
    migration_files = sorted((MIGRATIONS / "versions").glob("*.py"))
    return {
        "schema_version": "1.0.0",
        "migrations": [migration_entry(path) for path in migration_files],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    arguments = parser.parse_args()
    body = pretty_json_bytes(expected()).decode("ascii")
    if arguments.write:
        JOURNAL.write_text(body, encoding="utf-8")
        print("wrote migration journal")
        return
    if not JOURNAL.is_file() or JOURNAL.read_text(encoding="utf-8") != body:
        raise SystemExit("migration journal differs from migration sources")
    print("migration journal is current")


if __name__ == "__main__":
    main()
