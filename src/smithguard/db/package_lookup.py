"""Compatible query keys; retained package names and identities are never rewritten."""

from __future__ import annotations

from typing import Any

from sqlalchemy import and_, func, literal_column
from sqlalchemy.sql.elements import ColumnElement

ASCII_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ASCII_LOWER = "abcdefghijklmnopqrstuvwxyz"
# Registries that treat names case-insensitively (ASCII only). crates.io also treats
# "-" and "_" as the same character, so its key folds "-" to "_" as well.
ASCII_FOLDED_ECOSYSTEMS = frozenset({"nuget", "vscode", "open-vsx", "composer"})
RUST_ECOSYSTEM = "rust"
FOLDED_ECOSYSTEMS = ASCII_FOLDED_ECOSYSTEMS | {RUST_ECOSYSTEM}


def _fold_tables(ecosystem: str) -> tuple[str, str]:
    if ecosystem == RUST_ECOSYSTEM:
        return ASCII_UPPER + "-", ASCII_LOWER + "_"
    return ASCII_UPPER, ASCII_LOWER


def package_lookup_key(ecosystem: str, name: str) -> str:
    """The folded name the lookup indexes store for this ecosystem."""
    if ecosystem not in FOLDED_ECOSYSTEMS:
        return name
    source, target = _fold_tables(ecosystem)
    return name.translate(str.maketrans(source, target))


def package_name_predicate(
    name_column: Any, *, ecosystem_column: Any, ecosystem: str, name: str
) -> ColumnElement[bool]:
    """Fold names only where the registry does, identically to the expression indexes.

    Literal SQL constants (not bound parameters) let the planner prove each partial
    index predicate.
    """
    if ecosystem in FOLDED_ECOSYSTEMS:
        source, target = _fold_tables(ecosystem)
        return and_(
            ecosystem_column == literal_column(f"'{ecosystem}'"),
            func.translate(
                name_column, literal_column(f"'{source}'"), literal_column(f"'{target}'")
            )
            == package_lookup_key(ecosystem, name),
        )
    return and_(ecosystem_column == ecosystem, name_column == name)
