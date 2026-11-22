"""Compatible query keys; retained package names and identities are never rewritten."""

from __future__ import annotations

from typing import Any

from sqlalchemy import and_, func, literal_column, or_
from sqlalchemy.sql.elements import ColumnElement

ASCII_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ASCII_LOWER = "abcdefghijklmnopqrstuvwxyz"
# Registries that treat names case-insensitively (ASCII only). crates.io also treats
# "-" and "_" as the same character, so its key folds "-" to "_" as well.
ASCII_FOLDED_ECOSYSTEMS = frozenset({"nuget", "vscode", "open-vsx", "composer", "swift"})
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


def swift_bare_name(name: str) -> str | None:
    """Bare Swift candidate only for an exact GitHub owner/repository identity, written
    either as github.com/owner/repository or as the documented owner/repository form
    (GPT review round 6)."""
    parts = name.split("/")
    if len(parts) == 2 and all(parts):
        return parts[1]
    if len(parts) != 3 or parts[0].lower() != "github.com" or not all(parts[1:]):
        return None
    return parts[2]


def package_name_predicate(
    name_column: Any,
    *,
    ecosystem_column: Any,
    ecosystem: str,
    name: str,
    include_swift_bare_name: bool = False,
) -> ColumnElement[bool]:
    """Fold names only where the registry does, matching the expression indexes.

    Public Core has folded-name indexes for nuget, vscode/open-vsx, composer and rust;
    Swift lookups fold the same way but have no Core index yet (the private service's
    lookup index migration is not ported), so they are correct but scan Swift rows.

    Literal SQL constants (not bound parameters) let the planner prove each partial
    index predicate. Advisory lookups may include an ambiguous Swift bare name;
    retained artifact lookups keep exact repository identity.
    """
    if ecosystem in FOLDED_ECOSYSTEMS:
        source, target = _fold_tables(ecosystem)
        folded = func.translate(
            name_column, literal_column(f"'{source}'"), literal_column(f"'{target}'")
        )
        name_match = folded == package_lookup_key(ecosystem, name)
        bare = swift_bare_name(name) if include_swift_bare_name and ecosystem == "swift" else None
        if bare is not None:
            name_match = or_(name_match, folded == package_lookup_key(ecosystem, bare))
        return and_(ecosystem_column == literal_column(f"'{ecosystem}'"), name_match)
    return and_(ecosystem_column == ecosystem, name_column == name)
