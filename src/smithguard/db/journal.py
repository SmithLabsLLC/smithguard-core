"""Migration-source integrity and database journal synchronization."""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any

from sqlalchemy import MetaData, Table, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from smithguard.identifiers import (
    REGISTER_JSON_MAX_DEPTH,
    REGISTER_JSON_MAX_NODES,
    strict_json_loads,
)


class MigrationJournalError(RuntimeError):
    """The migration source and its committed journal disagree."""


def file_sha256(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def load_migration_journal(path: Path) -> dict[str, Any]:
    try:
        document = strict_json_loads(
            path.read_text(encoding="utf-8"),
            max_nodes=REGISTER_JSON_MAX_NODES,
            max_depth=REGISTER_JSON_MAX_DEPTH,
        )
    except ValueError as error:
        raise MigrationJournalError("migration journal is not strict JSON") from error
    if not isinstance(document, dict) or document.get("schema_version") != "1.0.0":
        raise MigrationJournalError("unsupported migration journal schema")
    entries = document.get("migrations")
    if not isinstance(entries, list) or not entries:
        raise MigrationJournalError("migration journal must contain at least one entry")
    seen: set[str] = set()
    previous_revision: str | None = None
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise MigrationJournalError("migration journal entry must be an object")
        revision = entry.get("revision")
        if not isinstance(revision, str) or not revision or revision in seen:
            raise MigrationJournalError("migration revisions must be non-empty and unique")
        if entry.get("down_revision") != previous_revision:
            raise MigrationJournalError(
                f"migration journal chain is not contiguous at revision: {revision}"
            )
        seen.add(revision)
        previous_revision = revision
        relative = entry.get("file")
        if (
            not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            raise MigrationJournalError("migration file must be a safe relative path")
        source = path.parent / relative
        if not source.is_file() or file_sha256(source) != entry.get("source_sha256"):
            raise MigrationJournalError(f"migration source checksum mismatch: {revision}")
        if entry.get("rollback_mode") not in {"safe_to_zero", "forward_only"}:
            raise MigrationJournalError(f"unsupported rollback mode: {revision}")
    return document


def record_migration_journal(
    session: Session,
    *,
    journal_path: Path,
    app_version: str,
    through_revision: str | None = None,
    target_notes: Mapping[str, str] | None = None,
) -> None:
    """Record verified migration sources without overwriting prior evidence."""
    document = load_migration_journal(journal_path)
    entries = document["migrations"]
    revisions = [entry["revision"] for entry in entries]
    target_revision = through_revision or revisions[-1]
    if through_revision is not None:
        try:
            final_index = revisions.index(through_revision)
        except ValueError as error:
            raise MigrationJournalError(
                f"migration journal does not contain target revision: {through_revision}"
            ) from error
        entries = entries[: final_index + 1]
    database_revision = session.scalar(text("SELECT version_num FROM public.alembic_version"))
    if database_revision != target_revision:
        raise MigrationJournalError(
            "database revision does not match migration journal target: "
            f"expected {target_revision}, found {database_revision}"
        )
    target_index = revisions.index(target_revision)
    if target_index < revisions.index("0013_watch_rebrand"):
        live_schema = "goodboy_security"
    elif target_index < revisions.index("0019_smithguard_rebrand"):
        live_schema = "goodboy_watch"
    else:
        live_schema = "smithguard"
    journal_table = Table(
        "migration_journal",
        MetaData(),
        schema=live_schema,
        autoload_with=session.connection(),
    )
    has_notes = "notes" in journal_table.c
    notes = dict(target_notes or {})
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in notes.items()):
        raise MigrationJournalError("migration journal notes must contain strings")
    if notes and not has_notes:
        raise MigrationJournalError("migration journal target does not support notes")
    for entry in entries:
        entry_notes = notes if entry["revision"] == target_revision else {}
        values: dict[str, Any] = {
            "revision": entry["revision"],
            "source_sha256": entry["source_sha256"],
            "description": entry["description"],
            "rollback_mode": entry["rollback_mode"],
            "app_version": app_version,
        }
        if has_notes:
            values["notes"] = entry_notes
        statement = (
            insert(journal_table)
            .values(**values)
            .on_conflict_do_nothing(index_elements=["revision"])
            .returning(journal_table.c.revision)
        )
        inserted_revision = session.scalar(statement)
        existing = (
            session.execute(
                select(journal_table)
                .where(journal_table.c.revision == entry["revision"])
                .with_for_update()
            )
            .mappings()
            .one_or_none()
        )
        if existing is None:
            raise MigrationJournalError("migration journal record disappeared")
        if (
            existing["source_sha256"] != entry["source_sha256"]
            or existing["description"] != entry["description"]
            or existing["rollback_mode"] != entry["rollback_mode"]
            or (inserted_revision is not None and has_notes and existing["notes"] != entry_notes)
        ):
            raise MigrationJournalError(
                f"database migration journal conflicts with source: {entry['revision']}"
            )
