"""Run the exact release migration and synchronize its append-only journal."""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from smithguard import __version__
from smithguard.db.journal import load_migration_journal, record_migration_journal
from smithguard.db.models import MigrationJournalRecord
from smithguard.diagnostics import write_exception_diagnostic
from smithguard.execution_policy import BACKUP_RESTORE_POLICY


class MigrationRuntimeError(RuntimeError):
    """The release migration and its journal could not be accepted together."""


REHEARSAL_DATABASE = re.compile(r"^smithguard_restore_drill$")


def _release_file(path: Path, *, name: str) -> Path:
    if not path.is_absolute() or path.name != name or path.is_symlink():
        raise MigrationRuntimeError(f"{name} path is invalid")
    try:
        resolved = path.resolve(strict=True)
        metadata = os.lstat(path)
    except OSError as error:
        raise MigrationRuntimeError(f"{name} path is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or metadata.st_size > 4 * 1024 * 1024
    ):
        raise MigrationRuntimeError(f"{name} path is unsafe")
    return resolved


def _database_url(value: str, *, scope: str = "production") -> str:
    try:
        parsed = make_url(value)
    except Exception as error:
        raise MigrationRuntimeError("migration database URL is invalid") from error
    query_host = parsed.query.get("host")
    production = scope == "production"
    rehearsal = scope == "isolated_rehearsal"
    if (
        parsed.drivername != "postgresql+psycopg"
        or not (production or rehearsal)
        or (
            production
            and (parsed.database != "smithguard" or parsed.username != "smithguard-maintenance")
        )
        or (
            rehearsal
            and (
                not isinstance(parsed.database, str)
                or REHEARSAL_DATABASE.fullmatch(parsed.database) is None
                or parsed.username != "smithguard-maintenance"
            )
        )
        or parsed.host not in {None, "localhost", "127.0.0.1", "::1"}
        or (
            query_host is not None
            and (not isinstance(query_host, str) or not query_host.startswith("/"))
        )
    ):
        raise MigrationRuntimeError(
            "migration requires the fixed local database, scope, and maintenance role"
        )
    return value


def migrate_and_record(
    *,
    database_url: str,
    alembic_config_path: Path,
    journal_path: Path,
    app_version: str = __version__,
    scope: str = "production",
) -> None:
    """Upgrade to the bundled head and accept it only with matching journal rows."""
    database_url = _database_url(database_url, scope=scope)
    config_path = _release_file(alembic_config_path, name="alembic.ini")
    verified_journal_path = _release_file(journal_path, name="journal.json")
    if verified_journal_path.parent.parent != config_path.parent:
        raise MigrationRuntimeError("migration journal is outside the release package")
    document = load_migration_journal(verified_journal_path)
    expected_head = document["migrations"][-1]["revision"]
    recovery_notes = {"backup_restore_policy": BACKUP_RESTORE_POLICY}

    configuration = Config(str(config_path))
    configuration.attributes["database_url"] = database_url
    command.upgrade(configuration, "head")

    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={
            "options": "-c statement_timeout=120000 -c lock_timeout=5000",
        },
    )
    try:
        with Session(engine) as session, session.begin():
            heads = tuple(session.scalars(text("SELECT version_num FROM public.alembic_version")))
            if heads != (expected_head,):
                raise MigrationRuntimeError("database migration head differs from the journal")
            record_migration_journal(
                session,
                journal_path=verified_journal_path,
                app_version=app_version,
                target_notes=recovery_notes,
            )
            recorded = tuple(
                session.scalars(
                    select(MigrationJournalRecord).order_by(MigrationJournalRecord.revision)
                )
            )
            expected = tuple(document["migrations"])
            if len(recorded) != len(expected) or any(
                (
                    row.revision,
                    row.source_sha256,
                    row.description,
                    row.rollback_mode,
                )
                != (
                    entry["revision"],
                    entry["source_sha256"],
                    entry["description"],
                    entry["rollback_mode"],
                )
                for row, entry in zip(recorded, expected, strict=True)
            ):
                raise MigrationRuntimeError("database migration journal differs from the release")
    finally:
        engine.dispose()


def main() -> int:
    try:
        database_url = os.environ["SMITHGUARD_DATABASE_URL"]
        alembic_config_path = Path(os.environ["SMITHGUARD_ALEMBIC_CONFIG_PATH"])
        journal_path = Path(os.environ["SMITHGUARD_MIGRATION_JOURNAL_PATH"])
        migrate_and_record(
            database_url=database_url,
            alembic_config_path=alembic_config_path,
            journal_path=journal_path,
            scope=os.environ.get("SMITHGUARD_MIGRATION_SCOPE", "production"),
        )
    except Exception as error:
        write_exception_diagnostic(error)
        sys.stderr.write("runtime_error:migration_and_journal_failed\n")
        return 2
    sys.stdout.write("migration_and_journal_complete outcome=succeeded\n")
    return 0
