"""Synthetic local PostgreSQL helpers for focused tests."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Self
from uuid import uuid4

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy import URL, Engine, create_engine
from sqlalchemy.orm import Session

from smithguard import __version__
from smithguard.db.journal import record_migration_journal

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI = PACKAGE_ROOT / "alembic.ini"
MIGRATION_JOURNAL = PACKAGE_ROOT / "migrations/journal.json"


def postgres_tool(name: str) -> str:
    direct = shutil.which(name)
    if direct is not None:
        return direct
    pg_config = shutil.which("pg_config")
    if pg_config is not None:
        result = subprocess.run(
            [pg_config, "--bindir"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            candidate = Path(result.stdout.strip()) / name
            if candidate.is_file():
                return str(candidate)
    candidates = sorted(
        Path("/usr/lib/postgresql").glob(f"*/bin/{name}"),
        key=lambda path: int(path.parent.parent.name),
        reverse=True,
    )
    if candidates:
        return str(candidates[0])
    raise RuntimeError(f"required PostgreSQL test tool is unavailable: {name}")


@dataclass(frozen=True, slots=True)
class DatabaseHandle:
    url: URL
    engine: Engine


class LocalPostgres:
    """One loopback-disabled PostgreSQL cluster containing disposable test databases."""

    def __init__(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="smithguard-tests-", dir="/tmp")
        self.root = Path(self._temporary.name)
        self.data = self.root / "data"
        self.socket = self.root / "socket"
        self.socket.mkdir(mode=0o700)
        self.port = 5432
        self.databases: list[str] = []
        # Migrated template databases by (revision, journal); cloning one is much
        # faster than running every migration for each test.
        self.templates: dict[tuple[str, bool], str] = {}
        self._started = False
        self._initdb = postgres_tool("initdb")
        self._pg_ctl = postgres_tool("pg_ctl")

    def start(self) -> Self:
        subprocess.run(
            [
                self._initdb,
                "-D",
                str(self.data),
                "-U",
                "postgres",
                "-A",
                "trust",
                "--no-locale",
                "-E",
                "UTF8",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                self._pg_ctl,
                "-D",
                str(self.data),
                "-o",
                f"-F -k {self.socket} -h '' -p {self.port}",
                "-w",
                "start",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._started = True
        return self

    def _admin_connection(self) -> psycopg.Connection:
        return psycopg.connect(
            host=str(self.socket),
            port=self.port,
            user="postgres",
            dbname="postgres",
            autocommit=True,
        )

    def create_database(self, *, name: str | None = None, template: str | None = None) -> URL:
        name = name or f"smithguard_{uuid4().hex}"
        statement = sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name))
        if template is not None:
            statement += sql.SQL(" TEMPLATE {}").format(sql.Identifier(template))
        with self._admin_connection() as connection:
            connection.execute(statement)
        self.databases.append(name)
        return self.url(name)

    def url(self, name: str) -> URL:
        return URL.create(
            "postgresql+psycopg",
            username="postgres",
            database=name,
            query={
                "host": str(self.socket),
                "port": str(self.port),
            },
        )

    def drop_database(self, name: str) -> None:
        if name not in self.databases:
            raise ValueError("test database is not tracked")
        with self._admin_connection() as connection:
            connection.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = %s AND pid <> pg_backend_pid()",
                (name,),
            )
            connection.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))
        self.databases.remove(name)

    def close(self) -> None:
        if self._started:
            with self._admin_connection() as connection:
                for name in self.databases:
                    connection.execute(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname = %s AND pid <> pg_backend_pid()",
                        (name,),
                    )
                    connection.execute(
                        sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name))
                    )
            subprocess.run(
                [
                    self._pg_ctl,
                    "-D",
                    str(self.data),
                    "-m",
                    "fast",
                    "-w",
                    "stop",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._started = False
        self._temporary.cleanup()


def alembic_config(url: URL) -> Config:
    configuration = Config(str(ALEMBIC_INI))
    configuration.attributes["database_url"] = url.render_as_string(hide_password=False)
    return configuration


def migrate(url: URL, revision: str) -> None:
    previous = os.environ.pop("SMITHGUARD_DATABASE_URL", None)
    try:
        if revision == "base":
            command.downgrade(alembic_config(url), "base")
        else:
            command.upgrade(alembic_config(url), revision)
    finally:
        if previous is not None:
            os.environ["SMITHGUARD_DATABASE_URL"] = previous


def migrated_database(
    cluster: LocalPostgres,
    *,
    journal: bool = True,
    name: str | None = None,
    revision: str = "head",
) -> DatabaseHandle:
    key = (revision, journal)
    template = cluster.templates.get(key)
    if template is None:
        template_url = cluster.create_database()
        migrate(template_url, revision)
        template_engine = create_engine(template_url)
        try:
            if journal:
                with Session(template_engine) as session, session.begin():
                    record_migration_journal(
                        session,
                        journal_path=MIGRATION_JOURNAL,
                        app_version=__version__,
                        through_revision=None if revision == "head" else revision,
                    )
        finally:
            # A template must have no open connections while it is cloned.
            template_engine.dispose()
        template = cluster.templates[key] = template_url.database
    url = cluster.create_database(name=name, template=template)
    return DatabaseHandle(url=url, engine=create_engine(url))


def openssf_manifest_pair(
    *, observed_at, sequence: int = 1, state: str = "complete", commit: str = "a" * 40
) -> tuple[object, object]:
    """One OpenSSF catalog run: malicious and withdrawn manifests at one snapshot."""
    from smithguard.advisory_catalog import OPENSSF_SOURCE_ID
    from smithguard.db.models import AdvisoryCatalogManifestRecord

    rows = []
    for offset, segment in enumerate(("openssf-malicious", "openssf-withdrawn")):
        identity = sequence * 2 + offset
        rows.append(
            AdvisoryCatalogManifestRecord(
                manifest_event_id=f"gbsec:advisory-catalog-manifest:openssf-{segment}-{sequence}",
                source_id=OPENSSF_SOURCE_ID,
                segment=segment,
                sequence=sequence,
                state=state,
                source_snapshot=f"{commit}:sha256:{identity:064x}",
                cursor_value=None,
                record_count=0,
                package_entry_count=0,
                manifest_sha256="sha256:" + f"{identity + 1000:064x}",
                observed_at=observed_at,
                record_hash="sha256:" + f"{identity + 2000:064x}",
            )
        )
    return tuple(rows)


def tree_state(roots) -> dict[str, tuple[int, int, int, int] | None]:
    """Every entry under ``roots`` with its inode, mode, size and modification time.

    Comparing two states finds created, removed and edited files at any depth. An
    absent root is recorded as None; an unreadable entry as (-1, -1, -1, -1).
    """
    state: dict[str, tuple[int, int, int, int] | None] = {}

    def record(path: str) -> None:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            state[path] = None
        except OSError:
            state[path] = (-1, -1, -1, -1)
        else:
            state[path] = (info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns)

    for root in roots:
        record(str(root))
        for directory, subdirectories, files in os.walk(root, onerror=lambda _error: None):
            for name in (*subdirectories, *files):
                record(os.path.join(directory, name))
    return state
