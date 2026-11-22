"""Synthetic local PostgreSQL helpers for focused tests."""

from __future__ import annotations

import os
import re
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
        # The check entry provides a short, disk-backed task directory. Pass it
        # explicitly because tempfile may have cached a different default before
        # TMPDIR was set; standalone tests still use Python's normal fallback.
        # A plain folder (not TemporaryDirectory): it is removed only on purpose, so a
        # server whose shutdown is unverified keeps its cluster (GPT review round 11).
        # GPT review round 15: find the tools before creating anything, and remove the new
        # folder if its socket directory cannot be made, so a failed setup leaves nothing.
        self._initdb = postgres_tool("initdb")
        self._pg_ctl = postgres_tool("pg_ctl")
        self.root = Path(tempfile.mkdtemp(prefix="sg-pg-", dir=os.environ.get("TMPDIR") or None))
        self.data = self.root / "data"
        self.socket = self.root / "socket"
        try:
            self.socket.mkdir(mode=0o700)
        except BaseException:
            shutil.rmtree(self.root, ignore_errors=True)
            raise
        self.port = 5432
        self.databases: list[str] = []
        # Migrated template databases by (revision, journal); cloning one is much
        # faster than running every migration for each test.
        self.templates: dict[tuple[str, bool], str] = {}
        self._started = False

    def _run_tool(self, args: list[str], *, log: str) -> int | None:
        """Run a PostgreSQL tool with its output in a file (never a pipe: the server
        keeps inherited pipes open). If the log cannot be created (for example no free
        file slots), the tool still runs, without a log (GPT review round 12)."""
        try:
            output = (self.root / log).open("wb")
        except OSError:
            output = None
        # GPT review round 13: a tool that cannot even be launched reports None.
        try:
            if output is None:
                return subprocess.run(
                    args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
                ).returncode
            with output:
                return subprocess.run(
                    args, stdout=output, stderr=subprocess.STDOUT, check=False
                ).returncode
        except OSError:
            return None

    def _failed_start(self, tool: str, code: int | None) -> None:
        """GPT review round 11: stop a partly started server of this exact cluster, keep
        its logs in the outer task folder, and remove the cluster only once stopped.
        Round 12: shutdown is attempted first and does not depend on creating any file;
        if the logs cannot be copied they stay in the cluster, which is then kept."""
        stopped, notes = True, []
        if (self.data / "postmaster.pid").exists() or tool == "pg_ctl":
            stop = self._run_tool(
                [self._pg_ctl, "-D", str(self.data), "-m", "immediate", "-w", "-t", "30", "stop"],
                log="pg_ctl-stop.log",
            )
            if stop is None:
                notes.append("pg_ctl stop could not be launched")
            # Checked even when the stop failed: pg_ctl status exits 3 when no server runs.
            status = self._run_tool(
                [self._pg_ctl, "-D", str(self.data), "status"], log="pg_ctl-status.log"
            )
            if status is None:
                notes.append("pg_ctl status could not be launched")
            stopped = status == 3
        try:
            logs = sorted(self.root.glob("*.log"))
        except OSError:
            logs = []
        parts = []
        for item in logs:
            try:
                parts.append(f"--- {item.name} ---\n" + item.read_text(errors="replace")[-2000:])
            except OSError as error:
                parts.append(f"--- {item.name} --- (unreadable: {type(error).__name__})")
        tail = "\n".join(parts)
        try:
            keep = self.root.parent / f"postgres-start-failure-{uuid4().hex[:8]}"
            keep.mkdir(mode=0o700)
            for item in logs:
                shutil.copy2(item, keep / item.name)
            where = f"logs retained at {keep}"
            copied = True
        except OSError as error:
            where = f"logs could not be copied ({type(error).__name__}); they stay in {self.root}"
            copied = False
        if stopped and copied:
            shutil.rmtree(self.root, ignore_errors=True)
            state = "the cluster was stopped and removed"
        elif stopped:
            state = f"the cluster was stopped and is kept at {self.root} for its logs"
        else:
            state = f"shutdown could not be verified; the cluster is kept at {self.root}"
        extra = "".join(f"; {note}" for note in notes)
        how = "could not be launched" if code is None else f"exited {code}"
        raise RuntimeError(f"{tool} {how}; {state}{extra}; {where}\n{tail}")

    def start(self) -> Self:
        # GPT review round 11: the socket folder goes into PostgreSQL's options unquoted
        # and into a comma-separated setting, so only plain path characters are supported.
        if not re.fullmatch(r"[A-Za-z0-9/._-]+", str(self.socket)):
            shutil.rmtree(self.root, ignore_errors=True)
            raise RuntimeError(
                f"Test database folder {self.socket} has unsupported characters; use a "
                "temporary folder whose path has only letters, digits, '/', '.', '_' or '-'."
            )
        code = self._run_tool(
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
            log="initdb.log",
        )
        if code != 0:  # GPT review round 14: None (not launched) is a failure too
            self._failed_start("initdb", code)
        code = self._run_tool(
            [
                self._pg_ctl,
                "-D",
                str(self.data),
                "-l",
                str(self.root / "postgres.log"),
                "-o",
                f"-F -k {self.socket} -h '' -p {self.port}",
                "-w",
                "start",
            ],
            log="pg_ctl.log",
        )
        if code != 0:  # GPT review round 14: None (not launched) is a failure too
            self._failed_start("pg_ctl", code)
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
        shutil.rmtree(self.root, ignore_errors=True)


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
