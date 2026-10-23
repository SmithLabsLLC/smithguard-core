"""Bind deployment compatibility to verified installed bytes and the live journal."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from smithguard.deploy.host import HostAdapter
from smithguard.deploy.release import _verify_migration_journal

SCHEMA_SQL = """
SELECT json_build_object(
  'heads', (SELECT json_agg(version_num ORDER BY version_num) FROM public.alembic_version),
  'journal', (SELECT json_agg(json_build_object(
    'revision', revision, 'source_sha256', source_sha256,
    'description', description, 'rollback_mode', rollback_mode
  ) ORDER BY revision) FROM smithguard.migration_journal)
)::text;
"""
JOURNAL_FIELDS = ("revision", "source_sha256", "description", "rollback_mode")


class SchemaBoundaryError(RuntimeError):
    """The target is incompatible or its exact migration identity is unproved."""


def verified_journal(
    host: HostAdapter,
    *,
    commit: str,
    digest: str,
    release_root: Path,
    current_link: Path | None = None,
) -> tuple[dict[str, Any], str]:
    proof = host.verify_release(
        commit, str(release_root), None if current_link is None else str(current_link)
    )
    if (
        proof.get("release_commit") != commit
        or proof.get("archive_sha256") != digest
        or proof.get("drift") is not False
    ):
        raise SchemaBoundaryError("verified installed artifact differs from approval")
    path = release_root / commit / "app/migrations/journal.json"
    body = host.read_file(str(path))
    try:
        document = json.loads(body)
    except (ValueError, UnicodeDecodeError) as error:
        raise SchemaBoundaryError("candidate migration journal is invalid") from error
    if not isinstance(document, dict) or not isinstance(document.get("migrations"), list):
        raise SchemaBoundaryError("candidate migration journal is invalid")
    files = {"app/migrations/journal.json": body}
    for entry in document["migrations"]:
        if (
            not isinstance(entry, Mapping)
            or not isinstance(entry.get("file"), str)
            or re.fullmatch(r"versions/[A-Za-z0-9_]+\.py", entry["file"]) is None
            or not all(isinstance(entry.get(key), str) for key in JOURNAL_FIELDS)
        ):
            raise SchemaBoundaryError("candidate migration journal entry is invalid")
        files["app/migrations/" + entry["file"]] = host.read_file(str(path.parent / entry["file"]))
    _verify_migration_journal(files)
    if proof.get("required_migration_head") != document["migrations"][-1]["revision"]:
        raise SchemaBoundaryError("candidate readiness schema differs from its verified journal")
    return document, hashlib.sha256(body).hexdigest()


def live_schema(host: HostAdapter, journal: Mapping[str, Any], *, forward: bool) -> str:
    raw = host.psql(SCHEMA_SQL).require_success("live migration boundary")
    try:
        state = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise SchemaBoundaryError("live migration boundary is invalid") from error
    entries = journal["migrations"]
    revisions = [entry["revision"] for entry in entries]
    if (
        not isinstance(state, Mapping)
        or not isinstance(state.get("heads"), list)
        or len(state["heads"]) != 1
        or state["heads"][0] not in revisions
    ):
        raise SchemaBoundaryError("live schema is not on the candidate migration chain")
    head = state["heads"][0]
    if not forward and head != revisions[-1]:
        raise SchemaBoundaryError("candidate schema is incompatible with the live database")
    expected = [
        {key: entry[key] for key in JOURNAL_FIELDS}
        for entry in entries[: revisions.index(head) + 1]
    ]
    recorded = state.get("journal")
    if not isinstance(recorded, list) or recorded != sorted(
        expected, key=lambda row: row["revision"]
    ):
        raise SchemaBoundaryError("live migration journal differs from the verified candidate")
    return head


def candidate_schema(
    host: HostAdapter,
    *,
    commit: str,
    digest: str,
    release_root: Path,
    migration: bool,
    current_link: Path | None = None,
) -> dict[str, Any]:
    journal, journal_sha256 = verified_journal(
        host, commit=commit, digest=digest, release_root=release_root, current_link=current_link
    )
    head = live_schema(host, journal, forward=migration)
    target = journal["migrations"][-1]["revision"]
    return {
        "live_head": head,
        "target_head": target,
        "journal_sha256": journal_sha256,
        "transition": "quiesced" if head != target else "same_schema",
    }
