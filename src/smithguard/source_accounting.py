"""Bounded, read-only inspection of immutable non-GitHub collection evidence."""

from __future__ import annotations

import re
import time
from collections.abc import Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from smithguard.advisory_catalog import OPENSSF_SOURCE_ID
from smithguard.db.models import (
    AdvisoryCatalogRecord,
    EvidenceRecord,
    SupplementalSnapshotRecord,
)
from smithguard.identifiers import canonical_json_bytes, sha256_id, strict_json_loads, timestamp
from smithguard.supplemental_store import (
    CVE,
    EPSS_SOURCE,
    GO_SOURCE,
    MAX_FACTS,
    RUST_SOURCE,
    latest_snapshot,
)

CATALOG_SOURCES = {
    "openssf": OPENSSF_SOURCE_ID,
    "rustsec": RUST_SOURCE,
    "go": GO_SOURCE,
}


def catalog_omissions(session: Session, *, source: str, limit: int = 50, after: str = "") -> dict:
    """Keep every observed omission inspectable, including exact successor identity.

    A successor is evidence of a later projection, not a named ledger resolution.
    Disappeared records retain their last known omission. Historical evidence is
    never edited, and unrelated newer records cannot hide an omission.
    """
    if (
        source not in CATALOG_SOURCES
        or not 1 <= limit <= 100
        or (after and re.fullmatch(r"gbsec:advisory-catalog:[0-9a-f]{40}", after) is None)
    ):
        raise ValueError("catalog omission selection is invalid")
    source_id = CATALOG_SOURCES[source]
    newer = aliased(AdvisoryCatalogRecord)
    rows = tuple(
        session.scalars(
            select(AdvisoryCatalogRecord)
            .where(
                AdvisoryCatalogRecord.source_id == source_id,
                AdvisoryCatalogRecord.package_omission_counts != {},
                AdvisoryCatalogRecord.catalog_event_id > after,
            )
            .order_by(AdvisoryCatalogRecord.catalog_event_id)
            .limit(limit + 1)
        )
    )
    selected = rows[:limit]
    identities = [row.upstream_record_id for row in selected]
    latest = (
        {
            row.upstream_record_id: row
            for row in session.scalars(
                select(AdvisoryCatalogRecord).where(
                    AdvisoryCatalogRecord.source_id == source_id,
                    AdvisoryCatalogRecord.upstream_record_id.in_(identities),
                    ~select(newer.catalog_event_id)
                    .where(
                        newer.source_id == AdvisoryCatalogRecord.source_id,
                        newer.upstream_record_id == AdvisoryCatalogRecord.upstream_record_id,
                        newer.revision > AdvisoryCatalogRecord.revision,
                    )
                    .exists(),
                )
            )
        }
        if identities
        else {}
    )
    return {
        "source_id": source_id,
        "records": [
            {
                "record_id": row.upstream_record_id,
                "catalog_event_id": row.catalog_event_id,
                "evidence_id": row.evidence_id,
                "source_sha256": row.source_sha256,
                "omissions": row.package_omission_counts,
                "state": row.state,
                "latest_catalog_event_id": latest[row.upstream_record_id].catalog_event_id,
                "latest_omissions": latest[row.upstream_record_id].package_omission_counts,
            }
            for row in selected
        ],
        "has_more": len(rows) > limit,
        "next_cursor": selected[-1].catalog_event_id if len(rows) > limit else None,
        "historical_coverage": "retained_catalog_revisions_only",
    }


def epss_missing(
    session: Session,
    *,
    snapshot_id: str | None = None,
    limit: int = 50,
    after: str = "",
    read_evidence: Callable[[str], bytes] | None = None,
) -> dict:
    """Read exact missing subjects from a pinned receipt, preserving old inventories."""
    if (
        not 1 <= limit <= 100
        or (after and re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", after) is None)
        or (
            snapshot_id is not None
            and re.fullmatch(r"gbsec:supplemental-snapshot:[0-9a-f]{40}", snapshot_id) is None
        )
    ):
        raise ValueError("missing score selection is invalid")
    snapshot = (
        session.get(SupplementalSnapshotRecord, snapshot_id)
        if snapshot_id
        else latest_snapshot(session, EPSS_SOURCE, complete_only=True)
    )
    if (
        snapshot is None
        or snapshot.source_id != EPSS_SOURCE
        or snapshot.state != "complete"
        or snapshot.mode != "public"
    ):
        raise ValueError("complete public EPSS snapshot is unavailable")
    evidence_ids = snapshot.document.get("missing_subject_evidence_ids")
    subjects: list[str] = []
    if evidence_ids is not None:
        if (
            not isinstance(evidence_ids, list)
            or len(evidence_ids) > (MAX_FACTS + 999) // 1000
            or any(not isinstance(value, str) for value in evidence_ids)
            or len(set(evidence_ids)) != len(evidence_ids)
        ):
            raise ValueError("missing score evidence inventory is invalid")
        deadline = time.monotonic() + 30
        records = (
            {
                row.id: row
                for row in session.scalars(
                    select(EvidenceRecord)
                    .where(EvidenceRecord.id.in_(evidence_ids))
                    .distinct(EvidenceRecord.id)
                    .order_by(EvidenceRecord.id, EvidenceRecord.revision.desc())
                )
            }
            if evidence_ids
            else {}
        )
        for evidence_id in evidence_ids:
            row = records.get(evidence_id)
            if (
                time.monotonic() >= deadline
                or read_evidence is None
                or row is None
                or row.source_id != EPSS_SOURCE
                or row.storage_state != "stored_immutable"
                or row.storage_key != row.sha256
                or not 1 <= row.byte_count <= 131072
            ):
                raise ValueError("missing score evidence is unavailable")
            body = read_evidence(row.storage_key)
            if len(body) != row.byte_count or sha256_id(body) != row.sha256:
                raise ValueError("missing score evidence identity differs")
            chunk = strict_json_loads(body, max_nodes=4000, max_depth=4)
            if not isinstance(chunk, list) or not 1 <= len(chunk) <= 1000:
                raise ValueError("missing score evidence shape is invalid")
            for item in chunk:
                if (
                    not isinstance(item, dict)
                    or set(item) != {"cve", "date"}
                    or snapshot.source_as_of is None
                    or item["date"] != timestamp(snapshot.source_as_of)
                    or not isinstance(item["cve"], str)
                    or CVE.fullmatch(item["cve"]) is None
                    or (subjects and item["cve"] <= subjects[-1])
                ):
                    raise ValueError("missing score subject inventory is invalid")
                subjects.append(item["cve"])
        if (
            time.monotonic() >= deadline
            or len(subjects) != snapshot.document.get("missing_count")
            or len(subjects) + snapshot.record_count != snapshot.document.get("requested_count")
            or sha256_id(canonical_json_bytes(subjects))
            != snapshot.document.get("missing_subjects_sha256")
        ):
            raise ValueError("missing score inventory does not reconcile")
    selected = [value for value in subjects if value > after][: limit + 1]
    return {
        "snapshot_id": snapshot.snapshot_id,
        "record_hash": snapshot.record_hash,
        "transport_sha256": snapshot.document.get("transport_sha256"),
        "requested_count": snapshot.document.get("requested_count"),
        "missing_count": snapshot.document.get("missing_count"),
        "identity_accounting": "complete"
        if evidence_ids is not None
        else "unavailable_legacy_receipt",
        "subjects": selected[:limit],
        "has_more": len(selected) > limit,
        "next_cursor": selected[limit - 1] if len(selected) > limit else None,
    }


def current_omission_count(session: Session, *, source_id: str) -> int:
    """Count latest known records with omissions without materializing the catalog."""
    newer = aliased(AdvisoryCatalogRecord)
    return int(
        session.scalar(
            select(func.count())
            .select_from(AdvisoryCatalogRecord)
            .where(
                AdvisoryCatalogRecord.source_id == source_id,
                AdvisoryCatalogRecord.package_omission_counts != {},
                ~select(newer.catalog_event_id)
                .where(
                    newer.source_id == AdvisoryCatalogRecord.source_id,
                    newer.upstream_record_id == AdvisoryCatalogRecord.upstream_record_id,
                    newer.revision > AdvisoryCatalogRecord.revision,
                )
                .exists(),
            )
        )
        or 0
    )
