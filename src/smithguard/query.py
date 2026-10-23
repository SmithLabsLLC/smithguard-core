"""Indexed latest-revision reads for the canonical public ledger."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Select, and_, func, select
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.orm import Session, aliased

from smithguard.db.models import (
    AffectedRangeRecord,
    ArtifactRecord,
    ClaimRecord,
    IncidentRecord,
)
from smithguard.db.package_lookup import package_name_predicate
from smithguard.version_order import exact_version_matches


@dataclass(frozen=True, slots=True)
class IncidentPosition:
    changed_at: datetime
    incident_id: str


def _latest_incident_query(
    *,
    as_of: datetime | None = None,
    incident_ids: Select[Any] | None = None,
) -> tuple[Any, Select[Any]]:
    ranked_statement = select(
        IncidentRecord.id.label("incident_id"),
        IncidentRecord.revision.label("incident_revision"),
        func.row_number()
        .over(
            partition_by=IncidentRecord.id,
            order_by=IncidentRecord.revision.desc(),
        )
        .label("position"),
    )
    if as_of is not None:
        ranked_statement = ranked_statement.where(IncidentRecord.last_changed_at <= as_of)
    if incident_ids is not None:
        ranked_statement = ranked_statement.where(IncidentRecord.id.in_(incident_ids))
    ranked = ranked_statement.subquery()
    latest = aliased(IncidentRecord)
    statement = select(latest).join(
        ranked,
        and_(
            latest.id == ranked.c.incident_id,
            latest.revision == ranked.c.incident_revision,
            ranked.c.position == 1,
        ),
    )
    return latest, statement


def latest_incident(
    session: Session,
    incident_id: str,
    *,
    public_only: bool = False,
) -> IncidentRecord | None:
    record = session.scalar(
        select(IncidentRecord)
        .where(IncidentRecord.id == incident_id)
        .order_by(IncidentRecord.revision.desc())
        .limit(1)
    )
    if record is not None and public_only and record.data_classification != "public":
        return None
    return record


def incident_ids_for_alias(session: Session, alias_id: str) -> tuple[str, ...]:
    latest, statement = _latest_incident_query()
    statement = statement.where(latest.alias_ids.contains([alias_id])).order_by(latest.id)
    return tuple(record.id for record in session.scalars(statement))


def list_latest_incidents(
    session: Session,
    *,
    public_only: bool = True,
    limit: int = 100,
    after: IncidentPosition | None = None,
    as_of: datetime | None = None,
) -> tuple[IncidentRecord, ...]:
    if not 1 <= limit <= 10_001:
        raise ValueError("incident query limit must be between 1 and 10001")
    latest, statement = _latest_incident_query(as_of=as_of)
    if public_only:
        statement = statement.where(latest.data_classification == "public")
    if after is not None:
        statement = statement.where(
            (latest.last_changed_at < after.changed_at)
            | ((latest.last_changed_at == after.changed_at) & (latest.id > after.incident_id))
        )
    statement = statement.order_by(latest.last_changed_at.desc(), latest.id).limit(limit)
    return tuple(session.scalars(statement))


def latest_incidents_for_artifacts(
    session: Session,
    artifact_ids: Sequence[str],
    *,
    public_only: bool = True,
    limit: int = 101,
) -> tuple[IncidentRecord, ...]:
    if not artifact_ids:
        return ()
    if not 1 <= limit <= 101:
        raise ValueError("incident correlation limit must be between 1 and 101")
    distinct_artifact_ids = list(dict.fromkeys(artifact_ids))
    candidate_incident_ids = (
        select(IncidentRecord.id)
        .where(IncidentRecord.artifact_ids.has_any(array(distinct_artifact_ids)))
        .distinct()
    )
    latest, statement = _latest_incident_query(incident_ids=candidate_incident_ids)
    if public_only:
        statement = statement.where(latest.data_classification == "public")
    statement = statement.where(
        latest.id.in_(candidate_incident_ids),
        latest.artifact_ids.has_any(array(distinct_artifact_ids)),
    )
    return tuple(
        session.scalars(statement.order_by(latest.last_changed_at.desc(), latest.id).limit(limit))
    )


# Retained artifacts per package peak at a few hundred (npm malware); the scan is bounded.
ARTIFACT_VERSION_SCAN_LIMIT = 2000


class ArtifactCandidateBoundExceeded(ValueError):
    """A package has more retained artifacts than one assessment may scan."""


def public_artifact_candidates(
    session: Session,
    *,
    ecosystem: str,
    normalized_name: str,
    version: str | None,
    digest: str | None,
    limit: int = 101,
) -> tuple[ArtifactRecord, ...]:
    if not 1 <= limit <= 101:
        raise ValueError("artifact candidate limit must be between 1 and 101")
    candidate_artifact_ids = (
        select(ArtifactRecord.id)
        .where(
            package_name_predicate(
                ArtifactRecord.name,
                ecosystem_column=ArtifactRecord.ecosystem,
                ecosystem=ecosystem,
                name=normalized_name,
            ),
        )
        .distinct()
    )
    ranked = (
        select(
            ArtifactRecord.id.label("artifact_id"),
            ArtifactRecord.revision.label("artifact_revision"),
            func.row_number()
            .over(partition_by=ArtifactRecord.id, order_by=ArtifactRecord.revision.desc())
            .label("position"),
        )
        .where(ArtifactRecord.id.in_(candidate_artifact_ids))
        .subquery()
    )
    latest = aliased(ArtifactRecord)
    statement = (
        select(latest)
        .join(
            ranked,
            and_(
                latest.id == ranked.c.artifact_id,
                latest.revision == ranked.c.artifact_revision,
                ranked.c.position == 1,
            ),
        )
        .where(
            latest.data_classification == "public",
            package_name_predicate(
                latest.name,
                ecosystem_column=latest.ecosystem,
                ecosystem=ecosystem,
                name=normalized_name,
            ),
        )
    )
    if digest is not None:
        statement = statement.where(latest.digest == digest)
    if digest is not None or version is None:
        return tuple(session.scalars(statement.order_by(latest.id).limit(limit)))
    # Retained artifacts keep their original spelling, so the version is matched with
    # the ecosystem's own equality (Go "v", PEP 440, qualifier aliases, case) in Python
    # over the package's bounded artifact set; undecided spellings are kept for range
    # evaluation to decide.
    rows = tuple(
        session.scalars(statement.order_by(latest.id).limit(ARTIFACT_VERSION_SCAN_LIMIT + 1))
    )
    if len(rows) > ARTIFACT_VERSION_SCAN_LIMIT:
        raise ArtifactCandidateBoundExceeded("package has more artifacts than the scan bound")
    return tuple(
        row
        for row in rows
        if row.version is None
        or exact_version_matches(ecosystem, version, row.version) is not False
    )[:limit]


def latest_affected_ranges_for_ids(
    session: Session,
    *,
    range_ids: Sequence[str],
    artifact_ids: Sequence[str],
    limit: int = 501,
) -> tuple[AffectedRangeRecord, ...]:
    if not range_ids or not artifact_ids:
        return ()
    if not 1 <= limit <= 501:
        raise ValueError("affected range correlation limit must be between 1 and 501")
    ranked = (
        select(
            AffectedRangeRecord.id.label("range_id"),
            AffectedRangeRecord.revision.label("range_revision"),
            func.row_number()
            .over(
                partition_by=AffectedRangeRecord.id,
                order_by=AffectedRangeRecord.revision.desc(),
            )
            .label("position"),
        )
        .where(AffectedRangeRecord.id.in_(tuple(dict.fromkeys(range_ids))))
        .subquery()
    )
    latest = aliased(AffectedRangeRecord)
    return tuple(
        session.scalars(
            select(latest)
            .join(
                ranked,
                and_(
                    latest.id == ranked.c.range_id,
                    latest.revision == ranked.c.range_revision,
                    ranked.c.position == 1,
                ),
            )
            .where(
                latest.artifact_id.in_(tuple(dict.fromkeys(artifact_ids))),
                latest.data_classification == "public",
            )
            .order_by(latest.id)
            .limit(limit)
        )
    )


def latest_public_claims_for_ids(
    session: Session,
    claim_ids: Sequence[str],
    *,
    limit: int = 501,
) -> tuple[ClaimRecord, ...]:
    if not claim_ids:
        return ()
    if not 1 <= limit <= 501:
        raise ValueError("claim correlation limit must be between 1 and 501")
    ranked = (
        select(
            ClaimRecord.id.label("claim_id"),
            ClaimRecord.revision.label("claim_revision"),
            func.row_number()
            .over(partition_by=ClaimRecord.id, order_by=ClaimRecord.revision.desc())
            .label("position"),
        )
        .where(ClaimRecord.id.in_(tuple(dict.fromkeys(claim_ids))))
        .subquery()
    )
    latest = aliased(ClaimRecord)
    return tuple(
        session.scalars(
            select(latest)
            .join(
                ranked,
                and_(
                    latest.id == ranked.c.claim_id,
                    latest.revision == ranked.c.claim_revision,
                    ranked.c.position == 1,
                ),
            )
            .where(latest.data_classification == "public")
            .order_by(latest.id)
            .limit(limit)
        )
    )
