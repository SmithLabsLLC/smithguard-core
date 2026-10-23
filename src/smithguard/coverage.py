"""Honest per-ecosystem coverage derived from canonical local evidence."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Any

from sqlalchemy import (
    String,
    and_,
    column,
    func,
    literal,
    literal_column,
    or_,
    select,
    union_all,
    values,
)
from sqlalchemy.orm import Session

from smithguard.advisory_catalog import OPENSSF_SOURCE_ID
from smithguard.collection_records import unresolved_count
from smithguard.collectors import GITHUB_ADVISORY
from smithguard.db.models import (
    AdvisoryCatalogManifestRecord,
    AdvisoryPackageRecord,
    AffectedRangeRecord,
    ArtifactRecord,
    ClaimRecord,
    CollectorProgressRecord,
)
from smithguard.ecosystems import CANONICAL_ECOSYSTEMS
from smithguard.identifiers import timestamp
from smithguard.openssf_budget import CATALOG_FRESHNESS_MAX_AGE
from smithguard.openssf_git import MAX_PAGE_SIZE
from smithguard.source_accounting import current_omission_count
from smithguard.supplemental_store import (
    EPSS_SOURCE,
    GO_SOURCE,
    KEV_SOURCE,
    MAX_AGE,
    RUST_SOURCE,
    load_latest_receipts,
    source_state,
)
from smithguard.version_order import ORDERED_ECOSYSTEMS

UPDATE_FRESHNESS_MAX_AGE = timedelta(hours=2, minutes=30)
HISTORICAL_PROGRESS_MAX_AGE = timedelta(hours=26)
COVERAGE_CACHE_MAX_AGE = timedelta(minutes=5)
COVERAGE_ECOSYSTEMS = CANONICAL_ECOSYSTEMS


@dataclass(frozen=True, slots=True)
class CoverageLane:
    ecosystem: str
    stage: str
    result: str
    as_of: str
    unknowns: tuple[str, ...]
    continuous_monitoring_claimed: bool = False
    version_range_evaluation: str = "not_supported"


@dataclass(frozen=True, slots=True)
class CollectionFreshness:
    lane: str
    latest_state: str | None
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    stale_after: datetime | None
    state: str


@dataclass(frozen=True, slots=True)
class SourceCoverageLane:
    source_id: str
    lane: str
    record_type: str
    state: str
    page_count: int
    source_record_count: int
    normalized_record_count: int
    oldest_published_at: str | None
    newest_published_at: str | None
    last_attempt_at: str | None
    last_success_at: str | None
    stale_after: str | None
    freshness_state: str
    ecosystems: tuple[str, ...]
    unknowns: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CoverageReport:
    measured_at: str
    human_review_hours: float
    live_collector_uptime: str
    lanes: tuple[CoverageLane, ...]
    source_lanes: tuple[SourceCoverageLane, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "measured_at": self.measured_at,
            "human_review_hours": self.human_review_hours,
            "live_collector_uptime": self.live_collector_uptime,
            "lanes": [
                {
                    "ecosystem": lane.ecosystem,
                    "stage": lane.stage,
                    "result": lane.result,
                    "as_of": lane.as_of,
                    "unknowns": list(lane.unknowns),
                    "continuous_monitoring_claimed": (lane.continuous_monitoring_claimed),
                    "version_range_evaluation": lane.version_range_evaluation,
                }
                for lane in self.lanes
            ],
            "source_lanes": [
                {
                    "source_id": lane.source_id,
                    "lane": lane.lane,
                    "record_type": lane.record_type,
                    "state": lane.state,
                    "page_count": lane.page_count,
                    "source_record_count": lane.source_record_count,
                    "normalized_record_count": lane.normalized_record_count,
                    "oldest_published_at": lane.oldest_published_at,
                    "newest_published_at": lane.newest_published_at,
                    "last_attempt_at": lane.last_attempt_at,
                    "last_success_at": lane.last_success_at,
                    "stale_after": lane.stale_after,
                    "freshness_state": lane.freshness_state,
                    "ecosystems": list(lane.ecosystems),
                    "unknowns": list(lane.unknowns),
                }
                for lane in self.source_lanes
            ],
        }


@dataclass(slots=True)
class _CoverageReportCache:
    """One report per argument set, rebuilt outside the read lock.

    Readers never wait for a rebuild while a report younger than ``max_age`` exists; the
    API refreshes it in the background before it ages out and disables builds on
    cache misses. Standalone callers can explicitly retain synchronous cold builds.
    """

    key: tuple[Any, ...] | None = None
    report: CoverageReport | None = None
    generated_at: datetime | None = None
    max_age: timedelta = COVERAGE_CACHE_MAX_AGE
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _build_lock: Lock = field(default_factory=Lock, init=False, repr=False)

    @staticmethod
    def _key(session: Session, **arguments: Any) -> tuple[Any, ...]:
        return (
            id(session.get_bind()),
            arguments["human_review_hours"],
            arguments["live_collector_uptime"],
            arguments["evidence_label"],
            arguments["expected_governance_policy_sha256"],
        )

    def _current(self, key: tuple[Any, ...], measured_at: datetime) -> CoverageReport | None:
        with self._lock:
            age = measured_at - self.generated_at if self.generated_at is not None else None
            if (
                self.report is not None
                and self.key == key
                and age is not None
                and timedelta(0) <= age < self.max_age
            ):
                return self.report
            return None

    def get(
        self,
        session: Session,
        *,
        measured_at: datetime,
        allow_build: bool = True,
        **arguments: Any,
    ) -> CoverageReport:
        key = self._key(session, **arguments)
        current = self._current(key, measured_at)
        if current is not None:
            return current
        if not allow_build:
            raise CoverageReportUnavailable("no fresh coverage report is available")
        if not self._build_lock.acquire(blocking=False):
            raise CoverageReportUnavailable("coverage report is being rebuilt")
        try:
            # Recheck after acquiring ownership: a build may have just completed.
            current = self._current(key, measured_at)
            if current is not None:
                return current
            return self._build(session, key=key, measured_at=measured_at, **arguments)
        finally:
            self._build_lock.release()

    def refresh(
        self,
        session: Session,
        *,
        measured_at: datetime,
        checkpoint: Callable[[], None] | None = None,
        **arguments: Any,
    ) -> None:
        """Rebuild now (the background refresher), without blocking readers."""
        key = self._key(session, **arguments)
        # One builder owns the report. A caller can retry a busy refresh without
        # adding another database worker behind a cold request or another runtime.
        if not self._build_lock.acquire(blocking=False):
            raise CoverageReportUnavailable("coverage report is being rebuilt")
        try:
            self._build(
                session, key=key, measured_at=measured_at, checkpoint=checkpoint, **arguments
            )
        finally:
            self._build_lock.release()

    def _build(
        self,
        session: Session,
        *,
        key: tuple[Any, ...],
        measured_at: datetime,
        checkpoint: Callable[[], None] | None = None,
        **arguments: Any,
    ) -> CoverageReport:
        if checkpoint is not None:
            checkpoint()
        report = _build_coverage_report(session, measured_at=measured_at, **arguments)
        if checkpoint is not None:
            checkpoint()
        with self._lock:
            self.key = key
            self.report = report
            self.generated_at = measured_at
        return report

    def clear(self) -> None:
        with self._lock:
            self.key = None
            self.report = None
            self.generated_at = None


class CoverageReportUnavailable(RuntimeError):
    """No fresh report is available for this caller without a new owned build."""


_COVERAGE_REPORT_CACHE = _CoverageReportCache()


@dataclass(frozen=True, slots=True)
class _CoveragePresence:
    artifacts: bool
    all_immutable: bool
    ranges: bool


def _ecosystem_values() -> Any:
    return (
        values(column("ecosystem", String))
        .data([(ecosystem,) for ecosystem in COVERAGE_ECOSYSTEMS])
        .cte("coverage_ecosystems")
    )


def _presence_query() -> Any:
    ecosystems = _ecosystem_values()
    artifact_filter = (
        ArtifactRecord.ecosystem == ecosystems.c.ecosystem,
        ArtifactRecord.data_classification == "public",
    )
    artifacts = select(ArtifactRecord.id).where(*artifact_filter).exists()
    mutable = (
        select(ArtifactRecord.id).where(*artifact_filter, ArtifactRecord.digest.is_(None)).exists()
    )
    ranges = (
        select(AffectedRangeRecord.id)
        .select_from(ArtifactRecord)
        .join(AffectedRangeRecord, AffectedRangeRecord.artifact_id == ArtifactRecord.id)
        .where(*artifact_filter, AffectedRangeRecord.data_classification == "public")
        .exists()
    )
    catalog = (
        select(AdvisoryPackageRecord.package_event_id)
        .where(
            AdvisoryPackageRecord.ecosystem == ecosystems.c.ecosystem,
            # A literal preserves eligibility for the partial index under a generic plan.
            AdvisoryPackageRecord.state == literal_column("'active'"),
        )
        .offset(0)
        .exists()
    )
    return select(
        ecosystems.c.ecosystem,
        artifacts.label("artifacts"),
        mutable.label("mutable"),
        ranges.label("ranges"),
        catalog.label("catalog"),
    ).order_by(ecosystems.c.ecosystem)


def _presence_by_ecosystem(session: Session) -> dict[str, _CoveragePresence]:
    # These are exactly the predicates consumed by the stage projection. Counting
    # every historical row adds no information to the public coverage contract.
    return {
        str(ecosystem): _CoveragePresence(
            artifacts=bool(artifacts or catalog),
            all_immutable=bool(not mutable and not catalog),
            ranges=bool(ranges or catalog),
        )
        for ecosystem, artifacts, mutable, ranges, catalog in session.execute(_presence_query())
    }


def _source_ecosystems_query(source_id: str) -> Any:
    # SQLAlchemy safely quotes this internal source value at execution. Fixed
    # ecosystem branches keep absent-ecosystem statistics visible to the planner.
    source = literal(source_id, type_=String, literal_execute=True)
    source_claim = (
        ClaimRecord.provenance.op("->>", return_type=String)(literal_column("'source_id'"))
        == source,
        ClaimRecord.data_classification == "public",
    )
    any_claims = select(ClaimRecord.id).where(*source_claim).exists()
    branches = []
    for name in (*COVERAGE_ECOSYSTEMS, "unknown"):
        # Names come only from the fixed contract enum, never from a request; a
        # literal (rendered and quoted by SQLAlchemy) keeps planner statistics visible.
        ecosystem = literal(name, type_=String, literal_execute=True)
        claimed_artifact = (
            select(ClaimRecord.id)
            .where(ClaimRecord.subject_id == ArtifactRecord.id, *source_claim)
            .correlate(ArtifactRecord)
            .offset(0)
            .exists()
        )
        claimed = (
            select(ArtifactRecord.id)
            .where(
                ArtifactRecord.ecosystem == ecosystem,
                ArtifactRecord.data_classification == "public",
                claimed_artifact,
            )
            .exists()
        )
        # An ordered range seek uses (ecosystem, source_id) even for an absent
        # pair. Equality on the first source at/above the target is exactly
        # membership, without the planner guessing an early sequential match.
        first_catalog_source = (
            select(AdvisoryPackageRecord.source_id)
            .where(
                AdvisoryPackageRecord.ecosystem == ecosystem,
                AdvisoryPackageRecord.source_id >= source,
            )
            .order_by(AdvisoryPackageRecord.source_id)
            .limit(1)
            .scalar_subquery()
        )
        branches.append(
            select(ecosystem.label("ecosystem")).where(
                or_(first_catalog_source == source, and_(any_claims, claimed))
            )
        )
    membership = union_all(*branches).subquery()
    # Preserve historical memberships, withdrawals, restricted-claim exclusion
    # and the contract's retained unknown ecosystem.
    return select(membership.c.ecosystem).order_by(membership.c.ecosystem)


def _source_ecosystems(session: Session, source_id: str) -> tuple[str, ...]:
    return tuple(session.scalars(_source_ecosystems_query(source_id)))


def range_evaluation(ecosystem: str) -> str:
    """How this ecosystem's version ranges are decided (the matcher's own table)."""
    if ecosystem in ORDERED_ECOSYSTEMS:
        return "ecosystem_rules"
    if ecosystem in {"oci", "docker"}:
        return "digest_only"
    return "not_supported"


def collection_freshness(
    session: Session,
    *,
    source_id: str,
    lane: str,
    measured_at: datetime,
    expected_governance_policy_sha256: str | None = None,
    progress: CollectorProgressRecord | None = None,
    progress_loaded: bool = False,
    last_success: datetime | None = None,
    last_success_loaded: bool = False,
    segment: str,
) -> CollectionFreshness:
    """Return explicit attempt and success freshness for one catalog lane."""
    if lane not in {"historical", "updates"}:
        raise ValueError("collection lane is invalid")
    if not progress_loaded:
        progress = session.scalar(
            select(CollectorProgressRecord)
            .where(
                CollectorProgressRecord.source_id == source_id,
                CollectorProgressRecord.segment == segment,
                CollectorProgressRecord.lane == lane,
            )
            .order_by(CollectorProgressRecord.sequence.desc())
            .limit(1)
        )
    if progress is None:
        return CollectionFreshness(
            lane=lane,
            latest_state=None,
            last_attempt_at=None,
            last_success_at=None,
            stale_after=None,
            state="missing",
        )
    if not last_success_loaded:
        if lane == "updates":
            # How far the data has caught up: the end of the newest completed window.
            # An in-progress page of an old window no longer counts as fresh.
            last_success = session.scalar(
                select(func.max(CollectorProgressRecord.window_ended_at)).where(
                    CollectorProgressRecord.source_id == source_id,
                    CollectorProgressRecord.segment == segment,
                    CollectorProgressRecord.lane == lane,
                    CollectorProgressRecord.state == "complete",
                )
            )
        else:
            last_success = session.scalar(
                select(CollectorProgressRecord.occurred_at)
                .where(
                    CollectorProgressRecord.source_id == source_id,
                    CollectorProgressRecord.segment == segment,
                    CollectorProgressRecord.lane == lane,
                    CollectorProgressRecord.state != "failed",
                )
                .order_by(CollectorProgressRecord.sequence.desc())
                .limit(1)
            )
    freshness_age = UPDATE_FRESHNESS_MAX_AGE if lane == "updates" else HISTORICAL_PROGRESS_MAX_AGE
    stale_at = last_success + freshness_age if last_success is not None else None
    if progress.state == "failed":
        state = "failed"
    elif lane == "historical" and progress.state == "complete":
        manifest = session.scalar(
            select(AdvisoryCatalogManifestRecord)
            .where(
                AdvisoryCatalogManifestRecord.source_id == source_id,
                AdvisoryCatalogManifestRecord.segment == segment,
            )
            .order_by(AdvisoryCatalogManifestRecord.sequence.desc())
            .limit(1)
        )
        expected_snapshot = (
            timestamp(progress.window_ended_at) if progress.window_ended_at is not None else None
        )
        if manifest is None:
            state = "missing"
            last_success = None
        elif manifest.state == "failed":
            state = "failed"
            last_success = None
        elif (
            manifest.state != "complete"
            or expected_snapshot is None
            or manifest.source_snapshot != expected_snapshot
        ):
            state = "unresolved"
            last_success = None
        else:
            state = "complete"
            last_success = manifest.observed_at
        return CollectionFreshness(
            lane=lane,
            latest_state=progress.state,
            last_attempt_at=progress.occurred_at,
            last_success_at=last_success,
            stale_after=None,
            state=state,
        )
    elif stale_at is None:
        state = "missing"
    elif measured_at > stale_at:
        # Behind, but still making successful progress (a page accepted or an old
        # window completed recently): a backlog being worked through, not a stopped
        # collector. Callers disclose it without treating it as an outage; a failed
        # or silent collector still becomes stale.
        catching_up = (
            lane == "updates"
            and progress.state in {"in_progress", "complete"}
            and progress.occurred_at is not None
            and timedelta(0) <= measured_at - progress.occurred_at <= freshness_age
        )
        state = "catching_up" if catching_up else "stale"
    else:
        state = "fresh"
    return CollectionFreshness(
        lane=lane,
        latest_state=progress.state,
        last_attempt_at=progress.occurred_at,
        last_success_at=last_success,
        stale_after=stale_at,
        state=state,
    )


def catalog_collection_freshness(
    session: Session,
    *,
    lane: str,
    measured_at: datetime,
    expected_governance_policy_sha256: str | None = None,
) -> CollectionFreshness:
    """Aggregate the three complete GitHub catalog segments fail-closed."""
    segments = ("malware", "reviewed", "unreviewed")
    results = tuple(
        collection_freshness(
            session,
            source_id=GITHUB_ADVISORY,
            lane=lane,
            measured_at=measured_at,
            expected_governance_policy_sha256=expected_governance_policy_sha256,
            segment=segment,
        )
        for segment in segments
    )
    state_priority = (
        "failed",
        "unresolved",
        "reconciling",
        "missing",
        "stale",
        "catching_up",
    )
    state = next(
        (candidate for candidate in state_priority if any(r.state == candidate for r in results)),
        "complete"
        if lane == "historical" and all(r.state == "complete" for r in results)
        else "fresh"
        if lane == "updates" and all(r.state == "fresh" for r in results)
        else "in_progress",
    )
    latest_state = (
        "failed"
        if any(r.latest_state == "failed" for r in results)
        else "complete"
        if all(r.latest_state == "complete" for r in results)
        else "in_progress"
        if any(r.latest_state is not None for r in results)
        else None
    )
    attempts = [r.last_attempt_at for r in results if r.last_attempt_at is not None]
    successes = [r.last_success_at for r in results if r.last_success_at is not None]
    stale_values = [r.stale_after for r in results if r.stale_after is not None]
    return CollectionFreshness(
        lane=lane,
        latest_state=latest_state,
        last_attempt_at=min(attempts) if attempts else None,
        last_success_at=min(successes) if len(successes) == len(results) else None,
        stale_after=min(stale_values) if len(stale_values) == len(results) else None,
        state=state,
    )


def _source_lane(
    session: Session,
    *,
    source_id: str,
    lane: str,
    record_type: str,
    measured_at: datetime,
    expected_governance_policy_sha256: str | None = None,
    ecosystems: tuple[str, ...] | None = None,
    segment: str,
    progress: CollectorProgressRecord | None = None,
    progress_loaded: bool = False,
    last_success: datetime | None = None,
    last_success_loaded: bool = False,
) -> SourceCoverageLane:
    if not progress_loaded:
        progress = session.scalar(
            select(CollectorProgressRecord)
            .where(
                CollectorProgressRecord.source_id == source_id,
                CollectorProgressRecord.segment == segment,
                CollectorProgressRecord.lane == lane,
            )
            .order_by(CollectorProgressRecord.sequence.desc())
            .limit(1)
        )
    if ecosystems is None:
        ecosystems = _source_ecosystems(session, source_id)
    freshness = collection_freshness(
        session,
        source_id=source_id,
        lane=lane,
        measured_at=measured_at,
        expected_governance_policy_sha256=expected_governance_policy_sha256,
        progress=progress,
        progress_loaded=True,
        last_success=last_success,
        last_success_loaded=last_success_loaded,
        segment=segment,
    )
    if progress is None:
        return SourceCoverageLane(
            source_id=source_id,
            lane=lane,
            record_type=record_type,
            state="not_started",
            page_count=0,
            source_record_count=0,
            normalized_record_count=0,
            oldest_published_at=None,
            newest_published_at=None,
            last_attempt_at=None,
            last_success_at=None,
            stale_after=None,
            freshness_state="missing",
            ecosystems=ecosystems,
            unknowns=("This exact source and record-type lane has not been collected.",),
        )
    freshness_state = freshness.state
    display_state = progress.state
    if lane == "historical" and progress.state == "complete" and freshness_state != "complete":
        display_state = "failed" if freshness_state == "failed" else "in_progress"
    unknowns: list[str] = []
    if lane == "historical" and display_state != "complete":
        unknowns.append("Older public records may still be missing.")
    if lane == "updates":
        unknowns.append(
            "Update coverage applies only through the last completed or attempted window."
        )
    if freshness_state == "failed":
        unknowns.append("The latest collection attempt failed.")
    elif freshness_state == "stale":
        unknowns.append("The latest successful collection is outside its freshness target.")
    elif freshness_state == "catching_up":
        # The public contract has no separate value: the data is behind, so it reads
        # as stale, with the reason stated.
        freshness_state = "stale"
        unknowns.append(
            "This lane is working through a backlog of source updates; the newest "
            "records may be missing until it catches up."
        )
    elif freshness_state == "missing" and lane == "historical" and progress.state == "complete":
        unknowns.append(
            "Historical collection completed, but its exact source inventory proof is unavailable."
        )
    elif freshness_state == "reconciling":
        unknowns.append("Authenticated source inventory reconciliation is still in progress.")
    elif freshness_state == "unresolved":
        unknowns.append(
            "Authenticated source inventory reconciliation has unresolved drift or "
            "uses a superseded governance policy."
        )
    if progress.reason_code in {
        "github_page_accepted_with_quarantine",
        "github_lane_complete_with_quarantine",
        "github_page_quarantined_retryable",
    }:
        unknowns.append(
            "One or more source records were quarantined, so this lane has an unresolved "
            "coverage gap."
        )
    if source_id == "gbsec:source:github-advisory-database" and segment != "legacy-malware":
        missing_records = unresolved_count(session, source_id=source_id, segment=segment)
        if missing_records:
            unknowns.append(
                f"{missing_records} source record(s) have unresolved collection omissions; "
                "a fresh update does not establish complete coverage."
            )
    if not ecosystems:
        unknowns.append("No supported exact artifact ecosystem has been accepted.")
    return SourceCoverageLane(
        source_id=source_id,
        lane=lane,
        record_type=record_type,
        state=display_state,
        page_count=progress.page_count,
        source_record_count=progress.source_record_count,
        normalized_record_count=progress.normalized_record_count,
        oldest_published_at=(
            timestamp(progress.oldest_published_at)
            if progress.oldest_published_at is not None
            else None
        ),
        newest_published_at=(
            timestamp(progress.newest_published_at)
            if progress.newest_published_at is not None
            else None
        ),
        last_attempt_at=(
            timestamp(freshness.last_attempt_at) if freshness.last_attempt_at is not None else None
        ),
        last_success_at=(
            timestamp(freshness.last_success_at) if freshness.last_success_at is not None else None
        ),
        stale_after=(
            timestamp(freshness.stale_after) if freshness.stale_after is not None else None
        ),
        freshness_state=freshness_state,
        ecosystems=ecosystems,
        unknowns=tuple(unknowns),
    )


def _openssf_catalog_lane(
    *,
    manifests: tuple[AdvisoryCatalogManifestRecord, ...],
    complete_manifests: tuple[AdvisoryCatalogManifestRecord, ...],
    terminal_manifests: tuple[AdvisoryCatalogManifestRecord, ...],
    ecosystems: tuple[str, ...],
    measured_at: datetime,
    omission_record_count: int = 0,
) -> SourceCoverageLane:
    """Keep latest attempt separate from the last proven complete source pair."""
    expected_segments = {"openssf-malicious", "openssf-withdrawn"}
    present = {row.segment for row in complete_manifests}
    pair_valid = (
        present == expected_segments
        and len({row.source_snapshot.partition(":")[0] for row in complete_manifests}) == 1
        and len({row.observed_at for row in complete_manifests}) == 1
    )
    unknowns: list[str] = []
    if omission_record_count:
        unknowns.append(
            f"{omission_record_count} latest retained OpenSSF record(s), active or withdrawn, "
            "have package omissions. This can include work from an unfinished collection; "
            "complete tree acquisition does not imply complete package applicability."
        )
    last_attempt = max((row.observed_at for row in manifests), default=None)
    last_success = (
        max((row.observed_at for row in complete_manifests), default=None) if pair_valid else None
    )
    stale_after = last_success + CATALOG_FRESHNESS_MAX_AGE if last_success is not None else None
    if not manifests:
        state, freshness_state = "not_started", "missing"
        unknowns.append("The complete OpenSSF active and withdrawn catalog has not been collected.")
    elif any(row.state == "failed" for row in terminal_manifests):
        state, freshness_state = "failed", "failed"
        unknowns.append("The latest OpenSSF catalog collection attempt failed.")
    elif pair_valid:
        state = "complete"
        freshness_state = "complete" if last_success <= measured_at <= stale_after else "stale"
        if freshness_state == "stale":
            unknowns.append("The complete OpenSSF catalog is stale or future-dated.")
    elif present != expected_segments:
        state, freshness_state = "in_progress", "missing"
        unknowns.append(
            "The OpenSSF catalog proof is missing required segment(s): "
            + ", ".join(sorted(expected_segments - present))
            + "."
        )
    else:
        state, freshness_state = "failed", "failed"
        unknowns.append(
            "The active and withdrawn OpenSSF catalog proofs do not describe one source snapshot."
        )
    if not ecosystems:
        unknowns.append("No supported exact artifact ecosystem has been accepted.")
    source_record_count = sum(row.record_count for row in complete_manifests) if pair_valid else 0
    return SourceCoverageLane(
        source_id=OPENSSF_SOURCE_ID,
        lane="historical",
        record_type="malicious_package_catalog",
        state=state,
        page_count=(source_record_count + MAX_PAGE_SIZE - 1) // MAX_PAGE_SIZE,
        source_record_count=source_record_count,
        normalized_record_count=sum(row.package_entry_count for row in complete_manifests)
        if pair_valid
        else 0,
        oldest_published_at=None,
        newest_published_at=None,
        last_attempt_at=timestamp(last_attempt) if last_attempt is not None else None,
        last_success_at=timestamp(last_success) if last_success is not None else None,
        stale_after=timestamp(stale_after) if stale_after is not None else None,
        freshness_state=freshness_state,
        ecosystems=ecosystems,
        unknowns=tuple(unknowns),
    )


def _openssf_manifest_rows(
    session: Session,
) -> tuple[
    tuple[AdvisoryCatalogManifestRecord, ...],
    tuple[AdvisoryCatalogManifestRecord, ...],
    tuple[AdvisoryCatalogManifestRecord, ...],
]:
    """Latest, latest complete and latest terminal OpenSSF manifests per segment."""
    latest_manifest_sequences = (
        select(
            AdvisoryCatalogManifestRecord.source_id.label("source_id"),
            AdvisoryCatalogManifestRecord.segment.label("segment"),
            func.max(AdvisoryCatalogManifestRecord.sequence).label("sequence"),
        )
        .where(
            AdvisoryCatalogManifestRecord.source_id == OPENSSF_SOURCE_ID,
            AdvisoryCatalogManifestRecord.segment.in_(("openssf-malicious", "openssf-withdrawn")),
        )
        .group_by(
            AdvisoryCatalogManifestRecord.source_id,
            AdvisoryCatalogManifestRecord.segment,
        )
        .subquery()
    )
    openssf_complete_manifests = tuple(
        session.scalars(
            select(AdvisoryCatalogManifestRecord)
            .where(
                AdvisoryCatalogManifestRecord.source_id == OPENSSF_SOURCE_ID,
                AdvisoryCatalogManifestRecord.state == "complete",
                AdvisoryCatalogManifestRecord.segment.in_(
                    ("openssf-malicious", "openssf-withdrawn")
                ),
            )
            .distinct(AdvisoryCatalogManifestRecord.segment)
            .order_by(
                AdvisoryCatalogManifestRecord.segment, AdvisoryCatalogManifestRecord.sequence.desc()
            )
        )
    )
    openssf_terminal_manifests = tuple(
        session.scalars(
            select(AdvisoryCatalogManifestRecord)
            .where(
                AdvisoryCatalogManifestRecord.source_id == OPENSSF_SOURCE_ID,
                AdvisoryCatalogManifestRecord.state.in_(("complete", "failed")),
                AdvisoryCatalogManifestRecord.segment.in_(
                    ("openssf-malicious", "openssf-withdrawn")
                ),
            )
            .distinct(AdvisoryCatalogManifestRecord.segment)
            .order_by(
                AdvisoryCatalogManifestRecord.segment, AdvisoryCatalogManifestRecord.sequence.desc()
            )
        )
    )
    openssf_manifests = tuple(
        session.scalars(
            select(AdvisoryCatalogManifestRecord)
            .join(
                latest_manifest_sequences,
                and_(
                    AdvisoryCatalogManifestRecord.source_id
                    == latest_manifest_sequences.c.source_id,
                    AdvisoryCatalogManifestRecord.segment == latest_manifest_sequences.c.segment,
                    AdvisoryCatalogManifestRecord.sequence == latest_manifest_sequences.c.sequence,
                ),
            )
            .order_by(AdvisoryCatalogManifestRecord.segment)
        )
    )
    return openssf_manifests, openssf_complete_manifests, openssf_terminal_manifests


def openssf_catalog_freshness(session: Session, *, measured_at: datetime) -> str:
    """The OpenSSF catalog's freshness state, as the coverage report computes it."""
    manifests, complete, terminal = _openssf_manifest_rows(session)
    return _openssf_catalog_lane(
        manifests=manifests,
        complete_manifests=complete,
        terminal_manifests=terminal,
        ecosystems=(),
        measured_at=measured_at,
    ).freshness_state


def _supplemental_coverage_lanes(
    session: Session, *, measured_at: datetime
) -> tuple[SourceCoverageLane, ...]:
    result = []
    receipts = load_latest_receipts(session)
    for source_id, record_type, ecosystems in (
        (EPSS_SOURCE, "exploit_prediction_context", COVERAGE_ECOSYSTEMS),
        (KEV_SOURCE, "known_exploited_context", COVERAGE_ECOSYSTEMS),
        (RUST_SOURCE, "origin_advisory", ("rust",)),
        (GO_SOURCE, "origin_advisory", ("go",)),
    ):
        state, complete = source_state(session, source_id, now=measured_at, receipts=receipts)
        attempt = receipts[source_id].attempt
        omitted = complete.document.get("omission_counts", {}) if complete else {}
        unknowns = ["Context never proves application reachability or absence of risk."]
        missing_scores = complete.document.get("missing_count", 0) if complete else 0
        if source_id == EPSS_SOURCE and missing_scores:
            unknowns.append(
                f"{missing_scores} requested CVEs had no EPSS score in this snapshot; "
                "a missing score is not zero."
            )
        elif omitted:
            unknowns.append(
                "Unsupported or informational source entries are counted as omissions: "
                + ", ".join(f"{key}={value}" for key, value in sorted(omitted.items()))
            )
        if source_id in (EPSS_SOURCE, KEV_SOURCE):
            unknowns.append(
                "Exact CVE prioritization context does not decide affected package versions."
            )
        result.append(
            SourceCoverageLane(
                source_id=source_id,
                lane="updates",
                record_type=record_type,
                state="not_started" if attempt is None else attempt.state,
                page_count=1 if complete else 0,
                source_record_count=int(
                    complete.document.get("validated_rows", complete.record_count)
                )
                if complete
                else 0,
                normalized_record_count=complete.record_count if complete else 0,
                oldest_published_at=None,
                newest_published_at=None,
                last_attempt_at=timestamp(attempt.observed_at) if attempt else None,
                last_success_at=timestamp(complete.observed_at) if complete else None,
                stale_after=timestamp(complete.observed_at + MAX_AGE) if complete else None,
                freshness_state=state,
                ecosystems=tuple(ecosystems),
                unknowns=tuple(unknowns),
            )
        )
    return tuple(result)


def _build_coverage_report(
    session: Session,
    *,
    measured_at: datetime,
    human_review_hours: float = 0.0,
    live_collector_uptime: str = "not_measured_no_live_collectors",
    evidence_label: str = "synthetic",
    expected_governance_policy_sha256: str | None = None,
) -> CoverageReport:
    """Describe only evidence actually present under the selected runtime mode."""
    if not 0 <= human_review_hours <= 24 * 366:
        raise ValueError("human review hours are outside the reporting bound")
    if live_collector_uptime not in {
        "not_measured_no_live_collectors",
        "not_measured_public_beta_collector",
    }:
        raise ValueError("live collector uptime label is invalid")
    if evidence_label not in {"synthetic", "public"}:
        raise ValueError("coverage evidence label is invalid")
    lanes: list[CoverageLane] = []
    presence = _presence_by_ecosystem(session)
    for ecosystem in COVERAGE_ECOSYSTEMS:
        evidence = presence[ecosystem]
        unknowns: list[str] = []
        if not evidence.artifacts:
            stage = "research" if ecosystem in {"go", "rust"} else "intake"
            result = "unknown"
            unknowns.append(f"No canonical {evidence_label} artifact evidence is present.")
        elif ecosystem in {"oci", "docker"}:
            if evidence.all_immutable and evidence.ranges:
                stage, result = "matched", "supported"
            else:
                stage, result = "normalized", "partial"
                unknowns.extend(
                    (
                        "Mutable tag history is unknown.",
                        "Base-image and transitive exposure paths are unknown.",
                    )
                )
        elif evidence.ranges:
            stage, result = "matched", "supported"
        else:
            stage, result = "normalized", "partial"
            unknowns.append("Affected-range matching evidence is incomplete.")
        lanes.append(
            CoverageLane(
                ecosystem=ecosystem,
                stage=stage,
                result=result,
                as_of=timestamp(measured_at),
                unknowns=tuple(unknowns),
                version_range_evaluation=range_evaluation(ecosystem),
            )
        )
    lanes.append(
        CoverageLane(
            ecosystem="developer-agent-extensions",
            stage="research",
            result="unknown",
            as_of=timestamp(measured_at),
            unknowns=("No canonical extension registry or identity contract is active.",),
        )
    )
    source_ecosystems = _source_ecosystems(session, GITHUB_ADVISORY)
    latest_sequences = (
        select(
            CollectorProgressRecord.source_id.label("source_id"),
            CollectorProgressRecord.segment.label("segment"),
            CollectorProgressRecord.lane.label("lane"),
            func.max(CollectorProgressRecord.sequence).label("sequence"),
        )
        .where(CollectorProgressRecord.source_id == GITHUB_ADVISORY)
        .group_by(
            CollectorProgressRecord.source_id,
            CollectorProgressRecord.segment,
            CollectorProgressRecord.lane,
        )
        .subquery()
    )
    progress_rows = session.scalars(
        select(CollectorProgressRecord).join(
            latest_sequences,
            and_(
                CollectorProgressRecord.source_id == latest_sequences.c.source_id,
                CollectorProgressRecord.segment == latest_sequences.c.segment,
                CollectorProgressRecord.lane == latest_sequences.c.lane,
                CollectorProgressRecord.sequence == latest_sequences.c.sequence,
            ),
        )
    ).all()
    progress_by_lane = {(row.segment, row.lane): row for row in progress_rows}
    last_success_by_lane: dict[tuple[str, str], datetime] = {}
    if progress_rows:
        last_success_by_lane = {
            (str(segment), str(lane)): occurred_at
            for segment, lane, occurred_at in session.execute(
                select(
                    CollectorProgressRecord.segment,
                    CollectorProgressRecord.lane,
                    func.max(CollectorProgressRecord.occurred_at),
                )
                .where(
                    CollectorProgressRecord.source_id == GITHUB_ADVISORY,
                    CollectorProgressRecord.state != "failed",
                )
                .group_by(CollectorProgressRecord.segment, CollectorProgressRecord.lane)
            )
            if occurred_at is not None
        }
        # Updates lanes: caught-up time is the end of the newest completed window, so
        # drop their attempt-based values and use only completed windows.
        last_success_by_lane = {
            key: value for key, value in last_success_by_lane.items() if key[1] != "updates"
        }
        for segment, window_end in session.execute(
            select(
                CollectorProgressRecord.segment,
                func.max(CollectorProgressRecord.window_ended_at),
            )
            .where(
                CollectorProgressRecord.source_id == GITHUB_ADVISORY,
                CollectorProgressRecord.lane == "updates",
                CollectorProgressRecord.state == "complete",
            )
            .group_by(CollectorProgressRecord.segment)
        ):
            if window_end is not None:
                last_success_by_lane[(str(segment), "updates")] = window_end

    openssf_ecosystems = _source_ecosystems(session, OPENSSF_SOURCE_ID)
    openssf_manifests, openssf_complete_manifests, openssf_terminal_manifests = (
        _openssf_manifest_rows(session)
    )

    def source_lane(*, lane: str, record_type: str, segment: str) -> SourceCoverageLane:
        key = (segment, lane)
        return _source_lane(
            session,
            source_id=GITHUB_ADVISORY,
            lane=lane,
            record_type=record_type,
            measured_at=measured_at,
            expected_governance_policy_sha256=expected_governance_policy_sha256,
            ecosystems=source_ecosystems,
            segment=segment,
            progress=progress_by_lane.get(key),
            progress_loaded=True,
            last_success=last_success_by_lane.get(key),
            last_success_loaded=True,
        )

    return CoverageReport(
        measured_at=timestamp(measured_at),
        human_review_hours=human_review_hours,
        live_collector_uptime=live_collector_uptime,
        lanes=tuple(lanes),
        source_lanes=(
            *(
                source_lane(
                    lane=lane,
                    record_type=f"{segment}_advisory",
                    segment=segment,
                )
                for lane in ("historical", "updates")
                for segment in ("malware", "reviewed", "unreviewed")
            ),
            _openssf_catalog_lane(
                manifests=openssf_manifests,
                complete_manifests=openssf_complete_manifests,
                terminal_manifests=openssf_terminal_manifests,
                measured_at=measured_at,
                ecosystems=openssf_ecosystems,
                omission_record_count=current_omission_count(session, source_id=OPENSSF_SOURCE_ID)
                if openssf_manifests
                else 0,
            ),
            *_supplemental_coverage_lanes(session, measured_at=measured_at),
        ),
    )


def build_coverage_report(
    session: Session,
    *,
    measured_at: datetime,
    human_review_hours: float = 0.0,
    live_collector_uptime: str = "not_measured_no_live_collectors",
    evidence_label: str = "synthetic",
    expected_governance_policy_sha256: str | None = None,
    allow_build: bool = True,
) -> CoverageReport:
    """Return one database-derived report per process and argument set for five minutes."""
    return _COVERAGE_REPORT_CACHE.get(
        session,
        measured_at=measured_at,
        allow_build=allow_build,
        human_review_hours=human_review_hours,
        live_collector_uptime=live_collector_uptime,
        evidence_label=evidence_label,
        expected_governance_policy_sha256=expected_governance_policy_sha256,
    )


def refresh_coverage_report(
    session: Session,
    *,
    measured_at: datetime,
    human_review_hours: float = 0.0,
    live_collector_uptime: str = "not_measured_no_live_collectors",
    evidence_label: str = "synthetic",
    expected_governance_policy_sha256: str | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> None:
    """Rebuild the cached report in the background so requests never wait for it."""
    _COVERAGE_REPORT_CACHE.refresh(
        session,
        measured_at=measured_at,
        checkpoint=checkpoint,
        human_review_hours=human_review_hours,
        live_collector_uptime=live_collector_uptime,
        evidence_label=evidence_label,
        expected_governance_policy_sha256=expected_governance_policy_sha256,
    )
