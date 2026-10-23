"""Fail-closed manual runtime for terminal source and authority reconciliation."""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from collections.abc import Mapping
from contextlib import ExitStack, closing, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from smithguard import __version__
from smithguard.acquisition import OperationDeadline
from smithguard.advisory_catalog import AdvisoryCatalogError
from smithguard.authority import load_authority_policy
from smithguard.collection_records import RecordAccountingError, unresolved_statement
from smithguard.collectors import (
    COLLECTOR_SPECS,
    GITHUB_ADVISORY,
    GITHUB_MAX_REFERENCES,
    CollectorBoundaryError,
    CollectorRetryLater,
    GitHubAdvisoryRestCollector,
    github_npm_advisory_range_expression,
    project_github_advisory_publication_scope,
)
from smithguard.db.models import (
    CollectionRecordOutcome,
    CollectorProgressRecord,
    EvidenceFinalizationRecord,
    EvidenceRecord,
    SourceIncidentLinkRecord,
    SourceReconciliationRunRecord,
    SourceRecord,
)
from smithguard.db.repository import RevisionConflict
from smithguard.evidence import (
    EvidenceCollectionBusy,
    EvidenceIntegrityError,
    LocalImmutableEvidenceStore,
)
from smithguard.evidence_finalization import EvidenceFinalizationError, require_finalized
from smithguard.identifiers import (
    INGEST_JSON_MAX_DEPTH,
    INGEST_JSON_MAX_NODES,
    DuplicateJsonKeyError,
    canonical_json_line,
    parse_timestamp,
    strict_json_loads,
    timestamp,
)
from smithguard.ingestion import IngestionReplayConflict, IngestionSourceError
from smithguard.normalization import NormalizationRejected
from smithguard.publication import PublicationError, publish_github_malware_incidents
from smithguard.query import IncidentPosition, latest_incident
from smithguard.reconciliation import (
    ReconciliationError,
    reconcile_historical_malware_authority,
)
from smithguard.retained_replay import (
    RetainedReplayError,
    replay_retained_github_evidence,
)
from smithguard.runtime import (
    RuntimeConfigurationError,
    _engine,
    _github_token,
    _session_factory,
    load_runtime_config,
)
from smithguard.source_governance import SourceGovernanceError, SourceGovernancePolicy
from smithguard.source_inventory import (
    STABLE_ID,
    UPSTREAM_ID,
    SourceInventoryError,
    SourceInventoryObservation,
    SourceInventoryReplayConflict,
    reconcile_source_inventory,
)
from smithguard.source_rights import RightsRegistry, SourceRightsError

GITHUB_INVENTORY_ENDPOINT = "https://api.github.com/advisories"
GITHUB_PAGE_SIZE = 100
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_CUTOFF_AGE = timedelta(hours=24)
INVENTORY_DUE_INTERVAL = timedelta(days=1)
TERMINAL_HISTORY_REASONS = frozenset(
    {
        "github_lane_complete",
        "github_lane_complete_with_scope_exclusion",
    }
)
GHSA_ID = re.compile(r"^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$")


class ReconciliationRuntimeError(ValueError):
    """The manual reconciliation request or provider response is unsafe."""


class ReconciliationDeferred(RuntimeError):
    """GitHub asked the bounded inventory request to wait."""

    def __init__(self, not_before: datetime) -> None:
        super().__init__("GitHub inventory request is rate limited")
        self.not_before = not_before


@dataclass(frozen=True, slots=True)
class GitHubInventoryPage:
    observations: tuple[SourceInventoryObservation, ...]
    continuation_parameter: str | None
    continuation_value: str | None
    excluded_advisory_count: int
    excluded_entry_count: int
    range_advisory_ids: tuple[str, ...] = ()

    @property
    def has_more(self) -> bool:
        return self.continuation_parameter is not None


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.isascii():
        raise ReconciliationRuntimeError(f"{label} is invalid")
    try:
        return parse_timestamp(value, maximum=64)
    except ValueError as error:
        if getattr(error, "reason", None) == "naive":
            raise ReconciliationRuntimeError(f"{label} must include a timezone") from error
        raise ReconciliationRuntimeError(f"{label} is invalid") from error


def _validated_cutoff(value: str, *, now: datetime) -> datetime:
    cutoff = _parse_time(value, label="inventory cutoff")
    if cutoff > now or now - cutoff > MAX_CUTOFF_AGE:
        raise ReconciliationRuntimeError("inventory cutoff is outside its allowed window")
    return cutoff


def _cursor_pair(parameter: str | None, value: str | None) -> str | None:
    if (parameter is None) != (value is None):
        raise ReconciliationRuntimeError("inventory continuation is incomplete")
    if parameter is None:
        return None
    if parameter not in {"before", "after"}:
        raise ReconciliationRuntimeError("inventory continuation parameter is invalid")
    if value is None or GitHubAdvisoryRestCollector.CURSOR_PATTERN.fullmatch(value) is None:
        raise ReconciliationRuntimeError("inventory continuation value is invalid")
    return f"{parameter}:{value}"


def _inventory_parameters(
    *,
    cutoff: datetime,
    cursor_parameter: str | None,
    cursor_value: str | None,
) -> dict[str, str]:
    _cursor_pair(cursor_parameter, cursor_value)
    parameters = {
        "type": "malware",
        "sort": "updated",
        "direction": "asc",
        "per_page": str(GITHUB_PAGE_SIZE),
        "updated": "<=" + timestamp(cutoff).replace("+00:00", "Z"),
    }
    if cursor_parameter is not None and cursor_value is not None:
        parameters[cursor_parameter] = cursor_value
    return parameters


def _inventory_endpoint(parameters: Mapping[str, str]) -> str:
    return GITHUB_INVENTORY_ENDPOINT + "?" + urlencode(parameters)


def _decode_json_page(body: bytes) -> tuple[dict[str, object], ...]:
    try:
        # A full 100-advisory page: keep the ingest collector's headroom, not the default.
        document = strict_json_loads(
            body.decode("utf-8", errors="strict"),
            max_nodes=INGEST_JSON_MAX_NODES,
            max_depth=INGEST_JSON_MAX_DEPTH,
        )
    except (UnicodeDecodeError, RecursionError) as error:
        raise ReconciliationRuntimeError("GitHub inventory is not valid JSON") from error
    except DuplicateJsonKeyError as error:
        raise ReconciliationRuntimeError(
            "GitHub inventory contains a duplicate JSON key"
        ) from error
    except ValueError as error:
        reason = getattr(error, "reason", None)
        if reason == "non_finite":
            raise ReconciliationRuntimeError(
                "GitHub inventory contains an invalid JSON number"
            ) from error
        if reason in {"too_many_nodes", "too_deep"}:
            raise ReconciliationRuntimeError(
                "GitHub inventory exceeds its bounded shape"
            ) from error
        raise ReconciliationRuntimeError("GitHub inventory is not valid JSON") from error
    if (
        not isinstance(document, list)
        or len(document) > GITHUB_PAGE_SIZE
        or not all(isinstance(item, dict) for item in document)
    ):
        raise ReconciliationRuntimeError("GitHub inventory page shape is invalid")
    return tuple(document)


def _retry_not_before(headers: Mapping[str, str], *, now: datetime) -> datetime:
    candidates: list[datetime] = []
    retry_after = headers.get("retry-after")
    if retry_after is not None:
        try:
            seconds = int(retry_after)
        except ValueError:
            try:
                parsed = parsedate_to_datetime(retry_after)
            except (TypeError, ValueError, OverflowError):
                parsed = None
            if parsed is not None:
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    parsed = parsed.replace(tzinfo=UTC)
                candidates.append(parsed.astimezone(UTC))
        else:
            if 0 <= seconds <= 86_400:
                candidates.append(now + timedelta(seconds=seconds))
    reset = headers.get("x-ratelimit-reset")
    if reset is not None:
        with suppress(ValueError, OverflowError, OSError):
            candidates.append(datetime.fromtimestamp(int(reset), tz=UTC))
    selected = max(candidates, default=now + timedelta(minutes=5))
    return min(max(selected, now + timedelta(seconds=1)), now + timedelta(hours=24))


def _next_cursor(
    response: httpx.Response,
    *,
    expected: Mapping[str, str],
) -> tuple[str | None, str | None]:
    link = response.links.get("next")
    if link is None:
        return None, None
    next_url = link.get("url")
    if not isinstance(next_url, str) or len(next_url) > 2000:
        raise ReconciliationRuntimeError("GitHub inventory next-page link is invalid")
    parsed = urlsplit(next_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.github.com"
        or parsed.path != "/advisories"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.fragment
    ):
        raise ReconciliationRuntimeError("GitHub inventory next-page link left its fixed endpoint")
    try:
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as error:
        raise ReconciliationRuntimeError("GitHub inventory next-page query is invalid") from error
    if not all(len(values) == 1 for values in query.values()):
        raise ReconciliationRuntimeError("GitHub inventory next-page query repeats a parameter")
    flattened = {key: values[0] for key, values in query.items()}
    cursor_parameters = [key for key in ("before", "after") if key in flattened]
    if len(cursor_parameters) != 1:
        raise ReconciliationRuntimeError("GitHub inventory next-page link has no single cursor")
    cursor_parameter = cursor_parameters[0]
    cursor_value = flattened.pop(cursor_parameter)
    if flattened != dict(expected):
        raise ReconciliationRuntimeError("GitHub inventory next-page link changed fixed parameters")
    _cursor_pair(cursor_parameter, cursor_value)
    return cursor_parameter, cursor_value


def _project_observations(
    advisories: tuple[dict[str, object], ...],
    *,
    cutoff: datetime,
) -> tuple[tuple[SourceInventoryObservation, ...], int, int, tuple[str, ...]]:
    observations: dict[str, SourceInventoryObservation] = {}
    excluded_advisories = 0
    excluded_entries = 0
    range_advisory_ids: set[str] = set()
    for advisory in advisories:
        if advisory.get("type") != "malware":
            raise ReconciliationRuntimeError("GitHub inventory contains a non-malware advisory")
        references = advisory.get("references", [])
        if isinstance(references, list) and len(references) > GITHUB_MAX_REFERENCES:
            excluded_advisories += 1
            excluded_entries += 1
            continue
        try:
            minimized, excluded = project_github_advisory_publication_scope(advisory)
        except NormalizationRejected as error:
            if error.code != "invalid_github_reference":
                raise
            excluded_advisories += 1
            excluded_entries += 1
            continue
        excluded_entries += excluded
        vulnerabilities = minimized.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise ReconciliationRuntimeError("GitHub inventory projection is invalid")
        if not vulnerabilities:
            excluded_advisories += 1
            continue
        advisory_id = minimized.get("ghsa_id")
        if (
            not isinstance(advisory_id, str)
            or GHSA_ID.fullmatch(advisory_id) is None
            or UPSTREAM_ID.fullmatch(advisory_id) is None
        ):
            raise ReconciliationRuntimeError("GitHub inventory advisory ID is invalid")
        if any(
            isinstance(vulnerability, Mapping)
            and isinstance(vulnerability.get("package"), Mapping)
            and str(vulnerability["package"].get("ecosystem", "")).lower() == "npm"
            and github_npm_advisory_range_expression(
                "npm", vulnerability.get("vulnerable_version_range")
            )
            is not None
            for vulnerability in vulnerabilities
        ):
            range_advisory_ids.add(advisory_id)
        modified_at = _parse_time(minimized.get("updated_at"), label="advisory update time")
        if modified_at > cutoff:
            raise ReconciliationRuntimeError("GitHub inventory exceeded its fixed cutoff")
        observation = SourceInventoryObservation(
            source_record_id=advisory_id,
            source_modified_at=modified_at,
        )
        existing = observations.get(advisory_id)
        if existing is not None and existing != observation:
            raise ReconciliationRuntimeError("GitHub inventory advisory is duplicated")
        observations[advisory_id] = observation
    return (
        tuple(observations[key] for key in sorted(observations)),
        excluded_advisories,
        excluded_entries,
        tuple(sorted(range_advisory_ids)),
    )


def fetch_github_inventory_page(
    *,
    client: httpx.Client,
    cutoff: datetime,
    cursor_parameter: str | None = None,
    cursor_value: str | None = None,
    token: str | None = None,
    now: datetime | None = None,
) -> GitHubInventoryPage:
    """Fetch and validate one fixed public GitHub malware-inventory page."""
    request_time = (now or datetime.now(UTC)).astimezone(UTC)
    parameters = _inventory_parameters(
        cutoff=cutoff,
        cursor_parameter=cursor_parameter,
        cursor_value=cursor_value,
    )
    endpoint = _inventory_endpoint(parameters)
    headers = {
        "Accept": "application/vnd.github+json",
        "Accept-Encoding": "identity",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": f"SmithGuard/{__version__}",
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with client.stream(
            "GET",
            endpoint,
            headers=headers,
            follow_redirects=False,
            timeout=httpx.Timeout(30.0, connect=10.0),
        ) as response:
            if response.status_code in {403, 429} and (
                response.status_code == 429
                or response.headers.get("retry-after") is not None
                or response.headers.get("x-ratelimit-remaining") == "0"
            ):
                raise ReconciliationDeferred(_retry_not_before(response.headers, now=request_time))
            if response.status_code != 200:
                raise ReconciliationRuntimeError("GitHub inventory response status is invalid")
            response.raise_for_status()
            if response.headers.get("content-encoding", "identity").lower() not in {
                "",
                "identity",
            }:
                raise ReconciliationRuntimeError("GitHub inventory response encoding is invalid")
            media_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
            if media_type != "application/json":
                raise ReconciliationRuntimeError("GitHub inventory response type is invalid")
            if str(response.url) != endpoint:
                raise ReconciliationRuntimeError("GitHub inventory response URL changed")
            declared = response.headers.get("content-length")
            if declared is not None and (int(declared) < 0 or int(declared) > MAX_RESPONSE_BYTES):
                raise ReconciliationRuntimeError("GitHub inventory response exceeds its limit")
            body = bytearray()
            for chunk in response.iter_bytes(64 * 1024):
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ReconciliationRuntimeError("GitHub inventory response exceeds its limit")
            if declared is not None and len(body) != int(declared):
                raise ReconciliationRuntimeError("GitHub inventory response length changed")
            advisories = _decode_json_page(bytes(body))
            expected = {
                key: value for key, value in parameters.items() if key not in {"before", "after"}
            }
            next_parameter, next_value = _next_cursor(response, expected=expected)
    except ReconciliationDeferred:
        raise
    except ReconciliationRuntimeError:
        raise
    except (httpx.HTTPError, ValueError) as error:
        raise ReconciliationRuntimeError("GitHub inventory request failed") from error
    observations, excluded_advisories, excluded_entries, range_advisory_ids = _project_observations(
        advisories,
        cutoff=cutoff,
    )
    return GitHubInventoryPage(
        observations=observations,
        continuation_parameter=next_parameter,
        continuation_value=next_value,
        excluded_advisory_count=excluded_advisories,
        excluded_entry_count=excluded_entries,
        range_advisory_ids=range_advisory_ids,
    )


def _terminal_history(session: Session) -> CollectorProgressRecord:
    progress = session.scalar(
        select(CollectorProgressRecord)
        .where(
            CollectorProgressRecord.source_id == GITHUB_ADVISORY,
            CollectorProgressRecord.lane == "historical",
        )
        .order_by(CollectorProgressRecord.sequence.desc())
        .limit(1)
    )
    if (
        progress is None
        or progress.cursor_parameter is not None
        or progress.cursor_value is not None
        or not (progress.state == "complete" or progress.reason_code in TERMINAL_HISTORY_REASONS)
    ):
        raise ReconciliationRuntimeError("historical collection is not terminal")
    return progress


def _validate_source_history(session: Session, registry: RightsRegistry) -> None:
    persisted = tuple(
        session.execute(
            select(SourceRecord.revision, SourceRecord.record_hash)
            .where(SourceRecord.id == GITHUB_ADVISORY)
            .order_by(SourceRecord.revision)
        ).tuples()
    )
    try:
        registry.validate_persisted_history(GITHUB_ADVISORY, persisted)
    except SourceRightsError as error:
        raise RuntimeConfigurationError(
            "stored source history differs from the reviewed register"
        ) from error


def _validate_inventory_continuation(
    session: Session,
    *,
    inventory_run_id: str,
    page_index: int,
    cutoff: datetime,
) -> None:
    if page_index == 1:
        return
    prior = session.scalar(
        select(SourceReconciliationRunRecord).where(
            SourceReconciliationRunRecord.source_id == GITHUB_ADVISORY,
            SourceReconciliationRunRecord.inventory_run_id == inventory_run_id,
            SourceReconciliationRunRecord.page_index == page_index - 1,
        )
    )
    if prior is None:
        raise ReconciliationRuntimeError("prior inventory page is missing")
    if prior.reconciled_at != cutoff:
        raise ReconciliationRuntimeError("inventory cutoff changed within one run")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="smithguard-reconcile")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    inventory = subparsers.add_parser("github-inventory")
    inventory.add_argument("--inventory-run-id", required=True)
    inventory.add_argument("--page-index", type=int, required=True)
    inventory.add_argument("--cutoff", required=True)
    inventory.add_argument("--cursor-parameter", choices=("before", "after"))
    inventory.add_argument("--cursor")
    inventory.add_argument("--commit", action="store_true")
    authority = subparsers.add_parser("historical-authority")
    authority.add_argument("--limit", type=int, default=10_000)
    authority.add_argument("--after-changed-at")
    authority.add_argument("--after-incident-id")
    authority.add_argument("--apply", action="store_true")
    retained = subparsers.add_parser("retained-github-replay")
    retained.add_argument("--inventory-run-id", required=True)
    retained.add_argument("--limit", type=int, default=100)
    retained.add_argument("--after-evidence-id")
    retained.add_argument("--commit", action="store_true")
    backfill = subparsers.add_parser("github-range-backfill")
    backfill.add_argument("--advisory-id", action="append", required=True)
    backfill.add_argument("--commit", action="store_true")
    backfill.add_argument("--catalog-segment", choices=("malware", "reviewed", "unreviewed"))
    backfill.add_argument("--resolve-outcome-id")
    gaps = subparsers.add_parser("github-record-gaps")
    gaps.add_argument(
        "--catalog-segment", choices=("malware", "reviewed", "unreviewed"), required=True
    )
    gaps.add_argument("--limit", type=int, default=100)
    gaps.add_argument("--after-outcome-id")
    omissions = subparsers.add_parser("source-omissions")
    omissions.add_argument("--source", choices=("openssf", "rustsec", "go", "epss"), required=True)
    omissions.add_argument("--limit", type=int, default=50)
    omissions.add_argument("--after", default="")
    omissions.add_argument("--snapshot-id")
    missing = subparsers.add_parser("provider-missing-review")
    missing.add_argument("--limit", type=int, default=100)
    return parser


def _latest_evidence_state(session: Session, evidence_id: str) -> str | None:
    return session.scalar(
        select(EvidenceRecord.storage_state)
        .where(EvidenceRecord.id == evidence_id)
        .order_by(EvidenceRecord.revision.desc())
        .limit(1)
    )


def _provider_missing_main(arguments: argparse.Namespace) -> int:
    """Classify the latest bounded provider-missing set without changing data."""
    if not 1 <= arguments.limit <= 100:
        raise ReconciliationRuntimeError("provider-missing review limit is invalid")
    config = load_runtime_config()
    engine = _engine(config)
    factory = _session_factory(engine)
    try:
        with factory() as session:
            terminal = session.scalar(
                select(SourceReconciliationRunRecord)
                .where(
                    SourceReconciliationRunRecord.source_id == GITHUB_ADVISORY,
                    SourceReconciliationRunRecord.complete_inventory.is_(True),
                    SourceReconciliationRunRecord.has_more.is_(False),
                )
                .order_by(
                    SourceReconciliationRunRecord.reconciled_at.desc(),
                    SourceReconciliationRunRecord.sequence.desc(),
                )
                .limit(1)
            )
            if terminal is None:
                raise ReconciliationRuntimeError(
                    "provider-missing review has no complete source inventory"
                )
            if terminal.drift_truncated:
                raise ReconciliationRuntimeError(
                    "provider-missing review source inventory is truncated"
                )
            missing_ids = tuple(terminal.missing_record_ids)
            selected = missing_ids[: arguments.limit]
            classifications: Counter[str] = Counter()
            for record_id in selected:
                rows = tuple(
                    session.scalars(
                        select(SourceIncidentLinkRecord)
                        .where(
                            SourceIncidentLinkRecord.source_id == GITHUB_ADVISORY,
                            SourceIncidentLinkRecord.upstream_record_id == record_id,
                        )
                        .order_by(
                            SourceIncidentLinkRecord.artifact_id,
                            SourceIncidentLinkRecord.sequence.desc(),
                        )
                    )
                )
                latest_by_artifact: dict[str, SourceIncidentLinkRecord] = {}
                for row in rows:
                    latest_by_artifact.setdefault(row.artifact_id, row)
                links = tuple(latest_by_artifact.values())
                if not links:
                    classifications["no_public_link"] += 1
                    continue
                if all(link.state in {"removed", "withdrawn"} for link in links):
                    classifications["terminal_source_link"] += 1
                    continue
                incidents = tuple(
                    latest_incident(session, link.incident_id, public_only=True) for link in links
                )
                if all(
                    incident is not None and incident.status in {"withdrawn", "expired", "disputed"}
                    for incident in incidents
                ):
                    classifications["terminal_public_incident"] += 1
                    continue
                retained_evidence = all(
                    _latest_evidence_state(session, link.evidence_id) == "stored_immutable"
                    for link in links
                )
                classifications[
                    "retained_active_requires_provider_clarification"
                    if retained_evidence
                    else "missing_retained_evidence"
                ] += 1
            inventory_run_id = terminal.inventory_run_id
            inventory_reconciled_at = timestamp(terminal.reconciled_at)
        output = {
            "operation": "provider_missing_review",
            "mode": "read_only",
            "inventory_run_id": inventory_run_id,
            "inventory_reconciled_at": inventory_reconciled_at,
            "provider_missing_count": len(missing_ids),
            "reviewed_count": len(selected),
            "classification_counts": dict(sorted(classifications.items())),
            "has_more": len(missing_ids) > len(selected),
            "apply_allowed": False,
        }
        sys.stdout.write(canonical_json_line(output).decode("ascii"))
        return 0
    finally:
        engine.dispose()


def _inventory_main(arguments: argparse.Namespace) -> int:
    now = datetime.now(UTC)
    cutoff = _validated_cutoff(arguments.cutoff, now=now)
    if not STABLE_ID.fullmatch(arguments.inventory_run_id):
        raise ReconciliationRuntimeError("inventory run ID is invalid")
    if not 1 <= arguments.page_index <= 10_000:
        raise ReconciliationRuntimeError("inventory page index is invalid")
    continuation_in = _cursor_pair(arguments.cursor_parameter, arguments.cursor)
    if arguments.page_index == 1 and continuation_in is not None:
        raise ReconciliationRuntimeError("first inventory page cannot have a continuation")
    if arguments.page_index > 1 and continuation_in is None:
        raise ReconciliationRuntimeError("continued inventory page requires a continuation")
    config = load_runtime_config(require_evidence=True)
    registry = RightsRegistry.from_path(config.rights_register_path)
    governance_policy = SourceGovernancePolicy.from_path(
        config.governance_policy_path,
        registry=registry,
    )
    engine = _engine(config)
    factory = _session_factory(engine)
    try:
        with factory() as session:
            terminal = _terminal_history(session)
            _validate_source_history(session, registry)
            _validate_inventory_continuation(
                session,
                inventory_run_id=arguments.inventory_run_id,
                page_index=arguments.page_index,
                cutoff=cutoff,
            )
            if terminal.occurred_at > cutoff:
                raise ReconciliationRuntimeError("inventory cutoff predates terminal history")
        token = _github_token()
        with httpx.Client(follow_redirects=False) as client:
            page = fetch_github_inventory_page(
                client=client,
                cutoff=cutoff,
                cursor_parameter=arguments.cursor_parameter,
                cursor_value=arguments.cursor,
                token=token,
                now=now,
            )
        continuation_out = _cursor_pair(
            page.continuation_parameter,
            page.continuation_value,
        )
        with factory() as session:
            transaction = session.begin()
            terminal = _terminal_history(session)
            _validate_source_history(session, registry)
            _validate_inventory_continuation(
                session,
                inventory_run_id=arguments.inventory_run_id,
                page_index=arguments.page_index,
                cutoff=cutoff,
            )
            if terminal.occurred_at > cutoff:
                raise ReconciliationRuntimeError("inventory cutoff predates terminal history")
            result = reconcile_source_inventory(
                session,
                policy=governance_policy,
                connector_id=COLLECTOR_SPECS[GITHUB_ADVISORY].connector_id,
                source_id=GITHUB_ADVISORY,
                acquisition_method="rest_api",
                canonical_url=GITHUB_INVENTORY_ENDPOINT,
                inventory_run_id=arguments.inventory_run_id,
                page_index=arguments.page_index,
                observations=page.observations,
                continuation_in=continuation_in,
                continuation_out=continuation_out,
                has_more=page.has_more,
                inventory_complete=not page.has_more,
                reconciled_at=cutoff,
                next_due_at=cutoff + INVENTORY_DUE_INTERVAL,
            )
            if arguments.commit:
                transaction.commit()
            else:
                transaction.rollback()
        output = {
            "operation": "github_inventory",
            "mode": "commit" if arguments.commit else "rollback_preview",
            "inventory_run_id": arguments.inventory_run_id,
            "page_index": arguments.page_index,
            "state": result.state,
            "accepted_observation_count": len(page.observations),
            "excluded_advisory_count": page.excluded_advisory_count,
            "excluded_entry_count": page.excluded_entry_count,
            "range_advisory_ids": list(page.range_advisory_ids),
            "late_count": len(result.late_record_ids),
            "modified_count": len(result.modified_record_ids),
            "deleted_count": len(result.deleted_record_ids),
            "missing_count": len(result.missing_record_ids),
            "unresolved_count": len(result.unresolved_record_ids),
            "drift_truncated": result.drift_truncated,
            "has_more": page.has_more,
            "next_cursor_parameter": page.continuation_parameter,
            "next_cursor": page.continuation_value,
        }
        sys.stdout.write(canonical_json_line(output).decode("ascii"))
        return 0
    finally:
        engine.dispose()


def _authority_after(arguments: argparse.Namespace) -> IncidentPosition | None:
    if (arguments.after_changed_at is None) != (arguments.after_incident_id is None):
        raise ReconciliationRuntimeError("authority continuation is incomplete")
    if arguments.after_changed_at is None:
        return None
    if not STABLE_ID.fullmatch(arguments.after_incident_id):
        raise ReconciliationRuntimeError("authority continuation incident is invalid")
    return IncidentPosition(
        changed_at=_parse_time(
            arguments.after_changed_at,
            label="authority continuation time",
        ),
        incident_id=arguments.after_incident_id,
    )


def _authority_main(arguments: argparse.Namespace) -> int:
    config = load_runtime_config(require_evidence=True)
    if config.evidence_root is None:
        raise RuntimeConfigurationError("authority reconciliation evidence path is missing")
    after = _authority_after(arguments)
    engine = _engine(config)
    factory = _session_factory(engine)
    try:
        with (
            closing(
                LocalImmutableEvidenceStore(
                    config.evidence_root,
                    allow_group_read=True,
                )
            ) as evidence_store,
            factory() as session,
        ):
            _terminal_history(session)
            registry = RightsRegistry.from_path(config.rights_register_path)
            _validate_source_history(session, registry)
            authority_policy = load_authority_policy(config.authority_policy_path)
            if authority_policy.source_rights_register_id != registry.register_id:
                raise RuntimeConfigurationError(
                    "authority policy and source-rights register differ"
                )
            transaction = session.begin_nested()
            report = reconcile_historical_malware_authority(
                session,
                evidence_store=evidence_store,
                reconciled_at=datetime.now(UTC),
                apply=arguments.apply,
                limit=arguments.limit,
                after=after,
                authority_policy=authority_policy,
            )
            if arguments.apply:
                transaction.commit()
                session.commit()
            else:
                transaction.rollback()
                session.rollback()
        next_after = report.next_after
        output = {
            "operation": "historical_authority",
            "mode": report.mode,
            "scanned_count": report.scanned_count,
            "eligible_count": report.eligible_count,
            "changed_count": report.changed_count,
            "skipped_count": report.skipped_count,
            "proposed_status_counts": dict(
                sorted(Counter(item.proposed_status for item in report.items).items())
            ),
            "reason_counts": dict(
                sorted(Counter(item.reason_code for item in report.items).items())
            ),
            "exception_count": sum(item.exception_reason_code is not None for item in report.items),
            "has_more": report.has_more,
            "next_after_changed_at": (
                timestamp(next_after.changed_at) if next_after is not None else None
            ),
            "next_after_incident_id": (next_after.incident_id if next_after is not None else None),
        }
        sys.stdout.write(canonical_json_line(output).decode("ascii"))
        return 0
    finally:
        engine.dispose()


def _retained_replay_main(arguments: argparse.Namespace) -> int:
    config = load_runtime_config(require_evidence=True)
    if config.evidence_root is None:
        raise RuntimeConfigurationError("retained replay evidence path is missing")
    engine = _engine(config)
    factory = _session_factory(engine)
    try:
        registry = RightsRegistry.from_path(config.rights_register_path)
        governance_policy = SourceGovernancePolicy.from_path(
            config.governance_policy_path,
            registry=registry,
        )
        authority_policy = load_authority_policy(config.authority_policy_path)
        with (
            closing(
                LocalImmutableEvidenceStore(
                    config.evidence_root,
                    allow_group_read=True,
                )
            ) as evidence_store,
            factory() as session,
            session.begin() as root_transaction,
        ):
            _terminal_history(session)
            _validate_source_history(session, registry)
            with session.begin_nested() as transaction:
                report = replay_retained_github_evidence(
                    session,
                    evidence_store=evidence_store,
                    registry=registry,
                    governance_policy=governance_policy,
                    authority_policy=authority_policy,
                    inventory_run_id=arguments.inventory_run_id,
                    limit=arguments.limit,
                    after_evidence_id=arguments.after_evidence_id,
                )
                if not arguments.commit:
                    transaction.rollback()
            if not arguments.commit:
                root_transaction.rollback()
        # Replay re-registers a stage whenever the contract row is rebuilt; a stage that
        # failed to finalize after the commit must not be reported as a completed replay.
        require_finalized(session)
        output = {
            "operation": "retained_github_replay",
            "mode": "commit" if arguments.commit else "rollback_preview",
            "inventory_observation_count": report.inventory_observation_count,
            "eligible_candidate_count": report.eligible_candidate_count,
            "selected_count": report.selected_count,
            "replayed_count": report.replayed_count,
            "normalized_record_count": report.normalized_record_count,
            "published_incident_count": report.published_incident_count,
            "has_more": report.has_more,
            "next_after_evidence_id": report.next_after_evidence_id,
        }
        sys.stdout.write(canonical_json_line(output).decode("ascii"))
        return 0
    finally:
        engine.dispose()


def _source_omissions_main(arguments: argparse.Namespace) -> int:
    from smithguard.source_accounting import catalog_omissions, epss_missing

    if arguments.snapshot_id and arguments.source != "epss":
        raise ReconciliationRuntimeError("snapshot selection requires EPSS")
    config = load_runtime_config()
    engine = _engine(config)
    try:
        with ExitStack() as stack, _session_factory(engine)() as session:
            session.execute(text("SET TRANSACTION READ ONLY"))
            session.execute(text("SET LOCAL statement_timeout = '20000ms'"))
            evidence_store = None

            def read_evidence(digest):
                nonlocal evidence_store
                if evidence_store is None:
                    if config.evidence_root is None:
                        raise ReconciliationRuntimeError("missing score evidence path is absent")
                    evidence_store = stack.enter_context(
                        closing(
                            LocalImmutableEvidenceStore(
                                config.evidence_root,
                                create=False,
                                allow_group_read=True,
                                max_bytes=131072,
                            )
                        )
                    )
                return evidence_store.read_bytes(digest)

            try:
                output = (
                    epss_missing(
                        session,
                        snapshot_id=arguments.snapshot_id,
                        limit=arguments.limit,
                        after=arguments.after,
                        read_evidence=read_evidence,
                    )
                    if arguments.source == "epss"
                    else catalog_omissions(
                        session,
                        source=arguments.source,
                        limit=arguments.limit,
                        after=arguments.after,
                    )
                )
            except ValueError as error:
                raise ReconciliationRuntimeError(str(error)) from error
            sys.stdout.write(canonical_json_line(output).decode("ascii"))
        return 0
    finally:
        engine.dispose()


def _record_gaps_main(arguments: argparse.Namespace) -> int:
    if not 1 <= arguments.limit <= 100:
        raise ReconciliationRuntimeError("record gap limit must be between 1 and 100")
    if arguments.after_outcome_id is not None and (
        len(arguments.after_outcome_id) > 160
        or STABLE_ID.fullmatch(arguments.after_outcome_id) is None
    ):
        raise ReconciliationRuntimeError("record gap cursor is invalid")
    engine = _engine(load_runtime_config())
    try:
        with _session_factory(engine)() as session:
            statement = unresolved_statement(
                source_id=GITHUB_ADVISORY, segment=arguments.catalog_segment
            )
            if arguments.after_outcome_id is not None:
                statement = statement.where(
                    CollectionRecordOutcome.outcome_id > arguments.after_outcome_id
                )
            rows = tuple(
                session.scalars(
                    statement.order_by(CollectionRecordOutcome.outcome_id).limit(
                        arguments.limit + 1
                    )
                )
            )
            selected = rows[: arguments.limit]
            output = {
                "operation": "github_record_gaps",
                "catalog_segment": arguments.catalog_segment,
                "outcomes": [
                    {
                        "outcome_id": row.outcome_id,
                        "record_key": row.record_key,
                        "disposition": row.disposition,
                        "input_sha256": row.input_sha256,
                        "processing_version": row.processing_version,
                        "policy_sha256": row.policy_sha256,
                        "omissions": row.document["omissions"],
                        "quarantine_reasons": row.document["quarantine_reasons"],
                        "source_updated_at": row.document["source_updated_at"],
                    }
                    for row in selected
                ],
                "next_outcome_id": selected[-1].outcome_id if len(rows) > arguments.limit else None,
            }
        sys.stdout.write(canonical_json_line(output).decode("ascii"))
        return 0
    finally:
        engine.dispose()


def _range_backfill_main(arguments: argparse.Namespace) -> int:
    advisory_ids = tuple(dict.fromkeys(arguments.advisory_id))
    catalog_segment = arguments.catalog_segment
    resolve_outcome_id = getattr(arguments, "resolve_outcome_id", None)
    if resolve_outcome_id is not None and (len(advisory_ids) != 1 or catalog_segment is None):
        raise ReconciliationRuntimeError(
            "record resolution requires one advisory and catalog segment"
        )
    if resolve_outcome_id is not None and (
        len(resolve_outcome_id) > 160 or STABLE_ID.fullmatch(resolve_outcome_id) is None
    ):
        raise ReconciliationRuntimeError("record resolution outcome ID is invalid")
    if not 1 <= len(advisory_ids) <= 100 or any(
        GHSA_ID.fullmatch(value) is None for value in advisory_ids
    ):
        raise ReconciliationRuntimeError("GitHub range backfill advisory IDs are invalid")
    config = load_runtime_config(require_evidence=True)
    if config.evidence_root is None:
        raise RuntimeConfigurationError("range backfill evidence path is missing")
    registry = RightsRegistry.from_path(config.rights_register_path)
    governance_policy = SourceGovernancePolicy.from_path(
        config.governance_policy_path,
        registry=registry,
    )
    authority_policy = load_authority_policy(config.authority_policy_path)
    engine = _engine(config)
    factory = _session_factory(engine)
    token = _github_token()
    try:
        with (
            closing(
                LocalImmutableEvidenceStore(
                    config.evidence_root,
                    allow_group_read=True,
                )
            ) as evidence_store,
            httpx.Client(follow_redirects=False) as client,
            evidence_store.collection_lock(),
            factory() as session,
            session.begin() as transaction,
        ):
            batch_deadline = OperationDeadline.start(120.0)
            _validate_source_history(session, registry)
            unresolved_finalizations = session.scalar(
                select(func.count())
                .select_from(EvidenceFinalizationRecord)
                .where(EvidenceFinalizationRecord.state != "finalized")
            )
            pending_stages = evidence_store.pending_manifest()
            if unresolved_finalizations or pending_stages:
                reason = (
                    "unresolved_finalizations" if unresolved_finalizations else "orphan_staging"
                )
                sys.stderr.write(f"collection_diagnostic:{reason}\n")
                raise ReconciliationRuntimeError(
                    "GitHub range backfill requires finalized evidence state"
                )
            collector = GitHubAdvisoryRestCollector(
                registry=registry,
                evidence_store=evidence_store,
                client=client,
                authority_policy=authority_policy,
                governance_policy=governance_policy,
                advisory_type=catalog_segment or "legacy-malware",
                catalog_mode=catalog_segment is not None,
            )
            catalog_package_entry_count = 0
            catalog_revisions = []
            normalized_record_count = 0
            published_incident_count = 0
            scope_exclusion_counts: Counter[str] = Counter()
            for advisory_id in advisory_ids:
                batch_deadline.check()
                try:
                    result = collector.backfill_advisory(
                        session,
                        advisory_id=advisory_id,
                        token=token,
                        deadline=batch_deadline,
                        **(
                            {"resolve_outcome_id": resolve_outcome_id}
                            if resolve_outcome_id is not None
                            else {}
                        ),
                    )
                except CollectorRetryLater as error:
                    raise ReconciliationDeferred(error.not_before) from error
                normalized_record_count += result.collection.outcome.record_count
                scope_exclusion_counts.update(dict(result.scope_exclusion_reasons))
                if catalog_segment is not None:
                    catalog_package_entry_count += result.catalog_package_entry_count
                    appended = result.catalog_append_result
                    if appended is None:
                        raise ReconciliationRuntimeError("catalog repair result is missing")
                    catalog_revisions.append(
                        {
                            "advisory_id": advisory_id,
                            "catalog_event_id": appended.catalog_event_id,
                            "revision": appended.revision,
                            "created": appended.created,
                            "source_sha256": appended.source_sha256,
                        }
                    )
                else:
                    published_incident_count += len(
                        publish_github_malware_incidents(
                            session,
                            collection=result.collection,
                            published_at=datetime.now(UTC),
                            authority_policy=authority_policy,
                            governance_policy=governance_policy,
                        )
                    )
                batch_deadline.check()
            if not arguments.commit:
                transaction.rollback()
        # A committed page whose evidence stage then failed to finalize is durable for
        # reconciliation, but this run must not report it as a completed backfill.
        require_finalized(session)
        output = {
            "operation": "github_range_backfill",
            "mode": "commit" if arguments.commit else "rollback_preview",
            "advisory_ids": list(advisory_ids),
            "catalog_segment": catalog_segment,
            "resolve_outcome_id": resolve_outcome_id,
            "catalog_package_entry_count": catalog_package_entry_count,
            "catalog_revisions": catalog_revisions,
            "normalized_record_count": normalized_record_count,
            "published_incident_count": published_incident_count,
            "scope_exclusion_counts": dict(sorted(scope_exclusion_counts.items())),
        }
        sys.stdout.write(canonical_json_line(output).decode("ascii"))
        return 0
    finally:
        engine.dispose()


def main(argv: list[str] | None = None) -> int:
    """Run one explicitly bounded manual reconciliation operation."""
    try:
        arguments = _parser().parse_args(argv)
        if arguments.operation == "github-inventory":
            return _inventory_main(arguments)
        if arguments.operation == "historical-authority":
            return _authority_main(arguments)
        if arguments.operation == "retained-github-replay":
            return _retained_replay_main(arguments)
        if arguments.operation == "source-omissions":
            return _source_omissions_main(arguments)
        if arguments.operation == "github-record-gaps":
            return _record_gaps_main(arguments)
        if arguments.operation == "github-range-backfill":
            return _range_backfill_main(arguments)
        if arguments.operation == "provider-missing-review":
            return _provider_missing_main(arguments)
        raise ReconciliationRuntimeError("reconciliation operation is invalid")
    except ReconciliationDeferred as error:
        sys.stderr.write("reconciliation_deferred not_before=" + timestamp(error.not_before) + "\n")
        return 4
    except EvidenceCollectionBusy:
        sys.stderr.write("reconciliation_error:evidence_coordination_timeout\n")
        return 3
    except (
        ReconciliationRuntimeError,
        RecordAccountingError,
        AdvisoryCatalogError,
        RuntimeConfigurationError,
        SourceInventoryError,
        SourceInventoryReplayConflict,
        ReconciliationError,
        RetainedReplayError,
        NormalizationRejected,
        IngestionReplayConflict,
        IngestionSourceError,
        EvidenceIntegrityError,
        EvidenceFinalizationError,
        PublicationError,
        RevisionConflict,
        CollectorBoundaryError,
        SourceGovernanceError,
        SourceRightsError,
    ) as error:
        sys.stderr.write(f"reconciliation_error:{error}\n")
        return 2
    except Exception:
        sys.stderr.write("runtime_error:reconciliation_failed\n")
        return 3
