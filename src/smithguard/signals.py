"""Actor-qualified preliminary warnings, bounded rechecks, and permanent history."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import Select, and_, func, or_, select
from sqlalchemy.orm import Session, aliased

from smithguard.acquisition import AcquisitionRejected, OperationDeadline
from smithguard.contracts.runtime import parse_contract
from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import (
    JobRecord,
    PreliminaryWarningApprovalRecord,
    PreliminaryWarningRecheckRecord,
    PreliminaryWarningRecord,
)
from smithguard.db.repository import append_contract, latest_contract
from smithguard.discovery import canonical_public_url
from smithguard.identifiers import (
    ACTOR_ID,
    PROVIDER_JSON_MAX_DEPTH,
    PROVIDER_JSON_MAX_NODES,
    DuplicateJsonKeyError,
    canonical_json_bytes,
    require_aware_utc,
    sha256_id,
    stable_id,
    strict_json_loads,
    timestamp,
)
from smithguard.spend import TECHNICAL_USAGE_STOP_REASONS, SpendPolicy
from smithguard.warning_dispatch import provider_guard
from smithguard.warning_lane_receipts import ProviderUsage, append_warning_lane_receipt
from smithguard.xai_settings import (
    XAI_MAX_ELAPSED_SECONDS,
    XAI_MAX_INPUT_TOKENS,
    XAI_MAX_OUTPUT_TOKENS,
    XAI_MAX_REQUEST_BYTES,
    XAI_MAX_RESPONSE_BYTES,
    XAI_MAX_TOTAL_TOKENS,
    XAI_RECHECK_MAX_INPUT_TOKENS,
    XAI_RECHECK_MAX_OUTPUT_TOKENS,
    XAI_RECHECK_MAX_TOTAL_TOKENS,
    XAI_THREAT_SEARCH_MODEL,
    XAI_THREAT_SEARCH_REASONING_EFFORT,
)

WARNING_TEXT = (
    "Emerging and unverified. SmithGuard has not independently confirmed this warning "
    "and is awaiting authoritative or non-social confirmation. Use it to "
    "investigate, not as proof or authorization for a disruptive action."
)
WARNING_LIFETIME = timedelta(hours=12)
RECHECK_INTERVAL = timedelta(hours=1)
MAX_RECHECKS = 12
RECHECK_MAX_INPUT_TOKENS = XAI_RECHECK_MAX_INPUT_TOKENS
RECHECK_MAX_OUTPUT_TOKENS = XAI_RECHECK_MAX_OUTPUT_TOKENS
RECHECK_MAX_TOTAL_TOKENS = XAI_RECHECK_MAX_TOTAL_TOKENS
# Receipt written in the same transaction that commits a recheck to the provider. A
# recheck whose dispatch receipt has no stored completion was interrupted and is
# closed without a second provider call.
RECHECK_DISPATCH_RECEIPT = "provider_request_started"
REVIEWER_ID = ACTOR_ID
PROVIDER_OUTCOMES = {
    "still_unverified",
    "no_new_evidence",
    "confirmation_candidate",
    "contradiction_candidate",
}
TERMINAL_STATES = {"expired", "withdrawn", "promoted", "contradicted"}
PUBLIC_BETA_EVIDENCE_CLASSES = {"social_only", "web_only", "web_and_social"}


class PreliminaryWarningError(ValueError):
    """A warning, reviewer action, or recheck result violates the fixed boundary."""


class RecheckProviderUnavailable(RuntimeError):
    """The bounded xAI request did not return a usable result."""

    def __init__(
        self,
        message: str,
        *,
        provider_error: BaseException | None = None,
        provider_result: object | None = None,
        reason_code: str | None = None,
    ) -> None:
        self.provider_error = provider_error
        self.provider_result = provider_result
        self.reason_code = reason_code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class PreliminaryWarningDraft:
    title: str
    claim: str
    affected_artifacts: tuple[str, ...]
    source_urls: tuple[str, ...]
    evidence_class: str
    independent_source_clusters: int
    observed_at: datetime
    reviewer_id: str
    policy_qualified: bool = False


@dataclass(frozen=True, slots=True)
class WarningPosition:
    updated_at: datetime
    warning_id: str


@dataclass(frozen=True, slots=True)
class RecheckProviderResult:
    outcome: str
    response_id: str
    server_side_tool_calls: int
    reason: str = "No material new public evidence was reported."
    source_urls: tuple[str, ...] = ()
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cached_input_tokens: int = 0
    reasoning_tokens: int = 0
    request_bytes: int = 0
    elapsed_milliseconds: int = 0
    response_bytes: int = 0
    credential_route: str | None = None


@dataclass(frozen=True, slots=True)
class RecheckRun:
    warning_id: str
    outcome: str
    revision: int
    recheck_count: int


RecheckProvider = Callable[[Mapping[str, Any], datetime], RecheckProviderResult]
SessionFactory = Callable[[], Session]


def _aware(value: datetime, *, field: str) -> datetime:
    try:
        return require_aware_utc(value)
    except ValueError as error:
        raise PreliminaryWarningError(f"{field} must be timezone-aware") from error


def _latest_warning_query() -> tuple[Any, Select[Any]]:
    ranked = select(
        PreliminaryWarningRecord.id.label("warning_id"),
        PreliminaryWarningRecord.revision.label("warning_revision"),
        func.row_number()
        .over(
            partition_by=PreliminaryWarningRecord.id,
            order_by=PreliminaryWarningRecord.revision.desc(),
        )
        .label("position"),
    ).subquery()
    latest = aliased(PreliminaryWarningRecord)
    statement = select(latest).join(
        ranked,
        and_(
            latest.id == ranked.c.warning_id,
            latest.revision == ranked.c.warning_revision,
            ranked.c.position == 1,
        ),
    )
    return latest, statement


def list_preliminary_warnings(
    session: Session,
    *,
    state: str = "active",
    after: WarningPosition | None = None,
    limit: int = 101,
    now: datetime | None = None,
) -> tuple[PreliminaryWarningRecord, ...]:
    """List latest revisions, including terminal archive states on request."""
    if state not in {"active", *TERMINAL_STATES, "all"}:
        raise PreliminaryWarningError("warning state filter is invalid")
    if not 1 <= limit <= 101:
        raise PreliminaryWarningError("warning query limit must be between 1 and 101")
    latest, statement = _latest_warning_query()
    current_time = _aware(now, field="now") if now is not None else datetime.now(UTC)
    if state != "all":
        statement = statement.where(latest.state == state)
    statement = statement.where((latest.state != "active") | (latest.expires_at > current_time))
    if after is not None:
        statement = statement.where(
            (latest.updated_at < after.updated_at)
            | ((latest.updated_at == after.updated_at) & (latest.id > after.warning_id))
        )
    statement = statement.order_by(latest.updated_at.desc(), latest.id).limit(limit)
    return tuple(session.scalars(statement))


def get_preliminary_warning(
    session: Session,
    warning_id: str,
    *,
    now: datetime | None = None,
) -> PreliminaryWarningRecord | None:
    record = latest_contract(session, "PreliminaryWarning", warning_id)
    if not isinstance(record, PreliminaryWarningRecord):
        return None
    if now is not None:
        current_time = _aware(now, field="now")
        if record.state == "active" and record.expires_at <= current_time:
            return None
    return record


def matching_preliminary_warnings(
    session: Session,
    *,
    affected_artifacts: Sequence[str],
    limit: int = 101,
    now: datetime | None = None,
) -> tuple[PreliminaryWarningRecord, ...]:
    """Return latest warning revisions for only the exact queried artifact aliases."""
    values = tuple(dict.fromkeys(affected_artifacts))
    if (
        not values
        or len(values) > 10
        or any(
            not isinstance(value, str) or not value.isascii() or not 1 <= len(value) <= 300
            for value in values
        )
    ):
        raise PreliminaryWarningError("warning artifact filter is invalid")
    if not 1 <= limit <= 101:
        raise PreliminaryWarningError("warning query limit must be between 1 and 101")
    latest, statement = _latest_warning_query()
    current_time = _aware(now, field="now") if now is not None else datetime.now(UTC)
    statement = (
        statement.where(
            latest.state == "active",
            latest.expires_at > current_time,
            or_(*(latest.document["affected_artifacts"].contains([value]) for value in values)),
        )
        .order_by(latest.updated_at.desc(), latest.id)
        .limit(limit)
    )
    return tuple(session.scalars(statement))


def _approval_hash(values: Mapping[str, Any], *, qualification_sha256: str) -> str:
    encoded = {
        **values,
        "reviewed_at": timestamp(values["reviewed_at"]),
        "qualification_sha256": qualification_sha256,
    }
    return sha256_id(canonical_json_bytes(encoded))


def _validate_warning_source_url(value: str) -> str:
    if not isinstance(value, str) or not value.isascii() or not 1 <= len(value) <= 2048:
        raise PreliminaryWarningError("warning source URL is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise PreliminaryWarningError("warning source URL is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or bool(parsed.fragment)
    ):
        raise PreliminaryWarningError("warning source URL must be a public HTTPS URL")
    hostname = parsed.hostname.lower()
    if (
        hostname == "localhost"
        or hostname.endswith((".localhost", ".local", ".internal"))
        or "." not in hostname
    ):
        raise PreliminaryWarningError("warning source URL must use a public host")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise PreliminaryWarningError("warning source URL must use a public host")
    return hostname


def create_preliminary_warning(
    session: Session,
    *,
    draft: PreliminaryWarningDraft,
    reviewed_at: datetime,
) -> dict[str, Any]:
    """Publish an Emerging/Unverified warning under one explicit qualification path."""
    reviewed = _aware(reviewed_at, field="reviewed_at")
    observed = _aware(draft.observed_at, field="observed_at")
    if observed > reviewed:
        raise PreliminaryWarningError("warning observation cannot be in the future")
    if not REVIEWER_ID.fullmatch(draft.reviewer_id):
        raise PreliminaryWarningError("warning qualification actor is invalid")
    if draft.evidence_class not in PUBLIC_BETA_EVIDENCE_CLASSES:
        raise PreliminaryWarningError("warning evidence class is invalid")
    if not 1 <= len(draft.source_urls) <= 20 or len(set(draft.source_urls)) != len(
        draft.source_urls
    ):
        raise PreliminaryWarningError("warning requires one to twenty unique source URLs")
    source_origins = tuple(sorted({_validate_warning_source_url(url) for url in draft.source_urls}))
    derived_cluster_count = len(source_origins)
    if draft.independent_source_clusters != derived_cluster_count:
        raise PreliminaryWarningError(
            "warning source count must equal its independently derived public origins"
        )
    qualification_basis = (
        "owner_authorized_early_lead_policy" if draft.policy_qualified else "human_review"
    )
    qualification_reason = (
        "Named actor qualified public early-lead evidence under the owner-authorized policy."
        if draft.policy_qualified
        else "Named human review of independently derived public origins."
    )
    qualification_sha256 = sha256_id(
        canonical_json_bytes(
            {
                "affected_artifacts": sorted(draft.affected_artifacts),
                "basis": qualification_basis,
                "claim": draft.claim,
                "evidence_class": draft.evidence_class,
                "qualification_actor": draft.reviewer_id,
                "reason": qualification_reason,
                "source_origins": source_origins,
                "source_urls": sorted(draft.source_urls),
                "title": draft.title,
            }
        )
    )
    warning_id = stable_id(
        "preliminary-warning",
        draft.title,
        sorted(draft.source_urls),
        timestamp(observed),
    )
    expiry = reviewed + WARNING_LIFETIME
    document = {
        "id": warning_id,
        "kind": "preliminary_warning",
        "schema_version": "1.1.0",
        "revision": 1,
        "created_at": timestamp(reviewed),
        "updated_at": timestamp(reviewed),
        "data_classification": "public",
        "title": draft.title,
        "state": "active",
        "claim": draft.claim,
        "affected_artifacts": list(draft.affected_artifacts),
        "source_urls": list(draft.source_urls),
        "evidence_class": draft.evidence_class,
        "independent_source_clusters": derived_cluster_count,
        "confirmation_status": "unverified",
        "awaiting_authoritative_confirmation": True,
        "automation_allowed": False,
        "max_action_level": 0,
        "human_reviewed": not draft.policy_qualified,
        "qualification_basis": qualification_basis,
        "qualification_actor_id": draft.reviewer_id,
        "qualification_reason": qualification_reason,
        "qualification_sha256": qualification_sha256,
        "source_origins": list(source_origins),
        "warning_text": WARNING_TEXT,
        "observed_at": timestamp(observed),
        "last_checked_at": timestamp(reviewed),
        "next_check_at": timestamp(reviewed + RECHECK_INTERVAL),
        "expires_at": timestamp(expiry),
        "recheck_count": 0,
        "latest_recheck_outcome": "not_checked",
        "latest_recheck_reason": None,
        "latest_recheck_source_urls": [],
        "final_reason": None,
        "terminal_actor_id": None,
        "terminal_evidence_urls": [],
        "terminal_expected_revision": None,
    }
    parsed = parse_contract("PreliminaryWarning", document).model_dump(
        mode="json",
        exclude_none=False,
    )
    record, created = append_contract(session, "PreliminaryWarning", parsed)
    approval_values = {
        "approval_id": stable_id("preliminary-warning-approval", warning_id),
        "warning_id": warning_id,
        "warning_revision": 1,
        "reviewer_id": draft.reviewer_id,
        "independent_source_clusters": derived_cluster_count,
        "reviewed_at": reviewed,
    }
    approval = session.get(
        PreliminaryWarningApprovalRecord,
        approval_values["approval_id"],
    )
    expected_hash = _approval_hash(
        approval_values,
        qualification_sha256=qualification_sha256,
    )
    if approval is None:
        session.add(
            PreliminaryWarningApprovalRecord(
                **approval_values,
                record_hash=expected_hash,
            )
        )
        session.flush()
    elif approval.record_hash != expected_hash:
        raise PreliminaryWarningError("warning approval conflicts with prior history")
    if not created and record.document != parsed:
        raise PreliminaryWarningError("warning identity conflicts with prior history")
    return record.document


def transition_preliminary_warning(
    session: Session,
    *,
    warning_id: str,
    expected_revision: int,
    state: str,
    actor_id: str,
    reason: str,
    evidence_urls: Sequence[str],
    occurred_at: datetime,
) -> dict[str, Any]:
    """Immediately append one operator-attributed terminal warning revision."""
    now = _aware(occurred_at, field="occurred_at")
    if state not in {"withdrawn", "contradicted"}:
        raise PreliminaryWarningError("operator warning transition is invalid")
    if (
        not isinstance(expected_revision, int)
        or isinstance(expected_revision, bool)
        or expected_revision < 1
    ):
        raise PreliminaryWarningError("expected warning revision is invalid")
    if not REVIEWER_ID.fullmatch(actor_id):
        raise PreliminaryWarningError("warning transition actor is invalid")
    if (
        not isinstance(reason, str)
        or reason != reason.strip()
        or not 1 <= len(reason) <= 300
        or not reason.isascii()
    ):
        raise PreliminaryWarningError("warning transition reason is invalid")
    if not 1 <= len(evidence_urls) <= 20 or len(set(evidence_urls)) != len(evidence_urls):
        raise PreliminaryWarningError("warning transition evidence is invalid")
    for source_url in evidence_urls:
        _validate_warning_source_url(source_url)
    advisory_xact_lock(session, f"preliminary-warning:{warning_id}")
    current = get_preliminary_warning(session, warning_id)
    if current is None:
        raise PreliminaryWarningError("warning does not exist")
    if current.state != "active":
        raise PreliminaryWarningError("warning is already terminal")
    if current.revision != expected_revision:
        raise PreliminaryWarningError("warning revision changed")
    current_document = current.document
    return _append_warning_revision(
        session,
        current=current,
        occurred_at=now,
        outcome=current_document["latest_recheck_outcome"],
        recheck_count=current.recheck_count,
        state=state,
        final_reason=reason,
        check_completed=False,
        schedule_next=False,
        terminal_actor_id=actor_id,
        terminal_evidence_urls=evidence_urls,
        terminal_expected_revision=expected_revision,
    )


def _append_warning_revision(
    session: Session,
    *,
    current: PreliminaryWarningRecord,
    occurred_at: datetime,
    outcome: str,
    recheck_count: int,
    state: str | None = None,
    final_reason: str | None = None,
    check_completed: bool,
    schedule_next: bool,
    terminal_actor_id: str | None = None,
    terminal_evidence_urls: Sequence[str] | None = None,
    terminal_expected_revision: int | None = None,
    recheck_reason: str | None = None,
    recheck_source_urls: Sequence[str] | None = None,
    retry_after: timedelta = RECHECK_INTERVAL,
) -> dict[str, Any]:
    now = _aware(occurred_at, field="occurred_at")
    current_document = dict(current.document)
    expiry = datetime.fromisoformat(current_document["expires_at"].replace("Z", "+00:00"))
    next_state = state or current_document["state"]
    next_check = None
    if schedule_next and next_state == "active" and recheck_count < MAX_RECHECKS:
        candidate = now + retry_after
        if candidate < expiry:
            next_check = timestamp(candidate)
    document = {
        **current_document,
        "revision": current_document["revision"] + 1,
        "updated_at": timestamp(now),
        "state": next_state,
        "last_checked_at": (
            timestamp(now) if check_completed else current_document["last_checked_at"]
        ),
        "next_check_at": next_check,
        "recheck_count": recheck_count,
        "latest_recheck_outcome": outcome,
        "latest_recheck_reason": (
            recheck_reason
            if recheck_reason is not None
            else current_document.get("latest_recheck_reason")
        ),
        "latest_recheck_source_urls": (
            list(recheck_source_urls)
            if recheck_source_urls is not None
            else current_document.get("latest_recheck_source_urls", [])
        ),
        "final_reason": final_reason,
        "awaiting_authoritative_confirmation": next_state == "active",
        "terminal_actor_id": (
            terminal_actor_id
            if terminal_actor_id is not None
            else current_document.get("terminal_actor_id")
        ),
        "terminal_evidence_urls": (
            list(terminal_evidence_urls)
            if terminal_evidence_urls is not None
            else current_document.get("terminal_evidence_urls", [])
        ),
        "terminal_expected_revision": (
            terminal_expected_revision
            if terminal_expected_revision is not None
            else current_document.get("terminal_expected_revision")
        ),
    }
    if outcome in {"confirmation_candidate", "contradiction_candidate"}:
        document["confirmation_status"] = outcome
    parsed = parse_contract("PreliminaryWarning", document).model_dump(
        mode="json",
        exclude_none=False,
    )
    record, _created = append_contract(session, "PreliminaryWarning", parsed)
    return record.document


def expire_due_warnings(session: Session, *, now: datetime) -> tuple[str, ...]:
    """Append terminal revisions; never delete warning or recheck history."""
    current_time = _aware(now, field="now")
    latest, statement = _latest_warning_query()
    due = tuple(
        session.scalars(
            statement.where(
                latest.state == "active",
                (latest.expires_at <= current_time) | (latest.recheck_count >= MAX_RECHECKS),
            ).order_by(latest.id)
        )
    )
    expired: list[str] = []
    for current in due:
        advisory_xact_lock(session, f"preliminary-warning:{current.id}")
        refreshed = get_preliminary_warning(session, current.id)
        if (
            refreshed is None
            or refreshed.state != "active"
            or (refreshed.expires_at > current_time and refreshed.recheck_count < MAX_RECHECKS)
        ):
            continue
        reason = (
            "Maximum hourly recheck count reached."
            if refreshed.recheck_count >= MAX_RECHECKS
            else "Fixed 12-hour warning lifetime reached."
        )
        _append_warning_revision(
            session,
            current=refreshed,
            occurred_at=current_time,
            outcome="expired",
            recheck_count=refreshed.recheck_count,
            state="expired",
            final_reason=reason,
            check_completed=False,
            schedule_next=False,
        )
        expired.append(refreshed.id)
    return tuple(expired)


def _store_recheck(
    session: Session,
    *,
    warning_document: Mapping[str, Any],
    sequence: int,
    outcome: str,
    provider_response_id: str | None,
    server_side_tool_calls: int,
    reservation_id: str,
    checked_at: datetime,
) -> PreliminaryWarningRecheckRecord:
    response_hash = (
        sha256_id(provider_response_id.encode("utf-8"))
        if provider_response_id is not None
        else None
    )
    values = {
        "recheck_id": stable_id(
            "preliminary-warning-recheck",
            warning_document["id"],
            str(sequence),
        ),
        "warning_id": warning_document["id"],
        "warning_revision": warning_document["revision"],
        "sequence": sequence,
        "outcome": outcome,
        "provider_response_id_hash": response_hash,
        "server_side_tool_calls": server_side_tool_calls,
        "reservation_id": reservation_id,
        "checked_at": checked_at,
    }
    hash_values = {**values, "checked_at": timestamp(checked_at)}
    expected_hash = sha256_id(canonical_json_bytes(hash_values))
    existing = session.get(PreliminaryWarningRecheckRecord, values["recheck_id"])
    if existing is not None:
        if existing.record_hash != expected_hash:
            raise PreliminaryWarningError("warning recheck conflicts with prior history")
        return existing
    record = PreliminaryWarningRecheckRecord(
        **values,
        record_hash=expected_hash,
    )
    session.add(record)
    session.flush()
    return record


def _recheck_usage(result: RecheckProviderResult, *, maximum_turns: int) -> ProviderUsage:
    return ProviderUsage(
        stage="recheck",
        model=XAI_THREAT_SEARCH_MODEL,
        response_id=result.response_id,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        total_tokens=result.total_tokens,
        cached_input_tokens=result.cached_input_tokens,
        reasoning_tokens=result.reasoning_tokens,
        server_side_tool_calls=result.server_side_tool_calls,
        configured_maximum_turns=maximum_turns,
        request_bytes=result.request_bytes,
        elapsed_milliseconds=result.elapsed_milliseconds,
        response_bytes=result.response_bytes,
        credential_route=result.credential_route,
    )


def _complete_recheck(
    session: Session,
    *,
    warning_id: str,
    sequence: int,
    outcome: str,
    checked_at: datetime,
    reservation_id: str,
    provider_response_id: str | None,
    server_side_tool_calls: int,
    schedule_next: bool,
    reason: str = "Provider usage or result was unavailable.",
    source_urls: Sequence[str] = (),
    retry_after: timedelta = RECHECK_INTERVAL,
) -> dict[str, Any]:
    current = get_preliminary_warning(session, warning_id)
    if current is None or current.state != "active":
        raise PreliminaryWarningError("warning is no longer active")
    if current.recheck_count != sequence:
        raise PreliminaryWarningError("warning recheck sequence changed")
    document = _append_warning_revision(
        session,
        current=current,
        occurred_at=checked_at,
        outcome=outcome,
        recheck_count=sequence,
        check_completed=True,
        schedule_next=schedule_next,
        recheck_reason=reason,
        recheck_source_urls=source_urls,
        retry_after=retry_after,
    )
    _store_recheck(
        session,
        warning_document=document,
        sequence=sequence,
        outcome=outcome,
        provider_response_id=provider_response_id,
        server_side_tool_calls=server_side_tool_calls,
        reservation_id=reservation_id,
        checked_at=checked_at,
    )
    return document


def _dispatch_receipt_exists(session: Session, *, warning_id: str, attempt_key: str) -> bool:
    return (
        session.scalar(
            select(JobRecord.job_id)
            .where(
                JobRecord.queue == "ai-warning-receipts",
                JobRecord.state == "succeeded",
                JobRecord.payload["receipt_type"].as_string() == RECHECK_DISPATCH_RECEIPT,
                JobRecord.payload["run_id"].as_string() == warning_id,
                JobRecord.payload["job_id_sha256"].as_string()
                == sha256_id(attempt_key.encode("utf-8")),
            )
            .limit(1)
        )
        is not None
    )


def _validate_recheck_result(provider_result: RecheckProviderResult, policy: SpendPolicy) -> None:
    if not isinstance(provider_result, RecheckProviderResult):
        raise RecheckProviderUnavailable("xAI recheck result type is invalid")
    if (
        not isinstance(provider_result.response_id, str)
        or not provider_result.response_id
        or len(provider_result.response_id) > 512
        or not provider_result.response_id.isascii()
        or isinstance(provider_result.server_side_tool_calls, bool)
        or not isinstance(provider_result.server_side_tool_calls, int)
        or not 0 <= provider_result.server_side_tool_calls <= 100
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (
                provider_result.input_tokens,
                provider_result.output_tokens,
                provider_result.total_tokens,
                provider_result.cached_input_tokens,
                provider_result.reasoning_tokens,
                provider_result.request_bytes,
                provider_result.elapsed_milliseconds,
                provider_result.response_bytes,
            )
        )
        or provider_result.input_tokens > XAI_MAX_INPUT_TOKENS
        or provider_result.output_tokens > XAI_MAX_OUTPUT_TOKENS
        or provider_result.total_tokens > XAI_MAX_TOTAL_TOKENS
        or provider_result.total_tokens
        != provider_result.input_tokens + provider_result.output_tokens
        or provider_result.cached_input_tokens > provider_result.input_tokens
        or provider_result.reasoning_tokens > provider_result.output_tokens
        or provider_result.request_bytes > policy.maximum_request_bytes
        or provider_result.elapsed_milliseconds > policy.maximum_elapsed_seconds * 1_000
        or provider_result.response_bytes > policy.maximum_response_bytes
    ):
        raise RecheckProviderUnavailable("xAI recheck accounting metadata is invalid")
    if provider_result.server_side_tool_calls > policy.maximum_tool_calls:
        raise RecheckProviderUnavailable(
            "xAI recheck tool usage exceeds its technical envelope",
            provider_result=provider_result,
            reason_code="provider_tool_usage_exceeded",
        )
    if (
        provider_result.input_tokens > RECHECK_MAX_INPUT_TOKENS
        or provider_result.output_tokens > RECHECK_MAX_OUTPUT_TOKENS
        or provider_result.total_tokens > RECHECK_MAX_TOTAL_TOKENS
    ):
        raise RecheckProviderUnavailable(
            "xAI recheck token usage exceeds its technical envelope",
            provider_result=provider_result,
            reason_code="provider_token_usage_exceeded",
        )
    if (
        provider_result.outcome not in PROVIDER_OUTCOMES
        or not isinstance(provider_result.reason, str)
        or not 1 <= len(provider_result.reason) <= 300
        or not provider_result.reason.isascii()
        or not isinstance(provider_result.source_urls, tuple)
        or len(provider_result.source_urls) > 8
        or any(not isinstance(value, str) for value in provider_result.source_urls)
        or len(set(provider_result.source_urls)) != len(provider_result.source_urls)
    ):
        raise RecheckProviderUnavailable(
            "xAI recheck metadata is invalid",
            provider_result=provider_result,
        )
    for source_url in provider_result.source_urls:
        try:
            _validate_warning_source_url(source_url)
        except PreliminaryWarningError as validation_error:
            raise RecheckProviderUnavailable(
                "xAI recheck source is invalid",
                provider_result=provider_result,
            ) from validation_error
    if (
        provider_result.outcome
        in {
            "confirmation_candidate",
            "contradiction_candidate",
        }
        and not provider_result.source_urls
    ):
        raise RecheckProviderUnavailable(
            "xAI candidate result has no public evidence",
            provider_result=provider_result,
        )


def _complete_failed_recheck(
    session_factory: SessionFactory,
    *,
    error: RecheckProviderUnavailable,
    warning_id: str,
    sequence: int,
    attempt_id: str,
    recheck_job_id: str,
    checked_at: datetime,
    known_uncharged_retry: bool,
    provider_input: dict[str, Any],
    policy: SpendPolicy,
) -> RecheckRun:
    with session_factory() as session, session.begin():
        provider_error = error.provider_error
        known_uncharged = (
            getattr(provider_error, "code", None) == "provider_http_error_uncharged"
            and getattr(provider_error, "retryable", False) is True
            and getattr(provider_error, "usage_uncertain", True) is False
        )
        if known_uncharged:
            retry_scheduled = not known_uncharged_retry
            append_warning_lane_receipt(
                session,
                receipt_type="provider_failure",
                reason_code="provider_http_error_uncharged",
                run_id=warning_id,
                job_id=recheck_job_id,
                occurred_at=checked_at + timedelta(microseconds=2),
                public_metadata={
                    "stage": "recheck",
                    "warning_id": warning_id,
                    "sequence": sequence,
                    "attempt_id": attempt_id,
                    "retry_scheduled": retry_scheduled,
                    "error_class": type(provider_error).__name__,
                },
            )
            if retry_scheduled:
                current = get_preliminary_warning(session, warning_id)
                if current is None or current.state != "active":
                    raise PreliminaryWarningError("warning is no longer active") from error
                document = _append_warning_revision(
                    session,
                    current=current,
                    occurred_at=checked_at,
                    outcome="provider_unavailable",
                    recheck_count=sequence,
                    check_completed=False,
                    schedule_next=True,
                    recheck_reason=str(provider_input["claim"]),
                    retry_after=timedelta(minutes=5),
                )
            else:
                document = _complete_recheck(
                    session,
                    warning_id=warning_id,
                    sequence=sequence,
                    outcome="provider_unavailable",
                    checked_at=checked_at,
                    reservation_id=attempt_id,
                    provider_response_id=None,
                    server_side_tool_calls=0,
                    schedule_next=False,
                    reason=str(provider_input["claim"]),
                )
            return RecheckRun(
                warning_id=warning_id,
                outcome="provider_unavailable",
                revision=document["revision"],
                recheck_count=sequence,
            )
        exact_result = error.provider_result
        if exact_result is not None:
            provider_code = getattr(provider_error, "code", None) or error.reason_code
            technical_integrity_reason = (
                str(provider_code) if provider_code in TECHNICAL_USAGE_STOP_REASONS else None
            )
            # The provider answered with trustworthy usage but the content or its
            # technical envelope was rejected: record the usage, then the rejection.
            append_warning_lane_receipt(
                session,
                receipt_type="provider_cost_observed",
                reason_code=(
                    technical_integrity_reason
                    if technical_integrity_reason is not None
                    else "within_technical_envelope"
                ),
                run_id=warning_id,
                job_id=recheck_job_id,
                occurred_at=checked_at + timedelta(microseconds=2),
                public_metadata={
                    "stage": "recheck",
                    "warning_id": warning_id,
                    "sequence": sequence,
                    "attempt_id": attempt_id,
                },
                provider_usage=_recheck_usage(exact_result, maximum_turns=policy.maximum_turns),
            )
            append_warning_lane_receipt(
                session,
                receipt_type=(
                    "provider_failure"
                    if technical_integrity_reason is not None
                    else "qualification_rejection"
                ),
                reason_code=(
                    technical_integrity_reason
                    if technical_integrity_reason is not None
                    else "recheck_response_rejected"
                ),
                run_id=warning_id,
                job_id=recheck_job_id,
                occurred_at=checked_at + timedelta(microseconds=3),
                public_metadata={
                    "stage": "recheck",
                    "warning_id": warning_id,
                    "sequence": sequence,
                    "error_class": type(error).__name__,
                },
            )
            # A technical envelope breach stops further rechecks of this warning.
            document = _complete_recheck(
                session,
                warning_id=warning_id,
                sequence=sequence,
                outcome="provider_unavailable",
                checked_at=checked_at,
                reservation_id=attempt_id,
                provider_response_id=exact_result.response_id,
                server_side_tool_calls=exact_result.server_side_tool_calls,
                schedule_next=technical_integrity_reason is None,
                reason=str(provider_input["claim"]),
            )
            return RecheckRun(
                warning_id=warning_id,
                outcome="provider_unavailable",
                revision=document["revision"],
                recheck_count=sequence,
            )
        provider_code = getattr(provider_error, "code", None)
        append_warning_lane_receipt(
            session,
            receipt_type="provider_failure",
            reason_code=(str(provider_code) if provider_code else "recheck_provider_unavailable"),
            run_id=warning_id,
            job_id=recheck_job_id,
            occurred_at=checked_at + timedelta(microseconds=2),
            public_metadata={
                "stage": "recheck",
                "warning_id": warning_id,
                "sequence": sequence,
                "attempt_id": attempt_id,
                "error_class": type(provider_error or error).__name__,
            },
        )
        document = _complete_recheck(
            session,
            warning_id=warning_id,
            sequence=sequence,
            outcome="provider_unavailable",
            checked_at=checked_at,
            reservation_id=attempt_id,
            provider_response_id=None,
            server_side_tool_calls=0,
            schedule_next=False,
            reason=str(provider_input["claim"]),
        )
    return RecheckRun(
        warning_id=warning_id,
        outcome="provider_unavailable",
        revision=document["revision"],
        recheck_count=sequence,
    )


@dataclass(frozen=True, slots=True)
class _RecheckDispatch:
    sequence: int
    attempt_id: str
    provider_input: dict[str, Any]
    provider_checked_at: datetime
    known_uncharged_retry: bool


def _prepare_recheck(
    session_factory: SessionFactory,
    *,
    warning_id: str,
    policy: SpendPolicy,
    checked_at: datetime,
) -> _RecheckDispatch | RecheckRun:
    known_uncharged_retry = False
    provider_checked_at = checked_at
    with session_factory() as session, session.begin():
        advisory_xact_lock(session, f"preliminary-warning:{warning_id}")
        current = get_preliminary_warning(session, warning_id)
        if current is None:
            raise PreliminaryWarningError("warning does not exist")
        if current.state != "active":
            return RecheckRun(
                warning_id=warning_id,
                outcome=current.state,
                revision=current.revision,
                recheck_count=current.recheck_count,
            )
        if current.expires_at <= checked_at or current.recheck_count >= MAX_RECHECKS:
            expired = _append_warning_revision(
                session,
                current=current,
                occurred_at=checked_at,
                outcome="expired",
                recheck_count=current.recheck_count,
                state="expired",
                final_reason="Fixed warning lifetime or recheck limit reached.",
                check_completed=False,
                schedule_next=False,
            )
            return RecheckRun(
                warning_id=warning_id,
                outcome="expired",
                revision=expired["revision"],
                recheck_count=expired["recheck_count"],
            )
        if current.next_check_at is None or current.next_check_at > checked_at:
            raise PreliminaryWarningError("warning is not due for a recheck")
        if current.recheck_count:
            interrupted_sequence = current.recheck_count
            interrupted_recheck_id = stable_id(
                "preliminary-warning-recheck",
                warning_id,
                str(interrupted_sequence),
            )
            if session.get(PreliminaryWarningRecheckRecord, interrupted_recheck_id) is None:
                retry_receipt = session.scalar(
                    select(JobRecord.job_id)
                    .where(
                        JobRecord.queue == "ai-warning-receipts",
                        JobRecord.state == "succeeded",
                        JobRecord.payload["receipt_type"].as_string() == "provider_failure",
                        JobRecord.payload["reason_code"].as_string()
                        == "provider_http_error_uncharged",
                        JobRecord.payload["run_id"].as_string() == warning_id,
                        JobRecord.payload["public_metadata"]["sequence"].as_integer()
                        == interrupted_sequence,
                        JobRecord.payload["public_metadata"]["retry_scheduled"]
                        .as_boolean()
                        .is_(True),
                    )
                    .limit(1)
                )
                retry_attempt_key = (
                    f"{warning_id}:recheck:{interrupted_sequence}:known-uncharged-retry"
                )
                if retry_receipt is not None and not _dispatch_receipt_exists(
                    session, warning_id=warning_id, attempt_key=retry_attempt_key
                ):
                    prior_dispatch = session.scalar(
                        select(PreliminaryWarningRecord).where(
                            PreliminaryWarningRecord.id == warning_id,
                            PreliminaryWarningRecord.revision == current.revision - 1,
                        )
                    )
                    if (
                        prior_dispatch is None
                        or prior_dispatch.document.get("recheck_count") != interrupted_sequence
                    ):
                        raise PreliminaryWarningError(
                            "known-uncharged recheck request history is unavailable"
                        )
                    provider_input = dict(prior_dispatch.document)
                    provider_checked_at = _aware(
                        datetime.fromisoformat(
                            str(provider_input["updated_at"]).replace("Z", "+00:00")
                        ),
                        field="provider_checked_at",
                    )
                    known_uncharged_retry = True
                else:
                    # The dispatch (first or retry) never stored its completion: the
                    # process died around the provider call. Close the sequence without
                    # another call; the warning keeps its last recorded outcome.
                    interrupted_attempt_key = (
                        retry_attempt_key
                        if retry_receipt is not None
                        else f"{warning_id}:recheck:{interrupted_sequence}"
                    )
                    interrupted_attempt_id = stable_id("recheck-attempt", interrupted_attempt_key)
                    append_warning_lane_receipt(
                        session,
                        receipt_type="provider_failure",
                        reason_code="interrupted_provider_usage",
                        run_id=warning_id,
                        job_id=f"{warning_id}:recheck:{interrupted_sequence}",
                        occurred_at=checked_at + timedelta(microseconds=1),
                        public_metadata={
                            "stage": "recheck",
                            "warning_id": warning_id,
                            "sequence": interrupted_sequence,
                            "attempt_id": interrupted_attempt_id,
                            "error_class": "InterruptedProviderAttempt",
                        },
                    )
                    document = _complete_recheck(
                        session,
                        warning_id=warning_id,
                        sequence=interrupted_sequence,
                        outcome="provider_unavailable",
                        checked_at=checked_at,
                        reservation_id=interrupted_attempt_id,
                        provider_response_id=None,
                        server_side_tool_calls=0,
                        schedule_next=False,
                        reason=str(current.document["claim"]),
                    )
                    return RecheckRun(
                        warning_id=warning_id,
                        outcome="provider_unavailable",
                        revision=document["revision"],
                        recheck_count=interrupted_sequence,
                    )
        policy.assert_preliminary_warning_recheck_allowed()
        sequence = current.recheck_count if known_uncharged_retry else current.recheck_count + 1
        attempt_key = f"{warning_id}:recheck:{sequence}"
        if known_uncharged_retry:
            attempt_key += ":known-uncharged-retry"
        attempt_id = stable_id("recheck-attempt", attempt_key)
        if not known_uncharged_retry:
            dispatch_document = _append_warning_revision(
                session,
                current=current,
                occurred_at=checked_at,
                outcome=current.document["latest_recheck_outcome"],
                recheck_count=sequence,
                check_completed=False,
                schedule_next=True,
            )
            provider_input = dict(dispatch_document)
        append_warning_lane_receipt(
            session,
            receipt_type=RECHECK_DISPATCH_RECEIPT,
            reason_code="recheck_dispatch",
            run_id=warning_id,
            job_id=attempt_key,
            occurred_at=checked_at,
            public_metadata={
                "stage": "recheck",
                "warning_id": warning_id,
                "sequence": sequence,
                "attempt_id": attempt_id,
                "known_uncharged_retry": known_uncharged_retry,
            },
        )
    return _RecheckDispatch(
        sequence,
        attempt_id,
        provider_input,
        provider_checked_at,
        known_uncharged_retry,
    )


def recheck_warning(
    session_factory: SessionFactory,
    *,
    warning_id: str,
    policy: SpendPolicy,
    provider: RecheckProvider,
    now: datetime,
) -> RecheckRun:
    """A paused or budget-blocked check consumes no revision or provider attempt."""
    with provider_guard(session_factory, stage="recheck", now=now) as allowed:
        if not allowed:
            with session_factory() as session:
                current = get_preliminary_warning(session, warning_id)
                if current is None:
                    raise PreliminaryWarningError("warning does not exist")
                return RecheckRun(
                    warning_id, "dispatch_contained", current.revision, current.recheck_count
                )
        return _recheck_warning_admitted(
            session_factory, warning_id=warning_id, policy=policy, provider=provider, now=now
        )


def _recheck_warning_admitted(
    session_factory: SessionFactory,
    *,
    warning_id: str,
    policy: SpendPolicy,
    provider: RecheckProvider,
    now: datetime,
) -> RecheckRun:
    """Run at most one durable hourly check without auto-confirming the warning.

    A dispatch receipt is committed before the provider call and a recheck record
    after it. A recheck with a dispatch receipt and no record was interrupted; it is
    closed without a second provider call, so a warning can never be checked twice for
    one sequence. Provider cost is not recorded: the owner monitors billing.
    """
    checked_at = _aware(now, field="now")
    dispatch = _prepare_recheck(
        session_factory,
        warning_id=warning_id,
        policy=policy,
        checked_at=checked_at,
    )
    if isinstance(dispatch, RecheckRun):
        return dispatch
    sequence = dispatch.sequence
    attempt_id = dispatch.attempt_id
    provider_input = dispatch.provider_input
    provider_checked_at = dispatch.provider_checked_at
    known_uncharged_retry = dispatch.known_uncharged_retry

    recheck_job_id = f"{warning_id}:recheck:{sequence}"
    try:
        provider_result = provider(provider_input, provider_checked_at)
        _validate_recheck_result(provider_result, policy)
    except RecheckProviderUnavailable as error:
        return _complete_failed_recheck(
            session_factory,
            error=error,
            warning_id=warning_id,
            sequence=sequence,
            attempt_id=attempt_id,
            recheck_job_id=recheck_job_id,
            checked_at=checked_at,
            known_uncharged_retry=known_uncharged_retry,
            provider_input=provider_input,
            policy=policy,
        )

    completed_at = checked_at + timedelta(microseconds=1)
    with session_factory() as session, session.begin():
        append_warning_lane_receipt(
            session,
            receipt_type="provider_cost_observed",
            reason_code="within_technical_envelope",
            run_id=warning_id,
            job_id=recheck_job_id,
            occurred_at=completed_at + timedelta(microseconds=1),
            public_metadata={
                "stage": "recheck",
                "warning_id": warning_id,
                "sequence": sequence,
                "attempt_id": attempt_id,
                "model_reason": provider_result.reason,
            },
            provider_usage=_recheck_usage(provider_result, maximum_turns=policy.maximum_turns),
        )
        document = _complete_recheck(
            session,
            warning_id=warning_id,
            sequence=sequence,
            outcome=provider_result.outcome,
            checked_at=checked_at,
            reservation_id=attempt_id,
            provider_response_id=provider_result.response_id,
            server_side_tool_calls=provider_result.server_side_tool_calls,
            schedule_next=True,
            reason=str(provider_input["claim"]),
            source_urls=provider_result.source_urls,
        )
    return RecheckRun(
        warning_id=warning_id,
        outcome=provider_result.outcome,
        revision=document["revision"],
        recheck_count=sequence,
    )


def due_warning_ids(
    session: Session,
    *,
    now: datetime,
    limit: int = 20,
) -> tuple[str, ...]:
    current_time = _aware(now, field="now")
    if not 1 <= limit <= 100:
        raise PreliminaryWarningError("due warning limit is invalid")
    latest, statement = _latest_warning_query()
    records = session.scalars(
        statement.where(
            latest.state == "active",
            latest.next_check_at.is_not(None),
            latest.next_check_at <= current_time,
            latest.expires_at > current_time,
            latest.recheck_count < MAX_RECHECKS,
        )
        .order_by(latest.next_check_at, latest.id)
        .limit(limit)
    )
    return tuple(record.id for record in records)


def _bounded_provider_json(
    value: bytes | str,
    *,
    deadline: OperationDeadline,
) -> Any:
    """Parse the provider's JSON strictly under the request deadline."""
    try:
        deadline.check()
        # strict_json_loads already strides the callback (every 128 nodes).
        document = strict_json_loads(
            value,
            max_nodes=PROVIDER_JSON_MAX_NODES,
            max_depth=PROVIDER_JSON_MAX_DEPTH,
            on_node=deadline.check,
        )
        deadline.check()
    except AcquisitionRejected as error:
        # Placed above ValueError (its base class) so a deadline expiry keeps the
        # pre-existing conversion instead of being classified as a JSON defect.
        raise RecheckProviderUnavailable("xAI response is not valid bounded JSON") from error
    except (RecursionError, UnicodeDecodeError) as error:
        raise RecheckProviderUnavailable("xAI response is not valid bounded JSON") from error
    except DuplicateJsonKeyError as error:
        raise RecheckProviderUnavailable("xAI response contains a duplicate JSON key") from error
    except ValueError as error:
        reason = getattr(error, "reason", None)
        if reason == "non_finite":
            raise RecheckProviderUnavailable(
                "xAI response contains an invalid JSON number"
            ) from error
        if reason in {"too_many_nodes", "too_deep"}:
            raise RecheckProviderUnavailable("xAI response JSON exceeds its shape limit") from error
        raise RecheckProviderUnavailable("xAI response is not valid bounded JSON") from error
    return document


class XaiWarningRecheckProvider:
    """One fixed-host, maximum-reasoning xAI Web and X recheck."""

    def __init__(
        self,
        *,
        api_key: str,
        client: httpx.Client | None = None,
        monotonic_clock: Callable[[], float] = monotonic,
        maximum_request_bytes: int = XAI_MAX_REQUEST_BYTES,
        maximum_response_bytes: int = XAI_MAX_RESPONSE_BYTES,
        maximum_elapsed_seconds: int = XAI_MAX_ELAPSED_SECONDS,
    ) -> None:
        if not api_key or len(api_key) > 1024:
            raise ValueError("xAI API key is absent or invalid")
        self._api_key = api_key
        self._client = client
        self._monotonic_clock = monotonic_clock
        self._maximum_request_bytes = maximum_request_bytes
        self._maximum_response_bytes = maximum_response_bytes
        self._maximum_elapsed_seconds = maximum_elapsed_seconds

    def __call__(
        self,
        warning: Mapping[str, Any],
        checked_at: datetime,
    ) -> RecheckProviderResult:
        observed = datetime.fromisoformat(str(warning["observed_at"]).replace("Z", "+00:00"))
        public_warning = {
            "title": warning["title"],
            "claim": warning["claim"],
            "affected_artifacts": warning["affected_artifacts"],
            "source_urls": warning["source_urls"],
            "observed_at": warning["observed_at"],
        }
        payload = {
            "model": XAI_THREAT_SEARCH_MODEL,
            "service_tier": "default",
            "reasoning": {"effort": XAI_THREAT_SEARCH_REASONING_EFFORT},
            "store": False,
            "parallel_tool_calls": False,
            "prompt_cache_key": warning["id"],
            "max_tool_calls": 4,
            "max_turns": 3,
            "max_output_tokens": RECHECK_MAX_OUTPUT_TOKENS,
            "instructions": (
                "Recheck only whether this already qualified preliminary software "
                "supply-chain warning has meaningful new public evidence. Search the "
                "web and X. Do not treat repetition, copied reporting, or model "
                "inference as confirmation. Return confirmation_candidate only when "
                "you find an attributable authoritative or independent non-social "
                "source. Return contradiction_candidate only for attributable "
                "contrary evidence. You cannot confirm, publish, remediate, contact "
                "anyone, or authorize action."
            ),
            # Deliberately not the canonical layout: these bytes are part of the hashed
            # request and its receipts, so the layout is frozen.
            "input": json.dumps(public_warning, sort_keys=True, ensure_ascii=True),
            "tools": [
                {"type": "web_search"},
                {
                    "type": "x_search",
                    "from_date": observed.astimezone(UTC).date().isoformat(),
                    "to_date": checked_at.astimezone(UTC).date().isoformat(),
                },
            ],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "preliminary_warning_recheck",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "outcome": {
                                "type": "string",
                                "enum": sorted(PROVIDER_OUTCOMES),
                            },
                            "reason": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 300,
                            },
                            "source_urls": {
                                "type": "array",
                                "maxItems": 8,
                                "uniqueItems": True,
                                "items": {"type": "string", "format": "uri"},
                            },
                        },
                        "required": ["outcome", "reason", "source_urls"],
                    },
                }
            },
        }
        from smithguard.scheduled_discovery import (
            ScheduledProviderError,
            XaiScheduledWarningProvider,
        )

        shared_provider = XaiScheduledWarningProvider(
            api_key=self._api_key,
            client=self._client,
            monotonic_clock=self._monotonic_clock,
            maximum_request_bytes=self._maximum_request_bytes,
            maximum_response_bytes=self._maximum_response_bytes,
            maximum_elapsed_seconds=self._maximum_elapsed_seconds,
            maximum_output_tokens=RECHECK_MAX_OUTPUT_TOKENS,
            maximum_total_tokens=RECHECK_MAX_TOTAL_TOKENS,
        )
        try:
            provider_result = shared_provider._request(
                payload,
                allowed_output_types=frozenset(
                    {"message", "reasoning", "web_search_call", "x_search_call"}
                ),
                maximum_tool_calls=4,
            )
        except ScheduledProviderError as error:
            raise RecheckProviderUnavailable(
                error.code,
                provider_error=error,
                provider_result=error.exact_usage,
            ) from error
        deadline = OperationDeadline.start(
            self._maximum_elapsed_seconds,
            clock=self._monotonic_clock,
        )
        try:
            result = _bounded_provider_json(provider_result.output_text, deadline=deadline)
        except RecheckProviderUnavailable as error:
            raise RecheckProviderUnavailable(
                str(error),
                provider_result=provider_result,
            ) from error
        if not isinstance(result, Mapping) or set(result) != {
            "outcome",
            "reason",
            "source_urls",
        }:
            raise RecheckProviderUnavailable(
                "xAI recheck result shape is invalid",
                provider_result=provider_result,
            )
        outcome = result["outcome"]
        reason = result["reason"]
        source_urls = result["source_urls"]
        if (
            not isinstance(outcome, str)
            or outcome not in PROVIDER_OUTCOMES
            or not isinstance(reason, str)
            or not 1 <= len(reason) <= 300
            or not reason.isascii()
            or not isinstance(source_urls, list)
            or len(source_urls) > 8
            or not all(isinstance(value, str) for value in source_urls)
            or len(set(source_urls)) != len(source_urls)
        ):
            raise RecheckProviderUnavailable(
                "xAI recheck result is invalid",
                provider_result=provider_result,
            )
        try:
            canonical_sources = tuple(canonical_public_url(value) for value in source_urls)
            canonical_citations = {
                canonical_public_url(value)
                for value in provider_result.citation_urls
                if len(value) <= 2048
            }
        except ValueError as error:
            raise RecheckProviderUnavailable(
                "xAI source citation is invalid",
                provider_result=provider_result,
            ) from error
        if tuple(source_urls) != canonical_sources or not set(canonical_sources).issubset(
            canonical_citations
        ):
            raise RecheckProviderUnavailable(
                "xAI source is absent from provider citations",
                provider_result=provider_result,
            )
        return RecheckProviderResult(
            outcome=outcome,
            response_id=provider_result.response_id,
            server_side_tool_calls=provider_result.server_side_tool_calls,
            reason=reason,
            source_urls=canonical_sources,
            input_tokens=provider_result.input_tokens,
            output_tokens=provider_result.output_tokens,
            total_tokens=provider_result.total_tokens,
            cached_input_tokens=provider_result.cached_input_tokens,
            reasoning_tokens=provider_result.reasoning_tokens,
            request_bytes=provider_result.request_bytes,
            elapsed_milliseconds=provider_result.elapsed_milliseconds,
            response_bytes=provider_result.response_bytes,
            credential_route=provider_result.credential_route,
        )
