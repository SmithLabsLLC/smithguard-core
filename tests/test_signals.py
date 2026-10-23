"""Actor-qualified preliminary warnings remain bounded, temporary, and auditable."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from smithguard.db.models import (
    JobRecord,
    PreliminaryWarningApprovalRecord,
    PreliminaryWarningRecheckRecord,
    PreliminaryWarningRecord,
)
from smithguard.identifiers import stable_id
from smithguard.signals import (
    RECHECK_DISPATCH_RECEIPT,
    RECHECK_MAX_OUTPUT_TOKENS,
    WARNING_TEXT,
    PreliminaryWarningDraft,
    PreliminaryWarningError,
    RecheckProviderResult,
    RecheckProviderUnavailable,
    XaiWarningRecheckProvider,
    create_preliminary_warning,
    due_warning_ids,
    expire_due_warnings,
    get_preliminary_warning,
    list_preliminary_warnings,
    matching_preliminary_warnings,
    recheck_warning,
    transition_preliminary_warning,
)
from smithguard.spend import load_spend_policy_path
from smithguard.xai_settings import (
    XAI_THREAT_SEARCH_MODEL,
    XAI_THREAT_SEARCH_REASONING_EFFORT,
)

pytestmark = pytest.mark.usefixtures("enabled_warning_dispatch")

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "contracts/v1/xai-spend-policy.json"
NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


class TrackingStream(httpx.SyncByteStream):
    def __init__(self, chunks: tuple[bytes, ...], *, before_yield=None) -> None:
        self.chunks = chunks
        self.before_yield = before_yield
        self.read_count = 0

    def __iter__(self):
        for chunk in self.chunks:
            if self.before_yield is not None:
                self.before_yield()
            self.read_count += 1
            yield chunk


def _provider_warning() -> dict:
    return {
        "id": "gbsec:warning:synthetic",
        "title": "Synthetic warning",
        "claim": "Synthetic claim.",
        "affected_artifacts": ["npm:synthetic@1.0.0"],
        "source_urls": [
            "https://example.test/one",
            "https://example.test/two",
        ],
        "observed_at": "2026-08-05T12:00:00Z",
    }


def _provider_response_body() -> bytes:
    return json.dumps(
        {
            "id": "response-fixed-boundary",
            "model": "grok-4.7",
            "service_tier": "default",
            "status": "completed",
            "incomplete_details": None,
            "output": [
                {
                    "id": "message-synthetic",
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "content": [
                        {
                            "type": "output_text",
                            "text": (
                                '{"outcome":"no_new_evidence",'
                                '"reason":"No material new public evidence.",'
                                '"source_urls":[]}'
                            ),
                        }
                    ],
                },
            ],
            "usage": {
                "num_server_side_tools_used": 0,
                "input_tokens": 100,
                "output_tokens": 20,
                "total_tokens": 120,
                "input_tokens_details": {"cached_tokens": 10},
                "output_tokens_details": {"reasoning_tokens": 5},
            },
        }
    ).encode()


def _draft(suffix: str = "one") -> PreliminaryWarningDraft:
    return PreliminaryWarningDraft(
        title=f"Unverified synthetic warning {suffix}",
        claim="Two independent public leads describe a possible package compromise.",
        affected_artifacts=("npm:synthetic-warning@1.0.0",),
        source_urls=(
            f"https://example.com/source-{suffix}-one",
            f"https://example.org/source-{suffix}-two",
        ),
        evidence_class="web_and_social",
        independent_source_clusters=2,
        observed_at=NOW,
        reviewer_id="reviewer:owner",
    )


def _active_policy():
    # Historical paid transport/receipt fixtures; current subscription policies
    # reject this route, covered separately by the negative production test.
    return replace(
        load_spend_policy_path(POLICY_PATH),
        subscription_first=False,
        policy_state="active",
        external_calls_allowed=True,
        unattended_collection_allowed=True,
        all_required_controls_pass=True,
    )


def _create(database, suffix: str = "one") -> str:
    with Session(database.engine) as session, session.begin():
        document = create_preliminary_warning(
            session,
            draft=_draft(suffix),
            reviewed_at=NOW,
        )
        assert document["warning_text"] == WARNING_TEXT
        assert not document["automation_allowed"]
        assert document["max_action_level"] == 0
        assert document["expires_at"] == "2026-08-06T00:00:00Z"
        return document["id"]


def _receipts(session: Session) -> list[dict]:
    """Return every warning-lane receipt payload in completion order."""
    return [
        dict(record.payload)
        for record in session.scalars(
            select(JobRecord)
            .where(JobRecord.queue == "ai-warning-receipts")
            .order_by(JobRecord.completed_at, JobRecord.job_id)
        )
    ]


def _receipt_kinds(session: Session) -> list[tuple[str, str]]:
    return [(item["receipt_type"], item["reason_code"]) for item in _receipts(session)]


def _attempt_id(warning_id: str, sequence: int, *, retry: bool = False) -> str:
    key = f"{warning_id}:recheck:{sequence}"
    if retry:
        key += ":known-uncharged-retry"
    return stable_id("recheck-attempt", key)


def test_public_warning_accepts_policy_qualified_social_lead_and_rejects_private_urls(
    database,
) -> None:
    with Session(database.engine) as session, session.begin():
        social = create_preliminary_warning(
            session,
            draft=replace(
                _draft("social"),
                source_urls=("https://example.com/social-lead",),
                evidence_class="social_only",
                independent_source_clusters=1,
                reviewer_id="scanner:grok-social",
                policy_qualified=True,
            ),
            reviewed_at=NOW,
        )
        assert social["confirmation_status"] == "unverified"
        assert social["qualification_basis"] == "owner_authorized_early_lead_policy"
        assert social["qualification_actor_id"] == "scanner:grok-social"
        assert social["human_reviewed"] is False

        strengthened = create_preliminary_warning(
            session,
            draft=replace(
                _draft("strengthened"),
                evidence_class="social_only",
                reviewer_id="scanner:grok-social",
                policy_qualified=True,
            ),
            reviewed_at=NOW,
        )
        assert strengthened["independent_source_clusters"] == 2
        assert strengthened["qualification_basis"] == "owner_authorized_early_lead_policy"

        human_one_origin = create_preliminary_warning(
            session,
            draft=replace(
                _draft("human-one-origin"),
                source_urls=("https://example.net/human-reviewed-lead",),
                independent_source_clusters=1,
            ),
            reviewed_at=NOW,
        )
        assert human_one_origin["human_reviewed"] is True
        assert human_one_origin["qualification_actor_id"] == "reviewer:owner"
        for invalid_url in (
            "http://example.com/source",
            "ftp://example.com/source",
            "https://user:password@example.com/source",
            "https://example.com:8443/source",
            "https://example.com/source#fragment",
            "https://127.0.0.1/source",
            "https://169.254.169.254/source",
            "https://10.0.0.1/source",
        ):
            with pytest.raises(PreliminaryWarningError, match="public|HTTPS"):
                create_preliminary_warning(
                    session,
                    draft=replace(
                        _draft("url"),
                        source_urls=(
                            invalid_url,
                            "https://example.org/source-two",
                        ),
                    ),
                    reviewed_at=NOW,
                )


def test_warning_human_review_path_expires_into_append_only_history(
    database,
) -> None:
    warning_id = _create(database)
    with Session(database.engine) as session:
        assert due_warning_ids(session, now=NOW) == ()
        assert due_warning_ids(session, now=NOW + timedelta(hours=1)) == (warning_id,)
        assert (
            session.scalar(select(func.count()).select_from(PreliminaryWarningApprovalRecord)) == 1
        )

    factory = sessionmaker(database.engine)
    calls = 0

    def provider(_warning, _checked_at):
        nonlocal calls
        calls += 1
        return RecheckProviderResult(
            outcome="still_unverified",
            response_id=f"xai-response-{calls}",
            server_side_tool_calls=2,
        )

    for hour in range(1, 12):
        with Session(database.engine) as session:
            assert due_warning_ids(
                session,
                now=NOW + timedelta(hours=hour),
            ) == (warning_id,)
        result = recheck_warning(
            factory,
            warning_id=warning_id,
            policy=_active_policy(),
            provider=provider,
            now=NOW + timedelta(hours=hour),
        )
        assert result.outcome == "still_unverified"
        assert result.recheck_count == hour

    with Session(database.engine) as session, session.begin():
        assert due_warning_ids(session, now=NOW + timedelta(hours=12)) == ()
        assert expire_due_warnings(
            session,
            now=NOW + timedelta(hours=12),
        ) == (warning_id,)
        archived = list_preliminary_warnings(session, state="expired")
        assert len(archived) == 1
        assert archived[0].id == warning_id
        assert archived[0].recheck_count == 11
        assert archived[0].document["final_reason"] == "Fixed 12-hour warning lifetime reached."
        assert (
            session.scalar(select(func.count()).select_from(PreliminaryWarningRecheckRecord)) == 11
        )
        assert session.scalar(select(func.count()).select_from(PreliminaryWarningRecord)) == 24
        kinds = _receipt_kinds(session)
        assert kinds.count((RECHECK_DISPATCH_RECEIPT, "recheck_dispatch")) == 11
        assert kinds.count(("provider_cost_observed", "within_technical_envelope")) == 11
        assert len(kinds) == 22
        rechecks = list(
            session.scalars(
                select(PreliminaryWarningRecheckRecord).order_by(
                    PreliminaryWarningRecheckRecord.sequence
                )
            )
        )
        assert [item.reservation_id for item in rechecks] == [
            _attempt_id(warning_id, sequence) for sequence in range(1, 12)
        ]


def test_wall_clock_expiry_hides_a_still_stored_active_warning(database) -> None:
    warning_id = _create(database, "wall-clock")
    with Session(database.engine) as session:
        assert (
            list_preliminary_warnings(
                session,
                state="active",
                now=NOW + timedelta(hours=12),
            )
            == ()
        )
        assert (
            matching_preliminary_warnings(
                session,
                affected_artifacts=("npm:synthetic-warning@1.0.0",),
                now=NOW + timedelta(hours=12),
            )
            == ()
        )
        stored = get_preliminary_warning(session, warning_id)
        assert stored is not None and stored.state == "active"
        assert (
            get_preliminary_warning(
                session,
                warning_id,
                now=NOW + timedelta(hours=12),
            )
            is None
        )


def test_operator_can_immediately_withdraw_with_bound_reason_and_evidence(database) -> None:
    warning_id = _create(database, "operator-withdrawal")
    with Session(database.engine) as session, session.begin():
        withdrawn = transition_preliminary_warning(
            session,
            warning_id=warning_id,
            expected_revision=1,
            state="withdrawn",
            actor_id="operator:owner",
            reason="The originating report was retracted.",
            evidence_urls=("https://example.net/retraction",),
            occurred_at=NOW + timedelta(minutes=5),
        )
        assert withdrawn["state"] == "withdrawn"
        assert withdrawn["terminal_actor_id"] == "operator:owner"
        assert withdrawn["terminal_expected_revision"] == 1
        assert withdrawn["terminal_evidence_urls"] == ["https://example.net/retraction"]
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(PreliminaryWarningError, match="already terminal"),
    ):
        transition_preliminary_warning(
            session,
            warning_id=warning_id,
            expected_revision=1,
            state="withdrawn",
            actor_id="operator:owner",
            reason="Duplicate transition.",
            evidence_urls=("https://example.net/retraction",),
            occurred_at=NOW + timedelta(minutes=6),
        )


def test_operator_transition_requires_public_evidence(database) -> None:
    warning_id = _create(database, "operator-evidence-required")
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(PreliminaryWarningError, match="transition evidence"),
    ):
        transition_preliminary_warning(
            session,
            warning_id=warning_id,
            expected_revision=1,
            state="contradicted",
            actor_id="operator:owner",
            reason="The report conflicts with current public evidence.",
            evidence_urls=(),
            occurred_at=NOW + timedelta(minutes=5),
        )


def test_confirmation_candidate_never_auto_confirms_or_authorizes_action(
    database,
) -> None:
    warning_id = _create(database, "candidate")
    result = recheck_warning(
        sessionmaker(database.engine),
        warning_id=warning_id,
        policy=_active_policy(),
        provider=lambda _warning, _checked_at: RecheckProviderResult(
            outcome="confirmation_candidate",
            response_id="xai-confirmation-candidate",
            server_side_tool_calls=2,
            reason="An independent public report may confirm the claim.",
            source_urls=("https://example.net/confirmation",),
        ),
        now=NOW + timedelta(hours=1),
    )
    assert result.outcome == "confirmation_candidate"
    with Session(database.engine) as session:
        current = get_preliminary_warning(session, warning_id)
        assert current is not None
        assert current.state == "active"
        assert current.document["confirmation_status"] == "confirmation_candidate"
        assert current.document["automation_allowed"] is False
        assert current.document["max_action_level"] == 0
        assert current.document["latest_recheck_reason"] == _draft("candidate").claim
        assert "independent public report" not in current.document["latest_recheck_reason"]


def test_recheck_semantic_rejection_records_usage_and_continues(database) -> None:
    warning_id = _create(database, "semantic-rejection")
    result = recheck_warning(
        sessionmaker(database.engine),
        warning_id=warning_id,
        policy=_active_policy(),
        provider=lambda _warning, _checked_at: RecheckProviderResult(
            outcome="unsupported_outcome",
            response_id="xai-semantic-rejection",
            server_side_tool_calls=0,
        ),
        now=NOW + timedelta(hours=1),
    )
    assert result.outcome == "provider_unavailable"
    with Session(database.engine) as session:
        current = get_preliminary_warning(session, warning_id)
        assert current is not None
        assert current.next_check_at == NOW + timedelta(hours=2)
        assert _receipt_kinds(session) == [
            (RECHECK_DISPATCH_RECEIPT, "recheck_dispatch"),
            ("provider_cost_observed", "within_technical_envelope"),
            ("qualification_rejection", "recheck_response_rejected"),
        ]
        usage = _receipts(session)[1]
        assert usage["provider"]["stage"] == "recheck"
        assert usage["provider"]["response_id_sha256"] is not None
        assert "exact_cost_usd_ticks" not in usage["provider"]
        assert "price_id" not in usage["provider"]
        recheck = session.scalar(select(PreliminaryWarningRecheckRecord))
        assert recheck is not None
        assert recheck.outcome == "provider_unavailable"
        assert recheck.reservation_id == _attempt_id(warning_id, 1)


def test_recheck_technical_usage_breach_records_usage_and_stops_rechecks(database) -> None:
    warning_id = _create(database, "technical-usage-breach")
    result = recheck_warning(
        sessionmaker(database.engine),
        warning_id=warning_id,
        policy=_active_policy(),
        provider=lambda _warning, _checked_at: RecheckProviderResult(
            outcome="still_unverified",
            response_id="xai-recheck-token-overage",
            server_side_tool_calls=0,
            input_tokens=100,
            output_tokens=RECHECK_MAX_OUTPUT_TOKENS + 1,
            total_tokens=100 + RECHECK_MAX_OUTPUT_TOKENS + 1,
        ),
        now=NOW + timedelta(hours=1),
    )
    assert result.outcome == "provider_unavailable"
    with Session(database.engine) as session:
        current = get_preliminary_warning(session, warning_id)
        assert current is not None
        assert current.next_check_at is None
        assert _receipt_kinds(session) == [
            (RECHECK_DISPATCH_RECEIPT, "recheck_dispatch"),
            ("provider_cost_observed", "provider_token_usage_exceeded"),
            ("provider_failure", "provider_token_usage_exceeded"),
        ]
        recheck = session.scalar(select(PreliminaryWarningRecheckRecord))
        assert recheck is not None
        assert recheck.outcome == "provider_unavailable"


def test_recheck_tool_usage_breach_records_usage_and_stops_rechecks(database) -> None:
    warning_id = _create(database, "tool-usage-breach")
    result = recheck_warning(
        sessionmaker(database.engine),
        warning_id=warning_id,
        policy=_active_policy(),
        provider=lambda _warning, _checked_at: RecheckProviderResult(
            outcome="still_unverified",
            response_id="xai-recheck-tool-overage",
            server_side_tool_calls=_active_policy().maximum_tool_calls + 1,
        ),
        now=NOW + timedelta(hours=1),
    )
    assert result.outcome == "provider_unavailable"
    with Session(database.engine) as session:
        current = get_preliminary_warning(session, warning_id)
        assert current is not None
        assert current.next_check_at is None
        assert _receipt_kinds(session) == [
            (RECHECK_DISPATCH_RECEIPT, "recheck_dispatch"),
            ("provider_cost_observed", "provider_tool_usage_exceeded"),
            ("provider_failure", "provider_tool_usage_exceeded"),
        ]


def test_provider_unavailable_is_logged_and_another_hour_is_scheduled(
    database,
) -> None:
    warning_id = _create(database, "unavailable")

    def unavailable(_warning, _checked_at):
        raise RecheckProviderUnavailable("synthetic provider outage")

    result = recheck_warning(
        sessionmaker(database.engine),
        warning_id=warning_id,
        policy=_active_policy(),
        provider=unavailable,
        now=NOW + timedelta(hours=1),
    )
    assert result.outcome == "provider_unavailable"
    with Session(database.engine) as session:
        current = get_preliminary_warning(session, warning_id)
        assert current is not None
        assert current.next_check_at is None
        recheck = session.scalar(select(PreliminaryWarningRecheckRecord))
        assert recheck is not None
        assert recheck.outcome == "provider_unavailable"
        assert recheck.provider_response_id_hash is None
        assert recheck.reservation_id == _attempt_id(warning_id, 1)
        assert _receipt_kinds(session) == [
            (RECHECK_DISPATCH_RECEIPT, "recheck_dispatch"),
            ("provider_failure", "recheck_provider_unavailable"),
        ]


def test_known_uncharged_recheck_retries_once_after_five_minutes(database) -> None:
    warning_id = _create(database, "known-uncharged")
    requests: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.content)
        return httpx.Response(
            503,
            json={"error": {"code": "temporarily_unavailable"}},
            request=request,
        )

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    factory = sessionmaker(database.engine)
    first_time = NOW + timedelta(hours=1)
    first = recheck_warning(
        factory,
        warning_id=warning_id,
        policy=_active_policy(),
        provider=provider,
        now=first_time,
    )
    assert first.outcome == "provider_unavailable"
    with Session(database.engine) as session:
        current = get_preliminary_warning(session, warning_id)
        assert current is not None
        assert current.next_check_at == first_time + timedelta(minutes=5)

    second = recheck_warning(
        factory,
        warning_id=warning_id,
        policy=_active_policy(),
        provider=provider,
        now=first_time + timedelta(minutes=5),
    )
    assert second.outcome == "provider_unavailable"
    assert first.recheck_count == second.recheck_count == 1
    assert requests[0] == requests[1]
    with Session(database.engine) as session:
        current = get_preliminary_warning(session, warning_id)
        assert current is not None
        assert current.next_check_at is None
        receipts = tuple(
            session.scalars(
                select(JobRecord)
                .where(
                    JobRecord.queue == "ai-warning-receipts",
                    JobRecord.payload["receipt_type"].as_string() == "provider_failure",
                )
                .order_by(JobRecord.completed_at)
            )
        )
        assert [item.payload["public_metadata"]["retry_scheduled"] for item in receipts] == [
            True,
            False,
        ]
        dispatches = [
            item for item in _receipts(session) if item["receipt_type"] == RECHECK_DISPATCH_RECEIPT
        ]
        assert [item["public_metadata"]["known_uncharged_retry"] for item in dispatches] == [
            False,
            True,
        ]
        assert [item["public_metadata"]["attempt_id"] for item in dispatches] == [
            _attempt_id(warning_id, 1),
            _attempt_id(warning_id, 1, retry=True),
        ]
        assert "provider_cost_observed" not in {item["receipt_type"] for item in _receipts(session)}
        recheck = session.scalar(select(PreliminaryWarningRecheckRecord))
        assert recheck is not None
        assert recheck.reservation_id == _attempt_id(warning_id, 1, retry=True)


def test_interrupted_known_uncharged_retry_is_never_dispatched_again(database) -> None:
    warning_id = _create(database, "interrupted-known-uncharged")
    calls = 0

    def uncharged_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            json={"error": {"code": "temporarily_unavailable"}},
            request=request,
        )

    first_provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(transport=httpx.MockTransport(uncharged_handler)),
    )

    def interrupted_provider(warning, checked_at):
        nonlocal calls
        calls += 1
        if calls == 1:
            return first_provider(warning, checked_at)
        raise SystemExit("synthetic retry process interruption")

    factory = sessionmaker(database.engine)
    first_time = NOW + timedelta(hours=1)
    first = recheck_warning(
        factory,
        warning_id=warning_id,
        policy=_active_policy(),
        provider=interrupted_provider,
        now=first_time,
    )
    assert first.outcome == "provider_unavailable"
    with pytest.raises(SystemExit, match="retry process interruption"):
        recheck_warning(
            factory,
            warning_id=warning_id,
            policy=_active_policy(),
            provider=interrupted_provider,
            now=first_time + timedelta(minutes=5),
        )

    def must_not_run(_warning, _checked_at):
        raise AssertionError("recovery must not dispatch a second retry")

    recovered = recheck_warning(
        factory,
        warning_id=warning_id,
        policy=_active_policy(),
        provider=must_not_run,
        now=first_time + timedelta(minutes=10),
    )
    assert calls == 2
    assert recovered.outcome == "provider_unavailable"
    assert recovered.recheck_count == 1
    with Session(database.engine) as session:
        current = get_preliminary_warning(session, warning_id)
        assert current is not None
        assert current.next_check_at is None
        assert _receipt_kinds(session) == [
            (RECHECK_DISPATCH_RECEIPT, "recheck_dispatch"),
            ("provider_failure", "provider_http_error_uncharged"),
            (RECHECK_DISPATCH_RECEIPT, "recheck_dispatch"),
            ("provider_failure", "interrupted_provider_usage"),
        ]
        interrupted = _receipts(session)[-1]["public_metadata"]
        assert interrupted["attempt_id"] == _attempt_id(warning_id, 1, retry=True)
        recheck = session.scalar(select(PreliminaryWarningRecheckRecord))
        assert recheck is not None
        assert recheck.outcome == "provider_unavailable"
        assert recheck.reservation_id == _attempt_id(warning_id, 1, retry=True)


def test_interrupted_dispatch_is_closed_without_a_duplicate_provider_call(
    database,
) -> None:
    warning_id = _create(database, "interrupted")
    calls = 0

    def interrupted(_warning, _checked_at):
        nonlocal calls
        calls += 1
        raise RuntimeError("synthetic process interruption")

    factory = sessionmaker(database.engine)
    with pytest.raises(RuntimeError, match="process interruption"):
        recheck_warning(
            factory,
            warning_id=warning_id,
            policy=_active_policy(),
            provider=interrupted,
            now=NOW + timedelta(hours=1),
        )
    with Session(database.engine) as session:
        current = get_preliminary_warning(session, warning_id)
        assert current is not None
        assert current.recheck_count == 1
        recheck_count = session.scalar(
            select(func.count()).select_from(PreliminaryWarningRecheckRecord)
        )
        assert recheck_count == 0
        assert _receipt_kinds(session) == [(RECHECK_DISPATCH_RECEIPT, "recheck_dispatch")]

    def must_not_run(_warning, _checked_at):
        raise AssertionError("recovery must not issue a duplicate provider request")

    recovered = recheck_warning(
        factory,
        warning_id=warning_id,
        policy=_active_policy(),
        provider=must_not_run,
        now=NOW + timedelta(hours=2),
    )
    assert calls == 1
    assert recovered.outcome == "provider_unavailable"
    assert recovered.recheck_count == 1
    with Session(database.engine) as session:
        current = get_preliminary_warning(session, warning_id)
        assert current is not None
        assert current.next_check_at is None
        recheck = session.scalar(select(PreliminaryWarningRecheckRecord))
        assert recheck is not None
        assert recheck.outcome == "provider_unavailable"
        assert recheck.reservation_id == _attempt_id(warning_id, 1)
        assert _receipt_kinds(session) == [
            (RECHECK_DISPATCH_RECEIPT, "recheck_dispatch"),
            ("provider_failure", "interrupted_provider_usage"),
        ]
        assert _receipts(session)[-1]["public_metadata"]["error_class"] == (
            "InterruptedProviderAttempt"
        )


def test_dispatch_receipt_is_durable_before_the_provider_is_called(database) -> None:
    """The dispatch receipt is committed before the provider sees the request."""
    warning_id = _create(database, "durable-dispatch")
    factory = sessionmaker(database.engine)
    observed: list[list[tuple[str, str]]] = []

    def crashing_provider(warning, _checked_at):
        # A separate connection sees only committed rows.
        with Session(database.engine) as session:
            observed.append(_receipt_kinds(session))
            current = get_preliminary_warning(session, warning_id)
            assert current is not None
            assert current.recheck_count == 1
            assert warning["recheck_count"] == 1
        raise ConnectionResetError("synthetic crash after the request was sent")

    with pytest.raises(ConnectionResetError):
        recheck_warning(
            factory,
            warning_id=warning_id,
            policy=_active_policy(),
            provider=crashing_provider,
            now=NOW + timedelta(hours=1),
        )
    assert observed == [[(RECHECK_DISPATCH_RECEIPT, "recheck_dispatch")]]
    with Session(database.engine) as session:
        dispatch = _receipts(session)[0]
        assert dispatch["run_id"] == warning_id
        assert dispatch["public_metadata"] == {
            "stage": "recheck",
            "warning_id": warning_id,
            "sequence": 1,
            "attempt_id": _attempt_id(warning_id, 1),
            "known_uncharged_retry": False,
        }

    def must_not_run(_warning, _checked_at):
        raise AssertionError("an interrupted sequence must never be dispatched again")

    recovered = recheck_warning(
        factory,
        warning_id=warning_id,
        policy=_active_policy(),
        provider=must_not_run,
        now=NOW + timedelta(hours=2),
    )
    assert recovered.outcome == "provider_unavailable"
    assert recovered.recheck_count == 1
    with Session(database.engine) as session:
        assert _receipt_kinds(session) == [
            (RECHECK_DISPATCH_RECEIPT, "recheck_dispatch"),
            ("provider_failure", "interrupted_provider_usage"),
        ]


@pytest.mark.audit_ids("WL-04")
def test_xai_provider_uses_fixed_maximum_reasoning_web_and_x_boundary() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "id": "response-fixed-boundary",
                "model": "grok-4.7",
                "service_tier": "default",
                "status": "completed",
                "incomplete_details": None,
                "output": [
                    {
                        "type": "web_search_call",
                        "id": "web-search-synthetic",
                        "status": "completed",
                        "action": {},
                    },
                    {
                        "type": "x_search_call",
                        "id": "x-search-synthetic",
                        "status": "completed",
                        "action": {},
                    },
                    {
                        "id": "message-fixed-boundary",
                        "type": "message",
                        "role": "assistant",
                        "status": "completed",
                        "content": [
                            {
                                "type": "output_text",
                                "text": (
                                    '{"outcome":"no_new_evidence",'
                                    '"reason":"No material new public evidence.",'
                                    '"source_urls":[]}'
                                ),
                            }
                        ],
                    },
                ],
                "usage": {
                    # Provider cost fields are ignored: the owner monitors billing.
                    "cost_in_usd_ticks": 123_000,
                    "num_server_side_tools_used": 2,
                    "input_tokens": 100,
                    "output_tokens": 8_192,
                    "total_tokens": 8_292,
                    "input_tokens_details": {"cached_tokens": 10},
                    "output_tokens_details": {"reasoning_tokens": 8_192},
                },
            },
            request=request,
        )

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = provider(
        _provider_warning(),
        NOW + timedelta(hours=1),
    )
    assert result.outcome == "no_new_evidence"
    assert result.output_tokens == 8_192
    assert result.total_tokens == 8_292
    request = captured[0]
    assert str(request.url) == "https://api.x.ai/v1/responses"
    payload = json.loads(request.content)
    assert payload["model"] == XAI_THREAT_SEARCH_MODEL == "grok-4.7"
    assert (
        payload["reasoning"]
        == {
            "effort": XAI_THREAT_SEARCH_REASONING_EFFORT,
        }
        == {"effort": "high"}
    )
    assert payload["max_output_tokens"] == RECHECK_MAX_OUTPUT_TOKENS == 8_192
    assert payload["parallel_tool_calls"] is False
    assert payload["max_tool_calls"] == 4
    assert payload["max_turns"] == 3
    assert payload["service_tier"] == "default"
    assert payload["store"] is False
    assert payload["tools"] == [
        {"type": "web_search"},
        {
            "type": "x_search",
            "from_date": "2026-08-05",
            "to_date": "2026-08-05",
        },
    ]


def test_xai_recheck_accepts_reasoning_and_exact_x_alias_without_retaining_values() -> None:
    body = json.loads(_provider_response_body())
    message = body["output"][0]
    marker = "raw-recheck-reasoning-must-not-persist"
    alias_marker = "raw-recheck-alias-input-must-not-persist"
    body["output"] = [
        {
            "id": "reasoning-recheck-synthetic",
            "type": "reasoning",
            "status": "completed",
            "summary": [{"type": "summary_text", "text": marker}],
        },
        {
            "type": "custom_tool_call",
            "id": "recheck-tool-synthetic",
            "call_id": "recheck-call-synthetic",
            "input": {"untrusted": alias_marker},
            "name": "x_keyword_search",
            "status": "completed",
        },
        message,
    ]
    body["usage"]["num_server_side_tools_used"] = 1

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json=body, request=request)
            )
        ),
    )
    result = provider(_provider_warning(), NOW + timedelta(hours=1))
    assert result.outcome == "no_new_evidence"
    assert result.server_side_tool_calls == 1
    assert marker not in repr(result)
    assert alias_marker not in repr(result)
    assert "reasoning-recheck-synthetic" not in repr(result)
    assert "recheck-call-synthetic" not in repr(result)


def test_xai_recheck_accepts_only_cited_canonical_public_sources() -> None:
    source_url = "https://security.example.com/report"
    body = json.loads(_provider_response_body())
    body["output"][0]["content"][0]["text"] = json.dumps(
        {
            "outcome": "confirmation_candidate",
            "reason": "A cited public source adds material evidence.",
            "source_urls": [source_url],
        }
    )
    body["output"][0]["content"][0]["annotations"] = [{"type": "url_citation", "url": source_url}]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body, request=request)

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = provider(_provider_warning(), NOW + timedelta(hours=1))
    assert result.source_urls == (source_url,)


@pytest.mark.parametrize("case", ["unexpected_output", "uncited_source", "too_many_tools"])
def test_xai_recheck_rejects_unexpected_tools_or_unbound_sources(case: str) -> None:
    body = json.loads(_provider_response_body())
    if case == "unexpected_output":
        body["output"].insert(0, {"type": "code_interpreter_call"})
    elif case == "uncited_source":
        body["output"][0]["content"][0]["text"] = json.dumps(
            {
                "outcome": "confirmation_candidate",
                "reason": "An uncited URL must not cross the provider boundary.",
                "source_urls": ["https://security.example.com/report"],
            }
        )
    else:
        body["usage"]["num_server_side_tools_used"] = 5

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body, request=request)

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(RecheckProviderUnavailable):
        provider(_provider_warning(), NOW + timedelta(hours=1))


@pytest.mark.parametrize(
    ("status", "incomplete_details"),
    [
        ("incomplete", {"reason": "max_output_tokens"}),
        ("completed", {"reason": "unexpected"}),
        (None, None),
    ],
)
def test_xai_rejects_incomplete_provider_responses(
    status: str | None,
    incomplete_details: dict[str, str] | None,
) -> None:
    body = json.loads(_provider_response_body())
    body["status"] = status
    body["incomplete_details"] = incomplete_details

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body, request=request)

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(RecheckProviderUnavailable, match="provider_response_incomplete"):
        provider(_provider_warning(), NOW + timedelta(hours=1))


@pytest.mark.audit_ids("WL-04")
def test_xai_forces_redirects_off_for_an_injected_redirecting_client() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers={"location": "https://example.invalid/redirected"},
            request=request,
        )

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=True,
        ),
    )
    with pytest.raises(RecheckProviderUnavailable):
        provider(_provider_warning(), NOW + timedelta(hours=1))
    assert len(requests) == 1
    assert requests[0].headers["accept-encoding"] == "identity"


def test_xai_declared_size_is_rejected_before_stream_read() -> None:
    stream = TrackingStream((_provider_response_body(),))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "content-length": "100",
            },
            stream=stream,
            request=request,
        )

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        maximum_response_bytes=32,
    )
    with pytest.raises(RecheckProviderUnavailable, match="provider_response_too_large"):
        provider(_provider_warning(), NOW + timedelta(hours=1))
    assert stream.read_count == 0


@pytest.mark.parametrize(
    "headers",
    [
        {"content-type": "text/html"},
        {
            "content-type": "application/json",
            "content-encoding": "gzip",
        },
    ],
)
def test_xai_rejects_unexpected_media_and_encoding_before_stream_read(
    headers: dict[str, str],
) -> None:
    stream = TrackingStream((_provider_response_body(),))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=headers,
            stream=stream,
            request=request,
        )

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(RecheckProviderUnavailable):
        provider(_provider_warning(), NOW + timedelta(hours=1))
    assert stream.read_count == 0


def test_xai_rejects_duplicate_provider_json_keys() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b'{"id":"first","id":"second"}',
            request=request,
        )

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(RecheckProviderUnavailable, match="provider_response_invalid_json"):
        provider(_provider_warning(), NOW + timedelta(hours=1))


def test_xai_stream_limit_and_operation_deadline_fail_closed() -> None:
    responses = iter(("overflow", "deadline"))
    clock_state = {"value": 0.0}

    def handler(request: httpx.Request) -> httpx.Response:
        mode = next(responses)
        stream = (
            TrackingStream((b"x" * 33,))
            if mode == "overflow"
            else TrackingStream(
                (_provider_response_body(),),
                before_yield=lambda: clock_state.update(value=121.0),
            )
        )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=stream,
            request=request,
        )

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        monotonic_clock=lambda: clock_state["value"],
        maximum_response_bytes=32,
    )
    with pytest.raises(RecheckProviderUnavailable, match="provider_response_too_large"):
        provider(_provider_warning(), NOW + timedelta(hours=1))

    clock_state["value"] = 0.0
    deadline_provider = XaiWarningRecheckProvider(
        api_key="synthetic-xai-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        monotonic_clock=lambda: clock_state["value"],
    )
    with pytest.raises(RecheckProviderUnavailable, match="provider_transport_failure"):
        deadline_provider(_provider_warning(), NOW + timedelta(hours=1))


@pytest.mark.parametrize("invalid_url", ({}, []))
def test_unhashable_recheck_source_closes_usage_without_replaying(
    database, invalid_url: object
) -> None:
    warning_id = _create(database, "malformed-source")
    body = json.loads(_provider_response_body())
    body["output"][0]["content"][0]["text"] = json.dumps(
        {
            "outcome": "no_new_evidence",
            "reason": "Synthetic invalid source",
            "source_urls": [invalid_url],
        }
    )
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=body, request=request)

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-key", client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    factory = sessionmaker(database.engine)
    result = recheck_warning(
        factory,
        warning_id=warning_id,
        policy=_active_policy(),
        provider=provider,
        now=NOW + timedelta(hours=1),
    )
    assert result.outcome == "provider_unavailable"
    with Session(database.engine) as session:
        recheck = session.scalar(select(PreliminaryWarningRecheckRecord))
        assert recheck is not None
        assert recheck.provider_response_id_hash is not None
        assert recheck.reservation_id == _attempt_id(warning_id, 1)
        assert _receipt_kinds(session) == [
            (RECHECK_DISPATCH_RECEIPT, "recheck_dispatch"),
            ("provider_cost_observed", "within_technical_envelope"),
            ("qualification_rejection", "recheck_response_rejected"),
        ]
    with pytest.raises(PreliminaryWarningError, match="not due"):
        recheck_warning(
            factory,
            warning_id=warning_id,
            policy=_active_policy(),
            provider=provider,
            now=NOW + timedelta(hours=1, minutes=1),
        )
    assert calls == 1


@pytest.mark.parametrize("malformed_text", [False, True])
def test_recheck_http_output_overage_preserves_token_failure_before_parsing(malformed_text):
    body = json.loads(_provider_response_body())
    body["usage"]["output_tokens"] = RECHECK_MAX_OUTPUT_TOKENS + 1
    body["usage"]["total_tokens"] = body["usage"]["input_tokens"] + body["usage"]["output_tokens"]
    if malformed_text:
        body["output"][0]["content"][0]["text"] = "not JSON"
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=body, request=request)

    provider = XaiWarningRecheckProvider(
        api_key="synthetic-key", client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(RecheckProviderUnavailable) as caught:
        provider(_provider_warning(), NOW + timedelta(hours=1))
    error = caught.value.provider_error
    assert error.code == "provider_token_usage_exceeded"
    assert not error.retryable and not error.usage_uncertain
    assert error.exact_usage.output_tokens == RECHECK_MAX_OUTPUT_TOKENS + 1
    assert len(requests) == 1
    assert json.loads(requests[0].content)["max_output_tokens"] == RECHECK_MAX_OUTPUT_TOKENS


@pytest.mark.usefixtures("enabled_warning_dispatch")
def test_subscription_policy_refuses_paid_recheck_before_sequence_or_request(database):
    from smithguard.spend import ExternalDispatchDisabled

    warning_id = _create(database, "subscription-recheck-denied")
    with pytest.raises(ExternalDispatchDisabled, match="paid rechecks"):
        recheck_warning(
            sessionmaker(database.engine),
            warning_id=warning_id,
            policy=replace(_active_policy(), subscription_first=True),
            provider=lambda *_: pytest.fail("paid request must not be sent"),
            now=NOW + timedelta(hours=1),
        )
    with Session(database.engine) as session:
        current = get_preliminary_warning(session, warning_id)
        assert current.revision == 1 and current.recheck_count == 0
