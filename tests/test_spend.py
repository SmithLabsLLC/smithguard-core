from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from smithguard.db.models import JobRecord
from smithguard.identifiers import canonical_json_bytes
from smithguard.spend import (
    BOUNDED_NATIVE_SUBSCRIPTION_CONTRACT,
    BOUNDED_STAGE_LIMITS,
    BOUNDED_SUBSCRIPTION_SCHEMA_VERSION,
    EXPECTED_STAGE_LIMITS,
    LEGACY_POLICY_SCHEMA_VERSION,
    POLICY_SCHEMA_VERSION,
    TECHNICAL_USAGE_STOP_REASONS,
    ExternalDispatchDisabled,
    SpendPolicyError,
    StageLimits,
    load_spend_policy,
    load_spend_policy_path,
    render_spend_policy_state,
)
from smithguard.warning_lane_receipts import ProviderUsage, append_warning_lane_receipt
from tools.render_warning_lane_policy import render_to_path

POLICY_PATH = Path("contracts/v1/xai-spend-policy.json")
NOW = datetime(2026, 8, 20, 12, tzinfo=UTC)
APPROVAL_ID = "gbsec:approval:warning-lane-public-20260820"


def _document() -> dict:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def _activated_document(state: str) -> dict:
    return render_spend_policy_state(
        _document(),
        state=state,
        approval_id=(APPROVAL_ID if state == "active" else None),
    )


def _legacy_document() -> dict:
    """Rebuild the retired version 3 shape around the current version 4 limits."""
    document = _document()
    for name in ("discovery", "qualification"):
        document["stage_limits"][name]["maximum_output_tokens"] = 8192
    document["provider_request_contract"]["maximum_output_tokens"] = 8192
    document["provider_request_contract"]["qualification_maximum_output_tokens"] = 8192
    document.pop("subscription_contract")
    document["provider_request_contract"].pop("reasoning_effort")
    document["provider_request_contract"]["model"] = "grok-4.6"
    document["schema_version"] = LEGACY_POLICY_SCHEMA_VERSION
    document["currency"] = "USD"
    document["billing_period"] = {"kind": "calendar_month", "timezone": "UTC"}
    document["billing_observability"] = {"mode": "owner_managed", "usd_ticks_per_usd": 1}
    document["accounting_contract"] = {"unavailable_usage_behavior": "deny_and_stop_dispatch"}
    envelopes = {
        "short_context_input_usd_ticks_per_million_tokens": 1,
        "short_context_output_usd_ticks_per_million_tokens": 1,
        "long_context_threshold_tokens": 1,
        "long_context_input_usd_ticks_per_million_tokens": 1,
        "long_context_output_usd_ticks_per_million_tokens": 1,
        "tool_usd_ticks_per_call": 1,
        "safety_multiplier": 1,
        "rounding_quantum_usd_ticks": 1,
    }
    for name, stage in document.pop("stage_limits").items():
        envelopes[name] = {**stage, "calculated_cost_usd_ticks": 1, "maximum_cost_usd_ticks": 2}
    document["technical_envelopes"] = envelopes
    document["provider_request_contract"]["price_id"] = "grok-4.6-web-x-2026-08"
    controls = document["activation_contract"]["required_controls"]
    controls.insert(
        2, {"control_id": "exact-cost-integrity", "required_for": "dispatch", "status": "passed"}
    )
    controls.append(
        {
            "control_id": "technical-capacity-reservation",
            "required_for": "dispatch",
            "status": "passed",
        }
    )
    controls.append(
        {
            "control_id": "price-model-and-usage-fail-closed",
            "required_for": "dispatch",
            "status": "passed",
        }
    )
    document["required_test_scenarios"] = ["exact cost reconciles", "price drift fails closed"]
    document["current_evidence"]["notes"] = "Version 3 carried exact cost accounting."
    return document


def _usage(response_id: str, *, stage: str = "discovery", output_tokens: int = 20) -> ProviderUsage:
    return ProviderUsage(
        stage=stage,
        model="grok-4.6",
        response_id=response_id,
        input_tokens=100,
        output_tokens=output_tokens,
        total_tokens=100 + output_tokens,
        cached_input_tokens=10,
        reasoning_tokens=5,
        server_side_tool_calls=1 if stage != "qualification" else 0,
        configured_maximum_turns=1 if stage == "qualification" else 3,
        request_bytes=2_000,
        elapsed_milliseconds=500,
        response_bytes=750,
    )


@pytest.mark.parametrize(
    "field,value",
    [("automatic_retries", False), ("session_upload", 0), ("maximum_qualification_turns", True)],
)
def test_native_policy_rejects_boolean_integer_aliases(field, value) -> None:
    document = json.loads(POLICY_PATH.read_text())
    document["subscription_contract"][field] = value
    with pytest.raises(SpendPolicyError, match="native subscription boundary"):
        load_spend_policy(document)


def test_version_six_policy_removes_early_warning_output_limits() -> None:
    document = _document()
    assert document["schema_version"] == POLICY_SCHEMA_VERSION == "6.0.0"
    assert set(document) == {
        "schema_version",
        "policy_id",
        "policy_state",
        "stage_limits",
        "lane_limits",
        "schedule_contract",
        "provider_request_contract",
        "activation_contract",
        "required_test_scenarios",
        "current_evidence",
        "subscription_contract",
    }
    assert "price" not in json.dumps(document)
    assert "cost" not in json.dumps(document).replace("provider cost is monitored", "")
    policy = load_spend_policy_path(POLICY_PATH)
    assert policy.stage_limits == EXPECTED_STAGE_LIMITS
    assert policy.maximum_output_tokens is None
    assert policy.qualification_maximum_output_tokens is None
    assert policy.maximum_provider_requests_per_run == 4
    assert policy.maximum_new_warnings_per_day == 4
    assert policy.schedule_minute_offsets == (27, 57)
    assert policy.schedule_grace_minutes == 20
    assert not policy.dispatch_allowed
    assert not hasattr(policy, "billing_mode")
    assert not hasattr(policy, "provider_price_id")
    with pytest.raises(ExternalDispatchDisabled):
        policy.assert_scheduled_discovery_allowed()


def test_stage_limits_parse_and_match_the_approved_values() -> None:
    policy = load_spend_policy_path(POLICY_PATH)
    assert set(policy.stage_limits) == {"discovery", "qualification", "recheck"}
    assert policy.stage_limits["discovery"] == StageLimits(500_000, 3, None, 4)
    assert policy.stage_limits["qualification"] == StageLimits(500_000, 1, None, 0)
    assert policy.stage_limits["recheck"] == StageLimits(500_000, 3, 8_192, 4)
    assert policy.stage_limits["qualification"].maximum_tool_calls == 0

    drift = _document()
    drift["stage_limits"]["discovery"]["maximum_tool_calls"] += 1
    with pytest.raises(SpendPolicyError, match="discovery stage limits changed"):
        load_spend_policy(drift)

    out_of_bound = _document()
    out_of_bound["stage_limits"]["recheck"]["maximum_turns"] = 11
    with pytest.raises(SpendPolicyError, match="recheck turns"):
        load_spend_policy(out_of_bound)

    missing = _document()
    del missing["stage_limits"]["qualification"]
    with pytest.raises(SpendPolicyError, match="stage limits"):
        load_spend_policy(missing)


def test_technical_usage_stop_reasons_are_exactly_the_token_and_tool_overages() -> None:
    assert (
        frozenset({"provider_token_usage_exceeded", "provider_tool_usage_exceeded"})
        == TECHNICAL_USAGE_STOP_REASONS
    )


def test_legacy_version_three_document_loads_with_its_pricing_stripped() -> None:
    legacy = _legacy_document()
    current = load_spend_policy_path(POLICY_PATH)
    assert load_spend_policy(legacy).provider_model == "grok-4.6"
    assert not load_spend_policy(legacy).subscription_first
    assert current.provider_model == "grok-4.7"
    assert current.subscription_first
    assert load_spend_policy(legacy).stage_limits == BOUNDED_STAGE_LIMITS

    unknown_envelope = _legacy_document()
    unknown_envelope["technical_envelopes"]["balance_usd_ticks"] = 1
    with pytest.raises(SpendPolicyError, match="unknown field"):
        load_spend_policy(unknown_envelope)

    legacy_drift = _legacy_document()
    legacy_drift["technical_envelopes"]["recheck"]["maximum_output_tokens"] = 4_096
    with pytest.raises(SpendPolicyError, match="recheck stage limits changed"):
        load_spend_policy(legacy_drift)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda document: document.__setitem__("currency", "USD"), "spend policy"),
        (
            lambda document: document.__setitem__(
                "accounting_contract", {"unavailable_usage_behavior": "deny"}
            ),
            "spend policy",
        ),
        (
            lambda document: document["provider_request_contract"].__setitem__(
                "price_id", "grok-4.6-web-x-2026-08"
            ),
            "provider request contract",
        ),
        (
            lambda document: document["stage_limits"]["discovery"].__setitem__(
                "maximum_cost_usd_ticks", 1
            ),
            "discovery stage limits",
        ),
        (
            lambda document: document["activation_contract"]["required_controls"].append(
                {
                    "control_id": "exact-cost-integrity",
                    "required_for": "dispatch",
                    "status": "passed",
                }
            ),
            "controls",
        ),
    ],
)
def test_version_four_document_rejects_every_pricing_field(mutate, match) -> None:
    document = _document()
    mutate(document)
    with pytest.raises(SpendPolicyError, match=match):
        load_spend_policy(document)


def test_current_qualification_policy_rejects_any_reintroduced_output_cap() -> None:
    document = _document()
    assert load_spend_policy(document).qualification_maximum_output_tokens is None
    for rejected in (0, -1, True, 1, 8_192, 8_193):
        document["provider_request_contract"]["qualification_maximum_output_tokens"] = rejected
        with pytest.raises(SpendPolicyError, match="no output token cap"):
            load_spend_policy(document)


def test_version_five_remains_readable_but_cannot_dispatch_uncapped_work() -> None:
    document = _document()
    document["schema_version"] = BOUNDED_SUBSCRIPTION_SCHEMA_VERSION
    document["subscription_contract"] = dict(BOUNDED_NATIVE_SUBSCRIPTION_CONTRACT)
    for name in ("discovery", "qualification"):
        document["stage_limits"][name]["maximum_output_tokens"] = 8192
    document["provider_request_contract"]["maximum_output_tokens"] = 8192
    document["provider_request_contract"]["qualification_maximum_output_tokens"] = 8192
    document["current_evidence"]["notes"] = document["current_evidence"]["notes"].replace(
        "Version 6", "Version 5"
    )
    shadow = load_spend_policy(render_spend_policy_state(document, state="shadow"))
    assert shadow.subscription_first and shadow.stage_limits == BOUNDED_STAGE_LIMITS
    assert shadow.maximum_output_tokens == 8192
    assert not shadow.dispatch_allowed
    with pytest.raises(ExternalDispatchDisabled):
        shadow.assert_scheduled_discovery_allowed()


def test_shadow_dispatch_cannot_publish_and_active_requires_exact_approval() -> None:
    shadow = load_spend_policy(_activated_document("shadow"))
    assert shadow.dispatch_allowed
    assert not shadow.automatic_warning_publication_allowed

    active = load_spend_policy(_activated_document("active"))
    assert active.dispatch_allowed
    assert active.automatic_warning_publication_allowed

    missing = _activated_document("active")
    missing["activation_contract"]["automatic_publication_approval_id"] = None
    with pytest.raises(SpendPolicyError, match="approval ID"):
        load_spend_policy(missing)


def test_rendered_policy_state_is_canonical_and_preserves_historical_model() -> None:
    first = canonical_json_bytes(render_spend_policy_state(_document(), state="shadow"))
    second = canonical_json_bytes(render_spend_policy_state(_document(), state="shadow"))
    assert first == second
    from_legacy = canonical_json_bytes(
        render_spend_policy_state(_legacy_document(), state="shadow")
    )
    assert from_legacy != first
    old_policy = load_spend_policy(json.loads(from_legacy))
    assert old_policy.provider_model == "grok-4.6"
    assert not old_policy.dispatch_allowed
    rendered = json.loads(first)
    assert rendered["schema_version"] == POLICY_SCHEMA_VERSION
    assert "technical_envelopes" not in rendered
    assert rendered["policy_state"] == "shadow"
    assert load_spend_policy(rendered).dispatch_allowed

    active = render_spend_policy_state(_document(), state="active", approval_id=APPROVAL_ID)
    assert canonical_json_bytes(active) != first
    assert load_spend_policy(active).automatic_warning_publication_allowed
    with pytest.raises(SpendPolicyError, match="approval ID"):
        render_spend_policy_state(_document(), state="active")
    with pytest.raises(SpendPolicyError, match="cannot retain"):
        render_spend_policy_state(_document(), state="shadow", approval_id=APPROVAL_ID)


def test_activation_policy_renderer_is_canonical_and_private(tmp_path: Path) -> None:
    shadow_path = tmp_path / "shadow.json"
    render_to_path(
        source=POLICY_PATH,
        output=shadow_path,
        state="shadow",
        approval_id=None,
    )
    assert shadow_path.stat().st_mode & 0o777 == 0o600
    assert shadow_path.read_bytes() == (
        canonical_json_bytes(render_spend_policy_state(_document(), state="shadow")) + b"\n"
    )
    shadow = load_spend_policy_path(shadow_path)
    assert shadow.dispatch_allowed
    assert not shadow.automatic_warning_publication_allowed

    active_path = tmp_path / "active.json"
    render_to_path(
        source=shadow_path,
        output=active_path,
        state="active",
        approval_id=APPROVAL_ID,
    )
    active = load_spend_policy_path(active_path)
    assert active.automatic_warning_publication_allowed
    assert active.automatic_publication_approval_id == APPROVAL_ID


def test_policy_rejects_unknown_fields_and_limit_drift() -> None:
    unknown = _document()
    unknown["billing_observability"] = {"balance": "secret"}
    with pytest.raises(SpendPolicyError, match="exact approved fields"):
        load_spend_policy(unknown)

    unknown_lane = _document()
    unknown_lane["lane_limits"]["maximum_spend_usd"] = 1
    with pytest.raises(SpendPolicyError, match="exact approved fields"):
        load_spend_policy(unknown_lane)

    drift = _document()
    drift["lane_limits"]["maximum_provider_requests_per_run"] += 1
    with pytest.raises(SpendPolicyError, match="approved boundary"):
        load_spend_policy(drift)

    schedule = _document()
    schedule["schedule_contract"]["grace_minutes"] = 21
    with pytest.raises(SpendPolicyError, match="schedule contract changed"):
        load_spend_policy(schedule)

    scenarios = _document()
    scenarios["required_test_scenarios"].append("exact cost reconciles")
    with pytest.raises(SpendPolicyError, match="test scenarios changed"):
        load_spend_policy(scenarios)


def test_provider_cost_observed_receipt_carries_usage_without_cost(database) -> None:
    with Session(database.engine) as session, session.begin():
        record = append_warning_lane_receipt(
            session,
            receipt_type="provider_cost_observed",
            reason_code="within_technical_envelope",
            run_id="run-usage",
            job_id="job-usage",
            occurred_at=NOW,
            public_metadata={"queue": "ai-warning-discovery", "attempt": 1},
            provider_usage=_usage("response-usage"),
        )
        payload = record.payload
        assert record.state == "succeeded"
        assert payload["schema_version"] == "2.1.0"
        assert set(payload["provider"]) == {
            "stage",
            "model",
            "response_id_sha256",
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "cached_input_tokens",
            "reasoning_tokens",
            "server_side_tool_calls",
            "configured_maximum_turns",
            "request_bytes",
            "elapsed_milliseconds",
            "response_bytes",
        }
        assert payload["provider"]["response_bytes"] == 750
        assert "response-usage" not in canonical_json_bytes(payload).decode("ascii")
        for retired in ("price_id", "exact_cost_usd_ticks", "reservation_id", "spend_event_id"):
            assert retired not in canonical_json_bytes(payload).decode("ascii")

        replay = append_warning_lane_receipt(
            session,
            receipt_type="provider_cost_observed",
            reason_code="within_technical_envelope",
            run_id="run-usage",
            job_id="job-usage",
            occurred_at=NOW,
            public_metadata={"queue": "ai-warning-discovery", "attempt": 1},
            provider_usage=_usage("response-usage"),
        )
        assert replay.job_id == record.job_id
        assert (
            session.scalar(
                select(JobRecord.job_id).where(JobRecord.payload["run_id"].astext == "run-usage")
            )
            == record.job_id
        )


@pytest.mark.audit_ids("WL-17")
def test_spend_integrity_and_provider_cost_queries_use_bounded_indexes(database) -> None:
    # The name is bound by audit row WL-17; the retired ledger plans it once covered are gone.
    # The receipt indexes that remain are the ones the health and lane queries rely on.
    with Session(database.engine) as session, session.begin():
        session.execute(text("SET LOCAL enable_seqscan = off"))
        run_plan = "\n".join(
            str(row[0])
            for row in session.execute(
                text(
                    "EXPLAIN SELECT job_id FROM smithguard.jobs "
                    "WHERE (payload ->> 'run_id') = 'synthetic-run' "
                    "AND completed_at >= :since"
                ),
                {"since": NOW - timedelta(hours=24)},
            )
        )
        type_plan = "\n".join(
            str(row[0])
            for row in session.execute(
                text(
                    "EXPLAIN SELECT job_id FROM smithguard.jobs "
                    "WHERE (payload ->> 'receipt_type') = 'provider_cost_observed' "
                    "AND completed_at >= :since"
                ),
                {"since": NOW - timedelta(hours=24)},
            )
        )
    assert "ix_jobs_receipt_run_completed" in run_plan
    assert "ix_jobs_receipt_type_completed" in type_plan


@pytest.mark.parametrize("invalid_id", ({}, []))
def test_legacy_unhashable_control_id_is_policy_error(invalid_id: object) -> None:
    document = _legacy_document()
    document["activation_contract"]["required_controls"][0]["control_id"] = invalid_id
    with pytest.raises(SpendPolicyError, match="controls"):
        load_spend_policy(document)
