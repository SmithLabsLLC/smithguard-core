"""The frozen xAI warning-lane policy: request, schedule and activation limits.

Since September 18, 2026 (owner direction: strip the pricing machinery) the policy
carries no prices, no cost ledger and no accounting contract. What remains is what
actually bounds the lane: how many provider requests a run and a day may make, how
large each request and response may be, when the schedule fires, and whether
unattended dispatch and publication are authorized. The owner monitors provider cost
through billing; SmithGuard never asks for pricing information.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from smithguard.identifiers import canonical_json_bytes
from smithguard.xai_settings import (
    XAI_DISCOVERY_STAGE_MAX_OUTPUT_TOKENS,
    XAI_MAX_ELAPSED_SECONDS,
    XAI_MAX_INPUT_TOKENS,
    XAI_MAX_OUTPUT_TOKENS,
    XAI_MAX_OUTPUT_TOKENS_PER_REQUEST,
    XAI_MAX_REQUEST_BYTES,
    XAI_MAX_RESPONSE_BYTES,
    XAI_QUALIFICATION_MAX_OUTPUT_TOKENS,
    XAI_RECHECK_MAX_OUTPUT_TOKENS,
    XAI_STAGE_MAX_INPUT_TOKENS_PER_TURN,
    XAI_THREAT_SEARCH_MODEL,
)

POLICY_SCHEMA_VERSION = "7.0.0"
GROK_API_SUBSCRIPTION_SCHEMA_VERSION = "6.0.0"
BOUNDED_SUBSCRIPTION_SCHEMA_VERSION = "5.0.0"
UNCAPPED_SUBSCRIPTION_SCHEMA_VERSIONS = {
    POLICY_SCHEMA_VERSION,
    GROK_API_SUBSCRIPTION_SCHEMA_VERSION,
}
SUBSCRIPTION_SCHEMA_VERSIONS = {
    *UNCAPPED_SUBSCRIPTION_SCHEMA_VERSIONS,
    BOUNDED_SUBSCRIPTION_SCHEMA_VERSION,
}
API_POLICY_SCHEMA_VERSION = "4.0.0"
POLICY_ID = "gbsec:control:xai-spend-policy"
# Version 3 remains readable for retained policy and recovery compatibility.
# Configure renders version 6; legacy pricing blocks are ignored, never validated
# or used, and do not restore a pricing ledger.
LEGACY_POLICY_SCHEMA_VERSION = "3.0.0"
LEGACY_PRICING_KEYS = frozenset(
    {"currency", "billing_period", "billing_observability", "accounting_contract"}
)
LEGACY_REQUEST_KEYS = frozenset({"price_id"})
LEGACY_STAGE_KEYS = frozenset({"calculated_cost_usd_ticks", "maximum_cost_usd_ticks"})
LEGACY_ENVELOPE_KEYS = frozenset(
    {
        "short_context_input_usd_ticks_per_million_tokens",
        "short_context_output_usd_ticks_per_million_tokens",
        "long_context_threshold_tokens",
        "long_context_input_usd_ticks_per_million_tokens",
        "long_context_output_usd_ticks_per_million_tokens",
        "tool_usd_ticks_per_call",
        "safety_multiplier",
        "rounding_quantum_usd_ticks",
    }
)
LEGACY_CONTROL_IDS = frozenset(
    {"exact-cost-integrity", "technical-capacity-reservation", "price-model-and-usage-fail-closed"}
)
# Provider usage overages the lane records and then stops on; they are technical
# request-contract breaches, not cost events.
TECHNICAL_USAGE_STOP_REASONS = frozenset(
    {"provider_token_usage_exceeded", "provider_tool_usage_exceeded"}
)
STAGES = ("discovery", "qualification", "recheck")


class SpendPolicyError(ValueError):
    """The frozen policy is invalid."""


class ExternalDispatchDisabled(PermissionError):
    """The policy does not authorize an external provider request."""


@dataclass(frozen=True, slots=True)
class StageLimits:
    """Per-request limits for one provider stage."""

    maximum_input_tokens_per_turn: int
    maximum_turns: int
    maximum_output_tokens: int | None
    maximum_tool_calls: int


@dataclass(frozen=True, slots=True)
class SpendPolicy:
    policy_id: str
    policy_state: str
    maximum_active_discovery_workers: int
    maximum_provider_requests_per_run: int
    maximum_discovery_requests_per_run: int
    maximum_validated_candidates_per_run: int
    maximum_qualification_requests_per_run: int
    maximum_new_warnings_per_run: int
    maximum_new_warnings_per_day: int
    maximum_provider_attempts: int
    maximum_tool_calls: int
    maximum_turns: int
    maximum_output_tokens: int | None
    qualification_maximum_output_tokens: int | None
    maximum_request_bytes: int
    maximum_response_bytes: int
    maximum_elapsed_seconds: int
    stage_limits: dict[str, StageLimits]
    schedule_minute_offsets: tuple[int, ...]
    schedule_grace_minutes: int
    external_calls_allowed: bool
    unattended_collection_allowed: bool
    unattended_scope: str
    maximum_warning_lifetime_hours: int
    recheck_interval_minutes: int
    maximum_rechecks_per_warning: int
    automatic_publication_allowed: bool
    automatic_publication_approval_id: str | None
    automatic_confirmation_allowed: bool
    all_required_controls_pass: bool
    publication_controls_pass: bool
    provider_model: str
    subscription_first: bool
    current_request_contract: bool
    primary_unavailable_reason: str | None = None

    @property
    def dispatch_allowed(self) -> bool:
        return (
            self.current_request_contract
            and self.provider_model == XAI_THREAT_SEARCH_MODEL
            and self.policy_state in {"shadow", "active"}
            and self.external_calls_allowed
            and self.all_required_controls_pass
        )

    @property
    def unattended_dispatch_allowed(self) -> bool:
        return self.dispatch_allowed and self.unattended_collection_allowed

    def assert_dispatch_allowed(self) -> None:
        if not self.dispatch_allowed:
            raise ExternalDispatchDisabled(
                "xAI dispatch is disabled by the frozen activation policy"
            )

    def assert_preliminary_warning_recheck_allowed(self) -> None:
        if self.subscription_first:
            raise ExternalDispatchDisabled("paid rechecks are disabled by subscription policy")
        if (
            not self.unattended_dispatch_allowed
            or self.unattended_scope != "scheduled_ai_qualified_warning_lane_and_hourly_recheck"
            or self.maximum_warning_lifetime_hours != 12
            or self.recheck_interval_minutes != 60
            or self.maximum_rechecks_per_warning != 12
            or self.automatic_confirmation_allowed
        ):
            raise ExternalDispatchDisabled(
                "xAI unattended dispatch is not authorized for this warning recheck"
            )

    def assert_scheduled_discovery_allowed(self) -> None:
        if (
            not self.unattended_dispatch_allowed
            or self.unattended_scope != "scheduled_ai_qualified_warning_lane_and_hourly_recheck"
        ):
            raise ExternalDispatchDisabled(
                "xAI unattended dispatch is not authorized for scheduled discovery"
            )

    @property
    def automatic_warning_publication_allowed(self) -> bool:
        return (
            self.policy_state == "active"
            and self.dispatch_allowed
            and self.publication_controls_pass
            and self.automatic_publication_allowed
            and self.automatic_publication_approval_id is not None
        )


def _expect_keys(document: Any, expected: set[str], *, field: str) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != expected:
        raise SpendPolicyError(f"{field} does not have the exact approved fields")
    return document


def _bounded_integer(value: Any, *, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SpendPolicyError(f"{field} is outside its approved bound")
    return value


def _strip_legacy_pricing(document: dict[str, Any]) -> dict[str, Any]:
    """Return the version 4 view of a version 3 document, dropping its pricing blocks."""
    root = {key: value for key, value in document.items() if key not in LEGACY_PRICING_KEYS}
    root["schema_version"] = API_POLICY_SCHEMA_VERSION
    envelopes = root.get("technical_envelopes")
    if isinstance(envelopes, dict):
        root["stage_limits"] = {
            name: {key: value for key, value in stage.items() if key not in LEGACY_STAGE_KEYS}
            for name, stage in envelopes.items()
            if name in STAGES and isinstance(stage, dict)
        }
        if set(envelopes) - set(STAGES) - LEGACY_ENVELOPE_KEYS:
            raise SpendPolicyError("technical envelopes carry an unknown field")
        del root["technical_envelopes"]
    request = root.get("provider_request_contract")
    if isinstance(request, dict):
        root["provider_request_contract"] = {
            key: value for key, value in request.items() if key not in LEGACY_REQUEST_KEYS
        }
    activation = root.get("activation_contract")
    if isinstance(activation, dict) and isinstance(activation.get("required_controls"), list):
        activation = dict(activation)
        activation["required_controls"] = [
            control
            for control in activation["required_controls"]
            if not (
                isinstance(control, dict)
                and isinstance(control.get("control_id"), str)
                and control["control_id"] in LEGACY_CONTROL_IDS
            )
        ]
        root["activation_contract"] = activation
    scenarios = root.get("required_test_scenarios")
    if isinstance(scenarios, list):
        root["required_test_scenarios"] = REQUIRED_TEST_SCENARIOS
    evidence = root.get("current_evidence")
    if isinstance(evidence, dict) and isinstance(root.get("policy_state"), str):
        notes = EVIDENCE_NOTES.get(root["policy_state"])
        if notes is not None:
            root["current_evidence"] = {**evidence, "notes": notes}
    return root


REQUIRED_TEST_SCENARIOS = [
    "concurrent request admission stays within the run limit",
    "idempotent retry",
    "known uncharged finite retry",
    "unavailable provider usage does not stop dispatch",
    "technical envelope breach records then dead-letters the request",
    "single latest schedule window after downtime",
    "shadow dispatch without publication",
    "active publication requires exact approval",
    "unknown policy field fails closed",
]
EVIDENCE_NOTES = {
    "disabled": (
        "Version 4 carries request, schedule and activation limits only; provider cost "
        "is monitored through billing. Policy state is disabled, so external calls and "
        "publication are prohibited."
    ),
    "ready": (
        "Version 4 carries request, schedule and activation limits only; provider cost "
        "is monitored through billing. Source state remains ready, so external calls and "
        "publication stay prohibited until the exact shadow and public-activation gates pass."
    ),
    "shadow": (
        "Version 4 carries request, schedule and activation limits only; provider cost "
        "is monitored through billing. Policy state is shadow, so bounded external "
        "dispatch is allowed and warning publication remains prohibited."
    ),
    "active": (
        "Version 4 carries request, schedule and activation limits only; provider cost "
        "is monitored through billing. Policy state is active under the exact approval "
        "binding; only Emerging / Unverified Level 0 publication is allowed."
    ),
}
BOUNDED_STAGE_LIMITS = {
    "discovery": StageLimits(
        XAI_STAGE_MAX_INPUT_TOKENS_PER_TURN,
        3,
        XAI_DISCOVERY_STAGE_MAX_OUTPUT_TOKENS,
        4,
    ),
    "qualification": StageLimits(
        XAI_STAGE_MAX_INPUT_TOKENS_PER_TURN,
        1,
        XAI_QUALIFICATION_MAX_OUTPUT_TOKENS,
        0,
    ),
    "recheck": StageLimits(
        XAI_STAGE_MAX_INPUT_TOKENS_PER_TURN,
        3,
        XAI_RECHECK_MAX_OUTPUT_TOKENS,
        4,
    ),
}
EXPECTED_STAGE_LIMITS = {
    **BOUNDED_STAGE_LIMITS,
    "discovery": StageLimits(XAI_STAGE_MAX_INPUT_TOKENS_PER_TURN, 3, None, 4),
    "qualification": StageLimits(XAI_STAGE_MAX_INPUT_TOKENS_PER_TURN, 1, None, 0),
}
EXPECTED_LANE_LIMITS = {
    "maximum_active_discovery_workers": 1,
    "maximum_provider_requests_per_run": 4,
    "maximum_discovery_requests_per_run": 2,
    "maximum_validated_candidates_per_run": 4,
    "maximum_qualification_requests_per_run": 2,
    "maximum_new_warnings_per_run": 2,
    "maximum_new_warnings_per_origin_and_package_per_run": 1,
    "maximum_new_warnings_per_ecosystem_per_run": 2,
    "maximum_new_warnings_per_utc_day": 4,
    "maximum_provider_attempts": 2,
}
EXPECTED_SCHEDULE = {
    "timezone": "UTC",
    "minute_offsets": [27, 57],
    "grace_minutes": 20,
    "downtime_behavior": "latest_eligible_window_only",
    "overlap_behavior": "skip_and_record",
}


def _evidence_notes(version: str, state: str) -> str:
    return EVIDENCE_NOTES[state].replace("Version 4", f"Version {version.split('.')[0]}")


def _load_policy_stage_limits(root: Mapping[str, Any]) -> dict[str, StageLimits]:
    stage_document = _expect_keys(root.get("stage_limits"), set(STAGES), field="stage limits")
    expected = (
        EXPECTED_STAGE_LIMITS
        if root["schema_version"] in UNCAPPED_SUBSCRIPTION_SCHEMA_VERSIONS
        else BOUNDED_STAGE_LIMITS
    )
    stage_limits: dict[str, StageLimits] = {}
    for name in STAGES:
        stage = _expect_keys(
            stage_document[name],
            {
                "maximum_input_tokens_per_turn",
                "maximum_turns",
                "maximum_output_tokens",
                "maximum_tool_calls",
            },
            field=f"{name} stage limits",
        )
        limits = StageLimits(
            maximum_input_tokens_per_turn=_bounded_integer(
                stage["maximum_input_tokens_per_turn"],
                field=f"{name} input tokens",
                minimum=1,
                maximum=XAI_MAX_INPUT_TOKENS,
            ),
            maximum_turns=_bounded_integer(
                stage["maximum_turns"], field=f"{name} turns", minimum=1, maximum=10
            ),
            maximum_output_tokens=(
                None
                if expected[name].maximum_output_tokens is None
                and stage["maximum_output_tokens"] is None
                else _bounded_integer(
                    stage["maximum_output_tokens"],
                    field=f"{name} output tokens",
                    minimum=1,
                    maximum=XAI_MAX_OUTPUT_TOKENS,
                )
            ),
            maximum_tool_calls=_bounded_integer(
                stage["maximum_tool_calls"], field=f"{name} tool calls", minimum=0, maximum=100
            ),
        )
        if limits != expected[name]:
            raise SpendPolicyError(f"{name} stage limits changed")
        stage_limits[name] = limits
    return stage_limits


def _load_policy_request_contract(
    root: Mapping[str, Any],
) -> tuple[Mapping[str, Any], int | None]:
    request_contract = _expect_keys(
        root.get("provider_request_contract"),
        {
            "model",
            "service_tier",
            "priority_processing_allowed",
            "store",
            "parallel_tool_calls",
            "maximum_request_bytes",
            "maximum_response_bytes",
            "maximum_elapsed_seconds",
            "maximum_tool_calls",
            "maximum_turns",
            "maximum_output_tokens",
            "qualification_maximum_output_tokens",
            "discovery_tools",
            "qualification_tools",
        }
        | (
            {"reasoning_effort"}
            if root["schema_version"] in SUBSCRIPTION_SCHEMA_VERSIONS
            else set()
        ),
        field="provider request contract",
    )
    qualification_output_limit = request_contract["qualification_maximum_output_tokens"]
    if (
        root["schema_version"] in UNCAPPED_SUBSCRIPTION_SCHEMA_VERSIONS
        and qualification_output_limit is not None
    ):
        raise SpendPolicyError("current early-warning policy has no output token cap")
    if qualification_output_limit is not None and (
        isinstance(qualification_output_limit, bool)
        or not isinstance(qualification_output_limit, int)
        or not 1 <= qualification_output_limit <= XAI_QUALIFICATION_MAX_OUTPUT_TOKENS
    ):
        raise SpendPolicyError("qualification output limit is outside its approved bound")
    expected_request = {
        "model": XAI_THREAT_SEARCH_MODEL
        if root["schema_version"] in SUBSCRIPTION_SCHEMA_VERSIONS
        else "grok-4.6",
        **(
            {"reasoning_effort": "high"}
            if root["schema_version"] in SUBSCRIPTION_SCHEMA_VERSIONS
            else {}
        ),
        "service_tier": "default",
        "priority_processing_allowed": False,
        "store": False,
        "parallel_tool_calls": False,
        "maximum_request_bytes": XAI_MAX_REQUEST_BYTES,
        "maximum_response_bytes": XAI_MAX_RESPONSE_BYTES,
        "maximum_elapsed_seconds": XAI_MAX_ELAPSED_SECONDS,
        "maximum_tool_calls": 4,
        "maximum_turns": 3,
        "maximum_output_tokens": (
            None
            if root["schema_version"] in UNCAPPED_SUBSCRIPTION_SCHEMA_VERSIONS
            else XAI_MAX_OUTPUT_TOKENS_PER_REQUEST
        ),
        "qualification_maximum_output_tokens": qualification_output_limit,
        "discovery_tools": ["web_search", "x_search"],
        "qualification_tools": [],
    }
    if request_contract != expected_request:
        raise SpendPolicyError("provider request contract is outside its approved boundary")
    return request_contract, qualification_output_limit


def _load_policy_activation(
    root: Mapping[str, Any], state: str
) -> tuple[Mapping[str, Any], list[dict[str, Any]], str | None]:
    activation = _expect_keys(
        root.get("activation_contract"),
        {
            "collector_present",
            "unattended_collection_allowed",
            "unattended_scope",
            "maximum_warning_lifetime_hours",
            "recheck_interval_minutes",
            "maximum_rechecks_per_warning",
            "automatic_publication_allowed",
            "automatic_publication_approval_id",
            "automatic_confirmation_allowed",
            "external_calls_allowed",
            "all_required_controls_must_pass",
            "required_controls",
        },
        field="activation contract",
    )
    required_controls = activation.get("required_controls", [])
    dispatch_status = "passed" if state in {"shadow", "active"} else "pending"
    publication_status = "passed" if state == "active" else "pending"
    expected_controls = [
        {
            "control_id": "no-provider-billing-settings-access",
            "required_for": "dispatch",
            "status": "passed",
        },
        {
            "control_id": "concurrency-and-idempotency",
            "required_for": "dispatch",
            "status": "passed",
        },
        {
            "control_id": "exact-activation-artifact",
            "required_for": "dispatch",
            "status": dispatch_status,
        },
        {
            "control_id": "four-consecutive-shadow-windows",
            "required_for": "publication",
            "status": publication_status,
        },
        {
            "control_id": "exact-public-activation-approval",
            "required_for": "publication",
            "status": publication_status,
        },
    ]
    if required_controls != expected_controls:
        raise SpendPolicyError("spend policy controls are outside the approved source state")
    expected_activation = {
        "collector_present": True,
        "unattended_collection_allowed": state in {"shadow", "active"},
        "unattended_scope": "scheduled_ai_qualified_warning_lane_and_hourly_recheck",
        "maximum_warning_lifetime_hours": 12,
        "recheck_interval_minutes": 60,
        "maximum_rechecks_per_warning": 12,
        "automatic_publication_allowed": state == "active",
        "automatic_publication_approval_id": activation.get("automatic_publication_approval_id"),
        "automatic_confirmation_allowed": False,
        "external_calls_allowed": state in {"shadow", "active"},
        "all_required_controls_must_pass": True,
    }
    activation_without_controls = {
        key: value for key, value in activation.items() if key != "required_controls"
    }
    if activation_without_controls != expected_activation:
        raise SpendPolicyError("spend activation is outside the approved warning-lane scope")
    approval_id = activation["automatic_publication_approval_id"]
    if state == "active":
        if not isinstance(approval_id, str) or not approval_id.startswith("gbsec:approval:"):
            raise SpendPolicyError("active publication requires an exact approval ID")
    elif approval_id is not None:
        raise SpendPolicyError("inactive publication cannot retain an approval ID")
    boolean_activation_fields = {
        "collector_present",
        "unattended_collection_allowed",
        "automatic_publication_allowed",
        "automatic_confirmation_allowed",
        "external_calls_allowed",
        "all_required_controls_must_pass",
    }
    if any(type(activation[field]) is not bool for field in boolean_activation_fields):
        raise SpendPolicyError("spend activation flags must be booleans")
    integer_activation_fields = {
        "maximum_warning_lifetime_hours",
        "recheck_interval_minutes",
        "maximum_rechecks_per_warning",
    }
    if any(
        isinstance(activation[field], bool) or not isinstance(activation[field], int)
        for field in integer_activation_fields
    ):
        raise SpendPolicyError("spend activation limits must be integers")
    return activation, required_controls, approval_id


BOUNDED_NATIVE_SUBSCRIPTION_CONTRACT = {
    "primary": "grok_build_subscription",
    "fallback": "api_key",
    "fallback_requires": "proven_uncharged_primary_receipt",
    "model": "grok-4.7",
    "actual_model": "grok-4.7-build",
    "reasoning_effort": "high",
    "harness_version": "1.0.41",
    "maximum_elapsed_seconds": 120,
    "maximum_model_turns": 3,
    "maximum_qualification_turns": 1,
    "maximum_output_tokens_per_discovery_turn": 2730,
    "maximum_observed_tool_calls": 4,
    "tool_bound_enforcement": "stop_and_reject_over_limit",
    "provider_internal_parallel_searches": "owner_approved_native_limitation",
    "discovery_tools": ["web_search", "x_search", "web_fetch"],
    "qualification_tools": [],
    "local_state": "ephemeral_64MiB_noswap_tmpfs",
    "session_upload": False,
    "retained_reasoning": False,
    "automatic_retries": 0,
}
NATIVE_SUBSCRIPTION_CONTRACT = {
    **BOUNDED_NATIVE_SUBSCRIPTION_CONTRACT,
    "maximum_output_tokens_per_discovery_turn": None,
    "maximum_output_tokens_per_attempt": None,
    "maximum_qualification_output_tokens": None,
}

# Version 6 remains readable with its historical paid-fallback contract. Version
# 7 cannot dispatch an API-key fallback. Route selection is policy-bound and is
# recorded before dispatch; a timed-out or partly consumed primary is not retried.
CLAUDE_FALLBACK_CONTRACT = {
    **NATIVE_SUBSCRIPTION_CONTRACT,
    "fallback": "claude_code_subscription",
    "fallback_requires": "policy_bound_primary_unavailability_or_proven_uncharged_receipt",
    "fallback_model": "claude-opus-5-5",
    "fallback_reasoning_effort": "high",
    "fallback_harness_version": "2.1.309",
    "fallback_tools": ["WebSearch"],
    "fallback_search_coverage": "public_web_index_only_not_native_x_search",
    "fallback_usage_basis": "aggregate_modelUsage_including_search_helpers",
    "fallback_search_helpers": "same_model_required_effort_not_independently_observable",
    "fallback_certificate_store": "system",
    "primary_unavailable_reason": "trust_not_qualified",
}


def load_spend_policy(document: dict[str, Any]) -> SpendPolicy:
    if isinstance(document, dict) and document.get("schema_version") == (
        LEGACY_POLICY_SCHEMA_VERSION
    ):
        document = _strip_legacy_pricing(document)
    root = _expect_keys(
        document,
        {
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
        }
        | (
            {"subscription_contract"}
            if isinstance(document, dict)
            and document.get("schema_version") in SUBSCRIPTION_SCHEMA_VERSIONS
            else set()
        ),
        field="spend policy",
    )
    if root.get("schema_version") not in {*SUBSCRIPTION_SCHEMA_VERSIONS, API_POLICY_SCHEMA_VERSION}:
        raise SpendPolicyError("unsupported spend policy schema")
    if root["schema_version"] in SUBSCRIPTION_SCHEMA_VERSIONS:
        native_contract = (
            CLAUDE_FALLBACK_CONTRACT
            if root["schema_version"] == POLICY_SCHEMA_VERSION
            else NATIVE_SUBSCRIPTION_CONTRACT
            if root["schema_version"] == GROK_API_SUBSCRIPTION_SCHEMA_VERSION
            else BOUNDED_NATIVE_SUBSCRIPTION_CONTRACT
        )
        if root["schema_version"] == POLICY_SCHEMA_VERSION:
            if not isinstance(root["subscription_contract"], dict):
                raise SpendPolicyError("native subscription boundary changed")
            reason = root["subscription_contract"].get("primary_unavailable_reason")
            if reason is not None and (
                not isinstance(reason, str)
                or reason not in {"allowance_exhausted", "trust_not_qualified"}
            ):
                raise SpendPolicyError("primary unavailability is not an approved reason")
            native_contract = {**native_contract, "primary_unavailable_reason": reason}
        if canonical_json_bytes(root["subscription_contract"]) != canonical_json_bytes(
            native_contract
        ):
            raise SpendPolicyError("native subscription boundary changed")
    if root.get("policy_id") != POLICY_ID:
        raise SpendPolicyError("spend policy ID is unsupported")
    if root.get("policy_state") not in {"disabled", "ready", "shadow", "active"}:
        raise SpendPolicyError("spend policy state is unsupported")
    state = root["policy_state"]
    stage_limits = _load_policy_stage_limits(root)
    lane_limits = _expect_keys(
        root.get("lane_limits"), set(EXPECTED_LANE_LIMITS), field="lane limits"
    )
    if any(isinstance(value, bool) or not isinstance(value, int) for value in lane_limits.values()):
        raise SpendPolicyError("scheduled warning lane limits must be integers")
    if lane_limits != EXPECTED_LANE_LIMITS:
        raise SpendPolicyError("scheduled warning lane limits are outside the approved boundary")
    schedule = _expect_keys(
        root.get("schedule_contract"), set(EXPECTED_SCHEDULE), field="schedule contract"
    )
    if schedule != EXPECTED_SCHEDULE:
        raise SpendPolicyError("schedule contract changed")
    request_contract, qualification_output_limit = _load_policy_request_contract(root)
    activation, required_controls, approval_id = _load_policy_activation(root, state)
    if root["required_test_scenarios"] != REQUIRED_TEST_SCENARIOS:
        raise SpendPolicyError("spend policy test scenarios changed")
    expected_evidence = {
        "contract_only": False,
        "executable_enforcement_present": True,
        "checklist_item_may_be_closed": False,
        "notes": _evidence_notes(root["schema_version"], state),
    }
    if root["current_evidence"] != expected_evidence:
        raise SpendPolicyError("spend policy evidence statement changed")
    controls_must_pass = bool(activation["all_required_controls_must_pass"])
    return SpendPolicy(
        policy_id=POLICY_ID,
        provider_model=request_contract["model"],
        subscription_first=root["schema_version"] in SUBSCRIPTION_SCHEMA_VERSIONS,
        current_request_contract=root["schema_version"] == POLICY_SCHEMA_VERSION,
        primary_unavailable_reason=(
            root["subscription_contract"]["primary_unavailable_reason"]
            if root["schema_version"] == POLICY_SCHEMA_VERSION
            else None
        ),
        policy_state=state,
        maximum_active_discovery_workers=lane_limits["maximum_active_discovery_workers"],
        maximum_provider_requests_per_run=lane_limits["maximum_provider_requests_per_run"],
        maximum_discovery_requests_per_run=lane_limits["maximum_discovery_requests_per_run"],
        maximum_validated_candidates_per_run=lane_limits["maximum_validated_candidates_per_run"],
        maximum_qualification_requests_per_run=lane_limits[
            "maximum_qualification_requests_per_run"
        ],
        maximum_new_warnings_per_run=lane_limits["maximum_new_warnings_per_run"],
        maximum_new_warnings_per_day=lane_limits["maximum_new_warnings_per_utc_day"],
        maximum_provider_attempts=lane_limits["maximum_provider_attempts"],
        maximum_tool_calls=request_contract["maximum_tool_calls"],
        maximum_turns=request_contract["maximum_turns"],
        maximum_output_tokens=request_contract["maximum_output_tokens"],
        qualification_maximum_output_tokens=qualification_output_limit,
        maximum_request_bytes=request_contract["maximum_request_bytes"],
        maximum_response_bytes=request_contract["maximum_response_bytes"],
        maximum_elapsed_seconds=request_contract["maximum_elapsed_seconds"],
        stage_limits=stage_limits,
        schedule_minute_offsets=tuple(schedule["minute_offsets"]),
        schedule_grace_minutes=schedule["grace_minutes"],
        external_calls_allowed=bool(activation["external_calls_allowed"]),
        unattended_collection_allowed=bool(activation["unattended_collection_allowed"]),
        unattended_scope=str(activation["unattended_scope"]),
        maximum_warning_lifetime_hours=int(activation["maximum_warning_lifetime_hours"]),
        recheck_interval_minutes=int(activation["recheck_interval_minutes"]),
        maximum_rechecks_per_warning=int(activation["maximum_rechecks_per_warning"]),
        automatic_publication_allowed=bool(activation["automatic_publication_allowed"]),
        automatic_publication_approval_id=approval_id,
        automatic_confirmation_allowed=bool(activation["automatic_confirmation_allowed"]),
        all_required_controls_pass=controls_must_pass
        and all(
            item["status"] == "passed"
            for item in required_controls
            if item["required_for"] == "dispatch"
        ),
        publication_controls_pass=controls_must_pass
        and all(
            item["status"] == "passed"
            for item in required_controls
            if item["required_for"] == "publication"
        ),
    )


def load_spend_policy_path(path: Path) -> SpendPolicy:
    return load_spend_policy(json.loads(path.read_text(encoding="utf-8")))


def render_spend_policy_state(
    document: dict[str, Any],
    *,
    state: str,
    approval_id: str | None = None,
) -> dict[str, Any]:
    """Render one exact shadow or active policy from a valid source document."""
    load_spend_policy(document)
    if state not in {"shadow", "active"}:
        raise SpendPolicyError("rendered policy state must be shadow or active")
    if state == "active":
        if not isinstance(approval_id, str) or not approval_id.startswith("gbsec:approval:"):
            raise SpendPolicyError("active publication requires an exact approval ID")
    elif approval_id is not None:
        raise SpendPolicyError("shadow policy cannot retain an approval ID")
    rendered = deepcopy(document)
    if rendered.get("schema_version") == LEGACY_POLICY_SCHEMA_VERSION:
        rendered = _strip_legacy_pricing(rendered)
    rendered["policy_state"] = state
    activation = rendered["activation_contract"]
    activation["unattended_collection_allowed"] = True
    activation["automatic_publication_allowed"] = state == "active"
    activation["automatic_publication_approval_id"] = approval_id
    activation["external_calls_allowed"] = True
    for control in activation["required_controls"]:
        if control["control_id"] == "exact-activation-artifact":
            control["status"] = "passed"
        elif control["required_for"] == "publication":
            control["status"] = "passed" if state == "active" else "pending"
    rendered["current_evidence"]["notes"] = _evidence_notes(rendered["schema_version"], state)
    load_spend_policy(rendered)
    return rendered
