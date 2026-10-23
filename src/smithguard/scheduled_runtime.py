"""Closed command surface for the source-only scheduled AI warning lane."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from smithguard.discovery import DISCOVERY_PROMPT_VERSION
from smithguard.grok_build import GrokBuildWarningProvider, SubscriptionFirstProvider
from smithguard.identifiers import sha256_id
from smithguard.runtime import (
    DEFAULT_SPEND_POLICY,
    RuntimeConfigurationError,
    _engine,
    _session_factory,
    _xai_key,
    load_runtime_config,
)
from smithguard.scheduled_discovery import (
    XaiScheduledWarningProvider,
    build_qualification_payload,
    enqueue_due_discovery,
    validate_candidates,
    validate_qualification,
    work_one,
)
from smithguard.spend import ExternalDispatchDisabled, load_spend_policy_path
from smithguard.warning_dispatch import dispatch_guard


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the bounded SmithGuard AI warning lane")
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--enqueue-due", action="store_true")
    operation.add_argument("--work", action="store_true")
    operation.add_argument("--rehearsal", action="store_true")
    parser.add_argument("--limit", type=int, default=1)
    return parser


def _rehearsal() -> None:
    source_url = "https://security.example/report"
    candidate = {
        "observed_claim": "A synthetic public report identifies a potentially malicious package.",
        "category": "malicious_package",
        "event_time": "2026-08-20T12:00:00Z",
        "time_precision": "exact",
        "artifacts": [
            {
                "ecosystem": "npm",
                "name": "synthetic-warning-lane",
                "version": "1.0.0",
                "digest": None,
                "public_identifier": None,
            }
        ],
        "sources": [
            {
                "url": source_url,
                "publisher": "Synthetic Security",
                "published_at": "2026-08-20T12:00:00Z",
                "source_class_suggestion": "discovery",
                "origin_cluster_suggestion": "untrusted-hint",
                "claimed_facts": ["The synthetic package is named."],
            }
        ],
        "supporting_factors": ["An exact public artifact is present."],
        "contradictions": [],
        "corrections_or_withdrawals": [],
        "unknowns": ["This is fabricated rehearsal data."],
        "rights_disposition": "unknown",
        "limitation": "sampled_not_complete",
    }
    output = json.dumps(
        {
            "prompt_version": DISCOVERY_PROMPT_VERSION,
            "sampled_not_complete": True,
            "candidates": [candidate],
        },
        sort_keys=True,
    )
    validated, rejected = validate_candidates(
        output,
        citation_urls=(source_url,),
        now=datetime(2026, 8, 20, 13, 0, tzinfo=UTC),
        allow_reserved_hosts=True,
    )
    if len(validated) != 1 or rejected:
        raise RuntimeError("synthetic discovery validation failed")
    qualification_payload = build_qualification_payload(validated[0])
    qualification = json.dumps(
        {
            "decision": "qualify",
            "reason_code": "synthetic_public_lead",
            "explanation": "Synthetic evidence qualifies only for an internal rehearsal.",
            "supporting_origin_url": source_url,
            "artifact_keys": list(validated[0].artifact_keys),
        },
        sort_keys=True,
    )
    decision = validate_qualification(qualification, candidate=validated[0])
    if decision.decision != "qualify" or qualification_payload["tools"] != []:
        raise RuntimeError("synthetic qualification validation failed")


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        if arguments.limit != 1:
            raise RuntimeConfigurationError("scheduled warning lane limit must equal one")
        if arguments.rehearsal:
            _rehearsal()
            sys.stdout.write(
                "warning_lane_rehearsal_complete external_calls=0 public_writes=0 candidates=1\n"
            )
            return 0
        from smithguard.emerging_leads import publication_enabled

        publication_enabled()
        config = load_runtime_config(require_xai=False)
        policy_path = config.spend_policy_path or Path(
            os.environ.get("SMITHGUARD_SPEND_POLICY_PATH", DEFAULT_SPEND_POLICY)
        )
        policy = load_spend_policy_path(policy_path)
        factory = _session_factory(_engine(config))
        now = datetime.now(UTC)
        if arguments.enqueue_due:
            # Keep the authority lock through the enqueue transaction's commit.
            # Lead expiry is independent and runs in the always-on signals unit.
            with dispatch_guard("discovery") as control:
                if control is None:
                    sys.stdout.write("warning_lane_enqueue_complete created=0 contained=1\n")
                    return 0
                with factory() as session, session.begin():
                    from smithguard.emerging_leads import yield_summary

                    lead_yield = yield_summary(session, since=now - timedelta(hours=24))
                    created = enqueue_due_discovery(
                        session, policy=policy, now=now, protocol_version="2.0.0"
                    )
            sys.stdout.write(
                f"warning_lane_enqueue_complete created={len(created)} "
                f"lead_decisions_24h={json.dumps(lead_yield, sort_keys=True)}\n"
            )
            return 0

        def fallback():
            if config.xai_key_path is None:
                raise RuntimeConfigurationError("scheduled fallback credential is missing")
            return XaiScheduledWarningProvider(
                api_key=_xai_key(config.xai_key_path),
                maximum_request_bytes=policy.maximum_request_bytes,
                maximum_response_bytes=policy.maximum_response_bytes,
                maximum_elapsed_seconds=policy.maximum_elapsed_seconds,
            )

        primary = GrokBuildWarningProvider()
        result = work_one(
            factory,
            policy=policy,
            provider=SubscriptionFirstProvider(
                primary=primary,
                fallback_factory=fallback,
            ),
            worker_id=f"{socket.gethostname()}:{os.getpid()}",
            now=now,
        )
        if primary.cleanup_failed:
            # Receipts have committed. Stop the oneshot before another ExecStart
            # so systemd tears down the private RAM mount immediately.
            sys.stderr.write("runtime_error:native_cleanup_failed\n")
            return 3
        sys.stdout.write(
            f"warning_lane_work_complete queue={result.queue} outcome={result.outcome}\n"
        )
        return 0
    except RuntimeConfigurationError as error:
        sys.stderr.write(f"configuration_error:{error}\n")
        return 2
    except ExternalDispatchDisabled:
        sys.stderr.write("policy_denied:scheduled_warning_lane_disabled\n")
        return 4
    except Exception as error:
        job_hash = sha256_id(b"unavailable").removeprefix("sha256:")[:12]
        sys.stderr.write(
            "stage=scheduled_runtime "
            f"error={type(error).__name__} "
            f"reason=scheduled_warning_lane_failed job={job_hash}\n"
        )
        sys.stderr.write("runtime_error:scheduled_warning_lane_failed\n")
        return 3
