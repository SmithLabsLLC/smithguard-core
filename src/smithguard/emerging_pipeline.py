"""Lead discovery and qualification reuse the scheduled lane's durable attempt guard."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, time, timedelta
from urllib.parse import urlsplit

from sqlalchemy import func, select

from smithguard.db.jobs import complete, enqueue
from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import EmergingLeadRecord, JobRecord, PreliminaryWarningRecord
from smithguard.emerging_leads import (
    latest_lead,
    publication_enabled,
    record_lead,
    retained_lead_for,
)
from smithguard.identifiers import canonical_json_bytes, sha256_id
from smithguard.lead_protocol import (
    DISCOVERY_INSTRUCTIONS,
    DISCOVERY_SCHEMA,
    POLICY_ID,
    PROMPT_VERSION,
    QUALIFICATION_INSTRUCTIONS,
    QUALIFICATION_SCHEMA,
    decode_leads,
    qualify_decision,
)
from smithguard.result_availability import observe_committed_result
from smithguard.xai_settings import XAI_THREAT_SEARCH_REASONING_EFFORT


def lead_discovery_payload(legacy: dict) -> dict:
    """Retain tools, windows, model and the current provider policy; use lead protocol."""
    result = deepcopy(legacy)
    values = json.loads(result["input"])
    values["prompt_version"] = PROMPT_VERSION
    values["objective"] = (
        "Find attributable early software-security reports, including unconfirmed single "
        "social posts. Missing technical details are acceptable."
    )
    values["source_limit_per_candidate"] = 5
    result.update(
        instructions=DISCOVERY_INSTRUCTIONS,
        prompt_cache_key=f"{PROMPT_VERSION}:{values['lane']}",
        input=json.dumps(values, sort_keys=True, ensure_ascii=True),
    )
    result["text"]["format"].update(name="smithguard_emerging_leads", schema=DISCOVERY_SCHEMA)
    return result


def finish_discovery(factory, *, job, policy, result, now, allow_reserved_hosts, request_hash):
    from smithguard import scheduled_discovery as lane

    response_hash = sha256_id(result.output_text.encode())
    try:
        candidates, rejections = decode_leads(
            result.output_text, result.citation_urls, now, allow_reserved_hosts=allow_reserved_hosts
        )
    except (ValueError, TypeError):
        candidates, rejections = (
            [],
            [{"reason": "lead_envelope_invalid", "candidate_sha256": response_hash}],
        )
    try:
        with factory() as session, session.begin():
            scheduled = retained = duplicates = deferred = 0
            for index, rejection in enumerate(rejections):
                lane.append_receipt(
                    session,
                    receipt_type="validation_rejection",
                    reason_code=rejection["reason"],
                    run_id=job.payload["run_id"],
                    job_id=job.job_id,
                    occurred_at=now + timedelta(microseconds=10 + index),
                    public_metadata=rejection,
                )
            for candidate in candidates[: policy.maximum_validated_candidates_per_run]:
                previous = latest_lead(session, candidate["lead_id"])
                if previous is None:
                    # A lead recorded under another identity for the same source (earlier
                    # identity rule or another link form) and subject keeps its identity.
                    earlier = retained_lead_for(session, candidate)
                    if earlier is not None:
                        candidate = {**candidate, "lead_id": earlier.lead_id}
                        previous = earlier
                # A repeat of identical evidence is not a renewal or another paid qualification.
                if (
                    previous
                    and previous.reason != "awaiting_triage"
                    and all(
                        previous.document.get(k) == candidate[k]
                        for k in ("subject", "allegation", "sources")
                    )
                ):
                    duplicates += 1
                    continue
                if previous and (
                    previous.state in {"withdrawn", "rejected", "expired"}
                    or previous.expires_at <= now
                ):
                    duplicates += 1
                    continue
                row, created = record_lead(
                    session, candidate, state="needs_enrichment", reason="awaiting_triage", now=now
                )
                if row.lead_id != candidate["lead_id"]:
                    duplicates += 1
                    continue
                retained += int(previous is None and created)
                if scheduled >= policy.maximum_qualification_requests_per_run:
                    deferred += 1
                    continue
                key = f"lead-qualification:{candidate['lead_id']}:{row.revision}"
                if session.scalar(
                    select(JobRecord.job_id)
                    .where(
                        JobRecord.queue == lane.QUALIFICATION_QUEUE,
                        JobRecord.idempotency_key_hash == sha256_id(key.encode()),
                    )
                    .limit(1)
                ):
                    continue
                candidate = {
                    k: row.document[k]
                    for k in ("lead_id", "subject", "allegation", "sources", "observed_at")
                }
                enqueue(
                    session,
                    queue=lane.QUALIFICATION_QUEUE,
                    job_type=lane.QUALIFICATION_JOB_TYPE,
                    idempotency_key=key,
                    payload={
                        "schema_version": "2.0.0",
                        "run_id": job.payload["run_id"],
                        "policy_id": policy.policy_id,
                        "lead_policy_id": POLICY_ID,
                        "schedule_window": job.payload["schedule_window"],
                        "candidate": candidate,
                        "lead_revision": row.revision,
                        "lead_record_hash": row.record_hash,
                        "candidate_sha256": sha256_id(canonical_json_bytes(candidate)),
                        "discovery_request_sha256": request_hash,
                        "discovery_response_sha256": response_hash,
                    },
                    payload_classification="internal_control",
                    # One retry for a failure proven uncharged (connect or refused).
                    max_attempts=2,
                    available_at=now,
                    now=now,
                )
                scheduled += 1
            completion_receipt = lane.append_receipt(
                session,
                receipt_type="discovery_completed",
                reason_code="bounded_leads_processed",
                run_id=job.payload["run_id"],
                job_id=job.job_id,
                occurred_at=now + timedelta(microseconds=300),
                public_metadata={
                    "accepted_candidates": len(candidates),
                    "rejected_candidates": len(rejections),
                    "leads_retained": retained,
                    "duplicate_leads": duplicates,
                    "qualification_queued": scheduled,
                    # Never silent: candidates beyond the run caps are counted.
                    "candidates_over_cap": max(
                        0, len(candidates) - policy.maximum_validated_candidates_per_run
                    ),
                    "qualification_deferred": deferred,
                    "request_sha256": request_hash,
                    "response_sha256": response_hash,
                },
            )
            complete(
                session,
                job_id=job.job_id,
                lease_token=job.lease_token,
                now=now + timedelta(microseconds=301),
            )
            receipt_binding = (
                completion_receipt.job_id,
                completion_receipt.payload["receipt_sha256"],
            )
    except Exception as error:
        lane._emit_failure_diagnostic(
            stage="lead_discovery_completion",
            error=error,
            reason_code="lead_discovery_completion_failed",
            job_id=job.job_id,
        )
        return lane._close_post_response_failure(
            factory, job=job, policy=policy, provider_result=result, now=now, error=error
        )
    observe_committed_result(
        factory,
        job_id=job.job_id,
        run_id=job.payload["run_id"],
        receipt_id=receipt_binding[0],
        receipt_hash=receipt_binding[1],
        stage="discovery",
        job_clock=now,
        provider_finished_at=result.native_timing.observed_finished_at
        if result.native_timing is not None
        else None,
    )
    return "succeeded"


def _publication_room(session, policy, now, candidate, run_id):
    day = datetime.combine(now.date(), time.min, tzinfo=UTC)
    advisory_xact_lock(session, "emerging-lead-publication:" + day.date().isoformat())
    if session.scalar(
        select(EmergingLeadRecord.lead_id)
        .where(
            EmergingLeadRecord.lead_id == candidate["lead_id"],
            EmergingLeadRecord.public_eligible.is_(True),
        )
        .limit(1)
    ):
        return True
    first_publications = (
        select(
            EmergingLeadRecord.lead_id,
            func.min(EmergingLeadRecord.observed_at).label("published_at"),
        )
        .where(EmergingLeadRecord.public_eligible.is_(True))
        .group_by(EmergingLeadRecord.lead_id)
        .subquery()
    )
    count = (
        session.scalar(
            select(func.count())
            .select_from(first_publications)
            .where(
                first_publications.c.published_at >= day,
                first_publications.c.published_at < day + timedelta(days=1),
            )
        )
        or 0
    )
    legacy_count = (
        session.scalar(
            select(func.count(func.distinct(PreliminaryWarningRecord.id))).where(
                PreliminaryWarningRecord.created_at >= day,
                PreliminaryWarningRecord.created_at < day + timedelta(days=1),
            )
        )
        or 0
    )
    published = list(
        session.scalars(
            select(EmergingLeadRecord).where(
                EmergingLeadRecord.public_eligible.is_(True),
                EmergingLeadRecord.document["publication_run_id"].as_string() == run_id,
                EmergingLeadRecord.observed_at >= day - timedelta(days=1),
            )
        )
    )
    ids = {row.lead_id for row in published}
    if candidate["lead_id"] in ids:
        return True
    origin = urlsplit(candidate["sources"][0]["url"]).hostname
    repeated_subject_origin = any(
        row.document["subject"].casefold() == candidate["subject"].casefold()
        and urlsplit(row.document["sources"][0]["url"]).hostname == origin
        for row in published
    )
    return (
        count + legacy_count < policy.maximum_new_warnings_per_day
        and len(ids) < policy.maximum_new_warnings_per_run
        and not repeated_subject_origin
    )


def process_qualification(factory, *, job, policy, provider, now):
    from smithguard import scheduled_discovery as lane

    payload = job.payload
    try:
        if (
            job.job_type != lane.QUALIFICATION_JOB_TYPE
            or set(payload)
            != {
                "schema_version",
                "run_id",
                "policy_id",
                "lead_policy_id",
                "schedule_window",
                "candidate",
                "lead_revision",
                "lead_record_hash",
                "candidate_sha256",
                "discovery_request_sha256",
                "discovery_response_sha256",
            }
            or payload["policy_id"] != policy.policy_id
            or payload["lead_policy_id"] != POLICY_ID
        ):
            raise ValueError("lead_qualification_binding_invalid")
        lane._scheduled_run_context(
            policy=policy, run_id=payload["run_id"], schedule_window=payload["schedule_window"]
        )
        for name in ("lead_record_hash", "discovery_request_sha256", "discovery_response_sha256"):
            if not isinstance(payload[name], str) or not lane.SHA256.fullmatch(payload[name]):
                raise ValueError("lead_qualification_hash_invalid")
        candidate = payload["candidate"]
        if sha256_id(canonical_json_bytes(candidate)) != payload["candidate_sha256"]:
            raise ValueError("lead_candidate_hash_invalid")
        with factory() as session:
            prior = session.get(
                EmergingLeadRecord, (candidate["lead_id"], payload["lead_revision"])
            )
            if (
                prior is None
                or prior.revision != payload["lead_revision"]
                or prior.record_hash != payload["lead_record_hash"]
            ):
                raise ValueError("lead_qualification_revision_changed")
            if any(
                prior.document.get(k) != candidate.get(k)
                for k in ("lead_id", "subject", "allegation", "sources", "observed_at")
            ):
                raise ValueError("lead_qualification_content_changed")
            if sha256_id(canonical_json_bytes(prior.document)) != prior.record_hash:
                raise ValueError("lead_qualification_integrity_invalid")
            current = latest_lead(session, candidate["lead_id"])
            superseded = current is not None and current.revision != prior.revision
            expired = prior.expires_at <= now or prior.state in {"expired", "rejected", "withdrawn"}
        if expired or superseded:
            with factory() as session, session.begin():
                lane.append_receipt(
                    session,
                    receipt_type="lead_decision",
                    reason_code="superseded_evidence" if superseded else "lead_expired",
                    run_id=payload["run_id"],
                    job_id=job.job_id,
                    occurred_at=now,
                    public_metadata={"lead_id": candidate["lead_id"]},
                )
                complete(session, job_id=job.job_id, lease_token=job.lease_token, now=now)
            return "succeeded"
    except (ValueError, KeyError, TypeError) as error:
        reason = str(error)
        if not (
            isinstance(error, ValueError)
            and reason.startswith("lead_")
            and lane.REASON_PATTERN.fullmatch(reason)
        ):
            reason = "lead_qualification_binding_invalid"
        lane._dead_letter_now(factory, job=job, error_code=reason, now=now)
        return "dead_letter"
    request = {
        "model": lane.DISCOVERY_MODEL,
        "service_tier": "default",
        "reasoning": {"effort": XAI_THREAT_SEARCH_REASONING_EFFORT},
        "store": False,
        "parallel_tool_calls": False,
        "tools": [],
        "instructions": QUALIFICATION_INSTRUCTIONS,
        "input": json.dumps(candidate, ensure_ascii=True, sort_keys=True),
        "text": {
            "format": {
                "type": "json_schema",
                "name": "smithguard_lead_triage",
                "strict": True,
                "schema": QUALIFICATION_SCHEMA,
            }
        },
    }
    if policy.qualification_maximum_output_tokens is not None:
        request["max_output_tokens"] = policy.qualification_maximum_output_tokens
    result = lane._run_provider_stage(
        factory,
        job=job,
        policy=policy,
        provider=provider,
        request_payload=request,
        qualification=True,
        now=now,
    )
    if isinstance(result, str):
        return result
    answer_invalid = False
    try:
        decision, reason = qualify_decision(result.output_text)
    except (ValueError, TypeError):
        # An unparseable answer keeps the lead for enrichment and is recorded as such.
        decision, reason = "needs_enrichment", "needs_more_information"
        answer_invalid = True
    primary = candidate["sources"][0]
    if decision == "retain_as_unverified" and not primary["citation_bound"]:
        decision, reason = "needs_enrichment", "missing_citation"
    if decision == "retain_as_unverified" and not primary["context"]:
        decision, reason = "needs_enrichment", "missing_source_context"
    state = {
        "retain_as_unverified": "unverified",
        "needs_enrichment": "needs_enrichment",
        "reject": "rejected",
    }[decision]
    if reason == "withdrawn_or_corrected":
        state = "withdrawn"
    try:
        with factory() as session, session.begin():
            # Serialize against newer source revisions before accepting a paid result.
            fingerprint = sha256_id(
                canonical_json_bytes(
                    [candidate["subject"].casefold(), candidate["allegation"].casefold()]
                )
            )
            advisory_xact_lock(session, "emerging-lead-fingerprint:" + fingerprint)
            advisory_xact_lock(session, "emerging-lead:" + candidate["lead_id"])
            current = latest_lead(session, candidate["lead_id"])
            if (
                current is None
                or current.revision != payload["lead_revision"]
                or current.record_hash != payload["lead_record_hash"]
            ):
                lane.append_receipt(
                    session,
                    receipt_type="lead_decision",
                    reason_code="superseded_evidence",
                    run_id=payload["run_id"],
                    job_id=job.job_id,
                    occurred_at=now,
                    public_metadata={"lead_id": candidate["lead_id"]},
                )
                complete(session, job_id=job.job_id, lease_token=job.lease_token, now=now)
                return "succeeded"
            publish = (
                publication_enabled()
                and state == "unverified"
                and _publication_room(session, policy, now, candidate, payload["run_id"])
            )
            row, created = record_lead(
                session,
                candidate,
                state=state,
                reason=reason,
                now=now,
                publish=publish,
                publication_run_id=payload["run_id"],
            )
            completion_receipt = lane.append_receipt(
                session,
                receipt_type="lead_decision",
                reason_code=reason,
                run_id=payload["run_id"],
                job_id=job.job_id,
                occurred_at=now + timedelta(microseconds=4),
                public_metadata={
                    "lead_id": row.lead_id,
                    "lead_state": row.state,
                    "lead_revision": row.revision,
                    "revision_created": created,
                    "qualification_answer_invalid": answer_invalid,
                    "qualification_request_sha256": lane.content_hash(request),
                    "qualification_response_sha256": sha256_id(result.output_text.encode()),
                },
            )
            complete(
                session,
                job_id=job.job_id,
                lease_token=job.lease_token,
                now=now + timedelta(microseconds=5),
            )
            receipt_binding = (
                completion_receipt.job_id,
                completion_receipt.payload["receipt_sha256"],
            )
    except Exception as error:
        lane._emit_failure_diagnostic(
            stage="lead_qualification_completion",
            error=error,
            reason_code="lead_qualification_completion_failed",
            job_id=job.job_id,
        )
        return lane._close_post_response_failure(
            factory, job=job, policy=policy, provider_result=result, now=now, error=error
        )
    observe_committed_result(
        factory,
        job_id=job.job_id,
        run_id=job.payload["run_id"],
        receipt_id=receipt_binding[0],
        receipt_hash=receipt_binding[1],
        stage="qualification",
        job_clock=now,
        provider_finished_at=result.native_timing.observed_finished_at
        if result.native_timing is not None
        else None,
    )
    return "succeeded"
