"""Incomplete public reports survive without contaminating exact assessments."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import timedelta

import httpx
import pytest
from jsonschema import Draft202012Validator
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

import smithguard.emerging_leads as leads_module
from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import EmergingLeadRecord, JobRecord, PreliminaryWarningRecord
from smithguard.emerging_leads import (
    enrichment_targets,
    expire_leads,
    latest_lead,
    overdue_lead_count,
    public_page,
    record_lead,
    yield_summary,
)
from smithguard.identifiers import canonical_json_bytes, sha256_id
from smithguard.lead_protocol import (
    POLICY_ID,
    PROMPT_VERSION,
    PUBLICATION_ENV,
    decode_leads,
    qualify_decision,
)
from smithguard.lead_public_contract import LEAD
from smithguard.scheduled_discovery import (
    ProviderResult,
    ScheduledProviderError,
    _transport_diagnostic,
    enqueue_due_discovery,
    work_one,
)

from .test_scheduled_discovery import NOW, _active_policy
from .test_service_api import _public_client

pytestmark = pytest.mark.usefixtures("enabled_warning_dispatch")

URL = "https://research.example/report/1"


def raw_lead(
    *,
    url=URL,
    context="The author reports possible authentication bypass in the Orion tool.",
    published_at=None,
    subject="Orion tool",
):
    return {
        "subject": subject,
        "allegation": "An author reports a possible authentication bypass.",
        "sources": [{"url": url, "context": context, "published_at": published_at}],
    }


def output(*items):
    return json.dumps({"prompt_version": PROMPT_VERSION, "leads": list(items)})


def candidate(**kwargs):
    leads, rejected = decode_leads(
        output(raw_lead(**kwargs)), (kwargs.get("url", URL),), NOW, allow_reserved_hosts=True
    )
    assert not rejected
    return leads[0]


@pytest.mark.parametrize(
    "published_at,precision",
    [
        (None, "unknown"),
        ("2026-08-20", "day"),
        ("2026-08-20T01:00:00Z", "exact"),
        ("2026-08-20T01:00:00", "unknown"),
        ("tomorrow", "unknown"),
        ("2099-01-01", "unknown"),
    ],
)
def test_dates_are_optional_and_never_invent_precision(published_at, precision):
    lead = candidate(published_at=published_at)
    assert lead["sources"][0]["time_precision"] == precision
    assert "artifacts" not in lead


def test_unicode_and_good_source_survive_bad_secondary():
    raw = raw_lead(subject="Orion \u5de5\u5177")
    raw["sources"].extend(
        [
            {"url": "http://127.0.0.1/private"},
            {"url": "https://bad.example", "published_at": {}, "context": "bad"},
        ]
    )
    leads, rejected = decode_leads(output(raw), (URL,), NOW, allow_reserved_hosts=True)
    assert not rejected
    assert leads[0]["subject"] == "Orion \u5de5\u5177"
    assert len(leads[0]["sources"]) == 1


def test_uncited_source_is_retained_internally_and_identity_does_not_change():
    first, _ = decode_leads(output(raw_lead()), (), NOW, allow_reserved_hosts=True)
    second = candidate()
    assert first[0]["lead_id"] == second["lead_id"]
    assert first[0]["sources"][0]["citation_bound"] is False


def test_one_bad_candidate_does_not_discard_good_candidate():
    leads, rejected = decode_leads(
        output(raw_lead(subject="owner/repository"), raw_lead()),
        (URL,),
        NOW,
        allow_reserved_hosts=True,
    )
    assert len(leads) == 1
    assert rejected[0]["reason"] == "lead_placeholder"


def test_control_characters_and_private_urls_fail():
    for raw in (raw_lead(subject="Orion\x00"), raw_lead(url="http://127.0.0.1/a")):
        leads, rejected = decode_leads(output(raw), (), NOW)
        assert not leads and rejected


def test_qualification_reasons_cannot_claim_confirmation():
    assert (
        qualify_decision(
            '{"decision":"retain_as_unverified","reason_code":"attributable_security_report"}'
        )[0]
        == "retain_as_unverified"
    )
    with pytest.raises(ValueError):
        qualify_decision('{"decision":"reject","reason_code":"missing_source_context"}')


def test_revision_history_repeat_expiry_and_correction(database, monkeypatch):
    monkeypatch.setenv(PUBLICATION_ENV, POLICY_ID)
    lead = candidate()
    with Session(database.engine) as session, session.begin():
        row, _ = record_lead(
            session,
            lead,
            state="unverified",
            reason="attributable_security_report",
            now=NOW,
            publish=True,
        )
        expires = row.expires_at
        repeat, created = record_lead(
            session,
            lead,
            state="unverified",
            reason="attributable_security_report",
            now=NOW + timedelta(hours=1),
        )
        assert not created and repeat.expires_at == expires
        page = public_page(session, now=NOW)
        assert len(page["leads"]) == 1
        Draft202012Validator(LEAD).validate(page["leads"][0])
        assert "model_reported_search_context" not in json.dumps(page)
        corrected = deepcopy(lead)
        corrected["sources"][0]["context"] = "The original author explicitly withdraws the report."
        terminal, _ = record_lead(
            session,
            corrected,
            state="withdrawn",
            reason="withdrawn_or_corrected",
            now=NOW + timedelta(hours=2),
        )
        assert terminal.revision == 2 and terminal.expires_at == expires
        assert public_page(session, now=NOW + timedelta(hours=2))["leads"] == []
        assert session.scalar(select(func.count()).select_from(EmergingLeadRecord)) == 2
        assert session.scalar(select(func.count()).select_from(PreliminaryWarningRecord)) == 0


def test_expiry_is_enforced_even_if_sweeper_has_not_run(database, monkeypatch):
    monkeypatch.setenv(PUBLICATION_ENV, POLICY_ID)
    with Session(database.engine) as session, session.begin():
        lead = candidate()
        record_lead(
            session,
            lead,
            state="unverified",
            reason="attributable_security_report",
            now=NOW,
            publish=True,
        )
        later = NOW + timedelta(hours=24)
        assert public_page(session, now=later)["leads"] == []
        assert expire_leads(session, now=later) == 1
        assert expire_leads(session, now=later) == 0
        assert latest_lead(session, lead["lead_id"]).state == "expired"


@pytest.mark.parametrize("new_state", ["unverified", "needs_enrichment", "withdrawn"])
def test_expiry_preserves_a_revision_committed_after_batch_selection(
    database, monkeypatch, new_state
):
    lead = candidate()
    with Session(database.engine) as session, session.begin():
        record_lead(
            session, lead, state="unverified", reason="attributable_security_report", now=NOW
        )
    corrected = deepcopy(lead)
    corrected["allegation"] = "The author has corrected the original report."
    lock = leads_module._try_expiry_lock
    revised = False

    def commit_new_revision_before_lock(session, name):
        nonlocal revised
        if not revised:
            revised = True
            with Session(database.engine) as writer, writer.begin():
                record_lead(
                    writer,
                    corrected,
                    state=new_state,
                    reason="withdrawn_or_corrected",
                    now=NOW + timedelta(hours=23),
                )
        return lock(session, name)

    monkeypatch.setattr(leads_module, "_try_expiry_lock", commit_new_revision_before_lock)
    later = NOW + timedelta(hours=25)
    with Session(database.engine) as session, session.begin():
        assert expire_leads(session, now=later) == 0
        current = latest_lead(session, lead["lead_id"])
        assert current.revision == 2
        assert current.state == new_state
        assert current.document["allegation"] == corrected["allegation"]
        assert overdue_lead_count(session, now=later) == int(new_state != "withdrawn")
    with Session(database.engine) as session, session.begin():
        assert expire_leads(session, now=later) == int(new_state != "withdrawn")
        current = latest_lead(session, lead["lead_id"])
        assert current.document["allegation"] == corrected["allegation"]
        assert current.revision == (2 if new_state == "withdrawn" else 3)


def test_expiry_skips_busy_leads_and_counts_only_current_overdue_states(database):
    later = NOW + timedelta(hours=25)
    lead = candidate()
    with Session(database.engine) as session, session.begin():
        row, _ = record_lead(
            session, lead, state="needs_enrichment", reason="missing_source_context", now=NOW
        )
        fingerprint = row.fingerprint
    with Session(database.engine) as writer, writer.begin():
        advisory_xact_lock(writer, "emerging-lead-fingerprint:" + fingerprint)
        advisory_xact_lock(writer, "emerging-lead:" + lead["lead_id"])
        with Session(database.engine) as sweeper, sweeper.begin():
            assert overdue_lead_count(sweeper, now=NOW) == 0
            assert overdue_lead_count(sweeper, now=later) == 1
            assert expire_leads(sweeper, now=later) == 0
    with Session(database.engine) as session, session.begin():
        assert expire_leads(session, now=later) == 1
        assert overdue_lead_count(session, now=later) == 0
        # The retained overdue revision does not count after a terminal append.
        assert session.scalar(select(func.count()).select_from(EmergingLeadRecord)) == 2


def test_publication_disabled_does_not_retroactively_publish_hidden_leads(database, monkeypatch):
    monkeypatch.delenv(PUBLICATION_ENV, raising=False)
    with Session(database.engine) as session, session.begin():
        record_lead(
            session, candidate(), state="unverified", reason="attributable_security_report", now=NOW
        )
        assert public_page(session, now=NOW)["status"] == "publication_disabled"
        monkeypatch.setenv(PUBLICATION_ENV, POLICY_ID)
        assert public_page(session, now=NOW)["leads"] == []
        monkeypatch.setenv(PUBLICATION_ENV, "true")
        with pytest.raises(ValueError, match="policy_invalid"):
            public_page(session, now=NOW)


def test_enrichment_records_and_pagination(database, monkeypatch):
    monkeypatch.setenv(PUBLICATION_ENV, POLICY_ID)
    with Session(database.engine) as session, session.begin():
        for i in range(4):
            lead = candidate(url=f"https://research.example/{i}", subject=f"Orion {i}")
            record_lead(
                session,
                lead,
                state="needs_enrichment" if i == 3 else "unverified",
                reason="missing_source_context" if i == 3 else "attributable_security_report",
                now=NOW,
                publish=True,
            )
        assert len(enrichment_targets(session, now=NOW)) == 2
        page = public_page(session, now=NOW, limit=2)
        second = public_page(session, now=NOW, limit=2, after=page["next_cursor"])
        assert len(page["leads"]) == 2 and len(second["leads"]) == 1
        assert {x["id"] for x in page["leads"]}.isdisjoint({x["id"] for x in second["leads"]})
        assert second["next_cursor"] is None
        assert yield_summary(session, since=NOW)["needs_enrichment"] == 1


def test_identical_cross_source_repost_does_not_create_or_renew(database):
    with Session(database.engine) as session, session.begin():
        first, _ = record_lead(
            session, candidate(), state="needs_enrichment", reason="awaiting_triage", now=NOW
        )
        duplicate, created = record_lead(
            session,
            candidate(url="https://elsewhere.example/repost"),
            state="needs_enrichment",
            reason="awaiting_triage",
            now=NOW + timedelta(hours=1),
        )
        assert not created and duplicate.lead_id == first.lead_id
        assert duplicate.expires_at == first.expires_at


def test_source_context_updates_are_append_only(database):
    with Session(database.engine) as session, session.begin():
        lead = candidate(context=None)
        first, _ = record_lead(
            session, lead, state="needs_enrichment", reason="awaiting_triage", now=NOW
        )
        second, created = record_lead(
            session,
            candidate(),
            state="needs_enrichment",
            reason="awaiting_triage",
            now=NOW + timedelta(minutes=30),
        )
        assert created and second.revision == first.revision + 1
        assert second.expires_at == first.expires_at
    for statement in (
        "UPDATE smithguard.emerging_leads SET reason = 'tamper'",
        "DELETE FROM smithguard.emerging_leads",
        "TRUNCATE smithguard.emerging_leads",
    ):
        with pytest.raises(DBAPIError), database.engine.begin() as conn:
            conn.execute(text(statement))


class LeadProvider:
    def __init__(
        self,
        raw=None,
        citations=(URL,),
        decision="retain_as_unverified",
        reason="attributable_security_report",
    ):
        self.raw = raw or raw_lead()
        self.citations = citations
        self.decision, self.reason = decision, reason
        self.discovery_calls = self.qualification_calls = 0
        self.qualification_payloads = []

    def discover(self, payload):
        self.discovery_calls += 1
        assert payload["store"] is False and payload["parallel_tool_calls"] is False
        assert payload["max_tool_calls"] == 4
        assert json.loads(payload["input"])["prompt_version"] == PROMPT_VERSION
        return ProviderResult(
            output_text=output(self.raw),
            response_id=f"synthetic-lead-search-{self.discovery_calls}",
            server_side_tool_calls=1,
            citation_urls=self.citations,
        )

    def qualify(self, payload):
        self.qualification_calls += 1
        self.qualification_payloads.append(payload)
        assert payload["tools"] == []
        return ProviderResult(
            output_text=json.dumps({"decision": self.decision, "reason_code": self.reason}),
            response_id=f"synthetic-lead-triage-{self.qualification_calls}",
            server_side_tool_calls=0,
            citation_urls=(),
        )


def work(database, provider, now=NOW):
    return work_one(
        sessionmaker(database.engine),
        policy=_active_policy(),
        provider=provider,
        worker_id="lead-test",
        now=now,
        allow_reserved_hosts=True,
    )


def enqueue_search(database, now=NOW):
    with Session(database.engine) as session, session.begin():
        return enqueue_due_discovery(
            session, policy=_active_policy(), now=now, protocol_version="2.0.0"
        )


@pytest.mark.parametrize(
    "context,citations,expected",
    [
        ("The author reports an authentication bypass in Orion.", (URL,), "unverified"),
        (None, (URL,), "needs_enrichment"),
        ("Author reports a bypass.", (), "needs_enrichment"),
    ],
)
def test_end_to_end_single_source_triage_and_no_repeat_calls(
    database, monkeypatch, context, citations, expected
):
    monkeypatch.setenv(PUBLICATION_ENV, POLICY_ID)
    provider = LeadProvider(raw_lead(context=context), citations)
    enqueue_search(database)
    assert work(database, provider).outcome == "succeeded"
    assert work(database, provider, NOW + timedelta(seconds=1)).outcome == "succeeded"
    assert work(database, provider, NOW + timedelta(seconds=2)).outcome == "idle"
    supplied = json.loads(provider.qualification_payloads[0]["input"])
    assert supplied["sources"][0]["context"] == context
    with Session(database.engine) as session:
        row = latest_lead(session, supplied["lead_id"])
        assert row.state == expected
        expires = row.expires_at
        assert len(public_page(session, now=NOW + timedelta(seconds=3))["leads"]) == int(
            expected == "unverified"
        )
        assert session.scalar(select(func.count()).select_from(PreliminaryWarningRecord)) == 0
    later = NOW + timedelta(minutes=30)
    enqueue_search(database, later)
    assert work(database, provider, later).outcome == "succeeded"
    assert work(database, provider, later + timedelta(seconds=1)).outcome == "idle"
    assert provider.qualification_calls == 1
    with Session(database.engine) as session:
        assert latest_lead(session, supplied["lead_id"]).expires_at == expires


def test_changed_queue_candidate_cannot_bypass_bound_source_record(database):
    provider = LeadProvider()
    enqueue_search(database)
    work(database, provider)
    with Session(database.engine) as session, session.begin():
        row = session.scalar(select(JobRecord).where(JobRecord.queue == "ai-warning-qualification"))
        payload = deepcopy(row.payload)
        payload["candidate"]["allegation"] = "Tampered accusation"
        payload["candidate_sha256"] = sha256_id(canonical_json_bytes(payload["candidate"]))
        row.payload = payload
        row.payload_hash = sha256_id(canonical_json_bytes(payload))
    assert work(database, provider, NOW + timedelta(seconds=1)).outcome == "dead_letter"
    assert provider.qualification_calls == 0


def test_transport_diagnostic_never_exposes_exception_text():
    try:
        try:
            raise httpx.ReadTimeout("sensitive synthetic request value")
        except httpx.ReadTimeout as cause:
            raise ScheduledProviderError(
                "provider_transport_failure", retryable=False, usage_uncertain=True
            ) from cause
    except ScheduledProviderError as error:
        assert _transport_diagnostic(error) == {
            "failure_stage": "provider_transport",
            "transport_cause": "ReadTimeout",
        }


def test_public_route_is_gated_uncached_and_bounded(database, monkeypatch):
    monkeypatch.delenv(PUBLICATION_ENV, raising=False)
    with _public_client(database) as client:
        response = client.get("/v1/emerging-leads.json")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["status"] == "publication_disabled"
        assert client.get("/v1/emerging-leads.json?limit=101").status_code == 400
        assert client.get("/v1/emerging-leads.json?after=invalid").status_code == 400


def test_subject_identity_is_separate_but_wording_is_not():
    first = candidate(subject="Orion")
    second = candidate(subject="Vega")
    assert first["lead_id"] != second["lead_id"]
    changed = raw_lead(subject="Orion")
    changed["allegation"] = "The author corrects a detail of the earlier report."
    decoded, _ = decode_leads(output(changed), (URL,), NOW, allow_reserved_hosts=True)
    assert decoded[0]["lead_id"] == first["lead_id"]


def test_joiners_survive_but_bidi_overrides_do_not():
    for subject in (
        "Orion \u0645\u06cc\u200c\u0634\u0648\u062f",
        "Orion \U0001f469\u200d\U0001f4bb",
    ):
        assert candidate(subject=subject)["subject"] == subject
    leads, rejected = decode_leads(
        output(raw_lead(subject="Orion\u202e")), (URL,), NOW, allow_reserved_hosts=True
    )
    assert not leads and rejected[0]["reason"] == "lead_text_control"


def test_large_unicode_source_set_is_bounded_before_storage(database):
    raw = raw_lead(subject="Orion")
    raw["allegation"] = "\U0001f680" * 1000
    raw["sources"] = [
        {
            "url": f"https://research.example/{i}/" + "a" * 1980,
            "context": "\U0001f680" * 1200,
            "published_at": None,
        }
        for i in range(5)
    ]
    leads, rejected = decode_leads(
        output(raw), (raw["sources"][0]["url"],), NOW, allow_reserved_hosts=True
    )
    assert not rejected and len(leads[0]["sources"]) < 5
    with Session(database.engine) as session, session.begin():
        record_lead(session, leads[0], state="needs_enrichment", reason="awaiting_triage", now=NOW)


def test_superseded_qualification_closes_without_alarm_or_provider_call(database):
    provider = LeadProvider()
    enqueue_search(database)
    work(database, provider)
    changed = candidate(context="The author has added more detail to the report.")
    with Session(database.engine) as session, session.begin():
        record_lead(
            session,
            changed,
            state="needs_enrichment",
            reason="awaiting_triage",
            now=NOW + timedelta(seconds=1),
        )
    assert work(database, provider, NOW + timedelta(seconds=2)).outcome == "succeeded"
    assert provider.qualification_calls == 0
    with Session(database.engine) as session:
        assert (
            session.scalar(
                select(func.count()).select_from(JobRecord).where(JobRecord.state == "dead_letter")
            )
            == 0
        )
        receipts = list(
            session.scalars(select(JobRecord).where(JobRecord.queue == "ai-warning-receipts"))
        )
        assert any(row.payload["reason_code"] == "superseded_evidence" for row in receipts)


def test_new_permalink_after_prior_expiry_is_not_permanently_suppressed(database):
    with Session(database.engine) as session, session.begin():
        first, _ = record_lead(
            session, candidate(), state="unverified", reason="attributable_security_report", now=NOW
        )
        later = NOW + timedelta(hours=25)
        second, created = record_lead(
            session,
            candidate(url="https://research.example/new-report"),
            state="needs_enrichment",
            reason="awaiting_triage",
            now=later,
        )
        assert created and second.lead_id != first.lead_id
        old, created = record_lead(
            session,
            candidate(),
            state="unverified",
            reason="attributable_security_report",
            now=later,
        )
        assert old.state == "expired" and old.expires_at == first.expires_at
        assert public_page(session, now=later)["leads"] == []


def test_publication_caps_share_daily_limit_and_preserve_existing_lead(database):
    from smithguard.emerging_pipeline import _publication_room

    policy = _active_policy()
    with Session(database.engine) as session, session.begin():
        first = candidate(subject="Orion")
        assert _publication_room(session, policy, NOW, first, "run-a")
        record_lead(
            session,
            first,
            state="unverified",
            reason="attributable_security_report",
            now=NOW,
            publish=True,
            publication_run_id="run-a",
        )
        same_subject = candidate(url="https://research.example/other", subject="Orion")
        assert not _publication_room(session, policy, NOW, same_subject, "run-a")
        second = candidate(subject="Vega")
        assert _publication_room(session, policy, NOW, second, "run-a")
        record_lead(
            session,
            second,
            state="unverified",
            reason="attributable_security_report",
            now=NOW,
            publish=True,
            publication_run_id="run-a",
        )
        third = candidate(subject="Altair")
        assert not _publication_room(session, policy, NOW, third, "run-a")
        assert _publication_room(session, policy, NOW, third, "run-b")
        for subject in ("Altair", "Deneb"):
            record_lead(
                session,
                candidate(subject=subject),
                state="unverified",
                reason="attributable_security_report",
                now=NOW,
                publish=True,
                publication_run_id="run-b",
            )
        assert not _publication_room(session, policy, NOW, candidate(subject="Rigel"), "run-c")
        assert _publication_room(session, policy, NOW, first, "run-c")


def test_new_day_does_not_charge_old_publication_revision(database):
    from smithguard.emerging_pipeline import _publication_room

    prior = NOW - timedelta(hours=3)
    with Session(database.engine) as session, session.begin():
        for i in range(4):
            item = candidate(subject=f"Orion {i}")
            record_lead(
                session,
                item,
                state="unverified",
                reason="attributable_security_report",
                now=prior,
                publish=True,
                publication_run_id="yesterday",
            )
            item["sources"][0]["context"] = "Updated context."
            record_lead(
                session,
                item,
                state="unverified",
                reason="attributable_security_report",
                now=NOW,
                publish=True,
                publication_run_id="today-old",
            )
        assert _publication_room(
            session, _active_policy(), NOW, candidate(subject="Vega"), "today-new"
        )


def test_active_http_feed_and_invalid_startup_policy(database, monkeypatch):
    monkeypatch.setenv(PUBLICATION_ENV, POLICY_ID)
    monkeypatch.setattr("tests.test_service_api.NOW", NOW)
    with Session(database.engine) as session, session.begin():
        record_lead(
            session,
            candidate(),
            state="unverified",
            reason="attributable_security_report",
            now=NOW,
            publish=True,
        )
    with _public_client(database) as client:
        response = client.get("/v1/emerging-leads.json")
        assert response.status_code == 200
        assert response.json()["leads"][0]["status"] == "Emerging / Unverified"
        assert "context" not in response.text and "artifact_keys" not in response.text
    monkeypatch.setenv(PUBLICATION_ENV, "enabled")
    with pytest.raises(ValueError, match="publication_policy_invalid"):
        _public_client(database)


def test_transport_failure_receipt_keeps_cause_but_not_message(database):
    class TransportFailureProvider(LeadProvider):
        def discover(self, payload):
            try:
                raise httpx.ReadTimeout("sensitive synthetic request value")
            except httpx.ReadTimeout as cause:
                raise ScheduledProviderError(
                    "provider_transport_failure", retryable=False, usage_uncertain=True
                ) from cause

    enqueue_search(database)
    assert work(database, TransportFailureProvider()).outcome == "dead_letter"
    with Session(database.engine) as session:
        receipts = list(
            session.scalars(select(JobRecord).where(JobRecord.queue == "ai-warning-receipts"))
        )
        failures = [r.payload for r in receipts if r.payload["receipt_type"] == "provider_failure"]
        assert len(failures) == 1
        assert "ReadTimeout" in json.dumps(failures[0])
        assert "sensitive synthetic" not in json.dumps(failures[0])


def test_final_provider_output_is_kept_privately_for_30_days(database) -> None:
    """Owner decision: keep final output text and citations (never reasoning) for
    diagnosis, and purge them after 30 days."""
    from smithguard.db.models import WarningLaneOutputRecord
    from smithguard.warning_lane_outputs import purge_expired_outputs, record_output

    with Session(database.engine) as session, session.begin():
        record_output(
            session,
            run_id="gbsec:ai-warning-run:retention",
            job_id="job-retention",
            attempt=1,
            stage="discovery",
            response_id="resp-1",
            output_text="x" * 300_000,
            citation_urls=("https://x.com/i/status/1970000000000000000",),
            now=NOW,
        )
        # Replays of the same attempt keep the first copy.
        record_output(
            session,
            run_id="gbsec:ai-warning-run:retention",
            job_id="job-retention",
            attempt=1,
            stage="discovery",
            response_id="resp-1",
            output_text="replayed",
            citation_urls=(),
            now=NOW,
        )
    with Session(database.engine) as session:
        (row,) = session.scalars(select(WarningLaneOutputRecord)).all()
        assert row.output_truncated is True
        assert len(row.output_text) == 262_144
        assert row.citation_urls == ["https://x.com/i/status/1970000000000000000"]
        assert row.expires_at == NOW + timedelta(days=30)
    with Session(database.engine) as session, session.begin():
        assert purge_expired_outputs(session, now=NOW + timedelta(days=29)) == 0
        assert purge_expired_outputs(session, now=NOW + timedelta(days=30)) == 1


@pytest.mark.parametrize("state", ["withdrawn", "expired"])
@pytest.mark.parametrize(
    ("stored_url", "seen_url"),
    [
        (URL + "/", URL),  # the earlier identity kept the trailing slash
        ("https://www.research.example/report/1?utm_source=x", URL),
        (  # a post from the day before NOW, in two link forms
            "https://x.com/alice/status/2084429104542646272",
            "https://twitter.com/i/web/status/2084429104542646272",
        ),
    ],
)
def test_leads_retained_under_another_identity_keep_it(
    database, monkeypatch, state, stored_url, seen_url
):
    """A report recorded under another identity (earlier rule or another link form of
    the same source) is found when seen again: it neither reappears nor gets a new
    lifetime, and its original identity is kept."""
    monkeypatch.setenv(PUBLICATION_ENV, POLICY_ID)
    stored = candidate(url=stored_url)
    stored = {
        **stored,
        # An identity not derivable from the new rule (as records from the old rule are).
        "lead_id": sha256_id(canonical_json_bytes(["legacy", stored_url]))[7:],
    }
    with Session(database.engine) as session, session.begin():
        record_lead(
            session, stored, state=state, reason="withdrawn_or_corrected", now=NOW, publish=True
        )
    provider = LeadProvider(raw_lead(url=seen_url), (seen_url,))
    later = NOW + timedelta(hours=30)
    enqueue_search(database, later)
    assert work(database, provider, later).outcome == "succeeded"
    work(database, provider, later + timedelta(seconds=1))
    assert provider.qualification_calls == 0
    with Session(database.engine) as session:
        assert latest_lead(session, stored["lead_id"]).state == state
        assert session.scalar(select(func.count(func.distinct(EmergingLeadRecord.lead_id)))) == 1
        assert public_page(session, now=later)["leads"] == []


def test_retained_lead_lookup_folds_case_like_python_and_reads_every_page(database):
    """A sharp s subject and STRASSE fold equal in Python (not in SQL lower()), and a
    match beyond the first 500 candidates for the same source is still found."""
    from smithguard.emerging_leads import retained_lead_for

    with Session(database.engine) as session, session.begin():
        for index in range(505):
            filler = candidate(
                url=f"https://research.example/report/1?page={index}", subject=f"Filler {index}"
            )
            record_lead(
                session,
                {**filler, "lead_id": sha256_id(canonical_json_bytes(["filler", index]))[7:]},
                state="expired",
                reason="stale_report",
                now=NOW,
            )
        stored = candidate(url=URL + "/", subject="Stra\u00dfe tool")
        stored = {**stored, "lead_id": sha256_id(canonical_json_bytes(["legacy", 1]))[7:]}
        record_lead(
            session,
            stored,
            state="withdrawn",
            reason="withdrawn_or_corrected",
            now=NOW + timedelta(minutes=1),
        )
        # A record stored before URLs were canonicalized may keep the host's case.
        upper = candidate(url=URL, subject="Upper host tool")
        upper = {
            **upper,
            "sources": [{**upper["sources"][0], "url": "https://WWW.Research.Example/report/1"}],
            "lead_id": sha256_id(canonical_json_bytes(["legacy", 2]))[7:],
        }
        record_lead(session, upper, state="expired", reason="stale_report", now=NOW)
    with Session(database.engine) as session:
        assert session.scalar(select(func.count(func.distinct(EmergingLeadRecord.lead_id)))) > 500
        found = retained_lead_for(session, candidate(url=URL, subject="STRASSE TOOL"))
        assert found is not None and found.lead_id == stored["lead_id"]
        found = retained_lead_for(session, candidate(url=URL, subject="upper HOST tool"))
        assert found is not None and found.lead_id == upper["lead_id"]
        assert retained_lead_for(session, candidate(url=URL, subject="Other tool")) is None


def test_public_feed_is_newest_first_with_a_stable_cursor(database, monkeypatch):
    monkeypatch.setenv(PUBLICATION_ENV, POLICY_ID)
    ids = []
    with Session(database.engine) as session, session.begin():
        for index in range(3):
            lead = candidate(
                url=f"https://research.example/report/{index}", subject=f"Orion tool {index}"
            )
            ids.append(lead["lead_id"])
            record_lead(
                session,
                lead,
                state="unverified",
                reason="attributable_security_report",
                now=NOW + timedelta(minutes=index),
                publish=True,
            )
        first = public_page(session, now=NOW + timedelta(minutes=5), limit=2)
        assert [item["id"] for item in first["leads"]] == [ids[2], ids[1]]
        second = public_page(
            session, now=NOW + timedelta(minutes=5), limit=2, after=first["next_cursor"]
        )
        assert [item["id"] for item in second["leads"]] == [ids[0]]
        assert second["next_cursor"] is None
        # An unknown cursor ends the feed instead of failing.
        gone = public_page(session, now=NOW + timedelta(minutes=5), after="f" * 64)
        assert gone["leads"] == []
        # A cursor lead withdrawn between pages still marks where the next page starts.
        withdrawn = {**latest_lead(session, ids[1]).document}
        record_lead(
            session,
            {**withdrawn, "lead_id": ids[1]},
            state="withdrawn",
            reason="withdrawn_or_corrected",
            now=NOW + timedelta(minutes=6),
        )
        resumed = public_page(
            session, now=NOW + timedelta(minutes=7), limit=2, after=first["next_cursor"]
        )
        assert [item["id"] for item in resumed["leads"]] == [ids[0]]
