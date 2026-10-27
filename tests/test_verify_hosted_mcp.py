"""Offline official-client smoke proof and verifier refusal boundaries."""

import asyncio
import json
from copy import deepcopy
from types import SimpleNamespace

import httpx2
import pytest
from cryptography.exceptions import InvalidSignature
from sqlalchemy.orm import Session

from smithguard import bulletin_store
from smithguard.feeds import SnapshotSigner
from tests import test_hosted_mcp
from tests.test_bulletins import GRANT, REGISTRY, content
from tests.test_service_api import NOW
from tools import verify_hosted_mcp as verifier

mcp_client = test_hosted_mcp.mcp_client


def assessment_result(value):
    if "signature" not in value:
        value["signature"] = SnapshotSigner.ephemeral().signature_for(value)
    structured = {
        "source_url": verifier.API + verifier.PATHS["assess_public_artifact"],
        "data": value,
    }
    return SimpleNamespace(
        is_error=False,
        structured_content=structured,
        content=[SimpleNamespace(type="text", text=json.dumps(structured))],
    )


@pytest.mark.parametrize("schema", ["2.1.0", "2.2.0", "2.3.0", "2.4.0"])
def test_assessment_verifier_accepts_only_reviewed_versions(contract_examples, schema):
    value = deepcopy(
        next(
            example["value"]
            for example in contract_examples
            if example["definition"] == "PublicArtifactAssessment"
        )
    )
    value["schema_version"] = schema
    value.pop("cve_context", None)
    if schema in {"2.2.0", "2.3.0", "2.4.0"}:
        value["cve_context"] = []
    if schema in {"2.3.0", "2.4.0"}:
        value["registry_project_context"] = None
    if schema == "2.4.0":
        value.update(
            reason_codes=["identity_unverified", "results_incomplete"],
            identity_assurance="caller_asserted",
            local_applicability="not_evaluated",
        )
        for incident in value["incidents"]:
            incident.update(
                source_fixed_versions=[],
                fix_evidence_incomplete=True,
                local_applicability="not_evaluated",
            )
            for report in incident["source_reports"]:
                report.update(
                    source_fixed_versions=[],
                    fix_evidence_incomplete=True,
                    local_applicability="not_evaluated",
                    fix_evidence=[],
                    range_bound_evidence=[],
                    historical_metadata_incomplete=False,
                    source_context=None,
                    source_context_state="unavailable",
                )
    args = {key: value["artifact"][key] for key in ("ecosystem", "name", "version")}
    assert (
        verifier.validate_result("assess_public_artifact", assessment_result(value), args) == value
    )


@pytest.mark.parametrize("context", [None, {}, [{}], [{}] * 2001])
def test_v22_context_must_be_bounded_and_match_the_frozen_contract(contract_examples, context):
    value = deepcopy(
        next(
            example["value"]
            for example in contract_examples
            if example["definition"] == "PublicArtifactAssessment"
        )
    )
    value.update(schema_version="2.2.0", cve_context=context)
    with pytest.raises(verifier.Refusal, match="assessment_(cve_context|contract)_invalid"):
        verifier.validate_result("assess_public_artifact", assessment_result(value), {})


@pytest.mark.parametrize("fault", ["missing_context", "unknown_version"])
def test_unknown_assessment_version_or_missing_v22_context_is_refused(contract_examples, fault):
    value = deepcopy(
        next(
            example["value"]
            for example in contract_examples
            if example["definition"] == "PublicArtifactAssessment"
        )
    )
    value["schema_version"] = "2.5.0" if fault == "unknown_version" else "2.2.0"
    value.pop("cve_context", None)
    with pytest.raises(verifier.Refusal, match="assessment_(cve_context_invalid|contract_changed)"):
        verifier.validate_result("assess_public_artifact", assessment_result(value), {})


def test_official_client_completes_initialize_list_and_fixed_suite_offline(
    mcp_client, database, tmp_path, monkeypatch
):
    monkeypatch.setattr(verifier, "utc_now", lambda: NOW)
    with Session(database.engine) as session, session.begin():
        document = content()
        document["source_published_at"] = "2026-08-05T10:00:00Z"
        bulletin_store.publish(
            session,
            document,
            registry=REGISTRY,
            grant={
                **GRANT,
                "effective_at": "2026-08-01T00:00:00Z",
                "review_due_at": "2026-08-10T00:00:00Z",
            },
            now=NOW,
            manual_approval="1" * 64,
        )
        bulletin_store.status_tick(session, now=NOW)
    report = {"checks": [], "status": "incomplete"}

    async def run():
        transport = httpx2.ASGITransport(app=mcp_client.app, client=("8.8.8.8", 50000))
        async with verifier.BoundedClient(tmp_path, transport=transport) as client:
            await verifier.run_suite(client, report)
            assert len(client.requests) == 28
            assert all(row["status"] == "received" for row in client.requests)

    asyncio.run(run())
    assert report["status"] == "pass"
    assert len(report["checks"]) == 19
    assert {row["tool"] for row in report["checks"] if "tool" in row} == verifier.EXPECTED_TOOLS
    assert not list(tmp_path.glob("*.response.json"))
    assert "Synthetic notice" not in "".join(path.read_text() for path in tmp_path.iterdir())
    signed_checks = [row for row in report["checks"] if row.get("signature_verified")]
    assert len(signed_checks) == 2
    assert {row["name"] for row in signed_checks} == {"django", "is-number"}


@pytest.mark.parametrize("fault", ["redirect", "session", "oversize", "sse"])
def test_wire_boundaries_refuse_before_sdk_can_retry_or_retain_state(tmp_path, monkeypatch, fault):
    calls = []
    monkeypatch.setattr(verifier, "MAX_RESPONSE", 64)

    def serve(request):
        calls.append(request)
        if fault == "redirect":
            return httpx2.Response(307, headers={"Location": verifier.TARGET})
        if fault == "session":
            return httpx2.Response(200, headers={"mcp-session-id": "synthetic-session"}, json={})
        if fault == "sse":
            return httpx2.Response(
                200, headers={"Content-Type": "text/event-stream"}, text="data: {}"
            )
        return httpx2.Response(200, content=b"x" * 65)

    async def run():
        async with verifier.BoundedClient(
            tmp_path, transport=httpx2.MockTransport(serve)
        ) as client:
            with pytest.raises(verifier.Refusal):
                await client.get(verifier.API + "/v1/public-key.json")
            with pytest.raises(verifier.Refusal, match="request_replay_refused"):
                await client.get(verifier.API + "/v1/public-key.json")
            assert len(client.requests) == 1
            assert client.requests[0]["status"] == "failed"

    asyncio.run(run())
    assert len(calls) == 1
    assert not list(tmp_path.glob("*.response.json"))


def test_unknown_target_and_request_budget_refuse_without_network(tmp_path, monkeypatch):
    calls = []

    def serve(request):
        calls.append(request)
        return httpx2.Response(200, json={})

    async def run():
        async with verifier.BoundedClient(
            tmp_path, transport=httpx2.MockTransport(serve)
        ) as client:
            with pytest.raises(verifier.Refusal, match="target_refused"):
                await client.get("https://elsewhere.example/mcp")
            monkeypatch.setattr(verifier, "MAX_REQUESTS", 0)
            with pytest.raises(verifier.Refusal, match="request_budget_exceeded"):
                await client.get(verifier.API + "/v1/public-key.json")

    asyncio.run(run())
    assert not calls and not list(tmp_path.iterdir())


def test_parity_never_ignores_signature_or_evidence_changes(monkeypatch):
    signer = SnapshotSigner.ephemeral()
    body = {"artifact": {"version": "1.0.0"}}
    body["signature"] = signer.signature_for(body)
    key = signer.public_key_document()
    verifier.verify_signature(body, key)
    changed = deepcopy(body)
    changed["signature"]["value"] = "invalid"
    with pytest.raises(verifier.Refusal, match="rest_parity_failed"):
        verifier.compare_documents("assess_public_artifact", body, changed)
    changed = deepcopy(body)
    changed["artifact"]["version"] = "2.2.17"
    with pytest.raises(verifier.Refusal, match="rest_parity_failed"):
        verifier.compare_documents("assess_public_artifact", body, changed)
    monkeypatch.setattr(verifier, "utc_now", lambda: NOW)
    with pytest.raises(verifier.Refusal, match="request_timestamp_difference_exceeded"):
        verifier.compare_documents(
            "get_coverage",
            {"measured_at": "2026-08-05T12:00:00Z"},
            {"measured_at": "2026-08-05T12:01:00Z"},
        )


def test_main_never_reuses_output_or_writes_tracked_output(tmp_path, monkeypatch):
    import sys

    root = tmp_path / "repo"
    local = root / "local"
    local.mkdir(parents=True)
    consumed = local / "consumed"
    consumed.mkdir()
    monkeypatch.setattr(verifier, "ROOT", root)
    for output in (consumed, root / "tracked"):
        monkeypatch.setattr(sys, "argv", ["verify", "--output", str(output)])
        with pytest.raises(verifier.Refusal):
            verifier.main()
    assert consumed.exists() and not (root / "tracked").exists()


def test_matching_tampered_signatures_cannot_pass_even_when_rest_parity_holds(
    mcp_client, tmp_path, monkeypatch
):
    monkeypatch.setattr(verifier, "utc_now", lambda: NOW)
    report = {"checks": [], "status": "incomplete"}

    async def run():
        backend = httpx2.ASGITransport(app=mcp_client.app, client=("8.8.8.8", 50000))

        async def serve(request):
            response = await backend.handle_async_request(request)
            raw = await response.aread()
            await response.aclose()
            document = json.loads(raw) if raw else None
            if isinstance(document, dict) and "signature" in document:
                document["signature"]["value"] = "A" * 86 + "=="
            elif isinstance(document, dict) and "result" in document:
                result = document["result"]
                data = result.get("structuredContent", {}).get("data", {})
                if "signature" in data:
                    data["signature"]["value"] = "A" * 86 + "=="
                    result["content"][0]["text"] = json.dumps(result["structuredContent"])
            headers = {"Content-Type": "application/json"} if raw else {}
            if "cache-control" in response.headers:
                headers["cache-control"] = response.headers["cache-control"]
            return (
                httpx2.Response(response.status_code, json=document, headers=headers)
                if raw
                else httpx2.Response(response.status_code, headers=headers)
            )

        async with verifier.BoundedClient(
            tmp_path, transport=httpx2.MockTransport(serve)
        ) as client:
            await verifier.run_suite(client, report)

    def signature_failure(error):
        if isinstance(error, BaseExceptionGroup):
            return any(signature_failure(child) for child in error.exceptions)
        return isinstance(error, InvalidSignature)

    with pytest.raises(Exception) as failed:
        asyncio.run(run())
    assert signature_failure(failed.value)
    assert report["status"] == "incomplete"
    assert not any(row.get("signature_verified") for row in report["checks"])


def test_failed_smoke_is_recorded_without_exception_content(tmp_path, monkeypatch, capsys):
    import sys

    root = tmp_path / "repo"
    local = root / "local"
    local.mkdir(parents=True)
    output = local / "new-smoke"
    monkeypatch.setattr(verifier, "ROOT", root)
    monkeypatch.setattr(sys, "argv", ["verify", "--output", str(output)])

    async def fail(_client, _report):
        raise RuntimeError("synthetic-untrusted-diagnostic")

    monkeypatch.setattr(verifier, "run_suite", fail)
    assert verifier.main() == 1
    report = json.loads((output / "report.json").read_text())
    assert report["status"] == "unavailable" and report["error_type"] == "RuntimeError"
    assert report["started_at"] and report["completed_at"] and report["target"] == verifier.TARGET
    assert "synthetic-untrusted-diagnostic" not in json.dumps(report) + capsys.readouterr().out


def test_task_group_keeps_only_safe_failure_metadata():
    error = ExceptionGroup(
        "untrusted-outer", [RuntimeError("untrusted-body"), verifier.Refusal("rest_parity_failed")]
    )
    assert verifier.failure_metadata(error) == {
        "failure_types": ["ExceptionGroup", "Refusal", "RuntimeError"],
        "failure_reasons": ["rest_parity_failed"],
    }


def test_bulletin_parity_checks_decoded_cursor_and_all_other_fields(monkeypatch):
    monkeypatch.setattr(verifier, "utc_now", lambda: NOW)
    cursor = {
        "v": 1,
        "kind": "events",
        "filters": {},
        "after": 1,
        "upper": 1,
        "issued": "2026-08-05T12:00:00Z",
    }
    first = {"items": [], "next_cursor": bulletin_store.encode_cursor(cursor), "watermark": 1}
    second = {
        **first,
        "next_cursor": bulletin_store.encode_cursor({**cursor, "issued": "2026-08-05T11:59:59Z"}),
    }
    assert (
        verifier.compare_documents("get_bulletin_changes", first, second)
        == "request_timestamp_only"
    )
    for change in ({"upper": 2}, {"after": 0}, {"filters": {"identity": "a" * 64}}):
        altered = {**first, "next_cursor": bulletin_store.encode_cursor({**cursor, **change})}
        with pytest.raises(verifier.Refusal, match="rest_parity_failed"):
            verifier.compare_documents("get_bulletin_changes", first, altered)
    with pytest.raises(verifier.Refusal, match="rest_parity_failed"):
        verifier.compare_documents("get_bulletin_changes", first, {**first, "watermark": 2})
