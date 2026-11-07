"""Maintained summary-profile proof uses local ASGI only, never live endpoints."""

import asyncio
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import httpx2
import pytest

from smithguard import summary_contract
from tests import test_hosted_mcp
from tests.test_service_api import NOW
from tools import verify_hosted_mcp as verifier

mcp_client = test_hosted_mcp.mcp_client


def test_summary_profile_uses_exact_one_tool_and_no_raw_fallback(mcp_client, tmp_path, monkeypatch):
    monkeypatch.setattr(verifier, "utc_now", lambda: NOW)
    report = {"checks": [], "status": "incomplete"}

    async def run():
        transport = httpx2.ASGITransport(app=mcp_client.app, client=("8.8.8.8", 50000))
        async with verifier.BoundedClient(tmp_path, summary=True, transport=transport) as client:
            await verifier.run_summary_suite(client, report)
            assert {row["url"] for row in client.requests} == {
                verifier.API + summary_contract.REST_PATH,
                verifier.API + summary_contract.MCP_PATH,
            }
            assert all(row["status"] == "received" for row in client.requests)
            client.bulletin_identity = "a" * 64
            for path in [
                "/mcp",
                "/v1/artifacts/assess",
                "/v1/coverage.json",
                "/v1/public-key.json",
                "/v1/bulletins/" + "a" * 64 + ".json",
            ]:
                with pytest.raises(verifier.Refusal, match="target_refused"):
                    await client.get(verifier.API + path)

    asyncio.run(run())
    assert report["status"] == "pass"
    assert report["checks"][-1]["client_signature_verified"] is False
    assert report["checks"][-1]["action_authorized"] is False


@pytest.mark.parametrize(
    "fault",
    ["raw_wrapper", "wrong_identity", "text_mismatch", "verification_claim", "unknown_field"],
)
def test_summary_verifier_refuses_unsafe_or_inconsistent_output(fault, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "integrations/t3/fixtures/summary.json"
    document = json.loads(path.read_text())
    monkeypatch.setattr(verifier, "utc_now", lambda: verifier.timestamp(document["generated_at"]))
    args = {
        key: document["artifact"][key] for key in ("ecosystem", "name", "version", "registry_host")
    }
    text = deepcopy(document)
    if fault == "raw_wrapper":
        document = {"data": document, "source_url": verifier.API + "/v1/artifacts/assess"}
    elif fault == "wrong_identity":
        args["version"] = "99.0.0"
    elif fault == "text_mismatch":
        text["result"] = "not_affected"
    elif fault == "verification_claim":
        document["client_signature_verified"] = True
    else:
        document["reasoning"] = "unapproved extra field"
    result = SimpleNamespace(
        is_error=False,
        structured_content=document,
        content=[SimpleNamespace(type="text", text=json.dumps(text))],
    )
    with pytest.raises(verifier.Refusal):
        verifier.validate_summary_result(result, args)
