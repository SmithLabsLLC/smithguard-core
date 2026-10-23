"""Real MCP protocol, existing REST behavior and bounded private-input rejection."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from copy import deepcopy

import httpx
import mcp_types as types
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator
from sqlalchemy.orm import sessionmaker

from smithguard import api, hosted_mcp
from smithguard.anonymous_quota import AnonymousQuotaStore
from smithguard.feeds import SnapshotSigner
from smithguard.identifiers import canonical_json_bytes
from tests.api_client import TestClient
from tests.test_service_api import NOW

HEADERS = {"Accept": "application/json, text/event-stream"}
COORDINATE = {"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"}


@pytest.fixture
def mcp_client(database):
    app = api.create_public_beta_app(
        session_factory=sessionmaker(database.engine),
        signer=SnapshotSigner.ephemeral(),
        base_url="https://api.smithguard.io",
        clock=lambda: NOW,
        anonymous_quota_store=AnonymousQuotaStore(),
        anonymous_quota_secret=b"synthetic-public-quota-secret!!!",
    )
    with TestClient(
        app, base_url="https://api.smithguard.io", client=("8.8.8.8", 50000), headers=HEADERS
    ) as client:
        yield client


def rpc(client, method, params=None, *, modern=False, headers=None):
    params = deepcopy(params or {})
    request_headers = dict(headers or {})
    if modern:
        params["_meta"] = {
            types.PROTOCOL_VERSION_META_KEY: "2026-07-28",
            types.CLIENT_CAPABILITIES_META_KEY: {},
            types.CLIENT_INFO_META_KEY: {"name": "synthetic-mcp-test", "version": "1"},
        }
        request_headers |= {"MCP-Protocol-Version": "2026-07-28", "MCP-Method": method}
        if method == "tools/call":
            request_headers["MCP-Name"] = params["name"]
    else:
        request_headers["MCP-Protocol-Version"] = "2025-11-25"
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        headers=request_headers,
    )


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_transport_method_rejections_are_not_cacheable(mcp_client, method):
    response = mcp_client.request(method, "/mcp")
    assert response.status_code == 405
    assert response.headers["cache-control"] == "no-store"


def test_malformed_transport_rejection_is_not_cacheable(mcp_client):
    response = mcp_client.post("/mcp", content=b"invalid json")
    assert response.status_code == 400
    assert response.headers["cache-control"] == "no-store"


def call(client, name, arguments=None, *, modern=False, headers=None):
    return rpc(
        client,
        "tools/call",
        {"name": name, "arguments": arguments or {}},
        modern=modern,
        headers=headers,
    )


@pytest.mark.parametrize("modern", [False, True])
def test_real_protocol_exposes_only_four_read_only_tools(mcp_client, modern):
    if not modern:
        response = rpc(
            mcp_client,
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "synthetic-mcp-test", "version": "1"},
            },
        )
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        result = response.json()["result"]
        assert result["protocolVersion"] == "2025-11-25"
        assert set(result["capabilities"]) <= {"tools", "experimental"}
        assert "tools" in result["capabilities"]
        assert not result["capabilities"].get("experimental")
        assert "mcp-session-id" not in response.headers
    response = rpc(mcp_client, "tools/list", modern=modern)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    tools = response.json()["result"]["tools"]
    assert {tool["name"] for tool in tools} == set(hosted_mcp.TOOL_PATHS)
    for tool in tools:
        assert tool["inputSchema"]["additionalProperties"] is False
        assert tool["annotations"]["readOnlyHint"] is True
        assert tool["annotations"]["destructiveHint"] is False
        assert tool["annotations"]["openWorldHint"] is True
        assert tool["securitySchemes"] == [{"type": "noauth"}]
        assert tool["_meta"]["securitySchemes"] == [{"type": "noauth"}]
        assert tool["outputSchema"]["additionalProperties"] is False
        assert "$ref" not in json.dumps(tool["inputSchema"])
    assessment = next(t for t in tools if t["name"] == "assess_public_artifact")
    generated = mcp_client.app.openapi()["components"]["schemas"]
    expected = deepcopy(generated["PublicArtifactAssessmentShortRequest"])
    expected["properties"]["digest"] = generated["Sha256"]
    assert assessment["inputSchema"] == expected


@pytest.mark.parametrize("modern", [False, True])
@pytest.mark.parametrize(
    "name,path,args",
    [
        ("assess_public_artifact", "/v1/artifacts/assess", COORDINATE),
        ("get_coverage", "/v1/coverage.json", {}),
        ("get_emerging_leads", "/v1/emerging-leads.json", {"limit": 1}),
        ("get_verification_key", "/v1/public-key.json", {}),
    ],
)
def test_mcp_returns_unchanged_full_public_rest_document(mcp_client, modern, name, path, args):
    rest = (
        mcp_client.post(path, json=args)
        if name == "assess_public_artifact"
        else mcp_client.get(path, params=args)
    )
    assert rest.status_code == 200, rest.text
    response = call(mcp_client, name, args, modern=modern)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    result = response.json()["result"]
    assert result["isError"] is False
    structured = result["structuredContent"]
    assert structured == {"data": rest.json(), "source_url": hosted_mcp.PUBLIC_SOURCE + path}
    assert json.loads(result["content"][0]["text"]) == structured
    tools = rpc(mcp_client, "tools/list", modern=modern).json()["result"]["tools"]
    output_schema = next(tool["outputSchema"] for tool in tools if tool["name"] == name)
    Draft202012Validator(output_schema).validate(structured)
    assert "mcp-session-id" not in response.headers


def test_mcp_assessment_signature_still_verifies(mcp_client):
    response = call(mcp_client, "assess_public_artifact", COORDINATE, modern=True)
    result = response.json()["result"]["structuredContent"]["data"]
    signature = result.pop("signature")
    key = call(mcp_client, "get_verification_key", {"public_key_id": signature["public_key_id"]})
    public = key.json()["result"]["structuredContent"]["data"]
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public["public_key_base64"])).verify(
        base64.b64decode(signature["value"]),
        canonical_json_bytes(result),
    )


@pytest.mark.parametrize(
    "name,args",
    [
        ("assess_public_artifact", {**COORDINATE, "version": "^3.3.6"}),
        (
            "assess_public_artifact",
            {"ecosystem": "oci", "name": "example", "digest": "sha256:" + "a" * 64},
        ),
        ("get_verification_key", {"public_key_id": "gbsec:snapshot-public-key:" + "a" * 40}),
    ],
)
def test_authoritative_api_validation_and_missing_key_are_tool_errors(mcp_client, name, args):
    response = call(mcp_client, name, args, modern=True)
    assert response.status_code == 200, response.text
    result = response.json()["result"]
    assert result["isError"] is True
    assert "error" in result["structuredContent"]["data"]


@pytest.mark.parametrize(
    "name,args",
    [
        ("fetch_url", {"url": "https://example.org/synthetic-private-content"}),
        ("assess_public_artifact", {**COORDINATE, "source": "synthetic-private-content"}),
        ("assess_public_artifact", {**COORDINATE, "lockfile": "synthetic-private-content"}),
        ("assess_public_artifact", {**COORDINATE, "digest": "synthetic-private-content"}),
        ("get_coverage", {"token": "synthetic-private-content"}),
        ("get_emerging_leads", {"limit": True}),
        ("get_emerging_leads", {"limit": 101}),
        ("get_emerging_leads", {"after": "a" * 64 + "\n"}),
        ("get_verification_key", {"public_key_id": "../../synthetic-private-content"}),
        ("get_verification_key", {"public_key_id": "gbsec:snapshot-public-key:" + "a" * 40 + "\n"}),
    ],
)
def test_unrecognized_tools_and_private_extra_inputs_never_reach_api(
    mcp_client, monkeypatch, caplog, name, args
):
    async def forbidden(*_args, **_kwargs):
        pytest.fail("invalid tool request reached the API")

    monkeypatch.setattr(httpx.ASGITransport, "handle_async_request", forbidden)
    response = call(mcp_client, name, args, modern=True)
    assert response.status_code == 400
    assert response.json()["id"] is None
    assert "synthetic-private-content" not in response.text + caplog.text


@pytest.mark.parametrize(
    "body",
    [
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"synthetic-private-content"}',
        b'[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"private":"synthetic-private-content"}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"x":'
        + b"[" * 15
        + b"0"
        + b"]" * 15
        + b"}}}",
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"x":NaN}}}',
    ],
)
def test_malformed_duplicate_batch_and_deep_requests_are_fixed_safe_errors(
    mcp_client, caplog, body
):
    response = mcp_client.post("/mcp", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert "synthetic-private-content" not in response.text + caplog.text


def test_oversized_request_is_rejected_before_protocol(mcp_client):
    response = mcp_client.post(
        "/mcp",
        content=b"x" * (hosted_mcp.MCP_MAX_REQUEST_BYTES + 1),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


@pytest.mark.parametrize(
    "origin", ["null", "https://evil.example/synthetic-private-content", "http://api.smithguard.io"]
)
def test_foreign_origin_is_rejected_without_logging_values(mcp_client, caplog, origin):
    response = rpc(mcp_client, "tools/list", headers={"Origin": origin})
    assert response.status_code == 403
    assert json.dumps(origin) not in response.text + caplog.text


def test_host_origin_methods_and_exact_route_boundary(mcp_client, caplog):
    assert (
        rpc(mcp_client, "tools/list", headers={"Origin": "https://api.smithguard.io"}).status_code
        == 200
    )
    response = rpc(mcp_client, "tools/list", headers={"Host": "synthetic-private-content.invalid"})
    assert response.status_code in {400, 421}
    assert "synthetic-private-content" not in response.text + caplog.text
    for method in ("GET", "DELETE", "HEAD", "PUT", "OPTIONS"):
        assert mcp_client.request(method, "/mcp").status_code == 405
    assert mcp_client.post("/mcp/", json={}).status_code == 404
    assert not mcp_client.get("/mcp").headers.get("access-control-allow-origin")


def test_mcp_never_uses_outbound_http_or_arbitrary_fetch(mcp_client, monkeypatch):
    async def forbidden(*_args, **_kwargs):
        pytest.fail("MCP tried outbound HTTP")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)
    for name in ("get_coverage", "get_emerging_leads", "get_verification_key"):
        assert call(mcp_client, name, modern=True).json()["result"]["isError"] is False


def test_mcp_quota_uses_actual_client_and_ignores_untrusted_xff(mcp_client, monkeypatch):
    import smithguard.anonymous_quota as quota

    monkeypatch.setattr(quota, "BURST_LIMIT", 1)
    first = call(
        mcp_client, "assess_public_artifact", COORDINATE, headers={"X-Forwarded-For": "1.1.1.1"}
    )
    assert first.json()["result"]["isError"] is False
    second = call(
        mcp_client,
        "assess_public_artifact",
        {**COORDINATE, "name": "other-public-package"},
        headers={"X-Forwarded-For": "9.9.9.9"},
    )
    result = second.json()["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["data"]["error"]["code"] == "anonymous_burst_limit_exceeded"
    assert int(result["structuredContent"]["retry_after"]) > 0


def test_mcp_preserves_existing_trusted_proxy_identity(database, monkeypatch):
    import smithguard.anonymous_quota as quota

    monkeypatch.setattr(quota, "BURST_LIMIT", 1)
    app = api.create_public_beta_app(
        session_factory=sessionmaker(database.engine),
        signer=SnapshotSigner.ephemeral(),
        base_url="https://api.smithguard.io",
        clock=lambda: NOW,
        anonymous_quota_store=AnonymousQuotaStore(),
        anonymous_quota_secret=b"synthetic-public-quota-secret!!!",
        trusted_proxy_header=True,
    )
    with TestClient(app, base_url="https://api.smithguard.io", headers=HEADERS) as client:
        assert (
            call(
                client, "assess_public_artifact", COORDINATE, headers={"X-Forwarded-For": "8.8.8.8"}
            ).json()["result"]["isError"]
            is False
        )
        rejected = call(
            client,
            "assess_public_artifact",
            {**COORDINATE, "name": "other-package"},
            headers={"X-Forwarded-For": "8.8.8.8"},
        )
        assert rejected.json()["result"]["isError"] is True
        allowed = call(
            client,
            "assess_public_artifact",
            {**COORDINATE, "name": "different-package"},
            headers={"X-Forwarded-For": "1.1.1.1"},
        )
        assert allowed.json()["result"]["isError"] is False
        invalid = call(
            client,
            "assess_public_artifact",
            {**COORDINATE, "name": "invalid-proxy-package"},
            headers={"X-Forwarded-For": "8.8.8.8, 1.1.1.1"},
        )
        assert (
            invalid.json()["result"]["structuredContent"]["data"]["error"]["code"]
            == "proxy_network_identity_invalid"
        )


def test_unexpected_internal_transport_failure_cannot_echo_arguments(
    mcp_client, monkeypatch, caplog
):
    async def broken(*_args, **_kwargs):
        raise RuntimeError("synthetic-private-content")

    monkeypatch.setattr(httpx.ASGITransport, "handle_async_request", broken)
    response = call(mcp_client, "get_coverage", modern=True)
    result = response.json()["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["data"]["error"]["code"] == "tool_unavailable"
    assert "synthetic-private-content" not in response.text + caplog.text


def test_tool_output_has_a_finite_byte_bound(mcp_client, monkeypatch):
    from smithguard.service import SmithGuardService

    monkeypatch.setattr(
        SmithGuardService,
        "get_source_coverage",
        lambda *_args: {"public": "x" * (hosted_mcp.MCP_MAX_DOCUMENT_BYTES + 1)},
    )
    response = call(mcp_client, "get_coverage", modern=True)
    result = response.json()["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["data"]["error"]["code"] == "tool_response_limit_exceeded"
    assert len(response.content) < 2048


def test_mcp_deadline_cancels_its_in_process_call(mcp_client, monkeypatch):
    stopped = []

    async def slow(*_args, **_kwargs):
        try:
            await asyncio.sleep(10)
        finally:
            stopped.append(True)

    monkeypatch.setattr(httpx.AsyncClient, "get", slow)
    monkeypatch.setattr(hosted_mcp, "MCP_TIMEOUT_SECONDS", 0.05)
    response = call(mcp_client, "get_coverage", modern=True)
    assert response.status_code == 503 and stopped == [True]
    assert response.json()["error"]["message"] == "Hosted tool service unavailable"


def test_mcp_capacity_is_bounded_and_does_not_retain_sessions(mcp_client):
    endpoint = next(route.endpoint for route in mcp_client.app.routes if route.path == "/mcp")

    async def occupy():
        for _ in range(hosted_mcp.MCP_CONCURRENCY):
            await endpoint.slots.acquire()

    mcp_client.portal.call(occupy)
    try:
        assert rpc(mcp_client, "tools/list", modern=True).status_code == 503
    finally:
        for _ in range(hosted_mcp.MCP_CONCURRENCY):
            mcp_client.portal.call(endpoint.slots.release)
    assert rpc(mcp_client, "tools/list", modern=True).status_code == 200
    manager = endpoint.server.session_manager
    assert manager.stateless and manager.event_store is None
    assert not manager._server_instances and not manager._session_owners


@pytest.mark.parametrize(
    "headers",
    [
        {"MCP-Session-Id": "synthetic-private-content"},
        {"Last-Event-ID": "synthetic-private-content"},
        {"MCP-Protocol-Version": "synthetic-private-content"},
        {"MCP-Param-url": "synthetic-private-content"},
    ],
)
def test_unknown_session_event_and_routing_headers_are_safe_rejections(mcp_client, caplog, headers):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    response = mcp_client.post("/mcp", json=body, headers=headers)
    assert response.status_code == 400
    assert "synthetic-private-content" not in response.text + caplog.text


def test_sdk_logs_cannot_retain_opaque_ids_client_metadata_or_exception_text(
    mcp_client, caplog, monkeypatch
):
    caplog.set_level(logging.DEBUG, logger="mcp")
    initialized = rpc(
        mcp_client,
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "synthetic-private-content", "version": "1"},
        },
    )
    assert initialized.status_code == 200
    assert "synthetic-private-content" not in initialized.text
    body = {
        "jsonrpc": "2.0",
        "id": "synthetic-private-content",
        "method": "tools/list",
        "params": {"_meta": {types.CLIENT_INFO_META_KEY: "synthetic-private-content"}},
    }
    response = mcp_client.post("/mcp", json=body)
    assert response.status_code == 400 and response.json()["id"] is None
    # Exercise the pinned SDK's possible closed-stream/error record shape directly.
    logger = logging.getLogger("mcp.shared.jsonrpc_dispatcher")
    monkeypatch.setattr(logger, "disabled", False)
    caplog.set_level(logging.DEBUG, logger=logger.name)
    try:
        raise RuntimeError("synthetic-private-content")
    except RuntimeError:
        logger.exception("rejected request %r", "synthetic-private-content")
    assert "synthetic-private-content" not in response.text + caplog.text
    records = [record for record in caplog.records if record.name.startswith("mcp.")]
    assert records and all(record.getMessage() == "MCP transport event" for record in records)
    assert all(record.exc_info is None and record.stack_info is None for record in records)
