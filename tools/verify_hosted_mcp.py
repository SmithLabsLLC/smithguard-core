"""Internal fixed public MCP smoke checks; no provider dispatch or client installation."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import time
from copy import deepcopy
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

import httpx2
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from smithguard.contracts.runtime import parse_contract
from tools.verification import canonical, exclusive_json, timestamp, verify_signature

ROOT = Path(__file__).resolve().parents[1]
API = "https://api.smithguard.io"
TARGET = API + "/mcp"
PATHS = {
    "assess_public_artifact": "/v1/artifacts/assess",
    "get_coverage": "/v1/coverage.json",
    "get_emerging_leads": "/v1/emerging-leads.json",
    "get_verification_key": "/v1/public-key.json",
}
EXPECTED_TOOLS = set(PATHS) | {
    "list_bulletins",
    "get_bulletin",
    "get_bulletin_changes",
    "get_bulletin_status",
}
CASES = (
    ("key", "get_verification_key", {}),
    (
        "django",
        "assess_public_artifact",
        {"ecosystem": "pypi", "name": "Django", "version": "2.2.17"},
    ),
    (
        "is-number",
        "assess_public_artifact",
        {"ecosystem": "npm", "name": "is-number", "version": "7.0.0"},
    ),
    ("coverage", "get_coverage", {}),
    ("leads", "get_emerging_leads", {"limit": 5}),
)
MAX_RESPONSE = 2_200_000
MAX_DOCUMENT = 1_048_576
MAX_REQUESTS = 20
REQUEST_SECONDS = 20
TOTAL_SECONDS = 180


class Refusal(ValueError):
    """Fixed safe failure reason; never arbitrary response or exception text."""


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def utc_now():
    return datetime.now(UTC)


class BoundedClient(httpx2.AsyncClient):
    """Bound the official SDK's actual wire reads and forbid redirects or replay."""

    def __init__(self, output, **kwargs):
        super().__init__(timeout=REQUEST_SECONDS, trust_env=False, follow_redirects=False, **kwargs)
        self.output = output
        self.started = time.monotonic()
        self.requests = []
        self.seen = set()

    async def send(self, request, **kwargs):
        allowed = {
            TARGET,
            *(API + path for path in PATHS.values()),
            API + PATHS["get_emerging_leads"] + "?limit=5",
        }
        require(str(request.url) in allowed, "target_refused")
        require(request.method in {"GET", "POST"}, "method_refused")
        require(
            not any(k in request.headers for k in ("authorization", "cookie")),
            "authentication_refused",
        )
        require(len(self.requests) < MAX_REQUESTS, "request_budget_exceeded")
        require(time.monotonic() - self.started < TOTAL_SECONDS, "elapsed_budget_exceeded")
        body = await request.aread()
        require(len(body) <= 16_384, "request_size_exceeded")
        identity = hashlib.sha256(
            request.method.encode() + str(request.url).encode() + body
        ).hexdigest()
        require(identity not in self.seen, "request_replay_refused")
        self.seen.add(identity)
        row = {
            "number": len(self.requests) + 1,
            "method": request.method,
            "url": str(request.url),
            "started_at": utc_now().isoformat(),
        }
        self.requests.append(row)
        exclusive_json(self.output / f"request-{row['number']:02d}.intent.json", row)
        response = None
        raw = bytearray()
        try:
            async with asyncio.timeout(REQUEST_SECONDS):
                response = await super().send(request, stream=True, follow_redirects=False)
                row["http_status"] = response.status_code
                require(not 300 <= response.status_code < 400, "redirect_refused")
                require("mcp-session-id" not in response.headers, "stateful_session_refused")
                require("set-cookie" not in response.headers, "cookie_response_refused")
                async for chunk in response.aiter_bytes():
                    require(len(raw) + len(chunk) <= MAX_RESPONSE, "response_size_exceeded")
                    raw.extend(chunk)
            require(
                not raw
                or response.headers.get("content-type", "").split(";", 1)[0] == "application/json",
                "response_type_invalid",
            )
            row["response_bytes"] = len(raw)
            row["response_sha256"] = hashlib.sha256(raw).hexdigest()
            if raw:
                document = json.loads(raw)
                require(isinstance(document, dict), "response_shape_invalid")
                exclusive_json(self.output / f"request-{row['number']:02d}.response.json", document)
            row["status"] = "received"
            # aiter_bytes decoded content already; prevent a second gzip decoding by the SDK.
            headers = {
                k: v
                for k, v in response.headers.items()
                if k not in {"content-encoding", "content-length"}
            }
            return httpx2.Response(
                response.status_code, headers=headers, content=bytes(raw), request=request
            )
        except BaseException as error:
            row.update(status="failed", error_type=type(error).__name__)
            if isinstance(error, Refusal):
                row["reason"] = str(error)
            raise
        finally:
            if response is not None:
                await response.aclose()
            row["completed_at"] = utc_now().isoformat()
            exclusive_json(self.output / f"request-{row['number']:02d}.result.json", row)


def validate_tools(tools, *, wire=False):
    require(
        len(tools) == len(EXPECTED_TOOLS) and {tool["name"] for tool in tools} == EXPECTED_TOOLS,
        "tool_set_changed",
    )
    for tool in tools:
        annotations = tool.get("annotations", {})
        require(
            all(
                annotations.get(k) is v
                for k, v in {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": True,
                }.items()
            ),
            "tool_annotations_changed",
        )
        require(
            tool.get("_meta", {}).get("securitySchemes") == [{"type": "noauth"}],
            "tool_auth_changed",
        )
        if wire:
            require(tool.get("securitySchemes") == [{"type": "noauth"}], "wire_auth_changed")
        require(
            tool["inputSchema"].get("additionalProperties") is False
            and "$ref" not in json.dumps(tool["inputSchema"]),
            "tool_input_unbounded",
        )
        require(tool["outputSchema"].get("additionalProperties") is False, "tool_output_unbounded")
    leads = next(tool for tool in tools if tool["name"] == "get_emerging_leads")
    require(leads["inputSchema"]["properties"]["limit"]["maximum"] == 100, "lead_limit_changed")


def compare_documents(name, rest, mcp):
    """Compare full signed answers; only unsigned request-time fields may vary."""
    fields = {"get_coverage": ("measured_at",), "get_emerging_leads": ("as_of",)}.get(name, ())
    first, second = deepcopy(rest), deepcopy(mcp)
    for field in fields:
        a, b = timestamp(first[field]), timestamp(second[field])
        require(abs((a - b).total_seconds()) <= 30, "request_timestamp_difference_exceeded")
        require(
            all(0 <= (utc_now() - observed).total_seconds() <= 660 for observed in (a, b)),
            "request_timestamp_stale",
        )
        first.pop(field)
        second.pop(field)
    require(first == second, "rest_parity_failed")
    return "exact" if rest == mcp else "request_timestamp_only"


def validate_result(name, result, args):
    require(result.is_error is False, "positive_tool_error")
    structured = result.structured_content
    require(
        isinstance(structured, dict) and set(structured) == {"data", "source_url"},
        "tool_result_shape_invalid",
    )
    require(structured["source_url"] == API + PATHS[name], "source_attribution_changed")
    require(
        len(result.content) == 1 and result.content[0].type == "text", "tool_content_shape_invalid"
    )
    require(json.loads(result.content[0].text) == structured, "tool_text_parity_failed")
    data = structured["data"]
    require(isinstance(data, dict) and len(canonical(data)) <= MAX_DOCUMENT, "tool_document_limit")
    if name == "assess_public_artifact":
        require(
            data.get("kind") == "public_artifact_assessment"
            and data.get("schema_version") in {"2.1.0", "2.2.0", "2.3.0", "2.4.0"},
            "assessment_contract_changed",
        )
        require(
            all(data.get("artifact", {}).get(k) == v for k, v in args.items()),
            "wrong_exact_artifact",
        )
        require(
            isinstance(data.get("incidents"), list) and "signature" in data,
            "assessment_unsigned_or_invalid",
        )
        if data["schema_version"] in {"2.2.0", "2.3.0", "2.4.0"}:
            require(
                isinstance(data.get("cve_context"), list) and len(data["cve_context"]) <= 2000,
                "assessment_cve_context_invalid",
            )
        try:
            parse_contract("PublicArtifactAssessment", data)
        except ValueError:
            raise Refusal("assessment_contract_invalid") from None
    if name == "get_emerging_leads":
        require(
            data.get("status") == "publication_disabled" and data.get("leads") == [],
            "publication_not_disabled",
        )
    return data


async def run_suite(client, report):
    checks = report["checks"]
    async with asyncio.timeout(TOTAL_SECONDS):
        async with Client(
            streamable_http_client(TARGET, http_client=client, terminate_on_close=False),
            mode="legacy",
            cache=None,
            read_timeout_seconds=REQUEST_SECONDS,
            input_required_max_rounds=0,
        ) as session:
            require(session.protocol_version == "2025-11-25", "protocol_version_changed")
            capabilities = session.server_capabilities.model_dump(by_alias=True, exclude_none=True)
            require(
                "tools" in capabilities
                and set(capabilities) <= {"tools", "experimental"}
                and not capabilities.get("experimental"),
                "server_capabilities_changed",
            )
            checks.append(
                {
                    "name": "official_sdk_initialize",
                    "status": "pass",
                    "protocol_version": session.protocol_version,
                }
            )
            listed = await session.list_tools()
            tools = [tool.model_dump(by_alias=True, exclude_none=True) for tool in listed.tools]
            validate_tools(tools)
            require(listed.next_cursor is None, "tool_pagination_changed")
            checks.append({"name": "official_sdk_four_tools", "status": "pass"})
            key = None
            for case, name, args in CASES:
                path = API + PATHS[name]
                response = await (
                    client.post(path, json=args)
                    if name == "assess_public_artifact"
                    else client.get(path, params=args)
                )
                require(response.status_code == 200, "rest_endpoint_unavailable")
                rest = response.json()
                result = await session.call_tool(name, args)
                data = validate_result(name, result, args)
                parity = compare_documents(name, rest, data)
                row = {
                    "name": case,
                    "tool": name,
                    "status": "pass",
                    "parity": parity,
                    "rest_sha256": hashlib.sha256(canonical(rest)).hexdigest(),
                    "mcp_sha256": hashlib.sha256(canonical(data)).hexdigest(),
                }
                if name == "get_verification_key":
                    key = data
                if name == "assess_public_artifact":
                    verify_signature(rest, key)
                    verify_signature(data, key)
                    row.update(signature_verified=True, result=data["result"])
                checks.append(row)

        headers = {
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
        }
        response = await client.post(
            TARGET,
            json={"jsonrpc": "2.0", "id": 101, "method": "tools/list", "params": {}},
            headers=headers,
        )
        require(response.status_code == 200, "wire_tools_unavailable")
        require(response.headers.get("cache-control") == "no-store", "wire_cache_policy")
        validate_tools(response.json()["result"]["tools"], wire=True)
        checks.append({"name": "wire_noauth_descriptors", "status": "pass"})
        negatives = (
            (
                "synthetic_source_argument",
                "assess_public_artifact",
                {"ecosystem": "npm", "name": "is-number", "version": "7.0.0", "source": ""},
            ),
            (
                "missing_exact_version",
                "assess_public_artifact",
                {"ecosystem": "npm", "name": "is-number"},
            ),
            ("unknown_tool", "unsupported_synthetic_tool", {}),
            ("lead_limit_exceeded", "get_emerging_leads", {"limit": 101}),
        )
        for index, (case, name, args) in enumerate(negatives, 201):
            response = await client.post(
                TARGET,
                json={
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": args},
                },
                headers=headers,
            )
            error = response.json()
            if case == "missing_exact_version":
                result = error.get("result", {})
                require(
                    response.status_code == 200
                    and result.get("isError") is True
                    and result.get("structuredContent", {})
                    .get("data", {})
                    .get("error", {})
                    .get("code")
                    == "invalid_request",
                    "missing_exact_version_not_rejected",
                )
            else:
                require(
                    response.status_code == 400
                    and error.get("id") is None
                    and "error" in error
                    and "result" not in error,
                    "negative_case_accepted",
                )
            checks.append({"name": case, "status": "pass", "http_status": response.status_code})
    report["status"] = "pass"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New directory under ignored local state; parent must exist",
    )
    args = parser.parse_args()
    output = args.output
    require(
        output.is_absolute() and output.resolve().is_relative_to((ROOT / "local").resolve()),
        "output_must_be_ignored_local_state",
    )
    require(
        output.parent.is_dir() and not output.exists() and not output.is_symlink(),
        "output_identity_exists_or_parent_missing",
    )
    output.mkdir(mode=0o700)
    report = {
        "target": TARGET,
        "verifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "fixed_cases_sha256": hashlib.sha256(canonical(CASES)).hexdigest(),
        "official_mcp_sdk_version": version("mcp"),
        "started_at": utc_now().isoformat(),
        "status": "incomplete",
        "checks": [],
        "limits": {
            "maximum_requests": MAX_REQUESTS,
            "maximum_response_bytes": MAX_RESPONSE,
            "maximum_document_bytes": MAX_DOCUMENT,
            "request_seconds": REQUEST_SECONDS,
            "total_seconds": TOTAL_SECONDS,
            "automatic_retries": False,
        },
        "limitations": (
            "Fixed public smoke cases; no semantic accuracy or safety claim, provider call, "
            "publication, supported-client UX test or directory acceptance. "
            "Verification keys share the service HTTPS trust anchor."
        ),
    }

    async def run():
        async with BoundedClient(output, transport=httpx2.AsyncHTTPTransport(retries=0)) as client:
            try:
                await run_suite(client, report)
            finally:
                report["requests"] = client.requests

    try:
        asyncio.run(run())
    except BaseException as error:
        report.update(status="unavailable", error_type=type(error).__name__)
        if isinstance(error, Refusal):
            report["reason"] = str(error)
    report["completed_at"] = utc_now().isoformat()
    exclusive_json(output / "report.json", report)
    print(
        json.dumps(
            {
                "status": report["status"],
                "checks_passed": len(report["checks"]),
                "report": str(output / "report.json"),
                "report_sha256": hashlib.sha256((output / "report.json").read_bytes()).hexdigest(),
            }
        )
    )
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
