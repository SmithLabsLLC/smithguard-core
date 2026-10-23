"""Stateless hosted MCP over the existing public API, without outbound HTTP."""

from __future__ import annotations

import asyncio
import json
import logging
from copy import deepcopy
from typing import Any

import httpx
import mcp_types as types
from jsonschema import Draft202012Validator
from mcp.server import Server
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types.version import KNOWN_PROTOCOL_VERSIONS
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from smithguard import __version__
from smithguard.bulletin_contract import MCP_INPUTS as BULLETIN_INPUTS
from smithguard.identifiers import strict_json_loads

MCP_PATH = "/mcp"
MCP_TRANSPORT_METHODS = frozenset({"POST", "GET", "DELETE"})
MCP_MAX_REQUEST_BYTES = 16_384
MCP_MAX_DOCUMENT_BYTES = 1_048_576
MCP_MAX_RESPONSE_BYTES = 2_200_000
MCP_CONCURRENCY = 16
MCP_TIMEOUT_SECONDS = 12.0
PUBLIC_SOURCE = "https://api.smithguard.io"
TOOL_PATHS = {
    "assess_public_artifact": "/v1/artifacts/assess",
    "get_coverage": "/v1/coverage.json",
    "get_emerging_leads": "/v1/emerging-leads.json",
    "get_verification_key": "/v1/public-key.json",
    "list_bulletins": "/v1/bulletins.json",
    "get_bulletin": "/v1/bulletins/{identity}.json",
    "get_bulletin_changes": "/v1/bulletin-events.json",
    "get_bulletin_status": "/v1/bulletin-status.json",
}


class _SDKLogPrivacy(logging.Filter):
    """The pinned transport has debug paths containing opaque request identities."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = "MCP transport event"
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


def _protect_sdk_logs() -> None:
    for name, logger in logging.Logger.manager.loggerDict.copy().items():
        if (
            isinstance(logger, logging.Logger)
            and (name == "mcp" or name.startswith("mcp."))
            and not any(isinstance(item, _SDKLogPrivacy) for item in logger.filters)
        ):
            logger.addFilter(_SDKLogPrivacy())


def _tool_definitions(contract: dict[str, Any]) -> list[types.Tool]:
    schemas = contract["components"]["schemas"]
    assessment = deepcopy(schemas["PublicArtifactAssessmentShortRequest"])
    # This schema has one local reference; never permit remote schema resolution.
    digest = assessment["properties"]["digest"]
    if digest != {"$ref": "#/components/schemas/Sha256"}:
        raise RuntimeError("MCP assessment schema reference changed")
    assessment["properties"]["digest"] = deepcopy(schemas["Sha256"])
    inputs = {
        "assess_public_artifact": assessment,
        "get_coverage": {"type": "object", "properties": {}, "additionalProperties": False},
        "get_emerging_leads": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
                "after": {"type": "string", "pattern": "^[a-f0-9]{64}$", "maxLength": 64},
            },
        },
        "get_verification_key": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "public_key_id": {
                    "type": "string",
                    "pattern": "^gbsec:snapshot-public-key:[a-f0-9]{40}$",
                    "maxLength": 66,
                }
            },
        },
    }
    descriptions = {
        "list_bulletins": (
            "Read attributed bulletins and freshness. Applicability is not evaluated; "
            "no authority to act on machines. Data is unsigned."
        ),
        "get_bulletin": (
            "Read the current or historical bulletin revision, including public takedown status. "
            "Always resolve current status before showing facts."
        ),
        "get_bulletin_changes": (
            "Read ordered bulletin change references. Bootstrap with list_bulletins; "
            "use its changes_cursor only after all snapshot pages. Resolve each current record."
        ),
        "get_bulletin_status": (
            "Read qualified-source coverage, gaps, backlog and bulletin stream status; "
            "an empty list is not a safety claim."
        ),
        "assess_public_artifact": (
            "Assess one exact public package version or immutable digest. Supply only a public "
            "coordinate; never source code, files, private inventories or credentials. "
            "The complete signed API answer describes scope and unknowns, not a safety guarantee."
        ),
        "get_coverage": "Read current public source coverage and freshness limitations.",
        "get_emerging_leads": (
            "Read public Emerging / Unverified leads and publication status. These allegations "
            "are separate from official incidents and exact-artifact assessments."
        ),
        "get_verification_key": "Read the current or named public assessment verification key.",
    }
    return [
        types.Tool(
            name=name,
            description=descriptions[name],
            input_schema=schema,
            output_schema={
                "type": "object",
                "additionalProperties": False,
                "required": ["data", "source_url"],
                "properties": {
                    "data": {
                        "type": "object",
                        "description": (
                            "The unchanged full public REST response document, including its "
                            "signature and limitations when present, or its standard API error."
                        ),
                    },
                    "source_url": {"type": "string", "format": "uri"},
                    "retry_after": {"type": "string", "pattern": "^[0-9]+$"},
                },
            },
            meta={"securitySchemes": [{"type": "noauth"}]},
            annotations=types.ToolAnnotations(
                read_only_hint=True,
                destructive_hint=False,
                idempotent_hint=True,
                open_world_hint=True,
            ),
        )
        for name, schema in {**inputs, **BULLETIN_INPUTS}.items()
    ]


def _rpc_error(status: int, code: int, message: str) -> JSONResponse:
    # An invalid envelope may contain a secret even in its id: never echo it.
    return JSONResponse(
        {"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}},
        status_code=status,
    )


def _tool_result(
    document: dict[str, Any], path: str, *, is_error: bool, retry_after: str | None = None
) -> types.CallToolResult:
    result = {"data": document, "source_url": PUBLIC_SOURCE + path}
    if retry_after is not None and retry_after.isascii() and retry_after.isdigit():
        result["retry_after"] = retry_after
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(result, separators=(",", ":")))],
        structured_content=result,
        is_error=is_error,
    )


def _tool_error(code: str, *, path: str, retryable: bool = False) -> types.CallToolResult:
    return _tool_result(
        {
            "error": {
                "code": code,
                "message": "The hosted tool request could not be completed.",
                "retryable": retryable,
            }
        },
        path,
        is_error=True,
    )


class HostedMCP:
    """Own protocol lifetime and enforce finite, content-free request failures."""

    def __init__(
        self, api: Any, *, contract: dict[str, Any], hosts: set[str], trusted_proxy_header: bool
    ) -> None:
        self.api = api
        self.hosts = hosts
        self.origins = {"https://" + host for host in hosts}
        self.trusted_proxy_header = trusted_proxy_header
        self.tools = _tool_definitions(contract)
        self.validators = {
            tool.name: Draft202012Validator(tool.input_schema) for tool in self.tools
        }
        self.slots = asyncio.Semaphore(MCP_CONCURRENCY)
        _protect_sdk_logs()
        self.server = Server(
            "SmithGuard",
            version=__version__,
            website_url="https://smithguard.io",
            on_list_tools=self.list_tools,
            on_call_tool=self.call_tool,
        )
        # This service exports no telemetry and makes no server-to-client requests.
        self.server.middleware.clear()
        self.server.middleware.append(self._public_descriptors)
        self.protocol = self.server.streamable_http_app(
            json_response=True,
            stateless_http=True,
            max_request_body_size=MCP_MAX_REQUEST_BYTES,
            transport_security=TransportSecuritySettings(
                allowed_hosts=sorted(hosts),
                allowed_origins=sorted(self.origins),
            ),
        )

    def route(self) -> Route:
        route = Route(MCP_PATH, self, methods=sorted(MCP_TRANSPORT_METHODS))
        # Starlette automatically adds HEAD to GET routes. MCP has no HEAD transport.
        route.methods.discard("HEAD")
        self.transport_route = route
        return route

    async def list_tools(self, _context: Any, _params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=self.tools)

    @staticmethod
    async def _public_descriptors(context: Any, call_next: Any) -> dict[str, Any]:
        result = await call_next(context)
        if context.method == "tools/list":
            # The SDK's standards-only serializer strips top-level extensions.
            # OpenAI clients accept this no-auth declaration and its _meta mirror.
            for tool in result["tools"]:
                tool["securitySchemes"] = [{"type": "noauth"}]
        return result

    async def call_tool(
        self, context: Any, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        path = TOOL_PATHS.get(params.name, MCP_PATH)
        arguments = params.arguments or {}
        validator = self.validators.get(params.name)
        if validator is None or not validator.is_valid(arguments):
            return _tool_error("invalid_tool_arguments", path=path)
        try:
            request = context.request
            if not isinstance(request, Request):
                return _tool_error("request_context_unavailable", path=path, retryable=True)
            if params.name == "get_verification_key" and "public_key_id" in arguments:
                path = "/v1/public-keys/" + arguments["public_key_id"] + ".json"
            headers = {}
            if self.trusted_proxy_header and "x-forwarded-for" in request.headers:
                headers["X-Forwarded-For"] = request.headers["x-forwarded-for"]
            client = (request.client.host, request.client.port) if request.client else None
            transport = httpx.ASGITransport(app=self.api, client=client, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_SOURCE) as internal:
                if params.name == "assess_public_artifact":
                    response = await internal.post(path, json=arguments, headers=headers)
                else:
                    query = (
                        arguments if params.name in {"get_emerging_leads", *BULLETIN_INPUTS} else {}
                    )
                    if params.name == "get_bulletin":
                        path = path.replace("{identity}", arguments["identity"])
                        query = {
                            key: value for key, value in arguments.items() if key != "identity"
                        }
                    response = await internal.get(path, params=query, headers=headers)
            if len(response.content) > MCP_MAX_DOCUMENT_BYTES:
                return _tool_error("tool_response_limit_exceeded", path=path)
            document = strict_json_loads(response.content)
            if not isinstance(document, dict):
                return _tool_error("tool_response_invalid", path=path)
            return _tool_result(
                document,
                path,
                is_error=response.is_error,
                retry_after=response.headers.get("retry-after"),
            )
        except Exception:
            # Never send exception messages, arguments, reprs or tracebacks to the SDK.
            return _tool_error("tool_unavailable", path=path, retryable=True)

    def _valid_envelope(self, document: Any, headers: Any) -> bool:
        if not isinstance(document, dict) or set(document) - {"jsonrpc", "id", "method", "params"}:
            return False
        if document.get("jsonrpc") != "2.0":
            return False
        method = document.get("method")
        if method not in {
            "initialize",
            "notifications/initialized",
            "tools/list",
            "tools/call",
            "ping",
            "server/discover",
        }:
            return False
        identity = document.get("id")
        if method == "notifications/initialized" and "id" in document:
            return False
        if method != "notifications/initialized" and not (
            type(identity) is int or isinstance(identity, str) and 1 <= len(identity) <= 64
        ):
            return False
        params = document.get("params", {})
        if not isinstance(params, dict):
            return False
        allowed = {
            "initialize": {"protocolVersion", "capabilities", "clientInfo", "_meta"},
            "tools/call": {"name", "arguments", "_meta"},
        }.get(method, {"_meta"})
        if set(params) - allowed:
            return False
        version = headers.get("mcp-protocol-version")
        if version is not None and version not in KNOWN_PROTOCOL_VERSIONS:
            return False
        if method == "initialize":
            if params.get("protocolVersion") not in KNOWN_PROTOCOL_VERSIONS:
                return False
            types.InitializeRequestParams.model_validate(params, by_name=False)
        elif method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str) or name not in self.validators:
                return False
            args = params.get("arguments", {})
            if not isinstance(args, dict) or not self.validators[name].is_valid(args):
                return False
            types.CallToolRequestParams.model_validate(params, by_name=False)
        else:
            types.RequestParams.model_validate(params, by_name=False)
        meta = params.get("_meta")
        if meta is not None and not isinstance(meta, dict):
            return False
        if isinstance(meta, dict):
            requested = meta.get(types.PROTOCOL_VERSION_META_KEY)
            if requested is not None and requested not in KNOWN_PROTOCOL_VERSIONS:
                return False
            if types.CLIENT_CAPABILITIES_META_KEY in meta:
                types.ClientCapabilities.model_validate(meta[types.CLIENT_CAPABILITIES_META_KEY])
            if types.CLIENT_INFO_META_KEY in meta:
                types.Implementation.model_validate(meta[types.CLIENT_INFO_META_KEY])
        for key in ("host", "origin", "mcp-method", "mcp-name", "mcp-protocol-version"):
            if len(headers.getlist(key)) > 1:
                return False
        for key, value in headers.items():
            if key.startswith("mcp-param-") or key in {"mcp-session-id", "last-event-id"}:
                return False
            if key == "mcp-method" and value != method:
                return False
            if key == "mcp-name" and value != params.get("name"):
                return False
        return True

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        async def uncached_send(message):
            if message["type"] == "http.response.start":
                message = {
                    **message,
                    "headers": [
                        (key, value)
                        for key, value in message.get("headers", [])
                        if key.lower() != b"cache-control"
                    ]
                    + [(b"cache-control", b"no-store")],
                }
            await send(message)

        await self._respond(scope, receive, uncached_send)

    async def _respond(self, scope: Any, receive: Any, send: Any) -> None:
        scope["route"] = self.transport_route
        request = Request(scope, receive)
        if request.headers.get("host") not in self.hosts:
            await _rpc_error(421, -32600, "Invalid host")(scope, receive, send)
            return
        origin = request.headers.get("origin")
        if origin is not None and origin not in self.origins:
            await _rpc_error(403, -32600, "Invalid origin")(scope, receive, send)
            return
        if request.method != "POST":
            response = JSONResponse({}, status_code=405, headers={"Allow": "POST"})
            await response(scope, receive, send)
            return
        if self.slots.locked():
            await _rpc_error(503, -32603, "Hosted tool capacity exceeded")(scope, receive, send)
            return
        async with self.slots:
            try:
                async with asyncio.timeout(MCP_TIMEOUT_SECONDS):
                    body = bytearray()
                    async for chunk in request.stream():
                        if len(body) + len(chunk) > MCP_MAX_REQUEST_BYTES:
                            await _rpc_error(413, -32600, "Request exceeds its byte limit")(
                                scope, receive, send
                            )
                            return
                        body.extend(chunk)
                    document = strict_json_loads(bytes(body), max_depth=12, max_nodes=2048)
                    if not self._valid_envelope(document, request.headers):
                        await _rpc_error(400, -32602, "Invalid hosted MCP request")(
                            scope, receive, send
                        )
                        return
                    pending = [{"type": "http.request", "body": bytes(body), "more_body": False}]

                    async def replay():
                        return pending.pop() if pending else await receive()

                    messages = []
                    response_size = 0

                    async def bounded_send(message):
                        nonlocal response_size
                        response_size += len(message.get("body", b""))
                        if response_size > MCP_MAX_RESPONSE_BYTES:
                            raise ValueError("MCP response exceeds its byte limit")
                        messages.append(message)

                    await self.protocol(scope, replay, bounded_send)
                for message in messages:
                    await send(message)
            except (ValueError, TypeError, RecursionError, ValidationError):
                await _rpc_error(400, -32602, "Invalid hosted MCP request")(scope, receive, send)
            except Exception:
                await _rpc_error(503, -32603, "Hosted tool service unavailable")(
                    scope, receive, send
                )
