"""Validate native Grok Build metadata; never retain thought or price content."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from smithguard.discovery import canonical_public_url
from smithguard.grok_build_citations import fetched_citations
from smithguard.native_usage import NativeInvocationUsage
from smithguard.scheduled_discovery import (
    X_SEARCH_ALIAS_NAMES,
    ProviderResult,
    ProviderUsageSnapshot,
    ScheduledProviderError,
)
from smithguard.spend import NATIVE_SUBSCRIPTION_CONTRACT as NATIVE_LIMITS
from smithguard.xai_settings import (
    XAI_MAX_INPUT_TOKENS,
    XAI_MAX_OUTPUT_TOKENS,
    XAI_MAX_TOTAL_TOKENS,
)

NATIVE_MODEL = "grok-4.7-build"
NATIVE_ROUTE = "grok_build_subscription"
NATIVE_X_RESULT_KEYS = frozenset({"call_id", "id", "input", "name"})


def uncertain(code: str = "native_response_invalid") -> ScheduledProviderError:
    return ScheduledProviderError(code, retryable=False, usage_uncertain=True)


def integer(value: Any, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise uncertain("native_usage_invalid")
    return value


class NativeStream:
    """One prompt in a manually titled RAM session, bounded closed tools.

    Build's native end record identifies the harness request, not a Responses API
    response. The receipt's credential route declares that distinction explicitly.
    """

    def __init__(
        self, *, session_id: str, qualification: bool, allowed: set[str] | None = None
    ) -> None:
        self.session_id = str(UUID(session_id))
        self.qualification = qualification
        self.allowed = (
            (set() if qualification else {"web_search", "web_fetch"})
            if allowed is None
            else allowed
        )
        if qualification and self.allowed:
            raise ValueError("qualification tools forbidden")
        self.maximum_turns = NATIVE_LIMITS[
            "maximum_qualification_turns" if qualification else "maximum_model_turns"
        ]
        self.maximum_tools = 0 if qualification else NATIVE_LIMITS["maximum_observed_tool_calls"]
        self.local_tools = self.allowed & {"web_fetch"}
        self.tools: dict[str, dict[str, Any]] = {}
        self.text: list[str] = []
        self.completed_text = ""
        self.citations: set[str] = set()
        self.end: dict | None = None
        self.advertised = False
        self.saw_error = False
        self.saw_inference = False
        self.incomplete_stop = False
        self.invalid_output = False
        self.observed_events = 0
        self.observed_model_turns = 0
        self.observed_tool_calls = 0
        self.turn_limit_events = 0
        self.bounded_continuation = False
        self.usage_counts: tuple[int, ...] | None = None

    def accept(self, event: Mapping[str, Any]) -> None:
        self.observed_events += 1
        kind = event.get("type")
        if kind == "usage":
            self.observed_model_turns += 1
        elif kind == "tool_call":
            self.observed_tool_calls += 1
        if self.end is not None:
            raise uncertain("native_event_after_end")
        if kind == "available_commands":
            tools = event.get("tools")
            if (
                not isinstance(tools, list)
                or any(not isinstance(tool, str) for tool in tools)
                or set(tools) != self.local_tools
            ):
                raise uncertain("native_tools_changed")
            self.advertised = True
        elif kind == "thought":
            self.saw_inference = True
            self.completed_text = ""
            # Discard the entire event immediately. No logging or retained diagnostic.
        elif kind == "text":
            self.saw_inference = True
            self.completed_text = ""
            value = event.get("data")
            if not isinstance(value, str):
                raise uncertain()
            self.text.append(value)
        elif kind == "usage":
            self.saw_inference = True
            usage = event.get("usage")
            counts = (
                tuple(
                    usage.get(name)
                    for name in (
                        "input_tokens",
                        "output_tokens",
                        "cache_read_input_tokens",
                        "cache_creation_input_tokens",
                        "reasoning_tokens",
                    )
                )
                if isinstance(usage, dict)
                else ()
            )
            self.usage_counts = (
                counts
                if len(counts) == 5
                and all(
                    type(value) is int and 0 <= value <= XAI_MAX_TOTAL_TOKENS for value in counts
                )
                else None
            )
            # A usage line closes one model response, including the final one.
            # Preserve its text until a later response/tool supersedes it.
            self.completed_text = "".join(self.text)
            self.text.clear()
        elif kind == "tool_call":
            self.saw_inference = True
            self.completed_text = ""
            self.text.clear()
            self._tool(event)
        elif kind == "tool_call_update":
            self.completed_text = ""
            self._tool_update(event)
        elif kind == "error":
            # Error prose is not proof of an uncharged failure. A separate native
            # structured terminal record is required before rate-limit fallback.
            self.saw_error = True
        elif kind == "end":
            self.end = dict(event)
        elif kind == "max_turns_reached":
            self.incomplete_stop = True
            self.turn_limit_events += 1
        else:
            raise uncertain("native_event_unknown")

    def _tool(self, event: Mapping[str, Any]) -> None:
        identity = event.get("toolCallId")
        if (
            not isinstance(identity, str)
            or not 1 <= len(identity) <= 256
            or identity in self.tools
            or len(self.tools) >= self.maximum_tools
        ):
            raise uncertain("native_tool_limit")
        name, request = event.get("toolName"), event.get("rawInput")
        if (
            "web_search" in self.allowed
            and name in {"Web search:", "web_search"}
            and request == {"variant": "WebSearch", "backend": True}
        ):
            tool = {"kind": "backend_search", "complete": False}
        elif (
            "x_search" in self.allowed
            and name in {"X search:", "x_search"}
            and request == {"variant": "XSearch", "backend": True}
        ):
            tool = {"kind": "x_search", "complete": False}
        elif (
            "web_fetch" in self.allowed
            and name == "web_fetch"
            and isinstance(request, dict)
            and set(request) == {"url"}
        ):
            try:
                url = canonical_public_url(request["url"])
            except (ValueError, TypeError) as error:
                raise uncertain("native_tool_url_invalid") from error
            tool = {"kind": "fetch", "url": url, "complete": False}
        else:
            # The local web_search helper makes an unaccounted auxiliary model
            # request. Only the model's native backend search is permitted.
            raise uncertain("native_tool_unapproved")
        if event.get("status") not in {"pending", "in_progress"}:
            raise uncertain("native_tool_state_invalid")
        self.tools[identity] = tool

    def _tool_update(self, event: Mapping[str, Any]) -> None:
        identity = event.get("toolCallId")
        if not isinstance(identity, str) or identity not in self.tools:
            raise uncertain("native_tool_identity_invalid")
        tool = self.tools[identity]
        status = event.get("status")
        if tool["complete"] or status not in {
            None,
            "pending",
            "in_progress",
            "completed",
            "failed",
        }:
            raise uncertain("native_tool_state_invalid")
        if status not in {"completed", "failed"}:
            return
        output = event.get("rawOutput")
        if not isinstance(output, dict):
            raise uncertain("native_tool_output_invalid")
        urls: list[str] = []
        if tool["kind"] == "fetch":
            # Native tool-runtime failures (including SSRF denial) use the ACP
            # error envelope rather than a WebFetch output variant. They prove
            # no citation, but allow a normal terminal usage ledger to be read.
            if (
                status == "failed"
                and set(output) == {"error", "message"}
                and output["error"] == "tool_execution_failed"
                and isinstance(output["message"], str)
            ):
                tool["complete"] = True
                return
            if output.get("type") != "WebFetch":
                raise uncertain("native_tool_output_invalid")
            variant = set(output) - {"type"}
            if len(variant) != 1:
                raise uncertain("native_tool_output_invalid")
            failed = (
                variant == {"DomainNotAllowed"}
                and isinstance(output["DomainNotAllowed"], str)
                or variant == {"CrossHostRedirect"}
                and isinstance(output["CrossHostRedirect"], dict)
                and set(output["CrossHostRedirect"]) == {"original_host", "redirect_url"}
                and all(isinstance(v, str) for v in output["CrossHostRedirect"].values())
                or variant == {"Error"}
                and isinstance(output["Error"], dict)
                and set(output["Error"]) == {"url", "message"}
                and (output["Error"]["url"] is None or isinstance(output["Error"]["url"], str))
                and isinstance(output["Error"]["message"], str)
            )
            if failed:
                tool["complete"] = True
                return
            if variant != {"Content"} or not isinstance(output["Content"], dict):
                raise uncertain("native_tool_output_invalid")
            # Never promote arbitrary URLs in fetched page text into citations.
            content = output["Content"]
            if (
                type(content.get("status_code")) is not int
                or not 100 <= content["status_code"] <= 599
                or not isinstance(content.get("content"), str)
            ):
                raise uncertain("native_tool_output_invalid")
            if not isinstance(content.get("url"), str):
                # The pinned shape requires a URL. Reject semantic output, but
                # drain a normally completing run to retain its exact usage.
                self.invalid_output = True
            if (
                status == "completed"
                and 200 <= content["status_code"] < 300
                and content["content"].strip()
            ):
                urls = fetched_citations(tool["url"], content)
        elif tool["kind"] == "x_search":
            # Native X output carries a tool invocation, not sourced search results.
            # Never turn its query text into evidence. A separate successful fetch
            # must establish a candidate's citation.
            # Build serializes the inner CustomToolCall (four fields). Completion
            # status belongs to the checked ACP envelope, not the API's six-field item.
            if (
                status != "completed"
                or set(output) != NATIVE_X_RESULT_KEYS
                or not isinstance(output.get("name"), str)
                or output.get("name") not in X_SEARCH_ALIAS_NAMES
                or not all(
                    isinstance(output.get(k), str)
                    and output[k].isascii()
                    and 1 <= len(output[k]) <= 512
                    for k in ("id", "call_id")
                )
                or not isinstance(output.get("input"), str)
                or len(output["input"]) > 65_536
            ):
                raise uncertain("native_tool_output_invalid")
        else:
            if status == "failed" and output.get("status") == "failed":
                tool["complete"] = True
                return
            if output.get("status") != "completed":
                raise uncertain("native_tool_output_invalid")
            action = output.get("action")
            if not isinstance(action, dict):
                raise uncertain("native_tool_output_invalid")
            sources = action.get("sources", [])
            if not isinstance(sources, list) or len(sources) > 100:
                raise uncertain("native_tool_output_invalid")
            for source in sources:
                if not isinstance(source, dict):
                    raise uncertain("native_tool_output_invalid")
                urls.append(source.get("url"))
            if action.get("type") in {"open_page", "find_in_page"}:
                urls.append(action.get("url"))
        for url in urls:
            try:
                self.citations.add(canonical_public_url(url))
            except (TypeError, ValueError):
                # Search result URLs are untrusted evidence candidates. An
                # unusable citation does not make the provider's usage unknown.
                continue
        tool["complete"] = True

    def result(
        self,
        *,
        request_bytes: int,
        response_bytes: int,
        elapsed_ms: int,
        execution_failed: bool = False,
        segmented: bool = False,
        accept_turn_boundary: bool = False,
    ) -> ProviderResult:
        self.bounded_continuation = False
        end = self.end
        if (
            not self.advertised
            or self.saw_error
            or not isinstance(end, dict)
            or end.get("stopReason")
            not in {"end_turn", "max_tokens", "max_turn_requests", "refusal", "cancelled"}
            or end.get("sessionId") != self.session_id
            or end.get("usage_is_incomplete", False) is not False
            or any(not tool["complete"] for tool in self.tools.values())
        ):
            raise uncertain("native_completion_incomplete")
        try:
            request_id = str(UUID(end["requestId"]))
            usage = end["usage"]
            models = end["modelUsage"]
            if "model_usage" in end:
                raise uncertain("native_usage_invalid")
            if (
                not isinstance(usage, dict)
                or not isinstance(models, dict)
                or set(models) != {NATIVE_MODEL}
            ):
                raise uncertain("native_model_or_usage_changed")
            model = models[NATIVE_MODEL]
            uncached = integer(usage["input_tokens"], XAI_MAX_INPUT_TOKENS)
            cached = integer(usage["cache_read_input_tokens"], XAI_MAX_INPUT_TOKENS)
            created = integer(usage["cache_creation_input_tokens"], XAI_MAX_INPUT_TOKENS)
            output = integer(usage["output_tokens"], XAI_MAX_OUTPUT_TOKENS)
            reasoning = integer(usage["reasoning_tokens"], output)
            total = integer(usage["total_tokens"], XAI_MAX_TOTAL_TOKENS)
            turns = integer(end["num_turns"], 10)
            if (
                turns < 1
                or uncached + cached + created > XAI_MAX_INPUT_TOKENS
                or total != uncached + cached + created + output
                or not isinstance(model, dict)
                or integer(model["modelCalls"], 10) != turns
                or integer(model["inputTokens"], XAI_MAX_INPUT_TOKENS) != uncached
                or integer(model["cacheReadInputTokens"], XAI_MAX_INPUT_TOKENS) != cached
                or integer(model["cacheCreationInputTokens"], XAI_MAX_INPUT_TOKENS) != created
                or integer(model["outputTokens"], XAI_MAX_OUTPUT_TOKENS) != output
            ):
                raise uncertain("native_usage_invalid")
        except (KeyError, TypeError, ValueError) as error:
            raise uncertain("native_usage_invalid") from error
        if (
            segmented
            and turns == 1
            and (
                self.observed_model_turns != 1
                or self.usage_counts != (uncached, output, cached, created, reasoning)
            )
        ):
            raise uncertain("native_usage_invalid")
        fields = dict(
            response_id=f"grok-build:{self.session_id}:{request_id}",
            server_side_tool_calls=len(self.tools),
            input_tokens=uncached + cached + created,
            cached_input_tokens=cached,
            output_tokens=output,
            reasoning_tokens=reasoning,
            total_tokens=total,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            elapsed_milliseconds=elapsed_ms,
            credential_route=NATIVE_ROUTE,
        )
        boundary = (
            segmented
            and not self.qualification
            and accept_turn_boundary
            and execution_failed
            and self.turn_limit_events == 1
            and end["stopReason"] == "cancelled"
            and turns == self.observed_model_turns == 1
            and bool(self.tools)
            and not self.invalid_output
        )
        if segmented:
            fields["native_invocations"] = (
                NativeInvocationUsage(
                    session_id=self.session_id,
                    request_id=request_id,
                    input_tokens=uncached + cached + created,
                    cached_input_tokens=cached,
                    output_tokens=output,
                    reasoning_tokens=reasoning,
                    total_tokens=total,
                    model_turns=turns,
                    tool_calls=len(self.tools),
                    stop_reason=end["stopReason"],
                    bounded_turn_limit=boundary,
                ),
            )
        if (
            uncached + cached + created > self.maximum_turns * 500_000
            or turns > self.maximum_turns
            or (segmented and (uncached + cached + created > 500_000 or turns != 1))
        ):
            raise ScheduledProviderError(
                "provider_token_usage_exceeded",
                retryable=False,
                usage_uncertain=False,
                exact_usage=ProviderUsageSnapshot(**fields),
            )
        if not boundary and (
            self.invalid_output
            or self.incomplete_stop
            or execution_failed
            or end["stopReason"] != "end_turn"
            or (segmented and self.observed_model_turns != 1)
        ):
            raise ScheduledProviderError(
                "native_output_invalid" if self.invalid_output else "native_response_incomplete",
                retryable=False,
                usage_uncertain=False,
                exact_usage=ProviderUsageSnapshot(**fields),
            )
        self.bounded_continuation = boundary
        return ProviderResult(
            output_text="".join(self.text) or self.completed_text,
            citation_urls=tuple(sorted(self.citations)),
            **fields,
        )
