"""Content-free accounting and structured citations from pinned Claude Code.

WebSearch can invoke an internal same-model helper. The result's aggregate
modelUsage is authoritative for that work; top-level usage omits it. Neither
thinking text nor search summaries are retained or treated as citation metadata.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from smithguard.discovery import X_HOSTS, canonical_public_url, citation_key
from smithguard.scheduled_discovery import ProviderResult

CLAUDE_MODEL = "claude-opus-5-5"
CLAUDE_ROUTE = "claude_code_subscription"
CLAUDE_VERSION = "2.1.309"
# These built-ins are advertised even with plugin settings empty and slash
# commands disabled. Bind their exact pinned identities; tools and skills still
# have separate closed allowlists below.
CLAUDE_BUILTINS = [
    {"name": "cc-plugin-agents-md", "path": "builtin", "source": "cc-plugin-agents-md@builtin"},
    {
        "name": "cc-plugin-plugin-authoring",
        "path": "builtin",
        "source": "cc-plugin-plugin-authoring@builtin",
    },
]


def count(value: Any, *, maximum: int = 2**53 - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("claude_counter_invalid")
    return value


def identity(value: Any) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("claude_identity_invalid")
    return value


class ClaudeStream:
    def __init__(self, *, qualification: bool) -> None:
        self.qualification = qualification
        self.session: str | None = None
        self.turns: set[str] = set()
        self.calls: dict[str, str] = {}
        self.completed: set[str] = set()
        self.citations: set[str] = set()
        self.search_requests = 0
        self.final: dict | None = None

    def accept(self, event: Mapping[str, Any]) -> None:
        if self.final is not None:
            raise ValueError("claude_event_after_result")
        kind = event.get("type")
        if kind == "system" and event.get("subtype") == "init":
            if (
                self.session is not None
                or event.get("model") != CLAUDE_MODEL
                or event.get("claude_code_version") != CLAUDE_VERSION
                or event.get("tools") != ([] if self.qualification else ["WebSearch"])
                or event.get("mcp_servers") != []
                or event.get("plugins") != CLAUDE_BUILTINS
                or event.get("skills") != []
            ):
                raise ValueError("claude_initial_boundary_changed")
            self.session = identity(event.get("session_id"))
            return
        # The pinned harness emits a UI invalidation before init. It is not a
        # model turn and contains no accepted result or citation evidence.
        if kind == "system" and event.get("subtype") == "ui_invalidate":
            return
        if self.session is None or event.get("session_id") != self.session:
            raise ValueError("claude_session_changed")
        if kind == "assistant":
            self._assistant(event)
        elif kind == "user":
            self._tool_result(event)
        elif kind == "result":
            self.final = dict(event)
        elif kind == "rate_limit_event":
            return  # The terminal result, not this advisory, closes usage.
        elif kind == "system" and event.get("subtype") == "thinking_tokens":
            return  # Estimated counters are not authoritative usage.
        else:
            raise ValueError("claude_stream_event_unknown")

    def _assistant(self, event: Mapping[str, Any]) -> None:
        message = event.get("message")
        request = event.get("request_id")
        if (
            not isinstance(message, dict)
            or message.get("model") != CLAUDE_MODEL
            or not isinstance(request, str)
            or not request.isascii()
            or not 1 <= len(request) <= 200
            or event.get("parent_tool_use_id") is not None
        ):
            raise ValueError("claude_model_turn_invalid")
        self.turns.add(request)
        if len(self.turns) > (1 if self.qualification else 3):
            raise ValueError("claude_model_turn_limit")
        blocks = message.get("content")
        if not isinstance(blocks, list):
            raise ValueError("claude_message_invalid")
        for block in blocks:
            if not isinstance(block, dict):
                raise ValueError("claude_message_invalid")
            kind = block.get("type")
            if kind in {"thinking", "redacted_thinking", "text"}:
                continue  # Only the terminal result supplies final output.
            if kind != "tool_use" or self.qualification or block.get("name") != "WebSearch":
                raise ValueError("claude_tool_not_allowed")
            key, arguments = block.get("id"), block.get("input")
            if (
                not isinstance(key, str)
                or not key.isascii()
                or not 1 <= len(key) <= 200
                or key in self.calls
                or not isinstance(arguments, dict)
                or set(arguments) != {"query"}
                or not isinstance(arguments["query"], str)
                or not 1 <= len(arguments["query"]) <= 2000
                or any(ord(c) < 32 for c in arguments["query"])
            ):
                raise ValueError("claude_search_call_invalid")
            self.calls[key] = arguments["query"]
            if len(self.calls) > 4:
                raise ValueError("claude_tool_call_limit")

    def _tool_result(self, event: Mapping[str, Any]) -> None:
        message, proof = event.get("message"), event.get("tool_use_result")
        if not isinstance(message, dict) or not isinstance(proof, dict):
            raise ValueError("claude_search_result_invalid")
        blocks = message.get("content")
        if not isinstance(blocks, list) or len(blocks) != 1:
            raise ValueError("claude_search_result_invalid")
        block = blocks[0]
        if not isinstance(block, dict):
            raise ValueError("claude_search_result_invalid")
        key = block.get("tool_use_id")
        if (
            block.get("type") != "tool_result"
            or block.get("is_error", False) is not False
            or key not in self.calls
            or key in self.completed
            or proof.get("query") != self.calls[key]
        ):
            raise ValueError("claude_search_result_binding")
        self.completed.add(key)
        self.search_requests += count(proof.get("searchCount"), maximum=32)
        results = proof.get("results")
        if not isinstance(results, list) or len(results) > 100:
            raise ValueError("claude_search_result_invalid")
        for result in results:
            if isinstance(result, str):
                continue  # Helper prose, never citation evidence.
            if not isinstance(result, dict) or not isinstance(result.get("content"), list):
                raise ValueError("claude_search_citation_shape")
            for link in result["content"]:
                if not isinstance(link, dict) or set(link) != {"title", "url"}:
                    raise ValueError("claude_search_citation_shape")
                try:
                    from urllib.parse import urlsplit

                    url = canonical_public_url(link["url"])
                    host = (urlsplit(url).hostname or "").removeprefix("www.")
                    # An indexed X URL is not proof of the post. This route has
                    # no native X search or oEmbed fetch and cannot qualify it.
                    if not citation_key(url).startswith("x-status:") and not any(
                        host == domain or host.endswith("." + domain) for domain in X_HOSTS
                    ):
                        self.citations.add(url)
                except (ValueError, TypeError):
                    continue
        if len(self.citations) > 500:
            raise ValueError("claude_citation_limit")

    def result(self, *, request_bytes: int, response_bytes: int, elapsed_ms: int) -> ProviderResult:
        result = self.final
        if (
            result is None
            or result.get("type") != "result"
            or result.get("subtype") != "success"
            or result.get("is_error") is not False
            or result.get("terminal_reason") != "completed"
            or result.get("stop_reason") != "end_turn"
            or result.get("permission_denials") != []
            or result.get("api_error_status") is not None
            or result.get("safety_stops") != 0
            or result.get("num_turns") != len(self.turns)
            or not self.turns
            or self.completed != set(self.calls)
            or not isinstance(result.get("subagent_stats"), dict)
            or result["subagent_stats"].get("spawned") != 0
        ):
            raise ValueError("claude_completion_unproven")
        result_id = identity(result.get("uuid"))
        models = result.get("modelUsage")
        usage = result.get("usage")
        if (
            not isinstance(models, dict)
            or set(models) != {CLAUDE_MODEL}
            or not isinstance(usage, dict)
            or usage.get("service_tier") != "standard"
            or usage.get("speed") != "standard"
        ):
            raise ValueError("claude_model_usage_unproven")
        aggregate = models[CLAUDE_MODEL]
        if (
            not isinstance(aggregate, dict)
            or aggregate.get("canonicalModel") != CLAUDE_MODEL
            or aggregate.get("provider") != "firstParty"
            or count(aggregate.get("webSearchRequests"), maximum=128) != self.search_requests
        ):
            raise ValueError("claude_model_usage_changed")
        cached = count(aggregate.get("cacheReadInputTokens"), maximum=2_000_000)
        input_tokens = (
            count(aggregate.get("inputTokens"), maximum=2_000_000)
            + cached
            + count(aggregate.get("cacheCreationInputTokens"), maximum=2_000_000)
        )
        output_tokens = count(aggregate.get("outputTokens"))
        thinking = count(aggregate.get("thinkingTokens"))
        if input_tokens > 2_000_000 or thinking > output_tokens:
            raise ValueError("claude_usage_outside_boundary")
        if not isinstance(result.get("result"), str):
            raise ValueError("claude_final_output_missing")
        return ProviderResult(
            output_text=result["result"],
            response_id=f"claude-code:{self.session}:{result_id}",
            citation_urls=tuple(sorted(self.citations)),
            server_side_tool_calls=len(self.calls),
            input_tokens=input_tokens,
            cached_input_tokens=cached,
            output_tokens=output_tokens,
            reasoning_tokens=thinking,
            total_tokens=input_tokens + output_tokens,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            elapsed_milliseconds=elapsed_ms,
            credential_route=CLAUDE_ROUTE,
            native_search_requests=self.search_requests,
            native_model_turns=len(self.turns),
        )
