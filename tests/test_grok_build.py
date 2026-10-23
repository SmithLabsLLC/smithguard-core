"""Native subscription isolation, provenance, cleanup and fail-closed fallback."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.orm import sessionmaker

from smithguard import grok_build as native
from smithguard.grok_build_stream import NATIVE_MODEL, NATIVE_ROUTE, NativeStream
from smithguard.scheduled_discovery import ScheduledProviderError, enqueue_due_discovery, work_one
from smithguard.subscription_provider import SubscriptionFirstProvider
from smithguard.warning_lane_receipts import ProviderUsage, _provider_document
from tests.test_scheduled_discovery import (
    NOW,
    SyntheticProvider,
    _active_policy,
    _discovery_result,
    _receipts,
)

pytestmark = pytest.mark.usefixtures("enabled_warning_dispatch")

SID = "11111111-1111-4111-8111-111111111111"
RID = "22222222-2222-4222-8222-222222222222"


def end_record():
    return {
        "type": "end",
        "sessionId": SID,
        "requestId": RID,
        "stopReason": "end_turn",
        "usage": {
            "input_tokens": 10,
            "cache_read_input_tokens": 20,
            "cache_creation_input_tokens": 3,
            "output_tokens": 8,
            "reasoning_tokens": 6,
            "total_tokens": 41,
        },
        "num_turns": 1,
        "modelUsage": {
            NATIVE_MODEL: {
                "inputTokens": 10,
                "cacheReadInputTokens": 20,
                "cacheCreationInputTokens": 3,
                "outputTokens": 8,
                "modelCalls": 1,
            }
        },
    }


def usage_record():
    return {
        "type": "usage",
        "usage": {k: v for k, v in end_record()["usage"].items() if k != "total_tokens"},
    }


def stream_result(stream):
    return stream.result(request_bytes=100, response_bytes=200, elapsed_ms=20)


def test_native_usage_counts_cached_input_and_discards_reasoning():
    stream = NativeStream(session_id=SID, qualification=True)
    stream.accept({"type": "available_commands", "tools": []})
    stream.accept({"type": "thought", "data": "synthetic reasoning must not survive"})
    stream.accept({"type": "text", "data": "{}"})
    stream.accept(end_record())
    result = stream_result(stream)
    assert result.input_tokens == 33 and result.output_tokens == 8 and result.total_tokens == 41
    assert result.output_text == "{}" and "reasoning must" not in repr(vars(stream))
    assert result.response_id == f"grok-build:{SID}:{RID}"
    usage = ProviderUsage(
        stage="discovery",
        model="grok-4.7",
        response_id=result.response_id,
        input_tokens=33,
        output_tokens=8,
        total_tokens=41,
        cached_input_tokens=20,
        reasoning_tokens=6,
        server_side_tool_calls=0,
        configured_maximum_turns=1,
        request_bytes=100,
        response_bytes=200,
        elapsed_milliseconds=20,
        credential_route=NATIVE_ROUTE,
    )
    doc = _provider_document(usage)
    assert doc["identity_scope"] == "native_harness_session_and_request"
    assert doc["actual_model"] == "grok-4.7-build" and doc["model"] == "grok-4.7"
    assert doc["tool_calls"] == 0 and "server_side_tool_calls" not in doc
    assert "identity_scope" not in _provider_document(replace(usage, credential_route="api_key"))


@pytest.mark.parametrize(
    "fault",
    [None, "disk", "swap", "core", "missing_cgroup", "wrong_size", "temp_disk", "temp_missing"],
)
def test_native_ram_preflight_requires_real_noswap_mount_and_cgroup(tmp_path, monkeypatch, fault):
    mount = f"1 0 0:1 / {tmp_path} rw,nosuid,nodev,noexec - tmpfs tmpfs rw,noswap,size=65536k"
    if fault == "disk":
        mount = mount.replace("tmpfs", "ext4")
    if fault == "wrong_size":
        mount = mount.replace("size=65536k", "size=131072k")
    mount += "\n2 0 0:2 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw,noswap,size=8192k"
    mount += "\n3 0 0:3 / /var/tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw,noswap,size=8192k"
    if fault == "temp_disk":
        mount = mount.replace("- tmpfs tmpfs rw,noswap,size=8192k", "- ext4 /dev/test rw")
    if fault == "temp_missing":
        mount = mount.splitlines()[0]
    original = Path.read_text

    def read(self, *args, **kwargs):
        if str(self) == "/proc/self/mountinfo":
            return mount
        if str(self) == "/proc/self/cgroup":
            return "" if fault == "missing_cgroup" else "0::/system.slice/synthetic.service\n"
        if str(self) == "/sys/fs/cgroup/system.slice/synthetic.service/memory.swap.max":
            return "max" if fault == "swap" else "0\n"
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(
        native.resource, "getrlimit", lambda _: (1, 1) if fault == "core" else (0, 0)
    )
    if fault:
        with pytest.raises(ValueError):
            native._ram_protections(tmp_path)
    else:
        native._ram_protections(tmp_path)


def test_native_usage_receipt_surfaces_subscription_route_in_health(database):
    from smithguard.scheduled_discovery import append_receipt
    from smithguard.warning_lane_health import collect_warning_lane_health

    factory = sessionmaker(database.engine)
    stream = NativeStream(session_id=SID, qualification=False)
    stream.accept({"type": "available_commands", "tools": ["web_fetch"]})
    stream.accept(end_record())
    with factory() as session, session.begin():
        append_receipt(
            session,
            receipt_type="provider_cost_observed",
            reason_code="within_technical_envelope",
            run_id="gbsec:ai-warning-run:native-health",
            occurred_at=NOW,
            public_metadata={},
            provider_result=stream_result(stream),
            provider_stage="discovery",
            configured_maximum_turns=3,
        )
    with factory() as session:
        health = collect_warning_lane_health(
            session,
            policy=_active_policy(),
            measured_at=NOW + timedelta(seconds=1),
            expiry_job_success=True,
            schedule_expected=True,
        )
    assert health.credential_routes == (("discovery", NATIVE_ROUTE),)


@pytest.mark.parametrize("qualification", [True, False])
@pytest.mark.parametrize("advertised_tools", [[], ["web_fetch"]])
def test_bootstrap_titles_without_prompt_and_passes_search_profile(
    tmp_path, monkeypatch, qualification, advertised_tools
):
    requests = []

    class Process:
        closed = False
        advertised = False

        def send(self, value):
            requests.append(value)

        def line(self, _deadline):
            last = requests[-1]
            if last["id"] == 3 and not self.advertised:
                self.advertised = True
                return json.dumps(
                    {
                        "method": "session/update",
                        "params": {
                            "sessionId": SID,
                            "update": {
                                "sessionUpdate": "available_commands_update",
                                "_meta": {"tools": advertised_tools},
                            },
                        },
                    }
                ).encode()
            result = {1: {}, 2: {"sessionId": SID}, 3: {"success": True}}[last["id"]]
            return json.dumps({"id": last["id"], "result": result}).encode()

        def close_input(self):
            self.eof = True

        def finish(self, _deadline):
            assert self.eof
            return 0

        def close(self):
            self.closed = True

    process = Process()
    provider = native.GrokBuildWarningProvider()

    def start(args, *_rest):
        assert args == ["agent", "--no-leader", "stdio"]
        return process

    monkeypatch.setattr(provider, "_start", start)
    from smithguard.grok_build_tools import search_profile

    tools = (
        []
        if qualification
        else [{"type": "web_search", "filters": {"allowed_domains": ["github.com"]}}]
    )
    profile = search_profile({"tools": tools}, qualification=qualification)
    assert profile["toolConfig"]["tools"] == [{"id": "GrokBuild:web_fetch"}]
    assert "web_fetch" in profile["disallowedTools"]
    if advertised_tools:
        with pytest.raises(ValueError, match="tool boundary changed"):
            provider._bootstrap(tmp_path, {}, SID, 100, profile)
    else:
        provider._bootstrap(tmp_path, {}, SID, 100, profile)
    assert [r["method"] for r in requests] == ["initialize", "session/new", "_x.ai/session/rename"]
    assert requests[1]["params"]["_meta"]["agentProfile"] == profile
    assert process.closed


@pytest.mark.parametrize(
    "fault", [None, "enabled", "missing_flag", "truthy_flag", "missing_field", "hooks"]
)
def test_inspect_accepts_only_explicitly_disabled_mcp_entries(tmp_path, monkeypatch, fault):
    data = {key: [] for key in ("mcpServers", "skills", "projectInstructions", "hooks", "plugins")}
    data["mcpServers"] = [{"name": "synthetic", "disabled": True}]
    if fault == "enabled":
        data["mcpServers"][0]["disabled"] = False
    elif fault == "missing_flag":
        data["mcpServers"][0].pop("disabled")
    elif fault == "truthy_flag":
        data["mcpServers"][0]["disabled"] = "true"
    elif fault == "missing_field":
        data.pop("mcpServers")
    elif fault == "hooks":
        data["hooks"] = [{"name": "unapproved"}]

    class Process:
        rows = iter([json.dumps(data).encode(), None])
        closed = False

        def line(self, _deadline):
            return next(self.rows)

        def finish(self, _deadline):
            return 0

        def close(self):
            self.closed = True

    process = Process()
    provider = native.GrokBuildWarningProvider()
    monkeypatch.setattr(provider, "_start", lambda *args: process)
    if fault:
        with pytest.raises(ValueError):
            provider._inspect(tmp_path, {}, 100)
    else:
        provider._inspect(tmp_path, {}, 100)
    assert process.closed


def test_native_final_answer_excludes_earlier_turn_text():
    stream = NativeStream(session_id=SID, qualification=False)
    stream.accept({"type": "available_commands", "tools": ["web_fetch"]})
    stream.accept({"type": "text", "data": "Let me search first."})
    stream.accept({"type": "usage", "stopReason": "tool_use"})
    stream.accept({"type": "thought", "data": "discard this"})
    stream.accept({"type": "text", "data": '{"candidates":'})
    stream.accept({"type": "text", "data": "[]}"})
    stream.accept({"type": "usage", "stopReason": "end_turn"})
    end = end_record()
    end["num_turns"] = 2
    end["modelUsage"][NATIVE_MODEL]["modelCalls"] = 2
    stream.accept(end)
    assert stream_result(stream).output_text == '{"candidates":[]}'


@pytest.mark.parametrize("unrelated_link", ["http://t.co/example", "/relative", "https://["])
@pytest.mark.parametrize("matching_post_link", [True, False])
def test_x_fetch_ignores_unusable_links_but_requires_exact_post_link(
    unrelated_link, matching_post_link
):
    from urllib.parse import urlencode

    from smithguard.grok_build_citations import fetched_citations

    post = "https://x.com/example/status/123456789"
    endpoint = "https://publish.x.com/oembed?" + urlencode({"url": post, "omit_script": "true"})
    linked_post = post if matching_post_link else post + "0"
    data = {
        "url": post,
        "type": "rich",
        "version": "1.0",
        "provider_url": "https://x.com",
        "html": '<blockquote class="twitter-tweet"><p>synthetic public post'
        f'<a href="{unrelated_link}">other link</a></p>'
        f'<a href="{linked_post}">date</a></blockquote>',
    }
    content = {"url": endpoint, "content": json.dumps(data)}
    assert fetched_citations(endpoint, content) == ([post] if matching_post_link else [])


def test_x_fetch_requires_exact_first_party_post_proof():
    from urllib.parse import urlencode

    from smithguard.grok_build_citations import fetched_citations

    post = "https://x.com/example/status/123456789"
    endpoint = "https://publish.x.com/oembed?" + urlencode({"url": post, "omit_script": "true"})
    data = {
        "url": post,
        "type": "rich",
        "version": "1.0",
        "provider_url": "https://x.com",
        "html": '<blockquote class="twitter-tweet"><p>synthetic public post</p>'
        f'<a href="{post}">date</a></blockquote>',
    }
    content = {"url": endpoint, "content": json.dumps(data)}
    assert fetched_citations(endpoint, content) == [post]
    assert fetched_citations(post, {"url": post, "content": "Please log in"}) == []
    assert fetched_citations(post, {"url": post, "content": data["html"]}) == []
    assert fetched_citations(endpoint, {"url": endpoint, "content": "Please log in"}) == []
    assert (
        fetched_citations(
            endpoint, {"url": endpoint, "content": json.dumps({**data, "url": post + "0"})}
        )
        == []
    )
    assert (
        fetched_citations(
            endpoint, {"url": endpoint, "content": json.dumps({**data, "html": "<p>log in</p>"})}
        )
        == []
    )
    assert (
        fetched_citations(
            endpoint,
            {
                "url": endpoint,
                "content": json.dumps({**data, "provider_url": "https://example.org"}),
            },
        )
        == []
    )
    assert (
        fetched_citations(
            endpoint,
            {
                "url": endpoint,
                "content": json.dumps(
                    {
                        **data,
                        "html": '<blockquote class="twitter-tweet"><p></p>'
                        f'<a href="{post}">date</a></blockquote>',
                    }
                ),
            },
        )
        == []
    )
    assert (
        fetched_citations(endpoint, {"url": "https://example.org/", "content": json.dumps(data)})
        == []
    )
    assert (
        fetched_citations("https://example.org/", {"url": endpoint, "content": json.dumps(data)})
        == []
    )


@pytest.mark.parametrize(
    "change",
    [
        lambda e: e.update(usage_is_incomplete=True),
        lambda e: e.update(stopReason="max_turns"),
        lambda e: e.update(sessionId=str(uuid4())),
        lambda e: e["usage"].update(total_tokens=40),
        lambda e: e["usage"].update(input_tokens=True),
        lambda e: e["modelUsage"].update({"helper-model": {}}),
        lambda e: e["modelUsage"][NATIVE_MODEL].update(modelCalls=2),
        lambda e: e.update(num_turns=4),
    ],
)
def test_native_incomplete_or_unknown_usage_never_falls_back(change):
    stream = NativeStream(session_id=SID, qualification=False)
    stream.accept({"type": "available_commands", "tools": ["web_fetch"]})
    end = end_record()
    change(end)
    stream.accept(end)
    with pytest.raises(ScheduledProviderError) as err:
        stream_result(stream)
    assert err.value.usage_uncertain and not err.value.retryable


def test_native_fetch_cites_only_requested_and_final_urls():
    stream = NativeStream(session_id=SID, qualification=False)
    stream.accept({"type": "available_commands", "tools": ["web_fetch"]})
    url = "https://github.com/advisories/GHSA-mh6f-8j2x-4483"
    stream.accept(
        {
            "type": "tool_call",
            "toolCallId": "a",
            "toolName": "web_fetch",
            "status": "pending",
            "rawInput": {"url": url},
        }
    )
    stream.accept(
        {
            "type": "tool_call_update",
            "toolCallId": "a",
            "status": "completed",
            "rawOutput": {
                "type": "WebFetch",
                "Content": {
                    "url": url,
                    "status_code": 200,
                    "content": "untrusted https://example.com/fabricated",
                },
            },
        }
    )
    stream.accept(end_record())
    assert stream_result(stream).citation_urls == (url,)


def test_native_backend_search_bound_and_helper_denial():
    stream = NativeStream(session_id=SID, qualification=False)
    for index in range(4):
        stream.accept(
            {
                "type": "tool_call",
                "toolCallId": str(index),
                "toolName": "Web search:",
                "rawInput": {"variant": "WebSearch", "backend": True},
                "status": "in_progress",
            }
        )
        stream.accept(
            {
                "type": "tool_call_update",
                "toolCallId": str(index),
                "status": "completed",
                "rawOutput": {
                    "status": "completed",
                    "action": {"sources": [{"url": "https://github.com/advisories"}]},
                },
            }
        )
    with pytest.raises(ScheduledProviderError, match="native_tool_limit"):
        stream.accept(
            {
                "type": "tool_call",
                "toolCallId": "5",
                "toolName": "Web search:",
                "rawInput": {"variant": "WebSearch", "backend": True},
                "status": "in_progress",
            }
        )
    for tool in ("run_terminal_cmd", "web_search", "read_file"):
        other = NativeStream(session_id=SID, qualification=False)
        with pytest.raises(ScheduledProviderError):
            other.accept(
                {
                    "type": "tool_call",
                    "toolCallId": "a",
                    "toolName": tool,
                    "rawInput": {},
                    "status": "pending",
                }
            )


def test_only_structured_first_empty_rate_limit_authorizes_fallback(tmp_path):
    path = tmp_path / "sessions" / "synthetic" / SID / "updates.jsonl"
    path.parent.mkdir(parents=True)
    event = {
        "params": {
            "sessionId": SID,
            "update": {
                "sessionUpdate": "turn_completed",
                "stop_reason": "rate_limit",
                "prompt_id": RID,
            },
        }
    }
    path.write_text(json.dumps(event) + "\n")
    stream = NativeStream(session_id=SID, qualification=False)
    stream.accept({"type": "error", "message": "text alone is untrusted"})
    assert native.GrokBuildWarningProvider._uncharged_rate_limit(tmp_path, SID, stream)
    event["params"]["update"]["usage"] = {"total_tokens": 0}
    path.write_text(json.dumps(event) + "\n")
    assert not native.GrokBuildWarningProvider._uncharged_rate_limit(tmp_path, SID, stream)
    event["params"]["update"].pop("usage")
    path.write_text(json.dumps(event) + "\n")
    stream.accept({"type": "thought", "data": "synthetic"})
    assert not native.GrokBuildWarningProvider._uncharged_rate_limit(tmp_path, SID, stream)


def test_clean_native_environment_never_inherits_operator_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("XAI_API_KEY", "synthetic-forbidden")
    monkeypatch.setenv("SMITHGUARD_DATABASE_URL", "synthetic-forbidden")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-forbidden")
    env = native._environment(tmp_path / "home", tmp_path / "work", tmp_path / "auth")
    assert not any("KEY" in k or "DATABASE" in k for k in env)
    assert env["GROK_MAX_RETRIES"] == "0" and env["TMPDIR"] == str(tmp_path / "work")
    assert "HOME" not in env


@pytest.mark.parametrize("failure", ["preflight", "after_start", "invalid_stream"])
def test_adapter_cleans_temporary_state_and_classifies_dispatch(tmp_path, monkeypatch, failure):
    class Process:
        bytes = 20
        closed = False

        def line(self, _deadline):
            return b'{"type":"unknown"}'

        def close(self):
            self.closed = True

    process = Process()

    def preflight(*args):
        if failure == "preflight":
            raise ValueError("synthetic")

    monkeypatch.setattr(native, "_preflight", preflight)
    provider = native.GrokBuildWarningProvider(ram=tmp_path)
    monkeypatch.setattr(provider, "_inspect", lambda *args: None)
    monkeypatch.setattr(provider, "_bootstrap", lambda *args: None)
    monkeypatch.setattr(provider, "_summary_clean", lambda *args: True)

    def start(*args):
        if failure == "after_start":
            raise RuntimeError("unknown start")
        assert list(tmp_path.glob("attempt-*"))
        return process

    monkeypatch.setattr(provider, "_start", start)
    payload = {
        "model": "grok-4.7",
        "reasoning": {"effort": "high"},
        "instructions": "public",
        "input": "public",
        "tools": [{"type": "web_search"}],
        "text": {"format": {"schema": {}}},
    }
    with pytest.raises(ScheduledProviderError) as err:
        provider.discover(payload)
    assert err.value.usage_uncertain == (failure != "preflight")
    assert not list(tmp_path.iterdir())
    if failure == "invalid_stream":
        assert process.closed


@pytest.mark.parametrize("primary_error", [None, "native_preflight_uncharged", "unknown_execution"])
def test_subscription_first_and_only_proven_uncharged_fallback(database, primary_error):
    calls = []

    class Primary(SyntheticProvider):
        credential_route = NATIVE_ROUTE

        def discover(self, payload):
            calls.append("subscription")
            if primary_error:
                raise ScheduledProviderError(
                    primary_error,
                    retryable=primary_error.startswith("native"),
                    usage_uncertain=primary_error == "unknown_execution",
                )
            return replace(super().discover(payload), credential_route=NATIVE_ROUTE)

    class Fallback(SyntheticProvider):
        credential_route = "claude_code_subscription"

        def discover(self, payload):
            calls.append("opus_subscription")
            return replace(
                super().discover(payload),
                response_id="claude-code:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222",
                native_search_requests=1,
                native_model_turns=2,
            )

    def fallback():
        calls.append("load_subscription_credential")
        return Fallback(_discovery_result())

    provider = SubscriptionFirstProvider(
        primary=Primary(_discovery_result()), fallback_factory=fallback
    )
    policy = _active_policy()
    factory = sessionmaker(database.engine)
    with factory() as session, session.begin():
        enqueue_due_discovery(session, policy=policy, now=NOW)
    first = work_one(
        factory,
        policy=policy,
        provider=provider,
        worker_id="synthetic",
        now=NOW + timedelta(minutes=1),
    )
    assert calls == ["subscription"]
    if primary_error == "native_preflight_uncharged":
        assert first.outcome == "retry_wait"
        second = work_one(
            factory,
            policy=policy,
            provider=provider,
            worker_id="synthetic2",
            now=NOW + timedelta(minutes=7),
        )
        assert second.outcome == "succeeded"
        assert calls == ["subscription", "load_subscription_credential", "opus_subscription"]
        with factory() as session:
            routes = [
                r["public_metadata"].get("credential_route")
                for r in _receipts(session)
                if r["receipt_type"] == "provider_request_started"
            ]
        assert routes == [NATIVE_ROUTE, "claude_code_subscription"]
    elif primary_error:
        assert first.outcome == "dead_letter"
    else:
        assert first.outcome == "succeeded"


def test_second_attempt_without_proven_native_failure_cannot_load_api():
    provider = SubscriptionFirstProvider(
        primary=object(), fallback_factory=lambda: pytest.fail("paid route")
    )
    with pytest.raises(ValueError):
        provider.for_attempt(attempt=2, prior_uncharged_native=False)


def test_missing_fallback_key_closes_without_dispatch(database):
    class Primary:
        credential_route = NATIVE_ROUTE

        def discover(self, _payload):
            raise ScheduledProviderError(
                "native_preflight_uncharged", retryable=True, usage_uncertain=False
            )

    def missing_key():
        raise FileNotFoundError("synthetic absent credential")

    provider = SubscriptionFirstProvider(primary=Primary(), fallback_factory=missing_key)
    policy = _active_policy()
    factory = sessionmaker(database.engine)
    with factory() as session, session.begin():
        enqueue_due_discovery(session, policy=policy, now=NOW)
    assert (
        work_one(
            factory,
            policy=policy,
            provider=provider,
            worker_id="one",
            now=NOW + timedelta(minutes=1),
        ).outcome
        == "retry_wait"
    )
    assert (
        work_one(
            factory,
            policy=policy,
            provider=provider,
            worker_id="two",
            now=NOW + timedelta(minutes=7),
        ).outcome
        == "dead_letter"
    )
    with factory() as session:
        receipts = _receipts(session)
    assert sum(r["receipt_type"] == "provider_request_started" for r in receipts) == 1
    assert receipts[-1]["reason_code"] == "claude_preflight_uncharged"


def test_native_rejects_synthetic_snake_case_usage_alias():
    stream = NativeStream(session_id=SID, qualification=True)
    stream.accept({"type": "available_commands", "tools": []})
    event = end_record()
    event["model_usage"] = event.pop("modelUsage")
    stream.accept(event)
    with pytest.raises(ScheduledProviderError):
        stream_result(stream)


@pytest.mark.parametrize(
    "output",
    [
        {
            "Content": {
                "status_code": 404,
                "content": "Not found",
                "url": "https://github.com/advisories",
            }
        },
        {"DomainNotAllowed": "github.com"},
        {
            "CrossHostRedirect": {
                "original_host": "github.com",
                "redirect_url": "https://example.org/",
            }
        },
        {"Error": {"url": "https://github.com/advisories", "message": "synthetic failure"}},
    ],
)
def test_completed_failed_fetch_keeps_usage_without_citations(output):
    stream = NativeStream(session_id=SID, qualification=False)
    stream.accept({"type": "available_commands", "tools": ["web_fetch"]})
    stream.accept(
        {
            "type": "tool_call",
            "toolCallId": "fetch",
            "toolName": "web_fetch",
            "status": "pending",
            "rawInput": {"url": "https://github.com/advisories"},
        }
    )
    stream.accept(
        {
            "type": "tool_call_update",
            "toolCallId": "fetch",
            "status": "failed",
            "rawOutput": {"type": "WebFetch", **output},
        }
    )
    stream.accept(end_record())
    result = stream_result(stream)
    assert result.server_side_tool_calls == 1 and result.total_tokens == 41
    assert result.citation_urls == ()


@pytest.mark.parametrize(
    "fault", [None, "completed", "unknown_error", "extra", "missing", "message_type"]
)
def test_native_fetch_runtime_failure_preserves_only_complete_usage(fault):
    stream = NativeStream(session_id=SID, qualification=False)
    stream.accept({"type": "available_commands", "tools": ["web_fetch"]})
    stream.accept(
        {
            "type": "tool_call",
            "toolCallId": "fetch",
            "toolName": "web_fetch",
            "status": "pending",
            "rawInput": {"url": "https://example.org/"},
        }
    )
    output = {"error": "tool_execution_failed", "message": "SSRF blocked: synthetic private IP"}
    status = "failed"
    if fault == "completed":
        status = "completed"
    elif fault == "unknown_error":
        output["error"] = "unknown"
    elif fault == "extra":
        output["url"] = "https://example.org/"
    elif fault == "missing":
        del output["message"]
    elif fault == "message_type":
        output["message"] = None
    event = {
        "type": "tool_call_update",
        "toolCallId": "fetch",
        "status": status,
        "rawOutput": output,
    }
    if fault:
        with pytest.raises(ScheduledProviderError) as err:
            stream.accept(event)
        assert err.value.usage_uncertain and not err.value.retryable
        return
    stream.accept(event)
    with pytest.raises(ScheduledProviderError) as err:
        stream_result(stream)
    assert err.value.usage_uncertain and not err.value.retryable
    stream.accept(end_record())
    result = stream_result(stream)
    assert result.server_side_tool_calls == 1 and result.total_tokens == 41
    assert result.citation_urls == ()


def test_native_search_profile_preserves_lane_filters_and_closes_qualification():
    from smithguard.grok_build_tools import search_profile

    x = {"type": "x_search", "from_date": "2026-09-26", "to_date": "2026-09-27"}
    profile = search_profile({"tools": [x]}, qualification=False)
    assert profile["tools"] == ["x_search", "web_fetch"]
    assert profile["injectDefaultTools"] is False
    assert profile["toolConfig"] == {"tools": [{"id": "GrokBuild:web_fetch"}]}
    assert profile["disallowedTools"] == ["web_search"]
    assert profile["toolOverrides"] == {
        "xSearch": {"dateBound": {"fromDate": "2026-09-26", "toDate": "2026-09-27"}}
    }
    with pytest.raises(ValueError, match="X filter unsupported"):
        search_profile({"tools": [{**x, "allowed_x_handles": ["synthetic"]}]}, qualification=False)
    profile = search_profile(
        {"tools": [{"type": "web_search", "filters": {"allowed_domains": ["github.com"]}}]},
        qualification=False,
    )
    assert profile["tools"] == ["web_search"]
    assert profile["toolOverrides"] == {"webSearch": {"allowedDomains": ["github.com"]}}
    profile = search_profile({"tools": []}, qualification=True)
    assert not set(profile["tools"]) - set(profile["disallowedTools"])
    assert "x_search" in profile["disallowedTools"]


@pytest.mark.parametrize("tool_name", ["X search:", "x_search"])
@pytest.mark.parametrize(
    "operation", ["x_user_search", "x_keyword_search", "x_semantic_search", "x_thread_fetch"]
)
def test_x_search_call_counts_but_query_is_not_a_citation(tool_name, operation):
    stream = NativeStream(session_id=SID, qualification=False, allowed={"x_search", "web_fetch"})
    stream.accept({"type": "available_commands", "tools": ["web_fetch"]})
    stream.accept(
        {
            "type": "tool_call",
            "toolCallId": "x",
            "toolName": tool_name,
            "status": "in_progress",
            "rawInput": {"variant": "XSearch", "backend": True},
        }
    )
    stream.accept(
        {
            "type": "tool_call_update",
            "toolCallId": "x",
            "status": "completed",
            "rawOutput": {
                "id": "x",
                "call_id": "call-x",
                "name": operation,
                "input": "https://example.org/not-evidence",
            },
        }
    )
    stream.accept(end_record())
    assert stream_result(stream).server_side_tool_calls == 1
    assert stream_result(stream).citation_urls == ()
    forbidden = NativeStream(session_id=SID, qualification=False, allowed={"web_search"})
    with pytest.raises(ScheduledProviderError, match="unapproved"):
        forbidden.accept(
            {
                "type": "tool_call",
                "toolCallId": "x",
                "toolName": tool_name,
                "status": "in_progress",
                "rawInput": {"variant": "XSearch", "backend": True},
            }
        )


@pytest.mark.parametrize("tool", ["grok", "claude"])
def test_pinned_installer_verifies_bytes_and_never_replaces_unknown_file(
    tmp_path, monkeypatch, tool
):
    import hashlib
    import io
    import os
    from importlib import import_module

    installer = import_module(f"smithguard.{tool}_build_install")

    binary = tmp_path / "tool-dir" / tool
    payload = b"synthetic public binary"
    monkeypatch.setattr(installer, f"{tool.upper()}_BINARY", binary)
    monkeypatch.setattr(installer, f"{tool.upper()}_SHA256", hashlib.sha256(payload).hexdigest())
    monkeypatch.setattr(installer, "BINARY_BYTES", len(payload))
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0)
    original = Path.stat

    def root_metadata(self, **kwargs):
        result = original(self, **kwargs)
        if self in (binary.parent, binary):
            fields = list(result)
            fields[4] = 0
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(Path, "stat", root_metadata)
    monkeypatch.setattr(Path, "lstat", lambda self: root_metadata(self, follow_symlinks=False))
    calls = []

    def download(url, timeout):
        calls.append((url, timeout))
        return io.BytesIO(payload)

    monkeypatch.setattr(installer.urllib.request, "urlopen", download)
    installer.install()
    assert binary.read_bytes() == payload
    installer.install()
    assert len(calls) == 1
    binary.write_bytes(b"unknown")
    with pytest.raises(ValueError, match="no replacement"):
        installer.install()
    assert binary.read_bytes() == b"unknown"
    assert not list(binary.parent.glob(f".{tool}-download-*"))


def test_old_api_retry_is_not_native_fallback_authority(database):
    calls = []

    class OldApi:
        credential_route = "api_key"

        def discover(self, _payload):
            raise ScheduledProviderError(
                "provider_http_error_uncharged", retryable=True, usage_uncertain=False
            )

    policy = _active_policy()
    factory = sessionmaker(database.engine)
    with factory() as session, session.begin():
        enqueue_due_discovery(session, policy=policy, now=NOW)
    first = work_one(
        factory, policy=policy, provider=OldApi(), worker_id="old", now=NOW + timedelta(minutes=1)
    )
    assert first.outcome == "dead_letter"
    provider = SubscriptionFirstProvider(
        primary=object(), fallback_factory=lambda: calls.append("api")
    )
    second = work_one(
        factory, policy=policy, provider=provider, worker_id="new", now=NOW + timedelta(minutes=7)
    )
    assert second.outcome == "idle" and calls == []


def test_process_bounds_output_and_always_reaps(tmp_path, monkeypatch):
    import sys
    from time import monotonic

    monkeypatch.setattr(native, "MAX_BYTES", 128)
    process = native._Process(
        [sys.executable, "-c", 'import sys; sys.stderr.write("x"*1024)'], cwd=tmp_path, env={}
    )
    try:
        with pytest.raises(ValueError, match="bound"):
            process.line(monotonic() + 5)
    finally:
        process.close()
    assert process.process.poll() is not None
    process = native._Process(
        [sys.executable, "-c", "import time; time.sleep(10)"], cwd=tmp_path, env={}
    )
    try:
        with pytest.raises(TimeoutError):
            process.line(monotonic() + 0.05)
    finally:
        process.close()
    assert process.process.poll() is not None


def test_native_configuration_omits_output_caps_and_keeps_model_controls():
    import tomllib

    config = tomllib.loads(native._configuration())
    assert "max_completion_tokens" not in config["models"]
    assert "max_completion_tokens" not in config["model"]["grok-4.7"]
    assert config["model"]["grok-4.7"]["reasoning_effort"] == "high"
    assert config["model"]["grok-4.7"]["max_retries"] == 0


@pytest.mark.parametrize("qualification", [False, True])
@pytest.mark.parametrize("output", [2786, 8193, 600001])
def test_native_complete_output_exceeds_retired_caps(qualification, output):
    stream = NativeStream(session_id=SID, qualification=qualification)
    stream.accept({"type": "available_commands", "tools": [] if qualification else ["web_fetch"]})
    stream.accept({"type": "text", "data": '{"synthetic":true}'})
    end = end_record()
    end["usage"]["output_tokens"] = output
    end["usage"]["reasoning_tokens"] = output - 1
    end["usage"]["total_tokens"] = 33 + output
    end["modelUsage"][NATIVE_MODEL]["outputTokens"] = output
    stream.accept(end)
    result = stream_result(stream)
    assert result.output_tokens == output and result.reasoning_tokens == output - 1
    assert result.total_tokens == 33 + output
    assert result.output_text == '{"synthetic":true}'


@pytest.mark.parametrize("lane", ["open_web_scout", "wide_semantic", "primary_pivot"])
def test_native_workload_guidance_preserves_real_lead_request_boundaries(lane):
    from copy import deepcopy

    from smithguard.discovery import DiscoveryRequest, build_discovery_payload
    from smithguard.emerging_pipeline import lead_discovery_payload
    from smithguard.identifiers import canonical_json_bytes
    from smithguard.lead_protocol import DISCOVERY_SCHEMA

    payload = lead_discovery_payload(
        build_discovery_payload(
            DiscoveryRequest(
                lane=lane,
                objective="Find public security reports.",
                from_date=NOW.date() - timedelta(days=3),
                to_date=NOW.date(),
                allowed_web_domains=("github.com",) if lane == "primary_pivot" else (),
            )
        )
    )
    inputs = json.loads(payload["input"])
    inputs["enrichment_targets"] = [{"subject": "synthetic", "source_url": "https://example.org"}]
    payload["input"] = json.dumps(inputs, sort_keys=True)
    original = deepcopy(payload)
    original_bytes = canonical_json_bytes(payload)
    raw = native._prompt(payload, qualification=False)
    document = json.loads(raw)

    # Native guidance never rewrites the paid request, trusted instructions or source data.
    assert payload == original and canonical_json_bytes(payload) == original_bytes
    assert document["instructions"] == original["instructions"]
    assert document["input"] == original["input"]
    assert document["search_boundary"] == original["tools"]
    assert document["required_output_schema"] == DISCOVERY_SCHEMA
    assert document["required_output_schema"]["properties"]["leads"]["maxItems"] == 4
    assert document["native_prompt_version"] == "smithguard-native-discovery-v2"
    assert "one focused search" in document["workload_guidance"]
    assert "original-source citation binding" in document["workload_guidance"]
    assert "Never invent evidence" in document["workload_guidance"]
    assert "https://publish.x.com/oembed" in document["tool_rule"]
    assert "An ordinary X page or login shell is not post evidence" in document["tool_rule"]
    assert raw == native._prompt(original, qualification=False) and len(raw) < 65_536


def test_native_workload_guidance_leaves_qualification_prompt_bytes_unchanged():
    from smithguard.identifiers import canonical_json_bytes

    payload = {
        "instructions": "Triage supplied public context without tools.",
        "input": '{"context":null}',
        "tools": [],
        "text": {"format": {"schema": {"type": "object"}}},
    }
    previous_document = {
        "instructions": payload["instructions"],
        "input": payload["input"],
        "required_output_schema": payload["text"]["format"]["schema"],
        "search_boundary": [],
        "tool_rule": "Use no tools. Return only the required JSON.",
    }
    assert native._prompt(payload, qualification=True) == canonical_json_bytes(previous_document)


@pytest.mark.parametrize(
    "fault",
    [
        "tools",
        "session",
        "missing",
        "agent_message_chunk",
        "agent_thought_chunk",
        "tool_call",
        "tool_call_update",
    ],
)
def test_bootstrap_rejects_changed_tools_and_early_inference(tmp_path, monkeypatch, fault):
    rows = [
        json.dumps({"id": 1, "result": {}}).encode(),
        json.dumps({"id": 2, "result": {"sessionId": SID}}).encode(),
        json.dumps({"id": 3, "result": {"success": True}}).encode(),
    ]
    event = {
        "method": "session/update",
        "params": {
            "sessionId": SID,
            "update": {
                "sessionUpdate": "available_commands_update",
                "_meta": {"tools": ["web_fetch"]},
            },
        },
    }
    if fault == "tools":
        event["params"]["update"]["_meta"]["tools"].append("run_terminal_cmd")
    elif fault == "session":
        event["params"]["sessionId"] = RID
    elif fault != "missing":
        event["params"]["update"]["sessionUpdate"] = fault
    if fault != "missing":
        rows.append(json.dumps(event).encode())
    rows.append(None)

    class Process:
        closed = False

        def send(self, _value):
            pass

        def line(self, _deadline):
            return rows.pop(0)

        def close(self):
            self.closed = True

    process = Process()
    provider = native.GrokBuildWarningProvider()
    monkeypatch.setattr(provider, "_start", lambda *args: process)
    with pytest.raises((ValueError, ScheduledProviderError)):
        provider._bootstrap(
            tmp_path,
            {},
            SID,
            100,
            {"toolConfig": {"tools": [{"id": "GrokBuild:web_fetch"}]}, "disallowedTools": []},
        )
    assert process.closed


def test_native_agent_flag_placement(tmp_path, monkeypatch):
    commands = []
    monkeypatch.setattr(native, "_Process", lambda args, **kwargs: commands.append(args))
    provider = native.GrokBuildWarningProvider()
    provider._start(["agent", "--no-leader", "stdio"], tmp_path, {})
    provider._start(["inspect", "--json"], tmp_path, {})
    assert commands[0] == [
        str(native.GROK_BINARY),
        "--no-auto-update",
        "agent",
        "--no-leader",
        "stdio",
    ]
    assert commands[1] == [
        str(native.GROK_BINARY),
        "--no-auto-update",
        "--no-leader",
        "inspect",
        "--json",
    ]


@pytest.mark.parametrize("profile_kind", ["qualification", "restricted", "x"])
@pytest.mark.parametrize("fault", ["none", "background", "tools"])
def test_headless_arguments_preserve_native_boundaries(tmp_path, monkeypatch, profile_kind, fault):
    import tomllib

    qualification = profile_kind == "qualification"
    restricted = profile_kind == "restricted"
    background = fault == "background"
    expected_tools = [] if qualification or restricted else ["web_fetch"]
    advertised_tools = (
        (["web_fetch"] if not expected_tools else ["web_fetch", "run_terminal_cmd"])
        if fault == "tools"
        else expected_tools
    )

    monkeypatch.setattr(native, "uuid4", lambda: SID)

    seen = []
    monkeypatch.setattr(native, "_preflight", lambda *args: None)
    provider = native.GrokBuildWarningProvider(ram=tmp_path)
    monkeypatch.setattr(provider, "_inspect", lambda *args: None)
    monkeypatch.setattr(provider, "_bootstrap", lambda *args: None)
    summaries = iter([True, not background])
    monkeypatch.setattr(provider, "_summary_clean", lambda *args: next(summaries))

    class Process:
        bytes = 100

        def __init__(self):
            self.rows = iter(
                [
                    json.dumps(
                        {
                            "type": "available_commands",
                            "tools": advertised_tools,
                        }
                    ).encode(),
                    json.dumps(usage_record()).encode(),
                    json.dumps(end_record()).encode(),
                    None,
                ]
            )

        def line(self, _deadline):
            return next(self.rows)

        def finish(self, _deadline):
            return 0

        def close(self):
            pass

    def start(args, work, env):
        prompt = Path(args[args.index("--prompt-file") + 1])
        profile = Path(args[args.index("--agent") + 1])
        document = json.loads(prompt.read_text())
        assert prompt.name == "prompt.txt" and isinstance(document, dict)
        if qualification:
            assert "native_prompt_version" not in document and "workload_guidance" not in document
        else:
            assert document["native_prompt_version"] == "smithguard-native-discovery-v2"
            assert "one focused search" in document["workload_guidance"]
        assert profile.name == "profile.md"
        data = json.loads(profile.read_text().split("---")[1])
        assert data["injectDefaultTools"] is False
        assert data["toolConfig"]["tools"] == [{"id": "GrokBuild:web_fetch"}]
        assert args[args.index("--tools") + 1] == (
            "web_search" if qualification or restricted else "x_search,web_fetch"
        )
        denied = set(args[args.index("--disallowed-tools") + 1].split(","))
        assert {"run_terminal_cmd", "read_file", "write_file"} <= denied
        assert ("web_search" in denied) is (not restricted)
        if qualification or restricted:
            assert {"x_search", "web_fetch"} <= denied
        assert args[args.index("--max-turns") + 1] == "1"
        config = tomllib.loads((Path(env["GROK_HOME"]) / "config.toml").read_text())
        assert "max_completion_tokens" not in config["model"]["grok-4.7"]
        assert "max_completion_tokens" not in config["models"]
        assert config["doom_loop_recovery"] == {"enabled": False, "max_retries": 0}
        assert env["GROK_DOOM_LOOP_RECOVERY"] == "0"
        seen.append(True)
        return Process()

    monkeypatch.setattr(provider, "_start", start)
    payload = {
        "model": "grok-4.7",
        "reasoning": {"effort": "high"},
        "instructions": "public",
        "input": "public",
        "tools": []
        if qualification
        else [{"type": "web_search", "filters": {"allowed_domains": ["github.com"]}}]
        if restricted
        else [{"type": "x_search", "from_date": "2026-09-26", "to_date": "2026-09-27"}],
        "text": {"format": {"schema": {}}},
    }
    if fault == "tools":
        with pytest.raises(ScheduledProviderError, match="native_tools_changed") as err:
            (provider.qualify if qualification else provider.discover)(payload)
        assert err.value.usage_uncertain and not err.value.retryable
    elif background:
        with pytest.raises(ScheduledProviderError, match="native_background_activity") as err:
            (provider.qualify if qualification else provider.discover)(payload)
        assert not err.value.retryable and not err.value.usage_uncertain
        assert err.value.exact_usage.total_tokens == 41
    else:
        (provider.qualify if qualification else provider.discover)(payload)
    assert seen == [True] and not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "tools",
    [
        [],
        ["web_search"],
        ["web_fetch", "web_search"],
        ["web_fetch", "x_search"],
        ["run_terminal_cmd"],
    ],
)
def test_headless_requires_exact_local_tool_registry(tools):
    stream = NativeStream(session_id=SID, qualification=False)
    with pytest.raises(ScheduledProviderError, match="native_tools_changed"):
        stream.accept({"type": "available_commands", "tools": tools})


def test_bad_search_citations_preserve_usage_and_ignore_pre_tool_text():
    stream = NativeStream(session_id=SID, qualification=False)
    stream.accept({"type": "available_commands", "tools": ["web_fetch"]})
    stream.accept({"type": "text", "data": "I will search."})
    stream.accept(
        {
            "type": "tool_call",
            "toolCallId": "search",
            "toolName": "web_search",
            "rawInput": {"variant": "WebSearch", "backend": True},
            "status": "in_progress",
        }
    )
    stream.accept(
        {
            "type": "tool_call_update",
            "toolCallId": "search",
            "status": "completed",
            "rawOutput": {
                "status": "completed",
                "action": {
                    "sources": [
                        {"url": "http://example.org/bad"},
                        {"url": "https://example.org/good"},
                        {"url": None},
                    ]
                },
            },
        }
    )
    stream.accept({"type": "text", "data": "{}"})
    stream.accept(end_record())
    result = stream_result(stream)
    assert result.total_tokens == 41 and result.output_text == "{}"
    assert result.citation_urls == ("https://example.org/good",)


@pytest.mark.parametrize("url", ["http://example.org/bad", None])
def test_unusable_fetch_final_url_does_not_erase_exact_usage(url):
    stream = NativeStream(session_id=SID, qualification=False)
    stream.accept({"type": "available_commands", "tools": ["web_fetch"]})
    stream.accept(
        {
            "type": "tool_call",
            "toolCallId": "fetch",
            "toolName": "web_fetch",
            "rawInput": {"url": "https://example.org/requested"},
            "status": "pending",
        }
    )
    content = {"status_code": 200, "content": "public text"}
    if url is not None:
        content["url"] = url
    stream.accept(
        {
            "type": "tool_call_update",
            "toolCallId": "fetch",
            "status": "completed",
            "rawOutput": {"type": "WebFetch", "Content": content},
        }
    )
    stream.accept(end_record())
    if url is None:
        with pytest.raises(ScheduledProviderError, match="native_output_invalid") as err:
            stream_result(stream)
        assert not err.value.usage_uncertain and not err.value.retryable
        assert err.value.exact_usage.total_tokens == 41
    else:
        result = stream_result(stream)
        assert result.citation_urls == () and result.total_tokens == 41


@pytest.mark.parametrize(
    "reason",
    [
        "max_tokens",
        "max_turn_requests",
        "refusal",
        "cancelled",
        "turn_limit_event",
        "process_failure",
    ],
)
def test_complete_incomplete_end_retains_usage_without_retry(reason):
    stream = NativeStream(session_id=SID, qualification=True)
    stream.accept({"type": "available_commands", "tools": []})
    if reason == "turn_limit_event":
        stream.accept({"type": "max_turns_reached"})
    end = end_record()
    if reason not in {"turn_limit_event", "process_failure"}:
        end["stopReason"] = reason
    stream.accept(end)
    with pytest.raises(ScheduledProviderError, match="native_response_incomplete") as err:
        stream.result(
            request_bytes=100,
            response_bytes=200,
            elapsed_ms=20,
            execution_failed=reason == "process_failure",
        )
    assert not err.value.usage_uncertain and not err.value.retryable
    assert err.value.exact_usage.total_tokens == 41


@pytest.mark.parametrize("limit", [True, 0, 2730, 8192, 8193, "512"])
def test_native_capped_request_refuses_before_dispatch(monkeypatch, tmp_path, limit):
    monkeypatch.setattr(native, "_preflight", lambda *args: None)
    provider = native.GrokBuildWarningProvider(ram=tmp_path)
    with pytest.raises(ScheduledProviderError) as caught:
        provider.qualify(
            {
                "model": "grok-4.7",
                "reasoning": {"effort": "high"},
                "max_output_tokens": limit,
                "tools": [],
                "input": "synthetic",
            }
        )
    assert caught.value.code == "provider_request_output_limit_invalid"
    assert not caught.value.retryable and not caught.value.usage_uncertain
    assert not list(tmp_path.iterdir())


def test_process_kills_group_before_waiting_or_closing_stdin(monkeypatch):
    from types import SimpleNamespace

    actions = []
    monkeypatch.setattr(native.os, "killpg", lambda pid, sig: actions.append(("kill", pid, sig)))
    process = native._Process.__new__(native._Process)
    process.process = SimpleNamespace(
        pid=12345,
        stdin=SimpleNamespace(close=lambda: actions.append("stdin")),
        stdout=None,
        stderr=None,
        wait=lambda **kwargs: actions.append("reap"),
    )
    process.selector = SimpleNamespace(close=lambda: actions.append("selector"))
    process.close()
    assert actions == [("kill", 12345, native.signal.SIGKILL), "stdin", "reap", "selector"]


@pytest.mark.parametrize("prior_inference", [False, True])
def test_native_structured_quota_request_routes_through_durable_fallback(
    database, tmp_path, monkeypatch, prior_inference
):
    calls = []
    monkeypatch.setattr(native, "uuid4", lambda: SID)
    monkeypatch.setattr(native, "_preflight", lambda *args: None)
    primary = native.GrokBuildWarningProvider(ram=tmp_path)
    monkeypatch.setattr(primary, "_inspect", lambda *args: None)
    monkeypatch.setattr(primary, "_bootstrap", lambda *args: None)
    monkeypatch.setattr(primary, "_summary_clean", lambda *args: True)

    class Process:
        bytes = 100

        def __init__(self):
            events = (
                [{"type": "thought", "data": "discard synthetic thought"}]
                if prior_inference
                else []
            ) + [{"type": "error", "message": "untrusted prose"}]
            self.rows = iter([json.dumps(e).encode() for e in events] + [None])

        def line(self, _deadline):
            return next(self.rows)

        def finish(self, _deadline):
            return 1

        def close(self):
            pass

    def start(_args, _work, env):
        calls.append("native_request")
        target = Path(env["GROK_HOME"]) / "sessions" / "synthetic" / SID / "updates.jsonl"
        target.parent.mkdir(parents=True)
        target.write_text(
            json.dumps(
                {
                    "params": {
                        "sessionId": SID,
                        "update": {
                            "sessionUpdate": "turn_completed",
                            "stop_reason": "rate_limit",
                            "prompt_id": RID,
                        },
                    }
                }
            )
            + "\n"
        )
        return Process()

    monkeypatch.setattr(primary, "_start", start)

    class Fallback(SyntheticProvider):
        credential_route = "claude_code_subscription"

        def discover(self, payload):
            calls.append("opus_request")
            return replace(
                super().discover(payload),
                response_id="claude-code:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222",
                native_search_requests=1,
                native_model_turns=2,
            )

    def fallback():
        calls.append("opus_credential")
        return Fallback(_discovery_result())

    provider = SubscriptionFirstProvider(primary=primary, fallback_factory=fallback)
    factory = sessionmaker(database.engine)
    policy = _active_policy()
    with factory() as session, session.begin():
        enqueue_due_discovery(session, policy=policy, now=NOW)
    first = work_one(
        factory,
        policy=policy,
        provider=provider,
        worker_id="synthetic",
        now=NOW + timedelta(minutes=1),
    )
    assert calls == ["native_request"] and not list(tmp_path.iterdir())
    if prior_inference:
        assert first.outcome == "dead_letter"
        return
    assert first.outcome == "retry_wait"
    with factory() as session:
        receipts = _receipts(session)
        assert any(r["reason_code"] == "provider_http_error_uncharged" for r in receipts)
    second = work_one(
        factory,
        policy=policy,
        provider=provider,
        worker_id="synthetic2",
        now=NOW + timedelta(minutes=7),
    )
    assert second.outcome == "succeeded"
    assert calls == ["native_request", "opus_credential", "opus_request"]
    with factory() as session:
        routes = [
            r["public_metadata"].get("credential_route")
            for r in _receipts(session)
            if r["receipt_type"] == "provider_request_started"
        ]
    assert routes == [NATIVE_ROUTE, "claude_code_subscription"]


def test_non_acp_commands_receive_eof_instead_of_an_open_stdin(tmp_path):
    import sys
    from time import monotonic

    process = native._Process(
        [sys.executable, "-c", "import sys; print(len(sys.stdin.read()))"], cwd=tmp_path, env={}
    )
    try:
        assert process.process.stdin is None
        assert process.line(monotonic() + 5) == b"0"
        assert process.finish(monotonic() + 5) == 0
    finally:
        process.close()


@pytest.mark.parametrize("incomplete", [False, True])
def test_cleanup_failure_keeps_exact_usage_and_marks_unit_for_teardown(
    tmp_path, monkeypatch, incomplete
):

    monkeypatch.setattr(native, "_preflight", lambda *args: None)
    monkeypatch.setattr(native, "uuid4", lambda: SID)
    provider = native.GrokBuildWarningProvider(ram=tmp_path)
    monkeypatch.setattr(provider, "_inspect", lambda *args: None)
    monkeypatch.setattr(provider, "_bootstrap", lambda *args: None)
    monkeypatch.setattr(provider, "_summary_clean", lambda *args: True)
    original = native.tempfile.TemporaryDirectory

    class CleanupFailure:
        def __init__(self, **kwargs):
            self.real = original(**kwargs)
            self.name = self.real.name

        def cleanup(self):
            self.real.cleanup()
            raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(native.tempfile, "TemporaryDirectory", CleanupFailure)

    class Process:
        bytes = 100

        def __init__(self):
            end = end_record()
            if incomplete:
                end["stopReason"] = "max_tokens"
            self.rows = iter(
                [
                    json.dumps({"type": "available_commands", "tools": []}).encode(),
                    json.dumps(end).encode(),
                    None,
                ]
            )

        def line(self, _deadline):
            return next(self.rows)

        def finish(self, _deadline):
            return 0

        def close(self):
            pass

    monkeypatch.setattr(provider, "_start", lambda *args: Process())
    payload = {
        "model": "grok-4.7",
        "reasoning": {"effort": "high"},
        "instructions": "public",
        "input": "public",
        "tools": [],
        "text": {"format": {"schema": {}}},
    }
    with pytest.raises(ScheduledProviderError, match="native_cleanup_failed") as err:
        provider.qualify(payload)
    assert err.value.exact_usage.total_tokens == 41 and not err.value.usage_uncertain
    assert not err.value.retryable and provider.cleanup_failed
    assert not list(tmp_path.iterdir())
    assert err.value.native_diagnostic.phase == "ram_cleanup"
    assert err.value.native_diagnostic.exception_category == "filesystem"
    assert err.value.native_diagnostic.observed_stream_events == 2
    assert err.value.native_diagnostic.stream_bytes == 100


def test_expired_lease_without_dispatch_is_documented_fail_closed(database):
    from smithguard.scheduled_discovery import _lease_work

    class Primary:
        def discover(self, _payload):
            pytest.fail("missing prior dispatch cannot silently restart native")

    provider = SubscriptionFirstProvider(
        primary=Primary(), fallback_factory=lambda: pytest.fail("paid route")
    )
    factory = sessionmaker(database.engine)
    policy = _active_policy()
    with factory() as session, session.begin():
        enqueue_due_discovery(session, policy=policy, now=NOW)
        leased = _lease_work(session, worker_id="crashed", now=NOW + timedelta(minutes=1))
        assert leased is not None
    result = work_one(
        factory, policy=policy, provider=provider, worker_id="next", now=NOW + timedelta(minutes=12)
    )
    assert result.outcome == "dead_letter"
    with factory() as session:
        receipts = _receipts(session)
    assert any(r["reason_code"] == "native_fallback_not_authorized" for r in receipts)
    assert not any(r["receipt_type"] == "provider_request_started" for r in receipts)


@pytest.mark.parametrize("fault", ["turns", "input"])
def test_consistent_over_envelope_usage_preserves_request_identity(fault):
    stream = NativeStream(session_id=SID, qualification=False)
    stream.accept({"type": "available_commands", "tools": ["web_fetch"]})
    end = end_record()
    if fault == "turns":
        end["num_turns"] = end["modelUsage"][NATIVE_MODEL]["modelCalls"] = 4
    else:
        end["usage"]["input_tokens"] = 1_600_000
        end["modelUsage"][NATIVE_MODEL]["inputTokens"] = 1_600_000
    end["usage"]["total_tokens"] = sum(
        end["usage"][k]
        for k in (
            "input_tokens",
            "cache_read_input_tokens",
            "cache_creation_input_tokens",
            "output_tokens",
        )
    )
    stream.accept(end)
    with pytest.raises(ScheduledProviderError, match="provider_token_usage_exceeded") as err:
        stream_result(stream)
    assert not err.value.retryable and not err.value.usage_uncertain
    exact = err.value.exact_usage
    assert exact.response_id == f"grok-build:{SID}:{RID}"
    assert exact.total_tokens == end["usage"]["total_tokens"]
    assert exact.output_tokens == end["usage"]["output_tokens"]


@pytest.mark.parametrize(
    "field",
    [
        None,
        "last_turn_summary",
        "last_recap",
        "generated_title",
        "session_summary",
        "title_is_manual",
        "missing",
    ],
)
def test_summary_check_distinguishes_manual_title_from_background_generation(tmp_path, field):
    parent = tmp_path / "sessions" / "synthetic" / SID
    parent.mkdir(parents=True)
    value = {
        "title_is_manual": True,
        "generated_title": native.MANUAL_TITLE,
        "session_summary": native.MANUAL_TITLE,
        "last_turn_summary": None,
        "last_recap": None,
    }
    if field is not None and field != "missing":
        value[field] = False if field == "title_is_manual" else "synthetic unexpected summary"
    if field != "missing":
        (parent / "summary.json").write_text(json.dumps(value))
    assert native.GrokBuildWarningProvider._summary_clean(tmp_path, SID) == (field is None)


def test_background_features_and_extra_retry_are_explicitly_disabled(tmp_path):
    import tomllib

    config = tomllib.loads(native._configuration())
    for name in ("turn_summary", "session_recap", "title_refresh", "turn_transient_retry"):
        assert config["features"][name] is False
    env = native._environment(tmp_path, tmp_path, tmp_path / "synthetic-auth")
    for name in (
        "GROK_TURN_SUMMARY",
        "GROK_SESSION_RECAP",
        "GROK_TITLE_REFRESH",
        "GROK_WORKFLOWS",
        "GROK_TURN_TRANSIENT_RETRY",
    ):
        assert env[name] == "0"


@pytest.mark.parametrize("fault", ["request", "timeout"])
def test_bootstrap_activity_anomaly_is_uncertain(tmp_path, monkeypatch, fault):
    class Process:
        closed = False

        def send(self, _value):
            pass

        def line(self, _deadline):
            if fault == "timeout":
                raise TimeoutError("synthetic")
            return b'{"jsonrpc":"2.0","id":99,"method":"session/request_permission"}'

        def close(self):
            self.closed = True

    process = Process()
    provider = native.GrokBuildWarningProvider()
    monkeypatch.setattr(provider, "_start", lambda *args: process)
    with pytest.raises(ScheduledProviderError) as err:
        provider._bootstrap(
            tmp_path, {}, SID, 100, {"toolConfig": {"tools": []}, "disallowedTools": []}
        )
    assert err.value.usage_uncertain and not err.value.retryable and process.closed


@pytest.mark.parametrize("kind", ["malformed", "duplicate", "unreadable"])
def test_unreadable_summary_is_anomaly_not_preflight_retry(tmp_path, monkeypatch, kind):
    parent = tmp_path / "sessions" / "synthetic" / SID
    parent.mkdir(parents=True)
    file = parent / "summary.json"
    file.write_text(
        '{"title_is_manual":true,"title_is_manual":false}' if kind == "duplicate" else "{"
    )
    if kind == "unreadable":

        def denied(_self):
            raise PermissionError("synthetic")

        monkeypatch.setattr(Path, "read_bytes", denied)
    assert native.GrokBuildWarningProvider._summary_clean(tmp_path, SID) is False


def test_pre_prompt_summary_anomaly_never_dispatches_or_falls_back(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "_preflight", lambda *args: None)
    provider = native.GrokBuildWarningProvider(ram=tmp_path)
    monkeypatch.setattr(provider, "_inspect", lambda *args: None)
    monkeypatch.setattr(provider, "_bootstrap", lambda *args: None)
    # The actual metadata reader sees the missing summary and rejects it.
    calls = []
    monkeypatch.setattr(provider, "_start", lambda *args: calls.append(args))
    payload = {
        "model": "grok-4.7",
        "reasoning": {"effort": "high"},
        "instructions": "public",
        "input": "public",
        "tools": [],
        "text": {"format": {"schema": {}}},
    }
    with pytest.raises(ScheduledProviderError, match="native_background_activity") as err:
        provider.qualify(payload)
    assert err.value.usage_uncertain and not err.value.retryable
    assert not calls and not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "fault",
    [
        "api_shape",
        "missing_id",
        "extra",
        "unknown_name",
        "name_list",
        "empty_id",
        "id_type",
        "long_id",
        "input_type",
        "input_oversize",
        "unfinished",
        "failed",
    ],
)
def test_native_x_completion_rejects_unknown_or_malformed_shapes(fault):
    stream = NativeStream(session_id=SID, qualification=False, allowed={"x_search"})
    stream.accept({"type": "available_commands", "tools": []})
    stream.accept(
        {
            "type": "tool_call",
            "toolCallId": "x",
            "toolName": "x_search",
            "status": "in_progress",
            "rawInput": {"variant": "XSearch", "backend": True},
        }
    )
    output = {"id": "x", "call_id": "call-x", "name": "x_keyword_search", "input": "public query"}
    status = "completed"
    if fault == "api_shape":
        output.update({"type": "custom_tool_call", "status": "completed"})
    elif fault == "missing_id":
        del output["id"]
    elif fault == "extra":
        output["unexpected"] = True
    elif fault == "unknown_name":
        output["name"] = "run_terminal_cmd"
    elif fault == "name_list":
        output["name"] = []
    elif fault == "empty_id":
        output["id"] = ""
    elif fault == "id_type":
        output["call_id"] = 123
    elif fault == "long_id":
        output["id"] = "x" * 513
    elif fault == "input_type":
        output["input"] = {}
    elif fault == "input_oversize":
        output["input"] = "x" * 65537
    elif fault == "failed":
        status = "failed"
    else:
        status = "unknown"
    with pytest.raises(ScheduledProviderError) as err:
        stream.accept(
            {"type": "tool_call_update", "toolCallId": "x", "status": status, "rawOutput": output}
        )
    assert err.value.usage_uncertain and not err.value.retryable
    assert not stream.citations and not stream.tools["x"]["complete"]


@pytest.mark.parametrize("x_calls", [3, 4])
def test_native_x_subsearches_share_four_tool_budget_with_fetch(x_calls):
    stream = NativeStream(session_id=SID, qualification=False, allowed={"x_search", "web_fetch"})
    stream.accept({"type": "available_commands", "tools": ["web_fetch"]})
    for i, name in enumerate(
        ["x_keyword_search", "x_semantic_search", "x_thread_fetch", "x_user_search"][:x_calls]
    ):
        identity = f"x-{i}"
        stream.accept(
            {
                "type": "tool_call",
                "toolCallId": identity,
                "toolName": "x_search",
                "status": "in_progress",
                "rawInput": {"variant": "XSearch", "backend": True},
            }
        )
        stream.accept(
            {
                "type": "tool_call_update",
                "toolCallId": identity,
                "status": "completed",
                "rawOutput": {
                    "id": identity,
                    "call_id": f"call-{i}",
                    "name": name,
                    "input": "https://example.org/not-a-citation",
                },
            }
        )
    assert not stream.citations
    url = "https://github.com/advisories/GHSA-mh6f-8j2x-4483"
    fetch = {
        "type": "tool_call",
        "toolCallId": "fetch",
        "toolName": "web_fetch",
        "status": "in_progress",
        "rawInput": {"url": url},
    }
    if x_calls == 4:
        with pytest.raises(ScheduledProviderError, match="native_tool_limit") as err:
            stream.accept(fetch)
        assert err.value.usage_uncertain and not err.value.retryable
        return
    stream.accept(fetch)
    stream.accept(
        {
            "type": "tool_call_update",
            "toolCallId": "fetch",
            "status": "completed",
            "rawOutput": {
                "type": "WebFetch",
                "Content": {"url": url, "status_code": 200, "content": "Public advisory."},
            },
        }
    )
    stream.accept(end_record())
    result = stream_result(stream)
    assert result.server_side_tool_calls == 4 and result.citation_urls == (url,)


@pytest.fixture
def diagnostic_native_provider(tmp_path, monkeypatch):
    """Real request lifecycle, synthetic native streams, no provider connection."""
    monkeypatch.setattr(native, "_preflight", lambda *args: None)
    monkeypatch.setattr(native, "uuid4", lambda: SID)
    provider = native.GrokBuildWarningProvider(ram=tmp_path)
    monkeypatch.setattr(provider, "_inspect", lambda *args: None)
    monkeypatch.setattr(provider, "_bootstrap", lambda *args: None)
    monkeypatch.setattr(provider, "_summary_clean", lambda *args: True)

    class Process:
        bytes = 200
        closed = False
        failure = TimeoutError("synthetic-private-content https://example.org/private")
        rows = iter(
            [
                json.dumps({"type": "available_commands", "tools": ["web_fetch"]}).encode(),
                json.dumps({"type": "thought", "data": "synthetic-private-content"}).encode(),
                json.dumps({"type": "usage", "data": "synthetic-private-content"}).encode(),
                json.dumps(
                    {
                        "type": "tool_call",
                        "toolCallId": "fetch",
                        "toolName": "web_fetch",
                        "status": "pending",
                        "rawInput": {"url": "https://example.org/private"},
                    }
                ).encode(),
            ]
        )

        def line(self, _deadline):
            try:
                return next(self.rows)
            except StopIteration:
                raise self.failure from None

        def finish(self, _deadline):
            raise self.failure

        def close(self):
            self.closed = True

    process = Process()
    monkeypatch.setattr(provider, "_start", lambda *args: process)
    return provider, process


@pytest.mark.parametrize(
    ("fault", "phase", "category", "events", "turns", "tools"),
    [
        ("timeout", "stream_read", "timeout", 4, 1, 1),
        ("transport", "stream_read", "transport", 4, 1, 1),
        ("json", "stream_parse", "invalid_data", 0, 0, 0),
        ("duplicate", "stream_parse", "invalid_data", 0, 0, 0),
        ("unknown", "stream_parse", "contract_rejection", 1, 0, 0),
        ("finish_timeout", "completion", "timeout", 0, 0, 0),
        ("process_cleanup", "process_cleanup", "filesystem", 4, 1, 1),
        ("other", "stream_read", "other", 4, 1, 1),
    ],
)
def test_native_failures_record_safe_phase_and_observations_without_authorizing_retry(
    diagnostic_native_provider, tmp_path, fault, phase, category, events, turns, tools
):
    provider, process = diagnostic_native_provider
    if fault == "transport":
        process.failure = BrokenPipeError("synthetic-private-content")
    elif fault == "json":
        process.rows = iter([b'{"synthetic-private-content":'])
    elif fault == "duplicate":
        process.rows = iter([b'{"type":"text","type":"synthetic-private-content"}'])
    elif fault == "unknown":
        process.rows = iter([b'{"type":"synthetic-private-content"}'])
    elif fault == "finish_timeout":
        process.rows = iter([None])
    elif fault == "process_cleanup":

        def fail_cleanup():
            process.closed = True
            raise OSError("synthetic-private-content")

        process.close = fail_cleanup
    elif fault == "other":

        class SyntheticPrivateException(RuntimeError):
            pass

        process.failure = SyntheticPrivateException("synthetic-private-content")
    payload = {
        "model": "grok-4.7",
        "reasoning": {"effort": "high"},
        "instructions": "synthetic-private-content",
        "input": "synthetic-private-content",
        "tools": [{"type": "web_search"}],
        "text": {"format": {"schema": {}}},
    }
    with pytest.raises(ScheduledProviderError) as err:
        provider.discover(payload)
    error = err.value
    assert error.usage_uncertain and not error.retryable and error.exact_usage is None
    from smithguard.scheduled_discovery import _failure_details

    metadata = _failure_details(error)
    details = metadata["native_diagnostic"]
    timing = details["timing"]
    assert timing["schema_version"] == "1.1.0"
    assert "observed_finished_at" in timing
    assert timing["first_failure"]["phase"] == (
        "stream_read" if fault == "process_cleanup" else phase
    )
    assert {key: value for key, value in details.items() if key != "timing"} == {
        "phase": phase,
        "exception_category": category,
        "elapsed_ms": error.elapsed_milliseconds,
        "observed_stream_events": events,
        "observed_model_turns": turns,
        "observed_tool_calls": tools,
        "prompt_bytes": details["prompt_bytes"],
        "stream_bytes": 200,
    }
    assert type(details["elapsed_ms"]) is int and 0 <= details["elapsed_ms"] < 120_000
    assert 0 < details["prompt_bytes"] <= 65_536
    assert "synthetic-private-content" not in json.dumps(metadata)
    assert "https://" not in json.dumps(metadata)
    assert "SyntheticPrivateException" not in json.dumps(metadata)
    assert process.closed and not list(tmp_path.iterdir())


def test_uncertain_native_diagnostics_survive_durable_failure_without_paid_fallback(
    diagnostic_native_provider, database, tmp_path
):
    primary, process = diagnostic_native_provider
    provider = SubscriptionFirstProvider(
        primary=primary, fallback_factory=lambda: pytest.fail("uncertain run cannot fall back")
    )
    factory = sessionmaker(database.engine)
    policy = _active_policy()
    with factory() as session, session.begin():
        enqueue_due_discovery(session, policy=policy, now=NOW)
    first = work_one(
        factory,
        policy=policy,
        provider=provider,
        worker_id="synthetic",
        now=NOW + timedelta(minutes=1),
    )
    assert first.outcome == "dead_letter"
    with factory() as session:
        receipts = _receipts(session)
    failures = [r for r in receipts if r["receipt_type"] == "provider_failure"]
    assert len(failures) == 1
    details = failures[0]["public_metadata"]["native_diagnostic"]
    assert details["phase"] == "stream_read" and details["exception_category"] == "timeout"
    assert details["observed_stream_events"] == 4 and details["observed_tool_calls"] == 1
    assert "synthetic-private-content" not in json.dumps(failures)
    second = work_one(
        factory,
        policy=policy,
        provider=provider,
        worker_id="synthetic-next",
        now=NOW + timedelta(minutes=7),
    )
    assert second.outcome == "idle"
    assert process.closed and not list(tmp_path.iterdir())


def test_exact_native_usage_and_diagnostic_survive_durable_cleanup_failure(
    diagnostic_native_provider, database, tmp_path
):
    provider, process = diagnostic_native_provider
    process.rows = iter(
        [
            b'{"type":"available_commands","tools":["web_fetch"]}',
            json.dumps(usage_record()).encode(),
            json.dumps(end_record()).encode(),
            None,
        ]
    )
    process.finish = lambda deadline: 0

    def close_failure():
        process.closed = True
        raise OSError("synthetic-private-content")

    process.close = close_failure
    factory = sessionmaker(database.engine)
    policy = _active_policy()
    with factory() as session, session.begin():
        enqueue_due_discovery(session, policy=policy, now=NOW)
    result = work_one(
        factory,
        policy=policy,
        provider=provider,
        worker_id="synthetic",
        now=NOW + timedelta(minutes=1),
    )
    assert result.outcome == "dead_letter"
    with factory() as session:
        receipts = _receipts(session)
    closing = [r for r in receipts if r["reason_code"] == "native_cleanup_failed"]
    assert len(closing) == 1
    metadata = closing[0]["public_metadata"]
    assert metadata["native_diagnostic"]["phase"] == "process_cleanup"
    assert metadata["native_diagnostic"]["exception_category"] == "filesystem"
    assert "completed_native_usage_scope" not in metadata["native_diagnostic"]
    assert "completed_native_invocations" not in metadata["native_diagnostic"]
    usage = [r for r in receipts if r["receipt_type"] == "provider_cost_observed"]
    assert len(usage) == 1
    assert usage[0]["provider"]["total_tokens"] == 41
    assert provider.cleanup_failed and process.closed and not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "overrides",
    [
        {"phase": "synthetic-private-content"},
        {"exception_category": "TimeoutError"},
        {"elapsed_ms": True},
        {"observed_model_turns": -1},
        {"observed_tool_calls": "secret"},
        {"prompt_bytes": 65_537},
        {"stream_bytes": 1_056_769},
    ],
)
def test_native_diagnostic_rejects_unbounded_or_arbitrary_metadata(overrides):
    from smithguard.scheduled_discovery import NativeFailureDiagnostic

    values = {"phase": "stream_read", "exception_category": "timeout", "elapsed_ms": 120_000}
    with pytest.raises(ValueError):
        NativeFailureDiagnostic(**(values | overrides))


def test_native_error_cannot_receive_an_unvalidated_diagnostic_mapping():
    with pytest.raises(ValueError, match="native diagnostic type invalid"):
        ScheduledProviderError(
            "native_execution_uncertain",
            retryable=False,
            usage_uncertain=True,
            native_diagnostic={"message": "synthetic-private-content"},
        )


def test_observed_fifth_tool_is_counted_while_usage_remains_uncertain():
    stream = NativeStream(session_id=SID, qualification=False)
    stream.accept({"type": "available_commands", "tools": ["web_fetch"]})
    for index in range(4):
        stream.accept(
            {
                "type": "tool_call",
                "toolCallId": f"call-{index}",
                "toolName": "web_search",
                "status": "pending",
                "rawInput": {"variant": "WebSearch", "backend": True},
            }
        )
    with pytest.raises(ScheduledProviderError, match="native_tool_limit") as err:
        stream.accept({"type": "tool_call", "toolCallId": "fifth"})
    assert stream.observed_tool_calls == 5 and len(stream.tools) == 4
    assert err.value.usage_uncertain and not err.value.retryable


@pytest.mark.parametrize("cleanup", ["process", "ram"])
def test_cleanup_cannot_reclassify_uncertain_bootstrap_as_uncharged(
    diagnostic_native_provider, tmp_path, monkeypatch, cleanup
):
    provider, process = diagnostic_native_provider
    # Exercise the actual ACP bootstrap, which has not yet sent a model prompt.
    monkeypatch.setattr(
        provider, "_bootstrap", native.GrokBuildWarningProvider._bootstrap.__get__(provider)
    )
    process.send = lambda value: None
    process.rows = iter([b'{"jsonrpc":"2.0","id":99,"method":"session/request_permission"}'])
    if cleanup == "process":

        def close_failure():
            process.closed = True
            raise OSError("synthetic-private-content")

        process.close = close_failure
    else:
        original = native.tempfile.TemporaryDirectory

        class CleanupFailure:
            def __init__(self, **kwargs):
                self.real = original(**kwargs)
                self.name = self.real.name

            def cleanup(self):
                self.real.cleanup()
                raise OSError("synthetic-private-content")

        monkeypatch.setattr(native.tempfile, "TemporaryDirectory", CleanupFailure)
    payload = {
        "model": "grok-4.7",
        "reasoning": {"effort": "high"},
        "instructions": "public",
        "input": "public",
        "tools": [],
        "text": {"format": {"schema": {}}},
    }
    with pytest.raises(ScheduledProviderError, match="native_execution_uncertain") as err:
        provider.qualify(payload)
    assert err.value.usage_uncertain and not err.value.retryable
    assert err.value.exact_usage is None and provider.cleanup_failed
    assert err.value.native_diagnostic.phase == (
        "process_cleanup" if cleanup == "process" else "ram_cleanup"
    )
    assert err.value.native_diagnostic.observed_stream_events == 0
    assert err.value.native_diagnostic.stream_bytes is None
    assert process.closed and not list(tmp_path.iterdir())


@pytest.mark.parametrize("ending", ["timeout", "fifth_tool", "malformed_final", "complete"])
def test_exhausted_tool_continuation_keeps_original_deadline_and_cleanup(
    diagnostic_native_provider, tmp_path, monkeypatch, ending
):
    """Reproduce the Oct17 two-invocation shape without calling the provider."""
    from tests.test_grok_build_sequence import _end, _tool

    provider, _ = diagnostic_native_provider
    clock = [1000.0]
    monkeypatch.setattr(native, "monotonic", lambda: clock[0])
    deadlines = []
    processes = []
    first = [{"type": "available_commands", "tools": ["web_fetch"]}]
    for i in range(4):
        first.extend(_tool(f"search-{i}"))
    first.extend(
        [
            {
                "type": "usage",
                "usage": {k: v for k, v in _end()["usage"].items() if k != "total_tokens"},
            },
            {"type": "max_turns_reached"},
            _end(stop="cancelled"),
        ]
    )
    second = [{"type": "available_commands", "tools": ["web_fetch"]}]
    if ending == "fifth_tool":
        second.append(_tool("search-5")[0])
    elif ending == "complete":
        second.extend(
            [
                {"type": "text", "data": "{}"},
                {
                    "type": "usage",
                    "usage": {k: v for k, v in _end()["usage"].items() if k != "total_tokens"},
                },
                _end(),
            ]
        )
    elif ending == "malformed_final":
        second.append(b'{"type":"text","data":')
    else:
        second.append({"type": "thought", "data": "discard synthetic private thought"})

    class Process:
        bytes = 0
        closed = False

        def __init__(self, rows, index):
            self.rows = iter(rows)
            self.index = index

        def line(self, deadline):
            deadlines.append(deadline)
            try:
                row = next(self.rows)
            except StopIteration:
                if self.index == 1 and ending == "timeout":
                    clock[0] = deadline
                    raise TimeoutError("synthetic unfinished output") from None
                return None
            clock[0] = 1043.0 if self.index == 0 else 1118.0 if ending == "complete" else 1119.0
            value = row if isinstance(row, bytes) else json.dumps(row).encode()
            self.bytes += len(value) + 1
            self.on_bytes(self.bytes)
            self.on_pipe("stdout", len(value) + 1)
            self.line_framing_bytes = 1
            return value

        def finish(self, deadline):
            deadlines.append(deadline)
            return 1 if self.index == 0 else 0

        def close(self):
            self.closed = True
            clock[0] += 1

    def start(*args):
        assert len(processes) < 2, "no third dispatch after failure or success"
        process = Process(first if not processes else second, len(processes))
        processes.append(process)
        return process

    monkeypatch.setattr(provider, "_start", start)
    payload = {
        "model": "grok-4.7",
        "reasoning": {"effort": "high"},
        "instructions": "synthetic boundary control",
        "input": "synthetic boundary control",
        "tools": [{"type": "web_search"}],
        "text": {"format": {"schema": {}}},
    }
    if ending == "complete":
        result = provider.discover(payload)
        assert result.server_side_tool_calls == 4
        assert len(result.native_invocations) == 2
    else:
        with pytest.raises(ScheduledProviderError) as caught:
            provider.discover(payload)
        assert caught.value.usage_uncertain and not caught.value.retryable
        assert caught.value.exact_usage is None
        assert "synthetic private thought" not in repr(vars(caught.value))
        expected_code = (
            "native_tool_limit" if ending == "fifth_tool" else "native_execution_uncertain"
        )
        assert caught.value.code == expected_code
        diagnostic = caught.value.native_diagnostic
        assert diagnostic is not None and len(diagnostic.known_invocations) == 1
        failure = diagnostic.timing.first_failure
        assert len(failure.invocations) == 2
        first_events = failure.invocations[0].events.metadata()
        second_events = failure.invocations[1].events.metadata()
        assert first_events["event_types"]["tool_call"]["count"] == 4
        assert (
            sum(item["serialized_bytes"] for item in first_events["event_types"].values())
            + first_events["framing_bytes"]
            == processes[0].bytes
        )
        assert first_events["first_text_elapsed_ms"] is None
        assert second_events["event_types"]["end"]["count"] == 0
        assert "synthetic private thought" not in json.dumps(diagnostic.metadata())
        assert "synthetic unfinished output" not in json.dumps(diagnostic.metadata())
        assert diagnostic.known_invocations[0].tool_calls == 4
        if ending == "timeout":
            assert diagnostic.phase == "stream_read" and diagnostic.exception_category == "timeout"
            assert second_events["event_types"]["thought"]["count"] == 1
            assert second_events["first_text_elapsed_ms"] is None
            assert failure.activity.elapsed_ms == 120000
            assert diagnostic.timing.activity.elapsed_ms == 121000
            assert (
                failure.invocations[1].elapsed_ms + 1000
                == diagnostic.timing.invocations[1].elapsed_ms
            )
        elif ending == "malformed_final":
            assert second_events["malformed_bytes"] == len(b'{"type":"text","data":')
            assert second_events["event_types"]["text"]["count"] == 0
            assert (
                diagnostic.phase == "stream_parse"
                and diagnostic.exception_category == "invalid_data"
            )

    assert len(processes) == 2
    assert set(deadlines) == {1120.0}, "continuation must not restart the 120-second clock"
    assert all(p.closed for p in processes) and not list(tmp_path.iterdir())
