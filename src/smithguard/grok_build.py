"""Bounded official Grok Build subscription calls with ephemeral RAM-only state."""

from __future__ import annotations

import hashlib
import json
import os
import resource
import selectors
import signal
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Any
from uuid import uuid4

from smithguard.grok_build_sequence import NativeSequence
from smithguard.grok_build_stream import NATIVE_ROUTE, NativeStream, uncertain
from smithguard.grok_build_tools import search_profile
from smithguard.identifiers import canonical_json_bytes
from smithguard.native_continuation import BASELINE, CANDIDATE, reminder
from smithguard.native_timing import NativeTimingRecorder
from smithguard.scheduled_discovery import (
    NativeFailureDiagnostic,
    ProviderResult,
    ProviderUsageSnapshot,
    ScheduledProviderError,
)
from smithguard.spend import NATIVE_SUBSCRIPTION_CONTRACT as NATIVE_LIMITS

GROK_BINARY = Path("/usr/local/lib/smithguard/grok-1.0.41")
GROK_SHA256 = "9ce03ed23e16ea01072b4496263d6213a27899e1e3e107f008d36edf82e70407"
GROK_AUTH = Path("/var/lib/smithguard/grok-auth/auth.json")
GROK_RAM = Path("/run/smithguard-grok")
MAX_BYTES = 1_048_576
MANUAL_TITLE = "SmithGuard bounded public check"
DENIED_TOOLS = (
    "read_file,list_dir,grep,run_terminal_cmd,search_replace,write_file,search_tool,use_tool,Agent"
)
NATIVE_DISCOVERY_PROMPT_VERSION = "smithguard-native-discovery-v2"
NATIVE_CONTINUATION = BASELINE
NATIVE_DISCOVERY_WORKLOAD = (
    "Start with one focused search appropriate to the supplied lane and date window. "
    "Reserve the remaining tool calls for required original-source citation binding. "
    "Normally return one or two useful leads with one original source each; "
    "the supplied schema remains the output cap. Stop searching once useful cited "
    "leads are available. Do not spend calls on optional breadth or corroboration. "
    "If enrichment_targets are supplied, revisit only a useful target within the "
    "same budget, rather than adding another broad search. Keep allegations, source "
    "context and JSON compact. Missing optional details may stay unknown or null. "
    "Never invent evidence, context or dates to save a tool call. Return fewer leads "
    "or an empty list when original-source citation binding cannot be established."
)


def _prompt(payload: Mapping[str, Any], *, qualification: bool) -> bytes:
    document = {
        "instructions": payload["instructions"],
        "input": payload["input"],
        "required_output_schema": payload["text"]["format"]["schema"],
        "search_boundary": payload["tools"],
        "tool_rule": (
            "Use only the configured public search/fetch tools, at most four calls. "
            "Fetch source URLs when search provides no cited source metadata. "
            "For X posts, fetch https://publish.x.com/oembed?url=ENCODED_POST_URL"
            "&omit_script=true and cite the post URL returned in its JSON. "
            "An ordinary X page or login shell is not post evidence. "
            "Return only the required JSON."
        )
        if not qualification
        else "Use no tools. Return only the required JSON.",
    }
    if not qualification:
        document["native_prompt_version"] = NATIVE_DISCOVERY_PROMPT_VERSION
        document["workload_guidance"] = NATIVE_DISCOVERY_WORKLOAD
    return canonical_json_bytes(document)


def _exception_category(error: Exception) -> str:
    # Inspect only built-in exception types, never messages or arbitrary class names.
    for _ in range(8):
        if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
            return "timeout"
        if isinstance(error, ConnectionError):
            return "transport"
        if error.__cause__ is None:
            break
        error = error.__cause__
    if isinstance(error, (ValueError, TypeError, KeyError, RecursionError)):
        return "invalid_data"
    if isinstance(error, OSError):
        return "filesystem"
    if isinstance(error, ScheduledProviderError):
        return "contract_rejection"
    return "other"


@dataclass
class _DiagnosticState:
    started: float
    timing: NativeTimingRecorder
    phase: str = "preflight"
    prompt_bytes: int | None = None
    process: _Process | None = None
    stream: NativeStream | NativeSequence | None = None
    usage_uncertain: bool = False
    completed_stream_bytes: int = 0

    def set_phase(self, phase: str) -> None:
        self.timing.switch(phase)
        self.phase = phase

    def note_failure(self, error: Exception) -> None:
        self.timing.failure(self.phase, _exception_category(error))

    def snapshot(
        self, error: Exception, *, include_known_invocations: bool = True
    ) -> NativeFailureDiagnostic:
        size = getattr(self.process, "bytes", None)
        if size is None and self.completed_stream_bytes:
            size = 0
        if type(size) is int:
            size += self.completed_stream_bytes
        return NativeFailureDiagnostic(
            timing=self.timing.snapshot(),
            phase=self.phase,
            exception_category=_exception_category(error),
            elapsed_ms=min(3_600_000, max(0, int((monotonic() - self.started) * 1000))),
            observed_stream_events=(
                self.stream.observed_stream_events
                if isinstance(self.stream, NativeSequence)
                else self.stream.observed_events
                if self.stream
                else 0
            ),
            observed_model_turns=self.stream.observed_model_turns if self.stream else 0,
            observed_tool_calls=self.stream.observed_tool_calls if self.stream else 0,
            prompt_bytes=self.prompt_bytes,
            stream_bytes=size if type(size) is int and 0 <= size <= MAX_BYTES + 8192 else None,
            known_invocations=(
                getattr(self.stream, "known_invocations", ()) if include_known_invocations else ()
            ),
        )


def _remaining(deadline: float) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError("native deadline")
    return remaining


def _json(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("native object required")
    return value


class _Process:
    """Drain both pipes with byte and wall-clock bounds, never log provider prose."""

    def __init__(self, args: list[str], *, cwd: Path, env: dict[str, str]) -> None:
        self.process = subprocess.Popen(  # noqa: S603 - fixed pinned binary, no shell
            args,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if "stdio" in args and "agent" in args else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.selector = selectors.DefaultSelector()
        try:
            self.selector.register(self.process.stdout, selectors.EVENT_READ, "stdout")
            self.selector.register(self.process.stderr, selectors.EVENT_READ, "stderr")
        except Exception:
            self.close()
            raise
        self.buffer = bytearray()
        self.bytes = 0
        self.byte_limit = MAX_BYTES
        self.on_bytes: Callable[[int], None] | None = None
        self.on_pipe: Callable[[str, int], None] | None = None
        self.line_framing_bytes = 0

    def line(self, deadline: float) -> bytes | None:
        while True:
            if b"\n" in self.buffer:
                line, _, rest = self.buffer.partition(b"\n")
                self.buffer = bytearray(rest)
                self.line_framing_bytes = 1
                return bytes(line)
            if not self.selector.get_map():
                if self.buffer:
                    line = bytes(self.buffer)
                    self.buffer.clear()
                    self.line_framing_bytes = 0
                    return line
                return None
            for key, _ in self.selector.select(_remaining(deadline)):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    self.selector.unregister(key.fileobj)
                    continue
                self.bytes += len(chunk)
                if self.on_pipe is not None:
                    self.on_pipe(key.data, len(chunk))
                if self.on_bytes is not None:
                    self.on_bytes(self.bytes)
                if self.bytes > self.byte_limit:
                    raise ValueError("native stream exceeds bound")
                if key.data == "stdout":
                    self.buffer.extend(chunk)
                # stderr is deliberately discarded, including errors and reasoning.

    def send(self, value: dict) -> None:
        if self.process.stdin is None:
            raise ValueError("native input pipe unavailable")
        self.process.stdin.write(canonical_json_bytes(value) + b"\n")
        self.process.stdin.flush()

    def finish(self, deadline: float) -> int:
        return self.process.wait(timeout=_remaining(deadline))

    def close_input(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()

    def close(self) -> None:
        # A rejected stream must not get a grace period to fetch or sample again.
        # Kill the whole group even if its leader already exited.
        with suppress(ProcessLookupError):
            os.killpg(self.process.pid, signal.SIGKILL)
        if self.process.stdin is not None:
            with suppress(BrokenPipeError):
                self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        finally:
            self.selector.close()
            for pipe in (self.process.stdout, self.process.stderr):
                if pipe is not None:
                    pipe.close()


def _configuration() -> str:
    # Leave completion size to the provider. An explicit zero or large sentinel
    # would still request a cap and would not mean unlimited output.
    return """[cli]
auto_update = false
use_leader = false
[models]
default = "grok-4.7"
web_search = "grok-4.7"
session_summary = "grok-4.7"
default_reasoning_effort = "high"
max_retries = 0
[model."grok-4.7"]
reasoning_effort = "high"
max_retries = 0
rate_limit_retry_threshold = 1
max_request_bytes = 65536
[memory]
enabled = false
[doom_loop_recovery]
enabled = false
max_retries = 0
[features]
telemetry = false
codebase_indexing = false
two_pass_compaction = false
turn_summary = false
session_recap = false
title_refresh = false
turn_transient_retry = false
[session]
load_envrc = false
[telemetry]
trace_upload = false
otel_enabled = false
"""


def _environment(home: Path, work: Path, auth: Path) -> dict[str, str]:
    result = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TMPDIR": str(work),
        "GROK_HOME": str(home),
        "GROK_AUTH_PATH": str(auth),
        "CLAUDE_CONFIG_DIR": str(work),
        "GROK_DISABLE_AUTOUPDATER": "1",
        "GROK_WORKSPACE_DATA_COLLECTION_DISABLED": "1",
        "GROK_STORAGE_MODE": "local",
        "GROK_TELEMETRY_ENABLED": "0",
        "GROK_TELEMETRY_TRACE_UPLOAD": "0",
        "GROK_EXTERNAL_OTEL": "0",
        "GROK_MEMORY": "0",
        "GROK_TURN_SUMMARY": "0",
        "GROK_SESSION_RECAP": "0",
        "GROK_TITLE_REFRESH": "0",
        "GROK_WORKFLOWS": "0",
        "GROK_TURN_TRANSIENT_RETRY": "0",
        "GROK_MAX_RETRIES": "0",
        "GROK_DOOM_LOOP_RECOVERY": "0",
        "GROK_WEB_FETCH_ALLOW_LOCAL": "0",
        "RUST_LOG": "off",
    }
    for vendor in ("CURSOR", "CLAUDE", "CODEX"):
        for feature in ("SKILLS", "RULES", "AGENTS", "MCPS", "HOOKS", "SESSIONS"):
            result[f"GROK_{vendor}_{feature}_ENABLED"] = "0"
    return result


def _preflight(binary: Path, auth: Path, ram: Path) -> None:
    metadata = binary.lstat()
    with binary.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if (
        binary.resolve(strict=True) != binary
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or digest != GROK_SHA256
    ):
        raise ValueError("native binary invalid")
    metadata = auth.lstat()
    if (
        auth.resolve(strict=True) != auth
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or stat.S_IMODE(auth.parent.stat().st_mode) != 0o700
        or auth.parent.stat().st_uid != os.getuid()
        or metadata.st_size > 65_536
    ):
        raise ValueError("native credential invalid")
    credentials = _json(auth.read_bytes())
    if len(credentials) != 1:
        raise ValueError("native credential route ambiguous")
    credential = next(iter(credentials.values()))
    if (
        not isinstance(credential, dict)
        or credential.get("auth_mode") != "oidc"
        or credential.get("oidc_issuer") != "https://auth.x.ai"
        or not credential.get("key")
        or not credential.get("refresh_token")
        or credential.get("coding_data_retention_opt_out") is not True
    ):
        raise ValueError("native subscription authentication required")
    _ram_protections(ram)


def _ram_protections(ram: Path) -> None:
    rows = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()]
    for path, size in (
        (ram, "65536k"),
        (Path("/tmp"), "8192k"),  # noqa: S108 - inspect mandatory private RAM mount only
        (Path("/var/tmp"), "8192k"),  # noqa: S108 - inspect mandatory private RAM mount only
    ):
        mounts = [row for row in rows if row[4] == str(path)]
        if path.resolve(strict=True) != path or len(mounts) != 1:
            raise ValueError("native RAM mount missing")
        mount = mounts[0]
        separator = mount.index("-")
        if (
            mount[separator + 1] != "tmpfs"
            or not {"nosuid", "nodev", "noexec"} <= set(mount[5].split(","))
            or not {"noswap", f"size={size}"} <= set(mount[separator + 3].split(","))
        ):
            raise ValueError("native RAM protections missing")
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        raise ValueError("native core protection missing")
    groups = [
        line[3:]
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::/")
    ]
    if len(groups) != 1 or ".." in Path(groups[0]).parts:
        raise ValueError("native cgroup missing")
    swap = Path("/sys/fs/cgroup") / groups[0].lstrip("/") / "memory.swap.max"
    if swap.read_text().strip() != "0":
        raise ValueError("native process swap protection missing")


class GrokBuildWarningProvider:
    credential_route = NATIVE_ROUTE

    def __init__(
        self,
        *,
        binary: Path = GROK_BINARY,
        auth: Path = GROK_AUTH,
        ram: Path = GROK_RAM,
        utc_now: Callable[[], datetime] | None = None,
        continuation_mode: str = "baseline",
    ) -> None:
        if continuation_mode not in {"baseline", CANDIDATE}:
            raise ValueError("unknown native continuation mode")
        self.continuation_mode = continuation_mode
        self.binary, self.auth, self.ram = binary, auth, ram
        self.utc_now = utc_now or (lambda: datetime.now(UTC))
        self.cleanup_failed = False

    @contextmanager
    def _directory(self, diagnostic: _DiagnosticState | None = None):
        directory = tempfile.TemporaryDirectory(prefix="attempt-", dir=self.ram)
        try:
            yield directory.name
        except Exception as error:
            if diagnostic is not None:
                diagnostic.note_failure(error)
                if isinstance(error, ScheduledProviderError):
                    diagnostic.usage_uncertain |= error.usage_uncertain
            raise
        finally:
            previous = diagnostic.phase if diagnostic is not None else None
            if diagnostic is not None:
                diagnostic.set_phase("ram_cleanup")
            try:
                directory.cleanup()
            except Exception as error:
                self.cleanup_failed = True
                if diagnostic is not None:
                    diagnostic.note_failure(error)
                raise
            else:
                if diagnostic is not None:
                    diagnostic.set_phase(previous)

    def _close(self, process: _Process, diagnostic: _DiagnosticState | None = None) -> None:
        previous = diagnostic.phase if diagnostic is not None else None
        if diagnostic is not None:
            diagnostic.set_phase("process_cleanup")
        try:
            process.close()
        except Exception as error:
            self.cleanup_failed = True
            if diagnostic is not None:
                diagnostic.note_failure(error)
            raise
        else:
            if diagnostic is not None:
                diagnostic.set_phase(previous)

    def _start(self, args: list[str], work: Path, env: dict[str, str]) -> _Process:
        # The native agent subcommand has its own --no-leader flag; the top-level
        # flag is explicitly rejected for that subcommand, even though --help parses.
        no_leader = [] if args[0] == "agent" else ["--no-leader"]
        return _Process(
            [str(self.binary), "--no-auto-update", *no_leader, *args], cwd=work, env=env
        )

    def _inspect(
        self,
        work: Path,
        env: dict[str, str],
        deadline: float,
        diagnostic: _DiagnosticState | None = None,
    ) -> None:
        process = self._start(["inspect", "--json"], work, env)
        lines = []
        try:
            while (line := process.line(deadline)) is not None:
                lines.append(line)
            if process.finish(deadline) != 0:
                raise ValueError("native inspection failed")
            data = _json(b"\n".join(lines))
            for key in ("mcpServers", "skills", "projectInstructions", "hooks", "plugins"):
                entries = data.get(key)
                if not isinstance(entries, list):
                    raise ValueError("native inspection shape changed")
                if key == "mcpServers":
                    if any(
                        not isinstance(e, dict) or e.get("disabled") is not True for e in entries
                    ):
                        raise ValueError("native configuration is not isolated")
                elif entries:
                    raise ValueError("native configuration is not isolated")
        except Exception as error:
            if diagnostic is not None:
                diagnostic.note_failure(error)
            raise
        finally:
            self._close(process, diagnostic)

    def _bootstrap(
        self,
        work: Path,
        env: dict[str, str],
        sid: str,
        deadline: float,
        profile: dict,
        diagnostic: _DiagnosticState | None = None,
    ) -> None:
        process = self._start(["agent", "--no-leader", "stdio"], work, env)
        expected_tools = {tool["id"].split(":", 1)[-1] for tool in profile["toolConfig"]["tools"]}
        expected_tools -= set(profile["disallowedTools"])
        advertised = False

        def observe(event: dict) -> None:
            nonlocal advertised
            params = event.get("params", {})
            update = params.get("update", {})
            kind = update.get("sessionUpdate")
            if kind in {
                "agent_message_chunk",
                "agent_thought_chunk",
                "tool_call",
                "tool_call_update",
            }:
                raise uncertain("native_bootstrap_inference_unexpected")
            if kind == "available_commands_update" and "tools" in update.get("_meta", {}):
                values = update["_meta"]["tools"]
                if (
                    params.get("sessionId") != sid
                    or not isinstance(values, list)
                    or any(not isinstance(v, str) for v in values)
                    or set(values) != expected_tools
                ):
                    raise ValueError("native bootstrap tool boundary changed")
                advertised = True

        def rpc(identity: int, method: str, params: dict) -> dict:
            process.send({"jsonrpc": "2.0", "id": identity, "method": method, "params": params})
            while (line := process.line(deadline)) is not None:
                event = _json(line)
                observe(event)
                if event.get("id") == identity:
                    if "error" in event or not isinstance(event.get("result"), dict):
                        raise ValueError("native bootstrap failed")
                    return event["result"]
                if "id" in event and "method" in event:
                    raise uncertain("native_bootstrap_request_unexpected")
            raise ValueError("native bootstrap closed")

        try:
            rpc(
                1,
                "initialize",
                {
                    "protocolVersion": 1,
                    "clientCapabilities": {"fs": {}, "terminal": False},
                    "_meta": {"clientType": "headless", "startupHints": {"nonInteractive": True}},
                },
            )
            created = rpc(
                2,
                "session/new",
                {
                    "cwd": str(work),
                    "mcpServers": [],
                    "_meta": {"sessionId": sid, "sessionKind": "headless", "agentProfile": profile},
                },
            )
            if created.get("sessionId") != sid:
                raise ValueError("native session identity changed")
            renamed = rpc(
                3,
                "_x.ai/session/rename",
                {
                    "sessionId": sid,
                    "cwd": str(work),
                    "title": MANUAL_TITLE,
                },
            )
            if renamed.get("success") is not True:
                raise ValueError("native manual title failed")
            while not advertised:
                line = process.line(deadline)
                if line is None:
                    raise ValueError("native bootstrap tools unavailable")
                observe(_json(line))
            # Only a successful no-prompt bootstrap gets an orderly EOF/flush.
            # A rejected stream goes directly to the immediate group kill below.
            process.close_input()
            if process.finish(deadline) != 0:
                raise ValueError("native bootstrap shutdown failed")
        except (TimeoutError, subprocess.TimeoutExpired) as error:
            if diagnostic is not None:
                diagnostic.note_failure(error)
                diagnostic.usage_uncertain = True
            raise uncertain("native_bootstrap_timeout") from error
        except ScheduledProviderError as error:
            if diagnostic is not None:
                diagnostic.note_failure(error)
                diagnostic.usage_uncertain |= error.usage_uncertain
            raise
        except Exception as error:
            if diagnostic is not None:
                diagnostic.note_failure(error)
            raise
        finally:
            self._close(process, diagnostic)

    @staticmethod
    def _summary_clean(home: Path, sid: str) -> bool:
        """Inspect RAM metadata only; manual titles also occupy generated-title fields."""
        try:
            files = list((home / "sessions").glob(f"*/{sid}/summary.json"))
            if len(files) != 1 or files[0].stat().st_size > MAX_BYTES:
                return False
            data = _json(files[0].read_bytes())
            return (
                data.get("title_is_manual") is True
                and data.get("generated_title") == MANUAL_TITLE
                and data.get("session_summary") == MANUAL_TITLE
                and data.get("last_turn_summary") is None
                and data.get("last_recap") is None
            )
        except (OSError, ValueError, RecursionError):
            return False

    @staticmethod
    def _uncharged_rate_limit(home: Path, sid: str, stream: NativeStream) -> bool:
        """Only native structured HTTP429 provenance on the first empty prompt.

        Build maps actual HTTP429 to ACP -32003, then to this durable terminal
        record. No prior output/tool/usage, absent error-path ledger, and no retry
        are required. Error strings or zero-filled usage never authorize fallback.
        """
        if not stream.saw_error or stream.saw_inference or stream.end is not None:
            return False
        files = list((home / "sessions").glob(f"*/{sid}/updates.jsonl"))
        if len(files) != 1 or files[0].stat().st_size > 4 * MAX_BYTES:
            return False
        terminal = []
        with files[0].open("rb") as source:
            for line in source:
                if len(line) > MAX_BYTES:
                    return False
                event = _json(line)
                params = event.get("params", {})
                update = params.get("update", {})
                if update.get("sessionUpdate") == "turn_completed":
                    if params.get("sessionId") != sid:
                        return False
                    terminal.append(update)
        return (
            len(terminal) == 1
            and terminal[0].get("stop_reason") == "rate_limit"
            and "usage" not in terminal[0]
            and "agent_result" not in terminal[0]
            and isinstance(terminal[0].get("prompt_id"), str)
        )

    def _request(self, payload: Mapping[str, Any], *, qualification: bool) -> ProviderResult:
        started = monotonic()
        diagnostic = _DiagnosticState(
            started=started,
            timing=NativeTimingRecorder(started=started, clock=monotonic, utc_now=self.utc_now),
        )
        deadline = started + NATIVE_LIMITS["maximum_elapsed_seconds"]
        dispatched = False
        accounted: ProviderUsageSnapshot | None = None
        try:
            _preflight(self.binary, self.auth, self.ram)
            if payload.get("model") != "grok-4.7" or payload.get("reasoning") != {"effort": "high"}:
                raise ValueError("native model contract changed")
            if payload.get("max_output_tokens") is not None:
                raise ScheduledProviderError(
                    "provider_request_output_limit_invalid",
                    retryable=False,
                    usage_uncertain=False,
                )
            profile = search_profile(payload, qualification=qualification)
            prompt = _prompt(payload, qualification=qualification)
            if len(prompt) > 65_536:
                raise ValueError("native prompt too large")
            diagnostic.prompt_bytes = len(prompt)
            diagnostic.set_phase("ram_setup")
            with self._directory(diagnostic) as directory:
                root = Path(directory)
                home, work = root / "home", root / "work"
                home.mkdir(mode=0o700)
                work.mkdir(mode=0o700)
                (home / "config.toml").write_text(_configuration())
                (home / "config.toml").chmod(0o600)
                # .json means native content-block input, not a JSON string prompt.
                prompt_path = root / "prompt.txt"
                prompt_path.write_bytes(prompt)
                prompt_path.chmod(0o600)
                profile_path = root / "profile.md"
                profile_path.write_text(
                    "---\n" + canonical_json_bytes(profile).decode("ascii") + "\n---\n"
                )
                profile_path.chmod(0o600)
                env = _environment(home, work, self.auth)
                diagnostic.set_phase("inspection")
                self._inspect(work, env, deadline, diagnostic)
                sid = str(uuid4())
                diagnostic.set_phase("bootstrap")
                self._bootstrap(work, env, sid, deadline, profile, diagnostic)
                diagnostic.set_phase("pre_dispatch_validation")
                if not self._summary_clean(home, sid):
                    raise uncertain("native_background_activity")
                allowed = set(profile["tools"]) - set(profile["disallowedTools"])
                sequence = None if qualification else NativeSequence(session_id=sid)
                args = [
                    "--cwd",
                    str(work),
                    "--model",
                    "grok-4.7",
                    "--reasoning-effort",
                    "high",
                    "--always-approve",
                    "--sandbox",
                    "off",
                    "--no-plan",
                    "--no-memory",
                    "--no-subagents",
                    "--storage-mode",
                    "local",
                    "--resume",
                    sid,
                    "--tools",
                    ",".join(profile["tools"]),
                    "--agent",
                    str(profile_path),
                    "--disallowed-tools",
                    ",".join([DENIED_TOOLS, *profile["disallowedTools"]]),
                    "--deny",
                    "Bash",
                    "--deny",
                    "Edit",
                    "--deny",
                    "Write",
                    "--deny",
                    "MCPTool",
                    "--max-turns",
                    "1",
                    "--output-format",
                    "streaming-json",
                    "--verbatim",
                    "--prompt-file",
                    str(prompt_path),
                ]
                prompt_bytes, stream_bytes = len(prompt), 0
                turn_limit = 1 if qualification else NATIVE_LIMITS["maximum_model_turns"]
                for turn in range(turn_limit):
                    diagnostic.set_phase("pre_dispatch_validation")
                    if turn:
                        continuation = reminder(
                            self.continuation_mode,
                            remaining_calls=NATIVE_LIMITS["maximum_observed_tool_calls"]
                            - sequence.observed_tool_calls,
                            remaining_ms=min(120_000, max(0, int(_remaining(deadline) * 1000))),
                        )
                        prompt_bytes += len(continuation)
                        if prompt_bytes > 65_536:
                            raise ValueError("native prompt sequence exceeds bound")
                        # Preserve consumed prompt bytes and the same RAM-only history.
                        continuation_path = root / f"continuation-{turn}.txt"
                        continuation_path.write_bytes(continuation)
                        continuation_path.chmod(0o600)
                        args[-1] = str(continuation_path)
                    diagnostic.prompt_bytes = prompt_bytes
                    stream = NativeStream(
                        session_id=sid, qualification=qualification, allowed=allowed
                    )
                    if sequence is not None:
                        sequence.prepare(stream)
                    diagnostic.stream = sequence if sequence is not None else stream
                    _remaining(deadline)
                    if stream_bytes >= MAX_BYTES:
                        raise ValueError("native stream sequence exceeds bound")
                    # A prior exact subtotal must never become the claimed total of
                    # a later uncertain dispatch. Diagnostics retain its closed ledgers.
                    accounted = None
                    dispatched = True
                    diagnostic.set_phase("launch")
                    diagnostic.completed_stream_bytes = stream_bytes
                    diagnostic.process = None
                    diagnostic.timing.start_invocation()
                    process = self._start(args, work, env)
                    diagnostic.process = process
                    process.on_bytes = diagnostic.timing.observe_bytes
                    process.on_pipe = diagnostic.timing.observe_pipe
                    process.byte_limit = MAX_BYTES - stream_bytes
                    try:
                        diagnostic.set_phase("stream_read")
                        while (line := process.line(deadline)) is not None:
                            diagnostic.timing.observe_bytes(process.bytes)
                            diagnostic.set_phase("stream_parse")
                            framing = getattr(process, "line_framing_bytes", 0)
                            try:
                                event = _json(line)
                            except (ValueError, TypeError, RecursionError):
                                diagnostic.timing.observe_line(
                                    None, len(line), framing, malformed=True
                                )
                                raise
                            diagnostic.timing.observe_line(event.get("type"), len(line), framing)
                            diagnostic.timing.observe_event()
                            if sequence is None:
                                stream.accept(event)
                            else:
                                sequence.accept(stream, event)
                            diagnostic.set_phase("stream_read")
                        diagnostic.set_phase("completion")
                        code = process.finish(deadline)
                        quota = turn == 0 and self._uncharged_rate_limit(home, sid, stream)
                        if not quota:
                            metrics = {
                                "request_bytes": prompt_bytes,
                                "response_bytes": stream_bytes + process.bytes,
                                "elapsed_ms": int((monotonic() - started) * 1000),
                            }
                            try:
                                part = stream.result(
                                    **metrics,
                                    execution_failed=code != 0,
                                    segmented=sequence is not None,
                                    accept_turn_boundary=sequence is not None and code == 1,
                                )
                            except ScheduledProviderError as error:
                                failed_usage = error.exact_usage
                                # A segment ledger is not the whole attempt. Keep
                                # it out of accounted until cross-segment identity
                                # and totals validate, including on cleanup errors.
                                if sequence is not None and failed_usage is not None:
                                    accounted = sequence.add_failure(stream, failed_usage)
                                    raise ScheduledProviderError(
                                        error.code,
                                        retryable=False,
                                        usage_uncertain=accounted is None,
                                        exact_usage=accounted,
                                    ) from error
                                accounted = failed_usage
                                raise
                            if sequence is None:
                                result = part
                                accounted = ProviderUsageSnapshot(
                                    **{
                                        field.name: getattr(result, field.name)
                                        for field in fields(ProviderUsageSnapshot)
                                    }
                                )
                            else:
                                try:
                                    sequence.add(stream, part)
                                    accounted = sequence.snapshot(**metrics)
                                except ScheduledProviderError as error:
                                    accounted = error.exact_usage
                                    raise
                    except Exception as error:
                        diagnostic.note_failure(error)
                        raise
                    finally:
                        try:
                            self._close(process, diagnostic)
                        finally:
                            diagnostic.timing.finish_invocation()
                    stream_bytes += process.bytes
                    diagnostic.set_phase("post_run_validation")
                    if not self._summary_clean(home, sid):
                        raise ScheduledProviderError(
                            "native_background_activity",
                            retryable=False,
                            usage_uncertain=accounted is None,
                            exact_usage=accounted,
                        )
                    if quota:
                        raise ScheduledProviderError(
                            "provider_http_error_uncharged",
                            retryable=True,
                            usage_uncertain=False,
                            http_status=429,
                        )
                    if sequence is not None:
                        if stream.bounded_continuation and turn + 1 < turn_limit:
                            continue
                        result = sequence.result(
                            request_bytes=prompt_bytes,
                            response_bytes=stream_bytes,
                            elapsed_ms=int((monotonic() - started) * 1000),
                        )
                    break
            # Include process and RAM cleanup in the original shared deadline.
            _remaining(deadline)
            return replace(
                result,
                elapsed_milliseconds=int((monotonic() - started) * 1000),
                native_timing=diagnostic.timing.snapshot(),
            )
        except ScheduledProviderError as error:
            diagnostic.note_failure(error)
            error.native_diagnostic = diagnostic.snapshot(
                error, include_known_invocations=error.exact_usage is None
            )
            error.elapsed_milliseconds = error.native_diagnostic.elapsed_ms
            raise
        except Exception as error:
            diagnostic.note_failure(error)
            details = diagnostic.snapshot(error, include_known_invocations=accounted is None)
            if accounted is not None:
                raise ScheduledProviderError(
                    "native_cleanup_failed"
                    if details.phase in {"process_cleanup", "ram_cleanup"}
                    else "native_deadline_exceeded"
                    if details.exception_category == "timeout"
                    else "native_continuation_failed",
                    retryable=False,
                    usage_uncertain=False,
                    exact_usage=accounted,
                    native_diagnostic=details,
                    elapsed_milliseconds=details.elapsed_ms,
                ) from error
            if dispatched or diagnostic.usage_uncertain:
                raise ScheduledProviderError(
                    "native_execution_uncertain",
                    retryable=False,
                    usage_uncertain=True,
                    native_diagnostic=details,
                    elapsed_milliseconds=details.elapsed_ms,
                ) from error
            raise ScheduledProviderError(
                "native_preflight_uncharged",
                retryable=True,
                usage_uncertain=False,
                native_diagnostic=details,
                elapsed_milliseconds=details.elapsed_ms,
            ) from error

    def discover(self, payload: Mapping[str, Any]) -> ProviderResult:
        return self._request(payload, qualification=False)

    def qualify(self, payload: Mapping[str, Any]) -> ProviderResult:
        return self._request(payload, qualification=True)


class SubscriptionFirstProvider:
    """Select one route per durable job attempt, never call both inside one receipt."""

    def __init__(self, *, primary: GrokBuildWarningProvider, fallback_factory: Callable) -> None:
        self.primary = primary
        self.fallback_factory = fallback_factory

    def for_attempt(self, *, attempt: int, prior_uncharged_native: bool):
        if attempt == 1:
            return self.primary
        if attempt == 2 and prior_uncharged_native:
            try:
                return self.fallback_factory()
            except Exception as error:
                raise ScheduledProviderError(
                    "api_preflight_uncharged", retryable=False, usage_uncertain=False
                ) from error
        raise ValueError("native fallback attempt outside bound")
