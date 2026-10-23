"""Bounded Opus subscription fallback with private RAM-only runtime state."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import fields
from pathlib import Path
from time import monotonic
from typing import Any

from smithguard.claude_build_stream import (
    CLAUDE_MODEL,
    CLAUDE_ROUTE,
    CLAUDE_VERSION,
    ClaudeStream,
)
from smithguard.grok_build import GROK_RAM, MAX_BYTES, _json, _Process, _ram_protections
from smithguard.grok_build_tools import search_profile
from smithguard.identifiers import canonical_json_bytes
from smithguard.scheduled_discovery import (
    ProviderResult,
    ProviderUsageSnapshot,
    ScheduledProviderError,
)

CLAUDE_BINARY = Path("/usr/local/lib/smithguard/claude-2.1.309")
CLAUDE_SHA256 = "4d704a8aecbe038affa3000f498ae17c1b4f753add8facb8764120affc99b658"
CLAUDE_TOKEN = Path("/var/lib/smithguard/claude-auth/oauth-token")
CLAUDE_QUALIFICATION = Path("/etc/SmithGuard/claude-subscription-qualified.json")
SYSTEM_CA = Path("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
MANAGED_PATHS = (Path("/etc/claude-code"),)


def _checked_bytes(
    path: Path, *, uid: int, mode: int | None, maximum: int, digest_only: bool = False
) -> bytes:
    if path.resolve(strict=True) != path:
        raise ValueError("claude_file_alias")
    for parent in path.parents:
        meta = parent.stat()
        if meta.st_uid not in {0, uid} or meta.st_mode & 0o022:
            raise ValueError("claude_parent_permissions")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != uid
            or meta.st_nlink != 1
            or meta.st_mode & 0o022
            or (mode is not None and stat.S_IMODE(meta.st_mode) != mode)
            or not 0 < meta.st_size <= maximum
        ):
            raise ValueError("claude_file_permissions")
        if digest_only:
            digest = hashlib.sha256()
            size = 0
            while block := stream.read(1024 * 1024):
                size += len(block)
                if size > maximum:
                    raise ValueError("claude_file_changed")
                digest.update(block)
            after = os.fstat(stream.fileno())
            if size != meta.st_size or (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                meta.st_size,
                meta.st_mtime_ns,
                meta.st_ctime_ns,
            ):
                raise ValueError("claude_file_changed")
            return digest.digest()
        body = stream.read(maximum + 1)
        if len(body) != meta.st_size or len(body) > maximum:
            raise ValueError("claude_file_changed")
        return body


def preflight(binary: Path, token: Path, ram: Path) -> str:
    binary_digest = _checked_bytes(
        binary, uid=0, mode=0o755, maximum=512 * 1024 * 1024, digest_only=True
    )
    if binary_digest.hex() != CLAUDE_SHA256:
        raise ValueError("claude_binary_changed")
    parent = token.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise ValueError("claude_token_directory")
    raw = _checked_bytes(token, uid=os.getuid(), mode=0o600, maximum=4096)
    value = raw.decode("ascii").strip()
    if not value.startswith("sk-ant-oat01-") or any(c.isspace() for c in value):
        raise ValueError("claude_subscription_token_required")
    if any(path.exists() or path.is_symlink() for path in MANAGED_PATHS):
        raise ValueError("claude_managed_configuration_unqualified")
    qualification = _json(_checked_bytes(CLAUDE_QUALIFICATION, uid=0, mode=0o644, maximum=8192))
    expected = {
        "schema_version": 1,
        "binary_sha256": CLAUDE_SHA256,
        "model": CLAUDE_MODEL,
        "effort": "high",
        "version": CLAUDE_VERSION,
        "certificate_store": "system",
        "system_ca_sha256": hashlib.sha256(
            _checked_bytes(SYSTEM_CA, uid=0, mode=None, maximum=4 * 1024 * 1024)
        ).hexdigest(),
        "native_probe_passed": True,
        "usage_credits_disabled": True,
    }
    # An exact host qualification is separate from a successful workstation run.
    # Configure never writes this attestation or invents a passing live probe.
    if qualification != expected:
        raise ValueError("claude_host_not_qualified")
    _ram_protections(ram)
    return value


def prompt(payload: Mapping[str, Any], *, qualification: bool) -> bytes:
    profile = search_profile(payload, qualification=qualification)
    if profile["toolOverrides"].get("webSearch"):
        raise ValueError("claude_domain_filter_not_supported")
    document = {
        "instructions": payload["instructions"],
        "input": payload["input"],
        "required_output_schema": payload["text"]["format"]["schema"],
        "native_prompt_version": "smithguard-claude-discovery-v1",
        "search_boundary": payload["tools"],
        "available_tools": [] if qualification else ["WebSearch"],
        "tool_rule": (
            "Use only WebSearch, at most four calls, with only its query argument. "
            "Search the supplied public topic and UTC date window. This fallback "
            "has only a public web index; it has no native X search, source fetch, "
            "private content or exhaustive social-network coverage. Prefer one "
            "focused search and one or two useful leads backed by original-source "
            "links in the structured search results. X post URLs cannot establish "
            "citations on this route. Do not claim the unavailable tools were used. "
            "Return fewer leads or an empty list when source binding is missing. "
            "Return only the supplied strict JSON schema."
        )
        if not qualification
        else "Use no tools. Return only the supplied strict JSON schema.",
    }
    raw = canonical_json_bytes(document)
    if len(raw) > 65_536:
        raise ValueError("claude_prompt_too_large")
    return raw


def environment(home: Path, work: Path, token: str) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "HOME": str(home),
        "CLAUDE_CONFIG_DIR": str(home / "config"),
        "TMPDIR": str(work),
        "CLAUDE_CODE_OAUTH_TOKEN": token,
        "CLAUDE_CODE_CERT_STORE": "system",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
        "CLAUDE_CODE_SKIP_PROMPT_HISTORY": "1",
        "CLAUDE_CODE_MAX_RETRIES": "0",
    }


def arguments(binary: Path, value: bytes, *, qualification: bool) -> list[str]:
    allowed = "" if qualification else "WebSearch"
    return [
        str(binary),
        "--print",
        "--model",
        CLAUDE_MODEL,
        "--effort",
        "high",
        "--max-turns",
        "1" if qualification else "3",
        "--tools",
        allowed,
        "--allowedTools",
        allowed,
        "--setting-sources",
        "",
        "--settings",
        '{"disableAllHooks":true,"enabledPlugins":{}}',
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--disable-slash-commands",
        "--no-session-persistence",
        "--permission-mode",
        "plan",
        "--output-format",
        "stream-json",
        "--verbose",
        value.decode("utf-8"),
    ]


class ClaudeBuildWarningProvider:
    credential_route = CLAUDE_ROUTE

    def __init__(
        self,
        *,
        binary: Path = CLAUDE_BINARY,
        token: Path = CLAUDE_TOKEN,
        ram: Path = GROK_RAM,
    ) -> None:
        self.binary, self.token, self.ram = binary, token, ram
        self.cleanup_failed = False

    def _request(self, payload: Mapping[str, Any], *, qualification: bool) -> ProviderResult:
        started = monotonic()
        launched = False
        process = None
        temporary = None
        try:
            value = prompt(payload, qualification=qualification)
            token = preflight(self.binary, self.token, self.ram)
            temporary = tempfile.TemporaryDirectory(prefix="claude-", dir=self.ram)
            root = Path(temporary.name)
            home, work = root / "home", root / "work"
            home.mkdir(mode=0o700)
            work.mkdir(mode=0o700)
            stream = ClaudeStream(qualification=qualification)
            # Construction can fail after Popen starts. Without a fully closed
            # result, conservatively treat that boundary as potentially consumed.
            launched = True
            process = _Process(
                arguments(self.binary, value, qualification=qualification),
                cwd=work,
                env=environment(home, work, token),
            )
            process.byte_limit = MAX_BYTES
            while (line := process.line(started + 120)) is not None:
                stream.accept(_json(line))
            if process.finish(started + 120) != 0:
                raise ValueError("claude_process_failed")
            result = stream.result(
                request_bytes=len(value),
                response_bytes=process.bytes,
                elapsed_ms=int((monotonic() - started) * 1000),
            )
            if result.input_tokens > (500_000 if qualification else 1_500_000):
                raise ScheduledProviderError(
                    "provider_token_usage_exceeded",
                    retryable=False,
                    usage_uncertain=False,
                    exact_usage=ProviderUsageSnapshot(
                        **{
                            field.name: getattr(result, field.name)
                            for field in fields(ProviderUsageSnapshot)
                        }
                    ),
                )
            return result
        except ScheduledProviderError:
            raise
        except Exception as error:
            # No automatic fallback follows any started Claude process. Even a
            # terminal auth/quota error is not taken as proof of zero prior use.
            raise ScheduledProviderError(
                "claude_attempt_incomplete" if launched else "claude_preflight_uncharged",
                retryable=False,
                usage_uncertain=launched,
            ) from error
        finally:
            if process is not None:
                try:
                    process.close()
                except Exception:
                    self.cleanup_failed = True
            if temporary is not None:
                try:
                    temporary.cleanup()
                except OSError:
                    self.cleanup_failed = True

    def discover(self, payload: Mapping[str, Any]) -> ProviderResult:
        return self._request(payload, qualification=False)

    def qualify(self, payload: Mapping[str, Any]) -> ProviderResult:
        return self._request(payload, qualification=True)
