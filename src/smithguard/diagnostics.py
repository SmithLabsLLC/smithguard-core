"""Bounded internal exception diagnostics with tracked-secret-pattern redaction."""

from __future__ import annotations

import re
import sys

MAX_DIAGNOSTIC_LINES = 20
MAX_DIAGNOSTIC_LINE_BYTES = 1024

_SECRET_PATTERNS = (
    re.compile(
        r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
        r"CLOUDFLARE_API_TOKEN|AGENTMAIL_API_KEY|DATABASE_PASSWORD|GITHUB_API_KEY|"
        r"GITHUB_TOKEN|OPENAI_API_KEY|SLACK_BOT_TOKEN|XAI_API_KEY)\s*=\s*[^\s]+"
    ),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    re.compile(r"A(?:KIA|SIA)[0-9A-Z]{16}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
    re.compile(
        r"(?:postgres(?:ql)?|mysql|mongodb)(?:\+[A-Za-z0-9_.-]+)?://"
        r"[^\s/@:]+:[^\s/@]+@"
    ),
)


def _redact_line(value: str) -> str:
    redacted = value
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    ascii_line = "".join(character if " " <= character <= "~" else " " for character in redacted)
    return ascii_line.encode("ascii")[:MAX_DIAGNOSTIC_LINE_BYTES].decode("ascii")


def _exception_stderr(error: BaseException) -> str | None:
    visited: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        value = getattr(current, "stderr", None)
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        if isinstance(value, str):
            return value
        current = current.__cause__ or current.__context__
    return None


def redacted_message(error: BaseException) -> str:
    """The exception text as one bounded, redacted ASCII line (empty when it has none)."""
    text = str(error).strip()
    return _redact_line(" ".join(text.split())) if text else ""


def exception_diagnostic_lines(
    error: BaseException,
    *,
    stderr: str | bytes | None = None,
) -> tuple[str, ...]:
    """Return the exception class, its message, and at most 20 safe stderr lines."""
    if stderr is None:
        stderr = _exception_stderr(error)
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    values = () if stderr is None else stderr.splitlines()[-MAX_DIAGNOSTIC_LINES:]
    message = redacted_message(error)
    return (
        f"error_class={type(error).__name__}",
        *((f"error_message={message}",) if message else ()),
        *tuple(f"error_stderr={_redact_line(value)}" for value in values),
    )


def write_exception_diagnostic(
    error: BaseException,
    *,
    stderr: str | bytes | None = None,
) -> None:
    """Write one bounded, redacted internal diagnostic to standard error."""
    for line in exception_diagnostic_lines(error, stderr=stderr):
        sys.stderr.write(line + "\n")
