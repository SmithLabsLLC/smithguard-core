"""One reader and one line-preserving writer for KEY=value environment files.

Every deploy-side environment file read or edit goes through this module. The
options reproduce the rules each call site historically enforced; nothing here
guesses, expands or reorders a value.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Literal

NAME_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
QUOTES = frozenset({"'", '"'})


class EnvFileError(ValueError):
    """An environment file is malformed under the rules the caller selected."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def decode_ascii_lines(body: bytes) -> list[str]:
    """Split a strictly ASCII body into lines; any other byte fails closed."""
    try:
        return body.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise EnvFileError("not_ascii", "environment file is not ASCII") from error


def parse_env_lines(
    lines: Iterable[str],
    *,
    allow_export: bool = False,
    strip_quotes: bool = False,
    skip_comments: bool = False,
    duplicates: Literal["reject", "last"] = "reject",
    validate_names: bool = False,
    reject_padded_values: bool = False,
) -> dict[str, str]:
    """Parse KEY=value lines into an ordered mapping.

    ``skip_comments`` strips each line and ignores blank and ``#`` lines; without it
    every line must be an assignment. ``allow_export`` drops one ``export `` prefix.
    ``strip_quotes`` removes one matching pair of surrounding quotes from a value of
    at least two characters. ``duplicates`` either rejects a repeated key or keeps
    the last value. ``validate_names`` requires ``[A-Z][A-Z0-9_]{1,63}`` names and
    rejects NUL bytes in values. ``reject_padded_values`` refuses a value with
    leading or trailing whitespace.
    """
    if duplicates not in {"reject", "last"}:
        raise ValueError("duplicates must be 'reject' or 'last'")
    result: dict[str, str] = {}
    for raw in lines:
        line = raw.strip() if skip_comments else raw
        if skip_comments and (not line or line.startswith("#")):
            continue
        if allow_export and line.startswith("export "):
            line = line.removeprefix("export ")
        name, separator, value = line.partition("=")
        if not separator:
            raise EnvFileError("unsupported", "environment line is not an assignment")
        if validate_names and (NAME_PATTERN.fullmatch(name) is None or "\x00" in value):
            raise EnvFileError("unsupported", "environment line has an unsupported name or value")
        if reject_padded_values and value != value.strip():
            raise EnvFileError("ambiguous", "environment value carries surrounding whitespace")
        if strip_quotes and len(value) >= 2 and value[0] == value[-1] and value[0] in QUOTES:
            value = value[1:-1]
        if name in result and duplicates == "reject":
            raise EnvFileError("ambiguous", f"environment key is repeated: {name}")
        result[name] = value
    return result


def values_for(lines: Iterable[str], name: str) -> list[str]:
    """Every value assigned to ``name`` by a line that starts with ``name=``."""
    prefix = f"{name}="
    return [line[len(prefix) :] for line in lines if line.startswith(prefix)]


def replace_env_values(
    lines: Iterable[str],
    updates: Mapping[str, str],
    *,
    require_present: bool = True,
    append_missing: bool = False,
) -> list[str]:
    """Replace the ``KEY=`` line for each update and keep every other line as it is.

    A key that appears more than once fails closed. A missing key fails when
    ``require_present`` is set, is appended at the end when ``append_missing`` is set,
    and is otherwise left absent.
    """
    output = list(lines)
    for name, value in updates.items():
        prefix = f"{name}="
        indexes = [index for index, line in enumerate(output) if line.startswith(prefix)]
        if len(indexes) > 1:
            raise EnvFileError("not_unique", f"environment key is not unique: {name}")
        if indexes:
            output[indexes[0]] = f"{name}={value}"
        elif require_present:
            raise EnvFileError("missing", f"environment key is absent: {name}")
        elif append_missing:
            output.append(f"{name}={value}")
    return output


def render_env_lines(lines: Iterable[str]) -> bytes:
    """Render lines back to ASCII bytes with one trailing newline."""
    return ("\n".join(lines) + "\n").encode("ascii")
