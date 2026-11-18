"""Validate an OpenSSF source link already bound to a retained advisory record."""

from urllib.parse import quote, unquote

from smithguard.openssf_git import (
    ADVISORY_ID,
    COMMIT,
    ECOSYSTEM,
    MAX_PACKAGE_PATH_CHARACTERS,
    MAX_PACKAGE_PATH_UTF8_BYTES,
    OPENSSF_REPOSITORY_URL,
    _safe_package_component,
)

SOURCE_NAME = "OpenSSF Malicious Packages"
LICENSE = "Apache-2.0"
PREFIX = OPENSSF_REPOSITORY_URL + "/blob/"
MAX_URL_CHARS = 4096


def verified_record_url(url: object, *, upstream_record_id: object) -> str | None:
    """Accept only the collector's canonical spelling of this exact source record."""
    if (
        not isinstance(url, str)
        or len(url) > MAX_URL_CHARS
        or not url.startswith(PREFIX)
        or not isinstance(upstream_record_id, str)
        or not ADVISORY_ID.fullmatch(upstream_record_id)
    ):
        return None
    commit, _, encoded_path = url.removeprefix(PREFIX).partition("/")
    if not COMMIT.fullmatch(commit):
        return None
    try:
        path = unquote(encoded_path, errors="strict")
        if quote(path, safe="/:@._+-") != encoded_path:
            return None
    except UnicodeError:
        return None
    parts = path.split("/")
    if (
        len(parts) < 5
        or parts[0] != "osv"
        or parts[1] not in {"malicious", "withdrawn"}
        or not ECOSYSTEM.fullmatch(parts[2])
        or parts[-1] != upstream_record_id + ".json"
        or not all(_safe_package_component(part) for part in parts[3:-1])
    ):
        return None
    package = "/".join(parts[3:-1])
    if (
        len(package) > MAX_PACKAGE_PATH_CHARACTERS
        or len(package.encode()) > MAX_PACKAGE_PATH_UTF8_BYTES
    ):
        return None
    return url
