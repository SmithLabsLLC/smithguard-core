"""Bounded public-only fetching for fixed, source-qualified publisher endpoints."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import signal
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import certifi

ENDPOINTS = {
    "php": ("https://www.php.net/feed.atom", 2 * 1024 * 1024),
    "mozilla": ("https://blog.mozilla.org/security/feed/", 256 * 1024),
}


def selected_sources(value):
    """A release-bound subset; an unavailable source never implies an empty feed."""
    from smithguard.bulletin_sources import INTAKE_SOURCE_IDS

    if (
        not isinstance(value, (list, tuple))
        or not value
        or not all(
            isinstance(key, str) and key in ENDPOINTS.keys() | INTAKE_SOURCE_IDS.keys()
            for key in value
        )
        or len(value) != len(set(value))
    ):
        raise ValueError("official_source_selection_invalid")
    return tuple(value)


def configured_sources(body):
    """Reviewed release configuration, independent of mutable runtime selection."""
    from smithguard.identifiers import strict_json_loads

    document = strict_json_loads(body)
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "source_keys"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
    ):
        raise ValueError("official_source_profile_invalid")
    return selected_sources(document["source_keys"])


class FetchError(ValueError):
    pass


@dataclass(frozen=True)
class FetchResult:
    status: int
    body: bytes
    etag: str | None
    modified: str | None
    sha256: str | None


def header(value):
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 512
        or not value.isascii()
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise FetchError("conditional_header_invalid")
    return value


def resolve(host):
    from smithguard.bulletin_sources import NETWORK_SOURCES

    hosts = (
        {urlsplit(url).hostname for url, _ in ENDPOINTS.values()}
        | {urlsplit(item.endpoint).hostname for item in NETWORK_SOURCES.values()}
        | {item.record_host for item in NETWORK_SOURCES.values()}
    )
    if host not in hosts:
        raise FetchError("dns_host_not_allowed")
    # A killable child bounds libc DNS even when its resolver ignores Python signals.
    code = (
        "import json,socket,sys;print(json.dumps(socket.getaddrinfo(sys.argv[1],443,"
        "type=socket.SOCK_STREAM,proto=socket.IPPROTO_TCP)[:17]))"
    )
    result = subprocess.run(  # noqa: S603 - isolated interpreter, fixed code/host, no shell
        [sys.executable, "-I", "-c", code, host], capture_output=True, timeout=5, check=True
    )
    if len(result.stdout) > 16384:
        raise FetchError("dns_answer_budget")
    return json.loads(result.stdout)


def addresses(host):
    rows = resolve(host)
    if not 1 <= len(rows) <= 16:
        raise FetchError("dns_answer_budget")
    for family, kind, protocol, _, address in rows:
        if (
            family not in {socket.AF_INET, socket.AF_INET6}
            or kind != socket.SOCK_STREAM
            or protocol != socket.IPPROTO_TCP
        ):
            raise FetchError("dns_answer_invalid")
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped):
            raise FetchError("dns_address_not_public")
    return [
        (family, kind, protocol, label, tuple(address))
        for family, kind, protocol, label, address in rows
    ]


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, row, deadline):
        super().__init__(
            host, timeout=10, context=ssl.create_default_context(cafile=certifi.where())
        )
        self.row = row
        self.deadline = deadline

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise FetchError("fetch_deadline")
        return min(10, remaining)

    def connect(self):
        family, kind, protocol, _, address = self.row
        sock = socket.socket(family, kind, protocol)
        try:
            sock.settimeout(self.remaining())
            sock.connect(address)
            # The original official hostname, never the resolved IP, authenticates TLS.
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def _deadline(signum, frame):
    raise FetchError("fetch_deadline")


def fetch(source, *, etag=None, modified=None):
    if source not in ENDPOINTS:
        raise FetchError("source_not_allowed")
    url, maximum = ENDPOINTS[source]
    return _fetch(
        url,
        maximum,
        {"application/atom+xml", "application/rss+xml", "application/xml", "text/xml"},
        etag=etag,
        modified=modified,
    )


def fetch_public(source, *, url=None, etag=None, modified=None):
    from smithguard.bulletin_sources import NETWORK_SOURCES, fetch_target

    target, maximum, media = fetch_target(source, url)
    return _fetch(
        target,
        maximum,
        media,
        etag=etag,
        modified=modified,
        allow_not_found=NETWORK_SOURCES[source].format == "mail-discovery",
    )


def _fetch(url, maximum, accepted_media, *, etag=None, modified=None, allow_not_found=False):
    etag, modified = header(etag), header(modified)
    parts = urlsplit(url)
    # This entrypoint is a serialized main-thread worker. The timer also bounds DNS.
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise FetchError("fetch_timer_in_use")
    previous = signal.signal(signal.SIGALRM, _deadline)
    signal.setitimer(signal.ITIMER_REAL, 25)
    connection = None
    try:
        deadline = time.monotonic() + 25
        rows = addresses(parts.hostname)
        connection = PinnedHTTPS(parts.hostname, rows[0], deadline)
        headers = {
            "User-Agent": "SmithGuard official-notice intake/1.0",
            "Accept": ", ".join(sorted(accepted_media)),
            "Accept-Encoding": "identity",
        }
        if etag is not None:
            headers["If-None-Match"] = etag
        if modified is not None:
            headers["If-Modified-Since"] = modified
        connection.request("GET", parts.path, headers=headers)
        response = connection.getresponse()
        # No redirects, authentication, cookies, scripts or linked-content requests.
        if response.status == 304:
            if etag is None and modified is None:
                raise FetchError("unsolicited_not_modified")
            return FetchResult(304, b"", etag, modified, None)
        if response.status == 404 and allow_not_found:
            return FetchResult(404, b"", None, None, None)
        if response.status != 200:
            raise FetchError("source_http_failure")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise FetchError("encoded_response_refused")
        media = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if media not in accepted_media:
            raise FetchError("source_content_type_changed")
        length = response.getheader("Content-Length")
        if length is not None and (
            not length.isascii() or not length.isdigit() or not 0 < int(length) <= maximum
        ):
            raise FetchError("feed_bytes_budget")
        body = bytearray()
        while True:
            if connection.sock is not None:
                connection.sock.settimeout(connection.remaining())
            chunk = response.read(min(16384, maximum + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > maximum:
                raise FetchError("feed_bytes_budget")
        if not body or (length is not None and len(body) != int(length)):
            raise FetchError("feed_body_incomplete")
        return FetchResult(
            200,
            bytes(body),
            header(response.getheader("ETag")),
            header(response.getheader("Last-Modified")),
            hashlib.sha256(body).hexdigest(),
        )
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
