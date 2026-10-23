import io
import signal
import socket
from types import SimpleNamespace

import pytest

import smithguard.official_notice_fetch as m


def public_rows(host="www.php.net", port=443, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))]


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fc00::1",
        "::ffff:93.184.216.34",
    ],
)
def test_nonpublic_resolution_refused(monkeypatch, ip):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    monkeypatch.setattr(
        m,
        "resolve",
        lambda *a, **k: [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))],
    )
    with pytest.raises(m.FetchError, match="dns_address_not_public"):
        m.addresses("www.php.net")


@pytest.mark.parametrize("value", ["x\r\nInjected: yes", "x\x00", "x" * 513, "\u00e9"])
def test_unsafe_conditional_header(value):
    with pytest.raises(m.FetchError, match="conditional_header_invalid"):
        m.header(value)


def install(monkeypatch, *, status=200, body=b"<feed/>", headers=None):
    record = []
    data = {"Content-Type": "application/atom+xml", **(headers or {})}

    class Connection:
        sock = None

        def __init__(self, host, row, deadline):
            record.append(("target", host, row))

        def request(self, method, path, headers):
            record.append(("request", method, path, headers))

        def getresponse(self):
            return SimpleNamespace(
                status=status,
                getheader=lambda key, default=None: data.get(key, default),
                read=io.BytesIO(body).read,
            )

        def close(self):
            record.append(("closed",))

    monkeypatch.setattr(m, "resolve", public_rows)
    monkeypatch.setattr(m, "PinnedHTTPS", Connection)
    return record


def test_success_is_exact_allowlisted_get(monkeypatch):
    record = install(monkeypatch)
    result = m.fetch("php")
    assert result.body == b"<feed/>"
    assert record[0][1] == "www.php.net"
    assert record[1][1:3] == ("GET", "/feed.atom")
    assert record[1][3]["Accept-Encoding"] == "identity"
    assert record[-1] == ("closed",)
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


@pytest.mark.parametrize("status", [301, 302, 307, 308, 401, 404, 429, 500])
def test_redirect_or_http_failure_never_followed(monkeypatch, status):
    record = install(monkeypatch, status=status, headers={"Location": "https://127.0.0.1/"})
    with pytest.raises(m.FetchError, match="source_http_failure"):
        m.fetch("php")
    assert len([r for r in record if r[0] == "request"]) == 1
    assert record[-1] == ("closed",)


@pytest.mark.parametrize(
    "headers,reason",
    [
        ({"Content-Encoding": "gzip"}, "encoded_response_refused"),
        ({"Content-Type": "text/html"}, "source_content_type_changed"),
        ({"Content-Length": "-1"}, "feed_bytes_budget"),
        ({"Content-Length": "999999999"}, "feed_bytes_budget"),
        ({"Content-Length": "100"}, "feed_body_incomplete"),
    ],
)
def test_response_bounds(monkeypatch, headers, reason):
    install(monkeypatch, headers=headers)
    with pytest.raises(m.FetchError, match=reason):
        m.fetch("php")


def test_chunked_over_limit_refused(monkeypatch):
    install(monkeypatch, body=b"x" * (256 * 1024 + 1))
    with pytest.raises(m.FetchError, match="feed_bytes_budget"):
        m.fetch("mozilla")


def test_304_requires_known_cursor(monkeypatch):
    install(monkeypatch, status=304)
    with pytest.raises(m.FetchError, match="unsolicited_not_modified"):
        m.fetch("php")
    assert m.fetch("php", etag='"known"').status == 304


def test_unknown_endpoint_has_zero_resolution(monkeypatch):
    monkeypatch.setattr(m, "resolve", lambda *a, **k: pytest.fail("network"))
    with pytest.raises(m.FetchError, match="source_not_allowed"):
        m.fetch("https://localhost/")


def test_dns_deadline_restores_handler(monkeypatch):
    before = signal.getsignal(signal.SIGALRM)
    monkeypatch.setattr(m, "resolve", lambda *a, **k: m._deadline(None, None))
    with pytest.raises(m.FetchError, match="fetch_deadline"):
        m.fetch("php")
    assert signal.getsignal(signal.SIGALRM) == before
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
