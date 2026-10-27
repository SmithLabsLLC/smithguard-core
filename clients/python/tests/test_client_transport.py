import asyncio
from threading import Event

import httpx
import pytest

from smithguard_client.discovery import artifact, discover
from smithguard_client.transport import API, PublicReader, ReadFailure, approved_coordinates


class Tick:
    def __init__(self):
        self.now = 100

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Stream(httpx.AsyncByteStream):
    def __init__(self, *chunks):
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk


def response(status=200, body=b"{}", **headers):
    return httpx.Response(
        status, headers={"content-type": "application/json", **headers}, stream=Stream(body)
    )


def reader(handler, **kwargs):
    tick = Tick()
    return PublicReader(
        _transport=httpx.MockTransport(handler), _clock=tick.clock, _sleep=tick.sleep, **kwargs
    )


def test_consent_requires_entire_current_preview(tmp_path):
    preview = discover([str(tmp_path)], approved_public=[])
    assert approved_coordinates(preview, preview["approval_sha256"]) == []
    changed = {**preview, "scopes": ["/private/changing-scope"]}
    with pytest.raises(ValueError):
        approved_coordinates(changed, preview["approval_sha256"])
    with pytest.raises(ValueError):
        approved_coordinates(preview, "yes")


def test_private_data_never_enters_requests_cookies_not_reused(monkeypatch):
    requests = []
    monkeypatch.setenv("HTTPS_PROXY", "https://private:secret@proxy.invalid")
    monkeypatch.setenv("NETRC", "/private/netrc-canary")

    def handler(request):
        requests.append(request)
        return response(**{"set-cookie": "secret-cookie=canary"})

    r = reader(handler)
    r.assess(artifact("public-demo", "1.0"))
    r.assess(artifact("public-demo", "2.0"))
    assert len(requests) == 2
    for request in requests:
        assert str(request.url).startswith(API + "/v1/artifacts/assess?")
        assert set(request.url.params) == {"ecosystem", "registry_host", "name", "version"}
        assert "authorization" not in request.headers and "cookie" not in request.headers
        assert request.content == b""
        assert not any(
            x in str(request.headers) + str(request.url) for x in ["canary", "private", "secret"]
        )


@pytest.mark.parametrize("status", [301, 302, 307, 308, 400, 401, 403, 404, 413])
def test_nonretryable_status_and_redirect_never_followed(status):
    calls = []

    def handler(request):
        calls.append(request)
        return response(status, **{"location": "https://private.invalid"})

    with pytest.raises(ReadFailure, match="http_error"):
        reader(handler)._read("/v1/artifacts/assess")
    assert len(calls) == 1


def test_rate_limit_stops_without_retry():
    calls = []

    def handler(request):
        calls.append(request)
        return response(429)

    with pytest.raises(ReadFailure) as e:
        reader(handler).assess(artifact("public", "1"))
    assert e.value.stop_run and len(calls) == 1


@pytest.mark.parametrize("status", [502, 503, 504])
def test_single_delayed_retry(status):
    calls = []

    def handler(request):
        calls.append(request)
        return response(status if len(calls) == 1 else 200, **{"retry-after": "2"})

    r = reader(handler)
    assert r._read("/v1/artifacts/assess") == b"{}"
    assert len(calls) == 2 and r.clock() >= 102


def test_retry_rejected_when_it_cannot_fit():
    calls = []

    def handler(request):
        calls.append(request)
        return response(503, **{"retry-after": "1000"})

    with pytest.raises(ReadFailure) as e:
        reader(handler, budget_seconds=3)._read("/v1/artifacts/assess")
    assert e.value.stop_run and len(calls) == 1


@pytest.mark.parametrize(
    "headers,body,reason",
    [
        ({"content-encoding": "gzip"}, b"bad", "encoding"),
        ({"content-type": "text/html"}, b"bad", "content_type"),
        ({}, b"x" * 1048577, "byte_limit"),
    ],
    ids=["encoding", "content-type", "byte-limit"],
)
def test_bound_response(headers, body, reason):
    with pytest.raises(ReadFailure, match=reason):
        reader(lambda request: response(body=body, **headers))._read("/v1/artifacts/assess")


def test_cancel_prevents_request():
    event = Event()
    event.set()
    calls = []
    with pytest.raises(ReadFailure, match="cancelled"):
        reader(lambda req: calls.append(req), stopped=event)._read("/v1/artifacts/assess")
    assert not calls


def test_protocol_error_is_sanitized():
    def handler(request):
        raise httpx.RemoteProtocolError("PRIVATE-CANARY")

    with pytest.raises(ReadFailure) as e:
        reader(handler)._read("/v1/artifacts/assess")
    assert str(e.value) == "http_protocol_failure" and "PRIVATE" not in str(e.value)


def test_async_total_deadline_covers_slow_body():
    class Slow(httpx.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.sleep(0.1)
            yield b"{}"

    r = reader(
        lambda req: httpx.Response(200, headers={"content-type": "application/json"}, stream=Slow())
    )
    with pytest.raises(TimeoutError):
        asyncio.run(r._single("/v1/artifacts/assess", None, 100, 0.01))


def test_unknown_endpoint_cannot_be_requested():
    with pytest.raises(ValueError):
        reader(lambda req: response())._read("/private")


@pytest.mark.parametrize(
    "date,age",
    [
        (None, None),
        ("Mon, 26 Oct 2020 12:00:00 GMT", "0"),
        ("now", "301"),
        ("now", "-1"),
        ("now", "invalid"),
    ],
)
def test_stale_cached_key_status_cannot_become_current(date, age):
    from datetime import UTC, datetime
    from email.utils import format_datetime

    headers = {}
    if date:
        headers["Date"] = format_datetime(datetime.now(UTC), usegmt=True) if date == "now" else date
    if age:
        headers["Age"] = age
    r = reader(lambda req: response(**headers))
    with pytest.raises(ReadFailure, match="key_status_freshness_unqualified"):
        r._read("/v1/public-keys/gbsec:snapshot-public-key:" + "a" * 40 + ".json")


def test_fresh_key_retains_server_age_in_current_status_clock():
    from datetime import UTC, datetime
    from email.utils import format_datetime

    r = reader(
        lambda req: response(Date=format_datetime(datetime.now(UTC), usegmt=True), Age="100")
    )
    r._read("/v1/public-keys/gbsec:snapshot-public-key:" + "a" * 40 + ".json")
    assert 99 <= (datetime.now(UTC) - r.key_response_time).total_seconds() <= 102
