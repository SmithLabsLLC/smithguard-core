from __future__ import annotations

import gzip
import json
from dataclasses import replace
from datetime import UTC, date, datetime

import httpx
import pytest

from smithguard.contracts.generated import PublicEpssValue
from smithguard.cve_enrichment import (
    EPSS_CURRENT_URL,
    CveEnrichmentError,
    EnrichmentLimits,
    epss_api_url,
    epss_bulk_url,
    fetch_epss,
    fetch_epss_bulk,
    fetch_epss_current,
    fetch_kev,
    parse_epss,
    parse_epss_csv_gzip,
    parse_kev,
)
from smithguard.identifiers import sha256_id
from smithguard.source_rights import SourceProfile

NOW = datetime(2026, 10, 6, 23, tzinfo=UTC)
DAY = NOW.date()
A = "CVE-2021-44228"
B = "CVE-2023-34362"
MISSING = "CVE-2026-999999"


def api_body(rows=None, **changes):
    rows = (
        rows
        if rows is not None
        else [
            {"cve": A, "epss": "0.999990000", "percentile": "1.000000000", "date": str(DAY)},
            {"cve": B, "epss": "0.999340000", "percentile": "0.999710000", "date": str(DAY)},
        ]
    )
    value = {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "total": len(rows),
        "offset": 0,
        "limit": 100,
        "data": rows,
    }
    value.update(changes)
    return json.dumps(value).encode()


def kev_body(rows=None, **changes):
    rows = (
        rows
        if rows is not None
        else [
            {"cveID": A, "dateAdded": "2021-12-10", "shortDescription": "Do not project prose"},
            {"cveID": B, "dateAdded": "2023-06-02", "notes": "Do not project links or prose"},
        ]
    )
    value = {
        "catalogVersion": "2026.10.06",
        "dateReleased": "2026-10-06T12:00:00Z",
        "count": len(rows),
        "vulnerabilities": rows,
    }
    value.update(changes)
    return json.dumps(value).encode()


def csv_body(rows=None, *, metadata=None, newline=True):
    rows = (
        rows
        if rows is not None
        else [f"{A},0.999990000,1.000000000", f"{B},0.999340000,0.999710000"]
    )
    metadata = metadata or "#model_version:v2026.06.15,score_date:2026-10-06T12:00:23Z"
    return gzip.compress(
        ("\n".join([metadata, "cve,epss,percentile", *rows]) + ("\n" if newline else "")).encode(),
        mtime=0,
    )


def profile(source="first-epss", **changes):
    fields = ["cve", "epss", "percentile", "date", "model_version"]
    if source == "cisa-kev":
        fields = ["cve", "date_added"]
    raw = {
        "id": "gbsec:source:" + source,
        "kill_switch": True,
        "allowed_hosts": ["api.first.org", "epss.empiricalsecurity.com", "www.cisa.gov"],
        "acquisition_methods": ["rest_api", "download"],
        "rights": {
            "decision": "approved_public",
            "normalized_fact_redistribution": "attribution",
            "retrieval": "allowed",
            "review_due_on": "2027-01-01",
        },
    }
    raw.update(changes)
    return SourceProfile(
        "phase1_planned_artifact_enrichment",
        raw,
        (
            {
                "fields": fields,
                "storage": "immutable_by_date",
                "public_output": "allowed_with_attribution",
            },
        ),
    )


def transport(body, *, media="application/json", status=200, headers=None, calls=None):
    def handler(request):
        if calls is not None:
            calls.append(request)
        return httpx.Response(
            status,
            headers={"Content-Type": media, "Content-Length": str(len(body)), **(headers or {})},
            stream=httpx.ByteStream(body),
        )

    return httpx.MockTransport(handler)


def test_api_positive_controls_exact_scores_and_missing_are_distinct():
    body = api_body()
    result = parse_epss(body, [MISSING, B, A], observed_at=NOW)
    assert result.response_sha256 == sha256_id(body)
    assert result.requested_cves == (A, B, MISSING)
    assert result.missing_cves == (MISSING,)
    assert [
        (row.cve, row.epss, row.percentile, row.score_date, row.model_version)
        for row in result.scores
    ] == [
        (A, "0.99999", "1", DAY, None),
        (B, "0.99934", "0.99971", DAY, None),
    ]
    assert result.model_version is None  # API envelope version is not an EPSS model version.
    assert not result.scores[0].is_stale(as_of=NOW)
    assert result.scores[0].is_stale(as_of=datetime(2026, 10, 9, tzinfo=UTC))


def test_zero_score_is_present_and_empty_success_reports_only_missing():
    row = {"cve": A, "epss": "0.000000000", "percentile": "0", "date": str(DAY)}
    assert parse_epss(api_body([row]), [A], observed_at=NOW).scores[0].epss == "0"
    result = parse_epss(api_body([]), [A], observed_at=NOW)
    assert result.scores == () and result.missing_cves == (A,) and result.score_date is None


@pytest.mark.parametrize(
    "changes",
    [
        {"total": 3},
        {"offset": 1},
        {"limit": 1},
        {"total": True},
        {"status-code": True},
        {"status": "ERROR"},
        {"data": {}},
    ],
)
def test_api_rejects_incomplete_envelopes(changes):
    with pytest.raises(CveEnrichmentError, match="incomplete_epss_page"):
        parse_epss(api_body(**changes), [A, B], observed_at=NOW)


@pytest.mark.parametrize(
    "field,value",
    [
        ("epss", "NaN"),
        ("epss", "1e-9999"),
        ("epss", "1.01"),
        ("epss", -1),
        ("epss", True),
        ("percentile", "Infinity"),
        ("percentile", "-0"),
        ("date", "2026-10-07"),
        ("date", "2026-02-30"),
        ("date", "20261006"),
        ("model_version", "arbitrary provider narrative"),
        ("cve", A.lower()),
    ],
)
def test_api_rejects_invalid_field_values(field, value):
    row = {"cve": A, "epss": "0.5", "percentile": "0.7", "date": str(DAY), field: value}
    with pytest.raises(CveEnrichmentError):
        parse_epss(api_body([row]), [A], observed_at=NOW)


def test_api_rejects_duplicate_unrequested_and_mixed_dates():
    rows = json.loads(api_body())["data"]
    for values in (
        [rows[0], rows[0]],
        [{**rows[0], "cve": MISSING}],
        [rows[0], {**rows[1], "date": "2026-10-05"}],
    ):
        with pytest.raises(CveEnrichmentError):
            parse_epss(api_body(values), [A, B], observed_at=NOW)


@pytest.mark.parametrize("field", ["epss", "percentile"])
@pytest.mark.parametrize("kind", ["api", "bulk"])
@pytest.mark.parametrize("value,accepted", [("1e-30", True), ("1e-31", False)])
def test_score_rendering_matches_public_contract_before_storage(field, kind, value, accepted):
    row = {"cve": A, "epss": "0.5", "percentile": "0.7", "date": str(DAY), field: value}

    def parse():
        if kind == "api":
            return parse_epss(api_body([row]), [A], observed_at=NOW)
        return parse_epss_csv_gzip(
            csv_body([f"{A},{row['epss']},{row['percentile']}"]),
            [A],
            score_date=DAY,
            observed_at=NOW,
        )

    if not accepted:
        with pytest.raises(CveEnrichmentError, match="invalid_score"):
            parse()
    else:
        score = parse().scores[0]
        assert len(getattr(score, field)) == 32
        PublicEpssValue(
            epss=score.epss,
            percentile=score.percentile,
            score_date=score.score_date,
            model_version=score.model_version,
        )


@pytest.mark.parametrize(
    "body",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":1e400}',
        b"\xff",
        b'{"a":' + b"[" * 20 + b"0" + b"]" * 20 + b"}",
    ],
)
def test_strict_json_rejects_bad_encoding_duplicates_nonfinite_and_depth(body):
    with pytest.raises(CveEnrichmentError):
        parse_kev(body, observed_at=NOW)


def test_kev_projects_minimal_membership_and_retains_removal_and_correction():
    previous = parse_kev(kev_body(), observed_at=NOW)
    body = kev_body([{"cveID": A, "dateAdded": "2021-12-11"}])
    corrected = parse_kev(body, observed_at=NOW)
    assert corrected.entries[0].date_added == date(2021, 12, 11)
    assert corrected.response_sha256 != previous.response_sha256
    assert corrected.removed_since(previous) == (B,)
    assert not hasattr(corrected.entries[0], "notes")
    with pytest.raises(CveEnrichmentError, match="snapshot_time_regression"):
        replace(corrected, date_released=datetime(2026, 10, 5, tzinfo=UTC)).removed_since(previous)


@pytest.mark.parametrize(
    "changes",
    [
        {"count": 3},
        {"count": True},
        {"count": 0},
        {"dateReleased": "2026-10-06"},
        {"dateReleased": "2026-10-07T00:00:00Z"},
        {"catalogVersion": 3},
    ],
)
def test_kev_rejects_bad_top_level(changes):
    with pytest.raises(CveEnrichmentError):
        parse_kev(kev_body(**changes), observed_at=NOW)


def test_kev_rejects_duplicate_or_future_added():
    row = {"cveID": A, "dateAdded": "2021-12-10"}
    for rows in ([row, row], [{**row, "dateAdded": "2026-10-07"}]):
        with pytest.raises(CveEnrichmentError):
            parse_kev(kev_body(rows), observed_at=NOW)


def test_bulk_validates_all_rows_streamed_and_projects_only_exact_selection():
    body = csv_body()
    for chunks in (body, [body[i : i + 1] for i in range(len(body))]):
        result = parse_epss_csv_gzip(chunks, [A, MISSING], score_date=DAY, observed_at=NOW)
        assert result.response_sha256 == sha256_id(body)
        assert result.validated_rows == 2
        assert tuple(row.cve for row in result.scores) == (A,)
        assert result.missing_cves == (MISSING,)
        assert result.scores[0].model_version == "v2026.06.15"
        assert result.score_timestamp == datetime(2026, 10, 6, 12, 0, 23, tzinfo=UTC)


def test_bulk_preserves_bounded_scientific_and_full_precision_decimal_values():
    result = parse_epss_csv_gzip(
        csv_body([f"{A},1.2345678901234567e-05,0.000000000000000000012345678901"]),
        [A],
        score_date=DAY,
        observed_at=NOW,
    )
    assert result.scores[0].epss == "0.000012345678901234567"
    assert result.scores[0].percentile == "0.000000000000000000012345678901"


@pytest.mark.parametrize(
    "rows",
    [
        [f"{B},NaN,0.2"],
        [f"{B},1e-31,0.2"],
        [f"{B},0.1,1e-31"],
        [f"{B},0.1,0.2", f"{B},0.3,0.4"],
        [],
        [f"{B},0.2,0.3,extra"],
        [f'"{B}",0.2,0.3'],
        ["bad-cve,0.1,0.2"],
    ],
)
def test_bulk_rejects_bad_or_duplicate_unselected_rows(rows):
    with pytest.raises(CveEnrichmentError):
        parse_epss_csv_gzip(csv_body(rows), [A], score_date=DAY, observed_at=NOW)


@pytest.mark.parametrize(
    "metadata",
    [
        "#score_date:2026-10-06",
        "#model_version:v5,score_date:2026-10-05",
        "#model_version:v5,score_date:2026-10-06T12:00:00",
        "#model_version:v5,score_date:bad",
    ],
)
def test_bulk_requires_exact_dated_metadata(metadata):
    with pytest.raises(CveEnrichmentError):
        parse_epss_csv_gzip(csv_body(metadata=metadata), [A], score_date=DAY, observed_at=NOW)


def test_bulk_rejects_truncation_crc_trailing_member_and_unterminated_csv():
    body = csv_body()
    corrupt = body[:-8] + bytes([body[-8] ^ 1]) + body[-7:]
    for invalid in (
        body[:-1],
        corrupt,
        body + b"junk",
        body + gzip.compress(b"x\n"),
        csv_body(newline=False),
    ):
        with pytest.raises(CveEnrichmentError):
            parse_epss_csv_gzip(invalid, [A], score_date=DAY, observed_at=NOW)


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"max_compressed_bytes": 10}, "compressed_size_limit"),
        ({"max_expanded_bytes": 10}, "expanded_size_limit"),
        ({"max_line_bytes": 10}, "line_size_limit"),
        ({"max_rows": 1}, "row_limit"),
        ({"max_selected_cves": 1}, "selection_limit"),
    ],
)
def test_bulk_enforces_each_resource_bound(changes, code):
    with pytest.raises(CveEnrichmentError, match=code):
        parse_epss_csv_gzip(
            csv_body(), [A, B], score_date=DAY, observed_at=NOW, limits=EnrichmentLimits(**changes)
        )


def test_fetchers_use_exact_fixed_urls_no_auth_and_single_request():
    calls = []
    assert (
        fetch_epss(
            [A, B], profile=profile(), observed_at=NOW, transport=transport(api_body(), calls=calls)
        ).validated_rows
        == 2
    )
    assert str(calls[0].url) == epss_api_url([A, B])
    assert "authorization" not in calls[0].headers
    assert calls[0].headers["accept-encoding"] == "identity"
    calls.clear()
    result = fetch_epss_bulk(
        [A],
        score_date=DAY,
        profile=profile(),
        observed_at=NOW,
        transport=transport(csv_body(), media="binary/octet-stream", calls=calls),
    )
    assert result.source_url == epss_bulk_url(DAY) and len(calls) == 1
    assert (
        fetch_kev(profile=profile("cisa-kev"), observed_at=NOW, transport=transport(kev_body()))
        .entries[0]
        .cve
        == A
    )


@pytest.mark.parametrize(
    "status,headers,media,code",
    [
        (302, {"Location": "https://evil.invalid"}, "application/json", "http_status_rejected"),
        (404, {}, "application/json", "http_not_found"),
        (200, {"Content-Encoding": "gzip"}, "application/json", "content_encoding_rejected"),
        (200, {"Content-Length": "999999999"}, "application/json", "body_size_limit"),
        (200, {"Content-Length": "1"}, "application/json", "content_length_mismatch"),
        (200, {"Content-Length": "-1"}, "application/json", "content_length_rejected"),
        (200, {}, "text/html", "media_type_rejected"),
    ],
)
def test_fetch_rejects_redirect_encoding_length_status_media_without_retry(
    status,
    headers,
    media,
    code,
):
    calls = []
    with pytest.raises(CveEnrichmentError, match=code):
        fetch_epss(
            [A, B],
            profile=profile(),
            observed_at=NOW,
            transport=transport(
                api_body(), status=status, headers=headers, media=media, calls=calls
            ),
        )
    assert len(calls) == 1


@pytest.mark.parametrize(
    "change",
    ["activation", "kill", "review", "link_only", "host", "method", "fields", "wrong_source"],
)
def test_source_rights_fail_before_transport(change):
    approved = profile()
    raw = {**approved.source, "rights": dict(approved.source["rights"])}
    fields = approved.field_rules
    activation = approved.activation
    if change == "activation":
        activation = "enrichment_only"
    elif change == "kill":
        raw["kill_switch"] = False
    elif change == "review":
        raw["rights"]["review_due_on"] = "2026-10-05"
    elif change == "link_only":
        raw["rights"]["decision"] = "approved_link_only"
    elif change == "host":
        raw["allowed_hosts"] = ["www.first.org"]
    elif change == "method":
        raw["acquisition_methods"] = ["download"]
    elif change == "fields":
        fields = ({"fields": ["cve"], "storage": "omit", "public_output": "omit"},)
    else:
        raw["id"] = "gbsec:source:wrong"
    calls = []
    with pytest.raises(CveEnrichmentError):
        fetch_epss(
            [A],
            profile=SourceProfile(activation, raw, fields),
            observed_at=NOW,
            transport=transport(api_body(), calls=calls),
        )
    assert calls == []


def test_transport_timeout_is_sanitized_and_deadline_exhaustion_rejects():
    def fail(request):
        raise httpx.ReadTimeout("SECRET PROVIDER MESSAGE", request=request)

    with pytest.raises(CveEnrichmentError) as caught:
        fetch_epss([A], profile=profile(), observed_at=NOW, transport=httpx.MockTransport(fail))
    assert str(caught.value) == "transport_unavailable"
    values = iter([0, 1, 21])
    with pytest.raises(CveEnrichmentError, match="operation_time_limit"):
        fetch_epss(
            [A],
            profile=profile(),
            observed_at=NOW,
            transport=transport(api_body()),
            clock=lambda: next(values),
        )


def test_invalid_selection_and_naive_time_rejected():
    for selected in ([], [A, A], [A.lower()], [f"CVE-2026-{i:05}" for i in range(101)]):
        with pytest.raises(CveEnrichmentError):
            epss_api_url(selected)
    with pytest.raises(CveEnrichmentError, match="invalid_observed_at"):
        parse_epss(api_body(), [A], observed_at=NOW.replace(tzinfo=None))


def current_transport(
    calls, *, location=None, status=302, body=None, final_status=200, final_headers=None
):
    def handler(request):
        calls.append(request)
        if str(request.url) == EPSS_CURRENT_URL:
            return httpx.Response(
                status,
                headers={"Location": epss_bulk_url(DAY) if location is None else location},
                stream=httpx.ByteStream(b"ignored redirect body"),
            )
        content = csv_body() if body is None else body
        return httpx.Response(
            final_status,
            headers={
                "Content-Type": "application/gzip",
                "Content-Length": str(len(content)),
                **(final_headers or {}),
            },
            stream=httpx.ByteStream(content),
        )

    return httpx.MockTransport(handler)


@pytest.mark.parametrize(
    "location",
    [epss_bulk_url(DAY), "/epss_scores-2026-10-06.csv.gz", "epss_scores-2026-10-06.csv.gz"],
)
def test_current_resolves_one_official_dated_redirect_and_retains_raw_identity(location):
    calls = []
    result = fetch_epss_current(
        [A, MISSING],
        profile=profile(),
        observed_at=NOW,
        transport=current_transport(calls, location=location),
    )
    assert [str(call.url) for call in calls] == [EPSS_CURRENT_URL, epss_bulk_url(DAY)]
    assert result.source_url == epss_bulk_url(DAY)
    assert result.response_sha256 == sha256_id(csv_body())
    assert result.score_date == DAY and result.score_timestamp is not None
    assert result.scores[0].cve == A and result.missing_cves == (MISSING,)
    assert all(call.headers["accept-encoding"] == "identity" for call in calls)
    assert all("authorization" not in call.headers for call in calls)


@pytest.mark.parametrize(
    "location,status,code",
    [
        (epss_bulk_url(DAY), 200, "current_redirect_rejected"),
        (epss_bulk_url(DAY), 404, "current_redirect_rejected"),
        (epss_bulk_url(DAY), 304, "current_redirect_rejected"),
        ("https://evil.invalid/epss_scores-2026-10-06.csv.gz", 302, "current_redirect_rejected"),
        (
            "http://epss.empiricalsecurity.com/epss_scores-2026-10-06.csv.gz",
            302,
            "current_redirect_rejected",
        ),
        (EPSS_CURRENT_URL, 302, "current_redirect_rejected"),
        (epss_bulk_url(DAY) + "?x=1", 302, "current_redirect_rejected"),
        (epss_bulk_url(DAY) + "#fragment", 302, "current_redirect_rejected"),
        ("../epss_scores-2026-10-06.csv.gz", 302, "current_redirect_rejected"),
        (
            "https://epss.empiricalsecurity.com:443/epss_scores-2026-10-06.csv.gz",
            302,
            "current_redirect_rejected",
        ),
        (
            "https://user@epss.empiricalsecurity.com/epss_scores-2026-10-06.csv.gz",
            302,
            "current_redirect_rejected",
        ),
        ("/epss_scores-2026-02-30.csv.gz", 302, "invalid_date"),
        ("/epss_scores-2026-10-07.csv.gz", 302, "future_date"),
        ("/epss_scores-2026-10-03.csv.gz", 302, "stale_epss_feed"),
        ("", 302, "current_redirect_rejected"),
    ],
)
def test_current_rejects_untrusted_redirect_status_path_or_date_before_second_request(
    location, status, code
):
    calls = []
    with pytest.raises(CveEnrichmentError, match=code):
        fetch_epss_current(
            [A],
            profile=profile(),
            observed_at=NOW,
            transport=current_transport(calls, location=location, status=status),
        )
    assert len(calls) == 1


@pytest.mark.parametrize(
    "final_status,headers,body,code",
    [
        (302, {"Location": epss_bulk_url(DAY)}, None, "http_status_rejected"),
        (200, {"Content-Type": "text/html"}, None, "media_type_rejected"),
        (200, {"Content-Length": "1"}, None, "content_length_mismatch"),
        (
            200,
            {},
            csv_body(metadata="#model_version:v5,score_date:2026-10-05"),
            "score_date_mismatch",
        ),
        (
            200,
            {},
            csv_body(metadata="#model_version:v5,score_date:2026-10-06T23:01:00Z"),
            "future_date",
        ),
    ],
)
def test_current_rejects_second_redirect_or_invalid_dated_body(final_status, headers, body, code):
    calls = []
    with pytest.raises(CveEnrichmentError, match=code):
        fetch_epss_current(
            [A],
            profile=profile(),
            observed_at=NOW,
            transport=current_transport(
                calls, final_status=final_status, final_headers=headers, body=body
            ),
        )
    assert len(calls) == 2


@pytest.mark.parametrize(
    "timestamp,accepted", [("2026-10-05T11:00:00Z", True), ("2026-10-05T10:59:59Z", False)]
)
def test_current_age_is_bound_to_exact_header_timestamp(timestamp, accepted):
    calls = []
    kwargs = dict(
        profile=profile(),
        observed_at=NOW,
        transport=current_transport(
            calls,
            location="/epss_scores-2026-10-05.csv.gz",
            body=csv_body(metadata=f"#model_version:v5,score_date:{timestamp}"),
        ),
    )
    if accepted:
        assert fetch_epss_current([A], **kwargs).score_timestamp == datetime(
            2026, 10, 5, 11, tzinfo=UTC
        )
    else:
        with pytest.raises(CveEnrichmentError, match="stale_epss_feed"):
            fetch_epss_current([A], **kwargs)
    assert len(calls) == 2


def test_current_rights_reject_before_redirect_and_shared_deadline_blocks_dated_fetch():
    calls = []
    with pytest.raises(CveEnrichmentError, match="source_rights_rejected"):
        fetch_epss_current(
            [A],
            profile=profile(kill_switch=False),
            observed_at=NOW,
            transport=current_transport(calls),
        )
    assert calls == []
    ticks = iter([0, 1, 2, 61])
    with pytest.raises(CveEnrichmentError, match="operation_time_limit"):
        fetch_epss_current(
            [A],
            profile=profile(),
            observed_at=NOW,
            transport=current_transport(calls),
            clock=lambda: next(ticks),
        )
    assert len(calls) == 1


@pytest.mark.parametrize("day,accepted", [("2026-10-06", True), ("2026-10-05", False)])
def test_current_date_only_metadata_uses_utc_midnight_for_age(day, accepted):
    calls = []
    kwargs = dict(
        profile=profile(),
        observed_at=NOW,
        transport=current_transport(
            calls,
            location=f"/epss_scores-{day}.csv.gz",
            body=csv_body(metadata=f"#model_version:v5,score_date:{day}"),
        ),
    )
    if accepted:
        assert fetch_epss_current([A], **kwargs).score_timestamp is None
    else:
        with pytest.raises(CveEnrichmentError, match="stale_epss_feed"):
            fetch_epss_current([A], **kwargs)
    assert len(calls) == 2


@pytest.mark.parametrize(
    "headers",
    [
        {},
        [
            ("Location", "/epss_scores-2026-10-06.csv.gz"),
            ("Location", "/epss_scores-2026-10-05.csv.gz"),
        ],
    ],
)
def test_current_missing_or_duplicate_location_rejects_without_followup(headers):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers=headers, stream=httpx.ByteStream(b""))

    with pytest.raises(CveEnrichmentError, match="current_redirect_rejected"):
        fetch_epss_current(
            [A], profile=profile(), observed_at=NOW, transport=httpx.MockTransport(handler)
        )
    assert len(calls) == 1


def test_current_redirect_transport_failure_is_sanitized_and_not_retried():
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("SECRET PROVIDER MESSAGE", request=request)

    with pytest.raises(CveEnrichmentError) as caught:
        fetch_epss_current(
            [A], profile=profile(), observed_at=NOW, transport=httpx.MockTransport(handler)
        )
    assert str(caught.value) == "transport_unavailable" and len(calls) == 1
