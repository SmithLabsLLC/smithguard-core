"""Offline replay of recorded provider answer shapes through the v4 lead decoder."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from smithguard.discovery import citation_key, x_post_time
from smithguard.identifiers import timestamp
from smithguard.lead_protocol import PROMPT_VERSION, decode_leads

CASES = json.loads(
    (Path(__file__).parent / "fixtures/warning_lane/replay-cases.json").read_text("utf-8")
)
# Two days after the fixture post IDs' encoded creation time.
NOW = datetime(2025, 9, 25, tzinfo=UTC)


def _body(sources) -> str:
    return json.dumps(
        {
            "prompt_version": PROMPT_VERSION,
            "leads": [
                {
                    "subject": "orion-cli",
                    "allegation": "A researcher reports a malicious orion-cli release.",
                    "sources": sources,
                }
            ],
        }
    )


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_recorded_answer_shapes_bind_citations(case) -> None:
    leads, rejected = decode_leads(
        _body(case["sources"]), tuple(case["citations"]), NOW, allow_reserved_hosts=True
    )
    assert rejected == []
    (lead,) = leads
    source = lead["sources"][0]
    assert source["citation_bound"] is case["expect_citation_bound"]
    if case["expect_published_from_post_id"]:
        assert source["time_precision"] == "exact"
        assert source["published_at"] == timestamp(x_post_time(source["url"]))


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (
            "https://x.com/alice/status/1970000000000000000",
            "https://x.com/i/status/1970000000000000000",
        ),
        (
            "https://twitter.com/alice/status/1970000000000000000/photo/1",
            "https://x.com/i/web/status/1970000000000000000",
        ),
        ("https://www.example.org/a/b/?utm_source=x&id=2", "https://example.org/a/b?id=2"),
    ],
)
def test_citation_keys_match_equivalent_links(left, right) -> None:
    assert citation_key(left) == citation_key(right)


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("https://x.com/alice/status/1", "https://x.com/alice/status/2"),
        ("https://example.org/a?page=1", "https://example.org/a?page=2"),
        ("https://example.org/a?s=1", "https://example.org/a"),  # "s" is only X tracking
        ("https://example.org/report?id=A&id=B", "https://example.org/report?id=B&id=A"),
    ],
)
def test_citation_keys_keep_distinct_pages_apart(left, right) -> None:
    assert citation_key(left) != citation_key(right)


def test_x_post_ids_carry_their_creation_time() -> None:
    posted = x_post_time("https://x.com/alice/status/1970000000000000000")
    assert posted is not None and posted.year == 2025
    assert x_post_time("https://x.com/alice/status/20") is None  # pre-snowflake ID
    assert x_post_time("https://example.org/status/1970000000000000000") is None


def test_one_post_linked_two_ways_is_one_lead_identity() -> None:
    first, _ = decode_leads(
        _body(
            [
                {
                    "url": "https://x.com/alice/status/1970000000000000000",
                    "context": None,
                    "published_at": None,
                }
            ]
        ),
        (),
        NOW,
    )
    second, _ = decode_leads(
        _body(
            [
                {
                    "url": "https://twitter.com/i/status/1970000000000000000",
                    "context": None,
                    "published_at": None,
                }
            ]
        ),
        (),
        NOW,
    )
    assert first[0]["lead_id"] == second[0]["lead_id"]


def test_a_month_old_report_is_not_an_early_warning() -> None:
    old = (NOW - timedelta(days=45)).date().isoformat()
    leads, rejected = decode_leads(
        _body([{"url": "https://research.example/old", "context": None, "published_at": old}]),
        (),
        NOW,
        allow_reserved_hosts=True,
    )
    assert leads == []
    assert rejected[0]["reason"] == "lead_stale_report"
