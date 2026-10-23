"""Complete feed safety, old corrections and a burst beyond the legacy ceiling."""

from datetime import timedelta
from pathlib import Path

import pytest

from smithguard.bulletin_intake_parser import parse_complete
from smithguard.official_notice_parser import NoticeError
from tests.test_official_notice_parser import NOW, URL, entry, feed


def test_complete_input_keeps_old_unseen_security_notices():
    notices = parse_complete("php", feed(entry(date="2026-09-01T00:00:00Z")), now=NOW)
    assert len(notices) == 1
    assert notices[0].published.month == 9


def test_checkpoint_excludes_only_unknown_old_input_keeps_known_corrections():
    old = entry(date="2026-09-01T00:00:00Z")
    diagnostics = {}
    assert (
        parse_complete(
            "php",
            feed(old),
            now=NOW,
            earliest_unseen=NOW - timedelta(days=2),
            diagnostics=diagnostics,
        )
        == ()
    )
    assert diagnostics["feed_entries"] == 1
    assert diagnostics["excluded_before_checkpoint"] == 1
    notices = parse_complete(
        "php", feed(old), now=NOW, earliest_unseen=NOW - timedelta(days=2), known_urls={URL}
    )
    assert len(notices) == 1


def test_checkpoint_does_not_hide_trailing_malformed_xml():
    old = feed(entry(date="2026-09-01T00:00:00Z")).replace(b"</feed>", b"<broken>")
    with pytest.raises(NoticeError, match="parse_failed"):
        parse_complete("php", old, now=NOW, earliest_unseen=NOW - timedelta(days=2))


def test_streaming_burst_past_legacy_limit_and_old_correction_at_end():
    values = []
    for i in range(1500):
        day = 1 + i // 999
        number = 1 + i % 999
        url = f"https://www.php.net/archive/2026.php#2026-10-{day:02d}-{number}"
        values.append(entry(url=url, date=f"2026-10-{day:02d}T00:00:00Z"))
    values.append(entry(url=URL, date="2026-09-01T00:00:00Z", content="Corrected security notice."))
    diagnostics = {}
    notices = parse_complete(
        "php", feed("".join(values)), now=NOW, known_urls={URL}, diagnostics=diagnostics
    )
    assert len(notices) == 1501
    assert notices[-1].context == "Corrected security notice."
    assert diagnostics["feed_entries"] == 1501
    assert diagnostics["oldest_published_at"] == "2026-09-01T00:00:00Z"


def test_security_text_beyond_preview_excerpt_is_not_lost():
    notices = parse_complete(
        "php",
        feed(entry(title="Release announcement", content="word " * 300 + "security update")),
        now=NOW,
    )
    assert len(notices) == 1 and len(notices[0].context) == 1200


def test_nonsecurity_and_duplicate_entries_preserve_selection_rules():
    counts = {}
    notices = parse_complete(
        "php",
        feed(entry() + entry() + entry(title="Conference", content="Tickets")),
        now=NOW,
        diagnostics=counts,
    )
    assert len(notices) == 1
    assert counts["identical_duplicates"] == 1
    assert counts["excluded_non_security_entries"] == 1


@pytest.mark.parametrize(
    "body",
    [
        feed(entry() + entry(title="Different security claim")),
        feed(entry()).replace(b"</feed>", b"<broken>"),
        feed("<x>" * 33 + "</x>" * 33),
        b"<!DOCTYPE rss><rss/>",
        b"\xff",
        b"x" * (2 * 1024 * 1024 + 1),
        feed(entry(url="https://127.0.0.1/private")),
    ],
)
def test_complete_parse_failure_never_returns_partial_input(body):
    with pytest.raises(NoticeError):
        parse_complete("php", body, now=NOW)


def test_mozilla_fixture_and_shape():
    body = (Path(__file__).parent / "fixtures/social-security/mozilla-feed.xml").read_bytes()
    assert parse_complete("mozilla", body, now=NOW)
    with pytest.raises(NoticeError):
        parse_complete("mozilla", body.replace(b"</rss>", b"<channel/></rss>"), now=NOW)
