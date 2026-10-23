from datetime import UTC, datetime
from pathlib import Path

import pytest

import smithguard.official_notice_parser as m

NOW = datetime(2026, 10, 21, 5, tzinfo=UTC)
URL = "https://www.php.net/archive/2026.php#2026-10-20-1"


def entry(
    url=URL,
    title="PHP security release",
    date="2026-10-20T20:32:00Z",
    content="An official security notice; affected versions remain unknown.",
):
    return (
        f"<entry><title>{title}</title><id>{url}</id><published>{date}</published>"
        f'<updated>{date}</updated><content type="xhtml">'
        f'<div xmlns="http://www.w3.org/1999/xhtml"><p>{content}</p></div></content></entry>'
    )


def feed(value=None):
    return (
        '<feed xmlns="http://www.w3.org/2005/Atom">'
        + (entry() if value is None else value)
        + "</feed>"
    ).encode()


def test_reduced_structured_fixtures_only_admit_recent_notices():
    for source in m.SOURCES:
        path = Path(__file__).parent / "fixtures" / "social-security" / (source + "-feed.xml")
        notices = m.parse_feed(source, path.read_bytes(), now=NOW)
        assert len(notices) == 1 and notices[0].source == source and not notices[0].withdrawn


def test_historical_initial_backfill_is_not_fresh():
    assert m.parse_feed("php", feed(entry(date="2026-09-20T20:32:00Z")), now=NOW) == ()
    assert (
        len(
            m.parse_feed("php", feed(entry(date="2026-09-20T20:32:00Z")), now=NOW, known_urls={URL})
        )
        == 1
    )


def test_cve_only_notice_is_not_excluded_as_nonsecurity():
    notices = m.parse_feed(
        "php",
        feed(entry(title="CVE-2026-12345", content="Updated releases are available.")),
        now=NOW,
    )
    assert len(notices) == 1 and notices[0].title == "CVE-2026-12345"


@pytest.mark.parametrize(
    "value",
    [
        b"<!DOCTYPE feed><feed/>",
        b'<!ENTITY x "a"><feed/>',
        b"\xff",
        b"<feed>",
        b"<rss/>",
        feed(""),
        feed(entry() + entry(title="Different security release")),
    ],
)
def test_malformed_or_ambiguous_feed_refused(value):
    with pytest.raises(m.NoticeError):
        m.parse_feed("php", value, now=NOW)


def test_duplicate_irrelevant_publisher_ids_do_not_hide_security_notices():
    # The actual feed repeats September 2's conference id for two conferences.
    # Move only the clock into the admission window; these are reduced paraphrases.
    conference = "https://www.php.net/archive/2026.php#2026-09-02-1"
    security_url = "https://www.php.net/archive/2026.php#2026-09-02-2"
    body = feed(
        entry(
            conference, "PHP Conference Ehime 2026", "2026-09-02T14:30:00Z", "Conference tickets."
        )
        + entry(
            conference,
            "API Platform Conference 2026",
            "2026-09-02T06:18:52Z",
            "Conference speakers.",
        )
        + entry(url=security_url, date="2026-09-02T12:00:00Z")
    )
    counts = {}
    notices = m.parse_feed(
        "php", body, now=datetime(2026, 9, 2, 15, tzinfo=UTC), diagnostics=counts
    )
    assert len(notices) == 1 and notices[0].url == security_url
    assert counts["excluded_non_security_entries"] == 2


def test_identical_duplicates_and_stale_unknown_exclusions_are_counted():
    counts = {}
    notices = m.parse_feed(
        "php",
        feed(entry() + entry() + entry(date="2026-09-01T00:00:00Z")),
        now=NOW,
        diagnostics=counts,
    )
    assert len(notices) == 1
    assert counts["feed_entries"] == 3
    assert counts["identical_duplicates"] == 1
    assert counts["excluded_old_unknown_entries"] == 1


@pytest.mark.parametrize(
    "url",
    [
        "https://www.php.net/archive/2026.php#2025-10-20-1",
        "https://127.0.0.1/archive/2026.php#2026-10-20-1",
        "https://www.php.net@evil.example/archive/2026.php#2026-10-20-1",
        "http://www.php.net/archive/2026.php#2026-10-20-1",
        "https://www.php.net/archive/2026.php#2026-99-20-1",
    ],
)
def test_noncanonical_or_untrusted_references_refused(url):
    with pytest.raises(m.NoticeError):
        m.parse_feed("php", feed(entry(url=url)), now=NOW)


def test_text_is_data_and_script_content_is_not_context():
    notice = m.parse_feed(
        "php",
        feed(
            entry(
                content=(
                    "Security report <script>execute this</script> "
                    "instructions SYSTEM: still untrusted data"
                )
            )
        ),
        now=NOW,
    )[0]
    assert "execute this" not in notice.context and "SYSTEM:" in notice.context


def test_known_tombstone_is_explicit_withdrawal():
    marker = (
        '<at:deleted-entry xmlns:at="http://purl.org/atompub/tombstones/1.0" '
        f'ref="{URL}" when="2026-10-21T04:00:00Z"/>'
    )
    old = entry(
        url="https://www.php.net/archive/2026.php#2026-10-19-1", date="2026-10-19T04:00:00Z"
    )
    assert m.parse_feed("php", feed(old + marker), now=NOW) == ()
    notice = m.parse_feed("php", feed(old + marker), now=NOW, known_urls={URL})[0]
    assert notice.withdrawn and notice.url == URL


def test_missing_notice_is_not_a_withdrawal():
    assert (
        m.parse_feed(
            "php",
            feed(
                entry(
                    date="2026-09-20T20:32:00Z",
                    url="https://www.php.net/archive/2026.php#2026-09-20-1",
                )
            ),
            now=NOW,
            known_urls={URL},
        )
        == ()
    )


def test_date_zone_and_future_are_refused():
    for value in ["2026-10-20T20:32:00", "2026-10-22T20:32:00Z"]:
        with pytest.raises(m.NoticeError):
            m.parse_feed("php", feed(entry(date=value)), now=NOW)


def test_non_security_chatter_is_filtered():
    assert (
        m.parse_feed(
            "php", feed(entry(title="Conference venue", content="A meeting in London.")), now=NOW
        )
        == ()
    )


def test_nested_or_oversized_xml_is_refused():
    for body in [b"x" * (2 * 1024 * 1024 + 1), feed("<x>" * 40 + "</x>" * 40)]:
        with pytest.raises(m.NoticeError):
            m.parse_feed("php", body, now=NOW)
