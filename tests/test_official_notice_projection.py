"""Official source confidence never grants applicability or social publication."""

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.db.models import EmergingLeadRecord, JobRecord
from smithguard.discovery import canonical_public_url, citation_key
from smithguard.emerging_leads import (
    enrichment_targets,
    expire_leads,
    latest_lead,
    public_page,
    record_lead,
    retained_lead_for,
    yield_summary,
)
from smithguard.lead_protocol import POLICY_ID, PUBLICATION_ENV
from smithguard.official_notice_coordinator import run
from smithguard.official_notice_fetch import FetchResult
from smithguard.official_notice_parser import parse_feed
from smithguard.official_notice_store import (
    QUEUE,
    candidate,
    notice_changes,
    notice_document,
    semantic_hash,
)
from tests.test_official_notice_parser import entry, feed
from tests.test_official_notice_store import NOW, URL, N


def test_official_and_social_same_words_keep_distinct_identities(database, monkeypatch):
    monkeypatch.setenv(PUBLICATION_ENV, POLICY_ID)
    official = candidate(notice_document(N), NOW)
    social = deepcopy(official)
    social.pop("provenance_kind")
    social["lead_id"] = "f" * 64
    with Session(database.engine) as session, session.begin():
        one, created = record_lead(
            session,
            official,
            state="unverified",
            reason="test_notice",
            now=NOW,
            publish=True,
            publication_run_id="test",
        )
        assert created and not one.public_eligible
        two, created = record_lead(
            session,
            social,
            state="unverified",
            reason="test_social",
            now=NOW,
            publish=True,
            publication_run_id="test",
        )
        assert created and two.lead_id != one.lead_id and two.fingerprint != one.fingerprint
        assert retained_lead_for(session, social).lead_id == two.lead_id
        assert retained_lead_for(session, official) is None
        assert len(enrichment_targets(session, now=NOW)) == 1
        assert [row["id"] for row in public_page(session, now=NOW)["leads"]] == [two.lead_id]
        assert yield_summary(session, since=NOW) == {"unverified": 1}
        changed = deepcopy(social)
        changed["lead_id"] = official["lead_id"]
        with pytest.raises(ValueError, match="lead_provenance_change_refused"):
            record_lead(session, changed, state="unverified", reason="test_cross_kind", now=NOW)


def test_social_words_cannot_equal_the_official_fingerprint_domain(database):
    official = candidate(notice_document(N), NOW)
    social = deepcopy(official)
    social.pop("provenance_kind")
    social.update(
        lead_id="f" * 64,
        subject="official_announcement",
        allegation=official["sources"][0]["url"],
    )
    with Session(database.engine) as session, session.begin():
        one, _ = record_lead(session, social, state="needs_enrichment", reason="test", now=NOW)
        two, created = record_lead(
            session, official, state="needs_enrichment", reason="test", now=NOW
        )
        assert created and one.fingerprint != two.fingerprint and one.lead_id != two.lead_id


def test_official_corrections_keep_expiry_and_receipts_after_terminal_state(database):
    def execute(at, body):
        return run(
            database.engine,
            enabled=lambda: True,
            now=at,
            observe_clock=lambda: at + timedelta(seconds=1),
            fetch=lambda source, **kw: (
                FetchResult(200, body, None, None, "a" * 64)
                if source == "php"
                else FetchResult(304, b"", None, None, None)
            ),
        )

    assert execute(NOW, feed())["status"] == "complete"
    with Session(database.engine) as session, session.begin():
        original = session.scalar(select(EmergingLeadRecord))
        lead_id, expiry, digest = original.lead_id, original.expires_at, original.record_hash
        assert original.state == "needs_enrichment" and not original.public_eligible
        assert enrichment_targets(session, now=NOW) == []
    assert (
        execute(NOW + timedelta(hours=1), feed(entry(content="Security correction.")))["status"]
        == "complete"
    )
    with Session(database.engine) as session, session.begin():
        corrected = latest_lead(session, lead_id)
        assert corrected.revision == 2 and corrected.expires_at == expiry
        assert expire_leads(session, now=expiry) == 1
    assert (
        execute(
            NOW + timedelta(hours=25), feed(entry(content="Security correction after expiry."))
        )["status"]
        == "complete"
    )
    with Session(database.engine) as session:
        final = latest_lead(session, lead_id)
        assert final.state == "expired" and final.revision == 3 and final.expires_at == expiry
        assert (
            session.scalar(
                select(EmergingLeadRecord).where(EmergingLeadRecord.revision == 1)
            ).record_hash
            == digest
        )
        notices = list(
            session.scalars(
                select(JobRecord)
                .where(JobRecord.queue == QUEUE, JobRecord.payload["kind"].as_string() == "notice")
                .order_by(JobRecord.created_at)
            )
        )
        assert len(notices) == 3 and notices[-1].payload["lead_projection"]["created"] is False
        assert notices[-1].payload["lead_projection"]["state"] == "expired"
        assert final.document["artifact_applicability"] == "unknown"


def test_explicit_tombstone_only_feed_preserves_source_publication():
    before = notice_document(N)
    known = {URL: {**before, "semantic_sha256": semantic_hash(before)}}
    marker = (
        '<at:deleted-entry xmlns:at="http://purl.org/atompub/tombstones/1.0" '
        f'ref="{URL}" when="2026-10-21T05:00:00Z"/>'
    )
    parsed = parse_feed("php", feed(marker), now=NOW, known_urls={URL})
    change = notice_changes(parsed, known, 4)["changes"][0]
    assert change["change"] == "withdrawn"
    assert change["document"]["published_at"] == before["published_at"]
    assert change["document"]["modified_at"] != before["modified_at"]
    with pytest.raises(ValueError, match="official_source_revision_regressed"):
        notice_changes([replace(N, modified=N.modified - timedelta(seconds=1))], known, 4)


def test_correction_beyond_excerpt_still_changes_semantic_identity():
    first = parse_feed("php", feed(entry(content="Security " + "x" * 1500 + " original")), now=NOW)[
        0
    ]
    second = parse_feed(
        "php", feed(entry(content="Security " + "x" * 1500 + " corrected")), now=NOW
    )[0]
    assert first.context == second.context
    assert first.content_sha256 != second.content_sha256
    before = notice_document(first)
    change = notice_changes(
        [second], {URL: {**before, "semantic_sha256": semantic_hash(before)}}, 4
    )
    assert len(change["changes"]) == 1


def test_php_archive_anchor_is_part_of_source_identity():
    other = URL[:-1] + "2"
    assert canonical_public_url(URL) == URL
    assert citation_key(URL) != citation_key(other)
    assert citation_key(URL) == citation_key(URL.replace("www.php.net", "php.net"))
    assert citation_key("https://example.com/story#top") == citation_key(
        "https://example.com/story"
    )
    assert canonical_public_url(URL.replace("10-20", "99-20")).endswith(".php")
