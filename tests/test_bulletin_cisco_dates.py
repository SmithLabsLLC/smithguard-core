"""Cisco feed dates are discovery hints; original/update dates come from details."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from smithguard import bulletin_automation as automation
from smithguard.bulletin_comparison import factual_hash
from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_facts import envelope, project_facts
from smithguard.bulletin_source_parser import (
    CISCO_DATE_BASIS,
    SourceCandidate,
    parse_index,
    publisher_detail,
)
from smithguard.db.bulletin_models import OfficialNoticeCurrent, OfficialNoticeEvidence
from smithguard.identifiers import canonical_json_bytes, sha256_id
from smithguard.official_notice_fetch import FetchResult
from smithguard.source_rights import RightsRegistry

NOW = datetime(2026, 10, 23, 18, tzinfo=UTC)
SOURCE = "cisco-advisories"
URL = (
    "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
    "cisco-sa-synthetic"
)
REGISTRY = RightsRegistry.from_path(
    Path(__file__).resolve().parents[1] / "contracts/v1/source-rights-register.json"
)


def feed(url=URL, date="2026-10-23 16:16:37.0"):
    return (
        f"<rss><channel><item><title>Synthetic advisory</title><link>{url}</link>"
        f"<guid>{url}</guid><pubDate>{date}</pubDate>"
        "<description>CVE-2026-12345</description></item></channel></rss>"
    ).encode()


def field(identity, label, value):
    return (
        f'<div id="{identity}"><div class="ud-divHeaderLabelSpacing">{label}</div>'
        f'<div class="divLabelContent">{value}</div></div>'
    )


def detail(url=URL, published="2026 October 21 19:12 GMT", updated="2026 October 23 16:16 GMT"):
    return (
        f'<link rel="canonical" href="{url}"><div id="advisorycontentcontainer">'
        + field("ud-published", "First Published:", published)
        + field("ud-last-updated", "Last Updated:", updated)
        + "<p>CVE-2026-12345</p></div>"
    ).encode()


def candidate():
    return parse_index(SOURCE, feed(), now=NOW)[0]


def public(value):
    return project_facts(envelope(value, now=NOW, retrospective=True), REGISTRY, now=NOW)


def test_detail_dates_replace_feed_hint_and_are_stable_on_recheck():
    hint = candidate()
    accepted = publisher_detail(hint, detail(), now=NOW)
    assert hint.published == datetime(2026, 10, 23, tzinfo=UTC)
    assert accepted.published == datetime(2026, 10, 21, 19, 12, tzinfo=UTC)
    assert accepted.modified == datetime(2026, 10, 23, 16, 16, tzinfo=UTC)
    assert accepted.facts["time_precision"] == "exact"
    assert accepted.facts["date_basis"] == CISCO_DATE_BASIS
    assert accepted.facts["index_hash"] == hint.facts["body_hash"]
    assert publisher_detail(accepted, detail(), now=NOW).document() == accepted.document()
    assert not automation.date_requalification(
        SimpleNamespace(source_key=SOURCE, document={"document": accepted.document()})
    )


@pytest.mark.parametrize("part", [b"First Published:", b"2026 October 21"])
def test_cisco_lone_windows_nbsp_in_date_or_label_is_normalized(part):
    body = detail().replace(part, part.replace(b" ", b"\xa0"))
    assert b"\xa0" in body
    accepted = publisher_detail(candidate(), body, now=NOW)
    assert accepted.document() == publisher_detail(candidate(), detail(), now=NOW).document()


@pytest.mark.parametrize("part", [b"First Published:", b"2026 October 21"])
def test_other_invalid_windows_bytes_in_date_or_label_fail_encoding(part):
    body = detail().replace(part, part.replace(b" ", b"\x96"))
    with pytest.raises(BulletinError, match="^bulletin_source_encoding$"):
        publisher_detail(candidate(), body, now=NOW)


def test_feed_date_only_change_requests_detail_without_changing_original_date():
    first = parse_index(SOURCE, feed(date="2026-10-22 14:00:00.0"), now=NOW)[0]
    second = candidate()
    assert first.facts["body_hash"] != second.facts["body_hash"]
    old = publisher_detail(first, detail(), now=NOW)
    new = publisher_detail(second, detail(), now=NOW)
    assert old.published == new.published
    assert factual_hash(public(old)) == factual_hash(public(new))


def test_update_date_only_is_metadata_but_original_publication_repair_is_factual():
    accepted = publisher_detail(candidate(), detail(updated="2026 October 22 16:16 GMT"), now=NOW)
    before = public(accepted)
    retained = deepcopy(before)
    updated = publisher_detail(accepted, detail(), now=NOW)
    after = public(updated)
    assert before["source_modified_at"] != after["source_modified_at"]
    assert factual_hash(before) == factual_hash(after)  # Publication emits source_updated.
    legacy = SourceCandidate(SOURCE, URL, candidate().published, None, candidate().facts)
    assert factual_hash(public(legacy)) != factual_hash(after)  # Emits corrected.
    assert before == retained


@pytest.mark.parametrize(
    "published, updated",
    [
        ("2026 October 32 19:12 GMT", "2026 October 23 16:16 GMT"),
        ("2026 October 21 25:12 GMT", "2026 October 23 16:16 GMT"),
        ("2026 October 21 19:12", "2026 October 23 16:16 GMT"),
        ("2026 October 21 19:12 GMT", "2026 October 23 16:16 UTC"),
        ("2026 October 21 19:12 GMT", "2026 October 23 16:16:37 GMT"),
        ("2026 October 21 19:12 GMT", "2026 October 21 19:11 GMT"),
        ("2026 October 24 19:12 GMT", "2026 October 24 19:12 GMT"),
        ("2026 October 21 19:12 GMT", "2026 October 23 18:01 GMT"),
    ],
)
def test_invalid_inverted_or_future_detail_dates_fail_closed(published, updated):
    with pytest.raises(BulletinError):
        publisher_detail(candidate(), detail(published=published, updated=updated), now=NOW)


@pytest.mark.parametrize("identity", ["ud-published", "ud-last-updated"])
@pytest.mark.parametrize(
    "mutation", ["missing", "duplicate", "outside", "wrong_label", "extra_value"]
)
def test_missing_duplicate_or_wrongly_scoped_metadata_fail_closed(identity, mutation):
    body = detail().decode()
    published = identity == "ud-published"
    label = "First Published:" if published else "Last Updated:"
    value = "2026 October 21 19:12 GMT" if published else "2026 October 23 16:16 GMT"
    metadata = field(identity, label, value)
    if mutation == "missing":
        body = body.replace(metadata, "" if published else field(identity, label, ""))
    elif mutation == "duplicate":
        body += metadata
    elif mutation == "outside":
        body = body.replace(metadata, "") + metadata
    elif mutation == "wrong_label":
        body = body.replace(label, "Another Date:")
    else:
        body = body.replace(
            metadata, metadata[:-6] + '<div class="divLabelContent">extra</div></div>'
        )
    with pytest.raises(BulletinError, match="cisco_detail_dates"):
        publisher_detail(candidate(), body.encode(), now=NOW)


def test_initial_advisory_with_no_update_container_or_label_keeps_update_unknown():
    body = detail().replace(
        field("ud-last-updated", "Last Updated:", "2026 October 23 16:16 GMT").encode(), b""
    )
    accepted = publisher_detail(candidate(), body, now=NOW)
    assert accepted.published == datetime(2026, 10, 21, 19, 12, tzinfo=UTC)
    assert accepted.modified is None
    assert public(accepted)["source_modified_at"] is None
    assert publisher_detail(accepted, body, now=NOW).document() == accepted.document()
    assert not automation.date_requalification(
        SimpleNamespace(source_key=SOURCE, document={"document": accepted.document()})
    )


@pytest.mark.parametrize(
    "stray",
    [
        '<div class="ud-divHeaderLabelSpacing">Last Updated:</div>',
        '<div id="changed-update-id">Last Updated: 2026 October 23 16:16 GMT</div>',
        "<p>last updated</p>",
        "<p>Last <span>Updated:</span></p>",
    ],
)
def test_missing_update_container_with_stray_update_label_fails_closed(stray):
    body = detail().replace(
        field("ud-last-updated", "Last Updated:", "2026 October 23 16:16 GMT").encode(), b""
    )
    with pytest.raises(BulletinError, match="cisco_detail_dates"):
        publisher_detail(candidate(), body + stray.encode(), now=NOW)


@pytest.mark.parametrize("date", ["2026-10-23 99:16:37.0", "2026-02-30 16:16:37.0"])
def test_invalid_feed_hint_fails_closed(date):
    with pytest.raises(BulletinError, match="cisco_feed_date"):
        parse_index(SOURCE, feed(date=date), now=NOW)


def test_legacy_date_repair_is_source_specific_and_does_not_mutate_evidence():
    doc = candidate().document()
    old = deepcopy(doc)
    row = SimpleNamespace(source_key=SOURCE, document={"document": doc})
    assert automation.date_requalification(row)
    row.source_key = "ubuntu-usn"
    assert not automation.date_requalification(row)
    assert doc == old


@pytest.mark.parametrize("index_unavailable", [False, True])
def test_existing_legacy_dates_requalify_in_bounded_batches_including_off_feed(
    database, index_unavailable
):
    """Legacy records requalify without changing admission or immutable history."""
    from smithguard.bulletin_intake_store import retain

    old_documents = {}
    first_seen = NOW - timedelta(days=1)
    with Session(database.engine) as session, session.begin():
        for number in range(9):
            url = URL + str(number)
            hint = parse_index(SOURCE, feed(url, date="2026-10-22 16:16:37.0"), now=NOW)[0]
            facts = {**hint.facts, "index_hash": hint.facts["body_hash"]}
            legacy = SourceCandidate(SOURCE, url, hint.published, None, facts)
            value = envelope(legacy, now=first_seen, retrospective=True)
            old_documents[retain(session, value, now=first_seen)] = deepcopy(value)
            session.add(
                OfficialNoticeCurrent(
                    source_key=SOURCE,
                    record_key=legacy.record_key,
                    document=value,
                    semantic_hash=value["semantic_hash"],
                    first_seen_at=first_seen if number < 8 else NOW - timedelta(days=100),
                    updated_at=NOW - timedelta(minutes=5),
                )
            )
    calls = []

    def fetch(source, *, url=None):
        if url:
            calls.append(url)
        elif index_unavailable:
            raise BulletinError("bulletin_source_http")
        body = detail(url, published="2026 September 1 19:12 GMT") if url else feed(URL + "0")
        return FetchResult(200, body, None, None, sha256_id(body))

    for offset, expected in [(0, 6), (1, 2), (2, 0)]:
        calls.clear()
        with database.engine.connect() as connection:
            result = automation.run_source(
                connection,
                SOURCE,
                now=NOW + timedelta(hours=offset),
                epoch=f"20261023T{18 + offset}",
                registry=REGISTRY,
                process=lambda *args, **kwargs: True,
                enabled=lambda: True,
                fetch=fetch,
            )
        assert len(calls) == expected
        assert result["accepted"]["corrected"] == expected
    with Session(database.engine) as session:
        rows = session.scalars(select(OfficialNoticeCurrent)).all()
        assert len(rows) == 9
        for row in rows:
            if row.first_seen_at == first_seen:
                assert row.document["document"]["published_at"] == "2026-09-01T19:12:00Z"
                assert not automation.date_requalification(row)
            else:
                assert automation.date_requalification(row)
        for identity, document in old_documents.items():
            retained = session.get(OfficialNoticeEvidence, identity)
            assert retained.document == document
            assert sha256_id(canonical_json_bytes(retained.document)) == identity


@pytest.fixture(params=["UTC", "America/New_York"])
def expiry_database(database, request):
    statements = {
        "UTC": "SET LOCAL TIME ZONE 'UTC'",
        "America/New_York": "SET LOCAL TIME ZONE 'America/New_York'",
    }

    def set_timezone(connection):
        connection.exec_driver_sql(statements[request.param])

    event.listen(database.engine, "begin", set_timezone)
    try:
        with database.engine.connect() as connection:
            assert connection.exec_driver_sql("SHOW TIME ZONE").scalar_one() == request.param
        yield database
    finally:
        event.remove(database.engine, "begin", set_timezone)


def test_published_legacy_date_repair_marks_budget_tail_stale_without_duplicate_decisions(
    expiry_database,
):
    database = expiry_database
    from smithguard import bulletin_store
    from smithguard.bulletin_contract import bulletin_id
    from smithguard.bulletin_intake_store import retain
    from smithguard.bulletin_publisher import processor
    from smithguard.db.bulletin_models import (
        BulletinCurrent,
        BulletinDecision,
        BulletinRevision,
        OfficialNoticePending,
    )

    from .test_bulletins import GRANT

    first_seen = NOW - timedelta(minutes=5)
    grant = {**GRANT, "mode": "automatic", "source_keys": [SOURCE]}
    originals = {}
    with Session(database.engine) as session, session.begin():
        for number in range(8):
            url = URL + str(number)
            hint = parse_index(SOURCE, feed(url, date="2026-10-22 16:16:37.0"), now=NOW)[0]
            facts = {**hint.facts, "index_hash": hint.facts["body_hash"]}
            legacy = SourceCandidate(SOURCE, url, hint.published, None, facts)
            value = envelope(legacy, now=first_seen, retrospective=True)
            retain(session, value, now=first_seen)
            session.add(
                OfficialNoticeCurrent(
                    source_key=SOURCE,
                    record_key=legacy.record_key,
                    document=value,
                    semantic_hash=value["semantic_hash"],
                    first_seen_at=first_seen,
                    updated_at=first_seen,
                )
            )
            session.flush()
            bulletin_store.publish(
                session,
                project_facts(value, REGISTRY, now=first_seen),
                grant=grant,
                registry=REGISTRY,
                now=first_seen,
            )
            identity = bulletin_id(SOURCE, url)
            current = session.get(BulletinCurrent, identity)
            revision = session.get(BulletinRevision, (identity, 1))
            assert current.verification_due_at > NOW
            originals[identity] = {
                "document": deepcopy(revision.document),
                "hash": revision.content_hash,
                "first_seen": current.first_seen_at,
                "expires": current.expires_at,
            }
    calls = []

    def fetch(source, *, url=None):
        if url:
            calls.append(url)
        body = detail(url, published="2026 September 1 19:12 GMT") if url else feed(URL + "0")
        return FetchResult(200, body, None, None, sha256_id(body))

    process = processor(registry=REGISTRY, grant_reader=lambda **kwargs: grant)
    with database.engine.connect() as connection:
        result = automation.run_source(
            connection,
            SOURCE,
            now=NOW,
            epoch="20261023T18-published-date-repair",
            registry=REGISTRY,
            process=process,
            enabled=lambda: True,
            fetch=fetch,
        )
    assert len(calls) == automation.DETAIL_LIMIT == 6
    assert result["accepted"]["corrected"] == 6
    with Session(database.engine) as session:
        pending = session.scalars(
            select(OfficialNoticePending).where(OfficialNoticePending.processed_at.is_(None))
        ).all()
        assert len(pending) == 2
        remaining = []
        for item in pending:
            identity = bulletin_id(SOURCE, item.record_url)
            row = session.get(BulletinCurrent, identity)
            assert row.revision == 1
            assert row.freshness_reason == "verification_pending"
            view = bulletin_store.detail(session, identity, now=NOW)
            assert view["freshness"] == "stale"
            assert view["freshness_reason"] == "verification_pending"
            current = session.get(OfficialNoticeCurrent, (SOURCE, item.record_key))
            doc = current.document["document"]
            remaining.append(
                SourceCandidate(
                    SOURCE,
                    item.record_url,
                    datetime.fromisoformat(doc["published_at"].replace("Z", "+00:00")),
                    None,
                    doc["facts"],
                    True,
                )
            )
        decision_ids = set(session.scalars(select(BulletinDecision.decision_id)))
        stale_ids = set(
            session.scalars(
                select(BulletinDecision.decision_id).where(
                    BulletinDecision.document["kind"].as_string() == "freshness_stale"
                )
            )
        )
        assert len(stale_ids) == 8
    for minute in [1, 2]:
        with Session(database.engine) as session, session.begin():
            automation.stage(
                session,
                SOURCE,
                remaining,
                now=NOW + timedelta(minutes=minute),
                baseline=NOW - timedelta(days=14),
            )
            assert set(session.scalars(select(BulletinDecision.decision_id))) == decision_ids
            for item in remaining:
                row = session.get(BulletinCurrent, bulletin_id(SOURCE, item.url))
                assert row.freshness_reason == "verification_pending"
    calls.clear()
    with database.engine.connect() as connection:
        repaired = automation.run_source(
            connection,
            SOURCE,
            now=NOW + timedelta(hours=1),
            epoch="20261023T19-published-date-repair",
            registry=REGISTRY,
            process=process,
            enabled=lambda: True,
            fetch=fetch,
        )
    assert len(calls) == 2
    assert repaired["accepted"]["corrected"] == 2
    with Session(database.engine) as session:
        for identity, original in originals.items():
            current = session.get(BulletinCurrent, identity)
            old = session.get(BulletinRevision, (identity, 1))
            new = session.get(BulletinRevision, (identity, 2))
            assert current.revision == 2
            assert current.first_seen_at == original["first_seen"] == first_seen
            assert current.expires_at == original["expires"] == first_seen + timedelta(days=90)
            assert current.freshness_reason is None
            assert old.document == original["document"]
            assert old.content_hash == original["hash"]
            assert new.predecessor_hash == original["hash"]
            assert new.document["source_published_at"] == "2026-09-01T19:12:00Z"
        assert all(
            row.first_seen_at == first_seen
            for row in session.scalars(select(OfficialNoticeCurrent))
        )
        assert (
            set(
                session.scalars(
                    select(BulletinDecision.decision_id).where(
                        BulletinDecision.document["kind"].as_string() == "freshness_stale"
                    )
                )
            )
            == stale_ids
        )


def test_emerging_correction_keeps_absolute_24_hour_expiry_across_dst(expiry_database):
    from smithguard import bulletin_store
    from smithguard.db.bulletin_models import BulletinCurrent, BulletinRevision

    from .test_bulletins import GRANT, content

    database = expiry_database
    first_seen = datetime(2026, 10, 31, 18, tzinfo=UTC)
    corrected_at = datetime(2026, 11, 1, 8, tzinfo=UTC)
    expected_expiry = first_seen + timedelta(hours=24)
    grant = {**GRANT, "review_due_at": "2026-11-02T00:00:00Z"}
    document = content()
    document["evidence_class"] = "emerging_report"
    with Session(database.engine) as session, session.begin():
        published = bulletin_store.publish(
            session,
            document,
            grant=grant,
            registry=REGISTRY,
            now=first_seen,
            manual_approval="1" * 64,
        )
        identity = published["bulletin_id"]
        initial = session.get(BulletinRevision, (identity, 1))
        original_document = deepcopy(initial.document)
        original_hash = initial.content_hash
        assert session.get(BulletinCurrent, identity).expires_at == expected_expiry
    changed = {
        **document,
        "summary": "Corrected synthetic evidence without extending its lifetime.",
    }
    with Session(database.engine) as session, session.begin():
        bulletin_store.publish(
            session,
            changed,
            grant=grant,
            registry=REGISTRY,
            now=corrected_at,
            manual_approval="2" * 64,
        )
        current = session.get(BulletinCurrent, identity)
        old = session.get(BulletinRevision, (identity, 1))
        assert current.first_seen_at == first_seen
        assert current.expires_at == expected_expiry
        assert old.document == original_document
        assert old.content_hash == original_hash
        assert session.get(BulletinRevision, (identity, 2)).predecessor_hash == original_hash
        expired = bulletin_store.detail(
            session, identity, now=expected_expiry + timedelta(seconds=1)
        )
        assert expired["effective_lifecycle"] == "expired"
