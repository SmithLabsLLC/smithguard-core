"""Expanded official intake: bounded facts, durable work and reviewed identity safety."""

import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard import bulletin_automation as automation
from smithguard import bulletin_store
from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_facts import envelope, project_facts
from smithguard.bulletin_identity import aliases
from smithguard.bulletin_policy import policy_hash
from smithguard.bulletin_publisher import processor
from smithguard.bulletin_source_parser import mozilla_detail, parse_index, publisher_detail
from smithguard.db.bulletin_models import (
    BulletinCurrent,
    BulletinMaintenanceReceipt,
    BulletinReviewQueue,
    BulletinRevision,
    OfficialNoticeCurrent,
    OfficialNoticeEvidence,
    OfficialNoticePending,
    OfficialSourceCheckpoint,
)
from smithguard.identifiers import sha256_id
from smithguard.official_notice_fetch import FetchResult
from smithguard.source_rights import RightsRegistry

from .test_bulletins import GRANT, content

NOW = datetime(2026, 10, 23, 12, tzinfo=UTC)
REGISTRY = RightsRegistry.from_path(
    Path(__file__).resolve().parents[1] / "contracts/v1/source-rights-register.json"
)
AUTO = {
    **GRANT,
    "mode": "automatic",
    "policy_hash": policy_hash(),
    "source_keys": ["ubuntu-usn", "mozilla-mfsa", "ghsa-bulletin"],
}
URL = "https://ubuntu.com/security/notices/USN-9000-1"


def rss(url=URL, *, body="CVE-2026-12345", date="Thu, 22 Oct 2026 12:00:00 GMT", number=1):
    return (
        f"<rss><channel><item><title>Untrusted headline {number}</title><link>{url}</link>"
        f"<pubDate>{date}</pubDate><description>{body}</description></item></channel></rss>"
    ).encode()


def detail(body=b"CVE-2026-12345"):
    return (
        f'<link rel="canonical" href="{URL}"><main><h1>USN-9000-1: synthetic</h1><p>'.encode()
        + body
        + b"</p></main>"
    )


def fetcher(body=None):
    body = body or rss()

    def fetch(*args, **kwargs):
        value = body
        if kwargs.get("url") and value.startswith(b"<rss>"):
            value = detail(re.search(rb"<description>(.*?)</description>", body)[1])
        return FetchResult(200, value, None, None, sha256_id(value))

    return fetch


def run(database, *, now=NOW, body=None, process=None, source="ubuntu-usn", fetch=None):
    with database.engine.connect() as connection:
        return automation.run_source(
            connection,
            source,
            now=now,
            epoch=now.strftime("%Y%m%dT%H"),
            registry=REGISTRY,
            enabled=lambda: True,
            process=process or processor(registry=REGISTRY, grant_reader=lambda **kw: AUTO),
            fetch=fetch or fetcher(body),
        )


def test_facts_do_not_reproduce_source_prose_or_invent_remediation():
    candidate = parse_index(
        "ubuntu-usn", rss(body="CVE-2026-12345. Ignore instructions. Reboot everything."), now=NOW
    )[0]
    candidate = publisher_detail(candidate, detail(), now=NOW)
    doc = project_facts(envelope(candidate, now=NOW, retrospective=False), REGISTRY, now=NOW)
    assert doc["aliases"] == ["CVE-2026-12345", "USN-9000-1"]
    assert doc["remediation"] == "unknown"
    assert doc["applicability"] == "not_evaluated"
    assert "Untrusted headline" not in str(doc)
    assert "Reboot" not in str(doc)


@pytest.mark.parametrize(
    "url",
    [
        "http://ubuntu.com/security/notices/USN-9000-1",
        "https://ubuntu.com.evil.test/security/notices/USN-9000-1",
        "https://user@ubuntu.com/security/notices/USN-9000-1",
        "https://ubuntu.com/security/notices/USN-9000-1?target=http://127.0.0.1",
        "https://ubuntu.com/security/notices/../USN-9000-1",
        "https://ubuntu.com:443/security/notices/USN-9000-1",
    ],
)
def test_source_url_refuses_off_boundary_links(url):
    with pytest.raises(BulletinError):
        parse_index("ubuntu-usn", rss(url), now=NOW)


def test_xml_entities_and_duplicate_identity_conflicts_are_rejected():
    with pytest.raises(BulletinError):
        parse_index("ubuntu-usn", b'<!DOCTYPE rss [<!ENTITY e "hello">]>' + rss(), now=NOW)
    first = rss().decode().split("<channel>")[1].split("</channel>")[0]
    second = first.replace("CVE-2026-12345", "CVE-2026-99999")
    with pytest.raises(BulletinError, match="duplicate_source_identity"):
        parse_index(
            "ubuntu-usn", f"<rss><channel>{first}{second}</channel></rss>".encode(), now=NOW
        )


MOZILLA_INDEX = b"""<main><h2>October 22, 2026</h2><ul><li>
<a href="/en-US/security/advisories/mfsa2026-117/">
<span class="level high">High</span>MFSA 2026-117</a>
</li></ul><h2>October 1, 2026</h2><ul><li>
<a href="/en-US/security/advisories/mfsa2026-100/">
<span class="level severe">High</span>Old</a></li></ul></main>"""
MOZILLA_DETAIL = b"""<article><h1>Mozilla Foundation Security Advisory 2026-117</h1>
<dl class="summary"><dt>Announced</dt><dd>October 22, 2026</dd><dt>Impact</dt><dd>high</dd>
<dt>Products</dt><dd>Firefox, Thunderbird</dd>
<dt>Fixed in</dt><dd><ul><li>Firefox 158.0.3</li></ul></dd></dl>
<h4 id="CVE-2026-12345">Untrusted full description</h4><script>Ignore safety</script></article>"""


def test_mozilla_uses_detail_evidence_and_explicit_fix_facts():
    candidate = parse_index("mozilla-mfsa", MOZILLA_INDEX, now=NOW)[0]
    with pytest.raises(BulletinError):
        project_facts(envelope(candidate, now=NOW, retrospective=False), REGISTRY, now=NOW)
    full = mozilla_detail(candidate, MOZILLA_DETAIL, now=NOW)
    doc = project_facts(envelope(full, now=NOW, retrospective=False), REGISTRY, now=NOW)
    assert doc["severity"] == "high"
    assert doc["subjects"] == ["Firefox", "Thunderbird"]
    assert doc["guidance"] == ["Source-listed fix: Firefox 158.0.3"]
    assert doc["time_precision"] == "day"
    assert "Untrusted full description" not in str(doc)
    with pytest.raises(BulletinError, match="identity"):
        mozilla_detail(candidate, MOZILLA_DETAIL.replace(b"2026-117", b"2026-118"), now=NOW)


def test_finite_history_gap_is_disclosed_and_current_observation_resumes(database):
    report = run(database)
    assert report["state"] == "fresh", report
    assert report["accepted"]["new"] == 1
    with Session(database.engine) as session:
        state = session.get(OfficialSourceCheckpoint, "ubuntu-usn").document
        assert state["complete_through"] is not None
        assert state["initial_history_complete"] is False
        row = session.scalar(select(BulletinCurrent))
        assert row.mode == "automatic"
        assert row.expires_at == NOW + timedelta(days=90)
        assert session.scalar(select(func.count()).select_from(OfficialNoticeEvidence)) == 2
    report = run(
        database, now=NOW + timedelta(days=2), body=rss(date="Sun, 25 Oct 2026 00:00:00 GMT")
    )
    assert report["state"] == "fresh"
    with Session(database.engine) as session:
        current = session.get(OfficialSourceCheckpoint, "ubuntu-usn").document
        assert current["complete_through"] > state["complete_through"]
        status = bulletin_store.source_status(session, now=NOW + timedelta(days=2))["sources"][0]
        assert status["coverage_gaps"]["count"] == 1
        assert status["coverage_gaps"]["recent"][0]["since"] == state["observed_through"]
        row = session.scalar(select(BulletinCurrent))
        assert (
            bulletin_store.detail(session, row.bulletin_id, now=NOW + timedelta(days=2))[
                "freshness"
            ]
            == "fresh"
        )
    run(
        database,
        now=NOW + timedelta(days=2, hours=1),
        body=rss(date="Sun, 25 Oct 2026 00:00:00 GMT"),
    )
    with Session(database.engine) as session:
        current = session.get(OfficialSourceCheckpoint, "ubuntu-usn").document
        assert current["coverage_gaps"]["count"] == 1


def test_unchanged_source_has_no_revision_churn_and_compact_renewal(database):
    run(database)
    later = NOW + timedelta(hours=23)
    run(database, now=later)
    with Session(database.engine) as session:
        row = session.scalar(select(BulletinCurrent))
        assert row.revision == 1 and row.verified_at == later
        assert session.scalar(select(func.count()).select_from(BulletinMaintenanceReceipt)) == 1
        assert session.scalar(select(func.count()).select_from(OfficialNoticeEvidence)) == 2


def test_changed_source_creates_new_immutable_revision(database):
    run(database)
    run(database, now=NOW + timedelta(hours=1), body=rss(body="CVE-2026-99999"))
    with Session(database.engine) as session:
        row = session.scalar(select(BulletinCurrent))
        assert row.revision == 2
        old = session.get(BulletinRevision, (row.bulletin_id, 1))
        new = session.get(BulletinRevision, (row.bulletin_id, 2))
        assert "CVE-2026-12345" in old.document["aliases"]
        assert "CVE-2026-99999" in new.document["aliases"]


def reviewed_ubuntu():
    doc = content()
    doc["record_url"] = URL
    doc["sources"] = [
        {
            **doc["sources"][0],
            "source_id": "gbsec:source:ubuntu-security-notices",
            "record_url": URL,
            "rights_revision": 1,
            "attribution": REGISTRY.get("gbsec:source:ubuntu-security-notices").source["rights"][
                "attribution_text"
            ],
            "used_fields": ["url"],
        }
    ]
    return doc


@pytest.mark.parametrize("revoked", [False, True])
def test_reviewed_identity_is_never_replaced_refreshed_or_resurrected(database, revoked):
    with Session(database.engine) as session, session.begin():
        result = bulletin_store.publish(
            session,
            reviewed_ubuntu(),
            grant=AUTO,
            registry=REGISTRY,
            now=NOW,
            manual_approval="1" * 64,
        )
        if revoked:
            bulletin_store.tombstone(session, result["bulletin_id"], now=NOW)
    run(database, now=NOW + timedelta(hours=1))
    run(database, now=NOW + timedelta(hours=2))
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(BulletinCurrent)) == 1
        row = session.get(BulletinCurrent, result["bulletin_id"])
        assert row.revision == 1 and row.verified_at == NOW
        assert row.tombstoned == revoked
        queue = session.scalars(select(BulletinReviewQueue)).all()
        assert len(queue) == 1 and queue[0].state == "pending"
        assert queue[0].reason == ("revoked_identity" if revoked else "reviewed_source_observed")


def test_github_publisher_aliases_match_without_merging_cves():
    global_url = "https://github.com/advisories/GHSA-mh6f-8j2x-4483"
    repository_url = "https://github.com/owner/project/security/advisories/GHSA-mh6f-8j2x-4483"
    assert aliases(global_url) & aliases(repository_url)
    assert not aliases(global_url) & aliases(URL)


def test_detail_failure_keeps_pending_work_and_does_not_publish_index(database):
    def fetch(source, **kw):
        if kw.get("url"):
            raise OSError("network unavailable")
        return fetcher(MOZILLA_INDEX)()

    report = run(database, source="mozilla-mfsa", fetch=fetch)
    assert report["detail_requests"]["failed"] == 1
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(BulletinCurrent)) == 0
        assert session.scalar(select(func.count()).select_from(OfficialNoticePending)) == 1
    report = run(
        database,
        source="mozilla-mfsa",
        now=NOW + timedelta(hours=6),
        fetch=lambda source, **kw: fetcher(MOZILLA_DETAIL if kw.get("url") else MOZILLA_INDEX)(),
    )
    assert report["accepted"]["new"] == 1


def test_unretained_or_changed_evidence_cannot_publish(database):
    candidate = parse_index("ubuntu-usn", rss(), now=NOW)[0]
    candidate = publisher_detail(candidate, detail(), now=NOW)
    doc = project_facts(envelope(candidate, now=NOW, retrospective=False), REGISTRY, now=NOW)
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(BulletinError, match="accepted_input_required"),
    ):
        bulletin_store.publish(session, doc, grant=AUTO, registry=REGISTRY, now=NOW)
    run(database)
    with Session(database.engine) as session, session.begin():
        current = session.scalar(select(OfficialNoticeCurrent))
        original = project_facts(current.document, REGISTRY, now=NOW)
        forged = deepcopy(original)
        forged["severity"] = "critical"
        with pytest.raises(BulletinError, match="projection_mismatch"):
            bulletin_store.publish(session, forged, grant=AUTO, registry=REGISTRY, now=NOW)


def test_catalog_reuses_latest_package_facts_and_rejects_stale_collector(database, monkeypatch):
    from smithguard import bulletin_catalog
    from smithguard.advisory_catalog import append_github_advisory

    from .test_advisory_catalog import EVIDENCE_ID, GOVERNANCE_ID, _github_event_stream

    value = _github_event_stream()
    value.update(published_at="2026-10-22T10:00:00Z", updated_at="2026-10-22T10:00:00Z")
    value["vulnerabilities"][0]["first_patched_version"] = "4.0.0"
    with Session(database.engine) as session, session.begin():
        append_github_advisory(
            session,
            document=value,
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )
    monkeypatch.setattr(
        bulletin_catalog, "freshness", lambda *a, **kw: (NOW, NOW + timedelta(hours=25))
    )
    report = run(database, source="ghsa-bulletin")
    assert report["accepted"]["new"] == 1, report
    with Session(database.engine) as session:
        row = session.scalar(select(BulletinCurrent))
        doc = session.get(BulletinRevision, (row.bulletin_id, row.revision)).document
        assert "npm: event-stream" in doc["subjects"]
        assert "Source-listed fix: npm: event-stream 4.0.0" in doc["guidance"]
        assert doc["severity"] == "unknown"

    def stale(*a, **kw):
        raise BulletinError("bulletin_catalog_not_fresh")

    monkeypatch.setattr(bulletin_catalog, "freshness", stale)
    report = run(database, source="ghsa-bulletin", now=NOW + timedelta(hours=1))
    assert report["state"] == "unavailable"
    with Session(database.engine) as session:
        assert session.scalar(select(BulletinCurrent)).verified_at == NOW


def test_discovery_never_confirms_or_copies_authors(database):
    from smithguard.bulletin_discovery import run as discover

    body = b"""<table><tr><td>ZDI-CAN-12345</td><td>Linux</td><td>CVSS: 8.8</td>
<td>2026-10-22</td><td>2027-02-19</td><td>Discovered by: private@example.test</td></tr></table>"""
    with database.engine.connect() as connection:
        result = discover(
            connection,
            "zdi-upcoming",
            now=NOW,
            epoch="20261023T12",
            registry=REGISTRY,
            enabled=lambda: True,
            fetch=fetcher(body),
        )
    assert result["accepted"]["new"] == 1, result
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(BulletinCurrent)) == 0
        row = session.scalar(select(BulletinReviewQueue))
        assert row.document["record"]["verification"] == "unverified"
        assert "private@example.test" not in str(row.document)
        assert "CVSS" not in str(row.document)


def test_mail_discovery_has_strict_origin_and_security_scope():
    from smithguard.bulletin_discovery import parse

    body = b"""<ul><li><a href="2026/10/22/100">CVE-2026-12345 kernel security</a>
<li><a href="2026/10/22/101">Ordinary driver cleanup</a></ul>"""
    values = parse("linux-security", body, now=NOW, baseline=NOW - timedelta(days=2))
    assert len(values) == 1 and values[0]["aliases"] == ["CVE-2026-12345"]
    assert "kernel security" not in str(values)
    with pytest.raises(BulletinError):
        parse(
            "linux-security",
            body.replace(b"2026/10/22/100", b"https://evil.test/linux-kernel/2026/10/22/100"),
            now=NOW,
            baseline=NOW - timedelta(days=2),
        )


def test_existing_detail_is_rechecked_when_index_fails(database):
    run(database)
    calls = []

    def missing_index(source, **kwargs):
        calls.append(kwargs.get("url"))
        if not kwargs.get("url"):
            raise BulletinError("synthetic_index_down")
        return fetcher()(source, **kwargs)

    later = NOW + timedelta(hours=23)
    result = run(database, now=later, fetch=missing_index)
    assert result["state"] == "unavailable"
    assert calls == [None, URL]
    with Session(database.engine) as session:
        assert session.scalar(select(BulletinCurrent)).verified_at == later
        state = bulletin_store.source_status(session, now=later)["sources"][0]
        assert state["state"] == "unavailable"


def test_preview_debt_is_processed_on_next_source_check(database):
    preview = processor(
        registry=REGISTRY, grant_reader=lambda **kw: {**AUTO, "mode": "manual_preview"}
    )
    run(database, process=preview)
    with Session(database.engine) as session:
        assert session.scalar(select(OfficialNoticeCurrent)).publication_pending
        assert session.scalar(select(BulletinCurrent)) is None
    run(database, now=NOW + timedelta(hours=1))
    with Session(database.engine) as session:
        assert session.scalar(select(BulletinCurrent)).revision == 1
        assert not session.scalar(select(OfficialNoticeCurrent)).publication_pending


def test_disabled_reader_never_dispatches(database, monkeypatch):
    called = []
    profile = REGISTRY.get("gbsec:source:apple-release-index")
    monkeypatch.setitem(profile.source, "kill_switch", False)
    result = run(database, source="apple-releases", fetch=lambda *a, **k: called.append(a))
    assert result["state"] == "unavailable"
    assert called == []


def test_review_resolution_is_exact_once_and_preserves_audit(database):
    from smithguard.bulletin_review import queue, resolve
    from smithguard.identifiers import canonical_json_bytes

    original = {"reason": "discovery_requires_review", "record": {"url": URL}}
    identity = sha256_id(canonical_json_bytes(original))
    with Session(database.engine) as session, session.begin():
        session.add(
            BulletinReviewQueue(
                review_id=identity,
                source_key="ubuntu-usn",
                record_key="a" * 64,
                state="pending",
                reason="discovery_requires_review",
                document=original,
                created_at=NOW,
                updated_at=NOW,
            )
        )
    with Session(database.engine) as session, session.begin():
        item = queue(session)["items"][0]
        decision = {
            "review_id": identity,
            "expected_document_hash": item["document_hash"],
            "outcome": "dismissed",
            "reason": "insufficient_evidence",
            "evidence_hashes": ["sha256:" + "a" * 64],
            "bulletin_id": None,
            "expected_revision": None,
        }
        with pytest.raises(BulletinError, match="changed"):
            resolve(session, {**decision, "expected_document_hash": "sha256:" + "b" * 64}, now=NOW)
        result = resolve(session, decision, now=NOW)
        assert result["state"] == "dismissed"
    with Session(database.engine) as session, session.begin():
        assert queue(session)["pending"] == 0
        assert session.get(BulletinReviewQueue, identity).document == original
        assert (
            session.get(BulletinMaintenanceReceipt, result["receipt_id"]).document["decision"]
            == decision
        )
        with pytest.raises(BulletinError, match="changed"):
            resolve(session, decision, now=NOW)


@pytest.mark.parametrize(
    "source,url,region,extra,fix",
    [
        (
            "node-releases",
            "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
            '<main><h1>Security update</h1><h2 id="downloads-and-release-details">Downloads</h2>'
            '<a href="/en/blog/release/v24.10.1">release</a><p>CVE-2026-12345</p></main>',
            "",
            "Node.js v24.10.1",
        ),
        (
            "gitlab-releases",
            "https://docs.gitlab.com/releases/patches/2026-10-22-gitlab-19-5-1-released/",
            '<div class="docs-content"><h1>GitLab Patch Release: 19.5.1</h1>'
            "<p>CVE-2026-12345</p></div>",
            "",
            "GitLab 19.5.1",
        ),
        (
            "zdi-published",
            "https://www.zerodayinitiative.com/advisories/ZDI-26-999/",
            "<article><h1>ZDI-26-999</h1><p>ZDI-CAN-12345 CVE-2026-12345</p></article>",
            "",
            None,
        ),
        (
            "cisco-advisories",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-example",
            '<div id="advisorycontentcontainer"><h1>Synthetic</h1><p>CVE-2026-12345</p></div>',
            "",
            None,
        ),
        (
            "fortinet-advisories",
            "https://fortiguard.fortinet.com/psirt/FG-IR-26-123",
            '<main><table class="meta"><tr><td>IR Number</td><td>FG-IR-26-123</td></tr>'
            "<tr><td>Severity</td><td>High</td></tr><tr><td>Updated Date</td><td>Oct 22, 2026</td>"
            "</tr></table><p>CVE-2026-12345</p></main>",
            "",
            None,
        ),
    ],
)
def test_source_specific_detail_identity_and_fields(source, url, region, extra, fix):
    from smithguard.bulletin_source_parser import SourceCandidate, basic_facts

    identifier = url.rstrip("/").rsplit("/", 1)[-1]
    initial = SourceCandidate(
        source,
        url,
        NOW - timedelta(days=1),
        None,
        basic_facts(record_id=identifier, aliases=[], body_hash="sha256:" + "a" * 64),
        True,
    )
    body = (f'<link rel="canonical" href="{url}">' + region + extra).encode()
    accepted = publisher_detail(initial, body, now=NOW)
    assert "CVE-2026-12345" in accepted.facts["aliases"]
    assert accepted.needs_detail is False
    if fix:
        assert fix in accepted.facts["fixed_versions"]
    if source == "fortinet-advisories":
        assert accepted.facts["severity"] == "high"
    with pytest.raises(BulletinError):
        publisher_detail(initial, b"<html><p>Wrong page</p></html>", now=NOW)


@pytest.mark.parametrize("origin", ["go", "rustsec"])
def test_origin_catalog_requires_latest_membership_and_preserves_range_context(
    database, monkeypatch, origin
):
    from types import SimpleNamespace

    from smithguard import bulletin_catalog, origin_advisories, supplemental_store
    from smithguard.db.models import AdvisoryCatalogRecord
    from tests.test_origin_advisories import document, normalize

    value = document(origin)
    value.update(published="2026-10-22T10:00:00Z", modified="2026-10-22T10:00:00Z")
    record = normalize(value, origin)
    with Session(database.engine) as session, session.begin():
        origin_advisories.append_origin_advisory(
            session,
            record=record,
            evidence_id="gbsec:evidence:synthetic-origin",
            governance_decision_id="gbsec:governance:synthetic-origin",
            observed_at=NOW,
        )
    source = "go-bulletin" if origin == "go" else "rustsec-bulletin"
    monkeypatch.setattr(
        supplemental_store,
        "source_state",
        lambda *a, **k: ("fresh", SimpleNamespace(snapshot_id="snapshot")),
    )
    with Session(database.engine) as session:
        row = session.scalar(select(AdvisoryCatalogRecord))
        member = {
            "catalog_event_id": row.catalog_event_id,
            "context": {"attribution_complete": True},
            "license_expression": "CC-BY-4.0",
            "attribution_urls": ["https://github.com/advisories/GHSA-2345-6789-cfgh"],
        }
        monkeypatch.setattr(
            supplemental_store, "snapshot_facts", lambda *a, **k: {row.upstream_record_id: member}
        )
        result = bulletin_catalog.candidate(session, source, row, now=NOW)
        assert any("introduced 0; fixed 0.10.0" in v for v in result.facts["conditions"])
        if origin == "rustsec":
            assert result.url.startswith("https://rustsec.org/advisories/")
            public = project_facts(
                envelope(result, now=NOW, retrospective=False), REGISTRY, now=NOW
            )
            assert public["sources"][1]["record_url"] == member["attribution_urls"][0]
        member["catalog_event_id"] = "gbsec:catalog-event:different"
        with pytest.raises(BulletinError, match="membership"):
            bulletin_catalog.candidate(session, source, row, now=NOW)
        monkeypatch.setattr(supplemental_store, "snapshot_facts", lambda *a, **k: {})
        with pytest.raises(BulletinError, match="membership"):
            bulletin_catalog.candidate(session, source, row, now=NOW)


def test_network_detail_freshness_is_independent_of_index_deadline(database):
    from smithguard.db.bulletin_models import BulletinSourceStatus

    run(database)
    with Session(database.engine) as session, session.begin():
        row = session.scalar(select(BulletinCurrent))
        identity = row.bulletin_id
        source = session.get(BulletinSourceStatus, "ubuntu-usn")
        source.upstream_due_at = NOW + timedelta(minutes=30)
        assert row.verification_due_at == NOW + timedelta(hours=24)
    with Session(database.engine) as session:
        first = bulletin_store.detail(session, identity, now=NOW)
        assert datetime.fromisoformat(first["verification_due_at"]) == NOW + timedelta(hours=24)
        assert first["freshness"] == "fresh"
        expired = bulletin_store.detail(session, identity, now=NOW + timedelta(minutes=31))
        assert expired["freshness"] == "fresh"
        assert session.scalar(select(func.count()).select_from(BulletinMaintenanceReceipt)) == 0
        assert session.scalar(select(BulletinCurrent)).verified_at == NOW


def test_busy_source_reserves_detail_capacity_for_new_arrivals(database):
    from smithguard.bulletin_intake_store import retain
    from smithguard.bulletin_source_parser import SourceCandidate, basic_facts

    earlier = NOW - timedelta(days=2)
    known = []
    with Session(database.engine) as session, session.begin():
        for number in range(150):
            url = f"https://ubuntu.com/security/notices/USN-{9100 + number}-1"
            facts = basic_facts(
                record_id=f"USN-{9100 + number}-1", aliases=[], body_hash=sha256_id(b"detail")
            )
            facts["index_hash"] = sha256_id(b"index")
            qualified = SourceCandidate("ubuntu-usn", url, earlier, None, facts, False)
            value = envelope(qualified, now=earlier, retrospective=True)
            retain(session, value, now=earlier)
            session.add(
                OfficialNoticeCurrent(
                    source_key="ubuntu-usn",
                    record_key=qualified.record_key,
                    document=value,
                    semantic_hash=value["semantic_hash"],
                    first_seen_at=earlier,
                    updated_at=earlier,
                )
            )
            known.append(SourceCandidate("ubuntu-usn", url, earlier, None, facts, True))
        session.flush()
        new = parse_index("ubuntu-usn", rss(), now=NOW)[0]
        automation.stage(session, "ubuntu-usn", known + [new], now=NOW, baseline=earlier)
        assert (
            session.scalar(
                select(func.count())
                .select_from(OfficialNoticePending)
                .where(OfficialNoticePending.kind == "recheck")
            )
            == 150
        )
    calls = []

    def fetch(source, *, url):
        calls.append(url)
        identity = url.rsplit("/", 1)[-1]
        body = (
            f'<link rel="canonical" href="{url}"><main><h1>{identity}: synthetic</h1>'
            "<p>CVE-2026-12345</p></main>"
        ).encode()
        return FetchResult(200, body, None, None, sha256_id(body))

    with database.engine.connect() as connection:
        result = automation.qualify_details(
            connection, "ubuntu-usn", now=NOW, fetch=fetch, registry=REGISTRY, enabled=lambda: True
        )
    assert result == {"attempted": automation.DETAIL_LIMIT, "failed": 0}
    assert URL in calls
    assert len(set(calls)) == automation.DETAIL_LIMIT


def test_older_details_have_explicit_longer_deadlines():
    from smithguard.bulletin_freshness import due

    assert due("ubuntu-usn", NOW - timedelta(days=2), NOW) == NOW + timedelta(days=1)
    assert due("ubuntu-usn", NOW - timedelta(days=15), NOW) == NOW + timedelta(days=7)
    assert due("ubuntu-usn", NOW - timedelta(days=60), NOW) == NOW + timedelta(days=14)
    assert due("ghsa-bulletin", NOW - timedelta(days=60), NOW) == NOW + timedelta(days=1)


def test_new_storage_pressure_does_not_rollback_corrections(database, monkeypatch):
    from smithguard.bulletin_source_parser import SourceCandidate

    run(database)
    with Session(database.engine) as session, session.begin():
        candidate = publisher_detail(
            parse_index("ubuntu-usn", rss(body="CVE-2026-99999"), now=NOW)[0],
            detail(b"CVE-2026-99999"),
            now=NOW,
        )
        new = SourceCandidate(
            "ubuntu-usn",
            URL.replace("9000", "9999"),
            candidate.published,
            None,
            candidate.facts,
            False,
        )
        automation.stage(
            session, "ubuntu-usn", [candidate, new], now=NOW, baseline=NOW - timedelta(days=14)
        )

    def capacity(session, *, new_identity):
        if new_identity:
            raise BulletinError("bulletin_admission_capacity")

    monkeypatch.setattr(automation, "capacity", capacity)
    with Session(database.engine) as session, session.begin():
        result = automation.drain_qualified(
            session, "ubuntu-usn", now=NOW, process=lambda *a, **kw: True
        )
        assert result["corrected"] == 1 and result["new"] == 0
        assert (
            session.scalar(
                select(func.count())
                .select_from(OfficialNoticePending)
                .where(OfficialNoticePending.processed_at.is_(None))
            )
            == 1
        )


def test_one_detail_failure_does_not_stale_other_records(database):
    from smithguard.db.bulletin_models import BulletinSourceStatus

    run(database)
    with Session(database.engine) as session, session.begin():
        source = session.get(BulletinSourceStatus, "ubuntu-usn")
        source.state, source.reason = "incomplete", "detail_qualification_failed"
        row = session.scalar(select(BulletinCurrent))
        assert bulletin_store.detail(session, row.bulletin_id, now=NOW)["freshness"] == "fresh"
        source.state, source.reason = "unavailable", "bulletin_source_http"
        assert bulletin_store.detail(session, row.bulletin_id, now=NOW)["freshness"] == "fresh"
        assert (
            bulletin_store.detail(session, row.bulletin_id, now=NOW + timedelta(days=1))[
                "freshness"
            ]
            == "stale"
        )


def populate_review_queue(session, count, *, offset=0):
    from sqlalchemy import insert

    session.execute(
        insert(BulletinReviewQueue),
        [
            dict(
                review_id=sha256_id(f"queue-{i}".encode()),
                source_key="zdi-upcoming",
                record_key=f"{i:064x}",
                state="pending",
                reason="discovery_requires_review",
                document={"synthetic": i},
                created_at=NOW,
                updated_at=NOW,
            )
            for i in range(offset, count + offset)
        ],
    )


def test_discovery_reserves_queue_space_for_identity_work(database):
    from smithguard.bulletin_discovery import run as discover

    with Session(database.engine) as session, session.begin():
        populate_review_queue(session, 1600)
        bulletin_store.publish(
            session,
            reviewed_ubuntu(),
            grant=AUTO,
            registry=REGISTRY,
            now=NOW,
            manual_approval="1" * 64,
        )
    body = (
        b"<table><tr><td>ZDI-CAN-12345</td><td>Linux</td><td>CVSS: 8.8</td>"
        b"<td>2026-10-22</td><td>2027-02-19</td><td>Private author</td></tr></table>"
    )
    with database.engine.connect() as connection:
        result = discover(
            connection,
            "zdi-upcoming",
            now=NOW,
            epoch="20261023T12",
            registry=REGISTRY,
            enabled=lambda: True,
            fetch=fetcher(body),
        )
    assert result["reason"] == "review_queue_capacity"
    assert result["accepted"]["new"] == 0
    run(database)
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(BulletinReviewQueue)) == 1601
        assert (
            session.scalar(
                select(func.count())
                .select_from(BulletinReviewQueue)
                .where(BulletinReviewQueue.reason == "reviewed_source_observed")
            )
            == 1
        )


def test_full_review_queue_defers_identity_without_aborting_source(database):
    with Session(database.engine) as session, session.begin():
        populate_review_queue(session, 2000)
        bulletin_store.publish(
            session,
            reviewed_ubuntu(),
            grant=AUTO,
            registry=REGISTRY,
            now=NOW,
            manual_approval="1" * 64,
        )
    report = run(database)
    assert report["input_qualified"] and report["state"] == "incomplete"
    with Session(database.engine) as session:
        assert session.scalar(select(OfficialNoticeCurrent)).publication_pending
        assert session.scalar(select(func.count()).select_from(BulletinCurrent)) == 1
        assert session.scalar(select(func.count()).select_from(BulletinReviewQueue)) == 2000


def test_catalog_isolates_a_malformed_record_and_discloses_omission(database, monkeypatch):
    from smithguard import bulletin_catalog
    from smithguard.advisory_catalog import append_github_advisory

    from .test_advisory_catalog import EVIDENCE_ID, GOVERNANCE_ID, _github_event_stream

    good = _github_event_stream()
    good.update(published_at="2026-10-22T10:00:00Z", updated_at="2026-10-22T10:00:00Z")
    bad = deepcopy(good)
    bad.update(
        ghsa_id="GHSA-2345-2345-2345", html_url="https://github.com/advisories/GHSA-2345-2345-2345"
    )
    with Session(database.engine) as session, session.begin():
        for value in [good, bad]:
            append_github_advisory(
                session,
                document=value,
                evidence_id=EVIDENCE_ID,
                governance_decision_id=GOVERNANCE_ID,
                observed_at=NOW,
            )
    monkeypatch.setattr(
        bulletin_catalog, "freshness", lambda *a, **kw: (NOW, NOW + timedelta(hours=25))
    )
    original = bulletin_catalog.candidate

    def candidate(session, source, row, *, now):
        if row.upstream_record_id == bad["ghsa_id"]:
            raise KeyError("type")
        return original(session, source, row, now=now)

    monkeypatch.setattr(bulletin_catalog, "candidate", candidate)
    report = run(database, source="ghsa-bulletin")
    assert report["accepted"]["new"] == 1
    assert report["observation"]["omitted_records"] == 1
    assert report["reason"] == "catalog_record_omitted"
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(BulletinReviewQueue)) == 1
        row = session.scalar(select(BulletinCurrent))
        assert bulletin_store.detail(session, row.bulletin_id, now=NOW)["freshness"] == "fresh"


def test_mozilla_detail_announcement_date_is_authoritative():
    candidate = parse_index("mozilla-mfsa", MOZILLA_INDEX, now=NOW)[0]
    detail = MOZILLA_DETAIL.replace(b"October 22, 2026", b"October 21, 2026")
    accepted = mozilla_detail(candidate, detail, now=NOW)
    assert accepted.published == candidate.published - timedelta(days=1)
    assert "announcement date" in accepted.facts["conditions"][0]


def test_large_official_rollup_keeps_identity_and_discloses_alias_omissions():
    from smithguard.bulletin_source_parser import SourceCandidate, basic_facts

    url = "https://security.paloaltonetworks.com/PAN-SA-2026-0013"
    candidate = SourceCandidate(
        "paloalto-advisories",
        url,
        NOW,
        None,
        basic_facts(record_id="PAN-SA-2026-0013", body_hash=sha256_id(b"index")),
        True,
    )
    body = (
        '<main id="content"><h2>PAN-SA-2026-0013 Security Update</h2><p>'
        + " ".join(f"CVE-2026-{i:05d}" for i in range(450))
        + "</p></main>"
    ).encode()
    accepted = publisher_detail(candidate, body, now=NOW)
    assert len(accepted.facts["aliases"]) == 100
    assert "PAN-SA-2026-0013" in accepted.facts["aliases"]
    assert accepted.facts["alias_omissions"] == 351
    public = project_facts(envelope(accepted, now=NOW, retrospective=False), REGISTRY, now=NOW)
    assert any("351 additional identifiers" in value for value in public["unknowns"])
