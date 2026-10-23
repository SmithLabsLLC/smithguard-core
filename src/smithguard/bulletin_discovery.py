"""Public disclosure discovery creates private review work, never confirmations."""

import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard import bulletin_intake_store as store
from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_source_parser import CVE, Element, parse_html, safe_text
from smithguard.bulletin_sources import NETWORK_SOURCES
from smithguard.bulletin_store import capacity, lock_stream
from smithguard.db.bulletin_models import BulletinReviewQueue, BulletinSourceStatus
from smithguard.identifiers import canonical_json_bytes, sha256_id, timestamp

MAX_PENDING = 2000
MAX_NEW = 100


class LinkIndex(HTMLParser):
    """The old archive HTML has omitted end tags; only bounded anchors matter."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.current, self.nodes = [], None, 0

    def handle_starttag(self, tag, attrs):
        self.nodes += 1
        if self.nodes > 100000:
            raise BulletinError("discovery_html_budget")
        if tag == "a":
            self.current = [dict(attrs).get("href", ""), ""]

    def handle_endtag(self, tag):
        if tag == "a" and self.current:
            self.links.append(self.current)
            self.current = None

    def handle_data(self, text):
        if self.current:
            self.current[1] += text
            if len(self.current[1]) > 2000:
                raise BulletinError("discovery_subject_budget")


def parse(source, body, *, now, baseline, fetch_url=None):
    spec = NETWORK_SOURCES[source]
    if not isinstance(body, bytes) or not 0 < len(body) <= spec.maximum_bytes:
        raise BulletinError("discovery_body_budget")
    records = []
    if source == "zdi-upcoming":
        root = parse_html(body, maximum=spec.maximum_bytes)
        for row in [n for n in root.walk() if n.tag == "tr"]:
            cells = [n for n in row.children if isinstance(n, Element) and n.tag == "td"]
            if not cells:
                continue
            if len(cells) not in {5, 6} or not re.fullmatch(
                r"ZDI-CAN-[0-9]{1,12}", cells[0].text()
            ):
                raise BulletinError("zdi_discovery_shape")
            published = datetime.strptime(cells[3].text(), "%Y-%m-%d").replace(tzinfo=UTC)
            if published > now:
                raise BulletinError("discovery_future")
            if published < baseline:
                continue
            records.append(
                {
                    "record_id": cells[0].text(),
                    "url": spec.endpoint,
                    "source_published_at": timestamp(published),
                    "time_precision": "day",
                    "vendor": safe_text(cells[1].text(), 200),
                    "aliases": [cells[0].text()],
                    "basis": "publisher_upcoming_report",
                    "verification": "unverified",
                }
            )
    else:
        value = body.decode("utf-8-sig")
        if "<!ENTITY" in value.upper():
            raise BulletinError("discovery_html_entity")
        parser = LinkIndex()
        parser.feed(value)
        parser.close()
        valid_archive_links = 0
        for href, title in parser.links:
            url = urljoin(fetch_url or spec.endpoint, href)
            if not re.fullmatch(spec.record_path, urlsplit(url).path):
                continue
            spec.record_url(url)
            valid_archive_links += 1
            parts = url.rstrip("/").rsplit("/", 4)
            published = datetime.strptime("-".join(parts[-4:-1]), "%Y-%m-%d").replace(tzinfo=UTC)
            if not baseline <= published <= now:
                continue
            identifiers = sorted(
                {v.upper() for v in CVE.findall(title)}
                | set(re.findall(r"\bZDI-CAN-[0-9]{1,12}\b", title))
            )
            if (
                source == "linux-security"
                and not identifiers
                and not re.search(
                    r"\b(vulnerabilit\w*|security|exploit\w*|ksmbd|use.after.free|out.of.bounds)\b",
                    title,
                    re.I,
                )
            ):
                continue
            records.append(
                {
                    "record_id": url.rsplit("/", 4)[-4:][0]
                    + "-"
                    + "/".join(url.rsplit("/", 3)[-3:]),
                    "url": url,
                    "source_published_at": timestamp(published),
                    "time_precision": "day",
                    "aliases": identifiers,
                    "subject_hash": sha256_id(" ".join(title.split()).encode()),
                    "basis": "public_security_list"
                    if source == "oss-security"
                    else "security_subject_match",
                    "verification": "unverified",
                }
            )
        # An empty day is allowed only for the archive's explicit empty-day page.
        if not valid_archive_links and "No messages" not in value and "no messages" not in value:
            raise BulletinError("discovery_archive_shape")
    unique = {}
    for record in records:
        key = record["record_id"]
        if key in unique and unique[key] != record:
            raise BulletinError("discovery_identity_conflict")
        unique[key] = record
    return list(unique.values())


def run(connection, source, *, now, epoch, registry, enabled, fetch, limit=MAX_NEW):
    from smithguard.bulletin_intake import reason

    spec = NETWORK_SOURCES[source]
    with Session(connection) as session, session.begin():
        checkpoint = store.checkpoint(session, source, now=now)
        state = deepcopy(checkpoint.document)
        if not state.get("discovery_version"):
            state.update(discovery_version=1, baseline_at=timestamp(now - timedelta(days=14)))
            checkpoint.document = deepcopy(state)
    baseline = store.instant(state["baseline_at"])
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    previous = store.instant(state["complete_through"])
    if source == "zdi-upcoming":
        urls, caught_up, through = [spec.endpoint], True, now
        state.setdefault("coverage_start_at", timestamp(baseline))
        state.setdefault("initial_history_complete", False)
    else:
        start = (
            min(
                previous.replace(hour=0, minute=0, second=0, microsecond=0),
                today - timedelta(days=2),
            )
            if previous
            else today - timedelta(days=2)
        )
        days = [start + timedelta(days=offset) for offset in range(3)]
        days = [day for day in days if day <= today]
        urls = [spec.endpoint + day.strftime("%Y/%m/%d/") for day in days]
        caught_up = days[-1] == today
        through = now if caught_up else days[-1] + timedelta(days=1) - timedelta(microseconds=1)
        state.setdefault("coverage_start_at", timestamp(start))
        state.setdefault("initial_history_complete", False)
    attempted, added, deferred, records, receipts, error = 0, 0, 0, [], [], None
    try:
        for url in urls:
            if not enabled():
                raise BulletinError("policy_paused")
            registry.get(spec.source_id).authorize_collection(
                method="download", canonical_url=url, today=now.date()
            )
            attempted += 1
            response = fetch(source, url=url)
            if (
                response.status == 404
                and source != "zdi-upcoming"
                and url.endswith(today.strftime("%Y/%m/%d/"))
            ):
                receipts.append({"url": url, "status": 404, "scope": "today_not_created_yet"})
                continue
            if response.status != 200:
                raise BulletinError("discovery_http")
            values = parse(source, response.body, now=now, baseline=baseline, fetch_url=url)
            records.extend(values)
            receipts.append(
                {
                    "url": url,
                    "status": 200,
                    "body_hash": response.sha256,
                    "records": len(values),
                    "bytes": len(response.body),
                }
            )
        with Session(connection) as session, session.begin():
            lock_stream(session, now=now)
            pending = session.scalar(
                select(func.count())
                .select_from(BulletinReviewQueue)
                .where(BulletinReviewQueue.state == "pending")
            )
            discovery_pending = session.scalar(
                select(func.count())
                .select_from(BulletinReviewQueue)
                .where(
                    BulletinReviewQueue.state == "pending",
                    BulletinReviewQueue.reason == "discovery_requires_review",
                )
            )
            queue_full = False
            for record in records:
                document = {
                    "source_key": source,
                    "source_id": spec.source_id,
                    "record": record,
                    "reason": "discovery_requires_review",
                }
                identity = sha256_id(canonical_json_bytes(document))
                if session.get(BulletinReviewQueue, identity):
                    continue
                if pending >= MAX_PENDING or discovery_pending >= 1600:
                    queue_full = True
                    deferred += 1
                    continue
                if added >= min(MAX_NEW, limit):
                    deferred += 1
                    continue
                capacity(session, new_identity=True)
                session.add(
                    BulletinReviewQueue(
                        review_id=identity,
                        source_key=source,
                        record_key=sha256_id(canonical_json_bytes([source, record["record_id"]]))[
                            7:
                        ],
                        state="pending",
                        reason="discovery_requires_review",
                        document=document,
                        created_at=now,
                        updated_at=now,
                    )
                )
                added, pending = added + 1, pending + 1
                discovery_pending += 1
            session.flush()
        state["last_success"] = timestamp(now)
        if not deferred:
            state["complete_through"] = timestamp(through)
    except Exception as caught:
        error = reason(caught)
    with Session(connection) as session, session.begin():
        checkpoint = store.checkpoint(session, source, now=now)
        state.update(last_attempt=timestamp(now), consumed_epoch=epoch)
        checkpoint.document, checkpoint.updated_at = state, now
        count, oldest = session.execute(
            select(func.count(), func.min(BulletinReviewQueue.created_at)).where(
                BulletinReviewQueue.source_key == source,
                BulletinReviewQueue.state == "pending",
            )
        ).one()
        status = session.get(BulletinSourceStatus, source)
        if status is None:
            status = BulletinSourceStatus(source_key=source)
            session.add(status)
        status.state = (
            "unavailable" if error else "incomplete" if deferred or not caught_up else "fresh"
        )
        status.reason = (
            error[:40]
            if error
            else "review_queue_capacity"
            if deferred and queue_full
            else "catching_up"
            if deferred
            else "catching_up"
            if not caught_up
            else None
        )
        status.last_attempt_at, status.last_success_at = now, store.instant(state["last_success"])
        status.complete_through_at = store.instant(state["complete_through"])
        status.coverage_start_at = store.instant(state["coverage_start_at"])
        status.initial_history_complete = state["initial_history_complete"]
        status.pending_count, status.oldest_pending_at, status.updated_at = count, oldest, now
        return {
            "source": source,
            "state": status.state,
            "reason": status.reason,
            "accepted": {"new": added},
            "pending": count,
            "deferred": deferred,
            "network_attempted": bool(attempted),
            "discovery_only": True,
            "input_qualified": error is None,
            "observations": receipts,
        }
