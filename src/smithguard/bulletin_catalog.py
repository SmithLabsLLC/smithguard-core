"""Reuse accepted catalog facts without a second collector or invented freshness."""

import re
from datetime import timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import aliased

from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_source_parser import SourceCandidate, basic_facts, safe_text
from smithguard.bulletin_sources import CATALOG_SOURCES
from smithguard.db.bulletin_models import BulletinReviewQueue
from smithguard.db.models import AdvisoryCatalogRecord, AdvisoryPackageRecord
from smithguard.identifiers import canonical_json_bytes, sha256_id, timestamp

URLS = {
    "ghsa-bulletin": r"https://github\.com/advisories/GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}",
    "go-bulletin": r"https://pkg\.go\.dev/vuln/GO-[0-9]{4}-[0-9]{4,8}",
    "rustsec-bulletin": r"https://rustsec\.org/advisories/RUSTSEC-[0-9]{4}-[0-9]{4,8}\.html",
}


def validate_catalog_url(source, url):
    if not isinstance(url, str) or not re.fullmatch(URLS[source], url):
        raise BulletinError("bulletin_catalog_url")
    return url


def freshness(session, source, *, now):
    source_id = CATALOG_SOURCES[source][0]
    if source == "ghsa-bulletin":
        from smithguard.coverage import collection_freshness

        state = collection_freshness(
            session, source_id=source_id, lane="updates", segment="reviewed", measured_at=now
        )
        if state.state != "fresh" or state.last_success_at is None:
            raise BulletinError("bulletin_catalog_not_fresh")
        return state.last_success_at, state.stale_after
    from smithguard.supplemental_store import MAX_AGE, source_state

    state, complete = source_state(session, source_id, now=now)
    if state != "fresh" or complete is None:
        raise BulletinError("bulletin_catalog_not_fresh")
    return complete.observed_at, complete.observed_at + MAX_AGE


def current_record(session, source, upstream_id):
    return session.scalar(
        select(AdvisoryCatalogRecord)
        .where(
            AdvisoryCatalogRecord.source_id == CATALOG_SOURCES[source][0],
            AdvisoryCatalogRecord.upstream_record_id == upstream_id,
        )
        .order_by(AdvisoryCatalogRecord.revision.desc())
        .limit(1)
    )


def candidate(session, source, row, *, now):
    public_url = row.canonical_url
    attribution = []
    license_expression = None
    if source in {"go-bulletin", "rustsec-bulletin"}:
        from smithguard.supplemental_store import snapshot_facts, source_state

        state, snapshot = source_state(session, CATALOG_SOURCES[source][0], now=now)
        if state != "fresh" or snapshot is None:
            raise BulletinError("bulletin_catalog_not_fresh")
        member = snapshot_facts(session, snapshot.snapshot_id, [row.upstream_record_id]).get(
            row.upstream_record_id
        )
        if member is None or member["catalog_event_id"] != row.catalog_event_id:
            raise BulletinError("bulletin_catalog_membership")
    if source == "rustsec-bulletin":
        if not member["context"]["attribution_complete"] or member["license_expression"] not in {
            "CC0-1.0",
            "CC-BY-4.0",
        }:
            raise BulletinError("bulletin_origin_attribution")
        license_expression = member["license_expression"]
        attribution = sorted(
            {
                url
                for url in member["attribution_urls"]
                if re.fullmatch(
                    r"https://github\.com/(?:advisories|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/security/advisories)/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}",
                    url,
                )
            }
        )
        if license_expression == "CC-BY-4.0" and not attribution:
            raise BulletinError("bulletin_origin_attribution")
        if len(attribution) > 8:
            raise BulletinError("bulletin_origin_attribution_budget")
        public_url = f"https://rustsec.org/advisories/{row.upstream_record_id}.html"
    validate_catalog_url(source, public_url)
    if (
        row.source_type != CATALOG_SOURCES[source][2]
        or row.confidence != "confirmed"
        or row.source_updated_at > now
        or row.source_published_at is None
        or row.source_published_at > now
    ):
        raise BulletinError("bulletin_catalog_record")
    packages = session.scalars(
        select(AdvisoryPackageRecord)
        .where(
            AdvisoryPackageRecord.catalog_event_id == row.catalog_event_id,
        )
        .order_by(AdvisoryPackageRecord.entry_key)
        .limit(101)
    ).all()
    subjects, fixed, conditions = set(), set(), set()
    omissions = sum(row.package_omission_counts.values()) + max(0, len(packages) - 100)
    for package in packages[:100]:
        label = f"{package.ecosystem}: {package.name}"
        if len(label) > 120 or len(subjects) >= 16:
            omissions += 1
            continue
        subjects.add(safe_text(label, 120))
        for affected in package.affected_ranges:
            # Preserve source expressions; this is not our assessment/range engine.
            expression = affected.get("expression")
            if isinstance(expression, str) and len(conditions) < 16:
                text = f"{label}: {expression}"
                if len(text) <= 500:
                    conditions.add(safe_text(text, 500))
                else:
                    omissions += 1
            events = affected.get("events", [])
            if events:
                expression = "; ".join(
                    f"{key} {value}" for event in events for key, value in event.items()
                )
                text = f"{label}: source {affected['type']} range: {expression}"
                if len(text) <= 500 and len(conditions) < 16:
                    conditions.add(safe_text(text, 500))
                else:
                    omissions += 1
            for event in events:
                if "fixed" in event:
                    text = f"{label} {event['fixed']}"
                    if len(text) <= 200 and len(fixed) < 8:
                        fixed.add(safe_text(text))
                    else:
                        omissions += 1
            patched = affected.get("first_patched_version")
            if isinstance(patched, str):
                text = f"{label} {patched}"
                if len(text) <= 200 and len(fixed) < 8:
                    fixed.add(safe_text(text))
                else:
                    omissions += 1
        if package.exact_versions:
            text = f"{label}: exact versions " + ", ".join(package.exact_versions[:10])
            if len(text) <= 500 and len(conditions) < 16:
                conditions.add(safe_text(text, 500))
            omissions += max(0, len(package.exact_versions) - 10)
    aliases = sorted(set(row.aliases + [row.upstream_record_id]))
    if len(aliases) > 100 or any(len(x) > 100 for x in aliases):
        raise BulletinError("bulletin_catalog_aliases")
    facts = basic_facts(
        record_id=row.upstream_record_id,
        aliases=aliases,
        body_hash=row.record_hash,
        subjects=subjects,
        fixed=fixed,
    )
    facts.update(
        withdrawn=row.state == "withdrawn",
        conditions=sorted(conditions),
        omissions=omissions,
        catalog_event_id=row.catalog_event_id,
        catalog_revision=row.revision,
        attribution_urls=attribution,
        license_expression=license_expression,
    )
    return SourceCandidate(
        source, public_url, row.source_published_at, row.source_updated_at, facts
    )


def candidates(session, source, *, now, baseline, known_urls):
    observed, due = freshness(session, source, now=now)
    latest = (
        select(AdvisoryCatalogRecord)
        .where(
            AdvisoryCatalogRecord.source_id == CATALOG_SOURCES[source][0],
        )
        .distinct(AdvisoryCatalogRecord.upstream_record_id)
        .order_by(
            AdvisoryCatalogRecord.upstream_record_id,
            AdvisoryCatalogRecord.revision.desc(),
        )
        .subquery()
    )
    row = aliased(AdvisoryCatalogRecord, latest)
    rows = session.scalars(
        select(row)
        .where(
            row.source_type == CATALOG_SOURCES[source][2],
            row.confidence == "confirmed",
            or_(
                row.source_published_at >= baseline,
                row.canonical_url.in_(known_urls),
                row.upstream_record_id.in_(
                    [url.rsplit("/", 1)[-1].removesuffix(".html") for url in known_urls]
                ),
            ),
        )
        .order_by(row.source_published_at, row.upstream_record_id)
        .limit(10001)
    ).all()
    if len(rows) > 10000:
        raise BulletinError("bulletin_catalog_population")
    result, omitted = [], 0
    for record in rows:
        try:
            result.append(candidate(session, source, record, now=now))
        except (BulletinError, KeyError, TypeError, ValueError):
            omitted += 1
            queue_omission(session, source, record.catalog_event_id, record.record_hash, now=now)
    return result, {
        "collector_observed_at": timestamp(observed),
        "collector_due_at": timestamp(due),
        "records": len(result),
        "omitted_records": omitted,
    }


def validate_observation(session, evidence, *, now):
    source = evidence["source"]
    _, due = freshness(session, source, now=now)
    doc = evidence["document"]
    row = current_record(session, source, doc["facts"]["record_id"])
    if (
        row is None
        or row.record_hash != doc["facts"]["body_hash"]
        or candidate(session, source, row, now=now).document() != doc
    ):
        raise BulletinError("bulletin_catalog_evidence_changed")
    return min(now + timedelta(hours=24), due)


def queue_omission(session, source, record_key, evidence_hash, *, now):
    """An invalid catalog row cannot suppress unrelated qualified advisories."""
    document = {
        "source_key": source,
        "record_key": record_key,
        "evidence_hash": evidence_hash,
        "reason": "catalog_record_omitted",
    }
    identity = sha256_id(canonical_json_bytes(document))
    if session.get(BulletinReviewQueue, identity):
        return
    count = session.scalar(
        select(func.count())
        .select_from(BulletinReviewQueue)
        .where(BulletinReviewQueue.state == "pending")
    )
    if count >= 2000:
        return  # Omission count is still disclosed; the immutable catalog retains the row.
    session.add(
        BulletinReviewQueue(
            review_id=identity,
            source_key=source,
            record_key=sha256_id(str(record_key).encode())[7:],
            state="pending",
            reason="catalog_record_omitted",
            document=document,
            created_at=now,
            updated_at=now,
        )
    )
    session.flush()
