"""Exact publisher identities protect reviewed work and permanent takedowns.

CVE, title similarity and cross-publisher aliases never establish identity.
"""

import re
from urllib.parse import urlsplit

from sqlalchemy import func, select

from smithguard.bulletin_contract import BulletinError
from smithguard.db.bulletin_models import (
    BulletinCurrent,
    BulletinIdentity,
    BulletinReviewQueue,
    BulletinRevision,
    OfficialSourceCheckpoint,
)
from smithguard.identifiers import canonical_json_bytes, sha256_id, timestamp


def aliases(url):
    values = {"url:" + url}
    parsed = urlsplit(url)
    if parsed.scheme == "https" and parsed.netloc == "github.com":
        match = re.fullmatch(
            r"/(?:advisories|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/security/advisories)/(GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})",
            parsed.path,
        )
        if match and not parsed.query and not parsed.fragment:
            values.add("github-advisory:" + match[1])
    return {sha256_id(value.encode()) for value in values}


def register(session, identity, document, *, now):
    # Use the primary publisher URL only. Secondary citations can describe a
    # distinct bulletin and must not take over that publisher's identity.
    for digest in aliases(document["record_url"]):
        if session.get(BulletinIdentity, (digest, identity)) is None:
            session.add(BulletinIdentity(alias_hash=digest, bulletin_id=identity, created_at=now))
    session.flush()


def seed(session, *, now):
    marker = "bulletin-identity-v1"
    if session.get(OfficialSourceCheckpoint, marker) is not None:
        return
    rows = session.scalars(select(BulletinCurrent).limit(10001)).all()
    if len(rows) > 10000:
        raise BulletinError("bulletin_identity_seed_capacity")
    for row in rows:
        revision = session.get(BulletinRevision, (row.bulletin_id, row.revision))
        register(session, row.bulletin_id, revision.document, now=now)
    session.add(
        OfficialSourceCheckpoint(
            source_key=marker,
            document={
                "schema_version": 1,
                "seeded": len(rows),
                "seeded_at": timestamp(now),
            },
            updated_at=now,
        )
    )
    session.flush()


def disposition(session, current, *, identity, now):
    matches = (
        session.scalars(
            select(BulletinCurrent)
            .join(
                BulletinIdentity,
                BulletinIdentity.bulletin_id == BulletinCurrent.bulletin_id,
            )
            .where(BulletinIdentity.alias_hash.in_(aliases(current.document["document"]["url"])))
        )
        .unique()
        .all()
    )
    others = [row for row in matches if row.bulletin_id != identity]
    if not others:
        return None
    reason = (
        "revoked_identity"
        if any(row.tombstoned for row in others)
        else "identity_conflict"
        if len(others) > 1
        else "reviewed_source_observed"
    )
    evidence = current.document
    document = {
        "source_key": current.source_key,
        "record_key": current.record_key,
        "semantic_hash": current.semantic_hash,
        "source_evidence_hash": sha256_id(canonical_json_bytes(evidence)),
        "matches": sorted([[row.bulletin_id, row.revision, row.tombstoned] for row in others]),
        "reason": reason,
    }
    # Re-observation time is not a new review item. Accepted immutable evidence
    # points to the same facts until the source changes.
    review_id = sha256_id(canonical_json_bytes(document))
    if session.get(BulletinReviewQueue, review_id) is None:
        pending = session.scalar(
            select(func.count())
            .select_from(BulletinReviewQueue)
            .where(BulletinReviewQueue.state == "pending")
        )
        if pending >= 2000:
            raise BulletinError("bulletin_review_queue_capacity")
        session.add(
            BulletinReviewQueue(
                review_id=review_id,
                source_key=current.source_key,
                record_key=current.record_key,
                state="pending",
                reason=reason,
                document=document,
                created_at=now,
                updated_at=now,
            )
        )
        session.flush()
    return reason
