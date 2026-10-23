"""Compact immutable authority for unchanged automatic source observations."""

from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_freshness import due as verification_due
from smithguard.bulletin_policy import authorize
from smithguard.db.bulletin_models import BulletinMaintenanceReceipt
from smithguard.identifiers import canonical_json_bytes, sha256_id, timestamp


def renew(session, row, revision, *, grant, registry, now):
    from smithguard.bulletin_store import accepted_input, capacity, verify_unchanged

    if row.freshness_reason is not None:
        verify_unchanged(
            session,
            row.bulletin_id,
            content_hash=revision.content_hash,
            grant=grant,
            registry=registry,
            now=now,
        )
        return
    observation = accepted_input(session, revision.document, now=now)
    authorize(revision.document, grant, registry, now=now, accepted_input=observation)
    due = verification_due(row.source_key, revision.document["source_published_at"], now)
    if due <= row.verification_due_at:
        return
    capacity(session, new_identity=False)
    row.verified_at, row.verification_due_at = now, due
    session.info.setdefault("bulletin_renewals", []).append(
        [
            row.bulletin_id,
            revision.content_hash,
            revision.document["sources"][0]["source_evidence_hash"],
            timestamp(due),
        ]
    )
    session.info["bulletin_renewal_authority"] = sha256_id(canonical_json_bytes(grant))
    session.info["bulletin_renewal_at"] = timestamp(now)


def flush(session, *, now):
    rows = session.info.pop("bulletin_renewals", [])
    for offset in range(0, len(rows), 200):
        document = {
            "schema_version": 1,
            "kind": "unchanged_source_verifications",
            "verified_at": session.info["bulletin_renewal_at"],
            "grant_hash": session.info["bulletin_renewal_authority"],
            "entries": rows[offset : offset + 200],
        }
        encoded = canonical_json_bytes(document)
        if len(encoded) > 90 * 1024:
            raise BulletinError("bulletin_verification_batch_budget")
        session.add(
            BulletinMaintenanceReceipt(
                receipt_id=sha256_id(encoded), document=document, created_at=now
            )
        )
    session.flush()
