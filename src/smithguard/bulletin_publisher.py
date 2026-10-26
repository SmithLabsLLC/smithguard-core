"""Connect accepted official facts to the separate, currently authorized publisher."""

from smithguard import bulletin_store as store
from smithguard.bulletin_contract import BulletinError, bulletin_id
from smithguard.bulletin_freshness import recheck_lead
from smithguard.bulletin_policy import same_publication_content
from smithguard.bulletin_projection import project_notice
from smithguard.db.bulletin_models import BulletinCurrent, BulletinRevision


def processor(*, registry, grant_reader):
    """The reader rechecks release-bound root authority at each factual decision."""

    def process(session, current, *, now):
        value = current.document
        identity = bulletin_id(current.source_key, value["document"]["url"])
        public = session.get(BulletinCurrent, identity)
        if public is not None and public.tombstoned:
            return True
        from smithguard.bulletin_identity import disposition
        from smithguard.bulletin_sources import SOURCE_IDS

        expanded = current.source_key in SOURCE_IDS
        try:
            if expanded and disposition(session, current, identity=identity, now=now):
                return True  # Durable review work; no overwrite or resurrection.
        except BulletinError:
            return False  # Queue pressure defers this identity, never the whole source.
        if expanded and public is not None and public.expires_at and public.expires_at <= now:
            return True
        if public is None and value["retrospective"] and not expanded:
            return True  # Imported history is not an authorized automatic backfill.
        try:
            grant = grant_reader(now=now)
            if grant["mode"] != "automatic":
                if public is not None and grant["mode"] == "paused":
                    store.mark_stale(session, identity, reason="policy_paused", now=now)
                return False  # Preview verification and new facts need individual review.
            if expanded:
                from smithguard.bulletin_facts import project_facts

                document = project_facts(value, registry, now=now)
            else:
                document = project_notice(value, registry, now=now)
            prior = session.get(BulletinRevision, (identity, public.revision)) if public else None
            if prior is not None and same_publication_content(prior.document, document, registry):
                # Retain hourly source receipts, but avoid hourly per-item events.
                # Renew only inside the source's shared scheduling lead, unless
                # a stale state needs an earlier explicit resolution.
                if (
                    public.freshness_reason is None
                    and public.verification_due_at > now + recheck_lead(current.source_key)
                ):
                    return True
                if expanded:
                    from smithguard.bulletin_renewal import renew

                    renew(session, public, prior, grant=grant, registry=registry, now=now)
                else:
                    store.verify_unchanged(
                        session,
                        identity,
                        content_hash=prior.content_hash,
                        grant=grant,
                        registry=registry,
                        now=now,
                    )
            else:
                store.publish(session, document, grant=grant, registry=registry, now=now)
            return True
        except (BulletinError, OSError) as error:
            reason = (
                "rights_review_due"
                if str(error) == "bulletin_rights_not_current"
                else "policy_paused"
                if isinstance(error, OSError)
                else "verification_pending"
            )
            if public is not None:
                store.mark_stale(session, identity, reason=reason, now=now)
            return False

    return process
