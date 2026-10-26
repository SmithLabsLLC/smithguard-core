"""Age-based detail deadlines; a feed observation never renews a detail fact."""

from datetime import datetime, timedelta

from smithguard.bulletin_sources import NETWORK_SOURCES


def due(source, published, verified):
    if isinstance(published, str):
        published = datetime.fromisoformat(published.replace("Z", "+00:00"))
    age = verified - published
    interval = timedelta(hours=24)
    if source in NETWORK_SOURCES:
        interval = timedelta(
            days=14 if age > timedelta(days=30) else 7 if age > timedelta(days=7) else 1
        )
    return verified + interval


def recheck_lead(source):
    # Hosted Red Hat uses DETAIL_LIMITS in bulletin_automation: 24/hour with
    # one new-arrival slot. This lead is dormant where that source is absent.
    # Give adjacent full cohorts an extra hourly opportunity despite timer jitter.
    # This changes eligibility only, never the deadline or request/time budget.
    return timedelta(hours=3 if source == "redhat-rhsa" else 2)


def recheck_due(current, now):
    return due(
        current.source_key, current.document["document"]["published_at"], current.updated_at
    ) <= now + recheck_lead(current.source_key)
