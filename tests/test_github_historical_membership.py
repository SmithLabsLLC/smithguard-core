"""Historical membership uses immutable content, with honest newer-revision gaps."""

from copy import deepcopy
from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.acquisition import OperationDeadline
from smithguard.advisory_catalog import AdvisoryCatalogError, append_github_inventory_membership
from smithguard.collection_records import actionable_quarantine_count, unresolved_count
from smithguard.collectors import GITHUB_ADVISORY
from smithguard.db.models import (
    AdvisoryCatalogInventoryRecord,
    AdvisoryCatalogManifestRecord,
    AdvisoryCatalogRecord,
    CollectionRecordMembership,
    CollectionRecordOutcome,
)
from smithguard.identifiers import timestamp

from .test_collection_records import advisory, collector, count, response
from .test_collectors import NOW

pytestmark = pytest.mark.audit_ids("COL-06")


def ingest(instance, session, document, *, lane, seconds=0):
    return instance._ingest_advisory(
        session,
        advisory=document,
        now=NOW + timedelta(seconds=seconds),
        elapsed=0.01,
        lane=lane,
        deadline=OperationDeadline.start(instance.MAX_OPERATION_SECONDS),
        retry_token=f"historical-membership-{seconds}",
        source_snapshot=timestamp(NOW) if lane == "historical" else None,
    )


def test_identical_timestamp_semantic_return_keeps_original_membership_bytes(database, tmp_path):
    original = advisory()
    changed = deepcopy(original)
    changed["vulnerabilities"][0]["package"]["name"] = "changed-package"
    instance, store = collector(tmp_path, lambda request: response(request, []))
    with Session(database.engine) as session, session.begin():
        first = ingest(instance, session, original, lane="historical")
        inventory = session.scalars(select(AdvisoryCatalogInventoryRecord)).one()
        before = (inventory.inventory_event_id, inventory.catalog_event_id, inventory.record_hash)
    with Session(database.engine) as session, session.begin():
        second = ingest(instance, session, changed, lane="updates", seconds=1)
        assert second.catalog_append_result.created
    with Session(database.engine) as session, session.begin():
        third = ingest(instance, session, original, lane="historical", seconds=2)
        assert third.catalog_append_result.created
        assert (
            third.catalog_append_result.catalog_event_id
            != first.catalog_append_result.catalog_event_id
        )
        assert (
            third.catalog_append_result.source_sha256 == first.catalog_append_result.source_sha256
        )
        inventory = session.scalars(select(AdvisoryCatalogInventoryRecord)).one()
        assert (
            inventory.inventory_event_id,
            inventory.catalog_event_id,
            inventory.record_hash,
        ) == before
        assert count(session, AdvisoryCatalogRecord) == 3
    assert not store.pending_manifest()


@pytest.mark.parametrize("returned", ["older", "newer"])
def test_historical_revisit_after_update_is_quarantined_and_never_certified(
    database, tmp_path, returned
):
    original = advisory()
    newer = deepcopy(original)
    newer["updated_at"] = "2026-08-05T11:30:00Z"
    newer["vulnerabilities"][0]["package"]["name"] = "newer-package"
    document = original if returned == "older" else newer
    instance, store = collector(tmp_path, lambda request: response(request, [document]))
    # Seed the retained inventory through the actual governed historical caller.
    # The page run below exercises a revisit; no timestamps or rows are rewritten.
    with Session(database.engine) as session, session.begin():
        ingest(instance, session, original, lane="historical")
        before = session.scalars(select(AdvisoryCatalogInventoryRecord)).one().record_hash
    with Session(database.engine) as session, session.begin():
        ingest(instance, session, newer, lane="updates", seconds=1)
    with Session(database.engine) as session, session.begin():
        result = instance.run(session, lane="historical")
        assert result.state == "failed" and result.has_scope_gap
        assert result.page_processed and result.page_source_record_count == 1
        assert unresolved_count(session, source_id=GITHUB_ADVISORY, segment="reviewed") == 1
        assert actionable_quarantine_count(session, source_id=GITHUB_ADVISORY) == 1
        assert count(session, CollectionRecordMembership) == 1
        outcome = session.scalars(select(CollectionRecordOutcome)).one()
        assert outcome.disposition == "quarantined"
        expected = (
            "github_advisory_stale_revision"
            if returned == "older"
            else "invalid_github_advisory_envelope_ghsa_2345_6789_cfgh"
        )
        assert outcome.document["quarantine_reasons"] == [expected]
        assert count(session, AdvisoryCatalogManifestRecord) == 0
        assert session.scalars(select(AdvisoryCatalogInventoryRecord)).one().record_hash == before
        assert count(session, AdvisoryCatalogRecord) == 2
    assert not store.pending_manifest()


def test_same_timestamp_changed_content_still_refuses_membership_relink(database, tmp_path):
    original = advisory()
    changed = deepcopy(original)
    changed["vulnerabilities"][0]["package"]["name"] = "changed-package"
    instance, _store = collector(tmp_path, lambda request: response(request, []))
    with Session(database.engine) as session, session.begin():
        ingest(instance, session, original, lane="historical")
        changed_result = ingest(instance, session, changed, lane="updates", seconds=1)
        with pytest.raises(AdvisoryCatalogError, match="membership changed"):
            append_github_inventory_membership(
                session,
                segment="reviewed",
                source_snapshot=timestamp(NOW),
                upstream_record_id=original["ghsa_id"],
                appended=changed_result.catalog_append_result,
                observed_at=NOW,
            )
        assert count(session, AdvisoryCatalogInventoryRecord) == 1
