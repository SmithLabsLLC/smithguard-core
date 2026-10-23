"""Metadata-only publications keep evidence history without claiming changed facts."""

from copy import deepcopy
from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from smithguard import bulletin_store as store
from smithguard.bulletin_comparison import COMPARISON_VERSION, comparison, factual_hash
from smithguard.db.bulletin_models import BulletinDecision
from smithguard.identifiers import parse_timestamp

from .test_bulletins import NOW, content, publish


def test_comparison_ignores_only_acquisition_hash_and_modified_date():
    before = content()
    changed = deepcopy(before)
    changed["source_modified_at"] = "2026-10-21T11:00:00Z"
    changed["sources"][0]["source_evidence_hash"] = "sha256:" + "c" * 64
    assert factual_hash(before) == factual_hash(changed)
    assert before == content()  # Comparison never mutates the committed evidence.
    assert comparison(before, changed)["version"] == COMPARISON_VERSION


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("aliases", ["CVE-2026-12345"]),
        ("subjects", ["Another product"]),
        ("summary", "Changed reported facts."),
        ("conditions", ["Only affected when this feature is enabled."]),
        ("guidance", ["Upgrade to the source-listed fixed release."]),
        ("unknowns", ["A different evidence gap."]),
        ("source_published_at", "2026-10-20T10:00:00Z"),
        ("time_precision", "day"),
        ("severity", "high"),
        ("exploitation", "source_reports_exploitation"),
        ("remediation", "vendor_fix_available"),
        ("verification", "independently_corroborated"),
        ("lifecycle", "withdrawn"),
        ("future_claim", "A future field is never silently ignored."),
    ],
)
def test_actual_or_unknown_claim_changes_are_never_metadata_only(field, value):
    before = content()
    changed = deepcopy(before)
    changed[field] = value
    assert factual_hash(before) != factual_hash(changed)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_id", "gbsec:source:other"),
        ("record_url", "https://example.com/other"),
        ("rights_revision", 99),
        ("attribution", "Another publisher"),
        ("used_fields", ["other"]),
    ],
)
def test_changed_provenance_identity_is_conservatively_substantive(field, value):
    before = content()
    changed = deepcopy(before)
    changed["sources"][0][field] = value
    assert factual_hash(before) != factual_hash(changed)


def test_source_update_retains_revision_chain_and_checked_freshness(database):
    with Session(database.engine) as session, session.begin():
        initial = publish(session)
        changed = content()
        changed["sources"][0]["source_evidence_hash"] = "sha256:" + "c" * 64
        changed["source_modified_at"] = "2026-10-21T11:00:00Z"
        later = NOW + timedelta(minutes=5)
        updated = publish(session, changed, approval=2, now=later)
        store.status_tick(session, now=later)
        assert updated["revision"] == 2
        old = store.detail(session, initial["bulletin_id"], revision=1, now=later)
        new = store.detail(session, initial["bulletin_id"], now=later)
        assert old["content"] == content()
        assert new["content"] == changed
        assert new["predecessor_hash"] == old["content_hash"]
        assert new["content_hash"] != old["content_hash"]
        assert [v["kind"] for v in store.events(session, now=later)["items"]] == [
            "published",
            "source_updated",
        ]
        decision = session.get(BulletinDecision, new["publication_decision_id"])
        assert decision.document["factual_comparison"] == comparison(content(), changed)
        assert parse_timestamp(new["verified_at"]) == later


@pytest.mark.parametrize("lifecycle", ["disputed", "withdrawn", "expired"])
def test_special_lifecycle_events_keep_their_meaning(database, lifecycle):
    with Session(database.engine) as session, session.begin():
        publish(session)
        changed = content()
        changed["lifecycle"] = lifecycle
        publish(session, changed, approval=2)
        store.status_tick(session, now=NOW)
        assert store.events(session, now=NOW)["items"][-1]["kind"] == lifecycle
