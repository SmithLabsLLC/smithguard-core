"""Neutral status survives revoked authority and never changes source facts."""

from copy import deepcopy
from datetime import timedelta

from sqlalchemy.orm import Session

from smithguard import bulletin_runtime as runtime
from smithguard import bulletin_store as store
from smithguard.source_rights import SourceProfile
from tests.test_bulletins import GRANT, NOW, REGISTRY, content, publish


def test_missing_grant_pauses_and_events_survive(database):
    def missing(**kw):
        raise FileNotFoundError()

    with Session(database.engine) as session, session.begin():
        record = publish(session)
        result = runtime.status_tick(session, registry=REGISTRY, grant_reader=missing, now=NOW)
        assert result["mode"] == "paused"
        current = store.detail(session, record["bulletin_id"], now=NOW)
        assert current["freshness"] == "paused"
        assert current["content"] == content()
        assert store.events(session, now=NOW)["items"][-1]["kind"] == "freshness_stale"
        assert (
            runtime.status_tick(session, registry=REGISTRY, grant_reader=missing, now=NOW)[
                "changed"
            ]
            == 0
        )


def test_due_review_stales_and_revocation_purges_all_versions(database):
    profile = REGISTRY.get(content()["sources"][0]["source_id"])
    source = deepcopy(profile.source)

    class Registry:
        def get(self, identity):
            assert identity == profile.source_id
            return SourceProfile(profile.activation, source, profile.field_rules)

    with Session(database.engine) as session, session.begin():
        record = publish(session)
        revised = content()
        revised["summary"] = "Another synthetic version."
        publish(session, revised, approval=2)
        source["rights"]["review_due_on"] = "2026-10-20"
        result = runtime.status_tick(
            session, registry=Registry(), grant_reader=lambda **kw: GRANT, now=NOW
        )
        assert result["changed"] == 1
        assert (
            store.detail(session, record["bulletin_id"], now=NOW)["freshness_reason"]
            == "rights_review_due"
        )
        source["rights"]["decision"] = "approved_internal"
        runtime.status_tick(session, registry=Registry(), grant_reader=lambda **kw: GRANT, now=NOW)
        for revision in (1, 2):
            current = store.detail(session, record["bulletin_id"], now=NOW, revision=revision)
            assert current["tombstoned"] and current["content"] is None
        assert store.events(session, now=NOW)["items"][-1]["kind"] == "public_purged"


def test_worker_outage_marks_stream_unavailable_and_deadline_stale(database):
    with Session(database.engine) as session, session.begin():
        record = publish(session)
        runtime.status_tick(session, registry=REGISTRY, grant_reader=lambda **kw: GRANT, now=NOW)
        assert store.stream_status(session, now=NOW)["available"]
        assert not store.stream_status(session, now=NOW + timedelta(minutes=6))["available"]
        assert (
            store.detail(session, record["bulletin_id"], now=NOW + timedelta(days=1))["freshness"]
            == "stale"
        )


def test_health_reports_worker_outage_and_paused_mode_without_private_read(database):
    from smithguard.bulletin_intake_status import health
    from smithguard.db.bulletin_models import BulletinStream

    with Session(database.engine) as session, session.begin():
        assert health(session, now=NOW) == "paused"
        publish(session)
        runtime.status_tick(session, registry=REGISTRY, grant_reader=lambda **kw: GRANT, now=NOW)
        assert health(session, now=NOW) == "fresh"
        assert health(session, now=NOW + timedelta(minutes=6)) == "unavailable"
        session.get(BulletinStream, "v1").mode = "paused"
        assert health(session, now=NOW + timedelta(minutes=6)) == "publication_paused"


def test_field_revocation_removes_historical_content_even_if_new_revision_omits_it(database):
    profile = REGISTRY.get(content()["sources"][0]["source_id"])

    class Registry:
        def get(self, identity):
            rules = deepcopy(profile.field_rules)
            for rule in rules:
                if "ghsa_id" in rule["fields"]:
                    rule["fields"] = [f for f in rule["fields"] if f != "ghsa_id"]
            return SourceProfile(profile.activation, profile.source, rules)

    with Session(database.engine) as session, session.begin():
        record = publish(session)
        changed = content()
        changed["sources"][0]["used_fields"] = ["vulnerabilities.package"]
        publish(session, changed, approval=2)
        runtime.status_tick(session, registry=Registry(), grant_reader=lambda **kw: GRANT, now=NOW)
        assert store.detail(session, record["bulletin_id"], now=NOW)["tombstoned"]
        assert store.detail(session, record["bulletin_id"], revision=1, now=NOW)["content"] is None
