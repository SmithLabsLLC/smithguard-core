"""Public JSON, Atom and hosted MCP agree on revocation and current status."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event
from xml.etree import ElementTree

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from sqlalchemy.orm import Session, sessionmaker

from smithguard import api
from smithguard import bulletin_store as store
from smithguard.anonymous_quota import AnonymousQuotaStore
from smithguard.bulletin_contract import BulletinError
from smithguard.feeds import SnapshotSigner
from tests.api_client import TestClient, coverage_runtime
from tests.test_bulletins import NOW, content, publish
from tests.test_hosted_mcp import call
from tests.test_service_api import _example


@pytest.fixture
def bulletin_client(database):
    time = [NOW]
    app = api.create_public_beta_app(
        session_factory=sessionmaker(database.engine),
        signer=SnapshotSigner.ephemeral(),
        base_url="https://api.smithguard.io",
        clock=lambda: time[0],
        anonymous_quota_store=AnonymousQuotaStore(),
        anonymous_quota_secret=b"synthetic-public-quota-secret!!!",
    )
    with TestClient(app, base_url="https://api.smithguard.io", client=("8.8.8.8", 50000)) as client:
        yield client, time


def test_every_public_surface_purges_content(database, bulletin_client):
    client, _clock = bulletin_client
    doc = content()
    doc["summary"] = "Synthetic unique content <script> never execute & never retained publicly."
    with Session(database.engine) as session, session.begin():
        record = publish(session, doc)
        store.status_tick(session, now=NOW)
    identity = record["bulletin_id"]
    routes = [
        "/v1/bulletins.json",
        f"/v1/bulletins/{identity}.json",
        f"/v1/bulletins/{identity}.json?revision=1",
        "/v1/bulletins.atom",
    ]
    previous_etags = {}
    for route in routes:
        response = client.get(route)
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["access-control-allow-origin"] == "https://smithguard.io"
        assert "access-control-allow-credentials" not in response.headers
        assert "Synthetic unique content" in response.text
        previous_etags[route] = response.headers["etag"]
        repeated = client.get(route, headers={"If-None-Match": response.headers["etag"]})
        assert repeated.status_code == 304
    tree = ElementTree.fromstring(client.get("/v1/bulletins.atom").content)
    assert tree.find("{http://www.w3.org/2005/Atom}entry") is not None
    assert b"<script>" not in client.get("/v1/bulletins.atom").content
    with Session(database.engine) as session, session.begin():
        store.tombstone(session, identity, now=NOW)
    for route in routes:
        response = client.get(route, headers={"If-None-Match": previous_etags[route]})
        assert response.status_code == 200
        assert "Synthetic unique content" not in response.text
        assert "<script>" not in response.text
    for tool, arguments in [
        ("list_bulletins", {}),
        ("get_bulletin", {"identity": identity}),
        ("get_bulletin", {"identity": identity, "revision": 1}),
        ("get_bulletin_changes", {}),
        ("get_bulletin_status", {}),
    ]:
        response = call(
            client, tool, arguments, headers={"Accept": "application/json, text/event-stream"}
        )
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        assert not response.json()["result"]["isError"], response.text
        assert "Synthetic unique content" not in response.text


@pytest.mark.parametrize("cve", [False, True])
def test_date_only_renewal_preserves_old_corrected_and_removed_public_versions(
    database, bulletin_client, cve
):
    from copy import deepcopy

    from smithguard.bulletin_policy import publication_rights
    from smithguard.bulletin_runtime import status_tick
    from smithguard.source_rights import RightsRegistry
    from tests.test_bulletin_licenses import cve_content
    from tests.test_bulletins import GRANT, REGISTRY
    from tests.test_source_rights import renewed_register

    client, clock = bulletin_client
    original = cve_content() if cve else content()
    with Session(database.engine) as session, session.begin():
        record = store.publish(
            session,
            original,
            registry=REGISTRY,
            grant=GRANT,
            now=NOW,
            manual_approval="a" * 64,
        )
        corrected = deepcopy(original)
        corrected["summary"] = "Corrected synthetic renewal evidence."
        store.publish(
            session,
            corrected,
            registry=REGISTRY,
            grant=GRANT,
            now=NOW,
            manual_approval="b" * 64,
        )
        identity = record["bulletin_id"]
        before = [store.detail(session, identity, revision=r, now=NOW) for r in (1, 2)]
    register = renewed_register(original["sources"][0]["source_id"])
    registry = RightsRegistry(register)
    without_renewal = deepcopy(register)
    del without_renewal["publication_renewals"]
    now = NOW + timedelta(days=3)
    clock[0] = now
    with Session(database.engine) as session, session.begin():
        with pytest.raises(BulletinError, match="bulletin_rights_not_current"):
            store.verify_unchanged(
                session,
                identity,
                content_hash=before[1]["content_hash"],
                registry=RightsRegistry(without_renewal),
                grant=GRANT,
                now=now,
                manual_approval="c" * 64,
            )
        for document in (original, corrected):
            publication_rights(document, registry, now=now)
        store.verify_unchanged(
            session,
            identity,
            content_hash=before[1]["content_hash"],
            registry=registry,
            grant=GRANT,
            now=now,
            manual_approval="c" * 64,
        )
        status_tick(session, registry=registry, grant_reader=lambda **kw: GRANT, now=now)
        for r in (1, 2):
            after = store.detail(session, identity, revision=r, now=now)
            for key in ("content", "content_hash", "sequence", "publication_decision_id"):
                assert after[key] == before[r - 1][key]

    routes = [
        "/v1/bulletins.json",
        f"/v1/bulletins/{identity}.json",
        f"/v1/bulletins/{identity}.json?revision=1",
        "/v1/bulletin-events.json",
        "/v1/bulletins.atom",
    ]
    for route in routes:
        response = client.get(route)
        assert response.status_code == 200, response.text
        assert identity in response.text
    for tool, arguments in [
        ("list_bulletins", {}),
        ("get_bulletin", {"identity": identity}),
        ("get_bulletin", {"identity": identity, "revision": 1}),
        ("get_bulletin_changes", {}),
    ]:
        response = call(client, tool, arguments)
        assert response.status_code == 200, response.text
        assert not response.json()["result"]["isError"], response.text
        assert identity in response.text
    with Session(database.engine) as session, session.begin():
        store.tombstone(session, identity, now=now)
        status_tick(session, registry=registry, grant_reader=lambda **kw: GRANT, now=now)
    for route in routes:
        response = client.get(route)
        assert response.status_code == 200, response.text
        assert original["summary"] not in response.text
        assert corrected["summary"] not in response.text
    for tool, arguments in [
        ("list_bulletins", {}),
        ("get_bulletin", {"identity": identity}),
        ("get_bulletin", {"identity": identity, "revision": 1}),
        ("get_bulletin_changes", {}),
    ]:
        response = call(client, tool, arguments)
        assert not response.json()["result"]["isError"], response.text
        assert original["summary"] not in response.text
        assert corrected["summary"] not in response.text


def test_generated_schema_matches_bulletin_routes(database, bulletin_client):
    client, _clock = bulletin_client
    with Session(database.engine) as session, session.begin():
        record = publish(session)
        store.status_tick(session, now=NOW)
    schemas = client.app.openapi()["components"]["schemas"]
    for path, schema in [
        ("/v1/bulletins.json", "BulletinPage"),
        (f"/v1/bulletins/{record['bulletin_id']}.json", "BulletinRecord"),
        ("/v1/bulletin-events.json", "BulletinEventPage"),
        ("/v1/bulletin-status.json", "BulletinStatus"),
    ]:
        response = client.get(path)
        assert response.status_code == 200, response.text
        Draft202012Validator(schemas[schema], format_checker=FormatChecker()).validate(
            response.json()
        )


def test_newest_bulletins_rest_and_mcp_have_identical_order(database, bulletin_client):
    client, _clock = bulletin_client
    with Session(database.engine) as session, session.begin():
        for i in range(4):
            document = content(i)
            document["source_published_at"] = store.timestamp(NOW - timedelta(days=4 - i))
            publish(session, document, approval=i + 1)
        store.status_tick(session, now=NOW)
    response = client.get("/v1/bulletins.json?order=newest&limit=2")
    assert response.status_code == 200, response.text
    page = response.json()
    dates = [r["content"]["source_published_at"] for r in page["items"]]
    assert dates == sorted(dates, reverse=True)
    response = call(client, "list_bulletins", {"order": "newest", "limit": 2})
    assert response.status_code == 200, response.text
    assert response.json()["result"]["structuredContent"]["data"] == page
    cursor = page["next_cursor"]
    response = client.get("/v1/bulletins.json", params={"order": "newest", "cursor": cursor})
    assert response.status_code == 200, response.text
    assert len(response.json()["items"]) == 2
    assert client.get("/v1/bulletins.json?order=invalid").status_code == 400


def test_worker_outage_stales_current_and_disables_changes(database, bulletin_client):
    client, clock = bulletin_client
    with Session(database.engine) as session, session.begin():
        record = publish(session)
        store.status_tick(session, now=NOW)
    clock[0] = NOW + timedelta(hours=24, minutes=6)
    assert client.get(f"/v1/bulletins/{record['bulletin_id']}.json").json()["freshness"] == "stale"
    assert client.get("/v1/bulletins.json").json()["changes_cursor"] is None
    for route in ("/v1/bulletin-events.json", "/v1/bulletins.atom"):
        response = client.get(route)
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "bulletin_stream_unavailable"


@pytest.mark.parametrize(
    "path",
    [
        "/v1/bulletins.json?limit=1&limit=2",
        "/v1/bulletins.json?unknown=1",
        "/v1/bulletin-events.json?cursor=invalid",
        "/v1/bulletin-status.json?private=1",
        "/v1/bulletins.atom?limit=0",
        "/v1/bulletins.json?evidence_class=confirmed_malware",
    ],
)
def test_invalid_bulletin_queries_fail_closed(database, bulletin_client, path):
    client, _clock = bulletin_client
    with Session(database.engine) as session, session.begin():
        store.status_tick(session, now=NOW)
    response = client.get(path)
    assert response.status_code == 400, response.text


def test_bulletin_overload_preserves_assessment_capacity(
    bulletin_client, monkeypatch, contract_examples
):
    client, _clock = bulletin_client
    runtime = coverage_runtime(client.app)
    runtime.max_bulletin_requests = 2
    entered = Barrier(3)
    release = Event()

    def blocked(*_args, **_kwargs):
        entered.wait(timeout=10)
        assert release.wait(timeout=10)
        return {"items": []}

    monkeypatch.setattr(store, "snapshot", blocked)
    with ThreadPoolExecutor(max_workers=2) as callers:
        pending = [callers.submit(client.get, "/v1/bulletins.json") for _ in range(2)]
        try:
            entered.wait(timeout=10)
            overloaded = client.get("/v1/bulletin-status.json")
            assert overloaded.status_code == 429
            assert overloaded.json()["error"]["code"] == "service_capacity_exceeded"
            assert overloaded.headers["retry-after"] == "1"
            assert overloaded.headers["cache-control"] == "no-store"
            assert overloaded.headers["access-control-allow-origin"] == "https://smithguard.io"
            assessment = client.post(
                "/v1/artifacts/assess",
                json=_example(contract_examples, "PublicArtifactAssessmentRequest"),
            )
            assert assessment.status_code == 200, assessment.text
        finally:
            release.set()
        assert all(result.result(timeout=10).status_code == 200 for result in pending)


def test_timed_out_bulletin_keeps_worker_slot(bulletin_client, monkeypatch):
    client, _clock = bulletin_client
    runtime = coverage_runtime(client.app)
    release = Event()
    calls = []

    def blocked(*_args, **_kwargs):
        calls.append(1)
        assert release.wait(timeout=10)
        return {"items": []}

    monkeypatch.setattr(store, "snapshot", blocked)
    monkeypatch.setattr(api, "PUBLIC_ASSESSMENT_TIMEOUT_SECONDS", 0.2)
    try:
        assert client.get("/v1/bulletins.json").status_code == 503
        assert client.get("/v1/bulletins.json").status_code == 503
        assert client.portal.call(runtime.bulletin_slots.locked)
        assert client.get("/v1/bulletins.json").status_code == 503
        assert len(calls) == 2
        assert client.portal.call(runtime.bulletin_slots.locked)
    finally:
        release.set()
