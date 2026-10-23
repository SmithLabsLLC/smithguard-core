"""Regression proof for the approved API-12 unpublished-surface removal."""

from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from sqlalchemy import inspect
from sqlalchemy.orm import sessionmaker

from smithguard.anonymous_quota import AnonymousQuotaStore
from smithguard.api import PUBLIC_BETA_ROUTE_ALLOWLIST, create_public_beta_app
from smithguard.contracts.runtime import CONTRACT_MODEL_NAMES
from smithguard.db.base import PRIVATE_WATCHLISTS_SCHEMA_NAME
from smithguard.db.inventory import EXPECTED_PRIVATE_WATCHLISTS_TABLES
from smithguard.feeds import SnapshotSigner
from tests.api_client import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
REMOVED_SOURCE_PATHS = (
    "src/smithguard/delivery.py",
    "src/smithguard/delivery_adapters.py",
    "src/smithguard/webhooks.py",
    "src/smithguard/private_watchlists.py",
    "src/smithguard/db/private_watchlists_models.py",
)
REMOVED_GENERATED_PATHS = (
    "src/smithguard/generated_artifacts/openapi.json",
    "src/smithguard/generated_artifacts/openapi-local-unpublished.json",
    "src/smithguard/generated_artifacts/openapi-private-watchlists-disabled.json",
    "src/smithguard/generated_artifacts/schemas/DeliveryEvent.schema.json",
    "src/smithguard/generated_artifacts/schemas/PrivateWatchlistSet.schema.json",
    "src/smithguard/generated_artifacts/schemas/PrivateWatchlistRejection.schema.json",
)


def _public_app(database, *, snapshot_archive=None):
    return create_public_beta_app(
        session_factory=sessionmaker(database.engine),
        signer=SnapshotSigner.ephemeral(),
        base_url="https://security.example",
        snapshot_archive=snapshot_archive,
        anonymous_quota_store=AnonymousQuotaStore(),
        anonymous_quota_secret=b"synthetic-api12-quota-secret-value",
    )


@pytest.mark.audit_ids("API-12")
def test_api12_removed_source_contract_and_generated_surfaces_stay_absent(database) -> None:
    assert not [path for path in REMOVED_SOURCE_PATHS if (REPO_ROOT / path).exists()]
    assert not [path for path in REMOVED_GENERATED_PATHS if (REPO_ROOT / path).exists()]
    assert {
        "DeliveryEvent",
        "PrivateWatchlistSet",
        "PrivateWatchlistRejection",
    }.isdisjoint(CONTRACT_MODEL_NAMES)

    app = _public_app(database)
    assert {
        (method, route.path)
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in route.methods
    } == PUBLIC_BETA_ROUTE_ALLOWLIST


@pytest.mark.audit_ids("API-12")
def test_api12_runtime_entry_points_stay_removed() -> None:
    api_source = (REPO_ROOT / "src/smithguard/api.py").read_text(encoding="utf-8")
    service_source = (REPO_ROOT / "src/smithguard/service.py").read_text(encoding="utf-8")
    feeds_source = (REPO_ROOT / "src/smithguard/feeds.py").read_text(encoding="utf-8")
    runtime_source = (REPO_ROOT / "src/smithguard/runtime.py").read_text(encoding="utf-8")

    for name in ("create_app", "create_local_unpublished_app", "_LocalSnapshotCache"):
        assert name not in api_source
    for name in (
        "CursorCodec",
        "def list_incidents(",
        "def list_delivery_events(",
        "def list_preliminary_warnings(",
        "def get_preliminary_warning(",
        "def list_incident_changes(",
        "def get_recommended_actions(",
    ):
        assert name not in service_source
    for name in ("def create_signed_snapshot(", "def render_json_feed(", "def render_atom("):
        assert name not in feeds_source
    assert "cursor_secret" not in runtime_source


@pytest.mark.audit_ids("API-12")
def test_api12_preserves_historical_database_tables_and_migrations(database) -> None:
    main_tables = set(inspect(database.engine).get_table_names(schema="smithguard"))
    private_tables = set(
        inspect(database.engine).get_table_names(schema=PRIVATE_WATCHLISTS_SCHEMA_NAME)
    )
    # The empty delivery and webhook tables were dropped by 0030 (owner decision,
    # September 24, 2026); the snapshot manifests keep their historical rows.
    assert (
        not {
            "delivery_events",
            "delivery_destinations",
            "delivery_attempts",
            "webhook_receipts",
        }
        & main_tables
    )
    assert "snapshot_manifests" in main_tables
    assert set(EXPECTED_PRIVATE_WATCHLISTS_TABLES) == private_tables
    assert len(tuple((REPO_ROOT / "migrations/versions").glob("*.py"))) > 1


@pytest.mark.audit_ids("DATA-02")
def test_public_core_routes_do_not_touch_the_historical_snapshot_archive(
    database,
    contract_examples,
) -> None:
    class ForbiddenArchive:
        touched: list[str] = []

        def public_key_document(self, public_key_id: str):
            self.touched.append(public_key_id)
            return None

    archive = ForbiddenArchive()
    with TestClient(
        _public_app(database, snapshot_archive=archive),
        base_url="https://security.example",
    ) as client:
        assert client.get("/").status_code == 200
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code in {200, 503}
        assert client.get("/v1/coverage.json").status_code == 200
        assert client.get("/v1/public-key.json").status_code == 200
        assert client.get("/openapi.json").status_code == 200
        request = deepcopy(
            next(
                item["value"]
                for item in contract_examples
                if item["definition"] == "PublicArtifactAssessmentRequest"
            )
        )
        assert client.post("/v1/artifacts/assess", json=request).status_code in {200, 503}
        assert archive.touched == []

        archived_key = "gbsec:snapshot-public-key:" + "0" * 40
        response = client.get(f"/v1/public-keys/{archived_key}.json")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"
        assert archive.touched == [archived_key]
