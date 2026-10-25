"""The existing product can read exact assessments without broadening other routes."""

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse

from smithguard import api
from tests.api_client import coverage_runtime
from tests.test_service_api import _public_client

QUERY = {"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"}
ORIGIN = "https://smithguard.io"


@pytest.mark.parametrize(
    "origin",
    [
        ORIGIN,
        "https://evil.example",
        "null",
        "https://www.smithguard.io",
        "https://smithguard.io.evil.example",
        None,
    ],
)
def test_only_exact_product_origin_can_read_assessment(database, origin):
    with _public_client(database) as client:
        response = client.get(
            "/v1/artifacts/assess", params=QUERY, headers={"Origin": origin} if origin else {}
        )
    assert response.status_code == 200
    assert response.json()["artifact"]["name"] == QUERY["name"]
    assert response.headers.get("access-control-allow-origin") == (
        ORIGIN if origin == ORIGIN else None
    )
    assert response.headers["vary"] == "Origin"
    assert "access-control-allow-credentials" not in response.headers
    assert "access-control-allow-methods" not in response.headers


def test_validation_error_remains_readable_without_echoing_private_inputs(database):
    with _public_client(database) as client:
        response = client.get(
            "/v1/artifacts/assess",
            params={**QUERY, "private_inventory": "private-decoy"},
            headers={"Origin": ORIGIN},
        )
    assert response.status_code == 400
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert "private-decoy" not in response.text


@pytest.mark.parametrize("status", [429, 503])
def test_quota_and_capacity_responses_remain_readable(database, monkeypatch, status):
    async def refused(_self, _request: Request):
        return JSONResponse(
            {"error": {"code": "synthetic_limit"}},
            status_code=status,
            headers={"Retry-After": "60"},
        )

    monkeypatch.setattr(api._PublicAssessmentRuntime, "assess_public_artifact_by_query", refused)
    with _public_client(database) as client:
        response = client.get("/v1/artifacts/assess", params=QUERY, headers={"Origin": ORIGIN})
    assert response.status_code == status
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.headers["retry-after"] == "60"


def test_outer_unexpected_error_is_readable_but_not_leaked(database, monkeypatch):
    async def failed(_self, _request: Request):
        raise RuntimeError("private diagnostic must not be exposed")

    monkeypatch.setattr(api._PublicAssessmentRuntime, "assess_public_artifact_by_query", failed)
    with _public_client(database, raise_server_exceptions=False) as client:
        response = client.get("/v1/artifacts/assess", params=QUERY, headers={"Origin": ORIGIN})
    assert response.status_code == 503
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert "private diagnostic" not in response.text


def test_startup_failure_keeps_browser_error_readable(database):
    with _public_client(database) as client:
        coverage_runtime(client.app).coverage_ready.clear()
        response = client.get("/v1/artifacts/assess", params=QUERY, headers={"Origin": ORIGIN})
    assert response.status_code == 503
    assert response.headers["access-control-allow-origin"] == ORIGIN


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/v1/artifacts/assess"),
        ("HEAD", "/v1/artifacts/assess"),
        ("OPTIONS", "/v1/artifacts/assess"),
        ("GET", "/v1/coverage.json"),
        ("GET", "/openapi.json"),
        ("GET", "/mcp"),
        ("GET", "/v1/artifacts/assess/"),
    ],
)
def test_other_methods_and_routes_gain_no_browser_permission(database, method, path):
    with _public_client(database) as client:
        response = client.request(
            method, path, json=QUERY if method == "POST" else None, headers={"Origin": ORIGIN}
        )
    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-credentials" not in response.headers
