"""Ambiguous tags and digest combinations cannot conceal retained version evidence."""

from copy import deepcopy

import pytest
from sqlalchemy.orm import Session

from smithguard.service import ServiceError, SmithGuardService, VersionNotExact
from tests.test_hosted_mcp import call
from tests.test_hosted_mcp import mcp_client as mcp_client  # noqa: F401
from tests.test_service_api import _append_api_legacy_match, _example, _public_client

DIGEST = "sha256:" + "a" * 64


@pytest.mark.parametrize("ecosystem", ["npm", "pypi", "github-actions", "go", "rust", "git"])
def test_non_container_version_and_digest_are_rejected_before_database_work(ecosystem):
    service = SmithGuardService()
    with pytest.raises(ServiceError, match="supply version or digest, not both"):
        service.validate_public_artifact_request(
            {"ecosystem": ecosystem, "name": "example", "version": "1.2.3", "digest": DIGEST}
        )


@pytest.mark.parametrize(
    "ecosystem,version",
    [
        ("github-actions", "v4"),
        ("github-actions", "v4.1"),
        ("github-actions", "abcdef1"),
        ("github-actions", "feature-branch"),
        ("docker", "1.0"),
        ("docker", "alpine"),
        ("oci", "2026-11-01"),
        ("oci", "release-1"),
    ],
)
def test_short_or_arbitrary_tags_are_not_exact(ecosystem, version):
    with pytest.raises(VersionNotExact):
        SmithGuardService().validate_public_artifact_request(
            {
                "ecosystem": ecosystem,
                "name": "example/project",
                "registry_host": "github.com" if ecosystem == "github-actions" else "ghcr.io",
                "version": version,
                **({"digest": DIGEST} if ecosystem in {"docker", "oci"} else {}),
            }
        )


@pytest.mark.parametrize(
    "coordinate",
    [
        {"ecosystem": "github-actions", "version": "v4.1.2"},
        {"ecosystem": "github-actions", "version": "ab" * 20},
        {"ecosystem": "docker", "digest": DIGEST, "registry_host": "docker.io"},
        {"ecosystem": "oci", "version": "1.2.3", "digest": DIGEST, "registry_host": "ghcr.io"},
        {
            "ecosystem": "docker",
            "digest": DIGEST,
            "version": "1.2.3-alpine",
            "registry_host": "docker.io",
        },
    ],
)
def test_full_release_commit_and_container_digest_forms_remain_supported(coordinate):
    _, identity = SmithGuardService().validate_public_artifact_request(
        {"name": "example/project", **coordinate}
    )
    assert identity["version"] == coordinate.get("version")
    assert identity["digest"] == coordinate.get("digest")


def test_legacy_affected_version_cannot_be_hidden_by_a_digest(database, contract_examples):
    with Session(database.engine) as session, session.begin():
        incident_id = _append_api_legacy_match(session, contract_examples, status="confirmed")
    request = _example(contract_examples, "PublicArtifactAssessmentRequest")
    with _public_client(database) as client:
        baseline = client.post("/v1/artifacts/assess", json=request)
        assert baseline.status_code == 200
        assert baseline.json()["result"] == "affected"
        assert baseline.json()["incident_ids"] == [incident_id]
        ambiguous = deepcopy(request)
        ambiguous["artifact"]["digest"] = DIGEST
        coordinate = {
            key: ambiguous["artifact"][key] for key in ("ecosystem", "name", "version", "digest")
        }
        for response in (
            client.post("/v1/artifacts/assess", json=ambiguous),
            client.post("/v1/artifacts/assess", json=coordinate),
            client.get("/v1/artifacts/assess", params=coordinate),
        ):
            assert response.status_code == 400
            assert response.json()["error"]["code"] == "invalid_request"
            assert "supply version or digest, not both" in response.text


@pytest.mark.parametrize(
    "coordinate,code",
    [
        (
            {"ecosystem": "npm", "name": "event-stream", "version": "3.3.6", "digest": DIGEST},
            "invalid_request",
        ),
        (
            {"ecosystem": "github-actions", "name": "actions/checkout", "version": "v4"},
            "version_not_exact",
        ),
        (
            {
                "ecosystem": "docker",
                "name": "library/alpine",
                "version": "1.0",
                "digest": DIGEST,
                "registry_host": "docker.io",
            },
            "version_not_exact",
        ),
    ],
)
def test_get_post_and_hosted_mcp_share_coordinate_rejection(mcp_client, coordinate, code):
    responses = [
        mcp_client.get("/v1/artifacts/assess", params=coordinate),
        mcp_client.post("/v1/artifacts/assess", json=coordinate),
    ]
    assert all(r.status_code == 400 and r.json()["error"]["code"] == code for r in responses)
    response = call(mcp_client, "assess_public_artifact", coordinate, modern=True)
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["isError"]
    assert code in str(result)
