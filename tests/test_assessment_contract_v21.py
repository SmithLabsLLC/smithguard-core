"""Assessment contract 2.1: short and GET requests, exact versions, per-incident
applicability and fixes, source freshness, and signed answers."""

from __future__ import annotations

import base64
from copy import deepcopy
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session

from smithguard.advisory_catalog import append_github_advisory, append_openssf_advisory
from smithguard.feeds import SnapshotSigner
from smithguard.identifiers import canonical_json_bytes
from smithguard.service import require_exact_version
from tests.test_service_api import NOW, _append_catalog_families, _example, _public_client

SHORT = {"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"}


def _post(client, body: Any, *, address: int = 1):
    return client.post(
        "/v1/artifacts/assess", json=body, headers={"X-Forwarded-For": f"8.8.8.{address}"}
    )


def _get(client, params: Any, *, address: int = 1):
    return client.get(
        "/v1/artifacts/assess", params=params, headers={"X-Forwarded-For": f"8.8.4.{address}"}
    )


def test_short_post_and_get_forms_match_the_full_request(database, contract_examples) -> None:
    full = _example(contract_examples, "PublicArtifactAssessmentRequest")
    with Session(database.engine) as session, session.begin():
        _append_catalog_families(session, 1)
    with _public_client(database) as client:
        by_full = _post(client, full, address=1)
        by_short = _post(client, SHORT, address=2)
        by_query = _get(client, SHORT, address=3)
    for response in (by_full, by_short, by_query):
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
    short, query = by_short.json(), by_query.json()
    assert short["result"] == query["result"] == by_full.json()["result"] == "affected"
    assert short["artifact"] == {
        "ecosystem": "npm",
        "registry_host": "registry.npmjs.org",
        "name": "event-stream",
        "version": "3.3.6",
        "digest": None,
        "public_visibility": "asserted_public",
    }
    assert short["id"] == query["id"]
    assert short["feed_revision"] == by_full.json()["feed_revision"]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"ecosystem": "npm", "name": "a", "version": "1.0.0", "extra": "x"}, "unsupported"),
        ({"ecosystem": "npm", "version": "1.0.0"}, "name is required"),
        (
            {"ecosystem": "oci", "name": "library/nginx", "digest": "sha256:" + "a" * 64},
            "registry_host",
        ),
        ({"ecosystem": "npm", "name": "a", "version": 1}, "must be strings"),
        ({"ecosystem": "cobol", "name": "a", "version": "1"}, "not supported"),
    ],
)
def test_short_request_errors_are_specific(database, body, message) -> None:
    with _public_client(database) as client:
        response = _post(client, body)
    assert response.status_code == 400
    assert message in response.json()["error"]["message"]


def test_query_form_rejects_unknown_and_repeated_parameters(database) -> None:
    with _public_client(database) as client:
        unknown = _get(client, {**SHORT, "limit": "5"}, address=1)
        repeated = client.get(
            "/v1/artifacts/assess?ecosystem=npm&name=a&name=b&version=1.0.0",
            headers={"X-Forwarded-For": "8.8.4.2"},
        )
    assert unknown.status_code == 400
    assert "unsupported query parameter" in unknown.json()["error"]["message"]
    assert repeated.status_code == 400
    assert "only once" in repeated.json()["error"]["message"]


@pytest.mark.parametrize(
    ("ecosystem", "version"),
    [
        ("npm", "latest"),
        ("npm", "^4.17.21"),
        ("npm", "1.x"),
        ("pypi", ">=2.0"),
        ("pypi", "2.*"),
        ("maven", "[1.0,2.0)"),
        ("maven", "LATEST"),
        ("go", "latest"),
        ("rubygems", "~> 2.0"),
        ("github-actions", "main"),
        ("npm", "1"),
        ("npm", "1.2"),
        ("composer", "dev-main"),
        ("composer", "1.x-dev"),
        ("maven", "1.0-SNAPSHOT"),
    ],
)
def test_ranges_and_floating_tags_are_not_exact_versions(database, ecosystem, version) -> None:
    with pytest.raises(ValueError, match="exact published version"):
        require_exact_version(ecosystem, version)


@pytest.mark.parametrize(
    ("ecosystem", "version"),
    [
        ("npm", "4.17.21"),
        ("pypi", "2.32.5"),
        ("maven", "2.14.1"),
        ("go", "v0.0.0-20210101000000-abcdef123456"),
        ("github-actions", "v45.0.7"),
        ("github-actions", "8f4b7f84864484a7bf31766abe9204da3cbe65b3"),
        ("rust", "1.0.0-alpha.1"),
        ("composer", "1.0.0-RC1"),
    ],
)
def test_exact_versions_and_commit_pins_are_accepted(ecosystem, version) -> None:
    require_exact_version(ecosystem, version)


def test_a_range_is_refused_with_its_own_error_code(database) -> None:
    with _public_client(database) as client:
        response = _post(client, {**SHORT, "version": "^3.3.0"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "version_not_exact"


def test_answers_are_signed_over_the_callers_own_document(database) -> None:
    signer = SnapshotSigner.ephemeral()
    with Session(database.engine) as session, session.begin():
        _append_catalog_families(session, 1)
    with _public_client(database, signer=signer) as client:
        key = client.get("/v1/public-key.json").json()
        first = _post(client, SHORT, address=1).json()
        cached = _post(client, {**SHORT, "registry_host": "registry.npmjs.org"}, address=2)
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(key["public_key_base64"]))
    for body in (first, cached.json()):
        signature = body["signature"]
        assert signature["algorithm"] == "Ed25519"
        assert signature["public_key_id"] == key["public_key_id"]
        assert signature["canonicalization"] == key["canonicalization"]
        unsigned = {name: value for name, value in body.items() if name != "signature"}
        public_key.verify(base64.b64decode(signature["value"]), canonical_json_bytes(unsigned))
    tampered = deepcopy(first)
    tampered["result"] = "not_affected"
    unsigned = {name: value for name, value in tampered.items() if name != "signature"}
    with pytest.raises(InvalidSignature):
        public_key.verify(
            base64.b64decode(first["signature"]["value"]), canonical_json_bytes(unsigned)
        )


def test_incidents_carry_applicability_fixes_aliases_and_upstream_links(database) -> None:
    with Session(database.engine) as session, session.begin():
        append_github_advisory(
            session,
            document={
                "ghsa_id": "GHSA-2345-6789-fgh2",
                "type": "reviewed",
                "published_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-02T00:00:00Z",
                "withdrawn_at": None,
                "html_url": "https://github.com/advisories/GHSA-2345-6789-fgh2",
                "cwes": [],
                "identifiers": [
                    {"type": "GHSA", "value": "GHSA-2345-6789-fgh2"},
                    {"type": "CVE", "value": "CVE-2023-0001"},
                ],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "npm", "name": "event-stream"},
                        "vulnerable_version_range": ">= 3.0.0, < 3.3.7",
                    }
                ],
            },
            evidence_id="gbsec:evidence:fix-range",
            governance_decision_id="gbsec:governance:fix-range",
            observed_at=NOW,
        )
        append_openssf_advisory(
            session,
            document={
                "id": "MAL-2026-77777",
                "published": "2026-08-30T00:00:00Z",
                "modified": "2026-08-31T00:00:00Z",
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "event-stream"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "3.3.6"}, {"fixed": "3.3.8"}],
                            }
                        ],
                    }
                ],
            },
            canonical_url="https://github.com/ossf/malicious-packages/blob/"
            "0123456789012345678901234567890123456789/osv/malicious/npm/event-stream/MAL-2026-77777.json",
            source_state="active",
            evidence_id="gbsec:evidence:fix-osv",
            governance_decision_id="gbsec:governance:fix-osv",
            observed_at=NOW,
        )
    with _public_client(database) as client:
        body = _post(client, SHORT).json()
    assert body["result"] == "affected"
    by_alias = {tuple(item["aliases"]): item for item in body["incidents"]}
    github = by_alias[("CVE-2023-0001", "GHSA-2345-6789-fgh2")]
    assert github["applies_to_version"] is True
    assert github["fixed_versions"] == ["3.3.7"]
    assert github["upstream_urls"] == ["https://github.com/advisories/GHSA-2345-6789-fgh2"]
    assert github["affected_range_ids"]
    openssf = by_alias[("MAL-2026-77777",)]
    assert openssf["fixed_versions"] == ["3.3.8"]
    assert openssf["applies_to_version"] is True


def test_stale_sources_are_named_in_the_answer(database) -> None:
    with _public_client(database) as client:
        body = _post(client, SHORT).json()
    kinds = {(item["source_id"], item["record_type"]) for item in body["source_freshness"]}
    assert ("gbsec:source:github-advisory-database", "malware_advisory") in kinds
    assert all(item["freshness_state"] != "fresh" for item in body["source_freshness"])
    assert any("recent reports may be missing" in value for value in body["unknowns"])
    assert any("not proof it is safe" in value for value in body["unknowns"])


def test_openapi_documents_the_short_get_form_and_server(database) -> None:
    with _public_client(database) as client:
        openapi = client.get("/openapi.json").json()
    assert openapi["servers"] == [{"url": "https://api.smithguard.io"}]
    get = openapi["paths"]["/v1/artifacts/assess"]["get"]
    assert {parameter["name"] for parameter in get["parameters"]} == {
        "ecosystem",
        "name",
        "version",
        "digest",
        "registry_host",
    }
    examples = openapi["paths"]["/v1/artifacts/assess"]["post"]["requestBody"]["content"][
        "application/json"
    ]["examples"]
    assert examples["npm"]["value"] == {
        "ecosystem": "npm",
        "name": "event-stream",
        "version": "3.3.6",
    }


def test_coverage_lanes_state_how_versions_are_compared(database) -> None:
    with _public_client(database) as client:
        lanes = {
            lane["ecosystem"]: lane for lane in client.get("/v1/coverage.json").json()["lanes"]
        }
    assert lanes["maven"]["version_range_evaluation"] == "ecosystem_rules"
    assert lanes["oci"]["version_range_evaluation"] == "digest_only"
    assert lanes["git"]["version_range_evaluation"] == "not_supported"


def test_retained_legacy_artifacts_match_equivalent_version_spellings(
    database, contract_examples
) -> None:
    """A retained Go artifact recorded as 3.3.6 is found for the request v3.3.6."""
    from tests.test_service_api import _append_api_legacy_match

    with Session(database.engine) as session, session.begin():
        incident_id = _append_api_legacy_match(
            session,
            contract_examples,
            ecosystem="go",
            name="example.com/module",
            status="confirmed",
        )
    with _public_client(database) as client:
        body = _post(
            client, {"ecosystem": "go", "name": "example.com/module", "version": "v3.3.6"}
        ).json()
    assert body["result"] == "affected"
    assert body["incident_ids"] == [incident_id]
    assert body["incidents"][0]["applies_to_version"] is True


@pytest.mark.parametrize("form", ["full", "short", "query"])
def test_every_request_form_refuses_an_npm_partial_version(database, contract_examples, form):
    full = _example(contract_examples, "PublicArtifactAssessmentRequest")
    full["artifact"]["version"] = "3.3"
    with _public_client(database) as client:
        if form == "full":
            response = _post(client, full)
        elif form == "short":
            response = _post(client, {**SHORT, "version": "3.3"})
        else:
            response = _get(client, {**SHORT, "version": "3.3"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "version_not_exact"


def test_maven_forms_outside_the_implemented_order_stay_possible(database) -> None:
    """Maven orders 1-1 below 1.1; that form is refused, so the answer is not
    'not affected' for a range that may include it."""
    with Session(database.engine) as session, session.begin():
        append_github_advisory(
            session,
            document={
                "ghsa_id": "GHSA-2345-6789-mvn2",
                "type": "reviewed",
                "published_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-02T00:00:00Z",
                "withdrawn_at": None,
                "html_url": "https://github.com/advisories/GHSA-2345-6789-mvn2",
                "cwes": [],
                "identifiers": [{"type": "GHSA", "value": "GHSA-2345-6789-mvn2"}],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "maven", "name": "org.example:lib"},
                        "vulnerable_version_range": "< 1.1",
                    }
                ],
            },
            evidence_id="gbsec:evidence:maven-form",
            governance_decision_id="gbsec:governance:maven-form",
            observed_at=NOW,
        )
    with _public_client(database) as client:
        body = _post(
            client, {"ecosystem": "maven", "name": "org.example:lib", "version": "1-1"}
        ).json()
    assert body["result"] == "possibly_affected"
    assert body["incidents"][0]["applies_to_version"] is None


@pytest.mark.parametrize(
    ("ecosystem", "stored", "requested"),
    [
        ("pypi", "1.0", "1.0.0+ubuntu1"),
        ("nuget", "1.0.0-beta1", "1.0.0-BETA1"),
        ("nuget", "1.0.0", "1.0.0+meta"),
        ("maven", "2.0", "2"),
        ("maven", "1-a1", "1.0-alpha1"),
    ],
)
def test_retained_artifacts_match_semantically_equal_versions(
    database, contract_examples, ecosystem, stored, requested
) -> None:
    from smithguard.db.repository import append_contract
    from smithguard.identifiers import stable_id
    from smithguard.normalization import normalize_artifact_identity
    from tests.test_service_api import _create_incident

    name = {"pypi": "example-dist", "nuget": "Example.Lib", "maven": "org.example:lib"}[ecosystem]
    artifact = _example(contract_examples, "Artifact")
    identity = normalize_artifact_identity(
        {"ecosystem": ecosystem, "name": name, "version": stored, "digest": None}
    )
    artifact.update(identity)
    artifact["id"] = stable_id("artifact", identity["coordinate"])
    claim = _example(contract_examples, "Claim")
    claim["subject_id"] = artifact["id"]
    affected_range = _example(contract_examples, "AffectedRange")
    affected_range.update(
        artifact_id=artifact["id"],
        range_type="EXACT",
        expression=f"= {stored}",
        introduced=stored,
        last_affected=stored,
    )
    with Session(database.engine) as session, session.begin():
        for definition, value in (
            ("Artifact", artifact),
            ("Claim", claim),
            ("AffectedRange", affected_range),
        ):
            append_contract(session, definition, value)
        incident = _create_incident(
            session,
            f"semantic-{ecosystem}",
            artifact_ids=(artifact["id"],),
            range_ids=(affected_range["id"],),
            claim_ids=(claim["id"],),
        )
    with _public_client(database) as client:
        body = _post(client, {"ecosystem": ecosystem, "name": name, "version": requested}).json()
    assert body["incident_ids"] == [incident["id"]], body.get("error")
    assert body["result"] == "affected"


def test_an_unsupported_spelling_never_reads_as_not_affected(database) -> None:
    """Maven compares qualifiers case-insensitively; an unimplemented qualifier that
    differs only in case from the advisory's is undecided, not excluded."""
    with Session(database.engine) as session, session.begin():
        append_github_advisory(
            session,
            document={
                "ghsa_id": "GHSA-2345-6789-mvn3",
                "type": "reviewed",
                "published_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-02T00:00:00Z",
                "withdrawn_at": None,
                "html_url": "https://github.com/advisories/GHSA-2345-6789-mvn3",
                "cwes": [],
                "identifiers": [{"type": "GHSA", "value": "GHSA-2345-6789-mvn3"}],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "maven", "name": "org.example:lib"},
                        "vulnerable_version_range": "= 1-FOO",
                    }
                ],
            },
            evidence_id="gbsec:evidence:maven-case",
            governance_decision_id="gbsec:governance:maven-case",
            observed_at=NOW,
        )
    with _public_client(database) as client:
        body = _post(
            client, {"ecosystem": "maven", "name": "org.example:lib", "version": "1-foo"}
        ).json()
    assert body["result"] == "possibly_affected"
    assert body["not_applicable_incident_count"] == 0
    assert body["incidents"][0]["applies_to_version"] is None


@pytest.mark.parametrize("form", ["full", "short", "query"])
@pytest.mark.parametrize(
    ("ecosystem", "name", "version"),
    [
        ("rust", "serde", "1.2"),
        ("go", "example.com/module", "1.2"),
        ("rust", "serde", "1.2.3-"),
        ("rust", "serde", "1.0.0-01"),
        ("rust", "serde", "01.2.3"),
        ("npm", "event-stream", "3.3.6+."),
        ("npm", "event-stream", "3.3.6+foo..bar"),
    ],
)
def test_partial_or_malformed_semver_versions_are_refused(
    database, contract_examples, form, ecosystem, name, version
):
    registry = {"rust": "crates.io", "go": "proxy.golang.org", "npm": "registry.npmjs.org"}[
        ecosystem
    ]
    full = _example(contract_examples, "PublicArtifactAssessmentRequest")
    full["artifact"].update(ecosystem=ecosystem, registry_host=registry, name=name, version=version)
    short = {"ecosystem": ecosystem, "name": name, "version": version}
    with _public_client(database) as client:
        if form == "full":
            response = _post(client, full)
        elif form == "short":
            response = _post(client, short)
        else:
            response = _get(client, short)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "version_not_exact"


def test_valid_pub_build_metadata_is_accepted_though_not_ordered(database) -> None:
    """pub orders by build metadata, which is not implemented: the version is still a
    valid exact request, and ranges over it stay undecided."""
    require_exact_version("pub", "1.0.0+1")


def test_an_oversized_retained_artifact_set_is_refused_not_truncated(
    database, contract_examples, monkeypatch
) -> None:
    import smithguard.query as query_module
    from tests.test_service_api import _append_api_legacy_match

    monkeypatch.setattr(query_module, "ARTIFACT_VERSION_SCAN_LIMIT", 0)
    with Session(database.engine) as session, session.begin():
        _append_api_legacy_match(session, contract_examples)
    with _public_client(database) as client:
        response = _post(client, SHORT)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_capacity_exceeded"


def test_composer_unnumbered_prerelease_is_inside_a_numbered_bound(database) -> None:
    with Session(database.engine) as session, session.begin():
        append_github_advisory(
            session,
            document={
                "ghsa_id": "GHSA-2345-6789-cmp2",
                "type": "reviewed",
                "published_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-02T00:00:00Z",
                "withdrawn_at": None,
                "html_url": "https://github.com/advisories/GHSA-2345-6789-cmp2",
                "cwes": [],
                "identifiers": [{"type": "GHSA", "value": "GHSA-2345-6789-cmp2"}],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "composer", "name": "vendor/lib"},
                        "vulnerable_version_range": "< 1.0.0-beta0",
                    }
                ],
            },
            evidence_id="gbsec:evidence:composer-beta",
            governance_decision_id="gbsec:governance:composer-beta",
            observed_at=NOW,
        )
    with _public_client(database) as client:
        body = _post(
            client, {"ecosystem": "composer", "name": "vendor/lib", "version": "1.0.0-beta"}
        ).json()
    assert body["result"] == "affected"
    assert body["incidents"][0]["applies_to_version"] is True


def test_valid_npm_build_metadata_is_accepted() -> None:
    require_exact_version("npm", "1.2.3+build.5")


def test_pypi_local_build_is_inside_its_public_versions_range(database) -> None:
    with Session(database.engine) as session, session.begin():
        append_github_advisory(
            session,
            document={
                "ghsa_id": "GHSA-2345-6789-pyp2",
                "type": "reviewed",
                "published_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-02T00:00:00Z",
                "withdrawn_at": None,
                "html_url": "https://github.com/advisories/GHSA-2345-6789-pyp2",
                "cwes": [],
                "identifiers": [{"type": "GHSA", "value": "GHSA-2345-6789-pyp2"}],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "pip", "name": "example-dist"},
                        "vulnerable_version_range": "<= 1.0",
                    }
                ],
            },
            evidence_id="gbsec:evidence:pypi-local",
            governance_decision_id="gbsec:governance:pypi-local",
            observed_at=NOW,
        )
    with _public_client(database) as client:
        body = _post(
            client, {"ecosystem": "pypi", "name": "example-dist", "version": "1.0+ubuntu1"}
        ).json()
    assert body["result"] == "affected"
    assert body["incidents"][0]["applies_to_version"] is True


@pytest.mark.parametrize("form", ["full", "short", "query"])
@pytest.mark.parametrize("version", ["1.x", "1.2.x", "1.2.X", "1.*", "1.0.0-dev+build.5"])
def test_composer_wildcards_are_refused(database, contract_examples, form, version) -> None:
    full = _example(contract_examples, "PublicArtifactAssessmentRequest")
    full["artifact"].update(
        ecosystem="composer", registry_host="repo.packagist.org", name="vendor/lib", version=version
    )
    short = {"ecosystem": "composer", "name": "vendor/lib", "version": version}
    with _public_client(database) as client:
        if form == "full":
            response = _post(client, full)
        elif form == "short":
            response = _post(client, short)
        else:
            response = _get(client, short)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "version_not_exact"


@pytest.mark.parametrize("form", ["full", "short", "query"])
@pytest.mark.parametrize(
    "version", ["1.0.0+build.5", "1.0.0+build.x", "1.0.0-stable", "v1.2.3", "1.0.0-RC1"]
)
def test_valid_composer_releases_are_assessed(database, contract_examples, form, version) -> None:
    full = _example(contract_examples, "PublicArtifactAssessmentRequest")
    full["artifact"].update(
        ecosystem="composer", registry_host="repo.packagist.org", name="vendor/lib", version=version
    )
    short = {"ecosystem": "composer", "name": "vendor/lib", "version": version}
    with _public_client(database) as client:
        if form == "full":
            response = _post(client, full)
        elif form == "short":
            response = _post(client, short)
        else:
            response = _get(client, short)
    assert response.status_code == 200, response.json()


def test_composer_stable_suffix_is_the_release_for_ranges(database) -> None:
    with Session(database.engine) as session, session.begin():
        append_github_advisory(
            session,
            document={
                "ghsa_id": "GHSA-2345-6789-cmp3",
                "type": "reviewed",
                "published_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-02T00:00:00Z",
                "withdrawn_at": None,
                "html_url": "https://github.com/advisories/GHSA-2345-6789-cmp3",
                "cwes": [],
                "identifiers": [{"type": "GHSA", "value": "GHSA-2345-6789-cmp3"}],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "composer", "name": "vendor/lib"},
                        "vulnerable_version_range": "<= 1.0.0",
                    }
                ],
            },
            evidence_id="gbsec:evidence:composer-stable",
            governance_decision_id="gbsec:governance:composer-stable",
            observed_at=NOW,
        )
    with _public_client(database) as client:
        body = _post(
            client, {"ecosystem": "composer", "name": "vendor/lib", "version": "1.0.0-stable1"}
        ).json()
    assert body["result"] == "affected"
