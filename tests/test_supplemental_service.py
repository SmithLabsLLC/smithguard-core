"""Supplemental context is exact, typed, signed and separate from applicability."""

import base64
from copy import deepcopy
from datetime import timedelta

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session

from smithguard.advisory_catalog import append_github_advisory
from smithguard.contracts.runtime import parse_contract
from smithguard.feeds import SnapshotSigner
from smithguard.identifiers import canonical_json_bytes
from smithguard.service import SmithGuardService
from smithguard.supplemental_store import EPSS_SOURCE, KEV_SOURCE, append_snapshot
from tests.test_service_api import NOW, _example, _public_client

CVE = "CVE-2021-44228"
OTHER_CVE = "CVE-2021-44229"
REQUEST = {"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"}


def advisory(session, *, suffix="cfgh", aliases=(CVE,), version="3.3.6"):
    ghsa = f"GHSA-2345-6789-{suffix}"
    append_github_advisory(
        session,
        document={
            "ghsa_id": ghsa,
            "type": "reviewed",
            "published_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-02T00:00:00Z",
            "withdrawn_at": None,
            "html_url": f"https://github.com/advisories/{ghsa}",
            "cwes": [],
            "identifiers": [
                {"type": "GHSA", "value": ghsa},
                *({"type": "CVE", "value": alias} for alias in aliases),
            ],
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "event-stream"},
                    "vulnerable_version_range": f"= {version}",
                }
            ],
        },
        evidence_id=f"gbsec:evidence:supplemental-{suffix}",
        governance_decision_id=f"gbsec:governance:supplemental-{suffix}",
        observed_at=NOW,
    )


def snapshot(session, source=EPSS_SOURCE, *, facts=None, at=NOW, state="complete"):
    return append_snapshot(
        session,
        source_id=source,
        mode="public",
        state=state,
        observed_at=at,
        source_as_of=NOW if state == "complete" else None,
        document={
            "source_url": "https://www.first.org/epss/"
            if source == EPSS_SOURCE
            else "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        facts=facts
        if facts is not None
        else {
            CVE: {
                "epss": "0.9",
                "percentile": "0.99",
                "score_date": "2026-08-05",
                "model_version": "v2025.03.14",
            }
        },
    )


def assessment(session, now=NOW):
    return SmithGuardService(clock=lambda: now).assess_public_artifact(session, REQUEST)


def test_context_joins_only_exact_cves_from_listed_incident_aliases(database):
    with Session(database.engine) as session, session.begin():
        advisory(session)
        advisory(session, suffix="cfgi", aliases=(CVE,))
        advisory(session, suffix="cfgj", aliases=(OTHER_CVE,), version="9.9.9")
        snapshot(session)
        snapshot(session, KEV_SOURCE, facts={CVE: {"date_added": "2021-12-10"}})
        result = assessment(session)
    assert result["schema_version"] == "2.4.0"
    assert result["result"] == "affected"
    assert result["not_applicable_incident_count"] == 1
    assert [item["cve"] for item in result["cve_context"]] == [CVE]
    context = result["cve_context"][0]
    assert context["epss"]["value"]["epss"] == "0.9"
    assert context["epss"]["listed"] is None
    assert context["kev"]["listed"] is True
    assert context["kev"]["value"] == {"date_added": "2021-12-10"}
    assert context["epss"]["observed_at"] == "2026-08-05T12:00:00Z"
    assert "FIRST" in context["epss"]["attribution"]


def test_missing_nonmembership_failure_and_staleness_never_change_verdict(database):
    with Session(database.engine) as session, session.begin():
        advisory(session)
        missing = assessment(session)
        assert missing["cve_context"][0]["epss"]["value"] is None
        assert missing["cve_context"][0]["kev"]["listed"] is None
        snapshot(session)
        snapshot(session, KEV_SOURCE, facts={})
        fresh = assessment(session)
        assert fresh["cve_context"][0]["kev"]["listed"] is False
        snapshot(session, state="failed", facts={}, at=NOW + timedelta(minutes=1))
        failed = assessment(session, NOW + timedelta(minutes=1))
        failed_context = failed["cve_context"][0]["epss"]
        assert failed_context["state"] == "failed"
        assert failed_context["value"] == fresh["cve_context"][0]["epss"]["value"]
        assert failed_context["snapshot_id"] == fresh["cve_context"][0]["epss"]["snapshot_id"]
        snapshot(session, at=NOW + timedelta(minutes=2))
        stale = assessment(session, NOW + timedelta(hours=49))
    answers = (missing, fresh, failed, stale)
    assert {item["result"] for item in answers} == {"affected"}
    assert len({item["feed_revision"] for item in answers}) == 4
    assert len({item["id"] for item in answers}) == 4
    assert stale["cve_context"][0]["epss"]["state"] == "stale"
    assert stale["cve_context"][0]["epss"]["value"]["epss"] == "0.9"


def test_no_incidents_does_not_export_unrelated_context(database):
    with Session(database.engine) as session, session.begin():
        snapshot(session)
        result = assessment(session)
    assert result["cve_context"] == []
    assert result["result"] == "unknown"


def test_context_in_signed_http_answer_and_cache_correction(database):
    signer = SnapshotSigner.ephemeral()
    with Session(database.engine) as session, session.begin():
        advisory(session)
    with _public_client(database, signer=signer) as client:
        before = client.post("/v1/artifacts/assess", json=REQUEST).json()
        with Session(database.engine) as session, session.begin():
            snapshot(session)
        after = client.post("/v1/artifacts/assess", json=REQUEST).json()
    assert before["feed_revision"] != after["feed_revision"]
    assert before["result"] == after["result"] == "affected"
    key = signer.public_key_document()
    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(key["public_key_base64"]))
    signature = base64.b64decode(after["signature"]["value"])
    unsigned = {key: value for key, value in after.items() if key != "signature"}
    public.verify(signature, canonical_json_bytes(unsigned))
    unsigned["cve_context"][0]["epss"]["value"]["epss"] = "0"
    with pytest.raises(InvalidSignature):
        public.verify(signature, canonical_json_bytes(unsigned))


def missing_context():
    from smithguard.supplemental_store import SOURCE_NAMES

    def source(source_id):
        return {
            "source_id": source_id,
            "attribution": SOURCE_NAMES[source_id],
            "state": "missing",
            "observed_at": None,
            "source_as_of": None,
            "source_url": None,
            "snapshot_id": None,
            "listed": None,
            "value": None,
        }

    return {"cve": CVE, "epss": source(EPSS_SOURCE), "kev": source(KEV_SOURCE)}


def test_contract_accepts_retained_v21_and_requires_v22_context(contract_examples):
    example = _example(contract_examples, "PublicArtifactAssessment")
    assert parse_contract("PublicArtifactAssessment", example).schema_version.value == "2.2.0"
    missing = deepcopy(example)
    missing.pop("cve_context")
    with pytest.raises(ValueError):
        parse_contract("PublicArtifactAssessment", missing)
    missing["schema_version"] = "2.1.0"
    original_bytes = canonical_json_bytes(missing)
    parsed = parse_contract("PublicArtifactAssessment", missing)
    parse_contract("PublicArtifactAssessment", parsed.model_dump(mode="json", exclude_none=False))
    assert canonical_json_bytes(missing) == original_bytes
    missing["schema_version"] = "2.3.0"
    with pytest.raises(ValueError):
        parse_contract("PublicArtifactAssessment", missing)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("cve",), "CVE-2021-44228-extra"),
        (("unknown",), True),
        (("epss", "source_id"), KEV_SOURCE),
        (("epss", "state"), "safe"),
        (("epss", "listed"), False),
        (("epss", "value"), {"epss": "0"}),
        (("epss", "source_url"), "http://www.first.org/epss/"),
        (("kev", "listed"), True),
        (("kev", "value"), {"date_added": "2021-12-10"}),
    ],
)
def test_context_contract_rejects_wrong_identity_types_and_ambiguous_missing(
    contract_examples, path, value
):
    example = _example(contract_examples, "PublicArtifactAssessment")
    context = missing_context()
    current = context
    for field in path[:-1]:
        current = current[field]
    current[path[-1]] = value
    example["cve_context"] = [context]
    with pytest.raises(ValueError):
        parse_contract("PublicArtifactAssessment", example)


@pytest.mark.parametrize("score", [0.9, "1.01", "-0.1", "NaN", "2", "1e-4"])
def test_epss_score_has_bounded_explicit_decimal_type(contract_examples, score):
    example = _example(contract_examples, "PublicArtifactAssessment")
    context = missing_context()
    context["epss"].update(
        state="fresh",
        value={
            "epss": score,
            "percentile": "0.99",
            "score_date": "2026-08-05",
            "model_version": None,
        },
    )
    example["cve_context"] = [context]
    with pytest.raises(ValueError):
        parse_contract("PublicArtifactAssessment", example)


def test_context_maximum_is_enforced_before_model_coercion(contract_examples):
    example = _example(contract_examples, "PublicArtifactAssessment")
    example["cve_context"] = [missing_context()] * 2001
    with pytest.raises(ValueError):
        parse_contract("PublicArtifactAssessment", example)


@pytest.mark.parametrize("origin", ["rustsec", "go"])
def test_origin_symbol_platform_provenance_is_public_and_never_reachability(database, origin):
    from smithguard.origin_advisories import append_origin_advisory
    from tests.test_origin_advisories import NOW as ORIGIN_NOW
    from tests.test_origin_advisories import document, normalize

    record = normalize(document(origin), origin)
    request = {
        "ecosystem": "rust" if origin == "rustsec" else "go",
        "name": "decompress" if origin == "rustsec" else "golang.org/x/net",
        "version": "0.9.0",
    }
    with Session(database.engine) as session, session.begin():
        append_origin_advisory(
            session,
            record=record,
            evidence_id="gbsec:evidence:origin-service",
            governance_decision_id="gbsec:governance:origin-service",
            observed_at=ORIGIN_NOW,
        )
        service = SmithGuardService(clock=lambda: ORIGIN_NOW)
        absent = service.assess_public_artifact(session, request)
        append_snapshot(
            session,
            source_id=record.source_id,
            mode="public",
            state="complete",
            observed_at=ORIGIN_NOW,
            source_as_of=record.source_modified_at,
            document={"source_url": record.canonical_url},
            facts={
                record.upstream_record_id: {
                    "source_sha256": record.source_sha256,
                    "license_expression": record.license_expression,
                    "attribution_urls": list(record.attribution_urls),
                    "context": dict(record.context),
                }
            },
        )
        present = service.assess_public_artifact(session, request)
        append_snapshot(
            session,
            source_id=record.source_id,
            mode="public",
            state="failed",
            observed_at=ORIGIN_NOW + timedelta(minutes=1),
            source_as_of=None,
            document={"source_url": record.canonical_url},
            facts={},
        )
        failed = SmithGuardService(
            clock=lambda: ORIGIN_NOW + timedelta(minutes=1)
        ).assess_public_artifact(session, request)
    assert absent["result"] == present["result"] == failed["result"] == "affected"
    assert len({answer["feed_revision"] for answer in [absent, present, failed]}) == 3
    assert absent["incidents"][0]["source_reports"][0]["origin_context"] is None
    provenance = present["incidents"][0]["source_reports"][0]["origin_context"]
    assert provenance["license_expression"] == record.license_expression
    assert provenance["source_sha256"] == record.source_sha256
    assert provenance["context"] == record.context
    package = provenance["context"]["packages"][0]
    assert package["ecosystem_specific"]["reachability"] == "not_assessed"
    if origin == "go":
        assert package["ecosystem_specific"]["imports"][0]["symbols"] == ["Server.ServeConn"]
        assert package["ecosystem_specific"]["imports"][0]["goos"] == ["linux"]
    else:
        assert package["ecosystem_specific"]["affects"]["functions"] == ["decompress::decompress"]
    retained = failed["incidents"][0]["source_reports"][0]["origin_context"]
    assert retained["state"] == "failed"
    assert retained["context"] == provenance["context"]
    for mutation in ["unknown", "reachability", "hash"]:
        invalid = deepcopy(present)
        value = invalid["incidents"][0]["source_reports"][0]["origin_context"]
        if mutation == "unknown":
            value["context"]["arbitrary"] = {}
        elif mutation == "reachability":
            value["context"]["reachability"] = "reachable"
        else:
            value["source_sha256"] = "abc"
        with pytest.raises(ValueError):
            parse_contract("PublicArtifactAssessment", invalid)


def test_context_is_limited_to_the_100_incidents_actually_listed(database):
    alphabet = "23456789cfghjmpqrvwx"
    with Session(database.engine) as session, session.begin():
        for index in range(101):
            suffix = "23" + alphabet[index // len(alphabet)] + alphabet[index % len(alphabet)]
            advisory(session, suffix=suffix, aliases=(f"CVE-2026-{index + 10000}",))
        result = assessment(session)
    assert result["incidents_truncated"] is True
    assert len(result["incidents"]) == 100
    listed = {
        alias
        for item in result["incidents"]
        for alias in item["aliases"]
        if alias.startswith("CVE-")
    }
    assert {item["cve"] for item in result["cve_context"]} == listed
    assert len(result["cve_context"]) == 100


@pytest.mark.parametrize(
    ("ecosystem", "name", "origin"),
    [
        ("rust", "decompress", "rust"),
        ("go", "golang.org/x/net", "go"),
        ("npm", "event-stream", None),
        ("pypi", "urllib3", None),
        ("maven", "org.apache.logging.log4j:log4j-core", None),
        ("git", "github.com/lodash/lodash", None),
    ],
)
def test_origin_freshness_names_only_the_matching_ecosystem(database, ecosystem, name, origin):
    from smithguard.supplemental_store import GO_SOURCE, RUST_SOURCE

    with Session(database.engine) as session:
        result = SmithGuardService(clock=lambda: NOW).assess_public_artifact(
            session,
            {
                "ecosystem": ecosystem,
                "name": name,
                "version": "a" * 40 if ecosystem == "git" else "0.9.0",
            },
        )
    sources = {item["source_id"]: item for item in result["source_freshness"]}
    origins = {source for source in sources if source in {RUST_SOURCE, GO_SOURCE}}
    assert origins == (
        {RUST_SOURCE} if origin == "rust" else {GO_SOURCE} if origin == "go" else set()
    )
    assert EPSS_SOURCE not in sources
    assert KEV_SOURCE not in sources
    if origin:
        assert sources[next(iter(origins))]["freshness_state"] == "missing"
        label = (
            "RustSec advisory updates" if origin == "rust" else "Go Vulnerability Database updates"
        )
        assert any(
            label in message and "not collected yet" in message for message in result["unknowns"]
        )
    else:
        assert not any(
            "RustSec" in message or "Go Vulnerability Database" in message
            for message in result["unknowns"]
        )


@pytest.mark.parametrize("origin", ["rust", "go"])
def test_origin_freshness_exposes_complete_failed_and_stale_states(database, origin):
    from smithguard.supplemental_store import GO_SOURCE, RUST_SOURCE

    source = RUST_SOURCE if origin == "rust" else GO_SOURCE
    request = {
        "ecosystem": origin,
        "name": "decompress" if origin == "rust" else "golang.org/x/net",
        "version": "0.9.0",
    }

    def read(at):
        with Session(database.engine) as session:
            service = SmithGuardService(clock=lambda: at)
            # Coverage is refreshed by a separate background loop in production.
            service.refresh_coverage(session)
            answer = service.assess_public_artifact(session, request)
        return answer, next(
            item for item in answer["source_freshness"] if item["source_id"] == source
        )

    with Session(database.engine) as session, session.begin():
        snapshot(session, source, facts={})
    _, fresh = read(NOW)
    assert fresh["freshness_state"] == "fresh"
    assert fresh["last_success_at"] == "2026-08-05T12:00:00Z"
    with Session(database.engine) as session, session.begin():
        snapshot(session, source, facts={}, at=NOW + timedelta(minutes=1), state="failed")
    failed_answer, failed = read(NOW + timedelta(minutes=1))
    assert failed["freshness_state"] == "failed"
    assert failed["last_success_at"] == fresh["last_success_at"]
    assert any("updates are failing" in message for message in failed_answer["unknowns"])
    with Session(database.engine) as session, session.begin():
        snapshot(session, source, facts={}, at=NOW + timedelta(minutes=2))
    stale_answer, stale = read(NOW + timedelta(hours=31))
    assert stale["freshness_state"] == "stale"
    assert stale["last_success_at"] == "2026-08-05T12:02:00Z"
    assert any("updates are out of date" in message for message in stale_answer["unknowns"])
