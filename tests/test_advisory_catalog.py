"""Complete GitHub and OpenSSF catalog classification and matching tests."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from smithguard.advisory_catalog import (
    AdvisoryCatalogCapacityExceeded,
    AdvisoryCatalogError,
    _github_range_matches,
    append_github_advisory,
    append_github_inventory_membership,
    append_github_segment_manifest,
    append_openssf_advisory,
    catalog_evidence_for_package,
)
from smithguard.db.models import (
    AdvisoryCatalogManifestRecord,
    AdvisoryCatalogRecord,
    AdvisoryPackageRecord,
)
from smithguard.identifiers import canonical_json_bytes, stable_id, timestamp
from smithguard.origin_advisories import (
    GO_SOURCE_ID,
    RUSTSEC_SOURCE_ID,
    append_origin_advisory,
    normalize_origin_record,
)
from smithguard.service import SmithGuardService
from smithguard.version_order import exact_version_matches

NOW = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
EVIDENCE_ID = "gbsec:evidence:catalog-test"
GOVERNANCE_ID = "gbsec:governance:catalog-test"


def catalog_matches_for_package(session, *, ecosystem: str, name: str, version: str | None):
    """The match families of the complete current package evidence packet."""
    return catalog_evidence_for_package(
        session, ecosystem=ecosystem, name=name, version=version
    ).families


@pytest.mark.parametrize("expression", [">= 0", "> 0", ">= 0.0.0", "*"])
def test_github_npm_universal_ranges_match_every_exact_version(expression: str) -> None:
    assert _github_range_matches("npm", "0.0.0", expression) is True
    assert _github_range_matches("npm", "99.999.123-beta.4", expression) is True


def test_github_pypi_spacing_and_exact_version_normalization() -> None:
    assert _github_range_matches("pypi", "1.5", ">= 1.0, < 2.0") is True
    assert _github_range_matches("pypi", "2.0", ">= 1.0, < 2.0") is False
    assert _github_range_matches("pypi", "1.9", "< 2.0") is True
    assert _github_range_matches("pypi", "2.1", "< 2.0") is False
    assert exact_version_matches("pypi", "1.0", "1.0.0") is True
    assert _github_range_matches("pypi", "1.0.0", "= 1.0") is True
    assert _github_range_matches("npm", "1.2.0", "= 1.2") is None


def _github_event_stream() -> dict[str, object]:
    return {
        "ghsa_id": "GHSA-mh6f-8j2x-4483",
        "type": "reviewed",
        "published_at": "2018-11-26T00:00:00Z",
        "updated_at": "2023-01-30T05:02:00Z",
        "withdrawn_at": None,
        "html_url": "https://github.com/advisories/GHSA-mh6f-8j2x-4483",
        "cwes": [{"cwe_id": "CWE-506"}],
        "identifiers": [
            {"type": "GHSA", "value": "GHSA-mh6f-8j2x-4483"},
        ],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": "event-stream"},
                "vulnerable_version_range": "= 3.3.6",
            },
            {
                "package": {"ecosystem": "npm", "name": "flatmap-stream"},
                "vulnerable_version_range": "= 0.1.1",
            },
        ],
    }


def test_reviewed_cwe_506_is_compromised_and_exactly_affected(database) -> None:
    document = _github_event_stream()
    document["vulnerabilities"][0]["first_patched_version"] = "4.0.0"
    with Session(database.engine) as session, session.begin():
        result = append_github_advisory(
            session,
            document=document,
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )
        assert result.created is True
        assert result.package_entry_count == 2

    with Session(database.engine) as session:
        affected = catalog_matches_for_package(
            session,
            ecosystem="npm",
            name="event-stream",
            version="3.3.6",
        )
        safe_before = catalog_matches_for_package(
            session,
            ecosystem="npm",
            name="event-stream",
            version="3.3.4",
        )
        safe_after = catalog_matches_for_package(
            session,
            ecosystem="npm",
            name="event-stream",
            version="4.0.0",
        )
        flatmap = catalog_matches_for_package(
            session,
            ecosystem="npm",
            name="flatmap-stream",
            version="0.1.1",
        )
        assert len(affected) == len(safe_before) == len(safe_after) == len(flatmap) == 1
        assert affected[0].classification == "compromised"
        assert affected[0].confidence == "confirmed"
        assert affected[0].evaluations == (True,)
        assert safe_before[0].evaluations == (False,)
        assert safe_after[0].evaluations == (False,)
        assert flatmap[0].evaluations == (True,)

    with Session(database.engine) as session:
        response = SmithGuardService(
            clock=lambda: NOW,
        ).assess_public_artifact(
            session,
            {
                "id": stable_id("assessment-request", "event-stream", "3.3.6"),
                "kind": "public_artifact_assessment_request",
                "schema_version": "1.0.0",
                "revision": 1,
                "created_at": timestamp(NOW),
                "updated_at": timestamp(NOW),
                "data_classification": "public",
                "artifact": {
                    "ecosystem": "npm",
                    "registry_host": "registry.npmjs.org",
                    "name": "event-stream",
                    "version": "3.3.6",
                    "digest": None,
                    "public_visibility": "asserted_public",
                },
            },
        )
        assert response["result"] == "affected"
        assert response["incidents"][0]["fixed_versions"] == ["4.0.0"]
        assert response["incidents"][0]["classification"] == "compromised"
        assert response["incidents"][0]["confidence"] == "confirmed"


def test_catalog_tables_reject_mutation(database) -> None:
    document = _github_event_stream()
    with Session(database.engine) as session, session.begin():
        appended = append_github_advisory(
            session,
            document=document,
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )
        append_github_inventory_membership(
            session,
            segment="reviewed",
            source_snapshot=timestamp(NOW),
            upstream_record_id=str(document["ghsa_id"]),
            appended=appended,
            observed_at=NOW,
        )
        append_github_segment_manifest(
            session,
            segment="reviewed",
            source_snapshot=timestamp(NOW),
            expected_record_count=1,
            expected_package_entry_count=2,
            observed_at=NOW,
        )

    for table_name in (
        "advisory_catalog_records",
        "advisory_package_records",
        "advisory_catalog_inventory",
        "advisory_catalog_manifests",
    ):
        with pytest.raises(DBAPIError, match="append-only"), database.engine.begin() as connection:
            connection.execute(
                text(f"UPDATE smithguard.{table_name} SET observed_at = observed_at")
            )


def test_unreviewed_cwe_506_never_becomes_confirmed_malware(database) -> None:
    document = _github_event_stream()
    document["ghsa_id"] = "GHSA-2345-6789-cfgh"
    document["type"] = "unreviewed"
    document["identifiers"] = [{"type": "GHSA", "value": "GHSA-2345-6789-cfgh"}]
    with Session(database.engine) as session, session.begin():
        append_github_advisory(
            session,
            document=document,
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )
    with Session(database.engine) as session:
        record = session.query(AdvisoryCatalogRecord).one()
        assert record.claim_type == "vulnerable"
        assert record.confidence == "unverified"


def test_github_manifest_uses_only_the_latest_type_and_exact_cutoff_counts(
    database,
) -> None:
    reviewed = _github_event_stream()
    promoted = _github_event_stream()
    promoted["type"] = "malware"
    promoted["updated_at"] = "2026-08-31T11:00:00Z"
    with Session(database.engine) as session, session.begin():
        reviewed_append = append_github_advisory(
            session,
            document=reviewed,
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )
        append_github_inventory_membership(
            session,
            segment="reviewed",
            source_snapshot="2026-08-31T10:00:00Z",
            upstream_record_id=str(reviewed["ghsa_id"]),
            appended=reviewed_append,
            observed_at=NOW,
        )
        promoted_append = append_github_advisory(
            session,
            document=promoted,
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )
        append_github_inventory_membership(
            session,
            segment="malware",
            source_snapshot=timestamp(NOW),
            upstream_record_id=str(promoted["ghsa_id"]),
            appended=promoted_append,
            observed_at=NOW,
        )
        append_github_segment_manifest(
            session,
            segment="reviewed",
            source_snapshot="2026-08-31T10:00:00Z",
            expected_record_count=1,
            expected_package_entry_count=2,
            observed_at=NOW,
        )
        append_github_segment_manifest(
            session,
            segment="malware",
            source_snapshot=timestamp(NOW),
            expected_record_count=1,
            expected_package_entry_count=2,
            observed_at=NOW,
        )
        try:
            append_github_segment_manifest(
                session,
                segment="malware",
                source_snapshot=timestamp(NOW),
                expected_record_count=2,
                expected_package_entry_count=2,
                observed_at=NOW,
            )
        except AdvisoryCatalogError as error:
            assert "record count differs" in str(error)
        else:
            raise AssertionError("a mismatched GitHub source manifest was accepted")
    with Session(database.engine) as session:
        manifests = session.query(AdvisoryCatalogManifestRecord).all()
        assert [(row.segment, row.record_count, row.package_entry_count) for row in manifests] == [
            ("reviewed", 1, 2),
            ("malware", 1, 2),
        ]


def test_openssf_unicode_nuget_identity_is_preserved_without_filtering(database) -> None:
    name = "Micros\u043eft.ApplicationInsights"
    document = {
        "id": "MAL-2026-12345",
        "published": "2026-08-30T00:00:00Z",
        "modified": "2026-08-31T00:00:00Z",
        "aliases": [],
        "affected": [
            {
                "package": {"ecosystem": "NuGet", "name": name},
                "versions": ["1.2.3"],
                "ranges": [],
            }
        ],
    }
    with Session(database.engine) as session, session.begin():
        append_openssf_advisory(
            session,
            document=document,
            canonical_url=(
                "https://github.com/ossf/malicious-packages/blob/"
                "0123456789012345678901234567890123456789/example.json"
            ),
            source_state="active",
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )
    with Session(database.engine) as session:
        package = session.query(AdvisoryPackageRecord).one()
        assert package.ecosystem == "nuget"
        assert package.name == name
        assert package.name != "Microsoft.ApplicationInsights"
        match = catalog_matches_for_package(
            session,
            ecosystem="nuget",
            name=name,
            version="1.2.3",
        )
        assert match[0].classification == "malicious"
        assert match[0].evaluations == (True,)


def test_github_nullable_fields_and_unmapped_ecosystem_are_preserved_honestly(database) -> None:
    document = _github_event_stream()
    document["ghsa_id"] = "GHSA-2345-6789-cfgj"
    document["identifiers"] = None
    document["cwes"] = None
    document["vulnerabilities"] = [
        {"package": None, "vulnerable_version_range": None},
        {
            "package": {"ecosystem": "other", "name": "outside-map"},
            "vulnerable_version_range": "= 1.0.0",
        },
        {
            "package": {"ecosystem": "npm", "name": None},
            "vulnerable_version_range": "= 1.0.0",
        },
        {
            "package": {"ecosystem": "npm", "name": "range-missing"},
            "vulnerable_version_range": None,
        },
    ]
    with Session(database.engine) as session, session.begin():
        appended = append_github_advisory(
            session,
            document=document,
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )
        assert appended.package_entry_count == 1
        assert appended.package_omission_counts == {
            "missing_package": 1,
            "missing_package_name": 1,
            "missing_version_range": 1,
            "unsupported_ecosystem": 1,
        }
    with Session(database.engine) as session:
        catalog = session.query(AdvisoryCatalogRecord).one()
        package = session.query(AdvisoryPackageRecord).one()
        assert catalog.package_omission_counts == appended.package_omission_counts
        assert package.name == "range-missing"
        assert package.affected_ranges == []
        match = catalog_matches_for_package(
            session,
            ecosystem="npm",
            name="range-missing",
            version="1.0.0",
        )
        assert match[0].evaluations == (None,)


def test_github_and_openssf_ghsa_aliases_form_one_two_source_family(database) -> None:
    github = _github_event_stream()
    openssf = {
        "id": "MAL-2026-54321",
        "published": "2026-08-30T00:00:00Z",
        "modified": "2026-08-31T00:00:00Z",
        "aliases": [github["ghsa_id"]],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "event-stream"},
                "versions": ["3.3.6"],
                "ranges": [],
            }
        ],
    }
    with Session(database.engine) as session, session.begin():
        append_github_advisory(
            session,
            document=github,
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )
        append_openssf_advisory(
            session,
            document=openssf,
            canonical_url=(
                "https://github.com/ossf/malicious-packages/blob/"
                "0123456789012345678901234567890123456789/example.json"
            ),
            source_state="active",
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )
    with Session(database.engine) as session:
        families = catalog_matches_for_package(
            session,
            ecosystem="npm",
            name="event-stream",
            version="3.3.6",
        )
        assert len(families) == 1
        assert families[0].family_key == str(github["ghsa_id"]).upper()
        assert len(families[0].source_reports) == 2
        assert families[0].classification == "compromised"


# AUD-MATCH: every assertion carries its own range and authority through aggregation.
def _matching_github(
    *,
    source_type: str = "reviewed",
    version: str = "3.3.6",
    cwe: bool = True,
    ecosystem: str = "npm",
    name: str = "event-stream",
) -> dict[str, Any]:
    value = _github_event_stream()
    value["type"] = source_type
    value["cwes"] = [{"cwe_id": "CWE-506"}] if cwe else []
    value["vulnerabilities"] = [
        {
            "package": {"ecosystem": ecosystem, "name": name},
            "vulnerable_version_range": "= " + version,
        }
    ]
    return value


def _matching_openssf(*, version: str = "3.3.6") -> dict[str, Any]:
    return {
        "id": "MAL-2026-54321",
        "published": "2026-08-30T00:00:00Z",
        "modified": "2026-08-31T00:00:00Z",
        "aliases": ["GHSA-mh6f-8j2x-4483"],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "event-stream"},
                "versions": [version],
                "ranges": [],
            }
        ],
    }


def _append_match_document(database, value: dict[str, Any], *, openssf: bool = False) -> None:
    with Session(database.engine) as session, session.begin():
        if openssf:
            append_openssf_advisory(
                session,
                document=value,
                canonical_url="https://github.com/ossf/malicious-packages/blob/"
                "0123456789012345678901234567890123456789/example.json",
                source_state="withdrawn" if value.get("withdrawn") else "active",
                evidence_id=EVIDENCE_ID,
                governance_decision_id=GOVERNANCE_ID,
                observed_at=NOW,
            )
        else:
            append_github_advisory(
                session,
                document=value,
                evidence_id=EVIDENCE_ID,
                governance_decision_id=GOVERNANCE_ID,
                observed_at=NOW,
            )


@pytest.mark.parametrize("ecosystem,source_ecosystem", [("npm", "npm"), ("pypi", "PyPI")])
def test_openssf_only_family_preserves_legacy_public_incident_id(
    database, ecosystem, source_ecosystem
) -> None:
    document = _matching_openssf()
    document["aliases"] = [document["id"], "CVE-2026-12345"]
    document["affected"][0]["package"] = {
        "ecosystem": source_ecosystem,
        "name": "legacy-package",
    }
    _append_match_document(database, document, openssf=True)
    with Session(database.engine) as session:
        families = catalog_matches_for_package(
            session, ecosystem=ecosystem, name="legacy-package", version="3.3.6"
        )
    legacy_key = "gbsec:source:openssf-malicious-packages:MAL-2026-54321"
    assert len(families) == 1
    assert families[0].family_key == legacy_key
    assert families[0].incident_id == stable_id("catalog-incident", legacy_key)
    assert len(families[0].source_reports) == 1


def _origin_document(
    origin: str,
    *,
    aliases: list[str],
    version: str = "1.2.3",
    reviewed: bool = True,
    name: str | None = None,
) -> dict[str, Any]:
    upstream_id = "RUSTSEC-2026-0123" if origin == "rustsec" else "GO-2026-1234"
    return {
        "id": upstream_id,
        "published": "2026-08-30T00:00:00Z",
        "modified": "2026-08-31T00:00:00Z",
        "aliases": aliases,
        "database_specific": (
            {"license": "CC0-1.0"}
            if origin == "rustsec"
            else {
                "review_status": "REVIEWED" if reviewed else "UNREVIEWED",
                "url": "https://pkg.go.dev/vuln/" + upstream_id,
            }
        ),
        "affected": [
            {
                "package": {
                    "ecosystem": "crates.io" if origin == "rustsec" else "Go",
                    "name": name or ("demo-crate" if origin == "rustsec" else "example.com/demo"),
                },
                "versions": [version],
            }
        ],
    }


def _append_origin_document(
    database, origin: str, document: dict[str, Any], *, rustsec_commit: str = "a" * 40
):
    record = normalize_origin_record(
        origin,
        canonical_json_bytes(document),
        rustsec_commit=rustsec_commit if origin == "rustsec" else None,
    )
    with Session(database.engine) as session, session.begin():
        return append_origin_advisory(
            session,
            record=record,
            evidence_id=EVIDENCE_ID,
            governance_decision_id=GOVERNANCE_ID,
            observed_at=NOW,
        )


def _distinct_github(ghsa: str, *, aliases: list[str], **kwargs) -> dict[str, Any]:
    document = _matching_github(**kwargs)
    document["ghsa_id"] = ghsa
    document["html_url"] = "https://github.com/advisories/" + ghsa
    document["identifiers"] = [
        {"type": "GHSA" if alias.startswith("GHSA-") else "CVE", "value": alias}
        for alias in [ghsa, *aliases]
    ]
    return document


@pytest.mark.parametrize(
    "ecosystem,name", [("npm", "demo"), ("rust", "demo-crate"), ("go", "example.com/demo")]
)
@pytest.mark.parametrize("reverse", [False, True])
def test_github_only_shared_cve_preserves_separate_legacy_ghsa_families(
    database, ecosystem, name, reverse
) -> None:
    identifiers = ["GHSA-mh6f-8j2x-4483", "GHSA-2345-6789-cfgh"]
    for ghsa in reversed(identifiers) if reverse else identifiers:
        _append_match_document(
            database,
            _distinct_github(
                ghsa,
                aliases=["CVE-2026-12345"],
                ecosystem=ecosystem,
                name=name,
                version="1.2.3",
                cwe=False,
            ),
        )
    with Session(database.engine) as session:
        families = catalog_matches_for_package(
            session, ecosystem=ecosystem, name=name, version="1.2.3"
        )
    assert {family.family_key for family in families} == {ghsa.upper() for ghsa in identifiers}
    assert {family.incident_id for family in families} == {
        stable_id("catalog-incident", ghsa.upper()) for ghsa in identifiers
    }
    assert all(len(family.source_reports) == 1 for family in families)


@pytest.mark.parametrize(
    "origin,ecosystem,name",
    [
        ("rustsec", "rust", "demo-crate"),
        ("go", "go", "example.com/demo"),
    ],
)
def test_cve_only_origin_alias_joins_github_without_claiming_source_independence(
    database, origin, ecosystem, name
) -> None:
    _append_match_document(
        database,
        _distinct_github(
            "GHSA-mh6f-8j2x-4483",
            aliases=["CVE-2026-12345"],
            ecosystem=ecosystem,
            name=name,
            version="1.2.3",
            cwe=False,
        ),
    )
    _append_origin_document(database, origin, _origin_document(origin, aliases=["CVE-2026-12345"]))
    with Session(database.engine) as session:
        packet = catalog_evidence_for_package(
            session, ecosystem=ecosystem, name=name, version="1.2.3"
        )
    assert len(packet.families) == 1
    family = packet.families[0]
    assert family.family_key == "GHSA-MH6F-8J2X-4483"
    assert len(family.source_reports) == 2
    assert family.evaluations == (True, True)
    assert family.authoritative_match is True
    assert family.classification == "vulnerable"


@pytest.mark.parametrize(
    "origin,ecosystem,name",
    [("rustsec", "rust", "demo-crate"), ("go", "go", "example.com/demo")],
)
def test_cve_bridge_coalesces_only_while_its_direct_origin_is_active(
    database, origin, ecosystem, name
) -> None:
    identifiers = ["GHSA-mh6f-8j2x-4483", "GHSA-2345-6789-cfgh"]
    for ghsa in identifiers:
        _append_match_document(
            database,
            _distinct_github(
                ghsa,
                aliases=["CVE-2026-12345"],
                ecosystem=ecosystem,
                name=name,
                version="1.2.3",
                cwe=False,
            ),
        )
    bridge = _origin_document(origin, aliases=["CVE-2026-12345"])
    _append_origin_document(database, origin, bridge)
    with Session(database.engine) as session:
        before = catalog_evidence_for_package(
            session, ecosystem=ecosystem, name=name, version="1.2.3"
        )
    assert len(before.families) == 1
    assert len(before.families[0].source_reports) == 3

    bridge["withdrawn"] = "2026-08-31T01:00:00Z"
    _append_origin_document(database, origin, bridge)
    with Session(database.engine) as session:
        after = catalog_evidence_for_package(
            session, ecosystem=ecosystem, name=name, version="1.2.3"
        )
    assert len(after.families) == 2
    assert {family.incident_id for family in after.families} == {
        stable_id("catalog-incident", ghsa.upper()) for ghsa in identifiers
    }
    assert all(len(family.source_reports) == 1 for family in after.families)
    assert after.fingerprint != before.fingerprint


@pytest.mark.parametrize("reverse", [False, True])
def test_multiple_ghsa_alias_bridge_forms_deterministic_connected_component(
    database, reverse
) -> None:
    identifiers = ["GHSA-mh6f-8j2x-4483", "GHSA-2345-6789-cfgh"]
    for ghsa in reversed(identifiers) if reverse else identifiers:
        _append_match_document(
            database,
            _distinct_github(
                ghsa,
                aliases=[],
                ecosystem="rust",
                name="demo-crate",
                version="1.2.3",
                cwe=False,
            ),
        )
    document = _origin_document(
        "rustsec", aliases=list(reversed(identifiers)) if reverse else identifiers
    )
    _append_origin_document(database, "rustsec", document)
    with Session(database.engine) as session:
        packet = catalog_evidence_for_package(
            session, ecosystem="rust", name="demo-crate", version="1.2.3"
        )
        again = catalog_evidence_for_package(
            session, ecosystem="rust", name="demo-crate", version="1.2.3"
        )
    assert len(packet.families) == 1
    assert packet.families[0].family_key == "GHSA-2345-6789-CFGH"
    assert len(packet.families[0].source_reports) == 3
    assert packet.families[0].incident_id == stable_id("catalog-incident", "GHSA-2345-6789-CFGH")
    assert packet.fingerprint == again.fingerprint


def test_same_package_unrelated_aliases_and_other_package_bridge_do_not_coalesce(database) -> None:
    identifiers = ["GHSA-mh6f-8j2x-4483", "GHSA-2345-6789-cfgh"]
    for index, ghsa in enumerate(identifiers):
        _append_match_document(
            database,
            _distinct_github(
                ghsa,
                aliases=[f"CVE-2026-1234{index}"],
                ecosystem="rust",
                name="demo-crate",
                version="1.2.3",
                cwe=False,
            ),
        )
    _append_origin_document(
        database,
        "rustsec",
        _origin_document(
            "rustsec",
            aliases=identifiers,
            name="other-crate",
        ),
    )
    with Session(database.engine) as session:
        families = catalog_matches_for_package(
            session, ecosystem="rust", name="demo-crate", version="1.2.3"
        )
    assert len(families) == 2
    assert all(len(family.source_reports) == 1 for family in families)


def test_alias_connected_nonmatch_cannot_lend_confirmed_authority_to_go_match(database) -> None:
    _append_match_document(
        database,
        _distinct_github(
            "GHSA-mh6f-8j2x-4483",
            aliases=["CVE-2026-12345"],
            ecosystem="go",
            name="example.com/demo",
            version="9.9.9",
            cwe=True,
        ),
    )
    _append_origin_document(
        database,
        "go",
        _origin_document(
            "go",
            aliases=["CVE-2026-12345"],
            reviewed=False,
        ),
    )
    with Session(database.engine) as session:
        families = catalog_matches_for_package(
            session, ecosystem="go", name="example.com/demo", version="1.2.3"
        )
    assert len(families) == 1
    family = families[0]
    assert set(family.evaluations) == {False, True}
    assert family.authoritative_match is False
    assert family.confidence == "unverified"
    assert family.classification == "vulnerable"


def test_withdrawn_alias_bridge_splits_families_and_changes_member_fingerprint(database) -> None:
    identifiers = ["GHSA-mh6f-8j2x-4483", "GHSA-2345-6789-cfgh"]
    for ghsa in identifiers:
        _append_match_document(
            database,
            _distinct_github(
                ghsa,
                aliases=[],
                ecosystem="rust",
                name="demo-crate",
                version="1.2.3",
                cwe=False,
            ),
        )
    bridge = _origin_document("rustsec", aliases=identifiers)
    _append_origin_document(database, "rustsec", bridge)
    with Session(database.engine) as session:
        before = catalog_evidence_for_package(
            session, ecosystem="rust", name="demo-crate", version="1.2.3"
        )
    bridge["withdrawn"] = "2026-08-31T01:00:00Z"
    _append_origin_document(database, "rustsec", bridge)
    with Session(database.engine) as session:
        after = catalog_evidence_for_package(
            session, ecosystem="rust", name="demo-crate", version="1.2.3"
        )
    assert len(before.families) == 1
    assert len(after.families) == 2
    assert after.fingerprint != before.fingerprint
    assert all(len(family.source_reports) == 1 for family in after.families)


def test_raw_body_context_only_origin_correction_binds_new_catalog_revision(database) -> None:
    document = _origin_document("go", aliases=["CVE-2026-12345"])
    first = _append_origin_document(database, "go", document)
    document["details"] = "Corrected explanatory text without changed range or timestamp."
    second = _append_origin_document(database, "go", document)
    assert first.created and second.created
    assert second.revision == first.revision + 1
    with Session(database.engine) as session:
        records = session.scalars(
            select(AdvisoryCatalogRecord).order_by(AdvisoryCatalogRecord.revision)
        ).all()
    assert len(records) == 2
    assert records[0].source_sha256 != records[1].source_sha256


def test_unchanged_rustsec_export_commit_preserves_catalog_package_and_family_identity(
    database,
) -> None:
    document = _origin_document("rustsec", aliases=["CVE-2026-12345"])
    first = _append_origin_document(database, "rustsec", document)
    with Session(database.engine) as session:
        before = catalog_evidence_for_package(
            session, ecosystem="rust", name="demo-crate", version="1.2.3"
        )
        original = session.query(AdvisoryCatalogRecord).one()
        first_url = original.canonical_url
        first_hash = original.source_sha256
    second = _append_origin_document(database, "rustsec", document, rustsec_commit="b" * 40)
    assert first.created and not second.created
    assert second.catalog_event_id == first.catalog_event_id
    assert second.revision == first.revision == 1
    assert second.source_sha256 == first.source_sha256
    with Session(database.engine) as session:
        assert session.query(AdvisoryCatalogRecord).count() == 1
        assert session.query(AdvisoryPackageRecord).count() == 1
        retained = session.query(AdvisoryCatalogRecord).one()
        assert retained.canonical_url == first_url
        assert retained.source_sha256 == first_hash
        after = catalog_evidence_for_package(
            session, ecosystem="rust", name="demo-crate", version="1.2.3"
        )
    assert after.fingerprint == before.fingerprint
    assert after.families == before.families


def test_alias_components_do_not_bridge_unnamespaced_text_and_enforce_link_budget(
    monkeypatch,
) -> None:
    from smithguard import advisory_catalog

    values = [
        (
            SimpleNamespace(source_id=source, upstream_record_id=upstream, aliases=["shared-note"]),
            SimpleNamespace(),
        )
        for source, upstream in [("source-a", "custom-a"), ("source-b", "custom-b")]
    ]
    components = advisory_catalog._alias_components(values)
    assert sorted(components) == ["source-a:custom-a", "source-b:custom-b"]
    values[0][0].aliases = ["CVE-2026-12345", "CVE-2026-12346"]
    monkeypatch.setattr(advisory_catalog, "CATALOG_ALIAS_LINK_LIMIT", 1)
    with pytest.raises(AdvisoryCatalogCapacityExceeded, match="explicit link bound"):
        advisory_catalog._alias_components(values)


def test_transitive_cve_components_are_order_independent_without_a_shared_ghsa() -> None:
    from smithguard.advisory_catalog import _alias_components

    values = [
        (
            SimpleNamespace(source_id=source, upstream_record_id=upstream, aliases=aliases),
            SimpleNamespace(),
        )
        for source, upstream, aliases in [
            (GO_SOURCE_ID, "GO-2026-1001", ["CVE-2026-12345"]),
            (RUSTSEC_SOURCE_ID, "RUSTSEC-2026-0001", ["CVE-2026-12345", "CVE-2026-12346"]),
            (GO_SOURCE_ID, "GO-2026-1002", ["CVE-2026-12346"]),
        ]
    ]
    for ordered in (values, list(reversed(values))):
        components = _alias_components(ordered)
        assert list(components) == ["CVE-2026-12345"]
        assert len(components["CVE-2026-12345"]) == 3


def test_origin_identifier_spelling_does_not_grant_origin_source_coalescing() -> None:
    from smithguard.advisory_catalog import _alias_components

    values = [
        (
            SimpleNamespace(
                source_id=source, upstream_record_id=upstream, aliases=["CVE-2026-12345"]
            ),
            SimpleNamespace(),
        )
        for source, upstream in [
            ("other-source-a", "GO-2026-1001"),
            ("other-source-b", "RUSTSEC-2026-0001"),
        ]
    ]
    assert sorted(_alias_components(values)) == [
        "other-source-a:GO-2026-1001",
        "other-source-b:RUSTSEC-2026-0001",
    ]


def _assessment_document(database, contract_examples) -> dict[str, Any]:
    request = deepcopy(
        next(
            value["value"]
            for value in contract_examples
            if value["definition"] == "PublicArtifactAssessmentRequest"
        )
    )
    with Session(database.engine) as session:
        return SmithGuardService(clock=lambda: NOW).assess_public_artifact(session, request)


@pytest.mark.audit_ids("AUD-01")
@pytest.mark.parametrize(
    (
        "source_type",
        "cwe",
        "github_version",
        "openssf_version",
        "confidence",
        "classification",
        "result",
    ),
    [
        ("unreviewed", True, "3.3.6", "9.9.9", "unverified", "vulnerable", "possibly_affected"),
        ("reviewed", False, "3.3.6", "9.9.9", "confirmed", "vulnerable", "affected"),
        ("reviewed", True, "9.9.9", "3.3.6", "confirmed", "malicious", "affected"),
        ("reviewed", True, "3.3.6", "3.3.6", "confirmed", "compromised", "affected"),
        # Nothing applies to 3.3.6: the family keeps its confirmed OpenSSF source label.
        ("unreviewed", False, "9.9.9", "9.9.9", "confirmed", "malicious", "not_affected"),
    ],
)
def test_catalog_authority_and_classification_belong_to_matching_assertions(
    database,
    contract_examples,
    source_type,
    cwe,
    github_version,
    openssf_version,
    confidence,
    classification,
    result,
) -> None:
    _append_match_document(
        database,
        _matching_github(
            source_type=source_type,
            cwe=cwe,
            version=github_version,
        ),
    )
    _append_match_document(database, _matching_openssf(version=openssf_version), openssf=True)
    body = _assessment_document(database, contract_examples)
    assert body["result"] == result
    if result == "not_affected":
        # A family whose ranges all exclude the version is counted, not listed.
        assert body["incidents"] == []
        assert body["not_applicable_incident_count"] == 1
        return
    assert len(body["incidents"]) == 1
    assert body["incidents"][0]["applies_to_version"] is True
    assert body["incidents"][0]["confidence"] == confidence
    assert body["incidents"][0]["classification"] == classification
    assert len(body["incidents"][0]["source_reports"]) == 2
    reports = {report["source_id"]: report for report in body["incidents"][0]["source_reports"]}
    assert reports["gbsec:source:github-advisory-database"]["applies_to_version"] is (
        github_version == "3.3.6"
    )
    assert reports["gbsec:source:openssf-malicious-packages"]["applies_to_version"] is (
        openssf_version == "3.3.6"
    )
    assert all(isinstance(report["fixed_versions"], list) for report in reports.values())
    assert any("Sources disagree" in reason for reason in body["unknowns"]) is (
        github_version != openssf_version
    )


@pytest.mark.audit_ids("AUD-01")
def test_undecidable_confirmed_assertion_cannot_promote_an_unverified_match(
    database,
    contract_examples,
) -> None:
    _append_match_document(database, _matching_github(source_type="unreviewed"))
    openssf = _matching_openssf()
    openssf["affected"][0]["versions"] = []
    openssf["affected"][0]["ranges"] = [{"type": "GIT", "events": [{"introduced": "0"}]}]
    _append_match_document(database, openssf, openssf=True)
    body = _assessment_document(database, contract_examples)
    assert body["result"] == "possibly_affected"
    assert body["incidents"][0]["confidence"] == "unverified"
    assert body["incidents"][0]["classification"] == "vulnerable"


@pytest.mark.audit_ids("AUD-05")
def test_complete_member_identity_tracks_nonmaximum_withdrawal_alias_and_restore(
    database,
    contract_examples,
) -> None:
    github = _matching_github(version="9.9.9")
    _append_match_document(database, github)
    github["updated_at"] = "2026-08-31T01:00:00Z"
    _append_match_document(database, github)
    openssf = _matching_openssf(version="9.9.9")
    _append_match_document(database, openssf, openssf=True)
    snapshots = [_assessment_document(database, contract_examples)]
    assert snapshots[-1]["result"] == "not_affected"
    assert snapshots[-1]["incidents"] == []
    assert snapshots[-1]["not_applicable_incident_count"] == 1
    openssf["affected"][0]["versions"] = ["3.3.6"]
    _append_match_document(database, openssf, openssf=True)
    snapshots.append(_assessment_document(database, contract_examples))
    assert snapshots[-1]["result"] == "affected"
    assert snapshots[-1]["incidents"][0]["revision"] == 2
    openssf["withdrawn"] = "2026-08-31T02:00:00Z"
    _append_match_document(database, openssf, openssf=True)
    snapshots.append(_assessment_document(database, contract_examples))
    assert snapshots[-1]["result"] == "not_affected"
    openssf.pop("withdrawn")
    _append_match_document(database, openssf, openssf=True)
    snapshots.append(_assessment_document(database, contract_examples))
    assert snapshots[-1]["result"] == "affected"
    openssf["aliases"] = []
    _append_match_document(database, openssf, openssf=True)
    snapshots.append(_assessment_document(database, contract_examples))
    # Two families now: the OpenSSF one applies; the GitHub one (9.9.9) is counted.
    assert len(snapshots[-1]["incidents"]) == 1
    assert snapshots[-1]["not_applicable_incident_count"] == 1
    assert len({value["feed_revision"] for value in snapshots}) == len(snapshots)
    assert len({value["id"] for value in snapshots}) == len(snapshots)
    again = _assessment_document(database, contract_examples)
    assert again["feed_revision"] == snapshots[-1]["feed_revision"]
    assert again["id"] == snapshots[-1]["id"]


@pytest.mark.audit_ids("AUD-05")
def test_omitted_package_keeps_latest_revision_without_resurrecting_history(
    database,
    contract_examples,
) -> None:
    empty = _assessment_document(database, contract_examples)
    github = _matching_github()
    _append_match_document(database, github)
    affected = _assessment_document(database, contract_examples)
    github["vulnerabilities"] = []
    _append_match_document(database, github)
    omitted = _assessment_document(database, contract_examples)
    assert omitted["result"] == "unknown"
    assert omitted["incidents"] == []
    assert len({value["feed_revision"] for value in (empty, affected, omitted)}) == 3
    github["updated_at"] = "2026-08-31T03:00:00Z"
    _append_match_document(database, github)
    changed = _assessment_document(database, contract_examples)
    assert changed["feed_revision"] != omitted["feed_revision"]
    assert changed["incidents"] == []
    # Replaying older upstream bytes cannot resurrect a removed package.
    with pytest.raises(AdvisoryCatalogError, match="older GitHub"):
        _append_match_document(database, _matching_github())
    corrected = _matching_github()
    corrected["updated_at"] = "2026-08-31T04:00:00Z"
    _append_match_document(database, corrected)
    restored = _assessment_document(database, contract_examples)
    assert restored["result"] == "affected"
    assert restored["feed_revision"] != affected["feed_revision"]
    with Session(database.engine) as session:
        assert len(tuple(session.scalars(select(AdvisoryCatalogRecord)))) == 4
        assert len(tuple(session.scalars(select(AdvisoryPackageRecord)))) == 2


@pytest.mark.audit_ids("AUD-05")
@pytest.mark.parametrize("state", ["active", "withdrawn", "omitted"])
def test_catalog_capacity_bound_includes_historical_memberships(
    database, monkeypatch, state
) -> None:
    import smithguard.advisory_catalog as module

    monkeypatch.setattr(module, "CATALOG_QUERY_LIMIT", 3)
    for suffix in ("2345", "2346", "2347"):
        value = _matching_github()
        value["ghsa_id"] = "GHSA-2345-6789-" + suffix
        _append_match_document(database, value)
        if state == "withdrawn":
            value["withdrawn_at"] = "2026-08-31T03:00:00Z"
        elif state == "omitted":
            value["vulnerabilities"] = []
        if state != "active":
            _append_match_document(database, value)
    with Session(database.engine) as session, pytest.raises(AdvisoryCatalogCapacityExceeded):
        catalog_evidence_for_package(session, ecosystem="npm", name="event-stream", version="3.3.6")


@pytest.mark.audit_ids("AUD-06")
@pytest.mark.parametrize(
    ("ecosystem", "retained", "requested", "matches"),
    [
        ("nuget", "Audit.Example", "audit.EXAMPLE", True),
        ("nuget", "Audit.Example", "Audit.Example.Other", False),
        ("nuget", "Audit.Example", "Aud\u0131t.Example", False),
        ("nuget", "Micr\u043es\u043eft.Package", "Microsoft.Package", False),
        ("maven", "Audit:Example", "audit:example", False),
        ("go", "example.org/Audit", "example.org/audit", False),
        ("composer", "Audit/Example", "audit/example", True),
        ("rust", "audit-example", "Audit_Example", True),
        ("rust", "audit_example", "audit-example", True),
        ("rust", "audit-example", "auditexample", False),
        ("rubygems", "Audit-Example", "audit-example", False),
    ],
)
def test_compatible_lookup_preserves_retained_names_hashes_and_confusables(
    database,
    ecosystem,
    retained,
    requested,
    matches,
) -> None:
    _append_match_document(database, _matching_github(ecosystem=ecosystem, name=retained))
    with Session(database.engine) as session:
        before = tuple(session.scalars(select(AdvisoryPackageRecord)))
        identities = [
            (row.name, row.package_event_id, row.entry_key, row.record_hash) for row in before
        ]
        evidence = catalog_evidence_for_package(
            session,
            ecosystem=ecosystem,
            name=requested,
            version="3.3.6",
        )
        assert bool(evidence.families) is matches
        after = tuple(session.scalars(select(AdvisoryPackageRecord)))
        assert [
            (row.name, row.package_event_id, row.entry_key, row.record_hash) for row in after
        ] == identities
        assert after[0].name == retained
        if matches:
            exact = catalog_evidence_for_package(
                session,
                ecosystem=ecosystem,
                name=retained,
                version="3.3.6",
            )
            assert evidence.fingerprint == exact.fingerprint


@pytest.mark.audit_ids("AUD-06")
def test_nuget_expression_indexes_support_actual_lookup_queries_and_generic_plans(
    database, contract_examples
) -> None:
    from smithguard.db.repository import append_contract
    from smithguard.normalization import normalize_artifact_identity
    from smithguard.query import public_artifact_candidates

    _append_match_document(database, _matching_github(ecosystem="nuget", name="Audit.Example"))
    artifact = deepcopy(
        next(value["value"] for value in contract_examples if value["definition"] == "Artifact")
    )
    identity = normalize_artifact_identity(
        {"ecosystem": "nuget", "name": "Audit.Example", "version": "3.3.6", "digest": None}
    )
    artifact.update(identity)
    artifact["id"] = stable_id("artifact", identity["coordinate"])
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Artifact", artifact)
    captured = []

    def capture(_connection, _cursor, statement, parameters, _context, _many):
        if statement.startswith(("SELECT", "WITH")):
            captured.append((statement, parameters))

    event.listen(database.engine, "before_cursor_execute", capture)
    try:
        with Session(database.engine) as session:
            catalog_evidence_for_package(
                session, ecosystem="nuget", name="audit.example", version="3.3.6"
            )
            public_artifact_candidates(
                session,
                ecosystem="nuget",
                normalized_name="audit.example",
                version="3.3.6",
                digest=None,
            )
    finally:
        event.remove(database.engine, "before_cursor_execute", capture)
    assert len(captured) == 2
    with database.engine.begin() as connection:
        # Small synthetic tables prefer sequential scans. This proves index eligibility,
        # not a production latency claim; use the actual statements emitted by both callers.
        connection.execute(text("SET LOCAL enable_seqscan = off"))
        for (statement, parameters), expected in zip(
            captured, ("ix_advisory_package_nuget_lookup", "ix_artifacts_nuget_lookup"), strict=True
        ):
            plan = connection.exec_driver_sql(
                "EXPLAIN (FORMAT JSON) " + statement, parameters
            ).scalar_one()
            assert expected in str(plan)
        connection.execute(text("SET LOCAL plan_cache_mode = force_generic_plan"))
        connection.exec_driver_sql(
            "PREPARE audmatch_lookup(text) AS SELECT package_event_id "
            "FROM smithguard.advisory_package_records WHERE ecosystem = 'nuget' "
            "AND translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') = $1"
        )
        try:
            plan = connection.exec_driver_sql(
                "EXPLAIN (FORMAT JSON) EXECUTE audmatch_lookup('audit.example')"
            ).scalar_one()
            assert "ix_advisory_package_nuget_lookup" in str(plan)
        finally:
            connection.exec_driver_sql("DEALLOCATE audmatch_lookup")


@pytest.mark.audit_ids("AUD-06")
def test_forward_nuget_indexes_preserve_existing_catalog_bytes_and_journal(
    postgres_cluster,
) -> None:
    from smithguard import __version__
    from smithguard.db.journal import record_migration_journal

    from .support import MIGRATION_JOURNAL, migrate, migrated_database

    handle = migrated_database(postgres_cluster, revision="0023_warning_receipt_indexes")
    try:
        _append_match_document(handle, _matching_github(ecosystem="nuget", name="Audit.Example"))
        with handle.engine.connect() as connection:
            before = (
                connection.execute(
                    text(
                        "SELECT row_to_json(p)::text FROM smithguard.advisory_package_records p "
                        "ORDER BY package_event_id"
                    )
                )
                .scalars()
                .all()
            )
            journal_before = (
                connection.execute(
                    text(
                        "SELECT row_to_json(j)::text FROM smithguard.migration_journal j "
                        "ORDER BY revision"
                    )
                )
                .scalars()
                .all()
            )
        migrate(handle.url, "0024_nuget_lookup_indexes")
        with Session(handle.engine) as session, session.begin():
            record_migration_journal(
                session,
                journal_path=MIGRATION_JOURNAL,
                app_version=__version__,
                through_revision="0024_nuget_lookup_indexes",
            )
        with handle.engine.connect() as connection:
            after = (
                connection.execute(
                    text(
                        "SELECT row_to_json(p)::text FROM smithguard.advisory_package_records p "
                        "ORDER BY package_event_id"
                    )
                )
                .scalars()
                .all()
            )
            journal_after = (
                connection.execute(
                    text(
                        "SELECT row_to_json(j)::text FROM smithguard.migration_journal j "
                        "WHERE revision != '0024_nuget_lookup_indexes' ORDER BY revision"
                    )
                )
                .scalars()
                .all()
            )
            assert before == after
            assert journal_before == journal_after
        # Runtime lookups require the current schema; the assertions above isolate 0024.
        migrate(handle.url, "head")
        with Session(handle.engine) as session:
            evidence = catalog_evidence_for_package(
                session, ecosystem="nuget", name="audit.example", version="3.3.6"
            )
            assert evidence.families[0].confidence == "confirmed"
    finally:
        handle.engine.dispose()


def test_openssf_catalog_range_verdicts_and_exact_version_union(database) -> None:
    document = _matching_openssf(version="3.0.0")
    document["affected"][0]["ranges"] = [
        {"type": "SEMVER", "events": [{"fixed": "2.0.0"}, {"introduced": "1.0.0"}]}
    ]
    _append_match_document(database, document, openssf=True)
    with Session(database.engine) as session:
        for version, expected in (("1.5.0", True), ("2.5.0", False), ("3.0.0", True)):
            matches = catalog_matches_for_package(
                session, ecosystem="npm", name="event-stream", version=version
            )
            assert matches[0].evaluations == (expected,)


def test_openssf_exact_version_dedup_preserves_projection_identity() -> None:
    from smithguard.advisory_catalog import _openssf_projection

    document = _matching_openssf()
    document["affected"][0]["versions"] = ["3.3.6", "1.0.0", "3.3.6", "1.0.0"]
    repeated = _openssf_projection(
        document, canonical_url="https://example.com/advisory", source_state="active"
    )
    document["affected"][0]["versions"] = ["3.3.6", "1.0.0"]
    unique = _openssf_projection(
        document, canonical_url="https://example.com/advisory", source_state="active"
    )
    assert repeated == unique


@pytest.mark.parametrize(
    ("source_ecosystem", "ecosystem", "registry", "name", "version"),
    [
        ("crates.io", "rust", "crates.io", "rustdecimal", "1.23.0"),
        ("Go", "go", "proxy.golang.org", "example.com/malware", "v1.2.3"),
    ],
)
def test_semver_malware_stays_affected_across_catalog_ecosystems(
    database, contract_examples, source_ecosystem, ecosystem, registry, name, version
) -> None:
    document = _matching_openssf()
    document["affected"] = [
        {
            "package": {"ecosystem": source_ecosystem, "name": name},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }
    ]
    _append_match_document(database, document, openssf=True)
    request = deepcopy(
        next(
            item["value"]
            for item in contract_examples
            if item["definition"] == "PublicArtifactAssessmentRequest"
        )
    )
    request["artifact"].update(
        ecosystem=ecosystem, registry_host=registry, name=name, version=version
    )
    with Session(database.engine) as session:
        body = SmithGuardService(clock=lambda: NOW).assess_public_artifact(session, request)
    assert body["result"] == "affected"
    assert body["incidents"][0]["classification"] == "malicious"


@pytest.mark.parametrize("reverse", [False, True])
def test_singleton_osv_range_has_exact_public_verdict(database, contract_examples, reverse) -> None:
    document = _matching_openssf()
    events = [{"introduced": "3.3.6"}, {"last_affected": "3.3.6"}]
    document["affected"][0]["versions"] = []
    document["affected"][0]["ranges"] = [
        {"type": "SEMVER", "events": list(reversed(events)) if reverse else events}
    ]
    _append_match_document(database, document, openssf=True)
    request = deepcopy(
        next(
            item["value"]
            for item in contract_examples
            if item["definition"] == "PublicArtifactAssessmentRequest"
        )
    )
    with Session(database.engine) as session:
        for version, expected in (
            ("3.3.5", "not_affected"),
            ("3.3.6", "affected"),
            ("3.3.7", "not_affected"),
        ):
            request["artifact"]["version"] = version
            body = SmithGuardService(clock=lambda: NOW).assess_public_artifact(session, request)
            assert body["result"] == expected


@pytest.mark.audit_ids("AUD-06")
@pytest.mark.parametrize("ecosystem", ["vscode", "open-vsx"])
def test_extension_lookup_ignores_publisher_and_name_case(database, ecosystem) -> None:
    """A known-malicious extension is found whatever case the caller uses."""
    value = _matching_openssf()
    value["affected"][0]["package"] = {
        "ecosystem": "VSCode" if ecosystem == "vscode" else "VSCode:https://open-vsx.org",
        "name": "EffetMer.darkgpt",
    }
    _append_match_document(database, value, openssf=True)
    with Session(database.engine) as session:
        for requested in ("EffetMer.darkgpt", "effetmer.darkgpt", "EFFETMER.DARKGPT"):
            evidence = catalog_evidence_for_package(
                session, ecosystem=ecosystem, name=requested, version="3.3.6"
            )
            assert evidence.families, requested


@pytest.mark.audit_ids("AUD-06")
@pytest.mark.parametrize(
    ("ecosystem", "retained", "requested", "advisory_index", "artifact_index"),
    [
        (
            "composer",
            "Audit/Example",
            "audit/example",
            "ix_advisory_package_casefold_lookup",
            "ix_artifacts_casefold_lookup",
        ),
        (
            "rust",
            "audit-example",
            "Audit_Example",
            "ix_advisory_package_rust_lookup",
            "ix_artifacts_rust_lookup",
        ),
    ],
)
def test_folded_lookup_indexes_serve_the_actual_queries(
    database, contract_examples, ecosystem, retained, requested, advisory_index, artifact_index
) -> None:
    from smithguard.db.repository import append_contract
    from smithguard.normalization import normalize_artifact_identity
    from smithguard.query import public_artifact_candidates

    _append_match_document(database, _matching_github(ecosystem=ecosystem, name=retained))
    artifact = deepcopy(
        next(value["value"] for value in contract_examples if value["definition"] == "Artifact")
    )
    identity = normalize_artifact_identity(
        {"ecosystem": ecosystem, "name": retained, "version": "3.3.6", "digest": None}
    )
    artifact.update(identity)
    artifact["id"] = stable_id("artifact", identity["coordinate"])
    with Session(database.engine) as session, session.begin():
        append_contract(session, "Artifact", artifact)
    captured = []

    def capture(_connection, _cursor, statement, parameters, _context, _many):
        if statement.startswith(("SELECT", "WITH")):
            captured.append((statement, parameters))

    event.listen(database.engine, "before_cursor_execute", capture)
    try:
        with Session(database.engine) as session:
            evidence = catalog_evidence_for_package(
                session, ecosystem=ecosystem, name=requested, version="3.3.6"
            )
            candidates = public_artifact_candidates(
                session,
                ecosystem=ecosystem,
                normalized_name=requested,
                version="3.3.6",
                digest=None,
            )
    finally:
        event.remove(database.engine, "before_cursor_execute", capture)
    assert evidence.families
    assert candidates
    assert len(captured) == 2
    with database.engine.begin() as connection:
        connection.execute(text("SET LOCAL enable_seqscan = off"))
        for (statement, parameters), expected in zip(
            captured, (advisory_index, artifact_index), strict=True
        ):
            plan = connection.exec_driver_sql(
                "EXPLAIN (FORMAT JSON) " + statement, parameters
            ).scalar_one()
            assert expected in str(plan)


@pytest.mark.parametrize("patch,expected", [("4.0.0", ("4.0.0",)), (None, ("3.3.7",))])
def test_explicit_github_patch_overrides_inferred_upper_bound(database, patch, expected):
    document = _github_event_stream()
    document["vulnerabilities"][0].update(
        vulnerable_version_range="< 3.3.7", first_patched_version=patch
    )
    _append_match_document(database, document)
    with Session(database.engine) as session:
        matches = catalog_matches_for_package(
            session, ecosystem="npm", name="event-stream", version="3.3.6"
        )
        assert matches[0].fixed_versions == expected
        assert matches[0].applies is True


@pytest.mark.parametrize("patch", ["", " 4.0.0", "4.0.0\n", "x" * 201, 4, {}, []])
def test_github_projection_rejects_invalid_patch_metadata(patch):
    from smithguard.advisory_catalog import _github_projection

    document = _github_event_stream()
    document["vulnerabilities"][0]["first_patched_version"] = patch
    with pytest.raises(AdvisoryCatalogError, match="first patched version"):
        _github_projection(document)


def test_openssf_omissions_preserve_supported_siblings_and_exact_history(database):
    from smithguard.source_accounting import catalog_omissions

    document = _matching_openssf()
    document["affected"].append(
        {
            "package": {"ecosystem": "FutureRegistry", "name": "example"},
            "versions": ["1.0"],
            "ranges": [],
        }
    )
    _append_match_document(database, document, openssf=True)
    _append_match_document(database, document, openssf=True)
    with Session(database.engine) as session:
        report = catalog_omissions(session, source="openssf")
        assert len(report["records"]) == 1
        old = report["records"][0]
        assert old["omissions"] == {"untyped_upstream_ecosystem": 1}
        assert session.query(AdvisoryPackageRecord).count() == 1
    document["affected"].pop()
    document["modified"] = "2026-08-31T01:00:00Z"
    _append_match_document(database, document, openssf=True)
    with Session(database.engine) as session:
        report = catalog_omissions(session, source="openssf")
        row = report["records"][0]
        assert row["catalog_event_id"] == old["catalog_event_id"]
        assert row["latest_catalog_event_id"] != old["catalog_event_id"]
        assert row["latest_omissions"] == {}
        assert row["omissions"] == {"untyped_upstream_ecosystem": 1}


@pytest.mark.parametrize("malformed", [False, True])
def test_openssf_package_less_git_is_counted_only_after_full_validation(malformed):
    from smithguard.advisory_catalog import _openssf_projection

    document = _matching_openssf()
    document["affected"] = [
        {
            "versions": ["v1.0.0", "release-candidate"],
            "ranges": [
                {
                    "type": "GIT",
                    "repo": "https://github.com/example/public",
                    "events": [{"introduced": 3 if malformed else "0"}],
                }
            ],
        }
    ]
    if malformed:
        with pytest.raises(AdvisoryCatalogError, match="event value"):
            _openssf_projection(
                document, canonical_url="https://example.com", source_state="active"
            )
    else:
        result = _openssf_projection(
            document, canonical_url="https://example.com", source_state="active"
        )
        assert result["packages"] == []
        assert result["package_omission_counts"] == {"unsupported_git_coordinate": 1}


def test_openssf_untyped_coordinate_does_not_hide_malformed_range():
    from smithguard.advisory_catalog import _openssf_projection

    document = _matching_openssf()
    document["affected"][0]["package"]["ecosystem"] = "FutureRegistry"
    document["affected"][0]["ranges"] = [{"type": "SEMVER", "events": "broken"}]
    with pytest.raises(AdvisoryCatalogError, match="range events"):
        _openssf_projection(document, canonical_url="https://example.com", source_state="active")
