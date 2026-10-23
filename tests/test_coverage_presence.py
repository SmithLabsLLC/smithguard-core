"""Equivalent coverage without historical full counts or source membership scans."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select, text, union_all
from sqlalchemy.orm import Session

from smithguard import __version__
from smithguard.advisory_catalog import OPENSSF_SOURCE_ID, append_github_advisory
from smithguard.collectors import GITHUB_ADVISORY
from smithguard.contracts.generated import Ecosystem
from smithguard.coverage import (
    COVERAGE_ECOSYSTEMS,
    _presence_by_ecosystem,
    _presence_query,
    _source_ecosystems,
    _source_ecosystems_query,
)
from smithguard.db.journal import record_migration_journal
from smithguard.db.models import (
    AdvisoryPackageRecord,
    AffectedRangeRecord,
    ArtifactRecord,
    ClaimRecord,
)
from smithguard.db.repository import append_contract
from smithguard.ecosystems import PURL_TYPE_BY_ECOSYSTEM, REGISTRY_HOSTS_BY_ECOSYSTEM
from smithguard.identifiers import stable_id

from .support import MIGRATION_JOURNAL, migrate, migrated_database

NOW = datetime(2026, 9, 6, 12, tzinfo=UTC)


def _example(examples, definition):
    return deepcopy(next(item["value"] for item in examples if item["definition"] == definition))


def _catalog(session, *, withdrawn=False):
    ghsa = "GHSA-2345-6789-cfgh"
    append_github_advisory(
        session,
        document={
            "ghsa_id": ghsa,
            "type": "reviewed",
            "published_at": "2026-09-01T00:00:00Z",
            "updated_at": "2026-09-02T00:00:00Z",
            "withdrawn_at": "2026-09-02T00:00:00Z" if withdrawn else None,
            "html_url": f"https://github.com/advisories/{ghsa}",
            "cwes": [],
            "identifiers": [{"type": "GHSA", "value": ghsa}],
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "synthetic"},
                    "vulnerable_version_range": "= 1.0.0",
                }
            ],
        },
        evidence_id="gbsec:evidence:coverage-presence",
        governance_decision_id="gbsec:governance:coverage-presence",
        observed_at=NOW,
    )


def _legacy_membership(session, source):
    claimed = (
        select(ArtifactRecord.ecosystem)
        .join(ClaimRecord, ClaimRecord.subject_id == ArtifactRecord.id)
        .where(
            ClaimRecord.provenance["source_id"].astext == source,
            ClaimRecord.data_classification == "public",
            ArtifactRecord.data_classification == "public",
        )
    )
    cataloged = select(AdvisoryPackageRecord.ecosystem).where(
        AdvisoryPackageRecord.source_id == source
    )
    combined = union_all(claimed, cataloged).subquery()
    return tuple(
        session.scalars(select(combined.c.ecosystem).distinct().order_by(combined.c.ecosystem))
    )


@pytest.mark.audit_ids("API-02")
def test_presence_matches_historical_count_predicates_and_unknown_source_membership(
    database,
    contract_examples,
) -> None:
    assert set(COVERAGE_ECOSYSTEMS) == {value.value for value in Ecosystem} - {"unknown"}
    # The lane order is served as an ordered array; it is pinned, not just its members.
    assert COVERAGE_ECOSYSTEMS == (
        "npm",
        "pypi",
        "github-actions",
        "oci",
        "docker",
        "go",
        "rust",
        "composer",
        "erlang",
        "git",
        "maven",
        "nuget",
        "open-vsx",
        "pub",
        "rubygems",
        "swift",
        "vscode",
    )
    # The same freeze guards the normalization purl map and the service registry map.
    frozen = {value.value for value in Ecosystem} - {"unknown"}
    assert set(REGISTRY_HOSTS_BY_ECOSYSTEM) == frozen
    verbatim_names = {"npm", "pypi", "github-actions", "oci", "docker"}
    assert set(PURL_TYPE_BY_ECOSYSTEM) | verbatim_names == frozen
    with Session(database.engine) as session, session.begin():
        for index, ecosystem in enumerate((*COVERAGE_ECOSYSTEMS, "unknown")):
            artifact = _example(contract_examples, "Artifact")
            artifact.update(
                id=stable_id("artifact", "coverage-presence", ecosystem),
                ecosystem=ecosystem,
                name=f"synthetic-{index}",
                coordinate=f"pkg:{ecosystem}/synthetic-{index}@1.0.0",
                version="1.0.0",
                digest=None if index % 2 else "sha256:" + "a" * 64,
            )
            append_contract(session, "Artifact", artifact)
            if index % 3:
                affected = _example(contract_examples, "AffectedRange")
                affected.update(
                    id=stable_id("affected-range", "coverage-presence", ecosystem),
                    artifact_id=artifact["id"],
                )
                append_contract(session, "AffectedRange", affected)
            claim = _example(contract_examples, "Claim")
            claim.update(
                id=stable_id("claim", "coverage-presence", ecosystem), subject_id=artifact["id"]
            )
            claim["provenance"]["source_id"] = GITHUB_ADVISORY
            append_contract(session, "Claim", claim)
            private_claim = deepcopy(claim)
            private_claim.update(
                id=stable_id("claim", "restricted-presence", ecosystem),
                data_classification="restricted_source",
            )
            private_claim["provenance"]["source_id"] = OPENSSF_SOURCE_ID
            append_contract(session, "Claim", private_claim)
        _catalog(session)
    with Session(database.engine) as session:
        actual = _presence_by_ecosystem(session)
        for ecosystem in COVERAGE_ECOSYSTEMS:
            artifacts, digests = session.execute(
                select(func.count(), func.count().filter(ArtifactRecord.digest.is_not(None))).where(
                    ArtifactRecord.ecosystem == ecosystem,
                    ArtifactRecord.data_classification == "public",
                )
            ).one()
            ranges = session.scalar(
                select(func.count())
                .select_from(AffectedRangeRecord)
                .join(ArtifactRecord, ArtifactRecord.id == AffectedRangeRecord.artifact_id)
                .where(
                    ArtifactRecord.ecosystem == ecosystem,
                    ArtifactRecord.data_classification == "public",
                    AffectedRangeRecord.data_classification == "public",
                )
            )
            catalog = session.scalar(
                select(func.count())
                .select_from(AdvisoryPackageRecord)
                .where(
                    AdvisoryPackageRecord.ecosystem == ecosystem,
                    AdvisoryPackageRecord.state == "active",
                )
            )
            assert actual[ecosystem].artifacts == bool(artifacts + catalog)
            assert actual[ecosystem].all_immutable == (digests == artifacts + catalog)
            assert actual[ecosystem].ranges == bool(ranges + catalog)
        for source in (
            GITHUB_ADVISORY,
            OPENSSF_SOURCE_ID,
            "gbsec:source:absent",
            "gbsec:source:absent'quoted\\source",
        ):
            assert _source_ecosystems(session, source) == _legacy_membership(session, source)
        assert "unknown" in _source_ecosystems(session, GITHUB_ADVISORY)
        assert _source_ecosystems(session, OPENSSF_SOURCE_ID) == ()


@pytest.mark.audit_ids("API-02")
def test_withdrawn_catalog_membership_is_preserved_without_active_coverage(database) -> None:
    with Session(database.engine) as session, session.begin():
        _catalog(session, withdrawn=True)
    with Session(database.engine) as session:
        assert _source_ecosystems(session, GITHUB_ADVISORY) == ("npm",)
        assert _source_ecosystems(session, GITHUB_ADVISORY) == _legacy_membership(
            session, GITHUB_ADVISORY
        )
        assert not _presence_by_ecosystem(session)["npm"].artifacts


@pytest.mark.audit_ids("API-02")
def test_actual_coverage_queries_and_generic_plans_can_use_the_new_indexes(database) -> None:
    with Session(database.engine) as session, session.begin():
        _catalog(session)
    with database.engine.connect() as connection:
        # Tiny fixtures need a sequential-scan preference override to test index
        # eligibility; this is not a production-latency measurement.
        connection.execute(text("SET LOCAL enable_seqscan = off"))
        for query, index in (
            (_presence_query(), "ix_advisory_package_active_ecosystem"),
            (_source_ecosystems_query(GITHUB_ADVISORY), "ix_advisory_package_ecosystem_source"),
        ):
            compiled = query.compile(connection, compile_kwargs={"render_postcompile": True})
            plan = connection.exec_driver_sql(
                "EXPLAIN (FORMAT JSON) " + str(compiled), compiled.params
            ).scalar_one()
            assert index in str(plan)
        connection.execute(text("SET LOCAL plan_cache_mode = force_generic_plan"))
        connection.exec_driver_sql(
            "PREPARE coverage_active(text) AS SELECT EXISTS(SELECT 1 FROM "
            "smithguard.advisory_package_records WHERE ecosystem=$1 AND state='active')"
        )
        connection.exec_driver_sql(
            "PREPARE coverage_source(text,text) AS SELECT (SELECT source_id FROM "
            "smithguard.advisory_package_records WHERE ecosystem=$1 AND source_id >= $2 "
            "ORDER BY source_id LIMIT 1) = $2"
        )
        try:
            assert "ix_advisory_package_active_ecosystem" in str(
                connection.exec_driver_sql(
                    "EXPLAIN (FORMAT JSON) EXECUTE coverage_active('npm')"
                ).scalar_one()
            )
            assert "ix_advisory_package_ecosystem_source" in str(
                connection.exec_driver_sql(
                    "EXPLAIN (FORMAT JSON) EXECUTE coverage_source('npm','gbsec:source:absent')"
                ).scalar_one()
            )
        finally:
            connection.exec_driver_sql("DEALLOCATE coverage_active")
            connection.exec_driver_sql("DEALLOCATE coverage_source")


@pytest.mark.audit_ids("API-02")
def test_forward_coverage_indexes_preserve_existing_rows_and_all_prior_journal_bytes(
    postgres_cluster,
) -> None:
    handle = migrated_database(postgres_cluster, revision="0024_nuget_lookup_indexes")
    try:
        with Session(handle.engine) as session, session.begin():
            _catalog(session)
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
            prior = (
                connection.execute(
                    text(
                        "SELECT row_to_json(j)::text FROM smithguard.migration_journal j "
                        "ORDER BY revision"
                    )
                )
                .scalars()
                .all()
            )
        migrate(handle.url, "0025_coverage_presence_indexes")
        with Session(handle.engine) as session, session.begin():
            record_migration_journal(
                session,
                journal_path=MIGRATION_JOURNAL,
                app_version=__version__,
                through_revision="0025_coverage_presence_indexes",
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
            retained = (
                connection.execute(
                    text(
                        "SELECT row_to_json(j)::text FROM smithguard.migration_journal j "
                        "WHERE revision != '0025_coverage_presence_indexes' ORDER BY revision"
                    )
                )
                .scalars()
                .all()
            )
        assert before == after
        assert prior == retained
    finally:
        handle.engine.dispose()
