"""Migration source journal integrity checks."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
import time
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest
from sqlalchemy import CheckConstraint, create_engine, func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from smithguard import __version__
from smithguard.db.journal import (
    MigrationJournalError,
    file_sha256,
    load_migration_journal,
    record_migration_journal,
)
from smithguard.db.models import (
    ArtifactRecord,
    MigrationJournalRecord,
    SnapshotManifestRecord,
)
from smithguard.db.repository import append_contract
from smithguard.migration_runtime import (
    MigrationRuntimeError,
    migrate_and_record,
)
from tools.migration_journal import migration_entry

from .support import MIGRATION_JOURNAL, LocalPostgres, migrate, migrated_database

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
MIGRATION_BOOTSTRAP = PACKAGE_ROOT / "deploy/postgresql/prepare-migration-role.sql"
ROLE_GRANTS = PACKAGE_ROOT / "deploy/postgresql/roles-and-grants.sql"
LEGACY_ROLE = "smithguard"
MAINTENANCE_ROLE = "smithguard-maintenance"
ORDINARY_ROLES = (
    "smithguard-api",
    "smithguard-collector",
    "smithguard-signals",
    "smithguard-health",
)
NOW = datetime(2026, 8, 12, 12, tzinfo=UTC)
LEGACY_SCHEMA_NAME = "goodboy_security"
LEGACY_WATCHLISTS_SCHEMA_NAME = "goodboy_hosted_watch"


def _admin_connection(url):
    query = url.query
    return psycopg.connect(
        host=str(query["host"]),
        port=int(query["port"]),
        user="postgres",
        dbname="smithguard",
        autocommit=True,
    )


def _release_migration_files(tmp_path: Path) -> tuple[Path, Path]:
    release_package = tmp_path / "release/app"
    release_package.mkdir(parents=True)
    release_config = Path(shutil.copy2(PACKAGE_ROOT / "alembic.ini", release_package))
    shutil.copytree(PACKAGE_ROOT / "migrations", release_package / "migrations")
    release_journal = release_package / "migrations/journal.json"
    release_config.chmod(0o644)
    release_journal.chmod(0o644)
    return release_config, release_journal


def _make_revision_seven_legacy_owned(url) -> None:
    migrate(url, "0007_cpbeta1")
    engine = create_engine(url, hide_parameters=True)
    try:
        legacy_engine = engine.execution_options(
            schema_translate_map={
                "smithguard": LEGACY_SCHEMA_NAME,
                "smithguard_private_watchlists": LEGACY_WATCHLISTS_SCHEMA_NAME,
            }
        )
        with Session(legacy_engine) as session, session.begin():
            record_migration_journal(
                session,
                journal_path=MIGRATION_JOURNAL,
                app_version=__version__,
                through_revision="0007_cpbeta1",
            )
    finally:
        engine.dispose()

    with _admin_connection(url) as connection:
        connection.execute(
            """
            DO $legacy_role$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles
                    WHERE rolname = 'smithguard'
                ) THEN
                    CREATE ROLE "smithguard" LOGIN;
                END IF;
            END
            $legacy_role$
            """
        )
        connection.execute('ALTER DATABASE smithguard OWNER TO "smithguard"')
        connection.execute(
            """
            DO $legacy_objects$
            DECLARE
                item record;
            BEGIN
                FOR item IN
                    SELECT n.nspname AS schemaname, c.relname, c.relkind
                    FROM pg_catalog.pg_class AS c
                    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                    WHERE (
                            n.nspname IN (
                                'goodboy_security',
                                'goodboy_hosted_watch'
                            )
                            OR (
                                n.nspname = 'public'
                                AND c.relname = 'alembic_version'
                            )
                        )
                      AND c.relkind IN ('r', 'p', 'S')
                    ORDER BY n.nspname, c.relname
                LOOP
                    IF item.relkind = 'S' THEN
                        EXECUTE format(
                            'ALTER SEQUENCE %I.%I OWNER TO %I',
                            item.schemaname,
                            item.relname,
                            'smithguard'
                        );
                    ELSE
                        EXECUTE format(
                            'ALTER TABLE %I.%I OWNER TO %I',
                            item.schemaname,
                            item.relname,
                            'smithguard'
                        );
                    END IF;
                END LOOP;
                FOR item IN
                    SELECT
                        n.nspname AS schemaname,
                        p.proname,
                        pg_get_function_identity_arguments(p.oid) AS args
                    FROM pg_catalog.pg_proc AS p
                    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE n.nspname IN (
                        'goodboy_security',
                        'goodboy_hosted_watch'
                    )
                      AND p.prokind IN ('f', 'p')
                LOOP
                    EXECUTE format(
                        'ALTER ROUTINE %I.%I(%s) OWNER TO %I',
                        item.schemaname,
                        item.proname,
                        item.args,
                        'smithguard'
                    );
                END LOOP;
            END
            $legacy_objects$
            """
        )
        connection.execute('ALTER SCHEMA goodboy_security OWNER TO "smithguard"')
        connection.execute('ALTER SCHEMA goodboy_hosted_watch OWNER TO "smithguard"')


def _application_owners(url) -> tuple[tuple[str, str, str, str], ...]:
    with _admin_connection(url) as connection:
        rows = connection.execute(
            """
            SELECT
                n.nspname,
                c.relname,
                c.relkind::text,
                pg_get_userbyid(c.relowner)
            FROM pg_catalog.pg_class AS c
            JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname IN ('goodboy_security', 'goodboy_hosted_watch')
               OR (
                   n.nspname = 'public'
                   AND c.relname = 'alembic_version'
                   AND c.relkind IN ('r', 'p')
               )
            UNION ALL
            SELECT
                n.nspname,
                '<schema>',
                'n',
                pg_get_userbyid(n.nspowner)
            FROM pg_catalog.pg_namespace AS n
            WHERE n.nspname IN ('goodboy_security', 'goodboy_hosted_watch')
            UNION ALL
            SELECT
                n.nspname,
                p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
                p.prokind::text,
                pg_get_userbyid(p.proowner)
            FROM pg_catalog.pg_proc AS p
            JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
            WHERE n.nspname IN ('goodboy_security', 'goodboy_hosted_watch')
            ORDER BY 1, 2, 3, 4
            """
        ).fetchall()
    return tuple(rows)


def _database_owner(url) -> str:
    with _admin_connection(url) as connection:
        owner = connection.execute(
            """
            SELECT pg_get_userbyid(datdba)
            FROM pg_catalog.pg_database
            WHERE datname = 'smithguard'
            """
        ).fetchone()
    assert owner is not None
    return str(owner[0])


def test_committed_migration_journal_matches_sources() -> None:
    journal = load_migration_journal(MIGRATION_JOURNAL)
    assert journal["migrations"] == [
        {
            "description": "Create CP-0B1 ledger foundation",
            "down_revision": None,
            "file": "versions/0001_cp0b1_create_cp_0b1_ledger_foundation.py",
            "revision": "0001_cp0b1",
            "rollback_mode": "safe_to_zero",
            "source_sha256": journal["migrations"][0]["source_sha256"],
        },
        {
            "description": "Create CP-0B2 ingestion, lifecycle, and audit state",
            "down_revision": "0001_cp0b1",
            "file": "versions/0002_cp0b2_create_ingestion_lifecycle_audit.py",
            "revision": "0002_cp0b2",
            "rollback_mode": "safe_to_zero",
            "source_sha256": journal["migrations"][1]["source_sha256"],
        },
        {
            "description": "Create CP-1 feed, review, source, and spend state",
            "down_revision": "0002_cp0b2",
            "file": "versions/0003_cp1_create_feed_review_spend.py",
            "revision": "0003_cp1",
            "rollback_mode": "safe_to_zero",
            "source_sha256": journal["migrations"][2]["source_sha256"],
        },
        {
            "description": "Allow the CP-2B signed public-knowledge snapshot version",
            "down_revision": "0003_cp1",
            "file": "versions/0004_cp2b_expand_snapshot_manifest_version.py",
            "revision": "0004_cp2b",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][3]["source_sha256"],
        },
        {
            "description": "Create CP-3A event and disabled delivery foundation",
            "down_revision": "0004_cp2b",
            "file": "versions/0005_cp3a_create_delivery_foundation.py",
            "revision": "0005_cp3a",
            "rollback_mode": "safe_to_zero",
            "source_sha256": journal["migrations"][4]["source_sha256"],
        },
        {
            "description": "Create disabled synthetic Hosted Watch boundary",
            "down_revision": "0005_cp3a",
            "file": "versions/0006_cphw_create_synthetic_hosted_watch.py",
            "revision": "0006_cphw",
            "rollback_mode": "safe_to_zero",
            "source_sha256": journal["migrations"][5]["source_sha256"],
        },
        {
            "description": (
                "Create append-only collection progress, source linkage, and warning archives"
            ),
            "down_revision": "0006_cphw",
            "file": ("versions/0007_cpbeta1_create_preliminary_warning_archive.py"),
            "revision": "0007_cpbeta1",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][6]["source_sha256"],
        },
        {
            "description": ("Create append-only malware authority decisions and incident lineage"),
            "down_revision": "0007_cpbeta1",
            "file": "versions/0008_mx002_create_malware_authority.py",
            "revision": "0008_mx002",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][7]["source_sha256"],
        },
        {
            "description": "Generalize disabled Hosted Watch rows into Watch Targets",
            "down_revision": "0008_mx002",
            "file": "versions/0009_mx003_generalize_watch_targets.py",
            "revision": "0009_mx003",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][8]["source_sha256"],
        },
        {
            "description": (
                "Create append-only source governance, publication lifecycle, "
                "and reconciliation state"
            ),
            "down_revision": "0009_mx003",
            "file": ("versions/0010_mx005_create_source_governance_lifecycle.py"),
            "revision": "0010_mx005",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][9]["source_sha256"],
        },
        {
            "description": (
                "Create recoverable evidence finalization and bounded ingestion retry state"
            ),
            "down_revision": "0010_mx005",
            "file": "versions/0011_mx006_create_recoverable_ingestion.py",
            "revision": "0011_mx006",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][10]["source_sha256"],
        },
        {
            "description": "Index bounded public incident artifact correlation",
            "down_revision": "0011_mx006",
            "file": "versions/0012_mx014_index_public_incident_artifacts.py",
            "revision": "0012_mx014",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][11]["source_sha256"],
        },
        {
            "description": "Rename live schemas and disabled watchlist contract values",
            "down_revision": "0012_mx014",
            "file": "versions/0013_watch_rebrand_runtime_names.py",
            "revision": "0013_watch_rebrand",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][12]["source_sha256"],
        },
        {
            "description": "Create append-only cross-source correlation shadow state",
            "down_revision": "0013_watch_rebrand",
            "file": "versions/0014_next001_create_correlation_foundation.py",
            "revision": "0014_next001",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][13]["source_sha256"],
        },
        {
            "description": (
                "Create append-only gateway governance and correlation rehearsal state"
            ),
            "down_revision": "0014_next001",
            "file": "versions/0015_next004_shadow_transport_governance.py",
            "revision": "0015_next004_shadow",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][14]["source_sha256"],
        },
        {
            "description": ("Accept owner-authorized model review in private shadow samples"),
            "down_revision": "0015_next004_shadow",
            "file": "versions/0016_next004_owner_review_basis_compatibility.py",
            "revision": "0016_next004_owner_basis",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][15]["source_sha256"],
        },
        {
            "description": (
                "Bind private public-fixture rehearsals to finalized review provenance"
            ),
            "down_revision": "0016_next004_owner_basis",
            "file": "versions/0017_next004_rehearsal_provenance.py",
            "revision": "0017_next004_provenance",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][16]["source_sha256"],
        },
        {
            "description": (
                "Allow one-origin Emerging/Unverified warning qualification and schema 1.1"
            ),
            "down_revision": "0017_next004_provenance",
            "file": "versions/0018_grok_audit_warning_origins.py",
            "revision": "0018_grok_audit_warning_origins",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][17]["source_sha256"],
        },
        {
            "description": "Rename the live GoodBoy Watch schemas for SmithGuard",
            "down_revision": "0018_grok_audit_warning_origins",
            "file": "versions/0019_smithguard_rebrand.py",
            "revision": "0019_smithguard_rebrand",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][18]["source_sha256"],
        },
        {
            "description": "Add complete GitHub and OpenSSF advisory catalog storage",
            "down_revision": "0019_smithguard_rebrand",
            "file": "versions/0020_full_advisory_catalog.py",
            "revision": "0020_full_advisory_catalog",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][19]["source_sha256"],
        },
        {
            "description": ("Protect complete advisory catalog history and migration evidence"),
            "down_revision": "0020_full_advisory_catalog",
            "file": "versions/0021_advisory_catalog_append_only.py",
            "revision": "0021_catalog_append_only",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][20]["source_sha256"],
        },
        {
            "description": "Index claim provenance and serialize checkpoint identities",
            "down_revision": "0021_catalog_append_only",
            "file": "versions/0022_claims_source_index.py",
            "revision": "0022_claims_source_index",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][21]["source_sha256"],
        },
        {
            "description": "Bound warning receipts and acknowledge dead letters",
            "down_revision": "0022_claims_source_index",
            "file": "versions/0023_warning_lane_receipt_indexes.py",
            "revision": "0023_warning_receipt_indexes",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][22]["source_sha256"],
        },
        {
            "description": "Index compatible NuGet package lookup preserving retained identities",
            "down_revision": "0023_warning_receipt_indexes",
            "file": "versions/0024_nuget_lookup_indexes.py",
            "revision": "0024_nuget_lookup_indexes",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][23]["source_sha256"],
        },
        {
            "description": "Index coverage presence and retained source ecosystem membership",
            "down_revision": "0024_nuget_lookup_indexes",
            "file": "versions/0025_coverage_presence_indexes.py",
            "revision": "0025_coverage_presence_indexes",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][24]["source_sha256"],
        },
        {
            "description": "Retire the spend ledger and the recheck exact-cost column",
            "down_revision": "0025_coverage_presence_indexes",
            "file": "versions/0026_retire_spend_ledger.py",
            "revision": "0026_retire_spend_ledger",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][25]["source_sha256"],
        },
        {
            "description": "Add append-only emerging lead lifecycle and bounded public projection",
            "down_revision": "0026_retire_spend_ledger",
            "file": "versions/0027_emerging_leads.py",
            "revision": "0027_emerging_leads",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][26]["source_sha256"],
        },
        {
            "description": (
                "Index case-insensitive package lookup for extension, Composer and crate names"
            ),
            "down_revision": "0027_emerging_leads",
            "file": "versions/0028_casefold_lookup_indexes.py",
            "revision": "0028_casefold_lookup_indexes",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][27]["source_sha256"],
        },
        {
            "description": "Keep final warning-lane provider output privately for 30 days",
            "down_revision": "0028_casefold_lookup_indexes",
            "file": "versions/0029_warning_lane_outputs.py",
            "revision": "0029_warning_lane_outputs",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][28]["source_sha256"],
        },
        {
            "description": "Drop eighteen empty tables of retired features",
            "down_revision": "0029_warning_lane_outputs",
            "file": "versions/0030_drop_unused_tables.py",
            "revision": "0030_drop_unused_tables",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][29]["source_sha256"],
        },
        {
            "description": "Add immutable exact-CVE context and direct Rust/Go source snapshots",
            "down_revision": "0030_drop_unused_tables",
            "file": "versions/0031_supplemental_feeds.py",
            "revision": "0031_supplemental_feeds",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][30]["source_sha256"],
        },
        {
            "description": "Add immutable collection record accounting and resolutions",
            "down_revision": "0031_supplemental_feeds",
            "file": "versions/0032_record_accounting.py",
            "revision": "0032_record_accounting",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][31]["source_sha256"],
        },
        {
            "description": (
                "Share future supplemental payloads without rewriting historical receipts"
            ),
            "down_revision": "0032_record_accounting",
            "file": "versions/0033_supplemental_payloads.py",
            "revision": "0033_supplemental_payloads",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][32]["source_sha256"],
        },
        {
            "description": (
                "Add bounded bulletin projections and immutable intake/publication evidence"
            ),
            "down_revision": "0033_supplemental_payloads",
            "file": "versions/0034_public_bulletins.py",
            "revision": "0034_public_bulletins",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][33]["source_sha256"],
        },
        {
            "description": "Add private bulletin automation evidence and identity protection",
            "down_revision": "0034_public_bulletins",
            "file": "versions/0035_bulletin_automation.py",
            "revision": "0035_bulletin_automation",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][34]["source_sha256"],
        },
        {
            "description": "Allow source update events without rewriting historical evidence",
            "down_revision": "0035_bulletin_automation",
            "file": "versions/0036_bulletin_source_updates.py",
            "revision": "0036_bulletin_source_updates",
            "rollback_mode": "forward_only",
            "source_sha256": journal["migrations"][35]["source_sha256"],
        },
    ]
    assert journal["migrations"][0]["source_sha256"].startswith("sha256:")


def test_claim_source_index_and_checkpoint_sequence_exist_at_head(database) -> None:
    with database.engine.connect() as connection:
        index_definition = connection.scalar(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE schemaname = 'smithguard' "
                "AND indexname = 'ix_claims_provenance_source_id'"
            )
        )
        sequence_exists = connection.scalar(
            text("SELECT to_regclass('smithguard.collector_checkpoint_sequence') IS NOT NULL")
        )
    assert "provenance ->> 'source_id'" in index_definition
    assert sequence_exists is True


def test_cp2b_schema_version_change_is_limited_to_snapshot_manifests() -> None:
    snapshot_constraints = {
        constraint.name: str(constraint.sqltext)
        for constraint in SnapshotManifestRecord.__table__.constraints
        if isinstance(constraint, CheckConstraint)
    }
    artifact_constraints = {
        constraint.name: str(constraint.sqltext)
        for constraint in ArtifactRecord.__table__.constraints
        if isinstance(constraint, CheckConstraint)
    }
    assert snapshot_constraints["ck_snapshot_manifests_schema_version"] == (
        "schema_version IN ('1.0.0', '1.1.0', '1.2.0')"
    )
    assert artifact_constraints["ck_artifacts_schema_version"] == "schema_version = '1.0.0'"


def test_owner_review_basis_migration_changes_only_the_closed_database_check(
    postgres_cluster: LocalPostgres,
) -> None:
    handle = migrated_database(
        postgres_cluster,
        journal=False,
        revision="0015_next004_shadow",
    )
    insert_sample = text(
        """
        INSERT INTO goodboy_watch.correlation_shadow_samples (
            sample_id,
            run_id,
            ordinal,
            left_observation_id,
            right_observation_id,
            expected_relation,
            proposed_relation,
            reason_codes,
            independent_origin_count,
            copied_transport,
            conflict_observed,
            review_basis,
            record_hash
        ) VALUES (
            :sample_id,
            :run_id,
            1,
            :left_observation_id,
            :right_observation_id,
            'no_candidate',
            'no_candidate',
            '[]'::jsonb,
            1,
            false,
            false,
            :review_basis,
            :record_hash
        )
        """
    )

    def values(suffix: str, review_basis: str) -> dict[str, str]:
        return {
            "sample_id": f"gbsec:shadow-sample:{suffix}",
            "run_id": f"gbsec:shadow-run:{suffix}",
            "left_observation_id": f"gbsec:observation:{suffix}:a",
            "right_observation_id": f"gbsec:observation:{suffix}:b",
            "review_basis": review_basis,
            "record_hash": "sha256:" + "a" * 64,
        }

    try:
        with handle.engine.connect() as connection:
            old_definition = connection.scalar(
                text(
                    """
                    SELECT pg_get_constraintdef(oid)
                    FROM pg_catalog.pg_constraint
                    WHERE conname = 'ck_correlation_shadow_samples_review_basis'
                    """
                )
            )
        assert old_definition is not None
        assert "owner_authorized_model_review" not in old_definition

        # Disable only foreign-key and append-only triggers in this disposable database
        # so the CHECK can be tested without manufacturing unrelated ledger parents.
        with handle.engine.begin() as connection:
            connection.execute(text("SET LOCAL session_replication_role = replica"))
            connection.execute(insert_sample, values("existing", "human_review"))
        with (
            pytest.raises(DBAPIError, match="review_basis"),
            handle.engine.begin() as connection,
        ):
            connection.execute(text("SET LOCAL session_replication_role = replica"))
            connection.execute(
                insert_sample,
                values("old-rejected", "owner_authorized_model_review"),
            )

        migrate(handle.url, "0016_next004_owner_basis")

        with handle.engine.connect() as connection:
            assert (
                connection.scalar(text("SELECT version_num FROM public.alembic_version"))
                == "0016_next004_owner_basis"
            )
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM goodboy_watch.correlation_shadow_samples")
                )
                == 1
            )
            new_definition = connection.scalar(
                text(
                    """
                    SELECT pg_get_constraintdef(oid)
                    FROM pg_catalog.pg_constraint
                    WHERE conname = 'ck_correlation_shadow_samples_review_basis'
                    """
                )
            )
        assert new_definition is not None
        for review_basis in (
            "synthetic_fixture",
            "exact_source_identity",
            "human_review",
            "owner_authorized_model_review",
        ):
            assert review_basis in new_definition
        with handle.engine.connect() as connection:
            preserved = connection.execute(
                text(
                    """
                    SELECT review_basis, record_hash
                    FROM goodboy_watch.correlation_shadow_samples
                    WHERE sample_id = 'gbsec:shadow-sample:existing'
                    """
                )
            ).one()
        assert preserved == ("human_review", "sha256:" + "a" * 64)

        with handle.engine.begin() as connection:
            connection.execute(text("SET LOCAL session_replication_role = replica"))
            connection.execute(
                insert_sample,
                values("new-accepted", "owner_authorized_model_review"),
            )
        with (
            pytest.raises(DBAPIError, match="review_basis"),
            handle.engine.begin() as connection,
        ):
            connection.execute(text("SET LOCAL session_replication_role = replica"))
            connection.execute(insert_sample, values("invalid", "unreviewed_model_guess"))
    finally:
        handle.engine.dispose()


def test_migration_journal_generator_check() -> None:
    result = subprocess.run(
        [sys.executable, str(PACKAGE_ROOT / "tools/migration_journal.py")],
        cwd=PACKAGE_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "migration journal is current"


def test_changed_migration_source_is_rejected(tmp_path: Path) -> None:
    copied = tmp_path / "migrations"
    shutil.copytree(PACKAGE_ROOT / "migrations", copied)
    migration = copied / "versions/0001_cp0b1_create_cp_0b1_ledger_foundation.py"
    migration.write_text(
        migration.read_text(encoding="utf-8") + "\n# changed\n",
        encoding="utf-8",
    )
    with pytest.raises(MigrationJournalError, match="checksum mismatch"):
        load_migration_journal(copied / "journal.json")


def test_migration_journal_rejects_a_noncontiguous_revision_chain(tmp_path: Path) -> None:
    copied = tmp_path / "migrations"
    shutil.copytree(PACKAGE_ROOT / "migrations", copied)
    journal_path = copied / "journal.json"
    journal = json.loads(journal_path.read_text(encoding="ascii"))
    journal["migrations"][1]["down_revision"] = None
    journal_path.write_text(
        json.dumps(journal, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    with pytest.raises(MigrationJournalError, match="chain is not contiguous"):
        load_migration_journal(journal_path)


def test_future_migration_must_declare_rollback_metadata(tmp_path: Path) -> None:
    migration = tmp_path / "0002_missing_metadata.py"
    migration.write_text(
        'revision: str = "0002_missing_metadata"\ndown_revision: str | None = "0001_cp0b1"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="migration_description"):
        migration_entry(migration)


def test_database_journal_conflicts_and_mutations_fail_closed(
    postgres_cluster: LocalPostgres,
) -> None:
    handle = migrated_database(postgres_cluster, journal=False)
    entry = load_migration_journal(MIGRATION_JOURNAL)["migrations"][0]
    try:
        with Session(handle.engine) as session, session.begin():
            session.add(
                MigrationJournalRecord(
                    revision=entry["revision"],
                    source_sha256=entry["source_sha256"],
                    description="conflicting description",
                    rollback_mode=entry["rollback_mode"],
                    app_version=__version__,
                )
            )
        with (
            Session(handle.engine) as session,
            session.begin(),
            pytest.raises(MigrationJournalError, match="conflicts with source"),
        ):
            record_migration_journal(
                session,
                journal_path=MIGRATION_JOURNAL,
                app_version=__version__,
            )
        with (
            pytest.raises(DBAPIError, match="append-only"),
            handle.engine.begin() as connection,
        ):
            connection.execute(update(MigrationJournalRecord).values(description="mutated"))
    finally:
        handle.engine.dispose()


def test_database_journal_can_stop_at_an_exact_reviewed_revision(
    postgres_cluster: LocalPostgres,
) -> None:
    handle = migrated_database(
        postgres_cluster,
        journal=False,
        revision="0013_watch_rebrand",
    )
    try:
        with Session(handle.engine) as session, session.begin():
            record_migration_journal(
                session,
                journal_path=MIGRATION_JOURNAL,
                app_version=__version__,
                through_revision="0013_watch_rebrand",
            )
        with handle.engine.connect() as connection:
            revisions = tuple(
                connection.scalars(
                    text("SELECT revision FROM goodboy_watch.migration_journal ORDER BY revision")
                )
            )
        assert revisions[-1] == "0013_watch_rebrand"
        assert "0014_next001" not in revisions
        assert "0015_next004_shadow" not in revisions
        assert "0016_next004_owner_basis" not in revisions
        assert "0017_next004_provenance" not in revisions
        assert "0018_grok_audit_warning_origins" not in revisions
        assert "0019_smithguard_rebrand" not in revisions
    finally:
        handle.engine.dispose()


def test_database_journal_rejects_an_unknown_target_before_writing(
    postgres_cluster: LocalPostgres,
) -> None:
    handle = migrated_database(postgres_cluster, journal=False)
    try:
        with (
            Session(handle.engine) as session,
            session.begin(),
            pytest.raises(MigrationJournalError, match="does not contain target revision"),
        ):
            record_migration_journal(
                session,
                journal_path=MIGRATION_JOURNAL,
                app_version=__version__,
                through_revision="9999_unknown",
            )
        with Session(handle.engine) as session:
            assert session.scalar(select(func.count()).select_from(MigrationJournalRecord)) == 0
    finally:
        handle.engine.dispose()


def test_database_journal_rejects_a_target_that_is_not_applied(
    postgres_cluster: LocalPostgres,
) -> None:
    handle = migrated_database(
        postgres_cluster,
        journal=False,
        revision="0013_watch_rebrand",
    )
    try:
        with (
            Session(handle.engine) as session,
            session.begin(),
            pytest.raises(MigrationJournalError, match="database revision does not match"),
        ):
            record_migration_journal(
                session,
                journal_path=MIGRATION_JOURNAL,
                app_version=__version__,
                through_revision="0012_mx014",
            )
        with handle.engine.connect() as connection:
            assert (
                connection.scalar(text("SELECT count(*) FROM goodboy_watch.migration_journal")) == 0
            )
    finally:
        handle.engine.dispose()


def test_one_maintenance_command_migrates_and_records_the_verified_journal(
    postgres_cluster: LocalPostgres,
    tmp_path: Path,
) -> None:
    url = postgres_cluster.create_database(name="smithguard")
    query = url.query
    engine = None
    try:
        with psycopg.connect(
            host=str(query["host"]),
            port=int(query["port"]),
            user="postgres",
            dbname="smithguard",
            autocommit=True,
        ) as connection:
            connection.execute(MIGRATION_BOOTSTRAP.read_text(encoding="ascii"))
        assert _database_owner(url) == "postgres"

        maintenance_url = url.set(username="smithguard-maintenance")
        release_config, release_journal = _release_migration_files(tmp_path)
        migrate_and_record(
            database_url=maintenance_url.render_as_string(hide_password=False),
            alembic_config_path=release_config,
            journal_path=release_journal,
        )

        engine = create_engine(maintenance_url, hide_parameters=True)
        with engine.connect() as connection:
            assert (
                connection.scalar(text("SELECT version_num FROM public.alembic_version"))
                == "0036_bulletin_source_updates"
            )
            assert connection.scalar(
                text("SELECT count(*) FROM smithguard.migration_journal")
            ) == len(load_migration_journal(MIGRATION_JOURNAL)["migrations"])
            notes = connection.scalar(
                text(
                    "SELECT notes FROM smithguard.migration_journal "
                    "WHERE revision = '0036_bulletin_source_updates'"
                )
            )
            assert notes == {"backup_restore_policy": "not_required_by_owner_20260911"}

        migrate_and_record(
            database_url=maintenance_url.render_as_string(hide_password=False),
            alembic_config_path=release_config,
            journal_path=release_journal,
        )
        with engine.connect() as connection:
            replayed_notes = connection.scalar(
                text(
                    "SELECT notes FROM smithguard.migration_journal "
                    "WHERE revision = '0036_bulletin_source_updates'"
                )
            )
        assert replayed_notes == notes
    finally:
        if engine is not None:
            engine.dispose()
        postgres_cluster.drop_database("smithguard")


def test_later_head_preserves_prior_migration_recovery_notes(
    postgres_cluster: LocalPostgres,
    tmp_path: Path,
) -> None:
    handle = migrated_database(postgres_cluster, journal=False)
    prior_notes = {"backup_manifest_sha256": "sha256:" + "b" * 64}
    future_notes = {"backup_restore_policy": "not_required_by_owner_20260911"}
    future_root = tmp_path / "future-migrations"
    shutil.copytree(PACKAGE_ROOT / "migrations", future_root)
    future_source = future_root / "versions/0037_test_notes.py"
    future_source.write_text(
        'revision: str = "0037_test_notes"\n'
        'down_revision: str | None = "0036_bulletin_source_updates"\n'
        'migration_description: str = "Test later migration notes"\n'
        'rollback_mode: str = "forward_only"\n',
        encoding="ascii",
    )
    future_journal = future_root / "journal.json"
    future_document = json.loads(future_journal.read_text(encoding="ascii"))
    future_document["migrations"].append(
        {
            "revision": "0037_test_notes",
            "down_revision": "0036_bulletin_source_updates",
            "file": "versions/0037_test_notes.py",
            "source_sha256": file_sha256(future_source),
            "description": "Test later migration notes",
            "rollback_mode": "forward_only",
        }
    )
    future_journal.write_text(
        json.dumps(future_document, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    try:
        with Session(handle.engine) as session, session.begin():
            record_migration_journal(
                session,
                journal_path=MIGRATION_JOURNAL,
                app_version=__version__,
                target_notes=prior_notes,
            )
        with handle.engine.begin() as connection:
            connection.execute(
                text("UPDATE public.alembic_version SET version_num = '0037_test_notes'")
            )
        with Session(handle.engine) as session, session.begin():
            record_migration_journal(
                session,
                journal_path=future_journal,
                app_version=__version__,
                target_notes=future_notes,
            )
        with handle.engine.connect() as connection:
            notes = {
                row.revision: row.notes
                for row in connection.execute(
                    text(
                        "SELECT revision, notes FROM smithguard.migration_journal "
                        "WHERE revision IN "
                        "('0036_bulletin_source_updates', '0037_test_notes')"
                    )
                )
            }
        assert notes == {
            "0036_bulletin_source_updates": prior_notes,
            "0037_test_notes": future_notes,
        }
    finally:
        handle.engine.dispose()


def test_restored_revision_0018_migrates_to_smithguard_without_rewriting_evidence(
    postgres_cluster: LocalPostgres,
    tmp_path: Path,
    contract_examples: list[dict[str, object]],
) -> None:
    handle = migrated_database(
        postgres_cluster,
        name="smithguard",
        revision="0018_grok_audit_warning_origins",
    )
    source_document = deepcopy(
        next(entry["value"] for entry in contract_examples if entry["definition"] == "Source")
    )
    legacy_engine = handle.engine.execution_options(
        schema_translate_map={
            "smithguard": "goodboy_watch",
            "smithguard_private_watchlists": "goodboy_private_watchlists",
        }
    )
    try:
        with Session(legacy_engine) as session, session.begin():
            append_contract(session, "Source", source_document)
        with handle.engine.connect() as connection:
            before = connection.execute(
                text("SELECT id, revision, record_hash, document FROM goodboy_watch.sources")
            ).one()
            assert (
                connection.scalar(text("SELECT count(*) FROM goodboy_watch.migration_journal"))
                == 18
            )

        with _admin_connection(handle.url) as connection:
            connection.execute(MIGRATION_BOOTSTRAP.read_text(encoding="ascii"))

        release_config, release_journal = _release_migration_files(tmp_path)
        maintenance_url = handle.url.set(username=MAINTENANCE_ROLE)
        migrate_and_record(
            database_url=maintenance_url.render_as_string(hide_password=False),
            alembic_config_path=release_config,
            journal_path=release_journal,
        )

        with create_engine(maintenance_url, hide_parameters=True).connect() as connection:
            after = connection.execute(
                text("SELECT id, revision, record_hash, document FROM smithguard.sources")
            ).one()
            assert after == before
            assert connection.scalar(
                text("SELECT count(*) FROM smithguard.migration_journal")
            ) == len(load_migration_journal(MIGRATION_JOURNAL)["migrations"])
            assert (
                connection.scalar(text("SELECT version_num FROM public.alembic_version"))
                == "0036_bulletin_source_updates"
            )
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM pg_catalog.pg_namespace "
                        "WHERE nspname IN ('goodboy_watch', 'goodboy_private_watchlists')"
                    )
                )
                == 0
            )
    finally:
        handle.engine.dispose()
        postgres_cluster.drop_database("smithguard")


def test_isolated_restore_migration_requires_the_explicit_rehearsal_scope(
    postgres_cluster: LocalPostgres,
    tmp_path: Path,
) -> None:
    url = postgres_cluster.create_database(name="smithguard_restore_drill")
    query = url.query
    engine = None
    try:
        with psycopg.connect(
            host=str(query["host"]),
            port=int(query["port"]),
            user="postgres",
            dbname="postgres",
            autocommit=True,
        ) as connection:
            connection.execute(
                """
                DO $role$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_catalog.pg_roles
                        WHERE rolname = 'smithguard-maintenance'
                    ) THEN
                        CREATE ROLE "smithguard-maintenance" LOGIN;
                    END IF;
                END
                $role$;
                """
            )
            connection.execute(
                'ALTER DATABASE smithguard_restore_drill OWNER TO "smithguard-maintenance"'
            )
        maintenance_url = url.set(username="smithguard-maintenance")
        rendered = maintenance_url.render_as_string(hide_password=False)
        migrate(maintenance_url, "0013_watch_rebrand")
        engine = create_engine(maintenance_url, hide_parameters=True)
        with Session(engine) as session, session.begin():
            record_migration_journal(
                session,
                journal_path=MIGRATION_JOURNAL,
                app_version=__version__,
                through_revision="0013_watch_rebrand",
            )
        engine.dispose()
        engine = None
        release_config, release_journal = _release_migration_files(tmp_path)
        with pytest.raises(MigrationRuntimeError, match="fixed local database"):
            migrate_and_record(
                database_url=rendered,
                alembic_config_path=release_config,
                journal_path=release_journal,
            )

        migrate_and_record(
            database_url=rendered,
            alembic_config_path=release_config,
            journal_path=release_journal,
            scope="isolated_rehearsal",
        )
        with psycopg.connect(
            host=str(query["host"]),
            port=int(query["port"]),
            user="postgres",
            dbname="postgres",
            autocommit=True,
        ) as connection:
            connection.execute("ALTER DATABASE smithguard_restore_drill OWNER TO postgres")
        with psycopg.connect(
            host=str(query["host"]),
            port=int(query["port"]),
            user="postgres",
            dbname="smithguard_restore_drill",
            autocommit=True,
        ) as connection:
            connection.execute("SET smithguard.isolated_rehearsal = 'true'")
            connection.execute(ROLE_GRANTS.read_text(encoding="ascii"))
        engine = create_engine(maintenance_url, hide_parameters=True)
        with engine.connect() as connection:
            assert (
                connection.scalar(text("SELECT version_num FROM public.alembic_version"))
                == "0036_bulletin_source_updates"
            )
            assert connection.scalar(
                text("SELECT count(*) FROM smithguard.migration_journal")
            ) == len(load_migration_journal(MIGRATION_JOURNAL)["migrations"])
            assert connection.scalar(
                text(
                    "SELECT has_table_privilege('smithguard-api', 'smithguard.incidents', 'SELECT')"
                )
            )
            assert not connection.scalar(
                text("SELECT has_schema_privilege('smithguard-maintenance', 'public', 'CREATE')")
            )
            assert not connection.scalar(
                text("SELECT pg_has_role('smithguard-maintenance', 'pg_database_owner', 'MEMBER')")
            )
    finally:
        if engine is not None:
            engine.dispose()
        postgres_cluster.drop_database("smithguard_restore_drill")


def test_legacy_owned_revision_seven_migrates_and_reaches_the_exact_role_boundary(
    postgres_cluster: LocalPostgres,
    tmp_path: Path,
) -> None:
    url = postgres_cluster.create_database(name="smithguard")
    maintenance_engine = None
    try:
        _make_revision_seven_legacy_owned(url)
        with _admin_connection(url) as connection:
            connection.execute("CREATE SEQUENCE goodboy_security.a_linked_sequence")
            connection.execute(
                """
                CREATE TABLE goodboy_security.z_linked_table (
                    id integer PRIMARY KEY
                        DEFAULT nextval('goodboy_security.a_linked_sequence')
                )
                """
            )
            connection.execute(
                """
                ALTER SEQUENCE goodboy_security.a_linked_sequence
                OWNED BY goodboy_security.z_linked_table.id
                """
            )
            connection.execute('ALTER TABLE goodboy_security.z_linked_table OWNER TO "smithguard"')
        before = _application_owners(url)
        assert before
        assert {row[3] for row in before} == {LEGACY_ROLE}
        assert _database_owner(url) == LEGACY_ROLE

        with _admin_connection(url) as connection:
            connection.execute(MIGRATION_BOOTSTRAP.read_text(encoding="ascii"))
            connection.execute(MIGRATION_BOOTSTRAP.read_text(encoding="ascii"))

        transitioned = _application_owners(url)
        assert transitioned
        assert {row[3] for row in transitioned} == {MAINTENANCE_ROLE}
        assert _database_owner(url) == "postgres"

        release_config, release_journal = _release_migration_files(tmp_path)
        maintenance_url = url.set(username=MAINTENANCE_ROLE)
        migrate_and_record(
            database_url=maintenance_url.render_as_string(hide_password=False),
            alembic_config_path=release_config,
            journal_path=release_journal,
        )
        with _admin_connection(url) as connection:
            connection.execute(ROLE_GRANTS.read_text(encoding="ascii"))

        maintenance_engine = create_engine(maintenance_url, hide_parameters=True)
        with maintenance_engine.connect() as connection:
            assert (
                connection.scalar(text("SELECT version_num FROM public.alembic_version"))
                == "0036_bulletin_source_updates"
            )
            assert connection.scalar(
                text("SELECT count(*) FROM smithguard.migration_journal")
            ) == len(load_migration_journal(MIGRATION_JOURNAL)["migrations"])

        with _admin_connection(url) as connection:
            role_attributes = connection.execute(
                """
                SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolinherit
                FROM pg_catalog.pg_roles
                WHERE rolname = 'smithguard-maintenance'
                """
            ).fetchone()
            assert role_attributes == (False, False, False, False, False)
            assert _database_owner(url) == "postgres"
            assert not connection.execute(
                "SELECT has_schema_privilege(%s, 'public', 'CREATE')",
                (MAINTENANCE_ROLE,),
            ).fetchone()[0]
            assert not connection.execute(
                "SELECT pg_has_role(%s, 'pg_database_owner', 'MEMBER')",
                (MAINTENANCE_ROLE,),
            ).fetchone()[0]
            for role in (*ORDINARY_ROLES, LEGACY_ROLE):
                assert not connection.execute(
                    "SELECT has_database_privilege(%s, current_database(), 'CREATE')",
                    (role,),
                ).fetchone()[0]
                assert not connection.execute(
                    "SELECT has_database_privilege(%s, current_database(), 'TEMP')",
                    (role,),
                ).fetchone()[0]
                assert not connection.execute(
                    "SELECT has_schema_privilege(%s, 'smithguard', 'CREATE')",
                    (role,),
                ).fetchone()[0]
                assert not connection.execute(
                    "SELECT pg_has_role(%s, 'smithguard-maintenance', 'MEMBER')",
                    (role,),
                ).fetchone()[0]
    finally:
        if maintenance_engine is not None:
            maintenance_engine.dispose()
        postgres_cluster.drop_database("smithguard")


@pytest.mark.parametrize(
    ("unexpected_shape", "expected_error"),
    [
        (
            "database_owner",
            "source ownership preflight found an unexpected database owner",
        ),
        ("schema_owner", "source ownership preflight found an unexpected schema owner"),
        ("owner", "source ownership preflight found an unexpected relation owner"),
        ("view", "source ownership preflight found an unsupported relation kind"),
        ("routine_owner", "source ownership preflight found an unexpected routine owner"),
        ("aggregate", "source ownership preflight found an unsupported routine kind"),
        ("enum", "source ownership preflight found an unsupported type kind"),
        ("incomplete", "source ownership preflight found an incomplete schema shape"),
    ],
)
def test_legacy_ownership_preflight_rolls_back_without_partial_transition(
    postgres_cluster: LocalPostgres,
    unexpected_shape: str,
    expected_error: str,
) -> None:
    url = postgres_cluster.create_database(name="smithguard")
    try:
        _make_revision_seven_legacy_owned(url)
        with _admin_connection(url) as connection:
            if unexpected_shape in {
                "database_owner",
                "schema_owner",
                "owner",
                "routine_owner",
            }:
                connection.execute(
                    """
                    DO $unexpected_owner$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1
                            FROM pg_catalog.pg_roles
                            WHERE rolname = 'synthetic-unexpected-owner'
                        ) THEN
                            CREATE ROLE "synthetic-unexpected-owner";
                        END IF;
                    END
                    $unexpected_owner$
                    """
                )
            if unexpected_shape == "database_owner":
                connection.execute(
                    'ALTER DATABASE smithguard OWNER TO "synthetic-unexpected-owner"'
                )
            elif unexpected_shape == "schema_owner":
                connection.execute(
                    'ALTER SCHEMA goodboy_security OWNER TO "synthetic-unexpected-owner"'
                )
            elif unexpected_shape == "owner":
                connection.execute(
                    'ALTER TABLE goodboy_security.sources OWNER TO "synthetic-unexpected-owner"'
                )
            elif unexpected_shape == "view":
                connection.execute(
                    "CREATE VIEW goodboy_security.synthetic_unexpected_view AS SELECT 1 AS value"
                )
                connection.execute(
                    'ALTER VIEW goodboy_security.synthetic_unexpected_view OWNER TO "smithguard"'
                )
            elif unexpected_shape == "routine_owner":
                connection.execute(
                    """
                    ALTER ROUTINE goodboy_security.reject_ledger_mutation()
                    OWNER TO "synthetic-unexpected-owner"
                    """
                )
            elif unexpected_shape == "aggregate":
                connection.execute(
                    """
                    CREATE AGGREGATE goodboy_security.synthetic_sum(integer) (
                        SFUNC = int4pl,
                        STYPE = integer,
                        INITCOND = '0'
                    )
                    """
                )
                connection.execute(
                    """
                    ALTER AGGREGATE goodboy_security.synthetic_sum(integer)
                    OWNER TO "smithguard"
                    """
                )
            elif unexpected_shape == "enum":
                connection.execute("CREATE TYPE goodboy_security.synthetic_enum AS ENUM ('value')")
                connection.execute(
                    """
                    ALTER TYPE goodboy_security.synthetic_enum
                    OWNER TO "smithguard"
                    """
                )
            else:
                connection.execute("DROP SCHEMA goodboy_hosted_watch CASCADE")
        before = _application_owners(url)
        before_database_owner = _database_owner(url)

        with _admin_connection(url) as connection:
            with pytest.raises(psycopg.errors.RaiseException, match=expected_error):
                connection.execute(MIGRATION_BOOTSTRAP.read_text(encoding="ascii"))
            connection.execute("ROLLBACK")

        assert _application_owners(url) == before
        assert _database_owner(url) == before_database_owner
    finally:
        postgres_cluster.drop_database("smithguard")


def test_unused_table_drop_refuses_a_table_that_gained_a_row(
    postgres_cluster: LocalPostgres,
) -> None:
    """0030 drops only empty tables (owner decision): one row stops it, and nothing is
    dropped; once empty, the tables go and the snapshot manifests stay."""
    handle = migrated_database(
        postgres_cluster, journal=False, revision="0029_warning_lane_outputs"
    )
    try:
        with handle.engine.begin() as connection:
            # Make a synthetic row possible without the retired feature's constraints.
            connection.execute(
                text("ALTER TABLE smithguard.webhook_receipts ADD COLUMN synthetic_marker integer")
            )
            for name in connection.scalars(
                text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conrelid = 'smithguard.webhook_receipts'::regclass "
                    "AND contype IN ('c', 'p', 'u', 'f')"
                )
            ).all():
                connection.execute(
                    text(f'ALTER TABLE smithguard.webhook_receipts DROP CONSTRAINT "{name}"')
                )
            for column in connection.scalars(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'smithguard' AND table_name = 'webhook_receipts' "
                    "AND is_nullable = 'NO'"
                )
            ).all():
                connection.execute(
                    text(
                        f'ALTER TABLE smithguard.webhook_receipts ALTER COLUMN "{column}" '
                        "DROP NOT NULL"
                    )
                )
            connection.execute(text("SET LOCAL session_replication_role = replica"))
            connection.execute(
                text("INSERT INTO smithguard.webhook_receipts (synthetic_marker) VALUES (1)")
            )
        with pytest.raises(Exception, match="refuses to drop tables with rows: webhook_receipts"):
            migrate(handle.url, "0030_drop_unused_tables")
        with handle.engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM public.alembic_version")) == (
                "0029_warning_lane_outputs"
            )
            assert connection.scalar(text("SELECT to_regclass('smithguard.delivery_events')"))

        with handle.engine.begin() as connection:
            connection.execute(text("SET LOCAL session_replication_role = replica"))
            connection.execute(text("DELETE FROM smithguard.webhook_receipts"))

        # A concurrent insert still open when the migration starts: the migration's
        # locks wait for it, and once it commits the check sees its row.
        writer = handle.engine.connect()
        outcome: list[BaseException | None] = []
        try:
            transaction = writer.begin()
            writer.execute(text("SET LOCAL session_replication_role = replica"))
            writer.execute(
                text("INSERT INTO smithguard.webhook_receipts (synthetic_marker) VALUES (2)")
            )

            def run() -> None:
                try:
                    migrate(handle.url, "0030_drop_unused_tables")
                except BaseException as error:  # the thread reports to the test
                    outcome.append(error)
                else:
                    outcome.append(None)

            thread = threading.Thread(target=run)
            thread.start()
            deadline = time.monotonic() + 4
            with handle.engine.connect() as observer:
                while True:
                    waiting = observer.scalar(
                        text(
                            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                            "WHERE wait_event_type = 'Lock' AND query LIKE 'LOCK TABLE%')"
                        )
                    )
                    observer.rollback()  # pg_stat_activity is snapshotted per transaction
                    if waiting:
                        break
                    assert time.monotonic() < deadline, f"migration never waited: {outcome}"
                    time.sleep(0.02)
            transaction.commit()
            thread.join(timeout=10)
        finally:
            writer.close()
        assert len(outcome) == 1 and outcome[0] is not None
        assert "refuses to drop tables with rows: webhook_receipts" in str(outcome[0])
        with handle.engine.begin() as connection:
            connection.execute(text("SET LOCAL session_replication_role = replica"))
            connection.execute(text("DELETE FROM smithguard.webhook_receipts"))
        migrate(handle.url, "0030_drop_unused_tables")
        with handle.engine.connect() as connection:
            assert (
                connection.scalar(text("SELECT to_regclass('smithguard.webhook_receipts')")) is None
            )
            assert (
                connection.scalar(text("SELECT to_regclass('smithguard.correlation_shadow_runs')"))
                is None
            )
            assert connection.scalar(text("SELECT to_regclass('smithguard.snapshot_manifests')"))
    finally:
        handle.engine.dispose()
