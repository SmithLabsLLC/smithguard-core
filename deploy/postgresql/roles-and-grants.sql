-- SmithGuard exact process roles and privileges.
-- Apply while ordinary services are stopped.
-- Run as a PostgreSQL superuser in the isolated smithguard database. The fixed
-- restore-drill database is accepted only with the explicit psql rehearsal variable.

BEGIN;

DO $database_identity$
BEGIN
    IF current_database() <> 'smithguard'
       AND NOT (
           current_database() = 'smithguard_restore_drill'
           AND current_setting('smithguard.isolated_rehearsal', true) = 'true'
       ) THEN
        RAISE EXCEPTION 'role grants require the fixed production or rehearsal database';
    END IF;
END
$database_identity$;

DO $roles$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'smithguard-api',
        'smithguard-collector',
        'smithguard-signals',
        'smithguard-maintenance',
        'smithguard-health'
    ]
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('CREATE ROLE %I LOGIN', role_name);
        END IF;
    END LOOP;
END
$roles$;

ALTER ROLE "smithguard-api"
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD NULL;
ALTER ROLE "smithguard-collector"
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD NULL;
ALTER ROLE "smithguard-signals"
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD NULL;
ALTER ROLE "smithguard-maintenance"
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD NULL;
ALTER ROLE "smithguard-health"
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD NULL;

DO $database_privileges$
BEGIN
    EXECUTE format(
        'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC',
        current_database()
    );
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO %I, %I, %I, %I, %I',
        current_database(),
        'smithguard-api',
        'smithguard-collector',
        'smithguard-signals',
        'smithguard-maintenance',
        'smithguard-health'
    );
END
$database_privileges$;

DO $maintenance_database_create$
BEGIN
    EXECUTE format(
        'GRANT CREATE ON DATABASE %I TO %I',
        current_database(),
        'smithguard-maintenance'
    );
END
$maintenance_database_create$;

DO $ownership$
DECLARE
    item record;
BEGIN
    FOR item IN
        SELECT schemaname, tablename
        FROM pg_catalog.pg_tables
        WHERE schemaname IN ('smithguard', 'smithguard_private_watchlists')
           OR (schemaname = 'public' AND tablename = 'alembic_version')
    LOOP
        EXECUTE format(
            'ALTER TABLE %I.%I OWNER TO %I',
            item.schemaname,
            item.tablename,
            'smithguard-maintenance'
        );
    END LOOP;
    FOR item IN
        SELECT sequence_schema AS schemaname, sequence_name AS object_name
        FROM information_schema.sequences
        WHERE sequence_schema IN ('smithguard', 'smithguard_private_watchlists')
    LOOP
        EXECUTE format(
            'ALTER SEQUENCE %I.%I OWNER TO %I',
            item.schemaname,
            item.object_name,
            'smithguard-maintenance'
        );
    END LOOP;
    FOR item IN
        SELECT n.nspname AS schemaname, p.proname, pg_get_function_identity_arguments(p.oid) AS args
        FROM pg_catalog.pg_proc AS p
        JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
        WHERE n.nspname IN ('smithguard', 'smithguard_private_watchlists')
          AND p.prokind IN ('f', 'p')
    LOOP
        EXECUTE format(
            'ALTER ROUTINE %I.%I(%s) OWNER TO %I',
            item.schemaname,
            item.proname,
            item.args,
            'smithguard-maintenance'
        );
    END LOOP;
END
$ownership$;

ALTER SCHEMA smithguard OWNER TO "smithguard-maintenance";
ALTER SCHEMA smithguard_private_watchlists OWNER TO "smithguard-maintenance";

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM "smithguard-maintenance";
REVOKE ALL ON SCHEMA smithguard, smithguard_private_watchlists FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA smithguard, smithguard_private_watchlists
    FROM PUBLIC,
         "smithguard-api",
         "smithguard-collector",
         "smithguard-signals",
         "smithguard-health";
REVOKE ALL ON TABLE public.alembic_version
    FROM PUBLIC,
         "smithguard-api",
         "smithguard-collector",
         "smithguard-signals",
         "smithguard-health";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA smithguard, smithguard_private_watchlists
    FROM PUBLIC,
         "smithguard-api",
         "smithguard-collector",
         "smithguard-signals",
         "smithguard-health";
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA smithguard, smithguard_private_watchlists
    FROM PUBLIC,
         "smithguard-api",
         "smithguard-collector",
         "smithguard-signals",
         "smithguard-health";

GRANT USAGE ON SCHEMA smithguard
    TO "smithguard-api",
       "smithguard-collector",
       "smithguard-signals",
       "smithguard-health";

GRANT SELECT ON TABLE public.alembic_version
    TO "smithguard-api", "smithguard-health";

GRANT SELECT ON TABLE
    smithguard.advisory_catalog_manifests,
    smithguard.advisory_catalog_records,
    smithguard.advisory_package_records,
    smithguard.affected_ranges,
    smithguard.artifacts,
    smithguard.claims,
    smithguard.collector_progress,
    smithguard.evidence_finalizations,
    smithguard.incident_events,
    smithguard.incidents,
    smithguard.migration_journal,
    smithguard.preliminary_warnings,
    smithguard.recommended_actions,
    smithguard.relationships,
    smithguard.source_incident_links,
    smithguard.source_reconciliation_runs,
    smithguard.sources
TO "smithguard-api";

GRANT SELECT, INSERT ON TABLE
    smithguard.advisory_catalog_inventory,
    smithguard.advisory_catalog_manifests,
    smithguard.advisory_catalog_records,
    smithguard.advisory_package_records,
    smithguard.affected_ranges,
    smithguard.artifacts,
    smithguard.authority_decisions,
    smithguard.claims,
    smithguard.collector_checkpoints,
    smithguard.collector_progress,
    smithguard.evidence_finalizations,
    smithguard.evidence_objects,
    smithguard.incident_events,
    smithguard.incident_seeds,
    smithguard.incident_transitions,
    smithguard.incidents,
    smithguard.ingestion_batches,
    smithguard.publication_lifecycle_events,
    smithguard.recommended_actions,
    smithguard.relationships,
    smithguard.review_queue_events,
    smithguard.source_cluster_members,
    smithguard.source_governance_decisions,
    smithguard.source_incident_links,
    smithguard.source_reconciliation_runs,
    smithguard.sources
TO "smithguard-collector";

GRANT UPDATE (
    state,
    attempts,
    last_error_code,
    updated_at,
    finalized_at
) ON TABLE smithguard.evidence_finalizations
TO "smithguard-collector";

GRANT SELECT, INSERT ON TABLE
    smithguard.jobs,
    smithguard.preliminary_warning_approvals,
    smithguard.preliminary_warning_rechecks,
    smithguard.preliminary_warnings
TO "smithguard-signals";

GRANT UPDATE (
    state,
    attempts,
    available_at,
    lease_owner,
    lease_token_hash,
    lease_expires_at,
    last_error_code,
    completed_at,
    updated_at
) ON TABLE smithguard.jobs
TO "smithguard-signals";

DO $checkpoint_sequence_grant$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'smithguard-collector'
    ) AND to_regclass('smithguard.collector_checkpoint_sequence') IS NOT NULL THEN
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE '
            'smithguard.collector_checkpoint_sequence TO "smithguard-collector"';
    END IF;
END
$checkpoint_sequence_grant$;

GRANT SELECT ON TABLE
    smithguard.advisory_catalog_manifests,
    smithguard.advisory_catalog_records,
    smithguard.collector_progress,
    smithguard.evidence_finalizations,
    smithguard.jobs,
    smithguard.migration_journal,
    smithguard.preliminary_warning_rechecks,
    smithguard.preliminary_warnings,
    smithguard.source_reconciliation_runs
TO "smithguard-health";

ALTER DEFAULT PRIVILEGES FOR ROLE "smithguard-maintenance"
    REVOKE EXECUTE ON ROUTINES FROM PUBLIC;

-- The same grant script is also used before upgrading a legacy schema. Migrations
-- grant their own new tables too (0029 onward), so this file mainly creates roles.
DO $lead_grants$
BEGIN
    IF to_regclass('smithguard.emerging_leads') IS NOT NULL THEN
        GRANT SELECT ON TABLE smithguard.emerging_leads
            TO "smithguard-api", "smithguard-health";
        GRANT SELECT, INSERT ON TABLE smithguard.emerging_leads TO "smithguard-signals";
    END IF;
    -- Private 30-day provider output (migration 0029 grants the same itself).
    IF to_regclass('smithguard.warning_lane_outputs') IS NOT NULL THEN
        GRANT SELECT, INSERT, DELETE ON TABLE smithguard.warning_lane_outputs
            TO "smithguard-signals";
    END IF;
END
$lead_grants$;

COMMIT;

-- Deliberately no default runtime grants. From migration 0029 on, each migration
-- grants its own new tables, so this file is needed only for role setup or a
-- migration that predates that rule; keep its table lists current either way.

-- Supplemental tables are created by migration 0031; preserve pre-upgrade use.
DO $supplemental_grants$
BEGIN
    IF to_regclass('smithguard.supplemental_snapshots') IS NOT NULL THEN
        GRANT SELECT ON TABLE smithguard.supplemental_snapshots TO "smithguard-health";
        GRANT SELECT ON TABLE smithguard.supplemental_snapshots, smithguard.supplemental_facts TO "smithguard-api";
        GRANT SELECT, INSERT ON TABLE smithguard.supplemental_snapshots, smithguard.supplemental_facts TO "smithguard-collector";
    END IF;
END
$supplemental_grants$;

DO $payload_grants$ BEGIN
    IF to_regclass('smithguard.supplemental_payloads') IS NOT NULL THEN
        GRANT SELECT ON TABLE smithguard.supplemental_payloads TO "smithguard-api";
        GRANT SELECT, INSERT ON TABLE smithguard.supplemental_payloads TO "smithguard-collector";
    END IF;
END $payload_grants$;

DO $record_accounting_grants$ BEGIN
    IF to_regclass('smithguard.collection_record_outcomes') IS NOT NULL THEN
        GRANT SELECT, INSERT ON TABLE smithguard.collection_record_outcomes, smithguard.collection_record_memberships, smithguard.collection_record_resolutions TO "smithguard-collector";
        GRANT SELECT ON TABLE smithguard.collection_record_outcomes, smithguard.collection_record_resolutions TO "smithguard-api", "smithguard-health";
    END IF;
END $record_accounting_grants$;

-- Bulletin private originals and publication decisions are never API-readable.
DO $bulletin_grants$ BEGIN
    IF to_regclass('smithguard.bulletin_stream') IS NOT NULL THEN
        GRANT SELECT ON TABLE smithguard.bulletin_stream, smithguard.bulletin_source_status,
            smithguard.official_intake_runs TO "smithguard-health";
        GRANT SELECT ON TABLE smithguard.bulletin_stream, smithguard.bulletin_current,
            smithguard.bulletin_public_versions, smithguard.bulletin_events,
            smithguard.bulletin_source_status TO "smithguard-api";
        GRANT SELECT, INSERT, UPDATE ON TABLE smithguard.bulletin_stream,
            smithguard.bulletin_current, smithguard.bulletin_public_versions,
            smithguard.bulletin_source_status, smithguard.official_source_checkpoints,
            smithguard.official_notice_current, smithguard.official_notice_pending
            TO "smithguard-signals";
        GRANT SELECT, INSERT ON TABLE smithguard.bulletin_revisions,
            smithguard.bulletin_events, smithguard.bulletin_decisions,
            smithguard.official_notice_evidence, smithguard.official_intake_runs
            TO "smithguard-signals";
    END IF;
END $bulletin_grants$;

-- Existing CISA snapshot facts only; no new download authority or writes.
DO $bulletin_kev_grants$
BEGIN
    IF to_regclass('smithguard.bulletin_stream') IS NOT NULL THEN
        GRANT SELECT ON TABLE smithguard.supplemental_snapshots,
            smithguard.supplemental_facts, smithguard.supplemental_payloads
            TO "smithguard-signals";
    END IF;
END
$bulletin_kev_grants$;

-- New private automation state; no API access to analyst or attribution evidence.
DO $bulletin_automation_grants$ BEGIN
    IF to_regclass('smithguard.bulletin_identity_aliases') IS NOT NULL THEN
        GRANT SELECT, INSERT ON TABLE smithguard.bulletin_identity_aliases,
            smithguard.bulletin_maintenance_receipts TO "smithguard-signals";
        GRANT SELECT, INSERT, UPDATE ON TABLE smithguard.bulletin_review_queue TO "smithguard-signals";
        GRANT SELECT ON TABLE smithguard.advisory_catalog_records, smithguard.advisory_package_records,
            smithguard.collector_progress, smithguard.advisory_catalog_manifests TO "smithguard-signals";
    END IF;
END $bulletin_automation_grants$;
