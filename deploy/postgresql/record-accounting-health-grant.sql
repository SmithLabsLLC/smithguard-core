-- Give the existing health reader the public catalog type needed to distinguish
-- a current quarantine from a preserved omission in an advisory's former segment.
-- Apply only after schema 0032, before the separately reviewed runtime adapter.
-- This is a SELECT-only grant, not a migration or a replay of any collection.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '20s';

DO $exact_target$
BEGIN
    IF current_database() <> 'smithguard'
       OR (SELECT array_agg(version_num::text ORDER BY version_num)
           FROM public.alembic_version) IS DISTINCT FROM
          ARRAY['0032_record_accounting']::text[] THEN
        RAISE EXCEPTION 'record accounting health grant requires smithguard schema 0032';
    END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_roles
        WHERE rolname = 'smithguard-health'
          AND rolcanlogin AND NOT rolsuper AND NOT rolcreaterole
          AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls) <> 1 THEN
        RAISE EXCEPTION 'record accounting health role boundary differs';
    END IF;
    IF (SELECT tableowner FROM pg_catalog.pg_tables
        WHERE schemaname = 'smithguard' AND tablename = 'advisory_catalog_records')
        IS DISTINCT FROM 'smithguard-maintenance' THEN
        RAISE EXCEPTION 'record accounting catalog ownership differs';
    END IF;
END
$exact_target$;

GRANT SELECT ON TABLE smithguard.advisory_catalog_records TO "smithguard-health";

COMMIT;
