-- Restore only the existing emerging-lead role contract on the diagnosed 0030 host.
-- Run once through the bound operator procedure, using psql --set=ON_ERROR_STOP=1.
-- This does not migrate the schema, create roles, replay jobs or publish leads.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '20s';

DO $exact_target$
BEGIN
    IF current_database() <> 'smithguard'
       OR (SELECT array_agg(version_num::text ORDER BY version_num)
           FROM public.alembic_version) IS DISTINCT FROM
          ARRAY['0030_drop_unused_tables']::text[] THEN
        RAISE EXCEPTION 'emerging-lead grant repair requires smithguard schema 0030';
    END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_roles
        WHERE rolname IN ('smithguard-api', 'smithguard-signals', 'smithguard-health')
          AND rolcanlogin AND NOT rolsuper AND NOT rolcreaterole
          AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls) <> 3 THEN
        RAISE EXCEPTION 'emerging-lead runtime role boundary differs';
    END IF;
    IF (SELECT tableowner FROM pg_catalog.pg_tables
        WHERE schemaname = 'smithguard' AND tablename = 'emerging_leads')
        IS DISTINCT FROM 'smithguard-maintenance' THEN
        RAISE EXCEPTION 'emerging-lead table ownership differs';
    END IF;
END
$exact_target$;

GRANT SELECT ON TABLE smithguard.emerging_leads TO "smithguard-api", "smithguard-health";
GRANT SELECT, INSERT ON TABLE smithguard.emerging_leads TO "smithguard-signals";

COMMIT;
