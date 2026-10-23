-- SmithGuard pre-migration maintenance-role bootstrap.
-- Run as a PostgreSQL administrator in the exact smithguard database while all
-- ordinary services are stopped. It accepts a fresh database, either supported
-- historical schema layout through revision 0018, or an already migrated SmithGuard
-- database. Apply the full roles-and-grants.sql after migration.

BEGIN;

DO $database_identity$
BEGIN
    IF current_database() <> 'smithguard' THEN
        RAISE EXCEPTION 'migration bootstrap requires the smithguard database';
    END IF;
END
$database_identity$;

DO $maintenance_role$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles
        WHERE rolname = 'smithguard-maintenance'
    ) THEN
        CREATE ROLE "smithguard-maintenance" LOGIN;
    END IF;
END
$maintenance_role$;

ALTER ROLE "smithguard-maintenance"
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD NULL;

REVOKE TEMPORARY ON DATABASE smithguard FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT, CREATE ON DATABASE smithguard TO "smithguard-maintenance";
GRANT CREATE ON SCHEMA public TO "smithguard-maintenance";

DO $source_ownership_preflight$
DECLARE
    application_schema_count integer;
    complete_pair_count integer;
    alembic_table_count integer;
    database_owner text;
BEGIN
    SELECT count(*)
    INTO application_schema_count
    FROM pg_catalog.pg_namespace
    WHERE nspname IN (
        'goodboy_security',
        'goodboy_hosted_watch',
        'goodboy_watch',
        'goodboy_private_watchlists',
        'smithguard',
        'smithguard_private_watchlists'
    );

    SELECT
        (CASE WHEN
            EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'goodboy_security')
            AND EXISTS (
                SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'goodboy_hosted_watch'
            )
        THEN 1 ELSE 0 END)
        + (CASE WHEN
            EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'goodboy_watch')
            AND EXISTS (
                SELECT 1
                FROM pg_catalog.pg_namespace
                WHERE nspname = 'goodboy_private_watchlists'
            )
        THEN 1 ELSE 0 END)
        + (CASE WHEN
            EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'smithguard')
            AND EXISTS (
                SELECT 1
                FROM pg_catalog.pg_namespace
                WHERE nspname = 'smithguard_private_watchlists'
            )
        THEN 1 ELSE 0 END)
    INTO complete_pair_count;

    SELECT count(*)
    INTO alembic_table_count
    FROM pg_catalog.pg_class AS c
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = 'alembic_version'
      AND c.relkind IN ('r', 'p');

    SELECT pg_get_userbyid(datdba)
    INTO database_owner
    FROM pg_catalog.pg_database
    WHERE datname = current_database();

    IF application_schema_count = 0 AND alembic_table_count = 0 THEN
        IF database_owner <> 'postgres' THEN
            RAISE EXCEPTION 'migration bootstrap found an unexpected fresh database owner';
        END IF;
        RETURN;
    END IF;
    IF application_schema_count <> 2 OR alembic_table_count <> 1 THEN
        RAISE EXCEPTION 'source ownership preflight found an incomplete schema shape';
    END IF;
    IF complete_pair_count <> 1 THEN
        RAISE EXCEPTION 'migration bootstrap found a mixed or duplicate naming state';
    END IF;
    IF database_owner NOT IN (
        'postgres',
        'smithguard',
        'smithguard-maintenance',
        'goodboy-watch',
        'goodboy-watch-maintenance'
    ) THEN
        RAISE EXCEPTION 'source ownership preflight found an unexpected database owner';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace
        WHERE nspname IN (
            'goodboy_security',
            'goodboy_hosted_watch',
            'goodboy_watch',
            'goodboy_private_watchlists',
            'smithguard',
            'smithguard_private_watchlists'
        )
          AND pg_get_userbyid(nspowner) NOT IN (
              'postgres',
              'smithguard',
              'smithguard-maintenance',
              'goodboy-watch',
              'goodboy-watch-maintenance'
          )
    ) THEN
        RAISE EXCEPTION 'source ownership preflight found an unexpected schema owner';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS c
        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname IN (
            'goodboy_security',
            'goodboy_hosted_watch',
            'goodboy_watch',
            'goodboy_private_watchlists',
            'smithguard',
            'smithguard_private_watchlists'
        )
          AND c.relkind NOT IN ('r', 'p', 'S', 'i', 'I')
    ) THEN
        RAISE EXCEPTION 'source ownership preflight found an unsupported relation kind';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS c
        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
        WHERE (
                n.nspname IN (
                    'goodboy_security',
                    'goodboy_hosted_watch',
                    'goodboy_watch',
                    'goodboy_private_watchlists',
                    'smithguard',
                    'smithguard_private_watchlists'
                )
                OR (
                    n.nspname = 'public'
                    AND c.relname = 'alembic_version'
                    AND c.relkind IN ('r', 'p')
                )
            )
          AND pg_get_userbyid(c.relowner) NOT IN (
              'postgres',
              'smithguard',
              'smithguard-maintenance',
              'goodboy-watch',
              'goodboy-watch-maintenance'
          )
    ) THEN
        RAISE EXCEPTION 'source ownership preflight found an unexpected relation owner';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_type AS t
        JOIN pg_catalog.pg_namespace AS n ON n.oid = t.typnamespace
        WHERE n.nspname IN (
            'goodboy_security',
            'goodboy_hosted_watch',
            'goodboy_watch',
            'goodboy_private_watchlists',
            'smithguard',
            'smithguard_private_watchlists'
        )
          AND t.typtype IN ('d', 'e')
    ) THEN
        RAISE EXCEPTION 'source ownership preflight found an unsupported type kind';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS p
        JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
        WHERE n.nspname IN (
            'goodboy_security',
            'goodboy_hosted_watch',
            'goodboy_watch',
            'goodboy_private_watchlists',
            'smithguard',
            'smithguard_private_watchlists'
        )
          AND p.prokind NOT IN ('f', 'p')
    ) THEN
        RAISE EXCEPTION 'source ownership preflight found an unsupported routine kind';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS p
        JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
        WHERE n.nspname IN (
            'goodboy_security',
            'goodboy_hosted_watch',
            'goodboy_watch',
            'goodboy_private_watchlists',
            'smithguard',
            'smithguard_private_watchlists'
        )
          AND pg_get_userbyid(p.proowner) NOT IN (
              'postgres',
              'smithguard',
              'smithguard-maintenance',
              'goodboy-watch',
              'goodboy-watch-maintenance'
          )
    ) THEN
        RAISE EXCEPTION 'source ownership preflight found an unexpected routine owner';
    END IF;
END
$source_ownership_preflight$;

DO $source_ownership_transition$
DECLARE
    item record;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace
        WHERE nspname IN (
            'goodboy_security',
            'goodboy_hosted_watch',
            'goodboy_watch',
            'goodboy_private_watchlists',
            'smithguard',
            'smithguard_private_watchlists'
        )
    ) THEN
        RETURN;
    END IF;

    ALTER DATABASE smithguard OWNER TO postgres;

    FOR item IN
        SELECT n.nspname AS schemaname, c.relname AS object_name
        FROM pg_catalog.pg_class AS c
        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
        WHERE (
                n.nspname IN (
                    'goodboy_security',
                    'goodboy_hosted_watch',
                    'goodboy_watch',
                    'goodboy_private_watchlists',
                    'smithguard',
                    'smithguard_private_watchlists'
                )
                OR (n.nspname = 'public' AND c.relname = 'alembic_version')
            )
          AND c.relkind IN ('r', 'p')
        ORDER BY n.nspname, c.relname
    LOOP
        EXECUTE format(
            'ALTER TABLE %I.%I OWNER TO %I',
            item.schemaname,
            item.object_name,
            'smithguard-maintenance'
        );
    END LOOP;

    FOR item IN
        SELECT n.nspname AS schemaname, c.relname AS object_name
        FROM pg_catalog.pg_class AS c
        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname IN (
            'goodboy_security',
            'goodboy_hosted_watch',
            'goodboy_watch',
            'goodboy_private_watchlists',
            'smithguard',
            'smithguard_private_watchlists'
        )
          AND c.relkind = 'S'
          AND NOT EXISTS (
              SELECT 1
              FROM pg_catalog.pg_depend AS d
              WHERE d.classid = 'pg_catalog.pg_class'::regclass
                AND d.objid = c.oid
                AND d.refclassid = 'pg_catalog.pg_class'::regclass
                AND d.deptype IN ('a', 'i')
          )
        ORDER BY n.nspname, c.relname
    LOOP
        EXECUTE format(
            'ALTER SEQUENCE %I.%I OWNER TO %I',
            item.schemaname,
            item.object_name,
            'smithguard-maintenance'
        );
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
            'goodboy_hosted_watch',
            'goodboy_watch',
            'goodboy_private_watchlists',
            'smithguard',
            'smithguard_private_watchlists'
        )
          AND p.prokind IN ('f', 'p')
        ORDER BY n.nspname, p.proname, p.oid
    LOOP
        EXECUTE format(
            'ALTER ROUTINE %I.%I(%s) OWNER TO %I',
            item.schemaname,
            item.proname,
            item.args,
            'smithguard-maintenance'
        );
    END LOOP;

    FOR item IN
        SELECT nspname AS schemaname
        FROM pg_catalog.pg_namespace
        WHERE nspname IN (
            'goodboy_security',
            'goodboy_hosted_watch',
            'goodboy_watch',
            'goodboy_private_watchlists',
            'smithguard',
            'smithguard_private_watchlists'
        )
        ORDER BY nspname
    LOOP
        EXECUTE format(
            'ALTER SCHEMA %I OWNER TO %I',
            item.schemaname,
            'smithguard-maintenance'
        );
    END LOOP;
END
$source_ownership_transition$;

DO $source_ownership_verify$
BEGIN
    IF (
        SELECT pg_get_userbyid(datdba) <> 'postgres'
        FROM pg_catalog.pg_database
        WHERE datname = current_database()
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace
        WHERE nspname IN (
            'goodboy_security',
            'goodboy_hosted_watch',
            'goodboy_watch',
            'goodboy_private_watchlists',
            'smithguard',
            'smithguard_private_watchlists'
        )
          AND pg_get_userbyid(nspowner) <> 'smithguard-maintenance'
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS c
        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
        WHERE (
                n.nspname IN (
                    'goodboy_security',
                    'goodboy_hosted_watch',
                    'goodboy_watch',
                    'goodboy_private_watchlists',
                    'smithguard',
                    'smithguard_private_watchlists'
                )
                OR (
                    n.nspname = 'public'
                    AND c.relname = 'alembic_version'
                    AND c.relkind IN ('r', 'p')
                )
            )
          AND pg_get_userbyid(c.relowner) <> 'smithguard-maintenance'
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS p
        JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
        WHERE n.nspname IN (
            'goodboy_security',
            'goodboy_hosted_watch',
            'goodboy_watch',
            'goodboy_private_watchlists',
            'smithguard',
            'smithguard_private_watchlists'
        )
          AND pg_get_userbyid(p.proowner) <> 'smithguard-maintenance'
    ) THEN
        RAISE EXCEPTION 'source ownership transition verification failed';
    END IF;
END
$source_ownership_verify$;

COMMIT;
