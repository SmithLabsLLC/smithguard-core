"""Immutable OpenSSF attempt proofs and exact cross-tree record repair."""

from alembic import op

revision: str = "0038_openssf_resilience"
down_revision: str | None = "0037_bulletin_intake_health"
branch_labels = None
depends_on = None
migration_description: str = (
    "Add immutable OpenSSF partial attempt proofs and exact repair semantics"
)
rollback_mode: str = "forward_only"


def upgrade():
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute("""
        CREATE TABLE smithguard.openssf_catalog_attempts (
            run_id VARCHAR(160) PRIMARY KEY,
            state VARCHAR(20) NOT NULL,
            observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
            document JSONB NOT NULL,
            record_hash VARCHAR(71) NOT NULL,
            CONSTRAINT ck_openssf_catalog_attempts_run_id CHECK (run_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'),
            CONSTRAINT ck_openssf_catalog_attempts_state CHECK (state IN ('partial','complete','failed')),
            CONSTRAINT ck_openssf_catalog_attempts_document CHECK (jsonb_typeof(document) = 'object'),
            CONSTRAINT ck_openssf_catalog_attempts_document_size CHECK (octet_length(document::text) <= 16384),
            CONSTRAINT ck_openssf_catalog_attempts_record_hash CHECK (record_hash ~ '^sha256:[a-f0-9]{64}$')
        );
        CREATE INDEX ix_openssf_attempts_observed ON smithguard.openssf_catalog_attempts (observed_at);
        CREATE TRIGGER reject_ledger_mutation BEFORE UPDATE OR DELETE ON smithguard.openssf_catalog_attempts
            FOR EACH ROW EXECUTE FUNCTION smithguard.reject_ledger_mutation();
        CREATE TRIGGER reject_ledger_truncate BEFORE TRUNCATE ON smithguard.openssf_catalog_attempts
            FOR EACH STATEMENT EXECUTE FUNCTION smithguard.reject_ledger_mutation();
    """)
    op.execute("""
        CREATE OR REPLACE FUNCTION smithguard.validate_collection_resolution() RETURNS trigger
        LANGUAGE plpgsql AS $body$
        DECLARE
            prior smithguard.collection_record_outcomes%ROWTYPE;
            replacement smithguard.collection_record_outcomes%ROWTYPE;
            observation smithguard.collection_record_memberships%ROWTYPE;
            prior_time timestamptz;
            replacement_time timestamptz;
        BEGIN
            SELECT * INTO STRICT prior FROM smithguard.collection_record_outcomes
            WHERE outcome_id = NEW.outcome_id;
            SELECT * INTO STRICT replacement FROM smithguard.collection_record_outcomes
            WHERE outcome_id = NEW.replacement_id;
            SELECT * INTO STRICT observation FROM smithguard.collection_record_memberships
            WHERE membership_id = NEW.membership_id;
            prior_time := (prior.document->>'source_updated_at')::timestamptz;
            replacement_time := (replacement.document->>'source_updated_at')::timestamptz;
            IF prior.disposition NOT IN ('excluded','quarantined')
               OR replacement.disposition <> 'accepted'
               OR (prior.source_id, prior.record_key)
                   IS DISTINCT FROM (replacement.source_id, replacement.record_key)
               OR (prior.segment <> replacement.segment AND NOT COALESCE((
                   prior.source_id = 'gbsec:source:openssf-malicious-packages'
                   AND prior.segment IN ('openssf-malicious','openssf-withdrawn')
                   AND replacement.segment IN ('openssf-malicious','openssf-withdrawn')
                   AND prior.document->'openssf_git'->>'reason' = 'openssf_tree_withdrawal_mismatch'
                   AND replacement.document->'openssf_git'->>'validated' = 'true'
               ), false))
               OR (prior.source_id = 'gbsec:source:openssf-malicious-packages' AND NOT COALESCE((
                   prior.document->'openssf_git'->>'reason' = 'openssf_tree_withdrawal_mismatch'
                   AND replacement.document->'openssf_git'->>'validated' = 'true'
                   AND replacement.segment = 'openssf-' || (replacement.document->'openssf_git'->>'tree')
               ), false))
               OR prior.record_key LIKE 'opaque:%'
               OR ((prior.input_sha256, prior.processing_version, prior.policy_sha256)
                   IS NOT DISTINCT FROM
                   (replacement.input_sha256, replacement.processing_version, replacement.policy_sha256)
                   AND NOT (prior.source_id = 'gbsec:source:openssf-malicious-packages'
                       AND prior.segment <> replacement.segment))
               OR (prior_time IS NOT NULL AND
                   (replacement_time IS NULL OR replacement_time < prior_time))
               OR observation.outcome_id <> replacement.outcome_id
               OR observation.observed_at < prior.observed_at
               OR NEW.resolved_at < observation.observed_at
               OR NEW.resolved_at < prior.observed_at
               OR NEW.resolved_at < replacement.observed_at
            THEN
                RAISE EXCEPTION 'collection resolution requires a corrected exact accepted record'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $body$;
    """)
    op.execute("""
        CREATE FUNCTION smithguard.validate_openssf_attempt() RETURNS trigger
        LANGUAGE plpgsql AS $body$
        DECLARE
            item jsonb;
            member smithguard.collection_record_memberships%ROWTYPE;
            outcome smithguard.collection_record_outcomes%ROWTYPE;
            rejections jsonb;
            rejected integer;
            accepted integer;
            scanned integer;
        BEGIN
            rejections := NEW.document->'rejections';
            IF NEW.document->>'schema_version' IS DISTINCT FROM '1.0.0'
               OR jsonb_typeof(rejections) IS DISTINCT FROM 'array'
            THEN
                RAISE EXCEPTION 'invalid OpenSSF terminal receipt' USING ERRCODE = '23514';
            END IF;
            IF NEW.state = 'failed' AND (
                (SELECT count(*) FROM jsonb_object_keys(NEW.document)) <> 3
                OR NOT (NEW.document ?& ARRAY['schema_version','commit','rejections'])
            ) THEN
                RAISE EXCEPTION 'failed OpenSSF attempt cannot claim a partition'
                    USING ERRCODE = '23514';
            END IF;
            rejected := jsonb_array_length(rejections);
            IF rejected > 10 OR (SELECT count(DISTINCT value->>'record_key') FROM jsonb_array_elements(rejections)) <> rejected THEN
                RAISE EXCEPTION 'invalid OpenSSF rejection count' USING ERRCODE = '23514';
            END IF;
            IF NEW.state <> 'failed' THEN
                accepted := (NEW.document->>'accepted_count')::integer;
                scanned := (NEW.document->>'scanned_count')::integer;
                IF accepted IS NULL OR scanned IS NULL OR accepted < 0 OR scanned > 500000
                   OR scanned <> accepted + rejected
                   OR (NEW.document->>'rejected_count')::integer IS DISTINCT FROM rejected
                   OR (NEW.state = 'partial') <> (rejected > 0)
                   OR NEW.document->>'commit' !~ '^[a-f0-9]{40}$'
                   OR NEW.document->>'commit' IS NULL
                   OR (NEW.document->>'validated_at')::timestamptz IS DISTINCT FROM NEW.observed_at
                THEN
                    RAISE EXCEPTION 'invalid OpenSSF partition proof' USING ERRCODE = '23514';
                END IF;
                FOREACH item IN ARRAY ARRAY[NEW.document->'tree_sha256', NEW.document->'accepted_sha256'] LOOP
                    IF jsonb_typeof(item) IS DISTINCT FROM 'object'
                       OR item->>'malicious' IS NULL OR item->>'withdrawn' IS NULL
                       OR item->>'malicious' !~ '^sha256:[a-f0-9]{64}$'
                       OR item->>'withdrawn' !~ '^sha256:[a-f0-9]{64}$'
                       OR (SELECT count(*) FROM jsonb_object_keys(item)) <> 2
                    THEN
                        RAISE EXCEPTION 'invalid OpenSSF tree commitments' USING ERRCODE = '23514';
                    END IF;
                END LOOP;
            END IF;
            FOR item IN SELECT value FROM jsonb_array_elements(rejections) LOOP
                SELECT * INTO STRICT member FROM smithguard.collection_record_memberships
                    WHERE membership_id = item->>'membership_id';
                SELECT * INTO STRICT outcome FROM smithguard.collection_record_outcomes
                    WHERE outcome_id = item->>'outcome_id';
                IF member.outcome_id <> outcome.outcome_id
                   OR outcome.source_id <> 'gbsec:source:openssf-malicious-packages'
                   OR outcome.record_key IS DISTINCT FROM item->>'record_key'
                   OR outcome.segment IS DISTINCT FROM 'openssf-' || (item->>'tree')
                   OR outcome.disposition <> 'quarantined'
                   OR outcome.input_sha256 IS DISTINCT FROM item->>'input_sha256'
                   OR member.transport_sha256 IS DISTINCT FROM item->>'input_sha256'
                   OR item->>'reason' IS DISTINCT FROM 'openssf_tree_withdrawal_mismatch'
                   OR item->>'commit' IS DISTINCT FROM NEW.document->>'commit'
                   OR member.observed_at > NEW.observed_at
                THEN
                    RAISE EXCEPTION 'OpenSSF receipt rejection membership differs' USING ERRCODE = '23514';
                END IF;
            END LOOP;
            RETURN NEW;
        END;
        $body$;
        CREATE TRIGGER validate_openssf_attempt BEFORE INSERT ON smithguard.openssf_catalog_attempts
            FOR EACH ROW EXECUTE FUNCTION smithguard.validate_openssf_attempt();
    """)
    op.execute("""
        DO $grants$ BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-collector') THEN
                GRANT SELECT, INSERT ON smithguard.openssf_catalog_attempts TO "smithguard-collector";
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-api') THEN
                GRANT SELECT ON smithguard.openssf_catalog_attempts TO "smithguard-api";
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-health') THEN
                GRANT SELECT ON smithguard.openssf_catalog_attempts TO "smithguard-health";
            END IF;
        END $grants$;
    """)


def downgrade():
    raise RuntimeError("0038_openssf_resilience is forward-only")
