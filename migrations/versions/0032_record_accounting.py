"""Add immutable collection outcomes, page membership and exact resolutions."""

from collections.abc import Sequence

from alembic import op

revision: str = "0032_record_accounting"
down_revision: str | None = "0031_supplemental_feeds"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Add immutable collection record accounting and resolutions"
rollback_mode: str = "forward_only"


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute("""
CREATE TABLE smithguard.collection_record_outcomes (
    outcome_id VARCHAR(160) NOT NULL,
    source_id VARCHAR(160) NOT NULL,
    segment VARCHAR(40) NOT NULL,
    record_key VARCHAR(160) NOT NULL,
    disposition VARCHAR(20) NOT NULL,
    input_sha256 VARCHAR(71) NOT NULL,
    processing_version VARCHAR(160) NOT NULL,
    policy_sha256 VARCHAR(71) NOT NULL,
    batch_id VARCHAR(160) NOT NULL,
    observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    document JSONB NOT NULL,
    record_hash VARCHAR(71) NOT NULL,
    CONSTRAINT pk_collection_record_outcomes PRIMARY KEY (outcome_id),
    CONSTRAINT fk_collection_record_outcomes_batch_id_ingestion_batches FOREIGN KEY(batch_id) REFERENCES smithguard.ingestion_batches (batch_id),
    CONSTRAINT ck_collection_record_outcomes_outcome_id CHECK (outcome_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'),
    CONSTRAINT ck_collection_record_outcomes_source_id CHECK (source_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'),
    CONSTRAINT ck_collection_record_outcomes_segment CHECK (segment ~ '^[a-z][a-z0-9_-]{0,39}$'),
    CONSTRAINT ck_collection_record_outcomes_record_key CHECK (record_key ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}$'),
    CONSTRAINT ck_collection_record_outcomes_processing_version CHECK (processing_version ~ '^[a-z0-9][a-z0-9._-]{1,79}$'),
    CONSTRAINT ck_collection_record_outcomes_input_sha256 CHECK (input_sha256 ~ '^sha256:[a-f0-9]{64}$'),
    CONSTRAINT ck_collection_record_outcomes_policy_sha256 CHECK (policy_sha256 ~ '^sha256:[a-f0-9]{64}$'),
    CONSTRAINT ck_collection_record_outcomes_record_hash CHECK (record_hash ~ '^sha256:[a-f0-9]{64}$'),
    CONSTRAINT ck_collection_record_outcomes_disposition CHECK (disposition IN ('accepted','excluded','quarantined')),
    CONSTRAINT ck_collection_record_outcomes_document CHECK (jsonb_typeof(document) = 'object'),
    CONSTRAINT ck_collection_record_outcomes_document_size CHECK (octet_length(document::text) <= 16384)
)
    """)
    op.execute("""
CREATE INDEX ix_collection_outcomes_case ON smithguard.collection_record_outcomes (source_id, segment, record_key) WHERE disposition <> 'accepted'
    """)
    op.execute("""
CREATE INDEX ix_collection_outcomes_quarantine ON smithguard.collection_record_outcomes (source_id, record_key) WHERE disposition = 'quarantined'
    """)
    op.execute("""
CREATE TABLE smithguard.collection_record_memberships (
    membership_id VARCHAR(160) NOT NULL,
    progress_event_id VARCHAR(160),
    ordinal INTEGER NOT NULL,
    outcome_id VARCHAR(160) NOT NULL,
    acquisition_kind VARCHAR(20) NOT NULL,
    observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    transport_sha256 VARCHAR(71) NOT NULL,
    record_hash VARCHAR(71) NOT NULL,
    CONSTRAINT pk_collection_record_memberships PRIMARY KEY (membership_id),
    CONSTRAINT uq_collection_record_memberships_progress_event_id_ordinal UNIQUE (progress_event_id, ordinal),
    CONSTRAINT fk_collection_record_memberships_progress_event_id_coll_e700 FOREIGN KEY(progress_event_id) REFERENCES smithguard.collector_progress (progress_event_id),
    CONSTRAINT fk_collection_record_memberships_outcome_id_collection__c7e7 FOREIGN KEY(outcome_id) REFERENCES smithguard.collection_record_outcomes (outcome_id),
    CONSTRAINT ck_collection_record_memberships_membership_id CHECK (membership_id ~ '^gbsec:[a-z0-9][a-z0-9:._/-]+$'),
    CONSTRAINT ck_collection_record_memberships_ordinal CHECK (ordinal >= 0 AND ordinal < 100),
    CONSTRAINT ck_collection_record_memberships_acquisition_shape CHECK ((acquisition_kind = 'page' AND progress_event_id IS NOT NULL) OR (acquisition_kind = 'replay' AND progress_event_id IS NULL AND ordinal = 0)),
    CONSTRAINT ck_collection_record_memberships_transport_sha256 CHECK (transport_sha256 ~ '^sha256:[a-f0-9]{64}$'),
    CONSTRAINT ck_collection_record_memberships_record_hash CHECK (record_hash ~ '^sha256:[a-f0-9]{64}$')
)
    """)
    op.execute("""
CREATE INDEX ix_collection_membership_outcome ON smithguard.collection_record_memberships (outcome_id)
    """)
    op.execute("""
CREATE TABLE smithguard.collection_record_resolutions (
    outcome_id VARCHAR(160) NOT NULL,
    replacement_id VARCHAR(160) NOT NULL,
    membership_id VARCHAR(160) NOT NULL,
    resolved_at TIMESTAMP WITH TIME ZONE NOT NULL,
    record_hash VARCHAR(71) NOT NULL,
    CONSTRAINT pk_collection_record_resolutions PRIMARY KEY (outcome_id),
    CONSTRAINT fk_collection_record_resolutions_outcome_id_collection__9044 FOREIGN KEY(outcome_id) REFERENCES smithguard.collection_record_outcomes (outcome_id),
    CONSTRAINT fk_collection_record_resolutions_replacement_id_collect_82cb FOREIGN KEY(replacement_id) REFERENCES smithguard.collection_record_outcomes (outcome_id),
    CONSTRAINT fk_collection_record_resolutions_membership_id_collecti_050b FOREIGN KEY(membership_id) REFERENCES smithguard.collection_record_memberships (membership_id),
    CONSTRAINT ck_collection_record_resolutions_different_outcomes CHECK (outcome_id <> replacement_id),
    CONSTRAINT ck_collection_record_resolutions_record_hash CHECK (record_hash ~ '^sha256:[a-f0-9]{64}$')
)
    """)
    op.execute("""
        CREATE FUNCTION smithguard.validate_collection_outcome() RETURNS trigger
        LANGUAGE plpgsql AS $body$
        DECLARE
            batch smithguard.ingestion_batches%ROWTYPE;
            source_time text;
        BEGIN
            source_time := NEW.document->>'source_updated_at';
            IF source_time IS NOT NULL THEN
                IF jsonb_typeof(NEW.document->'source_updated_at') <> 'string'
                   OR source_time !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})$'
                THEN
                    RAISE EXCEPTION 'collection outcome source timestamp requires an offset'
                        USING ERRCODE = '23514';
                END IF;
                PERFORM source_time::timestamptz;
            END IF;
            SELECT * INTO STRICT batch FROM smithguard.ingestion_batches
            WHERE batch_id = NEW.batch_id;
            IF NEW.source_id <> batch.source_id
               OR (NEW.disposition = 'quarantined') <> (batch.outcome = 'quarantined')
               OR (NEW.document->>'evidence_id') IS DISTINCT FROM batch.raw_evidence_id
               OR (NEW.document->>'governance_decision_id') IS DISTINCT FROM batch.governance_decision_id
               OR (batch.outcome = 'accepted' AND
                   (NEW.document->>'governed_input_sha256') IS DISTINCT FROM batch.input_sha256)
            THEN
                RAISE EXCEPTION 'collection outcome does not match ingestion batch'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $body$;
        CREATE TRIGGER validate_collection_outcome BEFORE INSERT
        ON smithguard.collection_record_outcomes FOR EACH ROW
        EXECUTE FUNCTION smithguard.validate_collection_outcome();
    """)
    op.execute("""
        CREATE FUNCTION smithguard.validate_collection_membership() RETURNS trigger
        LANGUAGE plpgsql AS $body$
        DECLARE
            outcome smithguard.collection_record_outcomes%ROWTYPE;
            progress smithguard.collector_progress%ROWTYPE;
        BEGIN
            SELECT * INTO STRICT outcome FROM smithguard.collection_record_outcomes
            WHERE outcome_id = NEW.outcome_id;
            IF NEW.observed_at < outcome.observed_at THEN
                RAISE EXCEPTION 'collection membership predates its outcome' USING ERRCODE = '23514';
            END IF;
            IF NEW.progress_event_id IS NOT NULL THEN
                SELECT * INTO STRICT progress FROM smithguard.collector_progress
                WHERE progress_event_id = NEW.progress_event_id;
                IF (outcome.source_id, outcome.segment, NEW.observed_at)
                   IS DISTINCT FROM (progress.source_id, progress.segment, progress.occurred_at)
                THEN
                    RAISE EXCEPTION 'collection membership does not match its progress receipt'
                        USING ERRCODE = '23514';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $body$;
        CREATE TRIGGER validate_collection_membership BEFORE INSERT
        ON smithguard.collection_record_memberships FOR EACH ROW
        EXECUTE FUNCTION smithguard.validate_collection_membership();
    """)
    op.execute("""
        CREATE FUNCTION smithguard.validate_collection_resolution() RETURNS trigger
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
               OR (prior.source_id, prior.segment, prior.record_key)
                   IS DISTINCT FROM (replacement.source_id, replacement.segment, replacement.record_key)
               OR prior.record_key LIKE 'opaque:%'
               OR (prior.input_sha256, prior.processing_version, prior.policy_sha256)
                   IS NOT DISTINCT FROM
                   (replacement.input_sha256, replacement.processing_version, replacement.policy_sha256)
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
        CREATE TRIGGER validate_collection_resolution BEFORE INSERT
        ON smithguard.collection_record_resolutions FOR EACH ROW
        EXECUTE FUNCTION smithguard.validate_collection_resolution();
    """)
    for table in (
        "collection_record_outcomes",
        "collection_record_memberships",
        "collection_record_resolutions",
    ):
        op.execute(
            f"CREATE TRIGGER reject_ledger_mutation BEFORE UPDATE OR DELETE ON "
            f"smithguard.{table} FOR EACH ROW "
            "EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
        )
        op.execute(
            f"CREATE TRIGGER reject_ledger_truncate BEFORE TRUNCATE ON "
            f"smithguard.{table} FOR EACH STATEMENT "
            "EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
        )
    op.execute("""
        DO $grants$ BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-collector') THEN
                GRANT SELECT, INSERT ON smithguard.collection_record_outcomes, smithguard.collection_record_memberships, smithguard.collection_record_resolutions TO "smithguard-collector";
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-api') THEN
                GRANT SELECT ON smithguard.collection_record_outcomes, smithguard.collection_record_resolutions TO "smithguard-api";
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-health') THEN
                GRANT SELECT ON smithguard.collection_record_outcomes, smithguard.collection_record_resolutions TO "smithguard-health";
            END IF;
        END $grants$;
    """)


def downgrade() -> None:
    raise RuntimeError("0032_record_accounting is forward-only")
