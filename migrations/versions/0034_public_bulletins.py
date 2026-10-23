"""Add bounded bulletin projections and immutable intake/publication evidence."""

from alembic import op

revision: str = "0034_public_bulletins"
down_revision: str | None = "0033_supplemental_payloads"
branch_labels = None
depends_on = None
migration_description: str = (
    "Add bounded bulletin projections and immutable intake/publication evidence"
)
rollback_mode: str = "forward_only"


# Frozen authored DDL: no runtime ORM imports or changes to applied migrations.
def upgrade():
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute(
        "CREATE TABLE smithguard.bulletin_stream (\n\tstream_id VARCHAR(8) NOT NULL, \n\tsequence BIGINT NOT NULL, \n\tmode VARCHAR(20) NOT NULL, \n\tgrant_hash VARCHAR(71), \n\tstatus_checked_at TIMESTAMP WITH TIME ZONE, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_bulletin_stream PRIMARY KEY (stream_id), \n\tCONSTRAINT ck_bulletin_stream_identity CHECK (stream_id = 'v1'), \n\tCONSTRAINT ck_bulletin_stream_sequence CHECK (sequence >= 0), \n\tCONSTRAINT ck_bulletin_stream_mode CHECK (mode IN ('paused','manual_preview','automatic'))\n)"
    )
    op.execute(
        "CREATE TABLE smithguard.bulletin_current (\n\tbulletin_id VARCHAR(64) NOT NULL, \n\trevision INTEGER NOT NULL, \n\tsequence BIGINT NOT NULL, \n\tsource_key VARCHAR(40) NOT NULL, \n\tevidence_class VARCHAR(30) NOT NULL, \n\tmode VARCHAR(20) NOT NULL, \n\ttombstoned BOOLEAN NOT NULL, \n\tfreshness_reason VARCHAR(40), \n\tfirst_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tverified_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tverification_due_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\texpires_at TIMESTAMP WITH TIME ZONE, \n\tCONSTRAINT pk_bulletin_current PRIMARY KEY (bulletin_id), \n\tCONSTRAINT ck_bulletin_current_identity CHECK (bulletin_id ~ '^[a-f0-9]{64}$'), \n\tCONSTRAINT ck_bulletin_current_revision CHECK (revision >= 1 AND sequence >= 1), \n\tCONSTRAINT ck_bulletin_current_evidence_class CHECK (evidence_class IN ('official_notice','official_advisory','emerging_report')), \n\tCONSTRAINT ck_bulletin_current_mode CHECK (mode IN ('manual_preview','automatic','reviewed'))\n)"
    )
    op.execute(
        "CREATE INDEX ix_bulletin_current_due ON smithguard.bulletin_current (verification_due_at, bulletin_id)"
    )
    op.execute(
        "CREATE INDEX ix_bulletin_current_expiry ON smithguard.bulletin_current (expires_at, bulletin_id)"
    )
    op.execute(
        "CREATE INDEX ix_bulletin_current_source ON smithguard.bulletin_current (source_key, bulletin_id)"
    )
    op.execute(
        "CREATE TABLE smithguard.bulletin_revisions (\n\tbulletin_id VARCHAR(64) NOT NULL, \n\trevision INTEGER NOT NULL, \n\tdocument JSONB NOT NULL, \n\tcontent_hash VARCHAR(71) NOT NULL, \n\tpredecessor_hash VARCHAR(71), \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_bulletin_revisions PRIMARY KEY (bulletin_id, revision), \n\tCONSTRAINT ck_bulletin_revisions_revision CHECK (revision >= 1), \n\tCONSTRAINT ck_bulletin_revisions_hash CHECK (content_hash ~ '^sha256:[a-f0-9]{64}$'), \n\tCONSTRAINT ck_bulletin_revisions_size CHECK (octet_length(document::text) <= 32768)\n)"
    )
    op.execute(
        "CREATE TABLE smithguard.bulletin_public_versions (\n\tbulletin_id VARCHAR(64) NOT NULL, \n\trevision INTEGER NOT NULL, \n\tsequence BIGINT NOT NULL, \n\tdocument JSONB NOT NULL, \n\tcontent_hash VARCHAR(71) NOT NULL, \n\tpredecessor_hash VARCHAR(71), \n\tpublication_decision_id VARCHAR(71) NOT NULL, \n\tpolicy_id VARCHAR(80) NOT NULL, \n\tgrant_hash VARCHAR(71) NOT NULL, \n\ttombstoned BOOLEAN NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_bulletin_public_versions PRIMARY KEY (bulletin_id, revision), \n\tCONSTRAINT ck_bulletin_public_versions_revision CHECK (revision >= 1 AND sequence >= 1), \n\tCONSTRAINT ck_bulletin_public_versions_hash CHECK (content_hash ~ '^sha256:[a-f0-9]{64}$'), \n\tCONSTRAINT ck_bulletin_public_versions_size CHECK (octet_length(document::text) <= 32768), \n\tCONSTRAINT fk_bulletin_public_versions_bulletin_id_revision_bullet_037c FOREIGN KEY(bulletin_id, revision) REFERENCES smithguard.bulletin_revisions (bulletin_id, revision) DEFERRABLE INITIALLY DEFERRED, \n\tCONSTRAINT uq_bulletin_public_versions_sequence UNIQUE (sequence)\n)"
    )
    op.execute(
        "CREATE INDEX ix_bulletin_public_sequence ON smithguard.bulletin_public_versions (sequence, bulletin_id)"
    )
    op.execute(
        "CREATE TABLE smithguard.bulletin_events (\n\tsequence BIGINT NOT NULL, \n\tbulletin_id VARCHAR(64) NOT NULL, \n\trevision INTEGER NOT NULL, \n\tkind VARCHAR(32) NOT NULL, \n\treason VARCHAR(40) NOT NULL, \n\toccurred_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_bulletin_events PRIMARY KEY (sequence), \n\tCONSTRAINT ck_bulletin_events_sequence CHECK (sequence >= 1 AND revision >= 1), \n\tCONSTRAINT fk_bulletin_events_bulletin_id_revision_bulletin_revisions FOREIGN KEY(bulletin_id, revision) REFERENCES smithguard.bulletin_revisions (bulletin_id, revision) DEFERRABLE INITIALLY DEFERRED, \n\tCONSTRAINT ck_bulletin_events_kind CHECK (kind IN ('published','corrected','disputed','withdrawn','expired','freshness_stale','freshness_verified','public_tombstoned','public_purge_requested','public_purged','public_purge_failed','associated'))\n)"
    )
    op.execute(
        "CREATE INDEX ix_bulletin_events_bulletin ON smithguard.bulletin_events (bulletin_id, sequence)"
    )
    op.execute(
        "CREATE INDEX ix_bulletin_events_retention ON smithguard.bulletin_events (occurred_at, sequence)"
    )
    op.execute(
        "CREATE TABLE smithguard.bulletin_decisions (\n\tdecision_id VARCHAR(71) NOT NULL, \n\tbulletin_id VARCHAR(64) NOT NULL, \n\tsequence BIGINT NOT NULL, \n\tmanual_approval_id VARCHAR(64), \n\tdocument JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_bulletin_decisions PRIMARY KEY (decision_id), \n\tCONSTRAINT ck_bulletin_decisions_identity CHECK (decision_id ~ '^sha256:[a-f0-9]{64}$'), \n\tCONSTRAINT ck_bulletin_decisions_size CHECK (octet_length(document::text) <= 16384), \n\tCONSTRAINT uq_bulletin_decisions_sequence UNIQUE (sequence), \n\tCONSTRAINT uq_bulletin_decisions_manual_approval_id UNIQUE (manual_approval_id)\n)"
    )
    op.execute(
        "CREATE TABLE smithguard.official_source_checkpoints (\n\tsource_key VARCHAR(40) NOT NULL, \n\tdocument JSONB NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_official_source_checkpoints PRIMARY KEY (source_key), \n\tCONSTRAINT ck_official_source_checkpoints_size CHECK (octet_length(document::text) <= 16384)\n)"
    )
    op.execute(
        "CREATE TABLE smithguard.official_notice_current (\n\tsource_key VARCHAR(40) NOT NULL, \n\trecord_key VARCHAR(64) NOT NULL, \n\tdocument JSONB NOT NULL, \n\tsemantic_hash VARCHAR(71) NOT NULL, \n\tpublication_pending BOOLEAN NOT NULL, \n\tfirst_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_official_notice_current PRIMARY KEY (source_key, record_key), \n\tCONSTRAINT ck_official_notice_current_identity CHECK (record_key ~ '^[a-f0-9]{64}$'), \n\tCONSTRAINT ck_official_notice_current_size CHECK (octet_length(document::text) <= 16384)\n)"
    )
    op.execute(
        "CREATE INDEX ix_official_notice_updated ON smithguard.official_notice_current (source_key, updated_at, record_key)"
    )
    op.execute(
        "CREATE TABLE smithguard.official_notice_evidence (\n\tevidence_id VARCHAR(71) NOT NULL, \n\tsource_key VARCHAR(40) NOT NULL, \n\trecord_key VARCHAR(64) NOT NULL, \n\tdocument JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_official_notice_evidence PRIMARY KEY (evidence_id), \n\tCONSTRAINT ck_official_notice_evidence_identity CHECK (evidence_id ~ '^sha256:[a-f0-9]{64}$'), \n\tCONSTRAINT ck_official_notice_evidence_size CHECK (octet_length(document::text) <= 16384)\n)"
    )
    op.execute(
        "CREATE INDEX ix_official_evidence_record ON smithguard.official_notice_evidence (source_key, record_key, created_at)"
    )
    op.execute(
        "CREATE TABLE smithguard.official_intake_runs (\n\tepoch VARCHAR(80) NOT NULL, \n\tkind VARCHAR(12) NOT NULL, \n\tdocument JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_official_intake_runs PRIMARY KEY (epoch, kind), \n\tCONSTRAINT ck_official_intake_runs_kind CHECK (kind IN ('intent','closure','cutover','rollup')), \n\tCONSTRAINT ck_official_intake_runs_size CHECK (octet_length(document::text) <= 32768)\n)"
    )
    op.execute(
        "CREATE INDEX ix_official_intake_runs_created ON smithguard.official_intake_runs (created_at, epoch)"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_mutation BEFORE UPDATE OR DELETE ON smithguard.bulletin_revisions FOR EACH ROW EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_truncate BEFORE TRUNCATE ON smithguard.bulletin_revisions FOR EACH STATEMENT EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_mutation BEFORE UPDATE OR DELETE ON smithguard.bulletin_events FOR EACH ROW EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_truncate BEFORE TRUNCATE ON smithguard.bulletin_events FOR EACH STATEMENT EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_mutation BEFORE UPDATE OR DELETE ON smithguard.bulletin_decisions FOR EACH ROW EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_truncate BEFORE TRUNCATE ON smithguard.bulletin_decisions FOR EACH STATEMENT EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_mutation BEFORE UPDATE OR DELETE ON smithguard.official_notice_evidence FOR EACH ROW EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_truncate BEFORE TRUNCATE ON smithguard.official_notice_evidence FOR EACH STATEMENT EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_mutation BEFORE UPDATE OR DELETE ON smithguard.official_intake_runs FOR EACH ROW EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_truncate BEFORE TRUNCATE ON smithguard.official_intake_runs FOR EACH STATEMENT EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "DO $grants$ BEGIN\nIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-api') THEN\nGRANT SELECT ON smithguard.bulletin_stream, smithguard.bulletin_current, smithguard.bulletin_public_versions, smithguard.bulletin_events TO \"smithguard-api\";\nEND IF;\nIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-signals') THEN\nGRANT SELECT, INSERT, UPDATE ON smithguard.bulletin_stream, smithguard.bulletin_current, smithguard.bulletin_public_versions, smithguard.official_source_checkpoints, smithguard.official_notice_current TO \"smithguard-signals\";\nEND IF;\nIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-signals') THEN\nGRANT SELECT, INSERT ON smithguard.bulletin_revisions, smithguard.bulletin_events, smithguard.bulletin_decisions, smithguard.official_notice_evidence, smithguard.official_intake_runs TO \"smithguard-signals\";\nEND IF;\nEND $grants$"
    )

    op.execute(
        "CREATE TABLE smithguard.bulletin_source_status (\n\tsource_key VARCHAR(40) NOT NULL, \n\tstate VARCHAR(20) NOT NULL, \n\treason VARCHAR(40), \n\tlast_attempt_at TIMESTAMP WITH TIME ZONE, \n\tlast_success_at TIMESTAMP WITH TIME ZONE, \n\tcomplete_through_at TIMESTAMP WITH TIME ZONE, \n\toldest_pending_at TIMESTAMP WITH TIME ZONE, \n\tpending_count INTEGER NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_bulletin_source_status PRIMARY KEY (source_key), \n\tCONSTRAINT ck_bulletin_source_status_state CHECK (state IN ('fresh','stale','unavailable','paused','incomplete')), \n\tCONSTRAINT ck_bulletin_source_status_pending_count CHECK (pending_count >= 0)\n)"
    )
    op.execute(
        "DO $grants$ BEGIN\nIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-api') THEN\nGRANT SELECT ON smithguard.bulletin_source_status TO \"smithguard-api\";\nEND IF;\nIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-signals') THEN\nGRANT SELECT, INSERT, UPDATE ON smithguard.bulletin_source_status TO \"smithguard-signals\";\nEND IF;\nEND $grants$"
    )

    op.execute(
        "CREATE TABLE smithguard.official_notice_pending (\n\tsource_key VARCHAR(40) NOT NULL, \n\trecord_key VARCHAR(64) NOT NULL, \n\trecord_url VARCHAR(2048) NOT NULL, \n\tevidence_id VARCHAR(71) NOT NULL, \n\tkind VARCHAR(12) NOT NULL, \n\tfirst_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tprocessed_at TIMESTAMP WITH TIME ZONE, \n\tCONSTRAINT pk_official_notice_pending PRIMARY KEY (source_key, record_key), \n\tCONSTRAINT ck_official_notice_pending_kind CHECK (kind IN ('new','corrected','withdrawn'))\n)"
    )

    op.execute(
        "CREATE INDEX ix_official_pending_work ON smithguard.official_notice_pending (source_key, processed_at, kind, first_seen_at)"
    )

    op.execute(
        "DO $grants$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-signals') THEN GRANT SELECT, INSERT, UPDATE ON smithguard.official_notice_pending TO \"smithguard-signals\"; END IF; END $grants$"
    )
    op.execute("""DO $grants$ BEGIN
IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-health') THEN
GRANT SELECT ON smithguard.bulletin_stream, smithguard.bulletin_source_status TO "smithguard-health";
END IF;
END $grants$""")

    op.execute("""
DO $grants$ BEGIN
IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-signals') THEN
GRANT SELECT ON smithguard.supplemental_snapshots, smithguard.supplemental_facts,
    smithguard.supplemental_payloads TO "smithguard-signals";
END IF;
END $grants$;
""")


def downgrade():
    raise RuntimeError("0034_public_bulletins is forward-only")
