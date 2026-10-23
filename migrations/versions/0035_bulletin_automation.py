"""Private identity protection, analyst queue and compact verification receipts."""

from alembic import op

revision: str = "0035_bulletin_automation"
down_revision: str | None = "0034_public_bulletins"
branch_labels = None
depends_on = None
migration_description: str = "Add private bulletin automation evidence and identity protection"
rollback_mode: str = "forward_only"


def upgrade():
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute(
        "ALTER TABLE smithguard.bulletin_source_status ADD COLUMN coverage_start_at TIMESTAMP WITH TIME ZONE, ADD COLUMN initial_history_complete BOOLEAN, ADD COLUMN coverage_gaps JSONB, ADD COLUMN upstream_due_at TIMESTAMP WITH TIME ZONE"
    )
    op.execute(
        "ALTER TABLE smithguard.official_notice_pending ADD COLUMN qualification_required BOOLEAN NOT NULL DEFAULT FALSE, ADD COLUMN next_attempt_at TIMESTAMP WITH TIME ZONE"
    )
    op.execute(
        "ALTER TABLE smithguard.official_notice_pending DROP CONSTRAINT ck_official_notice_pending_kind, ADD CONSTRAINT ck_official_notice_pending_kind CHECK (kind IN ('new','corrected','withdrawn','recheck'))"
    )
    op.execute(
        "\nCREATE TABLE smithguard.bulletin_identity_aliases (\n\talias_hash VARCHAR(71) NOT NULL, \n\tbulletin_id VARCHAR(64) NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_bulletin_identity_aliases PRIMARY KEY (alias_hash, bulletin_id)\n)\n\n"
    )
    op.execute(
        "\nCREATE TABLE smithguard.bulletin_review_queue (\n\treview_id VARCHAR(71) NOT NULL, \n\tsource_key VARCHAR(40) NOT NULL, \n\trecord_key VARCHAR(64) NOT NULL, \n\tstate VARCHAR(12) NOT NULL, \n\treason VARCHAR(40) NOT NULL, \n\tdocument JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_bulletin_review_queue PRIMARY KEY (review_id), \n\tCONSTRAINT ck_bulletin_review_queue_state CHECK (state IN ('pending','resolved','dismissed')), \n\tCONSTRAINT ck_bulletin_review_queue_size CHECK (octet_length(document::text) <= 16384)\n)\n\n"
    )
    op.execute(
        "CREATE INDEX ix_bulletin_review_pending ON smithguard.bulletin_review_queue (state, created_at, review_id)"
    )
    op.execute(
        "\nCREATE TABLE smithguard.bulletin_maintenance_receipts (\n\treceipt_id VARCHAR(71) NOT NULL, \n\tdocument JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_bulletin_maintenance_receipts PRIMARY KEY (receipt_id), \n\tCONSTRAINT ck_bulletin_maintenance_receipts_size CHECK (octet_length(document::text) <= 98304)\n)\n\n"
    )
    op.execute(
        "CREATE INDEX ix_bulletin_maintenance_created ON smithguard.bulletin_maintenance_receipts (created_at, receipt_id)"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_mutation BEFORE UPDATE OR DELETE ON smithguard.bulletin_identity_aliases FOR EACH ROW EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_truncate BEFORE TRUNCATE ON smithguard.bulletin_identity_aliases FOR EACH STATEMENT EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_mutation BEFORE UPDATE OR DELETE ON smithguard.bulletin_maintenance_receipts FOR EACH ROW EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        "CREATE TRIGGER reject_ledger_truncate BEFORE TRUNCATE ON smithguard.bulletin_maintenance_receipts FOR EACH STATEMENT EXECUTE FUNCTION smithguard.reject_ledger_mutation()"
    )
    op.execute(
        'DO $grants$ BEGIN\nIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = \'smithguard-signals\') THEN\nGRANT SELECT, INSERT ON smithguard.bulletin_identity_aliases, smithguard.bulletin_maintenance_receipts TO "smithguard-signals";\nGRANT SELECT, INSERT, UPDATE ON smithguard.bulletin_review_queue TO "smithguard-signals";\nGRANT SELECT ON smithguard.advisory_catalog_records, smithguard.advisory_package_records, smithguard.collector_progress, smithguard.advisory_catalog_manifests TO "smithguard-signals";\nEND IF;\nEND $grants$'
    )


def downgrade():
    raise RuntimeError("0035_bulletin_automation is forward-only")
