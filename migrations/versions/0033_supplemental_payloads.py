"""Share future supplemental payloads without rewriting historical receipts."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0033_supplemental_payloads"
down_revision: str | None = "0032_record_accounting"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = (
    "Share future supplemental payloads without rewriting historical receipts"
)
rollback_mode: str = "forward_only"


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.create_table(
        "supplemental_payloads",
        sa.Column("payload_sha256", sa.String(71), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.PrimaryKeyConstraint("payload_sha256"),
        sa.CheckConstraint("payload_sha256 ~ '^sha256:[a-f0-9]{64}$'", name="payload_sha256"),
        sa.CheckConstraint("jsonb_typeof(document) = 'object'", name="document"),
        schema="smithguard",
    )
    op.add_column(
        "supplemental_facts", sa.Column("payload_sha256", sa.String(71)), schema="smithguard"
    )
    op.alter_column("supplemental_facts", "document", nullable=True, schema="smithguard")
    op.create_foreign_key(
        None,
        "supplemental_facts",
        "supplemental_payloads",
        ["payload_sha256"],
        ["payload_sha256"],
        source_schema="smithguard",
        referent_schema="smithguard",
    )
    # The native forward deployment quiesces producers and the API. Validate both
    # constraints normally during that bounded migration; scans do not rewrite
    # existing facts, whose new reference is NULL and original document is intact.
    op.create_check_constraint(
        "payload_choice",
        "supplemental_facts",
        "(document IS NOT NULL AND payload_sha256 IS NULL) OR "
        "(document IS NULL AND payload_sha256 IS NOT NULL)",
        schema="smithguard",
    )
    op.execute("""
        CREATE TRIGGER reject_ledger_mutation BEFORE UPDATE OR DELETE ON
        smithguard.supplemental_payloads FOR EACH ROW
        EXECUTE FUNCTION smithguard.reject_ledger_mutation();
        CREATE TRIGGER reject_ledger_truncate BEFORE TRUNCATE ON
        smithguard.supplemental_payloads FOR EACH STATEMENT
        EXECUTE FUNCTION smithguard.reject_ledger_mutation();
    """)
    op.execute("""
        DO $grants$ BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-collector') THEN
                GRANT SELECT, INSERT ON smithguard.supplemental_payloads TO "smithguard-collector";
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'smithguard-api') THEN
                GRANT SELECT ON smithguard.supplemental_payloads TO "smithguard-api";
            END IF;
        END $grants$;
    """)


def downgrade() -> None:
    raise RuntimeError("0033_supplemental_payloads is forward-only")
