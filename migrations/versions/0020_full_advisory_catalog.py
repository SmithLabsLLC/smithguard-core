"""create the complete advisory catalog and segmented collector state

Revision ID: 0020_full_advisory_catalog
Revises: 0019_smithguard_rebrand
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0020_full_advisory_catalog"
down_revision: str | None = "0019_smithguard_rebrand"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Add complete GitHub and OpenSSF advisory catalog storage"
rollback_mode: str = "forward_only"

SCHEMA = "smithguard"
STABLE_ID_SQL = r"^gbsec:[a-z0-9][a-z0-9:._/-]+$"
SHA256_SQL = r"^sha256:[a-f0-9]{64}$"


def upgrade() -> None:
    """Add append-only full-catalog tables without rewriting prior evidence."""
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.add_column(
        "collector_progress",
        sa.Column(
            "segment",
            sa.String(length=40),
            nullable=False,
            server_default="legacy-malware",
        ),
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_collector_progress_segment"),
        "collector_progress",
        "segment IN ('legacy-malware', 'malware', 'reviewed', 'unreviewed')",
        schema=SCHEMA,
    )
    op.drop_constraint(
        op.f("uq_collector_progress_source_id_lane_sequence"),
        "collector_progress",
        schema=SCHEMA,
        type_="unique",
    )
    op.create_unique_constraint(
        op.f("uq_collector_progress_source_id_segment_lane_sequence"),
        "collector_progress",
        ["source_id", "segment", "lane", "sequence"],
        schema=SCHEMA,
    )
    op.drop_index(
        "ix_collector_progress_not_before",
        table_name="collector_progress",
        schema=SCHEMA,
    )
    op.create_index(
        "ix_collector_progress_not_before",
        "collector_progress",
        ["source_id", "segment", "lane", "not_before"],
        unique=False,
        schema=SCHEMA,
    )

    op.create_table(
        "advisory_catalog_records",
        sa.Column("catalog_event_id", sa.String(length=160), nullable=False),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("upstream_record_id", sa.String(length=160), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("source_type", sa.String(length=40), nullable=False),
        sa.Column("claim_type", sa.String(length=40), nullable=False),
        sa.Column("confidence", sa.String(length=40), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("cwe_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("aliases", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "package_omission_counts",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("canonical_url", sa.Text(), nullable=False),
        sa.Column("evidence_id", sa.String(length=160), nullable=False),
        sa.Column("governance_decision_id", sa.String(length=160), nullable=False),
        sa.Column("source_published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_sha256", sa.String(length=71), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.PrimaryKeyConstraint("catalog_event_id", name=op.f("pk_advisory_catalog_records")),
        sa.UniqueConstraint(
            "source_id",
            "upstream_record_id",
            "revision",
            name=op.f("uq_advisory_catalog_records_source_id_upstream_record_id_revision"),
        ),
        sa.CheckConstraint(
            f"catalog_event_id ~ '{STABLE_ID_SQL}'",
            name=op.f("ck_advisory_catalog_records_catalog_event_id"),
        ),
        sa.CheckConstraint(
            f"source_id ~ '{STABLE_ID_SQL}'",
            name=op.f("ck_advisory_catalog_records_source_id"),
        ),
        sa.CheckConstraint(
            f"evidence_id ~ '{STABLE_ID_SQL}'",
            name=op.f("ck_advisory_catalog_records_evidence_id"),
        ),
        sa.CheckConstraint(
            f"governance_decision_id ~ '{STABLE_ID_SQL}'",
            name=op.f("ck_advisory_catalog_records_governance_decision_id"),
        ),
        sa.CheckConstraint(
            f"source_sha256 ~ '{SHA256_SQL}'",
            name=op.f("ck_advisory_catalog_records_source_sha256"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256_SQL}'",
            name=op.f("ck_advisory_catalog_records_record_hash"),
        ),
        sa.CheckConstraint(
            "source_type IN ('malware', 'reviewed', 'unreviewed', 'openssf')",
            name=op.f("ck_advisory_catalog_records_source_type"),
        ),
        sa.CheckConstraint(
            "claim_type IN ('malicious', 'compromised', 'vulnerable')",
            name=op.f("ck_advisory_catalog_records_claim_type"),
        ),
        sa.CheckConstraint(
            "confidence IN ('confirmed', 'unverified')",
            name=op.f("ck_advisory_catalog_records_confidence"),
        ),
        sa.CheckConstraint(
            "state IN ('active', 'withdrawn')",
            name=op.f("ck_advisory_catalog_records_state"),
        ),
        sa.CheckConstraint("revision >= 1", name=op.f("ck_advisory_catalog_records_revision")),
        sa.CheckConstraint(
            "jsonb_typeof(cwe_ids) = 'array' AND jsonb_array_length(cwe_ids) <= 100",
            name=op.f("ck_advisory_catalog_records_cwe_ids"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(aliases) = 'array' AND jsonb_array_length(aliases) <= 100",
            name=op.f("ck_advisory_catalog_records_aliases"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(package_omission_counts) = 'object'",
            name=op.f("ck_advisory_catalog_records_package_omission_counts"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_advisory_catalog_source_record_revision",
        "advisory_catalog_records",
        ["source_id", "upstream_record_id", "revision"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_advisory_catalog_state_updated",
        "advisory_catalog_records",
        ["state", "source_updated_at"],
        schema=SCHEMA,
    )

    op.create_table(
        "advisory_package_records",
        sa.Column("package_event_id", sa.String(length=160), nullable=False),
        sa.Column("catalog_event_id", sa.String(length=160), nullable=False),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("upstream_record_id", sa.String(length=160), nullable=False),
        sa.Column("entry_key", sa.String(length=160), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("ecosystem", sa.String(length=40), nullable=False),
        sa.Column("raw_ecosystem", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("exact_versions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("affected_ranges", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("claim_type", sa.String(length=40), nullable=False),
        sa.Column("confidence", sa.String(length=40), nullable=False),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_sha256", sa.String(length=71), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.PrimaryKeyConstraint("package_event_id", name=op.f("pk_advisory_package_records")),
        sa.UniqueConstraint(
            "source_id",
            "upstream_record_id",
            "entry_key",
            "revision",
            name=op.f(
                "uq_advisory_package_records_source_id_upstream_record_id_entry_key_revision"
            ),
        ),
        sa.CheckConstraint(
            f"package_event_id ~ '{STABLE_ID_SQL}'",
            name=op.f("ck_advisory_package_records_package_event_id"),
        ),
        sa.CheckConstraint(
            f"catalog_event_id ~ '{STABLE_ID_SQL}'",
            name=op.f("ck_advisory_package_records_catalog_event_id"),
        ),
        sa.CheckConstraint(
            f"source_id ~ '{STABLE_ID_SQL}'",
            name=op.f("ck_advisory_package_records_source_id"),
        ),
        sa.CheckConstraint(
            f"source_sha256 ~ '{SHA256_SQL}'",
            name=op.f("ck_advisory_package_records_source_sha256"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256_SQL}'",
            name=op.f("ck_advisory_package_records_record_hash"),
        ),
        sa.CheckConstraint("revision >= 1", name=op.f("ck_advisory_package_records_revision")),
        sa.CheckConstraint(
            "ecosystem IN ('npm', 'pypi', 'github-actions', 'oci', 'docker', 'go', "
            "'rust', 'composer', 'erlang', 'git', 'maven', 'nuget', 'open-vsx', "
            "'pub', 'rubygems', 'swift', 'vscode')",
            name=op.f("ck_advisory_package_records_ecosystem"),
        ),
        sa.CheckConstraint(
            "char_length(name) BETWEEN 1 AND 300",
            name=op.f("ck_advisory_package_records_name"),
        ),
        sa.CheckConstraint(
            "state IN ('active', 'withdrawn', 'removed')",
            name=op.f("ck_advisory_package_records_state"),
        ),
        sa.CheckConstraint(
            "claim_type IN ('malicious', 'compromised', 'vulnerable')",
            name=op.f("ck_advisory_package_records_claim_type"),
        ),
        sa.CheckConstraint(
            "confidence IN ('confirmed', 'unverified')",
            name=op.f("ck_advisory_package_records_confidence"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(exact_versions) = 'array' "
            "AND jsonb_array_length(exact_versions) <= 10000",
            name=op.f("ck_advisory_package_records_exact_versions"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(affected_ranges) = 'array' "
            "AND jsonb_array_length(affected_ranges) <= 1000",
            name=op.f("ck_advisory_package_records_affected_ranges"),
        ),
        sa.ForeignKeyConstraint(
            ["catalog_event_id"],
            ["smithguard.advisory_catalog_records.catalog_event_id"],
            name="fk_advisory_package_catalog",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_advisory_package_coordinate_state",
        "advisory_package_records",
        ["ecosystem", "name", "state", "source_updated_at"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_advisory_package_source_record_revision",
        "advisory_package_records",
        ["source_id", "upstream_record_id", "revision"],
        schema=SCHEMA,
    )

    op.create_table(
        "advisory_catalog_inventory",
        sa.Column("inventory_event_id", sa.String(length=160), nullable=False),
        sa.Column("catalog_event_id", sa.String(length=160), nullable=False),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("segment", sa.String(length=40), nullable=False),
        sa.Column("source_snapshot", sa.String(length=160), nullable=False),
        sa.Column("upstream_record_id", sa.String(length=160), nullable=False),
        sa.Column("source_sha256", sa.String(length=71), nullable=False),
        sa.Column("package_entry_count", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.PrimaryKeyConstraint(
            "inventory_event_id",
            name=op.f("pk_advisory_catalog_inventory"),
        ),
        sa.UniqueConstraint(
            "source_id",
            "segment",
            "source_snapshot",
            "upstream_record_id",
            name=op.f(
                "uq_advisory_catalog_inventory_source_id_segment_source_snapshot_upstream_record_id"
            ),
        ),
        sa.CheckConstraint(
            f"inventory_event_id ~ '{STABLE_ID_SQL}'",
            name=op.f("ck_advisory_catalog_inventory_inventory_event_id"),
        ),
        sa.CheckConstraint(
            f"catalog_event_id ~ '{STABLE_ID_SQL}'",
            name=op.f("ck_advisory_catalog_inventory_catalog_event_id"),
        ),
        sa.CheckConstraint(
            f"source_id ~ '{STABLE_ID_SQL}'",
            name=op.f("ck_advisory_catalog_inventory_source_id"),
        ),
        sa.CheckConstraint(
            f"source_sha256 ~ '{SHA256_SQL}'",
            name=op.f("ck_advisory_catalog_inventory_source_sha256"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256_SQL}'",
            name=op.f("ck_advisory_catalog_inventory_record_hash"),
        ),
        sa.CheckConstraint(
            "segment IN ('malware', 'reviewed', 'unreviewed')",
            name=op.f("ck_advisory_catalog_inventory_segment"),
        ),
        sa.CheckConstraint(
            "package_entry_count >= 0",
            name=op.f("ck_advisory_catalog_inventory_package_entry_count"),
        ),
        sa.ForeignKeyConstraint(
            ["catalog_event_id"],
            ["smithguard.advisory_catalog_records.catalog_event_id"],
            name="fk_advisory_inventory_catalog",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_advisory_catalog_inventory_snapshot",
        "advisory_catalog_inventory",
        ["source_id", "segment", "source_snapshot", "upstream_record_id"],
        schema=SCHEMA,
    )

    op.create_table(
        "advisory_catalog_manifests",
        sa.Column("manifest_event_id", sa.String(length=160), nullable=False),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("segment", sa.String(length=40), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("source_snapshot", sa.String(length=160), nullable=False),
        sa.Column("cursor_value", sa.Text(), nullable=True),
        sa.Column("record_count", sa.BigInteger(), nullable=False),
        sa.Column("package_entry_count", sa.BigInteger(), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=71), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.PrimaryKeyConstraint("manifest_event_id", name=op.f("pk_advisory_catalog_manifests")),
        sa.UniqueConstraint(
            "source_id",
            "segment",
            "sequence",
            name=op.f("uq_advisory_catalog_manifests_source_id_segment_sequence"),
        ),
        sa.CheckConstraint(
            f"manifest_event_id ~ '{STABLE_ID_SQL}'",
            name=op.f("ck_advisory_catalog_manifests_manifest_event_id"),
        ),
        sa.CheckConstraint(
            f"source_id ~ '{STABLE_ID_SQL}'",
            name=op.f("ck_advisory_catalog_manifests_source_id"),
        ),
        sa.CheckConstraint(
            f"manifest_sha256 ~ '{SHA256_SQL}'",
            name=op.f("ck_advisory_catalog_manifests_manifest_sha256"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256_SQL}'",
            name=op.f("ck_advisory_catalog_manifests_record_hash"),
        ),
        sa.CheckConstraint(
            "segment IN ('malware', 'reviewed', 'unreviewed', "
            "'openssf-malicious', 'openssf-withdrawn')",
            name=op.f("ck_advisory_catalog_manifests_segment"),
        ),
        sa.CheckConstraint(
            "state IN ('in_progress', 'complete', 'failed')",
            name=op.f("ck_advisory_catalog_manifests_state"),
        ),
        sa.CheckConstraint("sequence >= 1", name=op.f("ck_advisory_catalog_manifests_sequence")),
        sa.CheckConstraint(
            "record_count >= 0", name=op.f("ck_advisory_catalog_manifests_record_count")
        ),
        sa.CheckConstraint(
            "package_entry_count >= 0",
            name=op.f("ck_advisory_catalog_manifests_package_entry_count"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_advisory_catalog_manifest_source_segment",
        "advisory_catalog_manifests",
        ["source_id", "segment", "sequence"],
        schema=SCHEMA,
    )


def downgrade() -> None:
    """Refuse to discard full-catalog history or segmented progress."""
    raise RuntimeError(
        "0020_full_advisory_catalog is forward-only; a verified pre-migration backup "
        "may be restored only before the first catalog or progress write"
    )
