"""create NEXT-004-SHADOW transport governance and rehearsal state

Revision ID: 0015_next004_shadow
Revises: 0014_next001
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015_next004_shadow"
down_revision: str | None = "0014_next001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Create append-only gateway governance and correlation rehearsal state"
rollback_mode: str = "forward_only"

SCHEMA = "goodboy_watch"
STABLE_ID = r"^gbsec:[a-z0-9][a-z0-9:._/-]+$"
SHA256 = r"^sha256:[a-f0-9]{64}$"


def _protect(table_name: str) -> None:
    op.execute(
        f"""
        CREATE TRIGGER reject_ledger_mutation
        BEFORE UPDATE OR DELETE ON {SCHEMA}.{table_name}
        FOR EACH ROW
        EXECUTE FUNCTION {SCHEMA}.reject_ledger_mutation()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER reject_ledger_truncate
        BEFORE TRUNCATE ON {SCHEMA}.{table_name}
        FOR EACH STATEMENT
        EXECUTE FUNCTION {SCHEMA}.reject_ledger_mutation()
        """
    )


def upgrade() -> None:
    """Add private transport authorization and sampled shadow evidence."""
    op.create_table(
        "gateway_source_governance_decisions",
        sa.Column("decision_id", sa.String(length=160), nullable=False),
        sa.Column("policy_id", sa.String(length=160), nullable=False),
        sa.Column("policy_version", sa.String(length=100), nullable=False),
        sa.Column("policy_sha256", sa.String(length=71), nullable=False),
        sa.Column("rights_register_id", sa.String(length=160), nullable=False),
        sa.Column("transport_source_id", sa.String(length=160), nullable=False),
        sa.Column("transport_connector_id", sa.String(length=160), nullable=False),
        sa.Column("transport_rights_revision", sa.Integer(), nullable=False),
        sa.Column("transport_canonical_url", sa.Text(), nullable=False),
        sa.Column(
            "transport_rights_evidence_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("origin_source_id", sa.String(length=160), nullable=False),
        sa.Column("origin_rights_revision", sa.Integer(), nullable=False),
        sa.Column("origin_canonical_url", sa.Text(), nullable=False),
        sa.Column(
            "origin_rights_evidence_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("origin_attribution_text", sa.String(length=500), nullable=False),
        sa.Column("origin_license_expression", sa.String(length=200), nullable=False),
        sa.Column("source_record_id", sa.String(length=512), nullable=False),
        sa.Column("field_policy_id", sa.String(length=160), nullable=False),
        sa.Column(
            "accepted_field_paths",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("accepted_sha256", sa.String(length=71), nullable=False),
        sa.Column("storage_scope", sa.String(length=40), nullable=False),
        sa.Column("public_output_authorized", sa.Boolean(), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"decision_id ~ '{STABLE_ID}'",
            name=op.f("ck_gateway_source_governance_decisions_decision_id"),
        ),
        sa.CheckConstraint(
            f"policy_id ~ '{STABLE_ID}'",
            name=op.f("ck_gateway_source_governance_decisions_policy_id"),
        ),
        sa.CheckConstraint(
            f"policy_sha256 ~ '{SHA256}'",
            name=op.f("ck_gateway_source_governance_decisions_policy_sha256"),
        ),
        sa.CheckConstraint(
            f"rights_register_id ~ '{STABLE_ID}'",
            name=op.f("ck_gateway_source_governance_decisions_rights_register_id"),
        ),
        sa.CheckConstraint(
            f"transport_source_id ~ '{STABLE_ID}'",
            name=op.f("ck_gateway_source_governance_decisions_transport_source_id"),
        ),
        sa.CheckConstraint(
            f"transport_connector_id ~ '{STABLE_ID}'",
            name=op.f("ck_gateway_source_governance_decisions_transport_connector_id"),
        ),
        sa.CheckConstraint(
            f"origin_source_id ~ '{STABLE_ID}'",
            name=op.f("ck_gateway_source_governance_decisions_origin_source_id"),
        ),
        sa.CheckConstraint(
            f"field_policy_id ~ '{STABLE_ID}'",
            name=op.f("ck_gateway_source_governance_decisions_field_policy_id"),
        ),
        sa.CheckConstraint(
            f"accepted_sha256 ~ '{SHA256}'",
            name=op.f("ck_gateway_source_governance_decisions_accepted_sha256"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_gateway_source_governance_decisions_record_hash"),
        ),
        sa.CheckConstraint(
            "transport_rights_revision >= 1",
            name=op.f("ck_gateway_source_governance_decisions_transport_revision"),
        ),
        sa.CheckConstraint(
            "origin_rights_revision >= 1",
            name=op.f("ck_gateway_source_governance_decisions_origin_rights_revision"),
        ),
        sa.CheckConstraint(
            "transport_source_id <> origin_source_id",
            name=op.f("ck_gateway_source_governance_decisions_distinct_sources"),
        ),
        sa.CheckConstraint(
            "storage_scope = 'isolated_shadow'",
            name=op.f("ck_gateway_source_governance_decisions_storage_scope"),
        ),
        sa.CheckConstraint(
            "public_output_authorized = false",
            name=op.f("ck_gateway_source_governance_decisions_no_public_output"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(transport_rights_evidence_ids) = 'array' "
            "AND jsonb_array_length(transport_rights_evidence_ids) BETWEEN 1 AND 20",
            name=op.f("ck_gateway_source_governance_decisions_transport_evidence"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(origin_rights_evidence_ids) = 'array' "
            "AND jsonb_array_length(origin_rights_evidence_ids) BETWEEN 1 AND 20",
            name=op.f("ck_gateway_source_governance_decisions_origin_evidence"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(accepted_field_paths) = 'array' "
            "AND jsonb_array_length(accepted_field_paths) BETWEEN 1 AND 40",
            name=op.f("ck_gateway_source_governance_decisions_accepted_fields"),
        ),
        sa.CheckConstraint(
            "decided_at >= authorized_at",
            name=op.f("ck_gateway_source_governance_decisions_decision_order"),
        ),
        sa.ForeignKeyConstraint(
            ["transport_source_id", "transport_rights_revision"],
            [f"{SCHEMA}.sources.id", f"{SCHEMA}.sources.revision"],
            name="fk_gateway_governance_transport_source",
        ),
        sa.ForeignKeyConstraint(
            ["origin_source_id", "origin_rights_revision"],
            [f"{SCHEMA}.sources.id", f"{SCHEMA}.sources.revision"],
            name="fk_gateway_governance_origin_source",
        ),
        sa.PrimaryKeyConstraint(
            "decision_id",
            name=op.f("pk_gateway_source_governance_decisions"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_gateway_governance_transport_origin_record",
        "gateway_source_governance_decisions",
        ["transport_source_id", "origin_source_id", "source_record_id"],
        schema=SCHEMA,
    )
    _protect("gateway_source_governance_decisions")

    op.add_column(
        "correlation_source_observations",
        sa.Column("gateway_governance_decision_id", sa.String(length=160), nullable=True),
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_correlation_source_observations_gateway_decision_id"),
        "correlation_source_observations",
        f"gateway_governance_decision_id IS NULL OR gateway_governance_decision_id ~ '{STABLE_ID}'",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_correlation_source_observations_gateway_decision_shape"),
        "correlation_source_observations",
        "(source_id = transport_source_id AND gateway_governance_decision_id IS NULL) "
        "OR (source_id <> transport_source_id "
        "AND gateway_governance_decision_id IS NOT NULL)",
        schema=SCHEMA,
    )
    op.create_foreign_key(
        "fk_correlation_observation_gateway_decision",
        "correlation_source_observations",
        "gateway_source_governance_decisions",
        ["gateway_governance_decision_id"],
        ["decision_id"],
        source_schema=SCHEMA,
        referent_schema=SCHEMA,
    )

    op.create_table(
        "correlation_shadow_runs",
        sa.Column("run_id", sa.String(length=160), nullable=False),
        sa.Column("contract_sha256", sa.String(length=71), nullable=False),
        sa.Column("input_sha256", sa.String(length=71), nullable=False),
        sa.Column("mode", sa.String(length=30), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("pair_count", sa.Integer(), nullable=False),
        sa.Column("expected_candidate_count", sa.Integer(), nullable=False),
        sa.Column("expected_non_candidate_count", sa.Integer(), nullable=False),
        sa.Column("proposed_candidate_count", sa.Integer(), nullable=False),
        sa.Column("proposed_non_candidate_count", sa.Integer(), nullable=False),
        sa.Column("unexpected_candidate_count", sa.Integer(), nullable=False),
        sa.Column("missed_candidate_count", sa.Integer(), nullable=False),
        sa.Column("copied_transport_count", sa.Integer(), nullable=False),
        sa.Column("conflict_count", sa.Integer(), nullable=False),
        sa.Column("authoritative", sa.Boolean(), nullable=False),
        sa.Column("public_output_authorized", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"run_id ~ '{STABLE_ID}'", name=op.f("ck_correlation_shadow_runs_run_id")
        ),
        sa.CheckConstraint(
            f"contract_sha256 ~ '{SHA256}'",
            name=op.f("ck_correlation_shadow_runs_contract_sha256"),
        ),
        sa.CheckConstraint(
            f"input_sha256 ~ '{SHA256}'",
            name=op.f("ck_correlation_shadow_runs_input_sha256"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_correlation_shadow_runs_record_hash"),
        ),
        sa.CheckConstraint(
            "mode IN ('synthetic_fixture', 'public_fixture')",
            name=op.f("ck_correlation_shadow_runs_mode"),
        ),
        sa.CheckConstraint(
            "state IN ('passed', 'failed')",
            name=op.f("ck_correlation_shadow_runs_state"),
        ),
        sa.CheckConstraint(
            "pair_count BETWEEN 1 AND 2000",
            name=op.f("ck_correlation_shadow_runs_pair_count"),
        ),
        sa.CheckConstraint(
            "expected_candidate_count >= 0 AND expected_non_candidate_count >= 0",
            name=op.f("ck_correlation_shadow_runs_expected_counts"),
        ),
        sa.CheckConstraint(
            "proposed_candidate_count >= 0 AND proposed_non_candidate_count >= 0",
            name=op.f("ck_correlation_shadow_runs_proposed_counts"),
        ),
        sa.CheckConstraint(
            "unexpected_candidate_count >= 0 AND missed_candidate_count >= 0",
            name=op.f("ck_correlation_shadow_runs_error_counts"),
        ),
        sa.CheckConstraint(
            "copied_transport_count >= 0 AND conflict_count >= 0",
            name=op.f("ck_correlation_shadow_runs_context_counts"),
        ),
        sa.CheckConstraint(
            "pair_count = expected_candidate_count + expected_non_candidate_count",
            name=op.f("ck_correlation_shadow_runs_expected_total"),
        ),
        sa.CheckConstraint(
            "pair_count = proposed_candidate_count + proposed_non_candidate_count",
            name=op.f("ck_correlation_shadow_runs_proposed_total"),
        ),
        sa.CheckConstraint(
            "authoritative = false",
            name=op.f("ck_correlation_shadow_runs_not_authoritative"),
        ),
        sa.CheckConstraint(
            "public_output_authorized = false",
            name=op.f("ck_correlation_shadow_runs_no_public_output"),
        ),
        sa.CheckConstraint(
            "completed_at >= started_at",
            name=op.f("ck_correlation_shadow_runs_run_order"),
        ),
        sa.PrimaryKeyConstraint("run_id", name=op.f("pk_correlation_shadow_runs")),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_shadow_runs_completed",
        "correlation_shadow_runs",
        ["completed_at"],
        schema=SCHEMA,
    )
    _protect("correlation_shadow_runs")

    op.create_table(
        "correlation_shadow_samples",
        sa.Column("sample_id", sa.String(length=160), nullable=False),
        sa.Column("run_id", sa.String(length=160), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("left_observation_id", sa.String(length=160), nullable=False),
        sa.Column("right_observation_id", sa.String(length=160), nullable=False),
        sa.Column("expected_relation", sa.String(length=20), nullable=False),
        sa.Column("proposed_relation", sa.String(length=20), nullable=False),
        sa.Column("reason_codes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("independent_origin_count", sa.Integer(), nullable=False),
        sa.Column("copied_transport", sa.Boolean(), nullable=False),
        sa.Column("conflict_observed", sa.Boolean(), nullable=False),
        sa.Column("review_basis", sa.String(length=30), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"sample_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_shadow_samples_sample_id"),
        ),
        sa.CheckConstraint(
            f"run_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_shadow_samples_run_id"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_correlation_shadow_samples_record_hash"),
        ),
        sa.CheckConstraint(
            "ordinal BETWEEN 1 AND 2000",
            name=op.f("ck_correlation_shadow_samples_ordinal"),
        ),
        sa.CheckConstraint(
            "left_observation_id < right_observation_id",
            name=op.f("ck_correlation_shadow_samples_canonical_observation_order"),
        ),
        sa.CheckConstraint(
            "expected_relation IN ('candidate', 'no_candidate')",
            name=op.f("ck_correlation_shadow_samples_expected_relation"),
        ),
        sa.CheckConstraint(
            "proposed_relation IN ('candidate', 'no_candidate')",
            name=op.f("ck_correlation_shadow_samples_proposed_relation"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(reason_codes) = 'array' AND jsonb_array_length(reason_codes) <= 20",
            name=op.f("ck_correlation_shadow_samples_reason_codes"),
        ),
        sa.CheckConstraint(
            "independent_origin_count BETWEEN 1 AND 2",
            name=op.f("ck_correlation_shadow_samples_independent_origin_count"),
        ),
        sa.CheckConstraint(
            "review_basis IN ('synthetic_fixture', 'exact_source_identity', 'human_review')",
            name=op.f("ck_correlation_shadow_samples_review_basis"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            [f"{SCHEMA}.correlation_shadow_runs.run_id"],
            name="fk_correlation_shadow_sample_run",
        ),
        sa.ForeignKeyConstraint(
            ["left_observation_id"],
            [f"{SCHEMA}.correlation_source_observations.observation_id"],
            name="fk_correlation_shadow_sample_left_observation",
        ),
        sa.ForeignKeyConstraint(
            ["right_observation_id"],
            [f"{SCHEMA}.correlation_source_observations.observation_id"],
            name="fk_correlation_shadow_sample_right_observation",
        ),
        sa.PrimaryKeyConstraint("sample_id", name=op.f("pk_correlation_shadow_samples")),
        sa.UniqueConstraint(
            "run_id",
            "ordinal",
            name="uq_correlation_shadow_sample_ordinal",
        ),
        sa.UniqueConstraint(
            "run_id",
            "left_observation_id",
            "right_observation_id",
            name="uq_correlation_shadow_sample_pair",
        ),
        schema=SCHEMA,
    )
    _protect("correlation_shadow_samples")


def downgrade() -> None:
    """Refuse to discard gateway and rehearsal evidence without a verified restore."""
    raise RuntimeError(
        "0015_next004_shadow is forward-only so rollback requires the verified pre-migration backup"
    )
