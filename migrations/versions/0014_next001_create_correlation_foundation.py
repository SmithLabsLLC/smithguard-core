"""create NEXT-001 cross-source correlation foundation

Revision ID: 0014_next001
Revises: 0013_watch_rebrand
Create Date: omitted for reproducibility
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014_next001"
down_revision: str | None = "0013_watch_rebrand"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Create append-only cross-source correlation shadow state"
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
    """Add private shadow state without changing the current publication path."""
    op.create_table(
        "correlation_source_observations",
        sa.Column("observation_id", sa.String(length=160), nullable=False),
        sa.Column("source_id", sa.String(length=160), nullable=False),
        sa.Column("transport_source_id", sa.String(length=160), nullable=False),
        sa.Column("upstream_record_id", sa.String(length=512), nullable=False),
        sa.Column("evidence_id", sa.String(length=160), nullable=False),
        sa.Column("source_incident_link_event_id", sa.String(length=160), nullable=True),
        sa.Column("source_state", sa.String(length=20), nullable=False),
        sa.Column("rights_revision", sa.Integer(), nullable=False),
        sa.Column("source_identity_sha256", sa.String(length=71), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"observation_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_source_observations_observation_id"),
        ),
        sa.CheckConstraint(
            f"source_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_source_observations_source_id"),
        ),
        sa.CheckConstraint(
            f"transport_source_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_source_observations_transport_source_id"),
        ),
        sa.CheckConstraint(
            f"evidence_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_source_observations_evidence_id"),
        ),
        sa.CheckConstraint(
            "source_incident_link_event_id IS NULL OR "
            f"source_incident_link_event_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_source_observations_source_link_event_id"),
        ),
        sa.CheckConstraint(
            "upstream_record_id ~ '^[ -~]+$' AND length(upstream_record_id) BETWEEN 1 AND 512",
            name=op.f("ck_correlation_source_observations_upstream_record_id"),
        ),
        sa.CheckConstraint(
            "source_state IN ('active', 'corrected', 'withdrawn', 'removed')",
            name=op.f("ck_correlation_source_observations_source_state"),
        ),
        sa.CheckConstraint(
            "rights_revision >= 1",
            name=op.f("ck_correlation_source_observations_rights_revision"),
        ),
        sa.CheckConstraint(
            f"source_identity_sha256 ~ '{SHA256}'",
            name=op.f("ck_correlation_source_observations_source_identity_sha256"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_correlation_source_observations_record_hash"),
        ),
        sa.CheckConstraint(
            "source_published_at IS NULL OR source_modified_at IS NULL "
            "OR source_modified_at >= source_published_at",
            name=op.f("ck_correlation_source_observations_source_timestamp_order"),
        ),
        sa.PrimaryKeyConstraint(
            "observation_id",
            name=op.f("pk_correlation_source_observations"),
        ),
        sa.UniqueConstraint(
            "transport_source_id",
            "upstream_record_id",
            "evidence_id",
            name="uq_correlation_observation_identity",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_observations_source_record",
        "correlation_source_observations",
        ["transport_source_id", "upstream_record_id", "observed_at"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_observations_evidence",
        "correlation_source_observations",
        ["evidence_id"],
        schema=SCHEMA,
    )

    op.create_table(
        "correlation_observation_origins",
        sa.Column("origin_event_id", sa.String(length=160), nullable=False),
        sa.Column("observation_id", sa.String(length=160), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("origin_id", sa.String(length=160), nullable=False),
        sa.Column("origin_source_id", sa.String(length=160), nullable=False),
        sa.Column("origin_upstream_id", sa.String(length=512), nullable=False),
        sa.Column("parent_origin_id", sa.String(length=160), nullable=True),
        sa.Column("lineage_relation", sa.String(length=40), nullable=False),
        sa.Column("independence_key_sha256", sa.String(length=71), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"origin_event_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_observation_origins_origin_event_id"),
        ),
        sa.CheckConstraint(
            f"origin_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_observation_origins_origin_id"),
        ),
        sa.CheckConstraint(
            f"origin_source_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_observation_origins_origin_source_id"),
        ),
        sa.CheckConstraint(
            f"parent_origin_id IS NULL OR parent_origin_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_observation_origins_parent_origin_id"),
        ),
        sa.CheckConstraint(
            "origin_upstream_id ~ '^[ -~]+$' AND length(origin_upstream_id) BETWEEN 1 AND 512",
            name=op.f("ck_correlation_observation_origins_origin_upstream_id"),
        ),
        sa.CheckConstraint(
            "sequence BETWEEN 1 AND 20",
            name=op.f("ck_correlation_observation_origins_sequence"),
        ),
        sa.CheckConstraint(
            "lineage_relation IN ('original_assertion', 'transported_assertion', "
            "'syndicated_assertion', 'unknown_origin')",
            name=op.f("ck_correlation_observation_origins_lineage_relation"),
        ),
        sa.CheckConstraint(
            f"independence_key_sha256 ~ '{SHA256}'",
            name=op.f("ck_correlation_observation_origins_independence_key_sha256"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_correlation_observation_origins_record_hash"),
        ),
        sa.ForeignKeyConstraint(
            ["observation_id"],
            [f"{SCHEMA}.correlation_source_observations.observation_id"],
            name=op.f(
                "fk_correlation_observation_origins_observation_id_correlation_source_observations"
            ),
        ),
        sa.PrimaryKeyConstraint(
            "origin_event_id",
            name=op.f("pk_correlation_observation_origins"),
        ),
        sa.UniqueConstraint(
            "observation_id",
            "sequence",
            name="uq_correlation_origin_sequence",
        ),
        sa.UniqueConstraint(
            "observation_id",
            "origin_id",
            "origin_upstream_id",
            "lineage_relation",
            name="uq_correlation_origin_identity",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_origins_independence",
        "correlation_observation_origins",
        ["independence_key_sha256", "observed_at"],
        schema=SCHEMA,
    )

    op.create_table(
        "correlation_claim_observations",
        sa.Column("claim_observation_id", sa.String(length=160), nullable=False),
        sa.Column("observation_id", sa.String(length=160), nullable=False),
        sa.Column("claim_id", sa.String(length=160), nullable=False),
        sa.Column("claim_revision", sa.Integer(), nullable=False),
        sa.Column("subject_id", sa.String(length=160), nullable=False),
        sa.Column("predicate", sa.String(length=120), nullable=False),
        sa.Column("object_sha256", sa.String(length=71), nullable=False),
        sa.Column("scope_sha256", sa.String(length=71), nullable=False),
        sa.Column("source_state", sa.String(length=20), nullable=False),
        sa.Column("correction_state", sa.String(length=20), nullable=False),
        sa.Column("evidence_id", sa.String(length=160), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"claim_observation_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_claim_observations_claim_observation_id"),
        ),
        sa.CheckConstraint(
            f"claim_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_claim_observations_claim_id"),
        ),
        sa.CheckConstraint(
            f"subject_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_claim_observations_subject_id"),
        ),
        sa.CheckConstraint(
            f"evidence_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_claim_observations_evidence_id"),
        ),
        sa.CheckConstraint(
            "claim_revision >= 1",
            name=op.f("ck_correlation_claim_observations_claim_revision"),
        ),
        sa.CheckConstraint(
            "predicate ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name=op.f("ck_correlation_claim_observations_predicate"),
        ),
        sa.CheckConstraint(
            f"object_sha256 ~ '{SHA256}'",
            name=op.f("ck_correlation_claim_observations_object_sha256"),
        ),
        sa.CheckConstraint(
            f"scope_sha256 ~ '{SHA256}'",
            name=op.f("ck_correlation_claim_observations_scope_sha256"),
        ),
        sa.CheckConstraint(
            "source_state IN ('active', 'corrected', 'withdrawn', 'disputed')",
            name=op.f("ck_correlation_claim_observations_source_state"),
        ),
        sa.CheckConstraint(
            "correction_state IN ('current', 'superseded', 'retracted', 'unknown')",
            name=op.f("ck_correlation_claim_observations_correction_state"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_correlation_claim_observations_record_hash"),
        ),
        sa.ForeignKeyConstraint(
            ["observation_id"],
            [f"{SCHEMA}.correlation_source_observations.observation_id"],
            name=op.f(
                "fk_correlation_claim_observations_observation_id_correlation_source_observations"
            ),
        ),
        sa.PrimaryKeyConstraint(
            "claim_observation_id",
            name=op.f("pk_correlation_claim_observations"),
        ),
        sa.UniqueConstraint(
            "observation_id",
            "claim_id",
            "claim_revision",
            name="uq_correlation_claim_observation",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_claims_subject_predicate",
        "correlation_claim_observations",
        ["subject_id", "predicate"],
        schema=SCHEMA,
    )

    for table_name, identity_name in (
        ("correlation_advisory_identities", "advisory"),
        ("correlation_vulnerability_identities", "vulnerability"),
    ):
        op.create_table(
            table_name,
            sa.Column("identity_event_id", sa.String(length=160), nullable=False),
            sa.Column("observation_id", sa.String(length=160), nullable=False),
            sa.Column(f"{identity_name}_id", sa.String(length=160), nullable=False),
            sa.Column("namespace", sa.String(length=40), nullable=False),
            sa.Column("external_id", sa.String(length=300), nullable=False),
            sa.Column("relationship", sa.String(length=20), nullable=False),
            sa.Column("record_hash", sa.String(length=71), nullable=False),
            sa.CheckConstraint(
                f"identity_event_id ~ '{STABLE_ID}'",
                name=op.f(f"ck_{table_name}_identity_event_id"),
            ),
            sa.CheckConstraint(
                f"{identity_name}_id ~ '{STABLE_ID}'",
                name=op.f(f"ck_{table_name}_{identity_name}_id"),
            ),
            sa.CheckConstraint(
                "namespace ~ '^[a-z0-9][a-z0-9._-]{0,39}$'",
                name=op.f(f"ck_{table_name}_namespace"),
            ),
            sa.CheckConstraint(
                "external_id ~ '^[ -~]+$' AND length(external_id) BETWEEN 1 AND 300",
                name=op.f(f"ck_{table_name}_external_id"),
            ),
            sa.CheckConstraint(
                "relationship IN ('primary', 'alias', 'upstream', 'related')",
                name=op.f(f"ck_{table_name}_relationship"),
            ),
            sa.CheckConstraint(
                f"record_hash ~ '{SHA256}'",
                name=op.f(f"ck_{table_name}_record_hash"),
            ),
            sa.ForeignKeyConstraint(
                ["observation_id"],
                [f"{SCHEMA}.correlation_source_observations.observation_id"],
                name=op.f(f"fk_{table_name}_observation_id_correlation_source_observations"),
            ),
            sa.PrimaryKeyConstraint(
                "identity_event_id",
                name=op.f(f"pk_{table_name}"),
            ),
            sa.UniqueConstraint(
                "observation_id",
                "namespace",
                "external_id",
                "relationship",
                name=f"uq_correlation_{identity_name}_identity",
            ),
            schema=SCHEMA,
        )
        op.create_index(
            f"ix_correlation_{identity_name}_exact_identity",
            table_name,
            ["namespace", "external_id", "relationship"],
            schema=SCHEMA,
        )

    op.create_table(
        "correlation_security_events",
        sa.Column("event_record_id", sa.String(length=160), nullable=False),
        sa.Column("event_id", sa.String(length=160), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("supersedes_event_record_id", sa.String(length=160), nullable=True),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"event_record_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_security_events_event_record_id"),
        ),
        sa.CheckConstraint(
            f"event_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_security_events_event_id"),
        ),
        sa.CheckConstraint(
            f"supersedes_event_record_id IS NULL OR supersedes_event_record_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_security_events_supersedes_event_record_id"),
        ),
        sa.CheckConstraint(
            "sequence BETWEEN 1 AND 1000",
            name=op.f("ck_correlation_security_events_sequence"),
        ),
        sa.CheckConstraint(
            "event_type IN ('malicious_release', 'vulnerability_exploitation', "
            "'maintainer_compromise', 'publisher_compromise', 'credential_theft', "
            "'campaign', 'provenance_change', 'legacy_incident', 'other_reviewed')",
            name=op.f("ck_correlation_security_events_event_type"),
        ),
        sa.CheckConstraint(
            "state IN ('candidate', 'active', 'corrected', 'withdrawn', 'merged', 'split')",
            name=op.f("ck_correlation_security_events_state"),
        ),
        sa.CheckConstraint(
            "last_observed_at >= first_observed_at",
            name=op.f("ck_correlation_security_events_observed_order"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_correlation_security_events_record_hash"),
        ),
        sa.PrimaryKeyConstraint(
            "event_record_id",
            name=op.f("pk_correlation_security_events"),
        ),
        sa.UniqueConstraint(
            "event_id",
            "sequence",
            name="uq_correlation_event_sequence",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_events_type_state",
        "correlation_security_events",
        ["event_type", "state"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_events_observed",
        "correlation_security_events",
        ["first_observed_at", "last_observed_at"],
        schema=SCHEMA,
    )

    op.create_table(
        "correlation_event_members",
        sa.Column("event_member_id", sa.String(length=160), nullable=False),
        sa.Column("event_record_id", sa.String(length=160), nullable=False),
        sa.Column("member_type", sa.String(length=20), nullable=False),
        sa.Column("member_id", sa.String(length=160), nullable=False),
        sa.Column("relationship", sa.String(length=20), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"event_member_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_event_members_event_member_id"),
        ),
        sa.CheckConstraint(
            f"member_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_event_members_member_id"),
        ),
        sa.CheckConstraint(
            "member_type IN ('artifact', 'vulnerability', 'advisory', 'origin', 'claim')",
            name=op.f("ck_correlation_event_members_member_type"),
        ),
        sa.CheckConstraint(
            "relationship IN ('involves', 'affects', 'exploits', 'targets', "
            "'asserted_by', 'described_by')",
            name=op.f("ck_correlation_event_members_relationship"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_correlation_event_members_record_hash"),
        ),
        sa.ForeignKeyConstraint(
            ["event_record_id"],
            [f"{SCHEMA}.correlation_security_events.event_record_id"],
            name=op.f("fk_correlation_event_members_event_record_id_correlation_security_events"),
        ),
        sa.PrimaryKeyConstraint(
            "event_member_id",
            name=op.f("pk_correlation_event_members"),
        ),
        sa.UniqueConstraint(
            "event_record_id",
            "member_type",
            "member_id",
            "relationship",
            name="uq_correlation_event_member",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_event_members_member",
        "correlation_event_members",
        ["member_type", "member_id"],
        schema=SCHEMA,
    )

    op.create_table(
        "correlation_candidates",
        sa.Column("candidate_id", sa.String(length=160), nullable=False),
        sa.Column("left_observation_id", sa.String(length=160), nullable=False),
        sa.Column("right_observation_id", sa.String(length=160), nullable=False),
        sa.Column("candidate_kind", sa.String(length=30), nullable=False),
        sa.Column(
            "reason_codes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("explanation_score", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.String(length=160), nullable=False),
        sa.Column("policy_version", sa.String(length=100), nullable=False),
        sa.Column("policy_sha256", sa.String(length=71), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"candidate_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_candidates_candidate_id"),
        ),
        sa.CheckConstraint(
            "left_observation_id < right_observation_id",
            name=op.f("ck_correlation_candidates_canonical_observation_order"),
        ),
        sa.CheckConstraint(
            "candidate_kind IN ('same_event', 'same_vulnerability', 'same_advisory')",
            name=op.f("ck_correlation_candidates_candidate_kind"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(reason_codes) = 'array' "
            "AND jsonb_array_length(reason_codes) BETWEEN 1 AND 20",
            name=op.f("ck_correlation_candidates_reason_codes"),
        ),
        sa.CheckConstraint(
            "explanation_score BETWEEN 0 AND 1000",
            name=op.f("ck_correlation_candidates_explanation_score"),
        ),
        sa.CheckConstraint(
            f"policy_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_candidates_policy_id"),
        ),
        sa.CheckConstraint(
            f"policy_sha256 ~ '{SHA256}'",
            name=op.f("ck_correlation_candidates_policy_sha256"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_correlation_candidates_record_hash"),
        ),
        sa.ForeignKeyConstraint(
            ["left_observation_id"],
            [f"{SCHEMA}.correlation_source_observations.observation_id"],
            name=op.f(
                "fk_correlation_candidates_left_observation_id_correlation_source_observations"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["right_observation_id"],
            [f"{SCHEMA}.correlation_source_observations.observation_id"],
            name=op.f(
                "fk_correlation_candidates_right_observation_id_correlation_source_observations"
            ),
        ),
        sa.PrimaryKeyConstraint(
            "candidate_id",
            name=op.f("pk_correlation_candidates"),
        ),
        sa.UniqueConstraint(
            "left_observation_id",
            "right_observation_id",
            "candidate_kind",
            "policy_sha256",
            name="uq_correlation_candidate_pair_policy",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_candidates_pair",
        "correlation_candidates",
        ["left_observation_id", "right_observation_id"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_candidates_created",
        "correlation_candidates",
        ["created_at"],
        schema=SCHEMA,
    )

    op.create_table(
        "correlation_decisions",
        sa.Column("decision_event_id", sa.String(length=160), nullable=False),
        sa.Column("decision_id", sa.String(length=160), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("candidate_id", sa.String(length=160), nullable=True),
        sa.Column("decision_type", sa.String(length=20), nullable=False),
        sa.Column("subject_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("target_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reason_codes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("evidence_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("actor_type", sa.String(length=20), nullable=False),
        sa.Column("actor_id", sa.String(length=160), nullable=False),
        sa.Column("policy_id", sa.String(length=160), nullable=False),
        sa.Column("policy_version", sa.String(length=100), nullable=False),
        sa.Column("policy_sha256", sa.String(length=71), nullable=False),
        sa.Column("reversal_of_decision_event_id", sa.String(length=160), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"decision_event_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_decisions_decision_event_id"),
        ),
        sa.CheckConstraint(
            f"decision_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_decisions_decision_id"),
        ),
        sa.CheckConstraint(
            "sequence BETWEEN 1 AND 1000",
            name=op.f("ck_correlation_decisions_sequence"),
        ),
        sa.CheckConstraint(
            "decision_type IN ('link', 'no_link', 'merge', 'split', 'correction', "
            "'withdrawal', 'reversal')",
            name=op.f("ck_correlation_decisions_decision_type"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(subject_ids) = 'array' "
            "AND jsonb_array_length(subject_ids) BETWEEN 1 AND 100",
            name=op.f("ck_correlation_decisions_subject_ids"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(target_ids) = 'array' AND jsonb_array_length(target_ids) <= 100",
            name=op.f("ck_correlation_decisions_target_ids"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(reason_codes) = 'array' "
            "AND jsonb_array_length(reason_codes) BETWEEN 1 AND 20",
            name=op.f("ck_correlation_decisions_reason_codes"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(evidence_ids) = 'array' "
            "AND jsonb_array_length(evidence_ids) BETWEEN 1 AND 100",
            name=op.f("ck_correlation_decisions_evidence_ids"),
        ),
        sa.CheckConstraint(
            "actor_type IN ('system_policy', 'reviewer', 'maintainer')",
            name=op.f("ck_correlation_decisions_actor_type"),
        ),
        sa.CheckConstraint(
            "actor_id ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{2,159}$'",
            name=op.f("ck_correlation_decisions_actor_id"),
        ),
        sa.CheckConstraint(
            f"policy_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_decisions_policy_id"),
        ),
        sa.CheckConstraint(
            f"policy_sha256 ~ '{SHA256}'",
            name=op.f("ck_correlation_decisions_policy_sha256"),
        ),
        sa.CheckConstraint(
            "(decision_type = 'reversal' AND reversal_of_decision_event_id IS NOT NULL) "
            "OR (decision_type <> 'reversal' AND reversal_of_decision_event_id IS NULL)",
            name=op.f("ck_correlation_decisions_reversal_shape"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_correlation_decisions_record_hash"),
        ),
        sa.ForeignKeyConstraint(
            ["candidate_id"],
            [f"{SCHEMA}.correlation_candidates.candidate_id"],
            name=op.f("fk_correlation_decisions_candidate_id_correlation_candidates"),
        ),
        sa.ForeignKeyConstraint(
            ["reversal_of_decision_event_id"],
            [f"{SCHEMA}.correlation_decisions.decision_event_id"],
            name=op.f(
                "fk_correlation_decisions_reversal_of_decision_event_id_correlation_decisions"
            ),
        ),
        sa.PrimaryKeyConstraint(
            "decision_event_id",
            name=op.f("pk_correlation_decisions"),
        ),
        sa.UniqueConstraint(
            "decision_id",
            "sequence",
            name="uq_correlation_decision_sequence",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_decisions_candidate",
        "correlation_decisions",
        ["candidate_id", "decided_at"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_decisions_identity",
        "correlation_decisions",
        ["decision_id", "sequence"],
        schema=SCHEMA,
    )
    op.create_index(
        "uq_correlation_decisions_single_reversal",
        "correlation_decisions",
        ["reversal_of_decision_event_id"],
        unique=True,
        schema=SCHEMA,
        postgresql_where=sa.text("reversal_of_decision_event_id IS NOT NULL"),
    )

    op.create_table(
        "correlation_incident_aliases",
        sa.Column("alias_event_id", sa.String(length=160), nullable=False),
        sa.Column("alias_incident_id", sa.String(length=160), nullable=False),
        sa.Column("canonical_incident_id", sa.String(length=160), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("decision_event_id", sa.String(length=160), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"alias_event_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_incident_aliases_alias_event_id"),
        ),
        sa.CheckConstraint(
            f"alias_incident_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_incident_aliases_alias_incident_id"),
        ),
        sa.CheckConstraint(
            f"canonical_incident_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_incident_aliases_canonical_incident_id"),
        ),
        sa.CheckConstraint(
            "alias_incident_id <> canonical_incident_id",
            name=op.f("ck_correlation_incident_aliases_distinct_incidents"),
        ),
        sa.CheckConstraint(
            "sequence BETWEEN 1 AND 1000",
            name=op.f("ck_correlation_incident_aliases_sequence"),
        ),
        sa.CheckConstraint(
            "state IN ('active', 'revoked')",
            name=op.f("ck_correlation_incident_aliases_state"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_correlation_incident_aliases_record_hash"),
        ),
        sa.ForeignKeyConstraint(
            ["decision_event_id"],
            [f"{SCHEMA}.correlation_decisions.decision_event_id"],
            name=op.f("fk_correlation_incident_aliases_decision_event_id_correlation_decisions"),
        ),
        sa.PrimaryKeyConstraint(
            "alias_event_id",
            name=op.f("pk_correlation_incident_aliases"),
        ),
        sa.UniqueConstraint(
            "alias_incident_id",
            "sequence",
            name="uq_correlation_incident_alias_sequence",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_aliases_canonical",
        "correlation_incident_aliases",
        ["canonical_incident_id", "occurred_at"],
        schema=SCHEMA,
    )

    op.create_table(
        "correlation_warning_links",
        sa.Column("warning_link_event_id", sa.String(length=160), nullable=False),
        sa.Column("warning_id", sa.String(length=160), nullable=False),
        sa.Column("warning_revision", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("security_event_id", sa.String(length=160), nullable=True),
        sa.Column("incident_id", sa.String(length=160), nullable=True),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("decision_event_id", sa.String(length=160), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            f"warning_link_event_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_warning_links_warning_link_event_id"),
        ),
        sa.CheckConstraint(
            f"warning_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_warning_links_warning_id"),
        ),
        sa.CheckConstraint(
            f"security_event_id IS NULL OR security_event_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_warning_links_security_event_id"),
        ),
        sa.CheckConstraint(
            f"incident_id IS NULL OR incident_id ~ '{STABLE_ID}'",
            name=op.f("ck_correlation_warning_links_incident_id"),
        ),
        sa.CheckConstraint(
            "warning_revision >= 1",
            name=op.f("ck_correlation_warning_links_warning_revision"),
        ),
        sa.CheckConstraint(
            "sequence BETWEEN 1 AND 1000",
            name=op.f("ck_correlation_warning_links_sequence"),
        ),
        sa.CheckConstraint(
            "state IN ('proposed', 'linked', 'rejected', 'expired', 'contradicted', 'reversed')",
            name=op.f("ck_correlation_warning_links_state"),
        ),
        sa.CheckConstraint(
            "(state = 'linked' AND security_event_id IS NOT NULL "
            "AND incident_id IS NOT NULL AND decision_event_id IS NOT NULL) "
            "OR state <> 'linked'",
            name=op.f("ck_correlation_warning_links_linked_shape"),
        ),
        sa.CheckConstraint(
            f"record_hash ~ '{SHA256}'",
            name=op.f("ck_correlation_warning_links_record_hash"),
        ),
        sa.ForeignKeyConstraint(
            ["decision_event_id"],
            [f"{SCHEMA}.correlation_decisions.decision_event_id"],
            name=op.f("fk_correlation_warning_links_decision_event_id_correlation_decisions"),
        ),
        sa.PrimaryKeyConstraint(
            "warning_link_event_id",
            name=op.f("pk_correlation_warning_links"),
        ),
        sa.UniqueConstraint(
            "warning_id",
            "warning_revision",
            "sequence",
            name="uq_correlation_warning_link_sequence",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_correlation_warning_links_warning",
        "correlation_warning_links",
        ["warning_id", "sequence"],
        schema=SCHEMA,
    )

    for table_name in (
        "correlation_source_observations",
        "correlation_observation_origins",
        "correlation_claim_observations",
        "correlation_advisory_identities",
        "correlation_vulnerability_identities",
        "correlation_security_events",
        "correlation_event_members",
        "correlation_candidates",
        "correlation_decisions",
        "correlation_incident_aliases",
        "correlation_warning_links",
    ):
        _protect(table_name)


def downgrade() -> None:
    """Refuse to discard correlation evidence without a verified restore."""
    raise RuntimeError(
        "0014_next001 is forward-only so rollback requires the verified pre-migration backup"
    )
