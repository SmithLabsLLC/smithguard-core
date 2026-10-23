"""Append-only canonical ledger and durable job models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from . import bulletin_models as _bulletin_models
from .base import Base

STABLE_ID_SQL = r"^gbsec:[a-z0-9][a-z0-9:._/-]+$"
SHA256_SQL = r"^sha256:[a-f0-9]{64}$"
CLASSIFICATIONS = (
    "public",
    "restricted_source",
    "customer_local",
    "private_watchlists_minimized",
    "internal_control",
)


class EmergingLeadRecord(Base):
    """Immutable revisions; approximate subjects never join exact artifact tables."""

    __tablename__ = "emerging_leads"
    __table_args__ = (
        PrimaryKeyConstraint("lead_id", "revision"),
        CheckConstraint("lead_id ~ '^[a-f0-9]{64}$'", name="lead_id"),
        CheckConstraint("revision >= 1", name="revision"),
        CheckConstraint(
            "state IN ('unverified','needs_enrichment','rejected','withdrawn','expired')",
            name="state",
        ),
        CheckConstraint(
            "expires_at > first_seen_at AND observed_at >= first_seen_at", name="times"
        ),
        CheckConstraint("octet_length(document::text) <= 32768", name="document_size"),
        CheckConstraint("record_hash ~ '^sha256:[a-f0-9]{64}$'", name="hash"),
        Index("ix_emerging_leads_observed", "observed_at", "lead_id"),
        Index("ix_emerging_leads_fingerprint", "fingerprint"),
    )
    lead_id: Mapped[str] = mapped_column(String(64))
    revision: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    reason: Mapped[str] = mapped_column(String(80), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(71), nullable=False)
    public_eligible: Mapped[bool] = mapped_column(Boolean, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class WarningLaneOutputRecord(Base):
    """Private final provider output (never reasoning), kept 30 days for diagnosis.

    Owner decision September 24, 2026. Only the signals role can read or purge it; the
    public API has no access. Rows are deleted after ``expires_at``.
    """

    __tablename__ = "warning_lane_outputs"
    __table_args__ = (
        PrimaryKeyConstraint("output_id"),
        CheckConstraint("output_id ~ '^sha256:[a-f0-9]{64}$'", name="output_id"),
        CheckConstraint("stage IN ('discovery','qualification')", name="stage"),
        CheckConstraint("expires_at > created_at", name="times"),
        CheckConstraint("char_length(output_text) <= 524288", name="output_size"),
        CheckConstraint("output_encoding IN ('text','escaped')", name="output_encoding"),
        CheckConstraint("jsonb_typeof(citation_urls) = 'array'", name="citations"),
        Index("ix_warning_lane_outputs_expires", "expires_at"),
        Index("ix_warning_lane_outputs_run", "run_id"),
    )
    output_id: Mapped[str] = mapped_column(String(71))
    run_id: Mapped[str] = mapped_column(String(512), nullable=False)
    job_id_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    stage: Mapped[str] = mapped_column(String(20), nullable=False)
    response_id_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    output_text: Mapped[str] = mapped_column(Text, nullable=False)
    output_truncated: Mapped[bool] = mapped_column(Boolean, nullable=False)
    output_encoding: Mapped[str] = mapped_column(String(20), nullable=False)
    citation_urls: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ContractRecordMixin:
    """Columns shared by immutable contract revisions."""

    id: Mapped[str] = mapped_column(String(160), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    schema_version: Mapped[str] = mapped_column(String(20), nullable=False)
    kind: Mapped[str] = mapped_column(String(80), nullable=False)
    data_classification: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)


def _contract_constraints(
    expected_kind: str,
    *,
    schema_versions: tuple[str, ...] = ("1.0.0",),
) -> tuple[Any, ...]:
    classifications = ", ".join(f"'{value}'" for value in CLASSIFICATIONS)
    schema_version_constraint = (
        f"schema_version = '{schema_versions[0]}'"
        if len(schema_versions) == 1
        else "schema_version IN (" + ", ".join(f"'{value}'" for value in schema_versions) + ")"
    )
    return (
        PrimaryKeyConstraint("id", "revision"),
        CheckConstraint(f"id ~ '{STABLE_ID_SQL}'", name="stable_id"),
        CheckConstraint("revision >= 1", name="positive_revision"),
        CheckConstraint(schema_version_constraint, name="schema_version"),
        CheckConstraint(f"kind = '{expected_kind}'", name="record_kind"),
        CheckConstraint(
            f"data_classification IN ({classifications})",
            name="data_classification",
        ),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint("updated_at >= created_at", name="timestamp_order"),
    )


class SourceRecord(ContractRecordMixin, Base):
    __tablename__ = "sources"
    __table_args__ = (
        *_contract_constraints("source"),
        CheckConstraint(
            "data_classification IN ('public', 'restricted_source')",
            name="source_classification",
        ),
        Index("ix_sources_class_name", "source_class", "name"),
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    source_class: Mapped[str] = mapped_column(String(40), nullable=False)
    canonical_url: Mapped[str] = mapped_column(Text, nullable=False)
    operator: Mapped[str] = mapped_column(String(200), nullable=False)
    rights: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    kill_switch: Mapped[bool] = mapped_column(Boolean, nullable=False)


class EvidenceRecord(ContractRecordMixin, Base):
    __tablename__ = "evidence_objects"
    __table_args__ = (
        *_contract_constraints("raw_evidence"),
        CheckConstraint(
            "data_classification = 'restricted_source'",
            name="evidence_classification",
        ),
        CheckConstraint(f"sha256 ~ '{SHA256_SQL}'", name="sha256"),
        CheckConstraint("byte_count >= 0 AND byte_count <= 52428800", name="byte_count"),
        Index("ix_evidence_source_record", "source_id", "source_record_id"),
        Index("ix_evidence_sha256", "sha256"),
    )

    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(512), nullable=False)
    canonical_url: Mapped[str] = mapped_column(Text, nullable=False)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    source_modified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    storage_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    byte_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    media_type: Mapped[str] = mapped_column(String(200), nullable=False)
    storage_state: Mapped[str] = mapped_column(String(40), nullable=False)
    rights_decision: Mapped[str] = mapped_column(String(40), nullable=False)
    quarantine_reasons: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )


class AuthorityDecisionRecord(ContractRecordMixin, Base):
    __tablename__ = "authority_decisions"
    __table_args__ = (
        *_contract_constraints("authority_decision"),
        CheckConstraint(
            "data_classification = 'public'",
            name="authority_decision_classification",
        ),
        CheckConstraint(
            "public_status IN ('reported', 'corroborated', 'confirmed', 'disputed', 'withdrawn')",
            name="public_status",
        ),
        CheckConstraint(
            "confirmation_method IN ('reported_source', 'automated_source_policy', "
            "'automated_corroboration', 'human_review', 'withdrawal', 'dispute')",
            name="confirmation_method",
        ),
        CheckConstraint(
            "(exception_required AND exception_reason_code IS NOT NULL) "
            "OR (NOT exception_required AND exception_reason_code IS NULL)",
            name="exception_pair",
        ),
        CheckConstraint(
            "jsonb_typeof(evidence_ids) = 'array' "
            "AND jsonb_array_length(evidence_ids) BETWEEN 1 AND 100",
            name="evidence_ids",
        ),
        CheckConstraint(
            "jsonb_typeof(upstream_ids) = 'array' "
            "AND jsonb_array_length(upstream_ids) BETWEEN 1 AND 20",
            name="upstream_ids",
        ),
        CheckConstraint(
            "jsonb_typeof(source_references) = 'array' "
            "AND jsonb_array_length(source_references) BETWEEN 1 AND 20",
            name="source_references",
        ),
        CheckConstraint("decided_at >= created_at", name="decided_at"),
        Index("ix_authority_decisions_incident_decided", "incident_id", "decided_at"),
        Index("ix_authority_decisions_artifact_status", "artifact_id", "public_status"),
    )

    incident_id: Mapped[str] = mapped_column(String(160), nullable=False)
    claim_id: Mapped[str] = mapped_column(String(160), nullable=False)
    artifact_id: Mapped[str] = mapped_column(String(160), nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    public_status: Mapped[str] = mapped_column(String(40), nullable=False)
    confirmation_method: Mapped[str] = mapped_column(String(40), nullable=False)
    transport_source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    assertion_source_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    confirming_authority_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    authority_policy_id: Mapped[str] = mapped_column(String(160), nullable=False)
    authority_policy_version: Mapped[str] = mapped_column(String(100), nullable=False)
    authority_rule_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_rights_register_id: Mapped[str] = mapped_column(String(160), nullable=False)
    attribution_policy_version: Mapped[str] = mapped_column(String(100), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(120), nullable=False)
    automated: Mapped[bool] = mapped_column(Boolean, nullable=False)
    independent_goodboy_analysis: Mapped[bool] = mapped_column(Boolean, nullable=False)
    upstream_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    source_references: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    exception_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    exception_reason_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SourceGovernanceDecisionRecord(Base):
    """One immutable source, field, rights, retention, and publication decision."""

    __tablename__ = "source_governance_decisions"
    __table_args__ = (
        PrimaryKeyConstraint("decision_id"),
        CheckConstraint(f"decision_id ~ '{STABLE_ID_SQL}'", name="decision_id"),
        CheckConstraint(f"policy_id ~ '{STABLE_ID_SQL}'", name="policy_id"),
        CheckConstraint(f"policy_sha256 ~ '{SHA256_SQL}'", name="policy_sha256"),
        CheckConstraint(f"rights_register_id ~ '{STABLE_ID_SQL}'", name="rights_register_id"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint(f"connector_id ~ '{STABLE_ID_SQL}'", name="connector_id"),
        CheckConstraint(f"field_policy_id ~ '{STABLE_ID_SQL}'", name="field_policy_id"),
        CheckConstraint(f"accepted_sha256 ~ '{SHA256_SQL}'", name="accepted_sha256"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint(
            "operating_mode IN ('historical', 'updates', 'exact_lookup', 'reconciliation')",
            name="operating_mode",
        ),
        CheckConstraint(
            "public_status_ceiling IN ('reported', 'corroborated', 'confirmed')",
            name="public_status_ceiling",
        ),
        CheckConstraint(
            "jsonb_typeof(rights_evidence_ids) = 'array' "
            "AND jsonb_array_length(rights_evidence_ids) BETWEEN 1 AND 20",
            name="rights_evidence_ids",
        ),
        CheckConstraint(
            "jsonb_typeof(authorized_disposition_adapter_ids) = 'array' "
            "AND jsonb_array_length(authorized_disposition_adapter_ids) <= 20",
            name="disposition_adapters",
        ),
        Index(
            "ix_source_governance_source_record_decided",
            "source_id",
            "source_record_id",
            "decided_at",
        ),
        Index(
            "ix_source_governance_connector_policy",
            "connector_id",
            "policy_sha256",
        ),
    )

    decision_id: Mapped[str] = mapped_column(String(160), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(160), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(100), nullable=False)
    policy_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    rights_register_id: Mapped[str] = mapped_column(String(160), nullable=False)
    authorized_disposition_adapter_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
    )
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    connector_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(512), nullable=False)
    operating_mode: Mapped[str] = mapped_column(String(40), nullable=False)
    acquisition_method: Mapped[str] = mapped_column(String(40), nullable=False)
    field_policy_id: Mapped[str] = mapped_column(String(160), nullable=False)
    accepted_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    attribution_text: Mapped[str] = mapped_column(String(500), nullable=False)
    license_expression: Mapped[str | None] = mapped_column(String(200), nullable=True)
    rights_evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    rights_evidence_verified: Mapped[bool] = mapped_column(Boolean, nullable=False)
    retention_behavior: Mapped[str] = mapped_column(String(80), nullable=False)
    public_status_ceiling: Mapped[str] = mapped_column(String(40), nullable=False)
    correction_behavior: Mapped[str] = mapped_column(String(80), nullable=False)
    withdrawal_behavior: Mapped[str] = mapped_column(String(80), nullable=False)
    rights_drift_behavior: Mapped[str] = mapped_column(String(80), nullable=False)
    qualified_publication_decision_id: Mapped[str | None] = mapped_column(
        String(160),
        nullable=True,
    )
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class GatewaySourceGovernanceDecisionRecord(Base):
    """One immutable private decision joining a transport to its home source."""

    __tablename__ = "gateway_source_governance_decisions"
    __table_args__ = (
        PrimaryKeyConstraint("decision_id"),
        CheckConstraint(f"decision_id ~ '{STABLE_ID_SQL}'", name="decision_id"),
        CheckConstraint(f"policy_id ~ '{STABLE_ID_SQL}'", name="policy_id"),
        CheckConstraint(f"policy_sha256 ~ '{SHA256_SQL}'", name="policy_sha256"),
        CheckConstraint(f"rights_register_id ~ '{STABLE_ID_SQL}'", name="rights_register_id"),
        CheckConstraint(f"transport_source_id ~ '{STABLE_ID_SQL}'", name="transport_source_id"),
        CheckConstraint(
            f"transport_connector_id ~ '{STABLE_ID_SQL}'", name="transport_connector_id"
        ),
        CheckConstraint(f"origin_source_id ~ '{STABLE_ID_SQL}'", name="origin_source_id"),
        CheckConstraint(f"field_policy_id ~ '{STABLE_ID_SQL}'", name="field_policy_id"),
        CheckConstraint(f"accepted_sha256 ~ '{SHA256_SQL}'", name="accepted_sha256"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint("transport_rights_revision >= 1", name="transport_revision"),
        CheckConstraint("origin_rights_revision >= 1", name="origin_rights_revision"),
        CheckConstraint("transport_source_id <> origin_source_id", name="distinct_sources"),
        CheckConstraint("storage_scope = 'isolated_shadow'", name="storage_scope"),
        CheckConstraint("public_output_authorized = false", name="no_public_output"),
        CheckConstraint(
            "jsonb_typeof(transport_rights_evidence_ids) = 'array' "
            "AND jsonb_array_length(transport_rights_evidence_ids) BETWEEN 1 AND 20",
            name="transport_evidence",
        ),
        CheckConstraint(
            "jsonb_typeof(origin_rights_evidence_ids) = 'array' "
            "AND jsonb_array_length(origin_rights_evidence_ids) BETWEEN 1 AND 20",
            name="origin_evidence",
        ),
        CheckConstraint(
            "jsonb_typeof(accepted_field_paths) = 'array' "
            "AND jsonb_array_length(accepted_field_paths) BETWEEN 1 AND 40",
            name="accepted_fields",
        ),
        CheckConstraint("decided_at >= authorized_at", name="decision_order"),
        ForeignKeyConstraint(
            ["transport_source_id", "transport_rights_revision"],
            ["smithguard.sources.id", "smithguard.sources.revision"],
            name="fk_gateway_governance_transport_source",
        ),
        ForeignKeyConstraint(
            ["origin_source_id", "origin_rights_revision"],
            ["smithguard.sources.id", "smithguard.sources.revision"],
            name="fk_gateway_governance_origin_source",
        ),
        Index(
            "ix_gateway_governance_transport_origin_record",
            "transport_source_id",
            "origin_source_id",
            "source_record_id",
        ),
    )

    decision_id: Mapped[str] = mapped_column(String(160), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(160), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(100), nullable=False)
    policy_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    rights_register_id: Mapped[str] = mapped_column(String(160), nullable=False)
    transport_source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    transport_connector_id: Mapped[str] = mapped_column(String(160), nullable=False)
    transport_rights_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    transport_canonical_url: Mapped[str] = mapped_column(Text, nullable=False)
    transport_rights_evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    origin_source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    origin_rights_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    origin_canonical_url: Mapped[str] = mapped_column(Text, nullable=False)
    origin_rights_evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    origin_attribution_text: Mapped[str] = mapped_column(String(500), nullable=False)
    origin_license_expression: Mapped[str] = mapped_column(String(200), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(512), nullable=False)
    field_policy_id: Mapped[str] = mapped_column(String(160), nullable=False)
    accepted_field_paths: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    accepted_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    storage_scope: Mapped[str] = mapped_column(String(40), nullable=False)
    public_output_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False)
    authorized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class ArtifactRecord(ContractRecordMixin, Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        *_contract_constraints("artifact"),
        CheckConstraint("data_classification = 'public'", name="artifact_classification"),
        Index("ix_artifacts_coordinate", "coordinate"),
        Index("ix_artifacts_ecosystem_name_version", "ecosystem", "name", "version"),
        Index(
            "ix_artifacts_nuget_lookup",
            text("translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"),
            "id",
            postgresql_where=text("ecosystem = 'nuget'"),
        ),
        Index(
            "ix_artifacts_casefold_lookup",
            text("translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"),
            "id",
            postgresql_where=text("ecosystem IN ('vscode', 'open-vsx', 'composer')"),
        ),
        Index(
            "ix_artifacts_rust_lookup",
            text("translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ-', 'abcdefghijklmnopqrstuvwxyz_')"),
            "id",
            postgresql_where=text("ecosystem = 'rust'"),
        ),
    )

    ecosystem: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    coordinate: Mapped[str] = mapped_column(String(1000), nullable=False)
    version: Mapped[str | None] = mapped_column(String(200), nullable=True)
    digest: Mapped[str | None] = mapped_column(String(71), nullable=True)
    identity_state: Mapped[str] = mapped_column(String(40), nullable=False)


class ClaimRecord(ContractRecordMixin, Base):
    __tablename__ = "claims"
    __table_args__ = (
        *_contract_constraints("claim"),
        CheckConstraint(
            "data_classification IN ('public', 'restricted_source')",
            name="claim_classification",
        ),
        Index("ix_claims_subject_state", "subject_id", "state"),
        Index("ix_claims_type_confidence", "claim_type", "confidence"),
        Index("ix_claims_provenance_source_id", text("(provenance ->> 'source_id')")),
    )

    claim_type: Mapped[str] = mapped_column(String(60), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(160), nullable=False)
    predicate: Mapped[str] = mapped_column(String(120), nullable=False)
    object_value: Mapped[Any] = mapped_column(JSONB, nullable=True)
    confidence: Mapped[str] = mapped_column(String(40), nullable=False)
    state: Mapped[str] = mapped_column(String(40), nullable=False)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    supersedes_claim_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)


class AffectedRangeRecord(ContractRecordMixin, Base):
    __tablename__ = "affected_ranges"
    __table_args__ = (
        *_contract_constraints("affected_range"),
        CheckConstraint("data_classification = 'public'", name="range_classification"),
        Index("ix_affected_ranges_artifact", "artifact_id"),
    )

    artifact_id: Mapped[str] = mapped_column(String(160), nullable=False)
    range_type: Mapped[str] = mapped_column(String(40), nullable=False)
    expression: Mapped[str] = mapped_column(String(1000), nullable=False)
    introduced: Mapped[str | None] = mapped_column(String(200), nullable=True)
    fixed: Mapped[str | None] = mapped_column(String(200), nullable=True)
    last_affected: Mapped[str | None] = mapped_column(String(200), nullable=True)
    evaluation_state: Mapped[str] = mapped_column(String(40), nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)


class RelationshipRecord(ContractRecordMixin, Base):
    __tablename__ = "relationships"
    __table_args__ = (
        *_contract_constraints("relationship"),
        CheckConstraint(
            "data_classification = 'public'",
            name="relationship_classification",
        ),
        Index(
            "ix_relationships_subject_type_object",
            "subject_id",
            "relationship_type",
            "object_id",
        ),
    )

    subject_id: Mapped[str] = mapped_column(String(160), nullable=False)
    object_id: Mapped[str] = mapped_column(String(160), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(80), nullable=False)
    assertion_origin: Mapped[str] = mapped_column(String(60), nullable=False)
    confidence: Mapped[str] = mapped_column(String(40), nullable=False)
    state: Mapped[str] = mapped_column(String(40), nullable=False)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)


class IncidentRecord(ContractRecordMixin, Base):
    __tablename__ = "incidents"
    __table_args__ = (
        *_contract_constraints("incident"),
        CheckConstraint(
            "("
            "status IN ('internal_candidate', 'emerging_unverified') "
            "AND data_classification = 'internal_control'"
            ") OR ("
            "status NOT IN ('internal_candidate', 'emerging_unverified') "
            "AND data_classification = 'public'"
            ")",
            name="status_classification",
        ),
        Index("ix_incidents_status_classification", "status", "data_classification"),
        Index("ix_incidents_last_changed", "last_changed_at"),
        Index("ix_incidents_alias_ids", "alias_ids", postgresql_using="gin"),
        Index("ix_incidents_artifact_ids", "artifact_ids", postgresql_using="gin"),
        Index("ix_incidents_redirect_to", "redirect_to"),
    )

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[str] = mapped_column(String(40), nullable=False)
    claim_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    artifact_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    affected_range_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    relationship_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    event_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    authority_decision_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    authority: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    alias_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    redirect_to: Mapped[str | None] = mapped_column(String(160), nullable=True)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    coverage: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    unknowns: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)


class IncidentEventRecord(ContractRecordMixin, Base):
    __tablename__ = "incident_events"
    __table_args__ = (
        *_contract_constraints("incident_event"),
        CheckConstraint(
            "data_classification IN ('public', 'internal_control')",
            name="event_classification",
        ),
        Index("ix_incident_events_incident_occurred", "incident_id", "occurred_at"),
    )

    incident_id: Mapped[str] = mapped_column(String(160), nullable=False)
    event_type: Mapped[str] = mapped_column(String(60), nullable=False)
    old_status: Mapped[str | None] = mapped_column(String(40), nullable=True)
    new_status: Mapped[str | None] = mapped_column(String(40), nullable=True)
    actor_type: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(160), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(120), nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    confidence: Mapped[str] = mapped_column(String(40), nullable=False)
    superseded_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)


class RecommendedActionRecord(ContractRecordMixin, Base):
    __tablename__ = "recommended_actions"
    __table_args__ = (
        *_contract_constraints("recommended_action"),
        CheckConstraint(
            "data_classification = 'public'",
            name="action_classification",
        ),
        CheckConstraint("risk_level >= 0 AND risk_level <= 4", name="risk_level"),
        CheckConstraint(
            "risk_level < 2 OR approval_required",
            name="high_risk_requires_approval",
        ),
        Index("ix_actions_type_risk", "action_type", "risk_level"),
        Index("ix_actions_evidence_ids", "evidence_ids", postgresql_using="gin"),
    )

    action_type: Mapped[str] = mapped_column(String(40), nullable=False)
    risk_level: Mapped[int] = mapped_column(Integer, nullable=False)
    approval_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    preconditions: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    expected_result: Mapped[str] = mapped_column(String(1000), nullable=False)
    validation: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    rollback: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    automation_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)


class PreliminaryWarningRecord(ContractRecordMixin, Base):
    """One append-only public revision of an actor-qualified preliminary warning."""

    __tablename__ = "preliminary_warnings"
    __table_args__ = (
        *_contract_constraints(
            "preliminary_warning",
            schema_versions=("1.0.0", "1.1.0"),
        ),
        CheckConstraint(
            "data_classification = 'public'",
            name="warning_classification",
        ),
        CheckConstraint(
            "state IN ('active', 'expired', 'withdrawn', 'promoted', 'contradicted')",
            name="state",
        ),
        CheckConstraint("expires_at > observed_at", name="expiry_order"),
        CheckConstraint("last_checked_at >= observed_at", name="check_order"),
        CheckConstraint("recheck_count BETWEEN 0 AND 12", name="recheck_count"),
        Index(
            "ix_preliminary_warnings_state_expiry",
            "state",
            "expires_at",
        ),
        Index(
            "ix_preliminary_warnings_updated_id",
            "updated_at",
            "id",
        ),
    )

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    next_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recheck_count: Mapped[int] = mapped_column(Integer, nullable=False)


class IngestionBatchRecord(Base):
    """One immutable accepted or quarantined ingestion outcome."""

    __tablename__ = "ingestion_batches"
    __table_args__ = (
        PrimaryKeyConstraint("batch_id"),
        UniqueConstraint("source_id", "idempotency_key_hash"),
        CheckConstraint(f"batch_id ~ '{STABLE_ID_SQL}'", name="stable_id"),
        CheckConstraint(f"idempotency_key_hash ~ '{SHA256_SQL}'", name="idempotency_hash"),
        CheckConstraint(f"request_hash ~ '{SHA256_SQL}'", name="request_hash"),
        CheckConstraint(f"input_sha256 ~ '{SHA256_SQL}'", name="input_sha256"),
        CheckConstraint(
            f"idempotency_root_hash ~ '{SHA256_SQL}'",
            name="idempotency_root_hash",
        ),
        CheckConstraint(
            f"representation_hash ~ '{SHA256_SQL}'",
            name="representation_hash",
        ),
        CheckConstraint(
            "processing_version ~ '^[a-z0-9][a-z0-9._-]{1,79}$'",
            name="processing_version",
        ),
        CheckConstraint(
            f"retry_of_batch_id IS NULL OR retry_of_batch_id ~ '{STABLE_ID_SQL}'",
            name="retry_of_batch_id",
        ),
        CheckConstraint(
            "(idempotency_root_hash IS NULL "
            "AND representation_hash IS NULL "
            "AND processing_version IS NULL "
            "AND retry_of_batch_id IS NULL) "
            "OR (idempotency_root_hash IS NOT NULL "
            "AND representation_hash IS NOT NULL "
            "AND processing_version IS NOT NULL)",
            name="lineage_shape",
        ),
        CheckConstraint("outcome IN ('accepted', 'quarantined')", name="outcome"),
        CheckConstraint("record_count >= 0 AND record_count <= 5000", name="record_count"),
        CheckConstraint(
            "(outcome = 'accepted' AND raw_evidence_id IS NOT NULL) "
            "OR (outcome = 'quarantined' AND raw_evidence_id IS NULL)",
            name="evidence_outcome",
        ),
        Index("ix_ingestion_batches_source_completed", "source_id", "completed_at"),
        Index(
            "ix_ingestion_batches_root_completed",
            "source_id",
            "idempotency_root_hash",
            "completed_at",
        ),
    )

    batch_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    idempotency_key_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    idempotency_root_hash: Mapped[str | None] = mapped_column(String(71), nullable=True)
    representation_hash: Mapped[str | None] = mapped_column(String(71), nullable=True)
    processing_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    retry_of_batch_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    raw_evidence_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    governance_decision_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    quarantine_reasons: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    normalized_record_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    coverage: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EvidenceFinalizationRecord(Base):
    """Recoverable bridge between a committed evidence row and its final blob."""

    __tablename__ = "evidence_finalizations"
    __table_args__ = (
        PrimaryKeyConstraint("finalization_id"),
        UniqueConstraint("digest"),
        CheckConstraint(f"finalization_id ~ '{STABLE_ID_SQL}'", name="finalization_id"),
        CheckConstraint(f"evidence_id ~ '{STABLE_ID_SQL}'", name="evidence_id"),
        CheckConstraint(f"digest ~ '{SHA256_SQL}'", name="digest"),
        CheckConstraint(f"staging_key ~ '{SHA256_SQL}'", name="staging_key"),
        CheckConstraint("state IN ('pending', 'finalized', 'failed')", name="state"),
        CheckConstraint("byte_count BETWEEN 0 AND 52428800", name="byte_count"),
        CheckConstraint("attempts BETWEEN 0 AND 100", name="attempts"),
        CheckConstraint(
            "last_error_code IS NULL OR last_error_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name="last_error_code",
        ),
        CheckConstraint("updated_at >= staged_at", name="timestamp_order"),
        CheckConstraint(
            "(state = 'finalized' AND finalized_at IS NOT NULL) OR "
            "(state <> 'finalized' AND finalized_at IS NULL)",
            name="finalized_shape",
        ),
        Index("ix_evidence_finalizations_state_updated", "state", "updated_at"),
    )

    finalization_id: Mapped[str] = mapped_column(String(160), nullable=False)
    evidence_id: Mapped[str] = mapped_column(String(160), nullable=False)
    digest: Mapped[str] = mapped_column(String(71), nullable=False)
    staging_key: Mapped[str] = mapped_column(String(71), nullable=False)
    byte_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    last_error_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    staged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finalized_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class IncidentSeedRecord(Base):
    """Immutable starting state for deterministic incident reconstruction."""

    __tablename__ = "incident_seeds"
    __table_args__ = (
        PrimaryKeyConstraint("incident_id"),
        CheckConstraint(f"incident_id ~ '{STABLE_ID_SQL}'", name="stable_id"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint(
            "initial_status IN ("
            "'internal_candidate', 'emerging_unverified', 'investigating', "
            "'reported', 'corroborated', 'confirmed', 'contained', 'resolved', 'disputed', "
            "'withdrawn', 'expired'"
            ")",
            name="initial_status",
        ),
        CheckConstraint(
            "initial_confidence IN ("
            "'confirmed', 'probable', 'possible', 'unverified', 'disputed', 'unknown'"
            ")",
            name="initial_confidence",
        ),
    )

    incident_id: Mapped[str] = mapped_column(String(160), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    initial_status: Mapped[str] = mapped_column(String(40), nullable=False)
    initial_confidence: Mapped[str] = mapped_column(String(40), nullable=False)
    claim_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    artifact_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    affected_range_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    relationship_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    authority_decision_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    authority: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    coverage: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    unknowns: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class IncidentTransitionRecord(Base):
    """Bounded event details omitted from the public lifecycle envelope."""

    __tablename__ = "incident_transitions"
    __table_args__ = (
        PrimaryKeyConstraint("event_id", "event_revision"),
        UniqueConstraint("incident_id", "sequence"),
        CheckConstraint(f"event_id ~ '{STABLE_ID_SQL}'", name="stable_id"),
        CheckConstraint("event_revision >= 1", name="positive_event_revision"),
        CheckConstraint("sequence >= 1 AND sequence <= 10000", name="sequence"),
        CheckConstraint("expected_incident_revision >= 0", name="expected_revision"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        Index("ix_incident_transitions_incident_sequence", "incident_id", "sequence"),
    )

    event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    event_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    incident_id: Mapped[str] = mapped_column(String(160), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    expected_incident_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PublicationLifecycleEventRecord(Base):
    """One cross-path publication, correction, withdrawal, or disposition event."""

    __tablename__ = "publication_lifecycle_events"
    __table_args__ = (
        PrimaryKeyConstraint("lifecycle_event_id"),
        UniqueConstraint("idempotency_key_hash"),
        CheckConstraint(f"lifecycle_event_id ~ '{STABLE_ID_SQL}'", name="event_id"),
        CheckConstraint(f"idempotency_key_hash ~ '{SHA256_SQL}'", name="idempotency_hash"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint(f"evidence_id ~ '{STABLE_ID_SQL}'", name="evidence_id"),
        CheckConstraint(
            f"governance_decision_id ~ '{STABLE_ID_SQL}'",
            name="governance_decision_id",
        ),
        CheckConstraint(
            f"authority_decision_id IS NULL OR authority_decision_id ~ '{STABLE_ID_SQL}'",
            name="authority_decision_id",
        ),
        CheckConstraint(
            "(incident_id IS NULL AND incident_revision IS NULL) OR "
            "(incident_id IS NOT NULL AND incident_revision >= 1)",
            name="incident_revision_pair",
        ),
        CheckConstraint(
            f"incident_id IS NULL OR incident_id ~ '{STABLE_ID_SQL}'",
            name="incident_id",
        ),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint(
            "event_type IN ("
            "'published', 'corrected', 'disputed', 'withdrawn', 'source_deleted', "
            "'rights_tombstoned', 'rights_purge_requested', 'rights_purged', "
            "'purge_failed'"
            ")",
            name="event_type",
        ),
        CheckConstraint(
            "actor_type IN ('system', 'reviewer', 'publisher', 'maintenance')",
            name="actor_type",
        ),
        CheckConstraint(
            "actor_id ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{2,159}$'",
            name="actor_id",
        ),
        CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name="reason_code",
        ),
        CheckConstraint(
            f"disposition_proof_sha256 IS NULL OR disposition_proof_sha256 ~ '{SHA256_SQL}'",
            name="disposition_proof",
        ),
        CheckConstraint(
            "(old_public_status IS NULL OR old_public_status IN ("
            "'reported', 'corroborated', 'confirmed', 'contained', 'resolved', "
            "'disputed', 'withdrawn')) AND "
            "(new_public_status IS NULL OR new_public_status IN ("
            "'reported', 'corroborated', 'confirmed', 'contained', 'resolved', "
            "'disputed', 'withdrawn'))",
            name="public_statuses",
        ),
        CheckConstraint(
            "(event_type IN ("
            "'published', 'corrected', 'disputed', 'withdrawn', 'source_deleted'"
            ") AND incident_id IS NOT NULL AND incident_revision >= 1 "
            "AND new_public_status IS NOT NULL) OR "
            "(event_type IN ("
            "'rights_tombstoned', 'rights_purge_requested', 'rights_purged', "
            "'purge_failed'"
            ") AND incident_id IS NULL AND incident_revision IS NULL "
            "AND old_public_status IS NULL AND new_public_status IS NULL "
            "AND authority_decision_id IS NULL)",
            name="event_shape",
        ),
        CheckConstraint(
            "(event_type = 'published' AND old_public_status IS NULL) OR "
            "(event_type = 'corrected' AND old_public_status IS NOT NULL) OR "
            "(event_type = 'disputed' AND old_public_status IS NOT NULL "
            "AND new_public_status = 'disputed') OR "
            "(event_type = 'withdrawn' AND old_public_status IS NOT NULL "
            "AND new_public_status = 'withdrawn') OR "
            "(event_type = 'source_deleted' AND old_public_status IS NOT NULL "
            "AND old_public_status = new_public_status) OR "
            "event_type IN ("
            "'rights_tombstoned', 'rights_purge_requested', 'rights_purged', "
            "'purge_failed')",
            name="event_status_semantics",
        ),
        CheckConstraint(
            "(event_type IN ('rights_purged', 'purge_failed') "
            "AND disposition_proof_sha256 IS NOT NULL) OR "
            "(event_type NOT IN ('rights_purged', 'purge_failed') "
            "AND disposition_proof_sha256 IS NULL)",
            name="purge_proof_pair",
        ),
        Index(
            "ix_publication_lifecycle_incident_occurred",
            "incident_id",
            "occurred_at",
        ),
        Index(
            "ix_publication_lifecycle_source_record",
            "source_id",
            "source_record_id",
            "occurred_at",
        ),
        Index(
            "ix_publication_lifecycle_evidence_occurred",
            "evidence_id",
            "occurred_at",
        ),
    )

    lifecycle_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    idempotency_key_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    incident_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    incident_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence_id: Mapped[str] = mapped_column(String(160), nullable=False)
    authority_decision_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    governance_decision_id: Mapped[str] = mapped_column(String(160), nullable=False)
    old_public_status: Mapped[str | None] = mapped_column(String(40), nullable=True)
    new_public_status: Mapped[str | None] = mapped_column(String(40), nullable=True)
    reason_code: Mapped[str] = mapped_column(String(120), nullable=False)
    disposition_proof_sha256: Mapped[str | None] = mapped_column(
        String(71),
        nullable=True,
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class CollectorCheckpointRecord(Base):
    """One append-only source checkpoint and health observation."""

    __tablename__ = "collector_checkpoints"
    __table_args__ = (
        PrimaryKeyConstraint("checkpoint_event_id"),
        UniqueConstraint("source_id", "sequence"),
        CheckConstraint(f"checkpoint_event_id ~ '{STABLE_ID_SQL}'", name="stable_id"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint(
            f"checkpoint_token_hash IS NULL OR checkpoint_token_hash ~ '{SHA256_SQL}'",
            name="checkpoint_hash",
        ),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint("sequence >= 1", name="sequence"),
        CheckConstraint(
            "result IN ('accepted', 'quarantined', 'disabled')",
            name="result",
        ),
        CheckConstraint(
            "record_count >= 0 AND record_count <= 5000",
            name="record_count",
        ),
        CheckConstraint(
            "byte_count >= 0 AND byte_count <= 52428800",
            name="byte_count",
        ),
        CheckConstraint(
            "duration_ms >= 0 AND duration_ms <= 3600000",
            name="duration_ms",
        ),
        CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name="reason_code",
        ),
        Index(
            "ix_collector_checkpoints_source_occurred",
            "source_id",
            "occurred_at",
        ),
    )

    checkpoint_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    checkpoint_token_hash: Mapped[str | None] = mapped_column(String(71), nullable=True)
    result: Mapped[str] = mapped_column(String(20), nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    byte_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    reason_code: Mapped[str] = mapped_column(String(120), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class CollectorProgressRecord(Base):
    """One append-only page-level progress event for a source collection lane."""

    __tablename__ = "collector_progress"
    __table_args__ = (
        PrimaryKeyConstraint("progress_event_id"),
        UniqueConstraint("source_id", "segment", "lane", "sequence"),
        CheckConstraint(f"progress_event_id ~ '{STABLE_ID_SQL}'", name="progress_event_id"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint(
            "segment IN ('legacy-malware', 'malware', 'reviewed', 'unreviewed')",
            name="segment",
        ),
        CheckConstraint("lane IN ('historical', 'updates')", name="lane"),
        CheckConstraint(
            "state IN ('in_progress', 'complete', 'failed')",
            name="state",
        ),
        CheckConstraint("sequence >= 1", name="sequence"),
        CheckConstraint("page_count >= 0", name="page_count"),
        CheckConstraint("source_record_count >= 0", name="source_record_count"),
        CheckConstraint("normalized_record_count >= 0", name="normalized_record_count"),
        CheckConstraint(
            "cursor_value IS NULL OR cursor_value ~ '^[A-Za-z0-9._~+=%/-]+$'",
            name="cursor_value",
        ),
        CheckConstraint(
            "(cursor_value IS NULL AND cursor_parameter IS NULL) OR "
            "(cursor_value IS NOT NULL AND cursor_parameter IN ('before', 'after'))",
            name="cursor_pair",
        ),
        CheckConstraint(
            "window_started_at IS NULL OR window_ended_at IS NOT NULL",
            name="window_pair",
        ),
        CheckConstraint(
            "window_started_at IS NULL OR window_ended_at >= window_started_at",
            name="window_order",
        ),
        CheckConstraint(
            "oldest_published_at IS NULL OR newest_published_at IS NOT NULL",
            name="published_pair",
        ),
        CheckConstraint(
            "oldest_published_at IS NULL OR newest_published_at >= oldest_published_at",
            name="published_order",
        ),
        CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name="reason_code",
        ),
        Index(
            "ix_collector_progress_state_occurred",
            "state",
            "occurred_at",
        ),
        Index(
            "ix_collector_progress_not_before",
            "source_id",
            "segment",
            "lane",
            "not_before",
        ),
    )

    progress_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    segment: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default="legacy-malware",
    )
    lane: Mapped[str] = mapped_column(String(20), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    cursor_value: Mapped[str | None] = mapped_column(String(500), nullable=True)
    cursor_parameter: Mapped[str | None] = mapped_column(String(10), nullable=True)
    page_count: Mapped[int] = mapped_column(Integer, nullable=False)
    source_record_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    normalized_record_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    window_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    window_ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    oldest_published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    newest_published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    not_before: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    reason_code: Mapped[str] = mapped_column(String(120), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class AdvisoryCatalogRecord(Base):
    """One append-only advisory identity and classification revision."""

    __tablename__ = "advisory_catalog_records"
    __table_args__ = (
        PrimaryKeyConstraint("catalog_event_id"),
        UniqueConstraint("source_id", "upstream_record_id", "revision"),
        CheckConstraint(f"catalog_event_id ~ '{STABLE_ID_SQL}'", name="catalog_event_id"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint(f"evidence_id ~ '{STABLE_ID_SQL}'", name="evidence_id"),
        CheckConstraint(
            f"governance_decision_id ~ '{STABLE_ID_SQL}'",
            name="governance_decision_id",
        ),
        CheckConstraint(f"source_sha256 ~ '{SHA256_SQL}'", name="source_sha256"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint(
            "source_type IN ('malware', 'reviewed', 'unreviewed', 'openssf', 'rustsec', 'go')",
            name="source_type",
        ),
        CheckConstraint(
            "claim_type IN ('malicious', 'compromised', 'vulnerable')",
            name="claim_type",
        ),
        CheckConstraint("confidence IN ('confirmed', 'unverified')", name="confidence"),
        CheckConstraint("state IN ('active', 'withdrawn')", name="state"),
        CheckConstraint("revision >= 1", name="revision"),
        CheckConstraint(
            "jsonb_typeof(cwe_ids) = 'array' AND jsonb_array_length(cwe_ids) <= 100",
            name="cwe_ids",
        ),
        CheckConstraint(
            "jsonb_typeof(aliases) = 'array' AND jsonb_array_length(aliases) <= 100",
            name="aliases",
        ),
        CheckConstraint(
            "jsonb_typeof(package_omission_counts) = 'object'",
            name="package_omission_counts",
        ),
        Index("ix_advisory_catalog_state_updated", "state", "source_updated_at"),
    )

    catalog_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    upstream_record_id: Mapped[str] = mapped_column(String(160), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    claim_type: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[str] = mapped_column(String(40), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    cwe_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    aliases: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    package_omission_counts: Mapped[dict[str, int]] = mapped_column(JSONB, nullable=False)
    canonical_url: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_id: Mapped[str] = mapped_column(String(160), nullable=False)
    governance_decision_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    source_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class AdvisoryPackageRecord(Base):
    """One append-only package-scoped entry from an advisory revision."""

    __tablename__ = "advisory_package_records"
    __table_args__ = (
        PrimaryKeyConstraint("package_event_id"),
        UniqueConstraint("source_id", "upstream_record_id", "entry_key", "revision"),
        CheckConstraint(f"package_event_id ~ '{STABLE_ID_SQL}'", name="package_event_id"),
        CheckConstraint(f"catalog_event_id ~ '{STABLE_ID_SQL}'", name="catalog_event_id"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint(f"source_sha256 ~ '{SHA256_SQL}'", name="source_sha256"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint("revision >= 1", name="revision"),
        CheckConstraint(
            "ecosystem IN ("
            "'npm', 'pypi', 'github-actions', 'oci', 'docker', 'go', 'rust', "
            "'composer', 'erlang', 'git', 'maven', 'nuget', 'open-vsx', 'pub', "
            "'rubygems', 'swift', 'vscode'"
            ")",
            name="ecosystem",
        ),
        CheckConstraint("char_length(name) BETWEEN 1 AND 300", name="name"),
        CheckConstraint("state IN ('active', 'withdrawn', 'removed')", name="state"),
        CheckConstraint(
            "claim_type IN ('malicious', 'compromised', 'vulnerable')",
            name="claim_type",
        ),
        CheckConstraint("confidence IN ('confirmed', 'unverified')", name="confidence"),
        CheckConstraint(
            "jsonb_typeof(exact_versions) = 'array' "
            "AND jsonb_array_length(exact_versions) <= 10000",
            name="exact_versions",
        ),
        CheckConstraint(
            "jsonb_typeof(affected_ranges) = 'array' "
            "AND jsonb_array_length(affected_ranges) <= 1000",
            name="affected_ranges",
        ),
        ForeignKeyConstraint(
            ["catalog_event_id"],
            ["smithguard.advisory_catalog_records.catalog_event_id"],
            name="fk_advisory_package_catalog",
        ),
        Index(
            "ix_advisory_package_nuget_lookup",
            text("translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"),
            "catalog_event_id",
            postgresql_where=text("ecosystem = 'nuget'"),
        ),
        Index(
            "ix_advisory_package_casefold_lookup",
            text("translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"),
            "catalog_event_id",
            postgresql_where=text("ecosystem IN ('vscode', 'open-vsx', 'composer')"),
        ),
        Index(
            "ix_advisory_package_rust_lookup",
            text("translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ-', 'abcdefghijklmnopqrstuvwxyz_')"),
            "catalog_event_id",
            postgresql_where=text("ecosystem = 'rust'"),
        ),
        Index(
            "ix_advisory_package_coordinate_state",
            "ecosystem",
            "name",
            "state",
            "source_updated_at",
        ),
        Index("ix_advisory_package_ecosystem_source", "ecosystem", "source_id"),
        Index(
            "ix_advisory_package_active_ecosystem",
            "ecosystem",
            postgresql_where=text("state = 'active'"),
        ),
        Index(
            "ix_advisory_package_source_record_revision",
            "source_id",
            "upstream_record_id",
            "revision",
        ),
    )

    package_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    catalog_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    upstream_record_id: Mapped[str] = mapped_column(String(160), nullable=False)
    entry_key: Mapped[str] = mapped_column(String(160), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(40), nullable=False)
    raw_ecosystem: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    exact_versions: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    affected_ranges: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    claim_type: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[str] = mapped_column(String(40), nullable=False)
    source_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class AdvisoryCatalogManifestRecord(Base):
    """One append-only full-catalog manifest or progress receipt."""

    __tablename__ = "advisory_catalog_manifests"
    __table_args__ = (
        PrimaryKeyConstraint("manifest_event_id"),
        UniqueConstraint("source_id", "segment", "sequence"),
        CheckConstraint(f"manifest_event_id ~ '{STABLE_ID_SQL}'", name="manifest_event_id"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint(f"manifest_sha256 ~ '{SHA256_SQL}'", name="manifest_sha256"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint(
            "segment IN ('malware', 'reviewed', 'unreviewed', 'openssf-malicious', "
            "'openssf-withdrawn')",
            name="segment",
        ),
        CheckConstraint(
            "state IN ('in_progress', 'complete', 'failed')",
            name="state",
        ),
        CheckConstraint("sequence >= 1", name="sequence"),
        CheckConstraint("record_count >= 0", name="record_count"),
        CheckConstraint("package_entry_count >= 0", name="package_entry_count"),
    )

    manifest_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    segment: Mapped[str] = mapped_column(String(40), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    source_snapshot: Mapped[str] = mapped_column(String(160), nullable=False)
    cursor_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    record_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    package_entry_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class AdvisoryCatalogInventoryRecord(Base):
    """One exact GitHub historical-snapshot membership receipt."""

    __tablename__ = "advisory_catalog_inventory"
    __table_args__ = (
        PrimaryKeyConstraint("inventory_event_id"),
        UniqueConstraint(
            "source_id",
            "segment",
            "source_snapshot",
            "upstream_record_id",
        ),
        CheckConstraint(f"inventory_event_id ~ '{STABLE_ID_SQL}'", name="inventory_event_id"),
        CheckConstraint(f"catalog_event_id ~ '{STABLE_ID_SQL}'", name="catalog_event_id"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint(f"source_sha256 ~ '{SHA256_SQL}'", name="source_sha256"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint(
            "segment IN ('malware', 'reviewed', 'unreviewed')",
            name="segment",
        ),
        CheckConstraint("package_entry_count >= 0", name="package_entry_count"),
        ForeignKeyConstraint(
            ["catalog_event_id"],
            ["smithguard.advisory_catalog_records.catalog_event_id"],
            name="fk_advisory_inventory_catalog",
        ),
    )

    inventory_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    catalog_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    segment: Mapped[str] = mapped_column(String(40), nullable=False)
    source_snapshot: Mapped[str] = mapped_column(String(160), nullable=False)
    upstream_record_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    package_entry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class SourceReconciliationRunRecord(Base):
    """One bounded source identity inventory and drift decision."""

    __tablename__ = "source_reconciliation_runs"
    __table_args__ = (
        PrimaryKeyConstraint("reconciliation_event_id"),
        UniqueConstraint("source_id", "sequence"),
        UniqueConstraint(
            "source_id",
            "inventory_run_id",
            "page_index",
            name="uq_source_reconciliation_run_page",
        ),
        CheckConstraint(
            f"reconciliation_event_id ~ '{STABLE_ID_SQL}'",
            name="reconciliation_event_id",
        ),
        CheckConstraint(f"inventory_run_id ~ '{STABLE_ID_SQL}'", name="inventory_run_id"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint(f"connector_id ~ '{STABLE_ID_SQL}'", name="connector_id"),
        CheckConstraint(f"policy_id ~ '{STABLE_ID_SQL}'", name="policy_id"),
        CheckConstraint(f"policy_sha256 ~ '{SHA256_SQL}'", name="policy_sha256"),
        CheckConstraint(f"observation_sha256 ~ '{SHA256_SQL}'", name="observation_sha256"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name="reason_code",
        ),
        CheckConstraint("sequence >= 1", name="sequence"),
        CheckConstraint("page_index BETWEEN 1 AND 10000", name="page_index"),
        CheckConstraint(
            "state IN ('in_progress', 'complete', 'unresolved', 'failed')",
            name="state",
        ),
        CheckConstraint(
            "(has_more AND state = 'in_progress') OR "
            "(NOT has_more AND state IN ('complete', 'unresolved', 'failed'))",
            name="state_continuation",
        ),
        CheckConstraint(
            "(page_index = 1 AND continuation_in_hash IS NULL) OR "
            "(page_index > 1 AND continuation_in_hash IS NOT NULL)",
            name="continuation_input",
        ),
        CheckConstraint(
            "(has_more AND continuation_out_hash IS NOT NULL) OR "
            "(NOT has_more AND continuation_out_hash IS NULL)",
            name="continuation_output",
        ),
        CheckConstraint(
            f"continuation_in_hash IS NULL OR continuation_in_hash ~ '{SHA256_SQL}'",
            name="continuation_in_hash",
        ),
        CheckConstraint(
            f"continuation_out_hash IS NULL OR continuation_out_hash ~ '{SHA256_SQL}'",
            name="continuation_out_hash",
        ),
        CheckConstraint(
            "NOT complete_inventory OR NOT has_more",
            name="complete_inventory_terminal",
        ),
        CheckConstraint(
            "scanned_count >= 0 AND scanned_count <= 5000",
            name="scanned_count",
        ),
        CheckConstraint(
            "observed_count >= 0 AND observed_count <= 100000",
            name="observed_count",
        ),
        CheckConstraint(
            "jsonb_typeof(observed_record_ids) = 'array' "
            "AND jsonb_array_length(observed_record_ids) <= 5000",
            name="observed_record_ids",
        ),
        CheckConstraint(
            "jsonb_typeof(late_record_ids) = 'array' "
            "AND jsonb_array_length(late_record_ids) <= 100",
            name="late_record_ids",
        ),
        CheckConstraint(
            "jsonb_typeof(modified_record_ids) = 'array' "
            "AND jsonb_array_length(modified_record_ids) <= 100",
            name="modified_record_ids",
        ),
        CheckConstraint(
            "jsonb_typeof(deleted_record_ids) = 'array' "
            "AND jsonb_array_length(deleted_record_ids) <= 100",
            name="deleted_record_ids",
        ),
        CheckConstraint(
            "jsonb_typeof(missing_record_ids) = 'array' "
            "AND jsonb_array_length(missing_record_ids) <= 100",
            name="missing_record_ids",
        ),
        CheckConstraint(
            "jsonb_typeof(unresolved_record_ids) = 'array' "
            "AND jsonb_array_length(unresolved_record_ids) <= 100",
            name="unresolved_record_ids",
        ),
        CheckConstraint("next_due_at > reconciled_at", name="next_due"),
        Index(
            "ix_source_reconciliation_source_reconciled",
            "source_id",
            "reconciled_at",
        ),
        Index(
            "ix_source_reconciliation_state_due",
            "state",
            "next_due_at",
        ),
        Index(
            "ix_source_reconciliation_run_page",
            "inventory_run_id",
            "page_index",
        ),
    )

    reconciliation_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    inventory_run_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    connector_id: Mapped[str] = mapped_column(String(160), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    page_index: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    complete_inventory: Mapped[bool] = mapped_column(Boolean, nullable=False)
    scanned_count: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_count: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_record_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    late_record_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    modified_record_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    deleted_record_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    missing_record_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    unresolved_record_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    drift_truncated: Mapped[bool] = mapped_column(Boolean, nullable=False)
    continuation_in_hash: Mapped[str | None] = mapped_column(String(71), nullable=True)
    continuation_out_hash: Mapped[str | None] = mapped_column(String(71), nullable=True)
    has_more: Mapped[bool] = mapped_column(Boolean, nullable=False)
    policy_id: Mapped[str] = mapped_column(String(160), nullable=False)
    policy_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    observation_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(120), nullable=False)
    reconciled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    next_due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class SourceIncidentLinkRecord(Base):
    """One append-only source-to-incident reconciliation decision."""

    __tablename__ = "source_incident_links"
    __table_args__ = (
        PrimaryKeyConstraint("link_event_id"),
        UniqueConstraint(
            "source_id",
            "upstream_record_id",
            "artifact_id",
            "sequence",
            name="uq_source_incident_link_identity_sequence",
        ),
        CheckConstraint(f"link_event_id ~ '{STABLE_ID_SQL}'", name="link_event_id"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint(f"artifact_id ~ '{STABLE_ID_SQL}'", name="artifact_id"),
        CheckConstraint(f"incident_id ~ '{STABLE_ID_SQL}'", name="incident_id"),
        CheckConstraint(f"evidence_id ~ '{STABLE_ID_SQL}'", name="evidence_id"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint("sequence >= 1", name="sequence"),
        CheckConstraint(
            "state IN ('active', 'removed', 'withdrawn')",
            name="state",
        ),
        CheckConstraint(
            "upstream_record_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,159}$'",
            name="upstream_record_id",
        ),
        Index(
            "ix_source_incident_links_source_record",
            "source_id",
            "upstream_record_id",
            "source_updated_at",
        ),
        Index(
            "ix_source_incident_links_incident",
            "incident_id",
            "observed_at",
        ),
    )

    link_event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    upstream_record_id: Mapped[str] = mapped_column(String(160), nullable=False)
    artifact_id: Mapped[str] = mapped_column(String(160), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(160), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    source_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    evidence_id: Mapped[str] = mapped_column(String(160), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class SourceClusterMemberRecord(Base):
    """One immutable source member and its deterministic independence relation."""

    __tablename__ = "source_cluster_members"
    __table_args__ = (
        PrimaryKeyConstraint("member_id"),
        UniqueConstraint(
            "cluster_id",
            "source_id",
            "source_record_id",
            name="uq_source_cluster_member_identity",
        ),
        CheckConstraint(f"member_id ~ '{STABLE_ID_SQL}'", name="stable_id"),
        CheckConstraint(f"cluster_id ~ '{STABLE_ID_SQL}'", name="cluster_id"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint(f"evidence_id ~ '{STABLE_ID_SQL}'", name="evidence_id"),
        CheckConstraint(f"artifact_id ~ '{STABLE_ID_SQL}'", name="artifact_id"),
        CheckConstraint(
            f"independent_origin_id ~ '{STABLE_ID_SQL}'",
            name="independent_origin_id",
        ),
        CheckConstraint(f"claim_fingerprint ~ '{SHA256_SQL}'", name="claim_fingerprint"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint(
            "relation IN ('origin', 'corroborates', 'conflicts', 'corrects', 'withdraws')",
            name="relation",
        ),
        Index(
            "ix_source_cluster_members_cluster_observed",
            "cluster_id",
            "observed_at",
        ),
        Index(
            "ix_source_cluster_members_artifact",
            "artifact_id",
            "claim_fingerprint",
        ),
    )

    member_id: Mapped[str] = mapped_column(String(160), nullable=False)
    cluster_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence_id: Mapped[str] = mapped_column(String(160), nullable=False)
    artifact_id: Mapped[str] = mapped_column(String(160), nullable=False)
    independent_origin_id: Mapped[str] = mapped_column(String(160), nullable=False)
    claim_fingerprint: Mapped[str] = mapped_column(String(71), nullable=False)
    relation: Mapped[str] = mapped_column(String(20), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class ReviewQueueEventRecord(Base):
    """One append-only review queue transition."""

    __tablename__ = "review_queue_events"
    __table_args__ = (
        PrimaryKeyConstraint("event_id"),
        UniqueConstraint("queue_item_id", "sequence"),
        CheckConstraint(f"event_id ~ '{STABLE_ID_SQL}'", name="stable_id"),
        CheckConstraint(f"queue_item_id ~ '{STABLE_ID_SQL}'", name="queue_item_id"),
        CheckConstraint(f"cluster_id ~ '{STABLE_ID_SQL}'", name="cluster_id"),
        CheckConstraint(
            f"incident_id IS NULL OR incident_id ~ '{STABLE_ID_SQL}'",
            name="incident_id",
        ),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint("sequence >= 1 AND sequence <= 1000", name="sequence"),
        CheckConstraint(
            "event_type IN ("
            "'opened', 'assigned', 'decided', 'disputed', 'appealed', "
            "'correction_requested', 'withdrawal_requested', 'expired', 'closed'"
            ")",
            name="event_type",
        ),
        CheckConstraint(
            "state IN ('pending', 'in_review', 'approved', 'rejected', 'disputed', "
            "'correction_pending', 'withdrawal_pending', 'expired', 'closed')",
            name="state",
        ),
        CheckConstraint(
            "actor_type IN ('system', 'reviewer', 'maintainer', 'affected_party')",
            name="actor_type",
        ),
        CheckConstraint(
            "actor_id ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{2,159}$'",
            name="actor_id",
        ),
        CheckConstraint(
            "reason_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name="reason_code",
        ),
        CheckConstraint(
            "decision IS NULL OR decision IN ('approved', 'rejected')",
            name="decision",
        ),
        Index(
            "ix_review_queue_events_item_sequence",
            "queue_item_id",
            "sequence",
        ),
        Index("ix_review_queue_events_state_occurred", "state", "occurred_at"),
    )

    event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    queue_item_id: Mapped[str] = mapped_column(String(160), nullable=False)
    cluster_id: Mapped[str] = mapped_column(String(160), nullable=False)
    incident_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    state: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(160), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(120), nullable=False)
    decision: Mapped[str | None] = mapped_column(String(20), nullable=True)
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class PreliminaryWarningRecheckRecord(Base):
    """One bounded append-only recheck outcome.

    ``reservation_id`` keeps its column name for schema continuity; since the spend
    ledger retirement it holds the recheck attempt identifier.
    """

    __tablename__ = "preliminary_warning_rechecks"
    __table_args__ = (
        PrimaryKeyConstraint("recheck_id"),
        UniqueConstraint("warning_id", "sequence"),
        CheckConstraint(f"recheck_id ~ '{STABLE_ID_SQL}'", name="recheck_id"),
        CheckConstraint(f"warning_id ~ '{STABLE_ID_SQL}'", name="warning_id"),
        CheckConstraint(f"reservation_id ~ '{STABLE_ID_SQL}'", name="reservation_id"),
        CheckConstraint(
            f"provider_response_id_hash IS NULL OR provider_response_id_hash ~ '{SHA256_SQL}'",
            name="provider_response_id_hash",
        ),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint("warning_revision >= 1", name="warning_revision"),
        CheckConstraint("sequence BETWEEN 1 AND 12", name="sequence"),
        CheckConstraint(
            "outcome IN ("
            "'still_unverified', 'no_new_evidence', 'confirmation_candidate', "
            "'contradiction_candidate', 'budget_blocked', "
            "'provider_unavailable', 'expired'"
            ")",
            name="outcome",
        ),
        CheckConstraint(
            "server_side_tool_calls BETWEEN 0 AND 64",
            name="server_side_tool_calls",
        ),
        Index(
            "ix_preliminary_warning_rechecks_warning_checked",
            "warning_id",
            "checked_at",
        ),
    )

    recheck_id: Mapped[str] = mapped_column(String(160), nullable=False)
    warning_id: Mapped[str] = mapped_column(String(160), nullable=False)
    warning_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(40), nullable=False)
    provider_response_id_hash: Mapped[str | None] = mapped_column(
        String(71),
        nullable=True,
    )
    server_side_tool_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    reservation_id: Mapped[str] = mapped_column(String(160), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class PreliminaryWarningApprovalRecord(Base):
    """One immutable reviewer approval for the initial public warning revision."""

    __tablename__ = "preliminary_warning_approvals"
    __table_args__ = (
        PrimaryKeyConstraint("approval_id"),
        UniqueConstraint("warning_id", "warning_revision"),
        CheckConstraint(f"approval_id ~ '{STABLE_ID_SQL}'", name="approval_id"),
        CheckConstraint(f"warning_id ~ '{STABLE_ID_SQL}'", name="warning_id"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint("warning_revision = 1", name="initial_revision_only"),
        CheckConstraint(
            "reviewer_id ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{2,159}$'",
            name="reviewer_id",
        ),
        CheckConstraint(
            "independent_source_clusters BETWEEN 1 AND 20",
            name="independent_source_clusters",
        ),
        Index(
            "ix_preliminary_warning_approvals_reviewed",
            "reviewed_at",
        ),
    )

    approval_id: Mapped[str] = mapped_column(String(160), nullable=False)
    warning_id: Mapped[str] = mapped_column(String(160), nullable=False)
    warning_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    reviewer_id: Mapped[str] = mapped_column(String(160), nullable=False)
    independent_source_clusters: Mapped[int] = mapped_column(Integer, nullable=False)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class SnapshotManifestRecord(Base):
    """One immutable signed canonical public snapshot manifest."""

    __tablename__ = "snapshot_manifests"
    __table_args__ = (
        PrimaryKeyConstraint("snapshot_id"),
        CheckConstraint(f"snapshot_id ~ '{STABLE_ID_SQL}'", name="stable_id"),
        CheckConstraint(f"content_sha256 ~ '{SHA256_SQL}'", name="content_sha256"),
        CheckConstraint(f"public_key_id ~ '{STABLE_ID_SQL}'", name="public_key_id"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint(
            "schema_version IN ('1.0.0', '1.1.0', '1.2.0')",
            name="schema_version",
        ),
        CheckConstraint("expires_at > generated_at", name="expiry_order"),
        CheckConstraint("incident_count >= 0", name="incident_count"),
        CheckConstraint("max_revision >= 0", name="max_revision"),
        Index("ix_snapshot_manifests_generated", "generated_at"),
    )

    snapshot_id: Mapped[str] = mapped_column(String(160), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(20), nullable=False)
    feed_version: Mapped[str] = mapped_column(String(40), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    signature_base64: Mapped[str] = mapped_column(String(128), nullable=False)
    public_key_id: Mapped[str] = mapped_column(String(160), nullable=False)
    incident_count: Mapped[int] = mapped_column(Integer, nullable=False)
    max_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    build_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class JobRecord(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        PrimaryKeyConstraint("job_id"),
        UniqueConstraint("queue", "idempotency_key_hash"),
        CheckConstraint(
            "state IN ("
            "'pending', 'running', 'retry_wait', 'succeeded', 'dead_letter', 'acknowledged'"
            ")",
            name="state",
        ),
        CheckConstraint("attempts >= 0 AND attempts <= max_attempts", name="attempts"),
        CheckConstraint("max_attempts >= 1 AND max_attempts <= 100", name="max_attempts"),
        CheckConstraint(f"idempotency_key_hash ~ '{SHA256_SQL}'", name="idempotency_hash"),
        CheckConstraint(f"payload_hash ~ '{SHA256_SQL}'", name="payload_hash"),
        CheckConstraint(
            "payload_classification IN ('public', 'restricted_source', 'internal_control')",
            name="payload_classification",
        ),
        CheckConstraint(
            "last_error_code IS NULL OR last_error_code ~ '^[a-z0-9][a-z0-9_]{1,119}$'",
            name="error_code",
        ),
        CheckConstraint("updated_at >= created_at", name="timestamp_order"),
        CheckConstraint(
            "completed_at IS NULL OR completed_at >= created_at",
            name="completion_time",
        ),
        CheckConstraint(
            "(state = 'running' AND lease_owner IS NOT NULL "
            "AND lease_token_hash IS NOT NULL AND lease_expires_at IS NOT NULL) "
            "OR (state <> 'running' AND lease_owner IS NULL "
            "AND lease_token_hash IS NULL AND lease_expires_at IS NULL)",
            name="lease_shape",
        ),
        CheckConstraint(
            "(state IN ('succeeded', 'dead_letter', 'acknowledged') "
            "AND completed_at IS NOT NULL) OR (state NOT IN "
            "('succeeded', 'dead_letter', 'acknowledged') AND completed_at IS NULL)",
            name="completion_shape",
        ),
        Index("ix_jobs_lease_scan", "queue", "state", "available_at", "created_at"),
        Index(
            "ix_jobs_expired_lease_scan",
            "queue",
            "state",
            "lease_expires_at",
            "job_id",
        ),
        Index(
            "ix_jobs_receipt_run_completed",
            text("(payload ->> 'run_id')"),
            "completed_at",
        ),
        Index(
            "ix_jobs_receipt_type_completed",
            text("(payload ->> 'receipt_type')"),
            "completed_at",
        ),
    )

    job_id: Mapped[str] = mapped_column(String(36), nullable=False)
    queue: Mapped[str] = mapped_column(String(80), nullable=False)
    job_type: Mapped[str] = mapped_column(String(120), nullable=False)
    idempotency_key_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    payload_classification: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_owner: Mapped[str | None] = mapped_column(String(160), nullable=True)
    lease_token_hash: Mapped[str | None] = mapped_column(String(71), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_error_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MigrationJournalRecord(Base):
    __tablename__ = "migration_journal"
    __table_args__ = (
        PrimaryKeyConstraint("revision"),
        CheckConstraint(f"source_sha256 ~ '{SHA256_SQL}'", name="source_sha256"),
        CheckConstraint("jsonb_typeof(notes) = 'object'", name="notes"),
    )

    revision: Mapped[str] = mapped_column(String(64), nullable=False)
    source_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    description: Mapped[str] = mapped_column(String(300), nullable=False)
    rollback_mode: Mapped[str] = mapped_column(String(80), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    app_version: Mapped[str] = mapped_column(String(40), nullable=False)
    notes: Mapped[dict[str, str]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )


CANONICAL_RECORD_MODELS = (
    SourceRecord,
    EvidenceRecord,
    ArtifactRecord,
    ClaimRecord,
    AffectedRangeRecord,
    RelationshipRecord,
    IncidentRecord,
    IncidentEventRecord,
    RecommendedActionRecord,
    PreliminaryWarningRecord,
)

CP_0B2_IMMUTABLE_MODELS = (
    IngestionBatchRecord,
    IncidentSeedRecord,
    IncidentTransitionRecord,
)

CP_1_IMMUTABLE_MODELS = (
    CollectorCheckpointRecord,
    SourceClusterMemberRecord,
    ReviewQueueEventRecord,
    SnapshotManifestRecord,
)

CP_BETA1_IMMUTABLE_MODELS = (
    CollectorProgressRecord,
    SourceIncidentLinkRecord,
    PreliminaryWarningRecheckRecord,
    PreliminaryWarningApprovalRecord,
)

MX_005_IMMUTABLE_MODELS = (
    SourceGovernanceDecisionRecord,
    PublicationLifecycleEventRecord,
    SourceReconciliationRunRecord,
)


class SupplementalSnapshotRecord(Base):
    """Immutable completed or failed source acquisition and projection receipt."""

    __tablename__ = "supplemental_snapshots"
    __table_args__ = (
        PrimaryKeyConstraint("snapshot_id"),
        UniqueConstraint("source_id", "mode", "sequence"),
        CheckConstraint(f"snapshot_id ~ '{STABLE_ID_SQL}'", name="snapshot_id"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint("mode IN ('shadow','public')", name="mode"),
        CheckConstraint("state IN ('complete','failed')", name="state"),
        CheckConstraint("sequence >= 1 AND record_count >= 0", name="counts"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint("jsonb_typeof(document) = 'object'", name="document"),
    )
    snapshot_id: Mapped[str] = mapped_column(String(160))
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_as_of: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class SupplementalPayloadRecord(Base):
    """One exact immutable document, shared by future snapshot memberships."""

    __tablename__ = "supplemental_payloads"
    __table_args__ = (
        PrimaryKeyConstraint("payload_sha256"),
        CheckConstraint(f"payload_sha256 ~ '{SHA256_SQL}'", name="payload_sha256"),
        CheckConstraint("jsonb_typeof(document) = 'object'", name="document"),
    )
    payload_sha256: Mapped[str] = mapped_column(String(71))
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)


class SupplementalFactRecord(Base):
    """Exact-key facts belonging to one atomic, immutable source snapshot."""

    __tablename__ = "supplemental_facts"
    __table_args__ = (
        PrimaryKeyConstraint("snapshot_id", "subject_id"),
        ForeignKeyConstraint(["snapshot_id"], ["smithguard.supplemental_snapshots.snapshot_id"]),
        ForeignKeyConstraint(
            ["payload_sha256"], ["smithguard.supplemental_payloads.payload_sha256"]
        ),
        CheckConstraint("char_length(subject_id) BETWEEN 1 AND 160", name="subject_id"),
        CheckConstraint("jsonb_typeof(document) = 'object'", name="document"),
        CheckConstraint(
            "(document IS NOT NULL AND payload_sha256 IS NULL) OR "
            "(document IS NULL AND payload_sha256 IS NOT NULL)",
            name="payload_choice",
        ),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
    )
    snapshot_id: Mapped[str] = mapped_column(String(160))
    subject_id: Mapped[str] = mapped_column(String(160))
    document: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True))
    payload_sha256: Mapped[str | None] = mapped_column(String(71))
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class CollectionRecordOutcome(Base):
    """Deduplicated governed record disposition, separate from page observations."""

    __tablename__ = "collection_record_outcomes"
    __table_args__ = (
        PrimaryKeyConstraint("outcome_id"),
        ForeignKeyConstraint(["batch_id"], ["smithguard.ingestion_batches.batch_id"]),
        CheckConstraint(f"outcome_id ~ '{STABLE_ID_SQL}'", name="outcome_id"),
        CheckConstraint(f"source_id ~ '{STABLE_ID_SQL}'", name="source_id"),
        CheckConstraint("segment ~ '^[a-z][a-z0-9_-]{0,39}$'", name="segment"),
        CheckConstraint("record_key ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}$'", name="record_key"),
        CheckConstraint(
            "processing_version ~ '^[a-z0-9][a-z0-9._-]{1,79}$'", name="processing_version"
        ),
        CheckConstraint(f"input_sha256 ~ '{SHA256_SQL}'", name="input_sha256"),
        CheckConstraint(f"policy_sha256 ~ '{SHA256_SQL}'", name="policy_sha256"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        CheckConstraint("disposition IN ('accepted','excluded','quarantined')", name="disposition"),
        CheckConstraint("jsonb_typeof(document) = 'object'", name="document"),
        CheckConstraint("octet_length(document::text) <= 16384", name="document_size"),
        Index(
            "ix_collection_outcomes_case",
            "source_id",
            "segment",
            "record_key",
            postgresql_where=text("disposition <> 'accepted'"),
        ),
        Index(
            "ix_collection_outcomes_quarantine",
            "source_id",
            "record_key",
            postgresql_where=text("disposition = 'quarantined'"),
        ),
    )
    outcome_id: Mapped[str] = mapped_column(String(160))
    source_id: Mapped[str] = mapped_column(String(160), nullable=False)
    segment: Mapped[str] = mapped_column(String(40), nullable=False)
    record_key: Mapped[str] = mapped_column(String(160), nullable=False)
    disposition: Mapped[str] = mapped_column(String(20), nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    processing_version: Mapped[str] = mapped_column(String(160), nullable=False)
    policy_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    batch_id: Mapped[str] = mapped_column(String(160), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class CollectionRecordMembership(Base):
    """Immutable acquisition receipt for a page slot or one exact replay."""

    __tablename__ = "collection_record_memberships"
    __table_args__ = (
        PrimaryKeyConstraint("membership_id"),
        UniqueConstraint("progress_event_id", "ordinal"),
        ForeignKeyConstraint(
            ["progress_event_id"], ["smithguard.collector_progress.progress_event_id"]
        ),
        ForeignKeyConstraint(["outcome_id"], ["smithguard.collection_record_outcomes.outcome_id"]),
        CheckConstraint(f"membership_id ~ '{STABLE_ID_SQL}'", name="membership_id"),
        CheckConstraint("ordinal >= 0 AND ordinal < 100", name="ordinal"),
        CheckConstraint(
            "(acquisition_kind = 'page' AND progress_event_id IS NOT NULL) OR "
            "(acquisition_kind = 'replay' AND progress_event_id IS NULL AND ordinal = 0)",
            name="acquisition_shape",
        ),
        CheckConstraint(f"transport_sha256 ~ '{SHA256_SQL}'", name="transport_sha256"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
        Index("ix_collection_membership_outcome", "outcome_id"),
    )
    membership_id: Mapped[str] = mapped_column(String(160))
    progress_event_id: Mapped[str | None] = mapped_column(String(160))
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome_id: Mapped[str] = mapped_column(String(160), nullable=False)
    acquisition_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    transport_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


class CollectionRecordResolution(Base):
    """Explicit closure preserves both the original gap and replacement receipt."""

    __tablename__ = "collection_record_resolutions"
    __table_args__ = (
        PrimaryKeyConstraint("outcome_id"),
        ForeignKeyConstraint(["outcome_id"], ["smithguard.collection_record_outcomes.outcome_id"]),
        ForeignKeyConstraint(
            ["replacement_id"], ["smithguard.collection_record_outcomes.outcome_id"]
        ),
        ForeignKeyConstraint(
            ["membership_id"], ["smithguard.collection_record_memberships.membership_id"]
        ),
        CheckConstraint("outcome_id <> replacement_id", name="different_outcomes"),
        CheckConstraint(f"record_hash ~ '{SHA256_SQL}'", name="record_hash"),
    )
    outcome_id: Mapped[str] = mapped_column(String(160))
    replacement_id: Mapped[str] = mapped_column(String(160), nullable=False)
    membership_id: Mapped[str] = mapped_column(String(160), nullable=False)
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)


APPEND_ONLY_MODELS: tuple[type, ...] = (
    _bulletin_models.BulletinIdentity,
    _bulletin_models.BulletinMaintenanceReceipt,
    _bulletin_models.BulletinRevision,
    _bulletin_models.BulletinEvent,
    _bulletin_models.BulletinDecision,
    _bulletin_models.OfficialNoticeEvidence,
    _bulletin_models.OfficialIntakeRun,
    CollectionRecordOutcome,
    CollectionRecordMembership,
    CollectionRecordResolution,
    EmergingLeadRecord,
    SupplementalSnapshotRecord,
    SupplementalPayloadRecord,
    SupplementalFactRecord,
    *CANONICAL_RECORD_MODELS,
    *CP_0B2_IMMUTABLE_MODELS,
    *CP_1_IMMUTABLE_MODELS,
    *CP_BETA1_IMMUTABLE_MODELS,
    *MX_005_IMMUTABLE_MODELS,
    MigrationJournalRecord,
    AuthorityDecisionRecord,
    GatewaySourceGovernanceDecisionRecord,
    AdvisoryCatalogRecord,
    AdvisoryPackageRecord,
    AdvisoryCatalogInventoryRecord,
    AdvisoryCatalogManifestRecord,
)
