"""Bulletin evidence and revocable public projections, separate from assessments."""

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
    String,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class BulletinStream(Base):
    """One locked publisher watermark; sequences become visible with their events."""

    __tablename__ = "bulletin_stream"
    __table_args__ = (
        CheckConstraint("stream_id = 'v1'", name="identity"),
        CheckConstraint("sequence >= 0", name="sequence"),
        CheckConstraint("mode IN ('paused','manual_preview','automatic')", name="mode"),
    )
    stream_id: Mapped[str] = mapped_column(String(8), primary_key=True)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    mode: Mapped[str] = mapped_column(String(20), nullable=False, default="paused")
    grant_hash: Mapped[str | None] = mapped_column(String(71))
    status_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BulletinCurrent(Base):
    """Public identity and current pointer; no private source body or inventory."""

    __tablename__ = "bulletin_current"
    __table_args__ = (
        CheckConstraint("bulletin_id ~ '^[a-f0-9]{64}$'", name="identity"),
        CheckConstraint("revision >= 1 AND sequence >= 1", name="revision"),
        CheckConstraint(
            "evidence_class IN ('official_notice','official_advisory','emerging_report')",
            name="evidence_class",
        ),
        CheckConstraint("mode IN ('manual_preview','automatic','reviewed')", name="mode"),
        Index("ix_bulletin_current_source", "source_key", "bulletin_id"),
        Index("ix_bulletin_current_due", "verification_due_at", "bulletin_id"),
        Index("ix_bulletin_current_expiry", "expires_at", "bulletin_id"),
    )
    bulletin_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    source_key: Mapped[str] = mapped_column(String(40), nullable=False)
    evidence_class: Mapped[str] = mapped_column(String(30), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    tombstoned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    freshness_reason: Mapped[str | None] = mapped_column(String(40))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verification_due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BulletinRevision(Base):
    """Immutable restricted evidence; the API role cannot read this table."""

    __tablename__ = "bulletin_revisions"
    __table_args__ = (
        CheckConstraint("revision >= 1", name="revision"),
        CheckConstraint("content_hash ~ '^sha256:[a-f0-9]{64}$'", name="hash"),
        CheckConstraint("octet_length(document::text) <= 32768", name="size"),
    )
    bulletin_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    predecessor_hash: Mapped[str | None] = mapped_column(String(71))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BulletinPublicVersion(Base):
    """Revocable public bytes; takedown replaces all versions with metadata stubs."""

    __tablename__ = "bulletin_public_versions"
    __table_args__ = (
        CheckConstraint("revision >= 1 AND sequence >= 1", name="revision"),
        CheckConstraint("content_hash ~ '^sha256:[a-f0-9]{64}$'", name="hash"),
        CheckConstraint("octet_length(document::text) <= 32768", name="size"),
        ForeignKeyConstraint(
            ["bulletin_id", "revision"],
            ["smithguard.bulletin_revisions.bulletin_id", "smithguard.bulletin_revisions.revision"],
            deferrable=True,
            initially="DEFERRED",
        ),
        Index("ix_bulletin_public_sequence", "sequence", "bulletin_id"),
    )
    bulletin_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    predecessor_hash: Mapped[str | None] = mapped_column(String(71))
    publication_decision_id: Mapped[str] = mapped_column(String(71), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(80), nullable=False)
    grant_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    tombstoned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BulletinEvent(Base):
    """Immutable content-free change references, safe to retain after takedown."""

    __tablename__ = "bulletin_events"
    __table_args__ = (
        CheckConstraint("sequence >= 1 AND revision >= 1", name="sequence"),
        ForeignKeyConstraint(
            ["bulletin_id", "revision"],
            ["smithguard.bulletin_revisions.bulletin_id", "smithguard.bulletin_revisions.revision"],
            deferrable=True,
            initially="DEFERRED",
        ),
        CheckConstraint(
            "kind IN ('published','corrected','source_updated','disputed','withdrawn','expired',"
            "'freshness_stale','freshness_verified','public_tombstoned',"
            "'public_purge_requested','public_purged','public_purge_failed','associated')",
            name="kind",
        ),
        Index("ix_bulletin_events_retention", "occurred_at", "sequence"),
        Index("ix_bulletin_events_bulletin", "bulletin_id", "sequence"),
    )
    sequence: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    bulletin_id: Mapped[str] = mapped_column(String(64), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(40), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BulletinDecision(Base):
    """Every publication or neutral transition has its own immutable decision."""

    __tablename__ = "bulletin_decisions"
    __table_args__ = (
        CheckConstraint("decision_id ~ '^sha256:[a-f0-9]{64}$'", name="identity"),
        CheckConstraint("octet_length(document::text) <= 16384", name="size"),
    )
    decision_id: Mapped[str] = mapped_column(String(71), primary_key=True)
    bulletin_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    manual_approval_id: Mapped[str | None] = mapped_column(String(64), unique=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OfficialSourceCheckpoint(Base):
    """Mutable indexed operational state, never reconstructed from a lifetime scan."""

    __tablename__ = "official_source_checkpoints"
    __table_args__ = (CheckConstraint("octet_length(document::text) <= 16384", name="size"),)
    source_key: Mapped[str] = mapped_column(String(40), primary_key=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BulletinSourceStatus(Base):
    """Content-free public status; the API never reads private intake checkpoints."""

    __tablename__ = "bulletin_source_status"
    __table_args__ = (
        CheckConstraint(
            "state IN ('fresh','stale','unavailable','paused','incomplete')", name="state"
        ),
        CheckConstraint("pending_count >= 0", name="pending_count"),
    )
    source_key: Mapped[str] = mapped_column(String(40), primary_key=True)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(40))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    complete_through_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    coverage_start_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    upstream_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    initial_history_complete: Mapped[bool | None] = mapped_column(Boolean)
    coverage_gaps: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    oldest_pending_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pending_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OfficialNoticeCurrent(Base):
    __tablename__ = "official_notice_current"
    __table_args__ = (
        CheckConstraint("record_key ~ '^[a-f0-9]{64}$'", name="identity"),
        CheckConstraint("octet_length(document::text) <= 16384", name="size"),
        Index("ix_official_notice_updated", "source_key", "updated_at", "record_key"),
    )
    source_key: Mapped[str] = mapped_column(String(40), primary_key=True)
    record_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    semantic_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    publication_pending: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OfficialNoticeEvidence(Base):
    __tablename__ = "official_notice_evidence"
    __table_args__ = (
        CheckConstraint("evidence_id ~ '^sha256:[a-f0-9]{64}$'", name="identity"),
        CheckConstraint("octet_length(document::text) <= 16384", name="size"),
        Index("ix_official_evidence_record", "source_key", "record_key", "created_at"),
    )
    evidence_id: Mapped[str] = mapped_column(String(71), primary_key=True)
    source_key: Mapped[str] = mapped_column(String(40), nullable=False)
    record_key: Mapped[str] = mapped_column(String(64), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OfficialNoticePending(Base):
    """One bounded work pointer per identity; immutable evidence keeps all changes."""

    __tablename__ = "official_notice_pending"
    __table_args__ = (
        CheckConstraint("kind IN ('new','corrected','withdrawn','recheck')", name="kind"),
        Index("ix_official_pending_work", "source_key", "processed_at", "kind", "first_seen_at"),
    )
    source_key: Mapped[str] = mapped_column(String(40), primary_key=True)
    record_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    record_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    evidence_id: Mapped[str] = mapped_column(String(71), nullable=False)
    kind: Mapped[str] = mapped_column(String(12), nullable=False)
    qualification_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OfficialIntakeRun(Base):
    """Two compact immutable records per consumed epoch, including failed epochs."""

    __tablename__ = "official_intake_runs"
    __table_args__ = (
        CheckConstraint("kind IN ('intent','closure','cutover','rollup')", name="kind"),
        CheckConstraint("octet_length(document::text) <= 32768", name="size"),
        Index("ix_official_intake_runs_created", "created_at", "epoch"),
    )
    epoch: Mapped[str] = mapped_column(String(80), primary_key=True)
    kind: Mapped[str] = mapped_column(String(12), primary_key=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BulletinIdentity(Base):
    """Private publisher identity aliases, including permanently revoked identities."""

    __tablename__ = "bulletin_identity_aliases"
    alias_hash: Mapped[str] = mapped_column(String(71), primary_key=True)
    bulletin_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BulletinReviewQueue(Base):
    """Durable factual-change/conflict work; never an automatic analyst approval."""

    __tablename__ = "bulletin_review_queue"
    __table_args__ = (
        CheckConstraint("state IN ('pending','resolved','dismissed')", name="state"),
        CheckConstraint("octet_length(document::text) <= 16384", name="size"),
        Index("ix_bulletin_review_pending", "state", "created_at", "review_id"),
    )
    review_id: Mapped[str] = mapped_column(String(71), primary_key=True)
    source_key: Mapped[str] = mapped_column(String(40), nullable=False)
    record_key: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(12), nullable=False)
    reason: Mapped[str] = mapped_column(String(40), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BulletinMaintenanceReceipt(Base):
    """Immutable compact renewal batches and operator review dispositions."""

    __tablename__ = "bulletin_maintenance_receipts"
    __table_args__ = (
        CheckConstraint("octet_length(document::text) <= 98304", name="size"),
        Index("ix_bulletin_maintenance_created", "created_at", "receipt_id"),
    )
    receipt_id: Mapped[str] = mapped_column(String(71), primary_key=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
