"""generalize disabled Hosted Watch rows into Watch Targets

Revision ID: 0009_mx003
Revises: 0008_mx002
Create Date: omitted for reproducibility
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0009_mx003"
down_revision: str | None = "0008_mx002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Generalize disabled Hosted Watch rows into Watch Targets"
rollback_mode: str = "forward_only"

SCHEMA = "goodboy_hosted_watch"


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _sha256_id(value: Any) -> str:
    return "sha256:" + sha256(_canonical_json_bytes(value)).hexdigest()


def _stable_id(namespace: str, value: str) -> str:
    digest = sha256(value.encode("utf-8")).hexdigest()
    return f"gbsec:{namespace}:{digest[:40]}"


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _rebuild_current_metadata() -> None:
    bind = op.get_bind()
    tenants = list(
        bind.execute(
            sa.text(
                f"""
                SELECT tenant_id, inventory_revision, contract_revision,
                       expires_unconfirmed_after_days, created_at, updated_at
                FROM {SCHEMA}.tenants
                ORDER BY tenant_id
                """
            )
        ).mappings()
    )
    for tenant in tenants:
        rows = list(
            bind.execute(
                sa.text(
                    f"""
                    SELECT project_alias, target_type, ecosystem, registry_host,
                           artifact_name, version, digest, public_visibility,
                           visibility_verified_at, visibility_source_url, directness,
                           usage, importance, inventory_revision, first_seen_at,
                           last_confirmed_at
                    FROM {SCHEMA}.current_entries
                    WHERE tenant_id = :tenant_id
                    """
                ),
                {"tenant_id": tenant["tenant_id"]},
            ).mappings()
        )
        rows.sort(
            key=lambda row: (
                row["project_alias"],
                row["ecosystem"],
                row["registry_host"],
                row["artifact_name"],
                row["version"] or "",
                row["digest"] or "",
            )
        )
        entries = [
            {
                "project_alias": row["project_alias"],
                "target_type": row["target_type"],
                "artifact": {
                    "ecosystem": row["ecosystem"],
                    "registry_host": row["registry_host"],
                    "name": row["artifact_name"],
                    "version": row["version"],
                    "digest": row["digest"],
                },
                "public_visibility": row["public_visibility"],
                "visibility_verified_at": _timestamp(row["visibility_verified_at"]),
                "visibility_source_url": row["visibility_source_url"],
                "directness": row["directness"],
                "usage": row["usage"],
                "importance": row["importance"],
                "inventory_revision": row["inventory_revision"],
                "first_seen_at": _timestamp(row["first_seen_at"]),
                "last_confirmed_at": _timestamp(row["last_confirmed_at"]),
            }
            for row in rows
        ]
        set_value = {
            "tenant_id": tenant["tenant_id"],
            "inventory_revision": tenant["inventory_revision"],
            "entries": entries,
            "expires_unconfirmed_after_days": tenant["expires_unconfirmed_after_days"],
        }
        document = {
            "id": _stable_id("hosted-watch-set", tenant["tenant_id"]),
            "kind": "hosted_watch_set",
            "schema_version": "1.0.0",
            "revision": tenant["contract_revision"],
            "created_at": _timestamp(tenant["created_at"]),
            "updated_at": _timestamp(tenant["updated_at"]),
            "data_classification": "hosted_watch_minimized",
            "feature_state": "disabled",
            "synthetic_only": True,
            "tenant_id": tenant["tenant_id"],
            "replace_current": True,
            "inventory_revision": tenant["inventory_revision"],
            "entries": entries,
            "expires_unconfirmed_after_days": tenant["expires_unconfirmed_after_days"],
        }
        bind.execute(
            sa.text(
                f"""
                UPDATE {SCHEMA}.tenants
                SET current_set_hash = :set_hash,
                    current_entry_count = :entry_count,
                    current_payload_bytes = :payload_bytes
                WHERE tenant_id = :tenant_id
                """
            ),
            {
                "set_hash": _sha256_id(set_value),
                "entry_count": len(entries),
                "payload_bytes": len(_canonical_json_bytes(document)),
                "tenant_id": tenant["tenant_id"],
            },
        )


def upgrade() -> None:
    """Classify every existing synthetic row without enabling Hosted Watch."""
    op.add_column(
        "current_entries",
        sa.Column("target_type", sa.String(length=40), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        "current_entries",
        sa.Column(
            "usage",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'unknown'"),
        ),
        schema=SCHEMA,
    )
    op.add_column(
        "current_entries",
        sa.Column(
            "importance",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'standard'"),
        ),
        schema=SCHEMA,
    )
    op.execute(
        f"""
        UPDATE {SCHEMA}.current_entries
        SET target_type = CASE
            WHEN ecosystem IN ('npm', 'pypi') THEN 'software_dependency'
            WHEN ecosystem = 'github-actions' THEN 'github_action'
            WHEN ecosystem IN ('oci', 'docker') THEN 'container_image'
        END
        """
    )
    _rebuild_current_metadata()
    op.alter_column(
        "current_entries",
        "target_type",
        existing_type=sa.String(length=40),
        nullable=False,
        schema=SCHEMA,
    )
    op.alter_column(
        "current_entries",
        "usage",
        existing_type=sa.String(length=20),
        server_default=None,
        schema=SCHEMA,
    )
    op.alter_column(
        "current_entries",
        "importance",
        existing_type=sa.String(length=20),
        server_default=None,
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_current_entries_target_type"),
        "current_entries",
        "target_type IN ('software_dependency', 'github_action', 'container_image')",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_current_entries_target_ecosystem"),
        "current_entries",
        "(target_type = 'software_dependency' AND ecosystem IN ('npm', 'pypi')) "
        "OR (target_type = 'github_action' AND ecosystem = 'github-actions') "
        "OR (target_type = 'container_image' AND ecosystem IN ('oci', 'docker'))",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_current_entries_usage"),
        "current_entries",
        "usage IN ('production', 'development', 'build', 'unknown')",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        op.f("ck_current_entries_importance"),
        "current_entries",
        "importance IN ('standard', 'important', 'critical')",
        schema=SCHEMA,
    )


def downgrade() -> None:
    """Refuse to discard Watch Target classification."""
    raise RuntimeError("0009_mx003 is forward-only because Watch Target classification is durable")
