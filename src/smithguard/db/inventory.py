"""Expected database inventory and a deterministic schema fingerprint.

These describe the current migration head for the database parity tests and any
operator check that needs the exact user-owned table set. The retired recovery
module used to own them; the recovery code was deleted on September 18, 2026.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection

from smithguard.identifiers import canonical_json_bytes

PRE_0020_MAIN_TABLES: tuple[str, ...] = (
    "affected_ranges",
    "artifacts",
    "authority_decisions",
    "claims",
    "collector_checkpoints",
    "collector_progress",
    "correlation_advisory_identities",
    "correlation_candidates",
    "correlation_claim_observations",
    "correlation_decisions",
    "correlation_event_members",
    "correlation_incident_aliases",
    "correlation_observation_origins",
    "correlation_security_events",
    "correlation_shadow_runs",
    "correlation_shadow_samples",
    "correlation_source_observations",
    "correlation_vulnerability_identities",
    "correlation_warning_links",
    "delivery_attempts",
    "delivery_destinations",
    "delivery_events",
    "evidence_finalizations",
    "evidence_objects",
    "gateway_source_governance_decisions",
    "incident_seeds",
    "incident_transitions",
    "incident_events",
    "incidents",
    "ingestion_batches",
    "jobs",
    "migration_journal",
    "recommended_actions",
    "relationships",
    "preliminary_warning_approvals",
    "preliminary_warning_rechecks",
    "preliminary_warnings",
    "publication_lifecycle_events",
    "review_audit_events",
    "review_queue_events",
    "snapshot_manifests",
    "sources",
    "source_cluster_members",
    "source_governance_decisions",
    "source_incident_links",
    "source_reconciliation_runs",
    "spend_ledger_events",
    "webhook_receipts",
)
PRE_0026_MAIN_TABLES: tuple[str, ...] = (
    *PRE_0020_MAIN_TABLES,
    "advisory_catalog_inventory",
    "advisory_catalog_manifests",
    "advisory_catalog_records",
    "advisory_package_records",
)
# Tables of retired features that 0030 dropped (all empty in production).
DROPPED_IN_0030: frozenset[str] = frozenset(
    {
        "correlation_advisory_identities",
        "correlation_candidates",
        "correlation_claim_observations",
        "correlation_decisions",
        "correlation_event_members",
        "correlation_incident_aliases",
        "correlation_observation_origins",
        "correlation_security_events",
        "correlation_shadow_runs",
        "correlation_shadow_samples",
        "correlation_source_observations",
        "correlation_vulnerability_identities",
        "correlation_warning_links",
        "delivery_attempts",
        "delivery_destinations",
        "delivery_events",
        "review_audit_events",
        "webhook_receipts",
    }
)
# 0026 dropped the spend ledger; every earlier layout still carries the table.
EXPECTED_MAIN_TABLES: tuple[str, ...] = tuple(
    table
    for table in PRE_0026_MAIN_TABLES
    if table != "spend_ledger_events" and table not in DROPPED_IN_0030
) + (
    "emerging_leads",
    "warning_lane_outputs",
    "supplemental_snapshots",
    "supplemental_facts",
    "supplemental_payloads",
    "collection_record_outcomes",
    "collection_record_memberships",
    "collection_record_resolutions",
    "bulletin_identity_aliases",
    "bulletin_review_queue",
    "bulletin_maintenance_receipts",
    "bulletin_stream",
    "bulletin_source_status",
    "bulletin_current",
    "bulletin_revisions",
    "bulletin_public_versions",
    "bulletin_events",
    "bulletin_decisions",
    "official_source_checkpoints",
    "official_notice_current",
    "official_notice_evidence",
    "official_notice_pending",
    "official_intake_runs",
)
EXPECTED_PRIVATE_WATCHLISTS_TABLES: tuple[str, ...] = (
    "admin_audit",
    "current_entries",
    "deletion_receipts",
    "encrypted_contacts",
    "encrypted_destinations",
    "tenants",
)


def _normalize_schema_definition(object_kind: str, definition: str) -> str:
    if object_kind != "constraint":
        return definition
    normalized = definition.replace("::character varying::text", "::text")
    normalized = normalized.replace("::character varying", "::text")
    return normalized.replace("]::text[]", "]")


def schema_description(connection: Connection) -> list[dict[str, Any]]:
    """Return a deterministic description of user-owned database objects."""
    rows = connection.execute(
        text(
            """
            SELECT object_kind, schema_name, object_name, sub_name, definition
            FROM (
                SELECT
                    'column'::text AS object_kind,
                    n.nspname::text AS schema_name,
                    c.relname::text AS object_name,
                    -- Ordinal among live columns: a dropped column leaves an attnum
                    -- gap on the source that pg_restore does not reproduce.
                    lpad(
                        (row_number() OVER (
                            PARTITION BY a.attrelid ORDER BY a.attnum
                        ))::text,
                        4,
                        '0'
                    ) AS sub_name,
                    concat_ws(
                        '|',
                        a.attname,
                        pg_catalog.format_type(a.atttypid, a.atttypmod),
                        a.attnotnull::text,
                        coalesce(pg_catalog.pg_get_expr(d.adbin, d.adrelid), '')
                    )::text AS definition
                FROM pg_catalog.pg_attribute AS a
                JOIN pg_catalog.pg_class AS c ON c.oid = a.attrelid
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                LEFT JOIN pg_catalog.pg_attrdef AS d
                  ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                WHERE c.relkind IN ('r', 'p')
                  AND a.attnum > 0
                  AND NOT a.attisdropped
                  AND n.nspname <> 'information_schema'
                  AND n.nspname !~ '^pg_'

                UNION ALL

                SELECT
                    'constraint',
                    n.nspname,
                    c.relname,
                    con.conname,
                    pg_catalog.pg_get_constraintdef(con.oid, true)
                FROM pg_catalog.pg_constraint AS con
                JOIN pg_catalog.pg_class AS c ON c.oid = con.conrelid
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname !~ '^pg_'

                UNION ALL

                SELECT
                    'index',
                    schemaname,
                    tablename,
                    indexname,
                    indexdef
                FROM pg_catalog.pg_indexes
                WHERE schemaname <> 'information_schema'
                  AND schemaname !~ '^pg_'

                UNION ALL

                SELECT
                    'routine',
                    n.nspname,
                    p.proname,
                    pg_catalog.pg_get_function_identity_arguments(p.oid),
                    pg_catalog.pg_get_functiondef(p.oid)
                FROM pg_catalog.pg_proc AS p
                JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
                WHERE n.nspname <> 'information_schema'
                  AND n.nspname !~ '^pg_'

                UNION ALL

                SELECT
                    'trigger',
                    n.nspname,
                    c.relname,
                    t.tgname,
                    pg_catalog.pg_get_triggerdef(t.oid, true)
                FROM pg_catalog.pg_trigger AS t
                JOIN pg_catalog.pg_class AS c ON c.oid = t.tgrelid
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                WHERE NOT t.tgisinternal
                  AND n.nspname <> 'information_schema'
                  AND n.nspname !~ '^pg_'
            ) AS objects
            ORDER BY object_kind, schema_name, object_name, sub_name, definition
            """
        )
    ).mappings()
    canonical: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["definition"] = _normalize_schema_definition(
            item["object_kind"],
            item["definition"],
        )
        canonical.append(item)
    return canonical


def schema_fingerprint(connection: Connection) -> str:
    """Hash the user-owned columns, constraints, indexes, routines, and triggers."""
    return sha256(canonical_json_bytes(schema_description(connection))).hexdigest()
