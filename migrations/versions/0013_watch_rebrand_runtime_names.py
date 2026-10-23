"""rename the live runtime schemas for GoodBoy Watch

Revision ID: 0013_watch_rebrand
Revises: 0012_mx014
Create Date: omitted for reproducibility
"""

import re
from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0013_watch_rebrand"
down_revision: str | None = "0012_mx014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
migration_description: str = "Rename live schemas and disabled watchlist contract values"
rollback_mode: str = "forward_only"

OLD_MAIN_SCHEMA = "goodboy_security"
NEW_MAIN_SCHEMA = "goodboy_watch"
OLD_WATCHLIST_SCHEMA = "goodboy_hosted_watch"
NEW_WATCHLIST_SCHEMA = "goodboy_private_watchlists"
OLD_CLASSIFICATION = "hosted_watch_minimized"
NEW_CLASSIFICATION = "private_watchlists_minimized"
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]*$")


def _quoted(value: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise RuntimeError("database supplied an unsafe identifier")
    return f'"{value}"'


def _assert_no_old_classification() -> None:
    connection = op.get_bind()
    columns = connection.execute(
        text(
            """
            SELECT table_schema, table_name
            FROM information_schema.columns
            WHERE table_schema IN (:main_schema, :watchlist_schema)
              AND column_name = 'data_classification'
            ORDER BY table_schema, table_name
            """
        ),
        {
            "main_schema": OLD_MAIN_SCHEMA,
            "watchlist_schema": OLD_WATCHLIST_SCHEMA,
        },
    ).mappings()
    for column in columns:
        schema = _quoted(column["table_schema"])
        table = _quoted(column["table_name"])
        count = connection.execute(
            text(
                f"SELECT count(*) FROM {schema}.{table} WHERE data_classification = :classification"
            ),
            {"classification": OLD_CLASSIFICATION},
        ).scalar_one()
        if count:
            raise RuntimeError(
                "legacy minimized watchlist rows must be handled before the naming migration"
            )


def _assert_disabled_watchlists_empty() -> None:
    connection = op.get_bind()
    tables = connection.execute(
        text(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = :schema
              AND table_type = 'BASE TABLE'
            ORDER BY table_name
            """
        ),
        {"schema": OLD_WATCHLIST_SCHEMA},
    ).scalars()
    for table_name in tables:
        table = _quoted(table_name)
        count = connection.execute(
            text(f'SELECT count(*) FROM "{OLD_WATCHLIST_SCHEMA}".{table}')
        ).scalar_one()
        if count:
            raise RuntimeError(
                "the disabled legacy watchlist schema must be empty before it is renamed"
            )


def _rename_classification_constraints() -> None:
    connection = op.get_bind()
    constraints = tuple(
        connection.execute(
            text(
                """
                SELECT n.nspname AS schema_name,
                       c.relname AS table_name,
                       con.conname AS constraint_name,
                       pg_get_constraintdef(con.oid, true) AS definition
                FROM pg_constraint AS con
                JOIN pg_class AS c ON c.oid = con.conrelid
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE con.contype = 'c'
                  AND n.nspname IN (:main_schema, :watchlist_schema)
                  AND pg_get_constraintdef(con.oid, true) LIKE :needle
                ORDER BY n.nspname, c.relname, con.conname
                """
            ),
            {
                "main_schema": OLD_MAIN_SCHEMA,
                "watchlist_schema": OLD_WATCHLIST_SCHEMA,
                "needle": f"%{OLD_CLASSIFICATION}%",
            },
        ).mappings()
    )
    if not constraints:
        raise RuntimeError("expected legacy classification constraints are missing")
    for constraint in constraints:
        schema = _quoted(constraint["schema_name"])
        table = _quoted(constraint["table_name"])
        name = _quoted(constraint["constraint_name"])
        definition = constraint["definition"]
        if not isinstance(definition, str) or OLD_CLASSIFICATION not in definition:
            raise RuntimeError("legacy classification constraint is malformed")
        replacement = definition.replace(OLD_CLASSIFICATION, NEW_CLASSIFICATION)
        connection.execute(text(f"ALTER TABLE {schema}.{table} DROP CONSTRAINT {name}"))
        connection.execute(
            text(f"ALTER TABLE {schema}.{table} ADD CONSTRAINT {name} {replacement}")
        )


def upgrade() -> None:
    """Rename only mutable live identifiers while preserving stable record IDs."""
    _assert_no_old_classification()
    _assert_disabled_watchlists_empty()
    _rename_classification_constraints()
    op.execute(
        "ALTER INDEX goodboy_hosted_watch.ix_hw_current_tenant_confirmed "
        "RENAME TO ix_private_watchlists_current_tenant_confirmed"
    )
    op.execute(
        "ALTER INDEX goodboy_hosted_watch.ix_hw_admin_audit_tenant_time "
        "RENAME TO ix_private_watchlists_admin_audit_tenant_time"
    )
    op.execute("ALTER SCHEMA goodboy_security RENAME TO goodboy_watch")
    op.execute("ALTER SCHEMA goodboy_hosted_watch RENAME TO goodboy_private_watchlists")


def downgrade() -> None:
    """Refuse to blur the post-cutover evidence boundary."""
    raise RuntimeError(
        "0013_watch_rebrand is forward-only so rollback requires the verified pre-cutover backup"
    )
