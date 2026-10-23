"""Alembic environment for the isolated SmithGuard schema."""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from smithguard.db import models as _models  # noqa: F401
from smithguard.db.base import (
    PRIVATE_WATCHLISTS_SCHEMA_NAME,
    Base,
)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _include_object(
    object_: object,
    _name: str | None,
    _type: str,
    _reflected: bool,
    _compare_to: object | None,
) -> bool:
    schema = getattr(object_, "schema", None)
    if schema is None:
        schema = getattr(getattr(object_, "table", None), "schema", None)
    return schema != PRIVATE_WATCHLISTS_SCHEMA_NAME


def _database_url() -> str:
    explicit = config.attributes.get("database_url")
    if explicit is not None:
        return str(explicit)
    return os.environ.get(
        "SMITHGUARD_DATABASE_URL",
        config.get_main_option("sqlalchemy.url"),
    )


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
        include_object=_include_object,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            include_object=_include_object,
            compare_type=True,
            transaction_per_migration=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
