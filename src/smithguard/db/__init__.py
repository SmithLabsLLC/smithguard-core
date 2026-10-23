"""PostgreSQL persistence for SmithGuard."""

from .base import PRIVATE_WATCHLISTS_SCHEMA_NAME, SCHEMA_NAME, Base

__all__ = [
    "Base",
    "PRIVATE_WATCHLISTS_SCHEMA_NAME",
    "SCHEMA_NAME",
]
