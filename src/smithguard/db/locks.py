"""The one PostgreSQL advisory-lock idiom.

The helper never opens a transaction: every caller supplies one, and the lock is held
until that transaction ends. Callers that need ordered acquisition sort their names
themselves; re-acquiring the same name inside one transaction is a no-op.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session


def advisory_xact_lock(session: Session, name: str) -> None:
    """Take the transaction-scoped advisory lock keyed by ``name``."""
    session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(name, 0))))
