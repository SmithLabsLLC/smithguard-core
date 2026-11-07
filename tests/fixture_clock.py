"""Fixed collection clock for synthetic catalog fixtures, never production rights."""

from datetime import UTC, datetime

FIXTURE_NOW = datetime(2026, 11, 1, 12, tzinfo=UTC)


class FixtureDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return FIXTURE_NOW.astimezone(tz) if tz is not None else FIXTURE_NOW.replace(tzinfo=None)
