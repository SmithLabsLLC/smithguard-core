"""Pin the shared early-renewal boundary without changing existing source behavior."""

from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.bulletin_freshness import recheck_due
from smithguard.db.bulletin_models import BulletinCurrent

from .test_bulletin_automation import NOW, run


@pytest.mark.parametrize("source", ["redhat-rhsa", "debian-dsa", "ubuntu-usn"])
def test_recheck_boundary_for_a_recent_source_detail(source):
    current = SimpleNamespace(
        source_key=source,
        document={"document": {"published_at": NOW - timedelta(days=1)}},
        updated_at=NOW,
    )
    assert not recheck_due(current, NOW + timedelta(hours=20, minutes=59))
    assert recheck_due(current, NOW + timedelta(hours=21, minutes=30)) is (source == "redhat-rhsa")
    assert recheck_due(current, NOW + timedelta(hours=22))


def test_existing_ubuntu_public_renewal_waits_until_two_hour_window(database):
    run(database)
    run(database, now=NOW + timedelta(hours=21, minutes=30))
    with Session(database.engine) as session:
        row = session.scalar(select(BulletinCurrent))
        assert row.verified_at == NOW and row.verification_due_at == NOW + timedelta(hours=24)
    run(database, now=NOW + timedelta(hours=22))
    with Session(database.engine) as session:
        row = session.scalar(select(BulletinCurrent))
        assert row.verified_at == NOW + timedelta(hours=22)
        assert row.revision == 1
