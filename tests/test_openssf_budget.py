"""Catalog deadlines stop work at safe boundaries without changing shadow callers."""

import pytest

from smithguard import openssf_budget as budget


def test_run_and_page_budget_are_finite_and_do_not_throw_on_stop_until_checkpoint(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(budget.time, "monotonic", lambda: clock[0])
    monkeypatch.setenv("SMITHGUARD_OPENSSF_TIMEOUT_SECONDS", "600")
    assert budget.bounded_timeout(1200) == 1200
    with budget.catalog_budget() as run:
        assert budget.bounded_timeout(1200) == 240
        with budget.page_budget():
            assert budget.bounded_timeout(1200) == 180
            run.stop_requested = True
            assert budget.bounded_timeout(30) == 30
        with pytest.raises(budget.CatalogStopped, match="stop requested"):
            budget.checkpoint()
        run.stop_requested = False
        clock[0] += 241
        with pytest.raises(budget.CatalogStopped, match="deadline expired"):
            budget.bounded_timeout(10)
    assert budget.bounded_timeout(1200) == 1200


@pytest.mark.parametrize(
    "value", ("infinity", "599", "601", "1800", "1801", "0600", "-1", "600.0", "\uff16\uff10\uff10")
)
def test_timeout_configuration_refuses_unbounded_values(monkeypatch, value):
    monkeypatch.setenv("SMITHGUARD_OPENSSF_TIMEOUT_SECONDS", value)
    with pytest.raises(ValueError, match="exactly 600"), budget.catalog_budget():
        pytest.fail("invalid timeout accepted")


def test_statement_budget_preserves_ten_second_limit_and_remaining_deadline(database, monkeypatch):
    from sqlalchemy import text
    from sqlalchemy.orm import Session

    clock = [100.0]
    monkeypatch.setattr(budget.time, "monotonic", lambda: clock[0])
    monkeypatch.setenv("SMITHGUARD_OPENSSF_TIMEOUT_SECONDS", "600")
    with budget.catalog_budget(), Session(database.engine) as session, session.begin():
        budget.set_statement_budget(session)
        assert session.scalar(text("SHOW statement_timeout")) == "10s"
        assert session.scalar(text("SHOW lock_timeout")) == "5s"
        clock[0] += 237
        budget.set_statement_budget(session)
        assert session.scalar(text("SHOW statement_timeout")) == "3s"
        assert session.scalar(text("SHOW lock_timeout")) == "3s"
