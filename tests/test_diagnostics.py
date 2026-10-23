"""Internal diagnostics are bounded and cannot echo credential-shaped values."""

from __future__ import annotations

import subprocess

import pytest

import smithguard.migration_runtime as migration_runtime
from smithguard.diagnostics import exception_diagnostic_lines, redacted_message


@pytest.mark.audit_ids("DATA-09", "WL-11")
def test_exception_diagnostics_redact_secret_patterns_and_keep_only_the_last_20_lines() -> None:
    assignment = "GITHUB_" + "TOKEN=" + "synthetic-value-that-must-not-appear"
    provider_token = "gh" + "p_" + "A" * 24
    database_url = "postgresql+psycopg://user:" + "password@localhost/database"
    stderr = "\n".join(
        [f"discarded-{index}" for index in range(5)]
        + [assignment, provider_token, database_url]
        + [f"retained-{index}" for index in range(17)]
    )
    lines = exception_diagnostic_lines(RuntimeError("private detail"), stderr=stderr)
    assert lines[0] == "error_class=RuntimeError"
    assert lines[1] == "error_message=private detail"
    assert len(lines) == 22
    rendered = "\n".join(lines)
    assert "discarded-" not in rendered
    assert "synthetic-value-that-must-not-appear" not in rendered
    assert provider_token not in rendered
    assert "password" not in rendered
    assert "[REDACTED]" in rendered
    assert rendered.isascii()


@pytest.mark.audit_ids("DATA-09")
def test_migration_main_writes_diagnostics_before_the_fixed_failure_token(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    error = subprocess.CalledProcessError(
        2,
        ["alembic"],
        stderr="first\nsecond\n",
    )
    monkeypatch.setattr(
        migration_runtime,
        "migrate_and_record",
        lambda **_kwargs: (_ for _ in ()).throw(error),
    )
    monkeypatch.setenv("SMITHGUARD_DATABASE_URL", "synthetic")
    monkeypatch.setenv("SMITHGUARD_ALEMBIC_CONFIG_PATH", "/tmp/alembic.ini")
    monkeypatch.setenv("SMITHGUARD_MIGRATION_JOURNAL_PATH", "/tmp/journal.json")
    assert migration_runtime.main() == 2
    assert capsys.readouterr().err.splitlines() == [
        "error_class=CalledProcessError",
        "error_message=Command '['alembic']' returned non-zero exit status 2.",
        "error_stderr=first",
        "error_stderr=second",
        "runtime_error:migration_and_journal_failed",
    ]


def test_exception_message_line_is_redacted_bounded_and_omitted_when_empty() -> None:
    token = "gh" + "p_" + "B" * 24
    lines = exception_diagnostic_lines(RuntimeError(f"refused  {token}\nmore"), stderr="")
    assert lines == ("error_class=RuntimeError", "error_message=refused [REDACTED] more")
    assert exception_diagnostic_lines(RuntimeError(""), stderr="") == ("error_class=RuntimeError",)
    assert redacted_message(ValueError("x" * 5000)).encode("ascii").__len__() <= 1024
