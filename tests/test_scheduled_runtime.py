"""The scheduled warning command exposes only closed operations."""

import pytest

from smithguard.scheduled_runtime import main


def test_rehearsal_needs_no_database_key_or_network(capsys, monkeypatch) -> None:
    for name in (
        "SMITHGUARD_DATABASE_URL",
        "SMITHGUARD_XAI_KEY_FILE",
        "SMITHGUARD_SPEND_POLICY_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
    assert main(["--rehearsal", "--limit", "1"]) == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert "external_calls=0 public_writes=0 candidates=1" in output.out


@pytest.mark.audit_ids("WL-12")
def test_command_rejects_any_worker_limit_other_than_one(capsys) -> None:
    assert main(["--rehearsal", "--limit", "2"]) == 2
    assert "limit must equal one" in capsys.readouterr().err


def test_native_cleanup_failure_stops_unit_after_receipts_commit(monkeypatch, capsys, tmp_path):
    from types import SimpleNamespace

    from smithguard import emerging_leads
    from smithguard import scheduled_runtime as runtime

    monkeypatch.setattr(emerging_leads, "publication_enabled", lambda: False)
    monkeypatch.setattr(
        runtime,
        "load_runtime_config",
        lambda **kwargs: SimpleNamespace(
            spend_policy_path=tmp_path / "policy.json", xai_key_path=None
        ),
    )
    monkeypatch.setattr(
        runtime,
        "load_spend_policy_path",
        lambda _path: SimpleNamespace(primary_unavailable_reason="trust_not_qualified"),
    )
    monkeypatch.setattr(runtime, "_engine", lambda _config: object())
    monkeypatch.setattr(runtime, "_session_factory", lambda _engine: object())
    calls = []

    def committed_work(_factory, **kwargs):
        calls.append("receipt_committed")
        kwargs["provider"].primary.cleanup_failed = True
        return SimpleNamespace(queue="discovery", outcome="dead_letter")

    monkeypatch.setattr(runtime, "work_one", committed_work)
    assert runtime.main(["--work"]) == 3
    assert calls == ["receipt_committed"]
    assert "runtime_error:native_cleanup_failed" in capsys.readouterr().err
