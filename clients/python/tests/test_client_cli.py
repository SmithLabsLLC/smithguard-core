"""Complete CLI lifecycle with synthetic metadata and an injected finite reader."""

import fcntl
import json
import os
import signal
from pathlib import Path

import pytest

import smithguard_client.cli as cli
from smithguard_client.storage import PrivateDirectory
from smithguard_client.transport import ReadFailure
from smithguard_client.verification import Verification, canonical


def setup_cli(tmp_path, monkeypatch, interrupt=None):
    scope = tmp_path / "site"
    scope.mkdir()
    for name in ("first", "second", "third"):
        metadata = scope / (name + ".dist-info")
        metadata.mkdir()
        (metadata / "METADATA").write_text(f"Name: {name}\nVersion: 1.0\n")
    output = tmp_path / "out"
    args = ["preview", "--scope", str(scope), "--output", str(output)]
    for name in ("first", "second", "third"):
        args.extend(["--public", name + "==1.0"])
    assert cli.main(args) == 0
    preview = json.loads((output / "preview.json").read_bytes())
    readers = []

    class Reader:
        def __init__(self, *, stopped, **kwargs):
            self.stopped = stopped
            self.calls = []
            self.closed = False
            readers.append(self)

        def assess(self, coord):
            self.calls.append(coord)
            if interrupt and len(self.calls) == 1:
                os.kill(os.getpid(), interrupt)
            if self.stopped.is_set():
                raise ReadFailure("cancelled", True)
            body = json.loads(Path(__file__).with_name("assessment-example.json").read_text())
            body["artifact"] = coord
            return Verification(
                "verified", "signature_verified", True, "active", True, True, canonical(body)
            )

        def close(self):
            self.closed = True

    monkeypatch.setattr(cli, "PublicReader", Reader)
    runargs = ["run", "--directory", str(output), "--approve", preview["approval_sha256"]]
    return output, runargs, readers


def states(output):
    return [json.loads(p.read_bytes()) for p in output.glob("state-*.json")]


def test_cli_success_and_resume_chain(tmp_path, monkeypatch):
    output, args, readers = setup_cli(tmp_path, monkeypatch)
    assert cli.main(args) == 0
    first = states(output)[0]
    assert first["run_complete"] and first["report_exports"]["status"] == "complete"
    assert len(first["report_exports"]["files"]) == 3
    for name in first["report_exports"]["files"]:
        assert (output / name).is_file()
        assert (output / name).stat().st_mode & 0o777 == 0o600
    assert cli.main(args + ["--resume", "state-" + first["run_id"] + ".json"]) == 0
    second = next(s for s in states(output) if s["run_id"] != first["run_id"])
    assert second["previous_run_id"] == first["run_id"]
    assert all(len(r.calls) == 3 and r.closed for r in readers)


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_cli_signal_cancels_and_writes_reports(tmp_path, monkeypatch, signum):
    output, args, readers = setup_cli(tmp_path, monkeypatch, signum)
    old_handler = signal.getsignal(signum)
    assert cli.main(args) == 2
    state = states(output)[0]
    assert not state["run_complete"]
    assert [v["status"] for v in state["coordinates"].values()].count("not_run") == 2
    assert state["report_exports"]["status"] == "complete"
    assert len(state["report_exports"]["files"]) == 3
    assert readers[0].closed
    assert signal.getsignal(signum) == old_handler


def test_cli_refuses_concurrent_directory_writer(tmp_path, monkeypatch):
    output, args, readers = setup_cli(tmp_path, monkeypatch)
    with PrivateDirectory(str(output)) as held:
        fcntl.flock(held.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert cli.main(args) == 2
    assert not readers and not states(output)


def test_cli_render_failure_records_exact_exports_and_can_resume(tmp_path, monkeypatch):
    output, args, readers = setup_cli(tmp_path, monkeypatch)
    original = cli.html_report

    def fail(report):
        raise TypeError("synthetic renderer failure")

    monkeypatch.setattr(cli, "html_report", fail)
    assert cli.main(args) == 2
    state = states(output)[0]
    assert state["run_complete"]
    assert state["report_exports"] == {
        "status": "failed",
        "error_type": "TypeError",
        "files": ["report-" + state["run_id"] + ".json"],
    }
    assert not list(output.glob("*.html")) and readers[0].closed
    monkeypatch.setattr(cli, "html_report", original)
    assert cli.main(args + ["--resume", "state-" + state["run_id"] + ".json"]) == 0
    assert len(readers[1].calls) == 3


@pytest.mark.parametrize("kind", ["stale", "unchecked"])
def test_cli_unused_facts_mean_incomplete_and_exit2(tmp_path, monkeypatch, capsys, kind):
    from datetime import UTC, datetime

    output, args, readers = setup_cli(tmp_path, monkeypatch)
    preview = json.loads((output / "preview.json").read_bytes())
    observed = "2020-01-01T00:00:00Z" if kind == "stale" else datetime.now(UTC).isoformat()
    facts = {
        preview["installations"][0]["installation_id"]: {
            "target": "synthetic",
            "observed_at": observed,
            "evidence": "explicit fixture",
            "values": {"os": "linux"},
        }
    }
    with PrivateDirectory(str(output)) as target:
        target.write_json("facts.json", facts)
    if kind == "unchecked":
        original = cli.PublicReader

        def reader_factory(**kw):
            reader = original(**kw)
            assess = reader.assess

            def unchecked(coord):
                value = assess(coord)
                return Verification(
                    "unchecked", "key_unavailable", False, "unknown", False, True, value.original
                )

            reader.assess = unchecked
            return reader

        monkeypatch.setattr(cli, "PublicReader", reader_factory)
    assert cli.main(args + ["--local-facts", "facts.json"]) == 2
    state = states(output)[0]
    report = json.loads((output / ("report-" + state["run_id"] + ".json")).read_bytes())
    assert not report["interpretation_complete"]
    assert report["counts"]["supplied_facts_not_fully_evaluated"] == 1
    message = capsys.readouterr().out
    assert "Supplied fact sets not fully evaluated: 1" in message
    if kind == "stale":
        assert state["stale_fact_sets_at_start"] == 1
        assert "supplied fact sets are stale" in message


def test_cli_service_truncation_preserves_checks_but_exits_incomplete(
    tmp_path, monkeypatch, capsys
):
    output, args, readers = setup_cli(tmp_path, monkeypatch)
    original = cli.PublicReader

    def factory(**kw):
        reader = original(**kw)
        assess = reader.assess

        def truncated(coord):
            value = assess(coord)
            body = value.document
            body["incidents_truncated"] = True
            body["reason_codes"] = ["results_incomplete"]
            return Verification(
                "verified", "signature_verified", True, "active", True, True, canonical(body)
            )

        reader.assess = truncated
        return reader

    monkeypatch.setattr(cli, "PublicReader", factory)
    assert cli.main(args) == 2
    assert "Evidence complete: False" in capsys.readouterr().out
    state = states(output)[0]
    assert state["run_complete"] and len(readers[0].calls) == 3
    assert state["report_exports"]["status"] == "complete"
