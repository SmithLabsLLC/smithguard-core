import copy
import json
from pathlib import Path

import pytest

from smithguard_client.discovery import artifact, discover
from smithguard_client.run import run
from smithguard_client.storage import PrivateDirectory
from smithguard_client.transport import ReadFailure
from smithguard_client.verification import Verification, canonical


def make_preview(tmp_path):
    for n, v in [("shared", "1.0"), ("other", "2.0"), ("private-canary", "1.0")]:
        root = tmp_path / f"{n}-{v}.dist-info"
        root.mkdir()
        (root / "METADATA").write_text(f"Name: {n}\nVersion: {v}\n")
    duplicate = tmp_path / "dup"
    duplicate.mkdir()
    root = duplicate / "shared-1.0.dist-info"
    root.mkdir()
    (root / "METADATA").write_text("Name: shared\nVersion: 1.0\n")
    return discover(
        [str(tmp_path), str(duplicate)],
        approved_public=[artifact("shared", "1.0"), artifact("other", "2.0")],
    )


def verified(coord, status="verified"):
    body = json.loads(Path(__file__).with_name("assessment-example.json").read_text())
    body["artifact"] = coord
    return Verification(status, "signature_verified", True, "active", True, True, canonical(body))


class Reader:
    def __init__(self, failure=None):
        self.calls = []
        self.failure = failure

    def assess(self, coord):
        self.calls.append(coord)
        if self.failure:
            raise self.failure
        return verified(coord)


def test_dedup_keeps_all_installations_and_preserves_preview(tmp_path):
    preview = make_preview(tmp_path)
    before = canonical(preview)
    reader = Reader()
    report, state = run(preview, preview["approval_sha256"], reader=reader)
    assert len(reader.calls) == 2
    assert report["counts"]["installations"] == 4
    assert report["counts"]["approved_coordinates"] == 2
    assert report["counts"]["installation_statuses"] == {
        "completed": 3,
        "skipped": 1,
        "unchecked": 0,
        "failed": 0,
        "not_run": 0,
    }
    assert canonical(preview) == before
    assert b"private-canary" not in canonical(reader.calls)
    assert b"incidents" not in canonical(state) and b"signature" not in canonical(state)


def test_resume_rechecks_and_does_not_load_old_answers(tmp_path):
    preview = make_preview(tmp_path)
    report, state = run(preview, preview["approval_sha256"], reader=Reader())
    reader = Reader()
    states = []
    new, newstate = run(
        preview,
        preview["approval_sha256"],
        reader=reader,
        resume=state,
        checkpoint=lambda x: states.append(copy.deepcopy(x)),
    )
    assert len(reader.calls) == 2
    assert all(x["status"] == "stale" for x in states[0]["coordinates"].values())
    assert newstate["previous_run_id"] == state["run_id"]
    changed = {**state, "policy_version": "old"}
    with pytest.raises(ValueError):
        run(preview, preview["approval_sha256"], reader=Reader(), resume=changed)


def test_rate_stop_accounts_remaining_and_duplicates(tmp_path):
    preview = make_preview(tmp_path)
    reader = Reader(ReadFailure("quota_or_rate_limit", True))
    report, state = run(preview, preview["approval_sha256"], reader=reader)
    assert len(reader.calls) == 1 and not report["run_complete"]
    assert {x["status"] for x in state["coordinates"].values()} == {"failed", "not_run"}
    assert sum(report["counts"]["installation_statuses"].values()) == 4


def test_invalid_answer_not_included_as_trusted_evidence(tmp_path):
    preview = make_preview(tmp_path)
    reader = Reader()
    reader.assess = lambda coord: Verification(
        "invalid", "signature_mismatch", False, "active", True, True, b"bad"
    )
    report, state = run(preview, preview["approval_sha256"], reader=reader)
    assert all("assessment" not in row for row in report["coordinate_results"].values())
    assert not report["run_complete"]


def test_bad_facts_rejected_before_network(tmp_path):
    preview = make_preview(tmp_path)
    reader = Reader()
    with pytest.raises(ValueError):
        run(preview, preview["approval_sha256"], reader=reader, local_facts={"missing": {}})
    assert not reader.calls


def test_private_output_refuses_links_replacement_and_public_directory(tmp_path):
    output = tmp_path / "output"
    with PrivateDirectory(str(output), create=True) as target:
        target.write_json("preview.json", {"private": "local"})
        assert (output / "preview.json").stat().st_mode & 0o777 == 0o600
        with pytest.raises(FileExistsError):
            target.write_json("preview.json", {})
        (output / "linked.json").symlink_to(output / "preview.json")
        with pytest.raises((OSError, ValueError)):
            target.read_json("linked.json")
        sha = target.replace_own_json("state.json", {"run_id": "a"}, previous_sha256=None)
        sha = target.replace_own_json("state.json", {"run_id": "b"}, previous_sha256=sha)
        assert target.read_json("state.json")["run_id"] == "b"
        (output / "state.json").write_text("changed")
        with pytest.raises(ValueError):
            target.replace_own_json("state.json", {}, previous_sha256=sha)
    output.chmod(0o755)
    with pytest.raises(ValueError):
        PrivateDirectory(str(output))


def test_report_html_and_text_escape_private_and_source_text(tmp_path):
    from smithguard_client.report import html_report, text_report

    preview = make_preview(tmp_path)
    report, _ = run(preview, preview["approval_sha256"], reader=Reader())
    report["installations"][0]["scope"] = "<script>alert(1)</script>\x1b[2J"
    report["coordinate_results"][next(iter(report["coordinate_results"]))]["assessment"][
        "incidents"
    ][0]["title"] = '<img src="https://leak.invalid">'
    page = html_report(report)
    assert b"<script>" not in page and b"<img " not in page
    assert b"default-src" in page and b"connect-src" not in page  # default none denies network
    assert b"\x1b" not in text_report(report)
    assert b"&lt;img" in page and b"coordinate-" in page and b"incident-" in page


def test_cli_preview_never_requests_and_run_refuses_changed_metadata(tmp_path, monkeypatch):
    import smithguard_client.cli as cli
    from smithguard_client.cli import main
    from smithguard_client.verification import strict_json

    scope = tmp_path / "site"
    scope.mkdir()
    root = scope / "shared.dist-info"
    root.mkdir()
    (root / "METADATA").write_text("Name: shared\nVersion: 1.0\n")
    output = tmp_path / "private"
    monkeypatch.setattr(
        cli, "PublicReader", lambda **kw: pytest.fail("network reader must not be created")
    )
    assert (
        main(["preview", "--scope", str(scope), "--public", "shared==1.0", "--output", str(output)])
        == 0
    )
    preview = strict_json((output / "preview.json").read_bytes())
    (root / "METADATA").write_text("Name: shared\nVersion: 2.0\n")
    assert main(["run", "--directory", str(output), "--approve", preview["approval_sha256"]]) == 2


def test_large_answer_compacts_and_continues_every_coordinate(tmp_path, monkeypatch):
    import importlib

    module = importlib.import_module("smithguard_client.run")
    monkeypatch.setattr(module, "ITEM_BUDGET", 1)
    preview = make_preview(tmp_path)
    report, state = run(preview, preview["approval_sha256"], reader=Reader())
    assert len(report["coordinate_results"]) == 2
    assert sum(report["counts"]["installation_statuses"].values()) == 4
    assert report["run_complete"] and not report["evidence_complete"]
    assert {r["status"] for r in state["coordinates"].values()} == {"completed"}
    assert all(r["assessment"]["evidence_truncated"] for r in report["coordinate_results"].values())
    assert report["counts"]["unique_incidents"] > 0
    assert report["counts"]["unique_source_reports"] > 0
    from smithguard_client.report import html_report, text_report

    assert b"Evidence truncated" in html_report(report)
    assert b"Evidence truncated" in text_report(report)


def test_small_output_budget_refuses_before_network(tmp_path, monkeypatch):
    import importlib

    module = importlib.import_module("smithguard_client.run")
    monkeypatch.setattr(module, "REPORT_BUDGET", 100)
    preview = make_preview(tmp_path)
    reader = Reader()
    with pytest.raises(ValueError, match="output budget"):
        run(preview, preview["approval_sha256"], reader=reader)
    assert reader.calls == []


def test_condition_annotation_budget_is_visible_without_losing_version_finding(
    tmp_path, monkeypatch
):
    import importlib
    from datetime import UTC, datetime

    module = importlib.import_module("smithguard_client.run")
    monkeypatch.setattr(module, "ANNOTATION_BUDGET", 1)
    preview = make_preview(tmp_path)
    item = next(x for x in preview["installations"] if x["coordinate"]["name"] == "shared")
    facts = {
        item["installation_id"]: {
            "target": "Synthetic target",
            "observed_at": datetime.now(UTC).isoformat(),
            "evidence": "Synthetic explicit facts",
            "values": {"os": "linux"},
        }
    }
    report, state = run(preview, preview["approval_sha256"], reader=Reader(), local_facts=facts)
    assert report["run_complete"] and not report["interpretation_complete"]
    affected = next(
        x for x in report["installations"] if x["installation_id"] == item["installation_id"]
    )
    assert affected["local_applicability_status"] == "incomplete_output_budget"
    assert affected["local_applicability_omitted"] > 0
    assert report["counts"]["unique_incidents"] > 0
    assert all(r["assessment"]["incidents"] for r in report["coordinate_results"].values())


def test_local_facts_have_an_aggregate_bound():
    from smithguard_client.run import validate_facts

    facts = {
        str(i): {
            "target": "x" * 2000,
            "observed_at": "2026-10-26T00:00:00Z",
            "evidence": "x" * 2000,
            "values": {},
        }
        for i in range(300)
    }
    with pytest.raises(ValueError, match="aggregate"):
        validate_facts(facts, set(facts))


def test_readable_report_overflow_keeps_json_and_complete_counts(tmp_path, monkeypatch):
    import smithguard_client.report as rendering

    preview = make_preview(tmp_path)
    report, _ = run(preview, preview["approval_sha256"], reader=Reader())
    # Escaping repeats source text in multiple views; the HTML cap is independent
    # of the retained JSON budget and must never discard the underlying evidence.
    for row in report["coordinate_results"].values():
        for incident in row["assessment"]["incidents"]:
            incident["title"] = "<malicious>&" * 1000
    before = canonical(report)
    monkeypatch.setattr(rendering, "MAX_RENDER_BYTES", 16000)
    page = rendering.html_report(report)
    assert len(page) <= 16000 and b"HTML detail is limited" in page
    assert b"<strong>4</strong> installations" in page
    assert b"<malicious>" not in page and page.endswith(b"</body></html>")
    assert canonical(report) == before
    text = rendering.text_report(report)
    assert len(text) <= 16000 and b"Text index truncated" in text
    assert b"4 installations" in text
    assert canonical(report) == before


def test_html_oversized_local_labels_fall_back_to_explicit_summary(tmp_path, monkeypatch):
    import smithguard_client.report as rendering

    preview = make_preview(tmp_path)
    report, _ = run(preview, preview["approval_sha256"], reader=Reader())
    for item in report["installations"]:
        if item["coordinate"] is None:
            item["metadata_directory"] = "<private>" * 10000
    # Force a valid local-only entry to exercise the large-label path.
    report["installations"][0]["coordinate"] = None
    report["installations"][0]["metadata_directory"] = "<private>" * 10000
    before = canonical(report)
    monkeypatch.setattr(rendering, "MAX_RENDER_BYTES", 16000)
    page = rendering.html_report(report)
    assert len(page) <= 16000 and b"HTML index omitted" in page
    assert b"Complete counts" in page and b"installations&quot;: 4" in page
    assert b"<private>" not in page and page.endswith(b"</body></html>")
    assert canonical(report) == before


@pytest.mark.parametrize("url", ["javascript:alert(1)", "https://me:secret@x.test", "https://["])
def test_report_refuses_unsafe_source_links(tmp_path, url):
    from smithguard_client.report import html_report

    preview = make_preview(tmp_path)
    report, _ = run(preview, preview["approval_sha256"], reader=Reader())
    for row in report["coordinate_results"].values():
        for incident in row["assessment"]["incidents"]:
            for source in incident["source_reports"]:
                source["source_context"] = {"source_url": url}
    page = html_report(report)
    assert b"Open the original source" not in page


@pytest.mark.parametrize("schema", ["2.1.0", "2.2.0", "2.3.0"])
def test_pre24_null_fields_render_and_never_qualify_candidate(tmp_path, schema):
    from importlib.resources import files

    from jsonschema import Draft202012Validator, FormatChecker

    from smithguard_client.interpretation import candidate_decision
    from smithguard_client.report import html_report, text_report

    preview = make_preview(tmp_path)
    values = []

    def legacy(coord):
        body = verified(coord).document
        body["schema_version"] = schema
        body["registry_project_context"] = None
        body["reason_codes"] = None
        for incident in body["incidents"]:
            for source in incident["source_reports"]:
                source["source_fixed_versions"] = None
                source["fix_evidence_incomplete"] = None
        # Exercise real schema compatibility rather than an invented projection.
        schema_doc = json.loads(
            files("smithguard_client.schemas").joinpath("assessment.json").read_text()
        )
        Draft202012Validator(schema_doc, format_checker=FormatChecker()).validate(body)
        value = Verification(
            "verified", "signature_verified", True, "active", True, True, canonical(body)
        )
        values.append(value)
        return value

    reader = Reader()
    reader.assess = legacy
    report, _ = run(preview, preview["approval_sha256"], reader=reader)
    assert b"Fix evidence is incomplete" in html_report(report)
    assert text_report(report)
    decision = candidate_decision(
        values[0],
        values[1],
        compatibility="reviewed_supported",
        installed_identity="independently_verified",
    )
    assert decision["outcome"] == "no_verified_recommendation"
    assert "source_fix_schema_unavailable" in decision["reasons"]


def test_unverified_answers_separate_counts_and_labels(tmp_path):
    from smithguard_client.report import html_report, text_report

    preview = make_preview(tmp_path)
    reader = Reader()
    reader.assess = lambda coord: Verification(
        "unchecked", "key_unavailable", False, None, False, True, verified(coord).original
    )
    report, _ = run(preview, preview["approval_sha256"], reader=reader)
    assert report["counts"]["unique_incidents"] == 0
    assert report["counts"]["unique_source_reports"] == 0
    assert report["counts"]["unverified_unique_incidents"] > 0
    assert b"Unverified answer; not decision evidence" in html_report(report)
    assert b"Unverified answer; not decision evidence" in text_report(report)
    assert b"Verified current version evidence" not in html_report(report)


def test_stale_supplied_facts_visible_in_both_reports(tmp_path):
    from smithguard_client.report import html_report, text_report

    preview = make_preview(tmp_path)
    item = next(x for x in preview["installations"] if x["coordinate"])
    facts = {
        item["installation_id"]: {
            "target": "synthetic",
            "observed_at": "2020-01-01T00:00:00Z",
            "evidence": "explicit synthetic",
            "values": {"os": "linux"},
        }
    }
    report, _ = run(preview, preview["approval_sha256"], reader=Reader(), local_facts=facts)
    assert b"facts_supplied_stale_not_evaluated" in html_report(report)
    assert b"facts_supplied_stale_not_evaluated" in text_report(report)


def test_failed_private_write_removes_partial_file(tmp_path, monkeypatch):
    import os

    with PrivateDirectory(str(tmp_path / "out"), create=True) as output:
        monkeypatch.setattr(
            os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("synthetic disk failure"))
        )
        with pytest.raises(OSError):
            output.write("partial.txt", b"sensitive synthetic data")
        assert not (tmp_path / "out" / "partial.txt").exists()


def test_aggregate_budget_still_accounts_remaining_coordinates(tmp_path, monkeypatch):
    import importlib

    module = importlib.import_module("smithguard_client.run")
    monkeypatch.setattr(module, "REPORT_BUDGET", module.ANNOTATION_BUDGET + 65536 + 32000)
    preview = make_preview(tmp_path)
    reader = Reader()

    def large(coord):
        reader.calls.append(coord)
        body = verified(coord).document
        incident = body["incidents"][0]
        body["incidents"] = []
        for index in range(30):
            row = copy.deepcopy(incident)
            row["incident_id"] += str(index)
            row["title"] = "Synthetic large title " * 90
            body["incidents"].append(row)
        return Verification(
            "verified", "signature_verified", True, "active", True, True, canonical(body)
        )

    reader.assess = large
    report, state = run(preview, preview["approval_sha256"], reader=reader)
    assert len(reader.calls) == 1
    assert {x["status"] for x in state["coordinates"].values()} == {"failed", "not_run"}
    assert sum(report["counts"]["installation_statuses"].values()) == 4
    assert not report["run_complete"]


@pytest.mark.parametrize("kind", ["skipped", "failed", "expired", "no_sources"])
def test_every_supplied_unevaluated_fact_set_is_counted(tmp_path, monkeypatch, kind):
    import importlib
    from datetime import UTC, datetime

    from smithguard_client.report import html_report, text_report

    module = importlib.import_module("smithguard_client.run")
    preview = make_preview(tmp_path)
    item = next(
        x
        for x in preview["installations"]
        if (x["status"] != "eligible_for_preview") == (kind == "skipped")
    )
    facts = {
        item["installation_id"]: {
            "target": "fixture",
            "observed_at": datetime.now(UTC).isoformat(),
            "evidence": "explicit",
            "values": {"os": "linux"},
        }
    }
    reader = Reader(ReadFailure("synthetic_failure") if kind == "failed" else None)
    if kind == "expired":
        current = iter([True, False])
        monkeypatch.setattr(module, "facts_current", lambda supplied: next(current))
    if kind == "no_sources":

        def no_sources(coord):
            value = verified(coord)
            body = value.document
            body["incidents"] = []
            return Verification(
                "verified", "signature_verified", True, "active", True, True, canonical(body)
            )

        reader.assess = no_sources
    report, _ = run(preview, preview["approval_sha256"], reader=reader, local_facts=facts)
    assert not report["interpretation_complete"]
    assert report["counts"]["supplied_facts_not_fully_evaluated"] == 1
    assert b"Supplied fact sets not fully evaluated: 1" in text_report(report)
    assert b"Supplied fact sets not fully evaluated: 1" in html_report(report)


def test_compact_projection_retains_warning_and_coverage_limits(tmp_path, monkeypatch):
    import importlib

    module = importlib.import_module("smithguard_client.run")
    monkeypatch.setattr(module, "ITEM_BUDGET", 1)
    preview = make_preview(tmp_path)
    reader = Reader()

    def warned(coord):
        body = verified(coord).document
        body.update(
            result="not_affected",
            preliminary_warnings=[{"warning_id": "gbsec:warning:synthetic"}],
            preliminary_warnings_truncated=True,
        )
        return Verification(
            "verified", "signature_verified", True, "active", True, True, canonical(body)
        )

    reader.assess = warned
    report, _ = run(preview, preview["approval_sha256"], reader=reader)
    for row in report["coordinate_results"].values():
        compact = row["assessment"]
        assert compact["preliminary_warning_count"] == 1
        assert compact["preliminary_warning_ids"] == ["gbsec:warning:synthetic"]
        assert compact["preliminary_warnings_truncated"]
        assert compact["coverage_result"] == "supported"
        assert compact["registry_state"] == "removed"
        assert compact["unknown_count"] == 1
    from smithguard_client.report import html_report, text_report

    assert b"Preliminary warnings: 1" in html_report(report)
    assert b'"preliminary_warning_count": 1' in text_report(report)


def test_unfresh_verified_response_has_visible_reason(tmp_path):
    from smithguard_client.report import html_report, text_report

    preview = make_preview(tmp_path)
    reader = Reader()
    reader.assess = lambda coord: Verification(
        "verified", "signature_verified", True, "active", True, False, verified(coord).original
    )
    report, state = run(preview, preview["approval_sha256"], reader=reader)
    assert not report["run_complete"]
    assert all(row["reason"] == "response_not_fresh" for row in state["coordinates"].values())
    assert b"response_not_fresh" in html_report(report)
    assert b"response_not_fresh" in text_report(report)


@pytest.mark.parametrize("kind", ["incidents", "warnings", "sources", "context", "fix_only"])
@pytest.mark.parametrize("compact", [False, True])
def test_service_omissions_remain_incomplete_in_full_and_compact_reports(
    tmp_path, monkeypatch, kind, compact
):
    import importlib
    from datetime import UTC, datetime

    from smithguard_client.report import html_report, text_report

    module = importlib.import_module("smithguard_client.run")
    if compact:
        monkeypatch.setattr(module, "ITEM_BUDGET", 1)
    preview = make_preview(tmp_path)
    selected = next(x for x in preview["installations"] if x["status"] == "eligible_for_preview")
    facts = {
        selected["installation_id"]: {
            "target": "synthetic",
            "observed_at": datetime.now(UTC).isoformat(),
            "evidence": "explicit fixture",
            "values": {"os": "linux"},
        }
    }
    reader = Reader()

    def limited(coord):
        body = verified(coord).document
        body["reason_codes"] = ["results_incomplete"]
        if kind == "incidents":
            body["incidents_truncated"] = True
        elif kind == "warnings":
            body["preliminary_warnings_truncated"] = True
        elif kind == "sources":
            body["incidents"][0]["source_reports_truncated"] = True
        elif kind == "context":
            body["incidents"][0]["source_reports"][0]["source_context_state"] = "omitted_budget"
        else:
            body["incidents"][0]["fix_evidence_incomplete"] = True
        return Verification(
            "verified", "signature_verified", True, "active", True, True, canonical(body)
        )

    reader.assess = limited
    report, _ = run(preview, preview["approval_sha256"], reader=reader, local_facts=facts)
    incomplete = compact or kind != "fix_only"
    assert report["run_complete"]
    assert report["evidence_complete"] is not incomplete
    assert report["interpretation_complete"] is not incomplete
    assert report["counts"]["service_incomplete_answers"] == 2
    assert report["counts"]["service_truncated_answers"] == (0 if kind == "fix_only" else 2)
    assert report["counts"]["supplied_facts_not_fully_evaluated"] == int(incomplete)
    for render in (html_report, text_report):
        output = render(report)
        assert b"results_incomplete" in output
        assert b"Service incomplete answers: 2" in output
        if incomplete:
            assert b"Evidence complete: False" in output
            assert b"evidence_truncated_not_evaluated" in output
