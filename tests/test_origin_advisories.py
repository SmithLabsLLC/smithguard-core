"""Complete direct-origin acquisition and conservative public-coordinate projection."""

from __future__ import annotations

import io
import json
import stat
import subprocess
import zipfile
from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest

from smithguard import origin_advisories as m
from smithguard.contracts.generated import Context
from smithguard.identifiers import canonical_json_bytes, sha256_id
from smithguard.range_evaluation import osv_range_matches

COMMIT = "a" * 40
NOW = datetime(2026, 10, 6, 23, 0, tzinfo=UTC)
PUBLISHED = "2026-01-01T12:00:00Z"
MODIFIED = "2026-10-01T12:00:00Z"


def document(origin="rustsec", *, identifier=None, name=None):
    advisory_id = identifier or ("RUSTSEC-2026-0328" if origin == "rustsec" else "GO-2026-0001")
    package_name = name or ("decompress" if origin == "rustsec" else "golang.org/x/net")
    context = (
        {
            "affects": {"arch": [], "os": [], "functions": ["decompress::decompress"]},
            "affected_functions": None,
        }
        if origin == "rustsec"
        else {
            "imports": [
                {
                    "path": package_name + "/http2",
                    "symbols": ["Server.ServeConn"],
                    "goos": ["linux"],
                    "goarch": ["amd64"],
                }
            ]
        }
    )
    database = (
        {"license": "CC0-1.0"}
        if origin == "rustsec"
        else {"url": f"https://pkg.go.dev/vuln/{advisory_id}", "review_status": "REVIEWED"}
    )
    return {
        "id": advisory_id,
        "published": PUBLISHED,
        "modified": MODIFIED,
        "database_specific": database,
        "aliases": ["CVE-2026-12345", "GHSA-2345-6789-cfgh"],
        "references": [
            {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-2345-6789-cfgh"}
        ],
        "affected": [
            {
                "package": {
                    "name": package_name,
                    "ecosystem": "crates.io" if origin == "rustsec" else "Go",
                },
                "ecosystem_specific": context,
                "database_specific": {"informational": None} if origin == "rustsec" else {},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.10.0"}]}
                ],
            }
        ],
    }


def normalize(value, origin="rustsec"):
    return m.normalize_origin_record(
        origin, canonical_json_bytes(value), rustsec_commit=COMMIT if origin == "rustsec" else None
    )


def archive(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as writer:
        for name, body in files.items():
            writer.writestr(name, body)
    return stream.getvalue()


def rust_archive(values):
    return archive(
        {
            f"advisory-db-{COMMIT}/README.md": b"Authoritative OSV export",
            **{
                f"advisory-db-{COMMIT}/crates/{value['id']}.json": canonical_json_bytes(value)
                for value in values
            },
        }
    )


def go_files(values):
    modules = {}
    for value in values:
        for affected in value["affected"]:
            modules.setdefault(affected["package"]["name"], []).append(
                {"id": value["id"], "modified": value["modified"]}
            )
    return {
        "index/db.json": canonical_json_bytes({"modified": MODIFIED}),
        "index/vulns.json": canonical_json_bytes(
            [{key: value[key] for key in ("id", "modified", "aliases")} for value in values]
        ),
        "index/modules.json": canonical_json_bytes(
            [{"path": name, "vulns": vulns} for name, vulns in modules.items()]
        ),
        **{f"ID/{value['id']}.json": canonical_json_bytes(value) for value in values},
    }


def test_direct_rustsec_record_keeps_identity_licenses_ranges_and_bounded_context():
    value = document()
    record = normalize(value)
    assert record.source_id == "gbsec:source:rustsec-advisory-database"
    assert record.source_sha256 == sha256_id(canonical_json_bytes(value))
    assert (
        record.canonical_url
        == f"https://github.com/RustSec/advisory-db/blob/{COMMIT}/crates/RUSTSEC-2026-0328.json"
    )
    assert record.license_expression == "CC0-1.0"
    assert record.catalog_projection["source_type"] == "rustsec"
    assert record.catalog_projection["confidence"] == "confirmed"
    package = record.catalog_projection["packages"][0]
    assert (package["ecosystem"], package["raw_ecosystem"], package["name"]) == (
        "rust",
        "crates.io",
        "decompress",
    )
    assert osv_range_matches("rust", "0.9.0", package["affected_ranges"][0]) is True
    assert osv_range_matches("rust", "0.10.0", package["affected_ranges"][0]) is False
    assert record.context["packages"][0]["ecosystem_specific"]["affects"]["functions"] == [
        "decompress::decompress"
    ]
    assert record.context["reachability"] == "not_assessed"
    assert record.context["raw_body_sha256"] == record.source_sha256


@pytest.mark.parametrize("function_count", [1000, 1001])
def test_rustsec_function_map_matches_public_property_limit(function_count):
    value = document()
    functions = {f"decompress::f{index}": [">=0"] for index in range(function_count)}
    value["affected"][0]["ecosystem_specific"]["affected_functions"] = functions
    if function_count > 1000:
        with pytest.raises(m.OriginAdvisoryError, match="RustSec function context"):
            normalize(value)
    else:
        record = normalize(value)
        assert (
            record.context["packages"][0]["ecosystem_specific"]["affected_functions"] == functions
        )


def test_rustsec_per_record_attribution_is_preserved_or_explicitly_omitted():
    value = document()
    value["database_specific"]["license"] = "CC-BY-4.0"
    record = normalize(value)
    assert "https://github.com/advisories/GHSA-2345-6789-cfgh" in record.attribution_urls
    assert record.context["attribution_complete"] is True
    value["references"] = []
    record = normalize(value)
    assert record.license_expression == "CC-BY-4.0"
    assert record.catalog_projection["packages"] == []
    assert record.catalog_projection["package_omission_counts"] == {
        "rustsec_attribution_incomplete": 1
    }
    assert record.context["attribution_complete"] is False
    value["database_specific"]["license"] = "proprietary"
    with pytest.raises(m.OriginAdvisoryError, match="per-record license"):
        normalize(value)


@pytest.mark.parametrize("reference_count", [998, 999, 1000])
def test_rustsec_attribution_union_matches_public_limit(reference_count):
    value = document()
    value["database_specific"]["license"] = "CC-BY-4.0"
    value["references"] = [
        {"type": "ADVISORY", "url": f"https://github.com/advisories/GHSA-2345-6789-{index:04x}"}
        for index in range(reference_count)
    ]
    if reference_count > 998:
        with pytest.raises(m.OriginAdvisoryError, match="origin attribution count"):
            normalize(value)
    else:
        record = normalize(value)
        assert len(record.attribution_urls) == 1000
        Context.model_validate(record.context)


def test_repeated_rustsec_references_do_not_inflate_attribution_count():
    value = document()
    value["database_specific"]["license"] = "CC-BY-4.0"
    value["references"] *= 1000
    record = normalize(value)
    assert len(record.attribution_urls) == 3
    Context.model_validate(record.context)


@pytest.mark.parametrize("notice", ["unsound", "unmaintained", "notice"])
def test_informational_rustsec_is_context_and_never_a_confirmed_public_vulnerability(notice):
    value = document(name="rutie")
    value["affected"][0]["database_specific"]["informational"] = notice
    record = normalize(value)
    assert record.catalog_projection["packages"] == []
    assert record.catalog_projection["confidence"] == "unverified"
    assert record.catalog_projection["package_omission_counts"] == {
        "rustsec_informational_" + notice: 1
    }
    assert record.context["packages"][0]["informational"] == notice


@pytest.mark.parametrize(
    "review,confidence", [("REVIEWED", "confirmed"), ("UNREVIEWED", "unverified")]
)
def test_go_review_import_symbols_and_platforms_never_claim_reachability(review, confidence):
    value = document("go")
    value["database_specific"]["review_status"] = review
    record = normalize(value, "go")
    assert record.source_id == "gbsec:source:go-vulnerability-database"
    assert record.license_expression == "CC-BY-4.0"
    assert record.catalog_projection["confidence"] == confidence
    context = record.context["packages"][0]["ecosystem_specific"]
    assert context["imports"] == [
        {
            "path": "golang.org/x/net/http2",
            "symbols": ["Server.ServeConn"],
            "goos": ["linux"],
            "goarch": ["amd64"],
        }
    ]
    assert context["reachability"] == "not_assessed"


def test_go_noncanonical_ranges_do_not_become_every_version_matches():
    value = document("go")
    value["affected"][0]["ranges"] = [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
    custom = [{"type": "ECOSYSTEM", "events": [{"introduced": "13.0.0"}, {"fixed": "13.4.13"}]}]
    value["affected"][0]["ecosystem_specific"]["custom_ranges"] = custom
    record = normalize(value, "go")
    assert record.catalog_projection["packages"] == []
    assert record.catalog_projection["package_omission_counts"] == {
        "go_custom_ranges_incomparable": 1
    }
    assert record.context["packages"][0]["ecosystem_specific"]["custom_ranges"] == custom
    assert record.context["packages"][0]["range_comparability"] == "unknown"


@pytest.mark.parametrize("name", ["stdlib", "toolchain"])
def test_go_toolchain_coordinates_are_omitted_explicitly(name):
    record = normalize(document("go", name=name), "go")
    assert record.catalog_projection["packages"] == []
    assert record.catalog_projection["confidence"] == "unverified"
    assert record.catalog_projection["package_omission_counts"] == {
        "unsupported_go_toolchain_coordinate": 1
    }


def test_valid_domain_only_go_module_is_supported():
    assert (
        normalize(document("go", name="aahframe.work"), "go").catalog_projection["packages"][0][
            "name"
        ]
        == "aahframe.work"
    )


def test_git_ancestry_range_is_explicitly_unknown_not_safe_or_inferred_fixed():
    value = document()
    value["affected"][0]["ranges"] = [
        {
            "type": "GIT",
            "repo": "https://github.com/example/crate",
            "events": [{"introduced": "0"}, {"fixed": "a" * 40}],
        }
    ]
    record = normalize(value)
    affected_range = record.catalog_projection["packages"][0]["affected_ranges"][0]
    assert osv_range_matches("rust", "0.9.0", affected_range) is None
    assert record.context["packages"][0]["range_comparability"] == "unknown"
    assert record.catalog_projection["package_omission_counts"] == {"incomparable_range_context": 1}


def test_source_date_precision_and_withdrawal_are_preserved_without_inventing_order():
    value = document()
    value.update(
        published="2026-01-01T12:00:00Z",
        modified="2026-01-01T07:00:00Z",
        withdrawn="2026-01-01T12:00:00Z",
    )
    record = normalize(value)
    assert record.state == "withdrawn"
    assert record.source_published_at.hour == 12 and record.source_modified_at.hour == 7
    assert record.context["source_withdrawn_at"] == value["withdrawn"]
    value = document("go")
    value["withdrawn"] = "2025-12-01T00:00:00Z"
    assert normalize(value, "go").state == "withdrawn"


@pytest.mark.parametrize(
    "body", [b'{"id":"one","id":"two"}', b'{"bad":NaN}', b'{"bad":1e400}', b"[]"]
)
def test_malformed_or_ambiguous_json_refuses_before_normalization(body):
    with pytest.raises(m.OriginAdvisoryError):
        m.normalize_origin_record("rustsec", body, rustsec_commit=COMMIT)


@pytest.mark.parametrize(
    "fault",
    [
        "unknown_origin",
        "wrong_id",
        "wrong_ecosystem",
        "canonical_url",
        "import_path",
        "review_status",
        "context",
        "range",
        "unsafe_reference",
        "naive_time",
    ],
)
def test_untrusted_origin_fields_fail_closed(fault):
    value = document("go")
    origin = "go"
    if fault == "unknown_origin":
        origin = "aggregator"
    elif fault == "wrong_id":
        value["id"] = "GHSA-2345-6789-cfgh"
    elif fault == "wrong_ecosystem":
        value["affected"][0]["package"]["ecosystem"] = "npm"
    elif fault == "canonical_url":
        value["database_specific"]["url"] = "https://pkg.go.dev.evil/vuln/GO-2026-0001"
    elif fault == "import_path":
        value["affected"][0]["ecosystem_specific"]["imports"][0]["path"] = "github.com/other/module"
    elif fault == "review_status":
        value["database_specific"]["review_status"] = "AUTOMATICALLY_SAFE"
    elif fault == "context":
        value["affected"][0]["ecosystem_specific"]["unknown"] = True
    elif fault == "range":
        value["affected"][0]["ranges"][0]["events"] = [{"fixed": "1.0", "introduced": "0"}]
    elif fault == "unsafe_reference":
        value["references"][0]["url"] = "https://secret@github.com/advisories/GHSA-2345-6789-cfgh"
    else:
        value["modified"] = "2026-10-01T12:00:00"
    with pytest.raises(m.OriginAdvisoryError):
        normalize(value, origin)


def test_legacy_http_references_are_unfetched_context_while_canonical_origin_stays_https():
    value = document("go")
    value["references"].append(
        {"type": "WEB", "url": "http://rhn.redhat.com/errata/RHSA-2016-1034.html"}
    )
    record = normalize(value, "go")
    assert record.canonical_url.startswith("https://pkg.go.dev/vuln/")
    assert value["references"][-1]["url"] in record.context["reference_urls"]


def test_rustsec_complete_batch_contains_general_subjects_not_only_study_controls():
    values = [
        document(name=name, identifier=f"RUSTSEC-2026-{index:04d}")
        for index, name in enumerate(
            ("rutie", "decompress", "wasmtime-wasi-http", "other-crate"), 1
        )
    ]
    snapshot = m.parse_rustsec_archive(rust_archive(values), commit=COMMIT, observed_at=NOW)
    assert snapshot.complete is True and len(snapshot.records) == 4
    assert snapshot.checkpoint_token == "git:" + COMMIT
    assert snapshot.transport_sha256.startswith("sha256:") and snapshot.manifest_sha256.startswith(
        "sha256:"
    )
    assert {record.catalog_projection["packages"][0]["name"] for record in snapshot.records} == {
        "rutie",
        "decompress",
        "wasmtime-wasi-http",
        "other-crate",
    }


def test_go_complete_batch_reconciles_all_indexes_including_omitted_toolchain():
    values = [
        document("go"),
        document("go", identifier="GO-2026-0002", name="golang.org/x/text"),
        document("go", identifier="GO-2026-0003", name="stdlib"),
    ]
    body = archive(go_files(values))
    snapshot = m.parse_go_archive(body, observed_at=NOW)
    assert snapshot.complete is True and len(snapshot.records) == 3
    assert snapshot.checkpoint_token == sha256_id(body)
    assert snapshot.omission_counts == {"unsupported_go_toolchain_coordinate": 1}


@pytest.mark.parametrize(
    "fault",
    [
        "missing_record",
        "unindexed_record",
        "duplicate_index",
        "modified",
        "aliases",
        "modules",
        "module_time",
        "unknown_member",
        "missing_index",
    ],
)
def test_go_partial_or_inconsistent_batch_never_returns_a_complete_snapshot(fault):
    files = go_files([document("go")])
    if fault == "missing_record":
        del files["ID/GO-2026-0001.json"]
    elif fault == "unindexed_record":
        other = document("go", identifier="GO-2026-0002")
        files["ID/GO-2026-0002.json"] = canonical_json_bytes(other)
    elif fault in {"duplicate_index", "modified", "aliases"}:
        index = json.loads(files["index/vulns.json"])
        if fault == "duplicate_index":
            index.append(index[0])
        elif fault == "modified":
            index[0]["modified"] = "2026-01-01T00:00:00Z"
        else:
            index[0]["aliases"] = []
        files["index/vulns.json"] = canonical_json_bytes(index)
    elif fault == "modules":
        files["index/modules.json"] = b"[]"
    elif fault == "module_time":
        index = json.loads(files["index/modules.json"])
        index[0]["vulns"][0]["modified"] = PUBLISHED
        files["index/modules.json"] = canonical_json_bytes(index)
    elif fault == "unknown_member":
        files["script.sh"] = b"untrusted"
    else:
        del files["index/db.json"]
    with pytest.raises(m.OriginAdvisoryError):
        m.parse_go_archive(archive(files), observed_at=NOW)


@pytest.mark.parametrize(
    "fault", ["commit", "path_id", "unknown_file", "symlink", "oversize", "traversal", "duplicate"]
)
def test_rustsec_archive_boundaries_are_fail_closed(fault, monkeypatch):
    value = document()
    files = {f"advisory-db-{COMMIT}/crates/{value['id']}.json": canonical_json_bytes(value)}
    if fault == "commit":
        files = {name.replace(COMMIT, "b" * 40): body for name, body in files.items()}
    elif fault == "path_id":
        value["id"] = "RUSTSEC-2026-0002"
        files[next(iter(files))] = canonical_json_bytes(value)
    elif fault == "unknown_file":
        files[f"advisory-db-{COMMIT}/execute.sh"] = b"untrusted"
    elif fault == "oversize":
        monkeypatch.setattr(m, "MAX_RECORD_BYTES", 10)
    elif fault == "traversal":
        files["../outside.json"] = b"{}"
    if fault in {"symlink", "duplicate"}:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as writer:
            info = zipfile.ZipInfo(next(iter(files)))
            if fault == "symlink":
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                writer.writestr(info, "outside")
            else:
                writer.writestr(info, canonical_json_bytes(value))
                with pytest.warns(UserWarning, match="Duplicate name"):
                    writer.writestr(info, canonical_json_bytes(value))
        body = stream.getvalue()
    else:
        body = archive(files)
    with pytest.raises(m.OriginAdvisoryError):
        m.parse_rustsec_archive(body, commit=COMMIT, observed_at=NOW)


def test_snapshot_corrections_withdrawals_restorations_and_removals_remain_distinct():
    first = document()
    before = m.parse_rustsec_archive(rust_archive([first]), commit=COMMIT, observed_at=NOW)
    second = deepcopy(first)
    second["modified"] = "2026-10-02T00:00:00Z"
    second["affected"][0]["ranges"][0]["events"][-1]["fixed"] = "0.11.0"
    after = m.parse_rustsec_archive(rust_archive([second]), commit=COMMIT, observed_at=NOW)
    assert [change.kind for change in m.compare_origin_snapshots(before, after)] == ["modified"]
    second["withdrawn"] = second["modified"]
    withdrawn = m.parse_rustsec_archive(rust_archive([second]), commit=COMMIT, observed_at=NOW)
    assert [change.kind for change in m.compare_origin_snapshots(after, withdrawn)] == ["withdrawn"]
    del second["withdrawn"]
    restored = m.parse_rustsec_archive(rust_archive([second]), commit=COMMIT, observed_at=NOW)
    assert [change.kind for change in m.compare_origin_snapshots(withdrawn, restored)] == [
        "restored"
    ]
    other = document(identifier="RUSTSEC-2026-0002")
    replaced = m.parse_rustsec_archive(rust_archive([other]), commit=COMMIT, observed_at=NOW)
    assert [change.kind for change in m.compare_origin_snapshots(before, replaced)] == [
        "added",
        "removed",
    ]
    assert m.compare_origin_snapshots(before, before) == ()
    with pytest.raises(m.OriginAdvisoryError, match="source time reversed"):
        m.compare_origin_snapshots(after, before)


@pytest.mark.parametrize("origin", ["rustsec", "go"])
def test_complete_http_acquisition_is_allowlisted_pinned_bounded_and_never_retries(origin):
    body = (
        rust_archive([document()]) if origin == "rustsec" else archive(go_files([document("go")]))
    )
    url = (
        f"https://codeload.github.com/RustSec/advisory-db/zip/{COMMIT}"
        if origin == "rustsec"
        else m.GO_ARCHIVE_URL
    )
    requests = []

    def transport(request):
        requests.append(request)
        assert str(request.url) == url
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, content=body, headers={"content-length": str(len(body))})

    with httpx.Client(transport=httpx.MockTransport(transport)) as client:
        snapshot = m.fetch_origin_snapshot(
            origin,
            client=client,
            observed_at=NOW,
            rustsec_commit=COMMIT if origin == "rustsec" else None,
        )
    assert len(requests) == 1 and len(snapshot.records) == 1
    assert snapshot.transport_sha256 == sha256_id(body)


@pytest.mark.parametrize(
    "fault",
    [
        "redirect",
        "429",
        "encoded",
        "declared_size",
        "truncated",
        "invalid_zip",
        "stream_size",
        "deadline",
    ],
)
def test_failed_transport_never_returns_a_partial_snapshot_or_retries(fault, monkeypatch):
    body = archive(go_files([document("go")]))
    calls = []

    def transport(request):
        calls.append(request)
        if fault == "redirect":
            return httpx.Response(302, headers={"location": "https://evil.invalid/vulndb.zip"})
        if fault == "429":
            return httpx.Response(429)
        headers = {"content-length": str(len(body))}
        if fault == "encoded":
            headers["content-encoding"] = "unknown"
        elif fault == "declared_size":
            headers["content-length"] = str(m.MAX_ARCHIVE_BYTES + 1)
        elif fault == "truncated":
            headers["content-length"] = str(len(body) + 1)
        elif fault == "invalid_zip":
            return httpx.Response(200, content=b"not a zip")
        elif fault == "stream_size":
            monkeypatch.setattr(m, "MAX_ARCHIVE_BYTES", 10)
            headers = {}
        elif fault == "deadline":
            monkeypatch.setattr(m.time, "monotonic", lambda: 200)
        return httpx.Response(200, content=body, headers=headers)

    with httpx.Client(transport=httpx.MockTransport(transport)) as client:
        if fault == "deadline":
            values = iter([0, 0, 0])
            monkeypatch.setattr(m.time, "monotonic", lambda: next(values, 200))
        with pytest.raises(m.OriginAdvisoryError):
            m.fetch_origin_snapshot("go", client=client, observed_at=NOW)
    assert len(calls) <= 1


def test_rustsec_ref_resolver_accepts_only_exact_official_export_ref(monkeypatch):
    calls = []

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return SimpleNamespace(returncode=0, stdout=(COMMIT + "\trefs/heads/osv\n").encode())

    monkeypatch.setattr(m.subprocess, "run", run)
    assert m.rustsec_head() == COMMIT
    arguments, kwargs = calls[0]
    assert arguments[-2:] == (m.RUSTSEC_REPOSITORY, "refs/heads/osv")
    assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert kwargs["env"]["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert kwargs["cwd"] == "/" and kwargs["timeout"] == 30


@pytest.mark.parametrize("fault", ["multiple", "wrong_ref", "failed", "timeout"])
def test_rustsec_ambiguous_or_unavailable_export_ref_refuses(fault, monkeypatch):
    def run(*_args, **_kwargs):
        if fault == "timeout":
            raise subprocess.TimeoutExpired("git", 30)
        body = (
            COMMIT + "\trefs/heads/" + ("main" if fault == "wrong_ref" else "osv") + "\n"
        ).encode()
        return SimpleNamespace(
            returncode=1 if fault == "failed" else 0,
            stdout=body * (2 if fault == "multiple" else 1),
        )

    monkeypatch.setattr(m.subprocess, "run", run)
    with pytest.raises(m.OriginAdvisoryError):
        m.rustsec_head()


def test_origin_append_uses_existing_append_only_projection_path_after_caller_governance(
    monkeypatch,
):
    from smithguard import advisory_catalog

    record = normalize(document())
    called = []
    monkeypatch.setattr(
        advisory_catalog,
        "_append_projection",
        lambda session, **kwargs: called.append((session, kwargs)) or "appended",
    )
    assert (
        m.append_origin_advisory(
            "synthetic-session",
            record=record,
            evidence_id="gbsec:evidence:test",
            governance_decision_id="gbsec:governance:test",
            observed_at=NOW,
        )
        == "appended"
    )
    assert called[0][1]["source_id"] == m.RUSTSEC_SOURCE_ID
    assert called[0][1]["projection"] is record.catalog_projection


def excluded_rust_archive(value):
    return archive({f"advisory-db-{COMMIT}/rust/{value['id']}.json": canonical_json_bytes(value)})


@pytest.mark.parametrize("withdrawn", [False, True])
def test_rust_scope_move_retains_same_id_and_explicit_source_state_without_package_claims(
    withdrawn,
):
    value = document()
    if withdrawn:
        value["withdrawn"] = MODIFIED
    before = m.parse_rustsec_archive(rust_archive([value]), commit=COMMIT, observed_at=NOW)
    after = m.parse_rustsec_archive(excluded_rust_archive(value), commit=COMMIT, observed_at=NOW)
    prior, current = before.records[0], after.records[0]
    assert prior.upstream_record_id == current.upstream_record_id
    assert prior.source_sha256 == current.source_sha256
    assert current.raw_body == prior.raw_body
    assert current.state == ("withdrawn" if withdrawn else "active")
    assert current.catalog_projection["packages"] == [] and current.context["packages"] == []
    assert current.context["source_withdrawn_at"] == value.get("withdrawn")
    assert current.license_expression == "CC0-1.0"
    assert current.canonical_url.endswith(f"/rust/{value['id']}.json")
    assert current.canonical_url in current.context["attribution_urls"]
    assert current.catalog_projection["confidence"] == "unverified"
    assert after.omission_counts == {"unsupported_rust_toolchain_record": 1}
    assert before.manifest_sha256 != after.manifest_sha256
    assert [change.kind for change in m.compare_origin_snapshots(before, after)] == ["modified"]


def test_rust_scope_correction_replaces_current_package_projection_preserving_history(database):
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session

    from smithguard.advisory_catalog import catalog_evidence_for_package
    from smithguard.db.models import AdvisoryCatalogRecord, AdvisoryPackageRecord

    value = document()
    before = m.parse_rustsec_archive(rust_archive([value]), commit=COMMIT, observed_at=NOW)
    after = m.parse_rustsec_archive(excluded_rust_archive(value), commit=COMMIT, observed_at=NOW)
    with Session(database.engine) as session, session.begin():
        for snapshot in (before, after):
            result = m.append_origin_advisory(
                session,
                record=snapshot.records[0],
                evidence_id="gbsec:evidence:scope-test",
                governance_decision_id="gbsec:governance:scope-test",
                observed_at=NOW,
            )
            assert result.created
            session.flush()
            families = catalog_evidence_for_package(
                session, ecosystem="rust", name="decompress", version="0.1.0"
            ).families
            assert bool(families) == (snapshot is before)
        assert result.revision == 2
        assert session.scalar(select(func.count()).select_from(AdvisoryPackageRecord)) == 1
        records = session.scalars(
            select(AdvisoryCatalogRecord).order_by(AdvisoryCatalogRecord.revision)
        ).all()
        assert [record.state for record in records] == ["active", "active"]
        assert records[0].source_sha256 != records[1].source_sha256
        assert records[1].package_omission_counts == {"unsupported_rust_toolchain_record": 1}


@pytest.mark.parametrize("scope", ["crates", "rust"])
def test_unchanged_rustsec_body_at_new_commit_changes_provenance_not_snapshot_semantics(scope):
    value = document()
    body = canonical_json_bytes(value)
    before = m.parse_rustsec_archive(
        archive({f"advisory-db-{COMMIT}/{scope}/{value['id']}.json": body}),
        commit=COMMIT,
        observed_at=NOW,
    )
    next_commit = "b" * 40
    after = m.parse_rustsec_archive(
        archive({f"advisory-db-{next_commit}/{scope}/{value['id']}.json": body}),
        commit=next_commit,
        observed_at=NOW,
    )
    assert before.records[0].raw_body == after.records[0].raw_body
    assert before.records[0].canonical_url != after.records[0].canonical_url
    assert before.records[0].context != after.records[0].context
    assert before.manifest_sha256 != after.manifest_sha256
    assert before.checkpoint_token != after.checkpoint_token
    assert m.compare_origin_snapshots(before, after) == ()


@pytest.mark.parametrize("change", ["content", "license", "range", "attribution"])
def test_rustsec_meaningful_changes_at_new_commit_still_append_revision(database, change):
    from sqlalchemy.orm import Session

    from smithguard.db.models import AdvisoryCatalogRecord, AdvisoryPackageRecord

    value = document()
    value["database_specific"]["license"] = "CC-BY-4.0"
    corrected = deepcopy(value)
    if change == "content":
        corrected["details"] = "A corrected public advisory explanation."
    elif change == "license":
        corrected["database_specific"]["license"] = "CC0-1.0"
    elif change == "range":
        corrected["affected"][0]["ranges"][0]["events"][-1]["fixed"] = "0.11.0"
    else:
        corrected["references"][0]["url"] = "https://github.com/advisories/GHSA-mh6f-8j2x-4483"
    records = [
        m.normalize_origin_record("rustsec", canonical_json_bytes(body), rustsec_commit=commit)
        for body, commit in [(value, COMMIT), (corrected, "b" * 40)]
    ]
    with Session(database.engine) as session, session.begin():
        results = [
            m.append_origin_advisory(
                session,
                record=record,
                evidence_id="gbsec:evidence:meaningful-test",
                governance_decision_id="gbsec:governance:meaningful-test",
                observed_at=NOW,
            )
            for record in records
        ]
        assert all(result.created for result in results)
        assert [result.revision for result in results] == [1, 2]
        assert results[0].source_sha256 != results[1].source_sha256
        assert session.query(AdvisoryCatalogRecord).count() == 2
        assert session.query(AdvisoryPackageRecord).count() == 2


def test_private_rustsec_semantic_copy_keeps_stored_urls_and_other_attribution_exact():
    from smithguard.advisory_catalog import _projection_source_hash

    record = normalize(document())
    original = deepcopy(record.catalog_projection)
    extra_url = record.canonical_url.replace(COMMIT, "c" * 40)
    original["origin_context"]["attribution_urls"].append(extra_url)
    semantic = m._origin_semantic_projection(original, source_id=m.RUSTSEC_SOURCE_ID)
    assert semantic["canonical_url"] == record.canonical_url.replace(COMMIT, "osv")
    assert extra_url in semantic["origin_context"]["attribution_urls"]
    assert original["canonical_url"] == record.canonical_url
    assert record.canonical_url in original["origin_context"]["attribution_urls"]
    altered = deepcopy(original)
    altered["origin_context"]["attribution_urls"][-1] = extra_url.replace("c" * 40, "d" * 40)
    assert _projection_source_hash(original, source_id=m.RUSTSEC_SOURCE_ID) != (
        _projection_source_hash(altered, source_id=m.RUSTSEC_SOURCE_ID)
    )


@pytest.mark.parametrize("fault", ["host", "commit", "uppercase_commit", "scope", "id", "path_id"])
def test_rustsec_semantic_normalization_rejects_noncanonical_export_identity(fault):
    projection = deepcopy(normalize(document()).catalog_projection)
    url = projection["canonical_url"]
    if fault == "host":
        url = url.replace("github.com", "example.com")
    elif fault == "commit":
        url = url.replace(COMMIT, "b" * 39)
    elif fault == "uppercase_commit":
        url = url.replace(COMMIT, "B" * 40)
    elif fault == "scope":
        url = url.replace("/crates/", "/other/")
    elif fault == "id":
        projection["upstream_record_id"] = "GO-2026-0001"
    else:
        url = url.replace("RUSTSEC-2026-0328.json", "RUSTSEC-2026-0329.json")
    projection["canonical_url"] = url
    with pytest.raises(m.OriginAdvisoryError, match="semantic"):
        m._origin_semantic_projection(projection, source_id=m.RUSTSEC_SOURCE_ID)


def test_semantic_normalization_requires_trusted_rustsec_source_and_preserves_go_hash():
    from smithguard.advisory_catalog import _projection_source_hash

    rust = normalize(document())
    assert m._origin_semantic_projection(rust.catalog_projection, source_id="other") is (
        rust.catalog_projection
    )
    assert _projection_source_hash(rust.catalog_projection, source_id="other") == (
        _projection_source_hash(rust.catalog_projection)
    )
    go = normalize(document("go"), "go")
    assert m._origin_semantic_projection(go.catalog_projection, source_id=m.GO_SOURCE_ID) is (
        go.catalog_projection
    )
    assert _projection_source_hash(go.catalog_projection, source_id=m.GO_SOURCE_ID) == (
        _projection_source_hash(go.catalog_projection)
    )


@pytest.mark.parametrize(
    "fault",
    [
        "id",
        "license",
        "published",
        "modified",
        "withdrawn",
        "future",
        "ecosystem",
        "package",
        "context",
        "range",
        "events",
        "reference",
        "informational",
    ],
)
def test_excluded_rust_records_are_fully_validated_not_blindly_acknowledged(fault):
    value = document()
    if fault == "id":
        value["id"] = "RUSTSEC-2026-0002"
        files = {f"advisory-db-{COMMIT}/rust/RUSTSEC-2026-0328.json": canonical_json_bytes(value)}
    else:
        if fault == "license":
            value["database_specific"]["license"] = "UNKNOWN"
        elif fault in {"published", "modified", "withdrawn"}:
            value[fault] = "not-a-timestamp"
        elif fault == "future":
            value["modified"] = "2026-10-07T00:00:00Z"
        elif fault == "ecosystem":
            value["affected"][0]["package"]["ecosystem"] = "unknown-toolchain"
        elif fault == "package":
            value["affected"][0]["package"] = None
        elif fault == "context":
            value["affected"][0]["ecosystem_specific"] = {"unsupported_key": True}
        elif fault == "range":
            value["affected"][0]["ranges"][0]["type"] = "UNKNOWN"
        elif fault == "events":
            value["affected"][0]["ranges"][0]["events"] = [{"introduced": "0", "fixed": "1"}]
        elif fault == "reference":
            value["references"][0]["url"] = (
                "https://secret@github.com/advisories/GHSA-2345-6789-cfgh"
            )
        else:
            value["affected"][0]["database_specific"]["informational"] = "unknown"
        files = {f"advisory-db-{COMMIT}/rust/{value['id']}.json": canonical_json_bytes(value)}
    with pytest.raises(m.OriginAdvisoryError):
        m.parse_rustsec_archive(archive(files), commit=COMMIT, observed_at=NOW)


def test_excluded_rust_ccby_requires_attribution_and_scope_does_not_accept_missing_ids():
    value = document()
    value["database_specific"]["license"] = "CC-BY-4.0"
    snapshot = m.parse_rustsec_archive(excluded_rust_archive(value), commit=COMMIT, observed_at=NOW)
    assert snapshot.records[0].context["attribution_complete"] is True
    assert value["references"][0]["url"] in snapshot.records[0].attribution_urls
    before = m.parse_rustsec_archive(rust_archive([document()]), commit=COMMIT, observed_at=NOW)
    other = document(identifier="RUSTSEC-2026-0002", name="rust")
    after = m.parse_rustsec_archive(excluded_rust_archive(other), commit=COMMIT, observed_at=NOW)
    assert before.records[0].upstream_record_id not in {r.upstream_record_id for r in after.records}
    assert "removed" in {change.kind for change in m.compare_origin_snapshots(before, after)}


def test_rust_record_cannot_appear_in_both_scopes_or_go_use_rust_scope():
    value = document()
    files = {
        f"advisory-db-{COMMIT}/{scope}/{value['id']}.json": canonical_json_bytes(value)
        for scope in ("crates", "rust")
    }
    with pytest.raises(m.OriginAdvisoryError, match="duplicate origin advisory ID"):
        m.parse_rustsec_archive(archive(files), commit=COMMIT, observed_at=NOW)
    with pytest.raises(m.OriginAdvisoryError, match="unknown origin record scope"):
        m.normalize_origin_record("go", canonical_json_bytes(document("go")), rustsec_scope="rust")
