"""NEXT-002 reads only bounded local OpenSSF Git objects and remains inactive."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import unicodedata
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

import smithguard.collectors as collectors_module
import smithguard.openssf_catalog as openssf_catalog_module
import smithguard.openssf_git as openssf_git_module
import smithguard.openssf_shadow as openssf_shadow_module
from smithguard.collectors import COLLECTOR_SPECS, OPENSSF_MALICIOUS, CollectorRunner
from smithguard.db.models import (
    AdvisoryCatalogManifestRecord,
    AdvisoryCatalogRecord,
    AdvisoryPackageRecord,
)
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.openssf_git import (
    MAX_BLOB_BYTES,
    OPENSSF_LICENSE_SHA256,
    LocalOpenSSFGitRepository,
    OpenSSFEntryTransport,
    OpenSSFGitError,
    OpenSSFProvisionalIDError,
    _path_entry,
    _safe_package_component,
    canonical_projected_record,
)
from smithguard.runtime import DEFAULT_AUTHORITY_POLICY, RuntimeConfig
from smithguard.source_governance import DEFAULT_GOVERNANCE_POLICY_PATH, SourceGovernancePolicy
from smithguard.source_rights import RightsRegistry

from .governance_fixtures import RIGHTS_REGISTER, active_governance_policy

NOW = datetime(2026, 8, 11, 20, 0, tzinfo=UTC)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONNECTOR_CONTRACT = REPOSITORY_ROOT / "contracts/v1/next-002-openssf-connector-contract.json"
CURRENT_PATH_POLICY = REPOSITORY_ROOT / "contracts/v1/openssf-path-policy-unicode16.json"


def _git(repository: Path, *arguments: str) -> str:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(repository),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": "Synthetic Test",
        "GIT_AUTHOR_EMAIL": "synthetic@example.test",
        "GIT_COMMITTER_NAME": "Synthetic Test",
        "GIT_COMMITTER_EMAIL": "synthetic@example.test",
        "GIT_AUTHOR_DATE": "2026-08-11T20:00:00Z",
        "GIT_COMMITTER_DATE": "2026-08-11T20:00:00Z",
    }
    completed = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        capture_output=True,
        text=True,
        encoding="ascii",
        env=environment,
    )
    return completed.stdout.strip()


def _record(
    advisory_id: str,
    *,
    ecosystem: str,
    name: str,
    withdrawn: bool = False,
    aliases: list[str] | None = None,
) -> dict:
    document = {
        "schema_version": "1.6.0",
        "id": advisory_id,
        "published": "2026-08-11T18:00:00Z",
        "modified": "2026-08-11T19:00:00Z",
        "aliases": aliases or [],
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": name},
                "versions": ["1.0.0"],
            }
        ],
        "references": [{"type": "REPORT", "url": "https://example.test/report"}],
        "database_specific": {"malicious-packages-origins": [{"source": "synthetic"}]},
        "summary": "This source prose must be excluded from the accepted projection.",
    }
    if withdrawn:
        document["withdrawn"] = "2026-08-11T19:30:00Z"
    return document


def _write_record(repository: Path, relative: str, document: dict) -> None:
    destination = repository / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, sort_keys=True), encoding="ascii")


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", "--all")
    _git(repository, "commit", "--quiet", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def _example(examples: list[dict[str, Any]], definition: str) -> dict[str, Any]:
    return deepcopy(next(item["value"] for item in examples if item["definition"] == definition))


def _repository(tmp_path: Path) -> tuple[Path, str, str]:
    repository = tmp_path / "openssf"
    repository.mkdir()
    _git(repository, "init", "--quiet", "--initial-branch=main")
    license_body = b"Synthetic Apache License fixture\n"
    (repository / "LICENSE").write_bytes(license_body)
    (repository / "osv/malicious/README.md").parent.mkdir(parents=True)
    (repository / "osv/malicious/README.md").write_text("synthetic\n", encoding="ascii")
    _write_record(
        repository,
        "osv/malicious/npm/example/MAL-2026-100.json",
        _record(
            "MAL-2026-100",
            ecosystem="npm",
            name="example",
            aliases=["GHSA-2345-6789-cfgh", "CVE-2026-1000", "OSV-2026-100"],
        ),
    )
    _write_record(
        repository,
        "osv/malicious/pypi/example-project/MAL-2026-101.json",
        _record("MAL-2026-101", ecosystem="PyPI", name="example-project"),
    )
    _write_record(
        repository,
        "osv/malicious/nuget/Example/MAL-2026-102.json",
        _record("MAL-2026-102", ecosystem="NuGet", name="Example"),
    )
    commit = _commit(repository, "initial synthetic tree")
    license_sha256 = "sha256:" + hashlib.sha256(license_body).hexdigest()
    return repository, commit, license_sha256


def test_snapshot_is_bounded_paged_and_projects_only_reviewed_fields(tmp_path: Path) -> None:
    repository, commit, license_sha256 = _repository(tmp_path)
    reader = LocalOpenSSFGitRepository(repository)
    snapshot = reader.inspect(commit, expected_license_sha256=license_sha256)

    assert snapshot.commit == commit
    assert snapshot.active_count == 2
    assert snapshot.withdrawn_count == 0
    assert snapshot.unsupported_counts == (("nuget", 1),)
    assert snapshot.ignored_nonrecord_count == 1
    assert [entry.advisory_id for entry in snapshot.entries] == [
        "MAL-2026-100",
        "MAL-2026-101",
    ]
    complete_snapshot = reader.inspect_complete(
        commit,
        expected_license_sha256=license_sha256,
    )
    assert complete_snapshot.active_count == 3
    assert complete_snapshot.unsupported_counts == ()
    assert [entry.advisory_id for entry in complete_snapshot.entries] == [
        "MAL-2026-100",
        "MAL-2026-102",
        "MAL-2026-101",
    ]

    first_page = reader.page(snapshot, limit=1)
    second_page = reader.page(snapshot, after_path=first_page.next_after_path, limit=1)
    replay = reader.page(snapshot, limit=1)
    assert first_page.has_more and first_page.next_after_path is not None
    assert not second_page.has_more and second_page.next_after_path is None
    assert replay == first_page
    assert not set(first_page.entries) & set(second_page.entries)

    source_record = reader.read_record(first_page.entries[0])
    projected = json.loads(canonical_projected_record(source_record))
    assert projected["id"] == "MAL-2026-100"
    assert "summary" not in projected and "schema_version" not in projected
    assert source_record.source_published_at == datetime(2026, 8, 11, 18, 0, tzinfo=UTC)

    bodies = reader.read_blobs(snapshot.entries)
    records = tuple(
        reader.parse_record(entry, body)
        for entry, body in zip(snapshot.entries, bodies, strict=True)
    )
    assert [record.entry.advisory_id for record in records] == [
        "MAL-2026-100",
        "MAL-2026-101",
    ]


def test_full_catalog_runner_has_no_ecosystem_allowlist_and_repeats_cleanly(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commit, license_sha256 = _repository(tmp_path)
    evidence_root = tmp_path / "evidence"
    state_root = tmp_path / "catalog-state"
    state_root.mkdir()
    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=evidence_root,
        rights_register_path=RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY_PATH,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
    )
    monkeypatch.setattr(
        openssf_catalog_module,
        "load_runtime_config",
        lambda **_kwargs: config,
    )
    monkeypatch.setattr(openssf_catalog_module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(openssf_catalog_module, "_state_root", lambda: state_root)
    current_commit = [commit]
    monkeypatch.setattr(
        openssf_catalog_module,
        "sync_official_repository",
        lambda _paths: (repository, current_commit[0]),
    )
    monkeypatch.setattr(openssf_catalog_module, "OPENSSF_LICENSE_SHA256", license_sha256)
    monkeypatch.setattr(openssf_catalog_module, "BOOTSTRAP_COMMIT", commit)
    monkeypatch.setattr(openssf_catalog_module, "MAX_PAGE_SIZE", 2)
    monkeypatch.setattr(openssf_catalog_module, "CATALOG_VALIDATION_PAGE_SIZE", 2)
    monkeypatch.setattr(
        collectors_module,
        "load_authority_policy",
        lambda: pytest.fail("the packaged collector must receive the configured policy"),
    )

    first = openssf_catalog_module.collect_openssf_catalog()
    (repository / "README.md").write_text("unrelated repository change\n", encoding="ascii")
    current_commit[0] = _commit(repository, "advance without changing an advisory blob")
    second = openssf_catalog_module.collect_openssf_catalog()

    assert first["record_count"] == 3
    assert first["package_entry_count"] == 3
    assert first["unsupported_ecosystem_count"] == 0
    assert first["created_revision_count"] == 3
    assert second["created_revision_count"] == 0
    assert second["parsed_record_count"] == 0
    assert second["physical_page_count"] == 0
    with Session(database.engine) as session:
        assert session.query(AdvisoryCatalogRecord).count() == 3
        assert session.query(AdvisoryPackageRecord).count() == 3
        assert set(session.scalars(select(AdvisoryPackageRecord.ecosystem))) == {
            "npm",
            "nuget",
            "pypi",
        }
        manifests = (
            session.query(AdvisoryCatalogManifestRecord)
            .filter_by(state="complete")
            .order_by(AdvisoryCatalogManifestRecord.sequence)
        )
        assert [(row.segment, row.record_count, row.package_entry_count) for row in manifests] == [
            ("openssf-malicious", 3, 3),
            ("openssf-withdrawn", 0, 0),
            ("openssf-malicious", 3, 3),
            ("openssf-withdrawn", 0, 0),
        ]


def test_full_catalog_validation_page_uses_bounded_backward_distinct_on() -> None:
    statement = str(
        openssf_catalog_module._openssf_catalog_validation_page().compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )

    assert "SELECT DISTINCT ON (" in statement
    assert "advisory_catalog_records.source_id" in statement
    assert "advisory_catalog_records.upstream_record_id" in statement
    assert "row_number" not in statement.lower()
    assert "advisory_catalog_records.revision DESC" in statement
    assert "advisory_catalog_records.upstream_record_id DESC" in statement
    assert "advisory_catalog_records.source_id DESC" in statement
    assert f"LIMIT {openssf_catalog_module.CATALOG_VALIDATION_PAGE_SIZE}" in statement


def test_full_catalog_validation_page_correlates_counts_and_uses_keyset_boundary() -> None:
    statement = str(
        openssf_catalog_module._openssf_catalog_validation_page("MAL-2026-123").compile(
            dialect=postgresql.dialect()
        )
    )

    assert "advisory_package_records.source_id = anon_1.source_id" in statement
    assert "advisory_package_records.upstream_record_id = anon_1.upstream_record_id" in statement
    assert "advisory_package_records.revision = anon_1.revision" in statement
    assert "advisory_package_records.catalog_event_id =" not in statement
    assert "advisory_catalog_records.upstream_record_id <" in statement
    assert "OFFSET" not in statement


@pytest.mark.parametrize(
    ("failure_kind", "message"),
    (
        ("missing", "header is invalid"),
        ("size", "identity or size differs"),
        ("truncated", "body is incomplete"),
        ("trailing", "returned trailing bytes"),
    ),
)
def test_blob_batch_rejects_missing_mismatched_or_incomplete_objects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
    message: str,
) -> None:
    repository, commit, license_sha256 = _repository(tmp_path)
    reader = LocalOpenSSFGitRepository(repository)
    entry = reader.inspect(commit, expected_license_sha256=license_sha256).entries[0]
    body = _git(repository, "cat-file", "blob", entry.blob_oid).encode("ascii")
    if failure_kind == "missing":
        output = f"{entry.blob_oid} missing\n".encode("ascii")
    elif failure_kind == "size":
        output = f"{entry.blob_oid} blob {entry.byte_count + 1}\n".encode("ascii")
    elif failure_kind == "truncated":
        output = f"{entry.blob_oid} blob {entry.byte_count}\n".encode("ascii") + body
    else:
        output = f"{entry.blob_oid} blob {entry.byte_count}\n".encode("ascii") + body + b"\nextra"

    class Process:
        returncode = 0

        def communicate(self, _request: bytes, *, timeout: int) -> tuple[bytes, bytes]:
            assert timeout == openssf_git_module.GIT_TIMEOUT_SECONDS
            return output, b""

    monkeypatch.setattr(reader, "_resolve_commit", lambda _commit: commit)
    monkeypatch.setattr(openssf_git_module.subprocess, "Popen", lambda *_a, **_k: Process())

    with pytest.raises(OpenSSFGitError, match=message):
        reader.read_blobs((entry,))


def test_snapshot_preserves_official_leading_hyphen_and_unicode_package_paths(
    tmp_path: Path,
) -> None:
    repository, _first_commit, license_sha256 = _repository(tmp_path)
    unicode_name = "malware-\u0430lpha-e\u0301"
    _write_record(
        repository,
        "osv/malicious/npm/--hiljson/MAL-2026-110.json",
        _record("MAL-2026-110", ecosystem="npm", name="--hiljson"),
    )
    _write_record(
        repository,
        f"osv/malicious/npm/{unicode_name}/MAL-2026-111.json",
        _record("MAL-2026-111", ecosystem="npm", name=unicode_name),
    )
    commit = _commit(repository, "add exact UTF-8 package paths")
    reader = LocalOpenSSFGitRepository(repository)
    snapshot = reader.inspect(commit, expected_license_sha256=license_sha256)
    hyphen_entry = next(item for item in snapshot.entries if item.advisory_id == "MAL-2026-110")
    unicode_entry = next(item for item in snapshot.entries if item.advisory_id == "MAL-2026-111")

    assert hyphen_entry.package_path == "--hiljson"
    assert unicode_entry.package_path == unicode_name
    assert "%D0%B0" in unicode_entry.canonical_url
    assert "%CC%81" in unicode_entry.canonical_url
    assert reader.read_record(hyphen_entry).projected["id"] == "MAL-2026-110"
    assert reader.read_record(unicode_entry).projected["id"] == "MAL-2026-111"

    replay = reader.page(snapshot, after_path=unicode_entry.path, limit=1)
    expected_index = [item.path for item in snapshot.entries].index(unicode_entry.path) + 1
    assert replay.entries == snapshot.entries[expected_index : expected_index + 1]
    with pytest.raises(OpenSSFGitError, match="cursor"):
        reader.page(snapshot, after_path=unicode_entry.path + "-changed", limit=1)
    with pytest.raises(OpenSSFGitError, match="cursor"):
        reader.page(snapshot, after_path="x" * 1_001, limit=1)
    with pytest.raises(OpenSSFGitError, match="cursor"):
        reader.page(snapshot, after_path="\ud800", limit=1)

    unicode_path = repository / unicode_entry.path
    unicode_path.unlink()
    later_commit = _commit(repository, "remove prior snapshot cursor")
    later_snapshot = reader.inspect(later_commit, expected_license_sha256=license_sha256)
    with pytest.raises(OpenSSFGitError, match="cursor"):
        reader.page(later_snapshot, after_path=unicode_entry.path, limit=1)


def test_tree_conventions_do_not_lowercase_or_rewrite_stored_package_identity(
    tmp_path: Path,
) -> None:
    repository, _first_commit, license_sha256 = _repository(tmp_path)
    _write_record(
        repository,
        "osv/malicious/npm/adultjs/MAL-2026-113.json",
        _record("MAL-2026-113", ecosystem="npm", name="AdultJS"),
    )
    _write_record(
        repository,
        "osv/malicious/pypi/amino-fix/MAL-2026-114.json",
        _record("MAL-2026-114", ecosystem="PyPI", name="amino.fix"),
    )
    commit = _commit(repository, "add official tree naming conventions")
    reader = LocalOpenSSFGitRepository(repository)
    snapshot = reader.inspect(commit, expected_license_sha256=license_sha256)
    records = {
        entry.advisory_id: reader.read_record(entry)
        for entry in snapshot.entries
        if entry.advisory_id in {"MAL-2026-113", "MAL-2026-114"}
    }

    assert records["MAL-2026-113"].projected["affected"][0]["package"]["name"] == "AdultJS"
    assert records["MAL-2026-114"].projected["affected"][0]["package"]["name"] == "amino.fix"
    assert records["MAL-2026-113"].entry.package_path == "adultjs"
    assert records["MAL-2026-114"].entry.package_path == "amino-fix"


@pytest.mark.parametrize(
    ("tree_name", "record_name", "ecosystem"),
    (
        ("\U000105c0-package", "\U000105c0-package", "npm"),
        ("package-\U000113b8", "package-\U000113b8", "npm"),
        ("\U00010d40-package", "\U00010d40-package", "npm"),
        ("\U00010d70-package", "\U00010d50-package", "npm"),
        ("\u0264-package", "\ua7cb-package", "npm"),
        ("\U00010d70-package", "\U00010d50_package", "PyPI"),
    ),
)
def test_unicode16_snapshot_preserves_new_characters_and_original_record_identity(
    tmp_path: Path, tree_name: str, record_name: str, ecosystem: str
) -> None:
    repository, _first, license_sha256 = _repository(tmp_path)
    relative = f"osv/malicious/{ecosystem.lower()}/{tree_name}/MAL-2026-116.json"
    original = _record("MAL-2026-116", ecosystem=ecosystem, name=record_name)
    _write_record(repository, relative, original)
    commit = _commit(repository, "Unicode 16 public fixture")
    reader = LocalOpenSSFGitRepository(repository)
    snapshot = reader.inspect(commit, expected_license_sha256=license_sha256)
    entry = next(item for item in snapshot.entries if item.advisory_id == "MAL-2026-116")
    record = reader.read_record(entry)
    assert entry.package_path == tree_name
    assert entry.path == relative
    assert record.projected["affected"] == original["affected"]
    assert json.loads(canonical_projected_record(record))["affected"] == original["affected"]


@pytest.mark.parametrize("value", ("\U000113b8leading", "package-\U0001fae9", "bad-\ud800"))
def test_unicode16_does_not_admit_leading_marks_symbols_or_invalid_utf8(value: str) -> None:
    assert not _safe_package_component(value)


@pytest.mark.parametrize("version", ("15.0.0", "17.0.0", "unknown"))
def test_unreviewed_unicode_runtime_is_refused_before_git_inspection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    repository, commit, _license = _repository(tmp_path)
    reader = LocalOpenSSFGitRepository(repository)
    monkeypatch.setattr(unicodedata, "unidata_version", version)
    monkeypatch.setattr(reader, "_resolve_commit", lambda _commit: pytest.fail("Git read occurred"))
    with pytest.raises(OpenSSFGitError, match="Unicode data version"):
        reader.inspect(commit)


def test_snapshot_shares_validated_labels_without_changing_record_identity(tmp_path: Path) -> None:
    repository, _, license_sha256 = _repository(tmp_path)
    for number, tree, ecosystem in (
        (120, "malicious", "NPM"),
        (121, "withdrawn", "npm"),
    ):
        _write_record(
            repository,
            f"osv/{tree}/{ecosystem}/Example/MAL-2026-{number}.json",
            _record(
                f"MAL-2026-{number}",
                ecosystem="npm",
                name="Example",
                withdrawn=tree == "withdrawn",
            ),
        )
    commit = _commit(repository, "repeated labels across states and case")
    snapshot = LocalOpenSSFGitRepository(repository).inspect_complete(
        commit, expected_license_sha256=license_sha256
    )
    entries = {entry.advisory_id: entry for entry in snapshot.entries}
    original = entries["MAL-2026-100"]
    active = entries["MAL-2026-120"]
    withdrawn = entries["MAL-2026-121"]
    assert active.ecosystem is original.ecosystem is withdrawn.ecosystem
    assert active.source_tree is original.source_tree
    assert active.path == "osv/malicious/NPM/Example/MAL-2026-120.json"
    assert active.package_path == withdrawn.package_path == "Example"
    assert active.source_state == "active"
    assert withdrawn.source_tree == withdrawn.source_state == "withdrawn"


def test_label_cache_is_bounded_and_never_changes_admitted_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(openssf_git_module, "MAX_CACHED_ECOSYSTEM_LABELS", 2)
    labels: dict[str, str] = {}
    common = {
        "commit": "0" * 40,
        "mode": "100644",
        "object_type": "blob",
        "blob_oid": "1" * 40,
        "byte_count": 1,
    }
    for number, ecosystem in enumerate(("NPM", "pypi", "arbitrary", "NPM", "arbitrary")):
        path = f"osv/malicious/{ecosystem}/Example/MAL-2026-{200 + number}.json"
        assert _path_entry(**common, path=path, ecosystem_labels=labels) == _path_entry(
            **common, path=path
        )
        assert len(labels) <= 2
    assert labels == {"npm": "npm", "pypi": "pypi"}
    with pytest.raises(OpenSSFGitError, match="tree shape"):
        _path_entry(
            **common,
            path="osv/malicious/bad label/Example/MAL-2026-210.json",
            ecosystem_labels=labels,
        )
    assert labels == {"npm": "npm", "pypi": "pypi"}


def test_package_component_boundaries_reject_traversal_overflow_and_leading_mark() -> None:
    assert not _safe_package_component(".")
    assert not _safe_package_component("..")
    assert not _safe_package_component("\u0301leading-mark")
    assert not _safe_package_component("invalid-\ud800")
    assert not _safe_package_component("a" * 301)
    assert len("\U00010400" * 226) < 300
    assert len(("\U00010400" * 226).encode("utf-8")) > 900
    assert not _safe_package_component("\U00010400" * 226)

    component = "\U00010400" * 100
    with pytest.raises(OpenSSFGitError, match="package path"):
        _path_entry(
            commit="0" * 40,
            mode="100644",
            object_type="blob",
            blob_oid="0" * 40,
            byte_count=1,
            path=f"osv/malicious/npm/{component}/{component}/{component}/MAL-2026-112.json",
        )


def test_only_recognized_provisional_advisory_paths_have_a_distinct_error() -> None:
    common = {
        "commit": "0" * 40,
        "mode": "100644",
        "object_type": "blob",
        "blob_oid": "1" * 40,
        "byte_count": 1,
    }

    with pytest.raises(OpenSSFProvisionalIDError, match="recognized provisional"):
        _path_entry(
            **common,
            path=("osv/malicious/npm/example/MAL-0000-amazon-inspector-0123456789abcdef.json"),
        )

    with pytest.raises(OpenSSFGitError) as malformed:
        _path_entry(
            **common,
            path="osv/malicious/npm/example/MAL-0000-!unreviewed.json",
        )
    assert type(malformed.value) is OpenSSFGitError

    with pytest.raises(OpenSSFGitError, match="package path") as unsafe_package:
        _path_entry(
            **common,
            path=(f"osv/malicious/npm/{'a' * 250}/{'b' * 250}/MAL-0000-amazon-inspector-a.json"),
        )
    assert type(unsafe_package.value) is OpenSSFGitError

    with pytest.raises(OpenSSFProvisionalIDError, match="recognized provisional"):
        _path_entry(**common, path="osv/malicious/npm/example/MAL-0000-123.json")


def test_entry_transport_is_exact_commit_pinned_and_has_no_network_default(
    tmp_path: Path,
) -> None:
    repository, commit, license_sha256 = _repository(tmp_path)
    reader = LocalOpenSSFGitRepository(repository)
    entry = reader.inspect(commit, expected_license_sha256=license_sha256).entries[0]
    record = reader.read_record(entry)
    transport = OpenSSFEntryTransport(record=record, retrieved_at=NOW)
    response = transport(
        COLLECTOR_SPECS[OPENSSF_MALICIOUS],
        None,
    )
    assert f"/blob/{commit}/osv/malicious/npm/example/" in response.canonical_url
    assert entry.blob_oid not in response.canonical_url
    assert response.source_record_id == "MAL-2026-100"
    assert response.checkpoint_token == f"{commit}:{entry.blob_oid}"
    assert response.body == record.raw_body

    with pytest.raises(OpenSSFGitError, match="checkpoint"):
        transport(
            COLLECTOR_SPECS[OPENSSF_MALICIOUS],
            "unexpected",
        )


def test_forward_diff_records_modification_withdrawal_addition_and_removal(
    tmp_path: Path,
) -> None:
    repository, first_commit, license_sha256 = _repository(tmp_path)
    reader = LocalOpenSSFGitRepository(repository)
    before = reader.inspect(first_commit, expected_license_sha256=license_sha256)

    _write_record(
        repository,
        "osv/malicious/npm/example/MAL-2026-100.json",
        _record(
            "MAL-2026-100",
            ecosystem="npm",
            name="example",
            aliases=["CVE-2026-1001"],
        ),
    )
    old_path = repository / "osv/malicious/pypi/example-project/MAL-2026-101.json"
    old_path.unlink()
    _write_record(
        repository,
        "osv/withdrawn/pypi/example-project/MAL-2026-101.json",
        _record(
            "MAL-2026-101",
            ecosystem="PyPI",
            name="example-project",
            withdrawn=True,
        ),
    )
    _write_record(
        repository,
        "osv/malicious/npm/added/MAL-2026-103.json",
        _record("MAL-2026-103", ecosystem="npm", name="added"),
    )
    second_commit = _commit(repository, "update synthetic tree")
    after = reader.inspect(second_commit, expected_license_sha256=license_sha256)
    changes = reader.diff(before, after).changes
    assert {(change.advisory_id, change.kind) for change in changes} == {
        ("MAL-2026-100", "modified"),
        ("MAL-2026-101", "withdrawn"),
        ("MAL-2026-103", "added"),
    }
    with pytest.raises(OpenSSFGitError, match="change limit"):
        reader.diff(before, after, maximum_changes=2)

    _git(repository, "checkout", "--quiet", "-b", "divergent", first_commit)
    _write_record(
        repository,
        "osv/malicious/npm/divergent/MAL-2026-104.json",
        _record("MAL-2026-104", ecosystem="npm", name="divergent"),
    )
    divergent_commit = _commit(repository, "divergent synthetic tree")
    divergent = reader.inspect(divergent_commit, expected_license_sha256=license_sha256)
    with pytest.raises(OpenSSFGitError, match="not a forward"):
        reader.diff(after, divergent)


def test_reader_rejects_license_path_withdrawal_and_blob_shape_drift(tmp_path: Path) -> None:
    repository, commit, license_sha256 = _repository(tmp_path)
    reader = LocalOpenSSFGitRepository(repository)
    snapshot = reader.inspect(commit, expected_license_sha256=license_sha256)

    with pytest.raises(OpenSSFGitError, match="license"):
        reader.inspect(commit, expected_license_sha256=OPENSSF_LICENSE_SHA256)

    mismatched = repository / "osv/malicious/npm/example/MAL-2026-100.json"
    mismatched.write_text(
        json.dumps(_record("MAL-2026-999", ecosystem="npm", name="example")),
        encoding="ascii",
    )
    mismatch_commit = _commit(repository, "identity mismatch")
    mismatch_snapshot = reader.inspect(mismatch_commit, expected_license_sha256=license_sha256)
    mismatch_entry = next(
        entry for entry in mismatch_snapshot.entries if entry.advisory_id == "MAL-2026-100"
    )
    with pytest.raises(OpenSSFGitError, match="identities differ"):
        reader.read_record(mismatch_entry)

    mismatched.write_text("{" + '"id":"MAL-2026-100",' * 2 + '"affected":[]}', encoding="ascii")
    duplicate_commit = _commit(repository, "duplicate key")
    duplicate_snapshot = reader.inspect(duplicate_commit, expected_license_sha256=license_sha256)
    duplicate_entry = next(
        entry for entry in duplicate_snapshot.entries if entry.advisory_id == "MAL-2026-100"
    )
    with pytest.raises(OpenSSFGitError, match="duplicate JSON key"):
        reader.read_record(duplicate_entry)

    oversized = repository / "osv/malicious/npm/oversized/MAL-2026-105.json"
    oversized.parent.mkdir(parents=True)
    oversized.write_bytes(b"{" + b" " * MAX_BLOB_BYTES + b"}")
    oversized_commit = _commit(repository, "oversized blob")
    with pytest.raises(OpenSSFGitError, match="size limit"):
        reader.inspect(oversized_commit, expected_license_sha256=license_sha256)

    assert snapshot.entries


def test_reader_rejects_promisor_repo_malformed_unsupported_path_and_bad_withdrawal_time(
    tmp_path: Path,
) -> None:
    repository, _first_commit, license_sha256 = _repository(tmp_path)
    _git(repository, "config", "remote.origin.promisor", "true")
    with pytest.raises(OpenSSFGitError, match="complete local objects"):
        LocalOpenSSFGitRepository(repository)
    _git(repository, "config", "--unset", "remote.origin.promisor")

    malformed = repository / "osv/malicious/nuget/$unsafe/MAL-2026-106.json"
    malformed.parent.mkdir(parents=True)
    malformed.write_text(
        json.dumps(_record("MAL-2026-106", ecosystem="NuGet", name="$unsafe")),
        encoding="ascii",
    )
    malformed_commit = _commit(repository, "malformed unsupported path")
    reader = LocalOpenSSFGitRepository(repository)
    with pytest.raises(OpenSSFGitError, match="reviewed tree shape"):
        reader.inspect(malformed_commit, expected_license_sha256=license_sha256)

    unsafe_unicode = repository / "osv/malicious/nuget/unsafe\u200dname/MAL-2026-107.json"
    unsafe_unicode.parent.mkdir(parents=True)
    unsafe_unicode.write_text(
        json.dumps(_record("MAL-2026-107", ecosystem="NuGet", name="unsafe\u200dname")),
        encoding="ascii",
    )
    unsafe_unicode_commit = _commit(repository, "unsafe Unicode path")
    with pytest.raises(OpenSSFGitError, match="reviewed tree shape"):
        reader.inspect(unsafe_unicode_commit, expected_license_sha256=license_sha256)

    withdrawal_root = tmp_path / "withdrawal"
    withdrawal_root.mkdir()
    withdrawal_repository, _withdrawal_commit, withdrawal_license = _repository(withdrawal_root)
    withdrawal_reader = LocalOpenSSFGitRepository(withdrawal_repository)
    active = withdrawal_repository / "osv/malicious/npm/example/MAL-2026-100.json"
    active.unlink()
    invalid_withdrawal = _record(
        "MAL-2026-100",
        ecosystem="npm",
        name="example",
        withdrawn=True,
    )
    invalid_withdrawal["withdrawn"] = "not-a-time"
    _write_record(
        withdrawal_repository,
        "osv/withdrawn/npm/example/MAL-2026-100.json",
        invalid_withdrawal,
    )
    withdrawn_commit = _commit(withdrawal_repository, "invalid withdrawal time")
    withdrawn_snapshot = withdrawal_reader.inspect(
        withdrawn_commit,
        expected_license_sha256=withdrawal_license,
    )
    withdrawn_entry = next(
        entry for entry in withdrawn_snapshot.entries if entry.advisory_id == "MAL-2026-100"
    )
    with pytest.raises(OpenSSFGitError, match="withdrawn time is invalid"):
        withdrawal_reader.read_record(withdrawn_entry)


def test_direct_record_projects_original_origin_and_typed_aliases(
    database,
    tmp_path: Path,
    contract_examples: list[dict[str, Any]],
) -> None:
    repository, commit, license_sha256 = _repository(tmp_path)
    reader = LocalOpenSSFGitRepository(repository)
    entry = reader.inspect(commit, expected_license_sha256=license_sha256).entries[0]
    record = reader.read_record(entry)
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    runner = CollectorRunner(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        transport=OpenSSFEntryTransport(record=record, retrieved_at=NOW),
        governance_policy=active_governance_policy(OPENSSF_MALICIOUS),
        clock=lambda: NOW,
    )
    with Session(database.engine) as session, session.begin():
        outcome = runner.run_public(session, source_id=OPENSSF_MALICIOUS)
        assert outcome.outcome is not None and outcome.outcome.raw_evidence_id is not None


def test_tracked_policy_activates_full_catalog_and_preserves_legacy_contract(
    tmp_path: Path,
) -> None:
    registry = RightsRegistry.from_path(RIGHTS_REGISTER)
    runner = CollectorRunner(
        registry=registry,
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "unused-evidence"),
    )
    assert runner._transport is None
    policy = SourceGovernancePolicy.from_path(
        DEFAULT_GOVERNANCE_POLICY_PATH,
        registry=registry,
    )
    authorization = policy.authorize_collection(
        connector_id="gbsec:connector:openssf-git-v1",
        source_id=OPENSSF_MALICIOUS,
        acquisition_method="git",
        operating_mode="historical",
        canonical_url="https://github.com/ossf/malicious-packages",
        source_record_id="preflight:openssf",
        authorized_at=NOW,
    )
    assert authorization.source_id == OPENSSF_MALICIOUS
    contract = json.loads(CONNECTOR_CONTRACT.read_text(encoding="ascii"))
    current_policy = json.loads(CURRENT_PATH_POLICY.read_text(encoding="ascii"))
    assert current_policy["supersedes"] == {
        "contract_path": str(CONNECTOR_CONTRACT.relative_to(REPOSITORY_ROOT)),
        "contract_sha256": hashlib.sha256(CONNECTOR_CONTRACT.read_bytes()).hexdigest(),
        "unicode_data_version": contract["path_policy"]["unicode_data_version"],
    }
    assert current_policy["supersedes"]["unicode_data_version"] == "15.0.0"
    assert current_policy["historical_observations_reinterpreted"] is False
    assert current_policy["stored_package_identity"] == "preserve_exact_original_record_value"
    assert current_policy["limits"] == contract["limits"]
    assert current_policy["unchanged_boundaries"] == {
        key: contract["path_policy"][key] for key in current_policy["unchanged_boundaries"]
    }
    assert unicodedata.unidata_version == current_policy["unicode_data_version"]
    assert contract["activation"] == {
        "governance_policy_enabled": False,
        "network_fetch_implemented": True,
        "scheduled_collection_authorized": False,
        "production_backfill_authorized": False,
        "public_output_authorized": False,
        "deployment_authorized": False,
    }
    assert contract["shadow_runtime"] == {
        "entry_point": "smithguard-openssf-shadow",
        "service": "smithguard-openssf-shadow.service",
        "timer": "smithguard-openssf-shadow.timer",
        "identity": "smithguard-openssf",
        "state_root": "/var/lib/smithguard/openssf-shadow",
        "kill_switch": "SMITHGUARD_OPENSSF_SHADOW_ENABLED",
        "kill_switch_default": "0",
        "database_access": False,
        "public_effect": False,
        "full_validation_interval_hours": int(
            openssf_shadow_module.FULL_VALIDATION_INTERVAL.total_seconds() // 3600
        ),
        "health_max_age_hours": int(openssf_shadow_module.HEALTH_MAX_AGE.total_seconds() // 3600),
        "production_timer_enabled": False,
    }


def test_blob_batch_rejects_cumulative_bytes_before_starting_git(tmp_path, monkeypatch):
    from dataclasses import replace

    from smithguard.openssf_git import MAX_RAW_BATCH_BYTES

    repository, commit, license_digest = _repository(tmp_path)
    reader = LocalOpenSSFGitRepository(repository)
    entries = reader.inspect_complete(commit, expected_license_sha256=license_digest).entries
    oversized_batch = [replace(entry, byte_count=MAX_BLOB_BYTES) for entry in entries]
    assert sum(entry.byte_count for entry in oversized_batch) > MAX_RAW_BATCH_BYTES
    monkeypatch.setattr(
        reader, "_resolve_commit", lambda *_a: pytest.fail("started Git before raw byte validation")
    )
    with pytest.raises(OpenSSFGitError, match="raw byte budget"):
        reader.read_blobs(oversized_batch)


def test_shadow_validation_splits_large_count_page_by_bytes():
    from types import SimpleNamespace

    from smithguard.openssf_git import MAX_RAW_BATCH_BYTES
    from smithguard.openssf_shadow import _validate_entries

    entries = [SimpleNamespace(byte_count=3 * 1024 * 1024) for _ in range(4)]
    batches = []

    class Reader:
        def read_blobs(self, page):
            assert sum(entry.byte_count for entry in page) <= MAX_RAW_BATCH_BYTES
            batches.append(len(page))
            return [b"{}"] * len(page)

        def parse_record(self, entry, body):
            pass

    assert _validate_entries(Reader(), entries) == (4, 0, ())
    assert batches == [2, 2]


@pytest.mark.parametrize("body", [b"", b"a", b"a\0", b"\0a\0\0b", b"a\0b\0"])
def test_streamed_tree_records_match_split_without_copying_full_tree(body):
    from smithguard.openssf_git import _nul_records

    assert list(_nul_records(body)) == body.split(b"\0")


def test_runtime_unicode_data_matches_the_reviewed_version():
    """A Python upgrade that changes Unicode data fails the gate, not production ingestion."""
    import unicodedata

    from smithguard import openssf_git

    assert unicodedata.unidata_version == openssf_git.REVIEWED_UNICODE_DATA_VERSION


def test_repository_maintenance_repacks_synchronously_and_keeps_history(tmp_path):
    """gc --auto runs to completion in the foreground and never drops needed commits."""
    import subprocess

    from smithguard.openssf_shadow import maintain_repository

    def git(*arguments, cwd=None):
        return subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@t", *arguments],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    origin = tmp_path / "origin"
    git("init", "-q", "-b", "main", str(origin))
    for index in range(4):
        (origin / f"file-{index}.txt").write_text(f"{index}\n")
        git("add", ".", cwd=origin)
        git("commit", "-q", "-m", f"commit {index}", cwd=origin)
    mirror = tmp_path / "mirror"
    git("clone", "-q", "--depth=2", "--no-checkout", f"file://{origin}", str(mirror))
    for index in range(4, 7):
        (origin / f"file-{index}.txt").write_text(f"{index}\n")
        git("add", ".", cwd=origin)
        git("commit", "-q", "-m", f"commit {index}", cwd=origin)
        git("-c", "fetch.unpackLimit=1", "fetch", "-q", "--depth=2", "origin", cwd=mirror)
    pack_root = mirror / ".git/objects/pack"

    def packs() -> int:
        """Reachable-object packs; Git keeps unreachable history in a cruft pack
        (with a .mtimes file) until gc.pruneExpire removes it."""
        return sum(
            1 for pack in pack_root.glob("*.pack") if not pack.with_suffix(".mtimes").exists()
        )

    before = packs()
    previous = git("rev-parse", "origin/main~1", cwd=mirror)
    assert before > 1
    assert maintain_repository(mirror, auto_pack_limit=1) is True
    assert packs() == 1  # finished in the foreground, not detached
    assert git("cat-file", "-t", previous, cwd=mirror) == "commit"
    assert maintain_repository(tmp_path / "missing") is False


def test_maintenance_never_leaves_git_running(monkeypatch, tmp_path):
    """An exhausted budget starts nothing; any failure after launch kills and reaps the
    process group before the caller releases its lock."""
    import os
    import signal

    import pytest

    from smithguard import openssf_shadow
    from smithguard.openssf_budget import CatalogStopped

    started: list[object] = []

    def no_budget(_seconds):
        raise CatalogStopped("catalog time budget is exhausted")

    monkeypatch.setattr(openssf_shadow, "bounded_timeout", no_budget)
    monkeypatch.setattr(openssf_shadow.subprocess, "Popen", lambda *a, **k: started.append(1))
    with pytest.raises(CatalogStopped):
        openssf_shadow.maintain_repository(tmp_path)
    assert started == []

    class Process:
        pid = 4242
        waits = 0

        def wait(self, timeout=None):
            Process.waits += 1
            if Process.waits == 1:
                raise CatalogStopped("stop requested")
            return 0

    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(openssf_shadow, "bounded_timeout", lambda seconds: seconds)
    monkeypatch.setattr(openssf_shadow.subprocess, "Popen", lambda *a, **k: Process())
    monkeypatch.setattr(os, "killpg", lambda pid, sig: killed.append((pid, sig)))
    monkeypatch.setattr(openssf_shadow, "_group_alive", lambda _pgid: False)
    with pytest.raises(CatalogStopped):
        openssf_shadow.maintain_repository(tmp_path)
    assert killed == [(4242, signal.SIGTERM)]  # graceful stop was enough here
    assert Process.waits == 2  # reaped after the stop


def test_stopped_maintenance_escalates_and_clears_git_locks(monkeypatch, tmp_path):
    """A stuck Git gets SIGKILL after the grace period, and a leftover shallow.lock is
    removed so the next shallow fetch still works."""
    import os
    import signal
    import subprocess

    import pytest

    from smithguard import openssf_shadow
    from smithguard.openssf_budget import CatalogStopped

    def git(*arguments, cwd=None):
        return subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@t", *arguments],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        )

    origin = tmp_path / "origin"
    git("init", "-q", "-b", "main", str(origin))
    (origin / "a.txt").write_text("a\n")
    git("add", ".", cwd=origin)
    git("commit", "-q", "-m", "a", cwd=origin)
    mirror = tmp_path / "mirror"
    git("clone", "-q", "--depth=1", "--no-checkout", f"file://{origin}", str(mirror))
    (mirror / ".git" / "shallow.lock").write_text("left by an interrupted gc\n")

    class StuckProcess:
        pid = 5151
        waits = 0

        def wait(self, timeout=None):
            StuckProcess.waits += 1
            if StuckProcess.waits == 1:
                raise CatalogStopped("stop requested")
            if StuckProcess.waits == 2:
                raise subprocess.TimeoutExpired("git", timeout)
            return -9

    signals: list[int] = []
    monkeypatch.setattr(openssf_shadow, "bounded_timeout", lambda seconds: seconds)
    monkeypatch.setattr(openssf_shadow.subprocess, "Popen", lambda *a, **k: StuckProcess())
    monkeypatch.setattr(os, "killpg", lambda pid, sig: signals.append(sig))
    monkeypatch.setattr(openssf_shadow, "_group_alive", lambda _pgid: signal.SIGKILL not in signals)
    StuckProcess.poll = lambda self: -9
    with pytest.raises(CatalogStopped):
        openssf_shadow.maintain_repository(mirror)
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert not (mirror / ".git" / "shallow.lock").exists()
    monkeypatch.undo()  # restore the real process launcher for the follow-up fetch
    (origin / "b.txt").write_text("b\n")
    git("add", ".", cwd=origin)
    git("commit", "-q", "-m", "b", cwd=origin)
    git("fetch", "-q", "--depth=1", "origin", cwd=mirror)


def test_group_stop_waits_for_children_that_ignore_sigterm(tmp_path):
    """A leader that exits on SIGTERM while a child keeps running is not "stopped":
    the child is SIGKILLed and the group is empty before locks may be touched."""
    import subprocess
    import time

    from smithguard.openssf_shadow import _group_alive, _stop_process_group

    marker = tmp_path / "child-started"
    script = f"(trap '' TERM; touch {marker}; exec sleep 60) & trap 'exit 0' TERM; wait"
    process = subprocess.Popen(["bash", "-c", script], start_new_session=True)
    deadline = time.monotonic() + 10
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert marker.exists()
    assert _stop_process_group(process) is True
    assert not _group_alive(process.pid)
    assert process.poll() is not None
