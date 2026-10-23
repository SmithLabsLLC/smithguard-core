"""Bounded complete RustSec/Go origin snapshots and conservative OSV projection.

Only registry crates and public Go modules are projected. Symbol/platform context
describes upstream assertions, never application reachability. Source governance,
transactional persistence and activation remain the caller's responsibility.
"""

from __future__ import annotations

import io
import re
import stat
import subprocess
import time
import zipfile
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit

import httpx

from smithguard.identifiers import (
    canonical_json_bytes,
    parse_timestamp,
    require_aware_utc,
    sha256_id,
    strict_json_loads,
)
from smithguard.normalization import NormalizationRejected, normalize_artifact_identity
from smithguard.range_evaluation import osv_intervals

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from smithguard.advisory_catalog import CatalogAppendResult

Origin = Literal["rustsec", "go"]
RUSTSEC_SOURCE_ID = "gbsec:source:rustsec-advisory-database"
GO_SOURCE_ID = "gbsec:source:go-vulnerability-database"
SOURCE_IDS = {"rustsec": RUSTSEC_SOURCE_ID, "go": GO_SOURCE_ID}
RUSTSEC_REPOSITORY = "https://github.com/RustSec/advisory-db"
GO_ARCHIVE_URL = "https://vuln.go.dev/vulndb.zip"
COMMIT = re.compile(r"[0-9a-f]{40}")
IDS = {
    "rustsec": re.compile(r"RUSTSEC-[12][0-9]{3}-[0-9]{4}"),
    "go": re.compile(r"GO-[12][0-9]{3}-[0-9]{4,8}"),
}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,159}")
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_CONTEXT_BYTES = 128 * 1024
ACQUISITION_SECONDS = 120


class OriginAdvisoryError(ValueError):
    """An origin batch is incomplete, ambiguous, malformed or outside its budget."""


@dataclass(frozen=True, slots=True)
class OriginAdvisoryRecord:
    origin: Origin
    source_id: str
    upstream_record_id: str
    canonical_url: str
    raw_body: bytes
    source_sha256: str
    license_expression: str
    attribution_urls: tuple[str, ...]
    source_published_at: datetime
    source_modified_at: datetime
    state: Literal["active", "withdrawn"]
    catalog_projection: Mapping[str, Any]
    context: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class OriginSnapshot:
    origin: Origin
    source_id: str
    checkpoint_token: str
    acquisition_url: str
    transport_sha256: str
    manifest_sha256: str
    observed_at: datetime
    source_modified_at: datetime
    records: tuple[OriginAdvisoryRecord, ...]
    omission_counts: Mapping[str, int]
    complete: bool = True


@dataclass(frozen=True, slots=True)
class OriginChange:
    kind: Literal["added", "modified", "withdrawn", "restored", "removed"]
    upstream_record_id: str
    before: OriginAdvisoryRecord | None
    after: OriginAdvisoryRecord | None


def _require(value: Any, reason: str) -> None:
    if not value:
        raise OriginAdvisoryError(reason)


def _text(value: Any, *, maximum: int = 300) -> str:
    _require(
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and value.isascii()
        and all(32 <= ord(c) < 127 for c in value),
        "invalid bounded string",
    )
    return value


def _strings(value: Any, *, maximum_items: int = 100, maximum_length: int = 300) -> list[str]:
    _require(isinstance(value, list) and len(value) <= maximum_items, "invalid bounded string list")
    return sorted({_text(item, maximum=maximum_length) for item in value})


def _https(value: Any, *, reference: bool = False) -> str:
    value = _text(value, maximum=2048)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise OriginAdvisoryError("invalid source reference URL") from error
    _require(
        parsed.scheme in ({"http", "https"} if reference else {"https"})
        and parsed.hostname
        and parsed.username is None
        and parsed.password is None
        and port is None
        and not any(c in value for c in '\\<>" '),
        "invalid source reference URL",
    )
    return value


def _json(body: bytes, *, index: bool = False) -> Any:
    _require(
        isinstance(body, bytes)
        and 0 < len(body) <= (MAX_EXPANDED_BYTES if index else MAX_RECORD_BYTES),
        "origin JSON size limit",
    )
    try:
        value = strict_json_loads(body, max_nodes=250_000 if index else 30_000, max_depth=20)
        canonical_json_bytes(value)  # Also reject overflowing floating-point literals.
        return value
    except (ValueError, RecursionError, UnicodeError) as error:
        raise OriginAdvisoryError("invalid origin JSON") from error


def _time(value: Any) -> datetime:
    try:
        return parse_timestamp(value)
    except ValueError as error:
        raise OriginAdvisoryError("invalid origin source timestamp") from error


def _package_context(origin: Origin, affected: Mapping[str, Any], name: str) -> dict[str, Any]:
    specific = affected.get("ecosystem_specific", {})
    _require(isinstance(specific, dict), "invalid origin ecosystem context")
    if origin == "go":
        _require(set(specific) <= {"imports", "custom_ranges"}, "unknown Go ecosystem context")
        imports = specific.get("imports", [])
        _require(isinstance(imports, list) and len(imports) <= 1000, "invalid Go imports")
        result = []
        for item in imports:
            _require(
                isinstance(item, dict) and set(item) <= {"path", "symbols", "goos", "goarch"},
                "invalid Go import context",
            )
            path = _text(item.get("path"))
            _require(path == name or path.startswith(name + "/"), "Go import is outside its module")
            result.append(
                {
                    "path": path,
                    "symbols": _strings(item.get("symbols", []), maximum_items=1000),
                    "goos": _strings(item.get("goos", [])),
                    "goarch": _strings(item.get("goarch", [])),
                }
            )
        custom = specific.get("custom_ranges", [])
        _require(isinstance(custom, list) and len(custom) <= 1000, "invalid Go custom ranges")
        for affected_range in custom:
            _require(
                isinstance(affected_range, dict)
                and affected_range.get("type") == "ECOSYSTEM"
                and set(affected_range) == {"type", "events"},
                "invalid Go custom range shape",
            )
            events = affected_range["events"]
            _require(
                isinstance(events, list) and 0 < len(events) <= 1000,
                "invalid Go custom range events",
            )
            for event in events:
                _require(
                    isinstance(event, dict) and len(event) == 1, "invalid Go custom range event"
                )
                key, boundary = next(iter(event.items()))
                _require(
                    key in {"introduced", "fixed", "last_affected", "limit"},
                    "invalid Go custom range boundary",
                )
                _text(boundary, maximum=200)
        return {"imports": result, "custom_ranges": custom, "reachability": "not_assessed"}
    _require(
        set(specific) <= {"affects", "affected_functions"}, "unknown RustSec ecosystem context"
    )
    affects = specific.get("affects", {})
    _require(
        isinstance(affects, dict) and set(affects) <= {"arch", "os", "functions"},
        "invalid RustSec platform context",
    )
    functions = specific.get("affected_functions")
    _require(
        functions is None or isinstance(functions, dict) and len(functions) <= 1000,
        "invalid RustSec function context",
    )
    function_ranges = {}
    for function, selectors in (functions or {}).items():
        function_ranges[_text(function)] = _strings(selectors, maximum_items=1000)
    return {
        "affects": {
            key: _strings(affects.get(key, []), maximum_items=1000)
            for key in ("arch", "os", "functions")
        },
        "affected_functions": function_ranges,
        "reachability": "not_assessed",
    }


def _validate_excluded_rust_package(item: Mapping[str, Any]) -> None:
    """Validate source semantics without inventing a public toolchain coordinate."""
    package = item["package"]
    _require(package.get("ecosystem") == "crates.io", "unexpected origin ecosystem")
    name = _text(package.get("name"))
    _package_context("rustsec", item, name)
    specific = item.get("database_specific", {})
    _require(isinstance(specific, dict), "invalid affected database context")
    informational = specific.get("informational")
    _require(
        informational is None
        or isinstance(informational, str)
        and informational in {"unsound", "unmaintained", "notice"},
        "unknown RustSec notice class",
    )
    versions = _strings(item.get("versions", []), maximum_items=10_000, maximum_length=200)
    ranges = item.get("ranges", [])
    _require(
        isinstance(ranges, list) and len(ranges) <= 1000 and (ranges or versions),
        "invalid origin range list",
    )
    for value in ranges:
        _require(
            isinstance(value, dict)
            and isinstance(value.get("type"), str)
            and value["type"] in {"SEMVER", "ECOSYSTEM", "GIT"},
            "unknown origin range type",
        )
        if value["type"] == "GIT":
            _https(value.get("repo"))
        events = value.get("events")
        _require(
            isinstance(events, list) and 0 < len(events) <= 1000,
            "invalid origin range events",
        )
        for event in events:
            _require(isinstance(event, dict) and len(event) == 1, "invalid origin range event")
            key, boundary = next(iter(event.items()))
            _require(
                key in {"introduced", "fixed", "last_affected", "limit"},
                "unknown origin range event",
            )
            _text(boundary, maximum=200)


def normalize_origin_record(
    origin: Origin,
    body: bytes,
    *,
    rustsec_commit: str | None = None,
    rustsec_scope: Literal["crates", "rust"] = "crates",
) -> OriginAdvisoryRecord:
    """Validate an origin's minimized semantics while retaining its exact raw identity."""
    _require(origin in SOURCE_IDS, "unknown advisory origin")
    _require(
        isinstance(rustsec_scope, str)
        and rustsec_scope in {"crates", "rust"}
        and (origin == "rustsec" or rustsec_scope == "crates"),
        "unknown origin record scope",
    )
    document = _json(body)
    _require(isinstance(document, dict), "origin record is not an object")
    upstream_id = _text(document.get("id"), maximum=160)
    _require(IDS[origin].fullmatch(upstream_id), "origin advisory ID is invalid")
    if origin == "rustsec":
        _require(
            isinstance(rustsec_commit, str) and COMMIT.fullmatch(rustsec_commit),
            "RustSec commit is invalid",
        )
        canonical_url = (
            f"{RUSTSEC_REPOSITORY}/blob/{rustsec_commit}/{rustsec_scope}/{upstream_id}.json"
        )
    else:
        canonical_url = f"https://pkg.go.dev/vuln/{upstream_id}"
    published, modified = _time(document.get("published")), _time(document.get("modified"))
    withdrawn = document.get("withdrawn")
    if withdrawn is not None:
        _time(withdrawn)
    state = "withdrawn" if withdrawn is not None else "active"
    aliases = _strings(document.get("aliases", []), maximum_length=160)
    _require(all(IDENTIFIER.fullmatch(value) for value in aliases), "invalid origin alias")
    references = document.get("references", [])
    _require(isinstance(references, list) and len(references) <= 1000, "invalid origin references")
    reference_urls = []
    for reference in references:
        _require(
            isinstance(reference, dict) and isinstance(reference.get("type"), str),
            "invalid origin reference",
        )
        reference_urls.append(_https(reference.get("url"), reference=True))
    database = document.get("database_specific", {})
    _require(isinstance(database, dict), "invalid origin database context")
    attribution_complete = True
    if origin == "rustsec":
        license_expression = database.get("license")
        _require(
            isinstance(license_expression, str) and license_expression in {"CC0-1.0", "CC-BY-4.0"},
            "unapproved RustSec per-record license",
        )
        attribution = [canonical_url, f"https://rustsec.org/advisories/{upstream_id}.html"]
        if license_expression == "CC-BY-4.0":
            originals = [
                url
                for url in reference_urls
                if re.fullmatch(
                    r"https://github\.com/(?:advisories|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/security/advisories)/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}",
                    url,
                )
            ]
            attribution_complete = bool(originals)
            attribution.extend(originals)
        review = "REVIEWED"
    else:
        license_expression = "CC-BY-4.0"
        review = database.get("review_status", "REVIEWED")
        _require(
            isinstance(review, str) and review in {"REVIEWED", "UNREVIEWED"},
            "unknown Go advisory review status",
        )
        expected_url = database.get("url", canonical_url)
        _require(expected_url == canonical_url, "Go canonical report URL changed")
        attribution = [canonical_url, f"https://vuln.go.dev/ID/{upstream_id}.json"]
    _require(len(set(attribution)) <= 1000, "invalid origin attribution count")
    affected = document.get("affected")
    _require(
        isinstance(affected, list) and 0 < len(affected) <= 1000, "invalid origin affected list"
    )
    packages, contexts, omissions = [], [], Counter()
    if rustsec_scope == "rust":
        omissions["unsupported_rust_toolchain_record"] = 1
    for index, item in enumerate(affected):
        _require(
            isinstance(item, dict) and isinstance(item.get("package"), dict),
            "invalid origin affected package",
        )
        if rustsec_scope == "rust":
            _validate_excluded_rust_package(item)
            continue
        package = item["package"]
        raw_ecosystem = package.get("ecosystem")
        expected_ecosystem = "crates.io" if origin == "rustsec" else "Go"
        _require(raw_ecosystem == expected_ecosystem, "unexpected origin ecosystem")
        name = _text(package.get("name"))
        if origin == "go" and name in {"stdlib", "toolchain"}:
            omissions["unsupported_go_toolchain_coordinate"] += 1
            continue
        ecosystem = "rust" if origin == "rustsec" else "go"
        try:
            normalized = normalize_artifact_identity(
                {"ecosystem": ecosystem, "name": name, "version": "0", "digest": None}
            )
        except NormalizationRejected as error:
            raise OriginAdvisoryError(
                "origin package is outside the public coordinate contract"
            ) from error
        _require(normalized["name"] == name, "origin package identity changed")
        if origin == "go":
            _require(
                "." in name.split("/")[0],
                "Go subject is not a public module coordinate",
            )
        specific = item.get("database_specific", {})
        _require(isinstance(specific, dict), "invalid affected database context")
        informational = specific.get("informational") if origin == "rustsec" else None
        _require(
            informational is None
            or isinstance(informational, str)
            and informational in {"unsound", "unmaintained", "notice"},
            "unknown RustSec notice class",
        )
        context = {
            "index": index,
            "ecosystem": ecosystem,
            "name": name,
            "informational": informational,
            "ecosystem_specific": _package_context(origin, item, name),
        }
        contexts.append(context)
        if not attribution_complete:
            omissions["rustsec_attribution_incomplete"] += 1
            continue
        if informational is not None:
            omissions["rustsec_informational_" + informational] += 1
            continue
        if origin == "go" and context["ecosystem_specific"]["custom_ranges"]:
            # These source tags deliberately differ from canonical Go versions.
            # Do not turn the accompanying conservative introduced:0 into a
            # definitive package-version match by silently dropping this context.
            context["range_comparability"] = "unknown"
            omissions["go_custom_ranges_incomparable"] += 1
            continue
        versions = _strings(item.get("versions", []), maximum_items=10_000, maximum_length=200)
        ranges = item.get("ranges", [])
        _require(
            isinstance(ranges, list) and len(ranges) <= 1000 and (ranges or versions),
            "invalid origin range list",
        )
        projected_ranges = []
        comparable = True
        for value in ranges:
            _require(
                isinstance(value, dict)
                and isinstance(value.get("type"), str)
                and value["type"] in {"SEMVER", "ECOSYSTEM", "GIT"},
                "unknown origin range type",
            )
            events = value.get("events")
            _require(
                isinstance(events, list) and 0 < len(events) <= 1000, "invalid origin range events"
            )
            copied_events = []
            for event in events:
                _require(isinstance(event, dict) and len(event) == 1, "invalid origin range event")
                key, boundary = next(iter(event.items()))
                _require(
                    key in {"introduced", "fixed", "last_affected", "limit"},
                    "unknown origin range event",
                )
                copied_events.append({key: _text(boundary, maximum=200)})
            projected_range = {"type": value["type"], "events": copied_events}
            if value["type"] == "GIT":
                projected_range["repo"] = _https(value.get("repo"))
            if osv_intervals(ecosystem, projected_range) is None:
                comparable = False
            projected_ranges.append(projected_range)
        context["range_comparability"] = "comparable" if comparable else "unknown"
        if not comparable:
            omissions["incomparable_range_context"] += 1
        packages.append(
            {
                "entry_key": sha256_id(
                    canonical_json_bytes([index, ecosystem, name, versions, projected_ranges])
                ),
                "ecosystem": ecosystem,
                "raw_ecosystem": raw_ecosystem,
                "name": name,
                "exact_versions": versions,
                "affected_ranges": projected_ranges,
            }
        )
    context = {
        "raw_body_sha256": sha256_id(body),
        "review_status": review,
        "license_expression": license_expression,
        "attribution_complete": attribution_complete,
        "source_withdrawn_at": withdrawn,
        "attribution_urls": sorted(set(attribution)),
        "packages": contexts,
        "reference_urls": sorted(set(reference_urls)),
        "reachability": "not_assessed",
    }
    _require(
        len(canonical_json_bytes(context)) <= MAX_CONTEXT_BYTES,
        "origin context exceeds byte budget",
    )
    projection = {
        "upstream_record_id": upstream_id,
        "source_type": origin,
        "claim_type": "vulnerable",
        "confidence": "confirmed" if review == "REVIEWED" and packages else "unverified",
        "state": state,
        "cwe_ids": [],
        "aliases": aliases,
        "package_omission_counts": dict(sorted(omissions.items())),
        "canonical_url": canonical_url,
        "source_published_at": published,
        "source_updated_at": modified,
        "packages": packages,
        "origin_context": context,
    }
    return OriginAdvisoryRecord(
        origin,
        SOURCE_IDS[origin],
        upstream_id,
        canonical_url,
        body,
        sha256_id(body),
        license_expression,
        tuple(sorted(set(attribution))),
        published,
        modified,
        state,
        projection,
        context,
    )


def _archive(body: bytes) -> dict[str, bytes]:
    _require(
        isinstance(body, bytes) and 0 < len(body) <= MAX_ARCHIVE_BYTES, "origin archive byte budget"
    )
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            members = archive.infolist()
            _require(0 < len(members) <= MAX_ARCHIVE_MEMBERS, "origin archive member budget")
            _require(
                len({entry.filename for entry in members}) == len(members),
                "duplicate origin archive member",
            )
            total, paths, result = 0, set(), {}
            for entry in members:
                path = entry.filename
                _require(
                    path.isascii()
                    and 0 < len(path) <= 500
                    and not path.startswith("/")
                    and "\\" not in path
                    and all(part not in {"", ".", ".."} for part in path.rstrip("/").split("/")),
                    "unsafe origin archive path",
                )
                _require(path not in paths, "duplicate origin archive member")
                paths.add(path)
                mode = entry.external_attr >> 16
                _require(
                    not stat.S_ISLNK(mode) and not entry.flag_bits & 1,
                    "unsafe origin archive member",
                )
                if entry.is_dir():
                    _require(entry.file_size == 0, "origin directory contains bytes")
                    continue
                limit = MAX_EXPANDED_BYTES if path.startswith("index/") else MAX_RECORD_BYTES
                _require(0 <= entry.file_size <= limit, "origin member byte budget")
                total += entry.file_size
                _require(total <= MAX_EXPANDED_BYTES, "origin expanded archive byte budget")
                result[path] = archive.read(entry)
            return result
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as error:
        raise OriginAdvisoryError("invalid complete origin archive") from error


def _snapshot(
    origin: Origin,
    body: bytes,
    records: list[OriginAdvisoryRecord],
    *,
    checkpoint: str,
    url: str,
    observed_at: datetime,
    modified: datetime,
    extra_omissions: Mapping[str, int] | None = None,
) -> OriginSnapshot:
    _require(records, "origin snapshot contains no records")
    records.sort(key=lambda record: record.upstream_record_id)
    _require(
        len({record.upstream_record_id for record in records}) == len(records),
        "duplicate origin advisory ID",
    )
    omissions = Counter(extra_omissions or {})
    for record in records:
        omissions.update(record.catalog_projection["package_omission_counts"])
    manifest = {
        "origin": origin,
        "checkpoint": checkpoint,
        "records": [
            [
                record.upstream_record_id,
                record.source_sha256,
                record.state,
                record.canonical_url,
                sha256_id(canonical_json_bytes(record.context)),
                dict(record.catalog_projection["package_omission_counts"]),
            ]
            for record in records
        ],
        "omission_counts": dict(sorted(omissions.items())),
    }
    return OriginSnapshot(
        origin,
        SOURCE_IDS[origin],
        checkpoint,
        url,
        sha256_id(body),
        sha256_id(canonical_json_bytes(manifest)),
        require_aware_utc(observed_at),
        modified,
        tuple(records),
        dict(sorted(omissions.items())),
    )


def parse_rustsec_archive(body: bytes, *, commit: str, observed_at: datetime) -> OriginSnapshot:
    _require(isinstance(commit, str) and COMMIT.fullmatch(commit), "RustSec commit is invalid")
    prefix = f"advisory-db-{commit}/"
    records = []
    for path, raw in sorted(_archive(body).items()):
        _require(path.startswith(prefix), "RustSec archive commit root changed")
        relative = path[len(prefix) :]
        if relative == "README.md":
            continue
        match = re.fullmatch(r"(crates|rust)/(RUSTSEC-[12][0-9]{3}-[0-9]{4})\.json", relative)
        _require(match, "unknown RustSec archive member")
        # Represent explicit scope corrections under the same origin ID. A rust/
        # record has no eligible package claim but is not an invented withdrawal.
        record = normalize_origin_record(
            "rustsec", raw, rustsec_commit=commit, rustsec_scope=match[1]
        )
        _require(record.upstream_record_id == match[2], "RustSec path identity changed")
        if match[1] == "rust":
            observed = require_aware_utc(observed_at)
            _require(
                record.source_published_at <= observed
                and record.source_modified_at <= observed
                and (
                    record.context["source_withdrawn_at"] is None
                    or _time(record.context["source_withdrawn_at"]) <= observed
                ),
                "RustSec excluded record source time is in the future",
            )
        records.append(record)
    return _snapshot(
        "rustsec",
        body,
        records,
        checkpoint="git:" + commit,
        url=f"https://codeload.github.com/RustSec/advisory-db/zip/{commit}",
        observed_at=observed_at,
        modified=max(
            (record.source_modified_at for record in records),
            default=require_aware_utc(observed_at),
        ),
    )


def parse_go_archive(body: bytes, *, observed_at: datetime) -> OriginSnapshot:
    files = _archive(body)
    _require(
        {"index/db.json", "index/vulns.json", "index/modules.json"} <= files.keys(),
        "Go archive omits canonical indexes",
    )
    db = _json(files["index/db.json"], index=True)
    _require(isinstance(db, dict), "invalid Go database index")
    modified = _time(db.get("modified"))
    index = _json(files["index/vulns.json"], index=True)
    _require(
        isinstance(index, list) and 0 < len(index) <= MAX_ARCHIVE_MEMBERS,
        "invalid Go vulnerability index",
    )
    indexed = {}
    for item in index:
        _require(isinstance(item, dict), "invalid Go vulnerability index entry")
        advisory_id = _text(item.get("id"), maximum=160)
        _require(
            IDS["go"].fullmatch(advisory_id) and advisory_id not in indexed,
            "duplicate or invalid Go index ID",
        )
        indexed[advisory_id] = item
    records, module_memberships = [], set()
    for path, raw in sorted(files.items()):
        if path in {"index/db.json", "index/vulns.json", "index/modules.json"}:
            continue
        match = re.fullmatch(r"ID/(GO-[12][0-9]{3}-[0-9]{4,8})\.json", path)
        _require(
            match and match[1] in indexed, "Go archive contains an unindexed or unknown member"
        )
        record = normalize_origin_record("go", raw)
        _require(record.upstream_record_id == match[1], "Go path identity changed")
        indexed_item = indexed[record.upstream_record_id]
        _require(
            _time(indexed_item.get("modified")) == record.source_modified_at,
            "Go index modification differs from record",
        )
        _require(
            _strings(indexed_item.get("aliases", []), maximum_length=160)
            == record.catalog_projection["aliases"],
            "Go index aliases differ from record",
        )
        for affected in _json(raw)["affected"]:
            module_memberships.add((affected["package"]["name"], record.upstream_record_id))
        records.append(record)
    _require(
        set(indexed) == {record.upstream_record_id for record in records},
        "Go archive is missing indexed records",
    )
    modules = _json(files["index/modules.json"], index=True)
    _require(
        isinstance(modules, list) and len(modules) <= MAX_ARCHIVE_MEMBERS, "invalid Go module index"
    )
    indexed_memberships, seen_modules = set(), set()
    for item in modules:
        _require(isinstance(item, dict), "invalid Go module index entry")
        name = _text(item.get("path"))
        _require(name not in seen_modules, "duplicate Go module index path")
        seen_modules.add(name)
        vulns = item.get("vulns")
        _require(
            isinstance(vulns, list) and len(vulns) <= MAX_ARCHIVE_MEMBERS,
            "invalid Go module vulnerability list",
        )
        for value in vulns:
            _require(
                isinstance(value, dict)
                and isinstance(value.get("id"), str)
                and value["id"] in indexed,
                "invalid Go module vulnerability reference",
            )
            _require(
                _time(value.get("modified")) == _time(indexed[value["id"]].get("modified")),
                "Go module index modification changed",
            )
            indexed_memberships.add((name, value["id"]))
    _require(
        module_memberships == indexed_memberships, "Go module index is incomplete or inconsistent"
    )
    return _snapshot(
        "go",
        body,
        records,
        checkpoint="sha256:" + sha256_id(body).removeprefix("sha256:"),
        url=GO_ARCHIVE_URL,
        observed_at=observed_at,
        modified=modified,
    )


def _origin_semantic_projection(
    projection: Mapping[str, Any], *, source_id: str
) -> Mapping[str, Any]:
    """A private semantic copy; exact export permalinks remain stored unchanged.

    Only the trusted RustSec source's generated export commit is acquisition
    identity. Keep its repository, scope and advisory ID, and every other field
    and attribution URL. GitHub, OpenSSF and Go projections are untouched.
    """
    if source_id != RUSTSEC_SOURCE_ID or projection.get("source_type") != "rustsec":
        return projection
    upstream_id = projection.get("upstream_record_id")
    canonical_url = projection.get("canonical_url")
    _require(
        isinstance(upstream_id, str) and IDS["rustsec"].fullmatch(upstream_id),
        "RustSec semantic advisory ID is invalid",
    )
    match = (
        re.fullmatch(
            re.escape(RUSTSEC_REPOSITORY)
            + r"/blob/[0-9a-f]{40}/(crates|rust)/(RUSTSEC-[12][0-9]{3}-[0-9]{4})\.json",
            canonical_url,
        )
        if isinstance(canonical_url, str)
        else None
    )
    _require(
        match is not None and match.group(2) == upstream_id,
        "RustSec semantic export URL is invalid",
    )
    context = projection.get("origin_context")
    _require(isinstance(context, Mapping), "RustSec semantic context is invalid")
    attribution = context.get("attribution_urls")
    _require(
        isinstance(attribution, list) and all(isinstance(url, str) for url in attribution),
        "RustSec semantic attribution is invalid",
    )
    semantic_url = f"{RUSTSEC_REPOSITORY}/blob/osv/{match.group(1)}/{upstream_id}.json"
    return {
        **projection,
        "canonical_url": semantic_url,
        "origin_context": {
            **context,
            "attribution_urls": [
                semantic_url if url == canonical_url else url for url in attribution
            ],
        },
    }


def compare_origin_snapshots(
    before: OriginSnapshot, after: OriginSnapshot
) -> tuple[OriginChange, ...]:
    """Report removals explicitly; removal is never silently treated as withdrawal."""
    _require(
        before.complete
        and after.complete
        and before.origin == after.origin
        and before.source_id == after.source_id,
        "incompatible origin snapshot diff",
    )
    old, new = (
        {record.upstream_record_id: record for record in snapshot.records}
        for snapshot in (before, after)
    )
    result = []
    for advisory_id in sorted(old.keys() | new.keys()):
        prior, current = old.get(advisory_id), new.get(advisory_id)
        if prior is None:
            kind = "added"
        elif current is None:
            kind = "removed"
        elif prior.source_sha256 == current.source_sha256 and _origin_semantic_projection(
            prior.catalog_projection, source_id=prior.source_id
        ) == _origin_semantic_projection(current.catalog_projection, source_id=current.source_id):
            continue
        else:
            _require(
                current.source_modified_at >= prior.source_modified_at,
                "origin correction source time reversed",
            )
            kind = (
                ("withdrawn" if current.state == "withdrawn" else "restored")
                if prior.state != current.state
                else "modified"
            )
        result.append(OriginChange(kind, advisory_id, prior, current))
    return tuple(result)


def _download(url: str, *, client: httpx.Client, deadline: float) -> bytes:
    _require(
        url == GO_ARCHIVE_URL
        or re.fullmatch(r"https://codeload\.github\.com/RustSec/advisory-db/zip/[0-9a-f]{40}", url),
        "origin acquisition URL is not allowlisted",
    )
    remaining = deadline - time.monotonic()
    _require(remaining > 0, "origin acquisition deadline expired")
    try:
        with client.stream(
            "GET",
            url,
            headers={"Accept-Encoding": "identity"},
            follow_redirects=False,
            timeout=httpx.Timeout(remaining, connect=min(10, remaining)),
        ) as response:
            _require(
                response.status_code == 200 and str(response.url) == url,
                "origin acquisition HTTP status or URL changed",
            )
            _require(
                response.headers.get("content-encoding", "identity").lower() in {"", "identity"},
                "origin archive content encoding changed",
            )
            declared = response.headers.get("content-length")
            if declared is not None:
                _require(
                    declared.isdecimal() and 0 < int(declared) <= MAX_ARCHIVE_BYTES,
                    "origin archive declared size invalid",
                )
            result = bytearray()
            for chunk in response.iter_bytes(64 * 1024):
                _require(time.monotonic() < deadline, "origin acquisition deadline expired")
                result.extend(chunk)
                _require(len(result) <= MAX_ARCHIVE_BYTES, "origin archive streamed byte budget")
            _require(
                declared is None or len(result) == int(declared),
                "origin archive transport is truncated",
            )
            return bytes(result)
    except httpx.HTTPError as error:
        raise OriginAdvisoryError("origin acquisition HTTP failure") from error


def rustsec_head() -> str:
    """Resolve only the official export ref, with no credential prompt or retry."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed official Git ref and argv, isolated Git configuration, no shell
            (
                "/usr/bin/git",
                "-c",
                "credential.helper=",
                "-c",
                "protocol.file.allow=never",
                "-c",
                "protocol.ext.allow=never",
                "ls-remote",
                "--refs",
                RUSTSEC_REPOSITORY,
                "refs/heads/osv",
            ),
            check=False,
            capture_output=True,
            timeout=30,
            env={
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
            },
            cwd="/",
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OriginAdvisoryError("RustSec export ref unavailable") from error
    _require(
        completed.returncode == 0 and len(completed.stdout) <= 256, "RustSec export ref unavailable"
    )
    match = re.fullmatch(rb"([0-9a-f]{40})\trefs/heads/osv\n", completed.stdout)
    _require(match, "RustSec export ref is ambiguous")
    return match[1].decode("ascii")


def fetch_origin_snapshot(
    origin: Origin,
    *,
    observed_at: datetime | None = None,
    client: httpx.Client | None = None,
    rustsec_commit: str | None = None,
) -> OriginSnapshot:
    """Acquire one full batch or raise; never return an accepted partial batch."""
    _require(origin in SOURCE_IDS, "unknown advisory origin")
    deadline = time.monotonic() + ACQUISITION_SECONDS
    observed_at = require_aware_utc(observed_at or datetime.now(UTC))
    if origin == "rustsec":
        rustsec_commit = rustsec_commit or rustsec_head()
        _require(COMMIT.fullmatch(rustsec_commit), "RustSec commit is invalid")
        url = f"https://codeload.github.com/RustSec/advisory-db/zip/{rustsec_commit}"
    else:
        _require(rustsec_commit is None, "Go source cannot take a RustSec commit")
        url = GO_ARCHIVE_URL
    if client is None:
        with httpx.Client(follow_redirects=False, trust_env=False) as owned_client:
            body = _download(url, client=owned_client, deadline=deadline)
    else:
        body = _download(url, client=client, deadline=deadline)
    _require(time.monotonic() < deadline, "origin acquisition deadline expired")
    result = (
        parse_rustsec_archive(body, commit=rustsec_commit, observed_at=observed_at)
        if origin == "rustsec"
        else parse_go_archive(body, observed_at=observed_at)
    )
    _require(time.monotonic() < deadline, "origin validation deadline expired")
    return result


def append_origin_advisory(
    session: Session,
    *,
    record: OriginAdvisoryRecord,
    evidence_id: str,
    governance_decision_id: str,
    observed_at: datetime,
) -> CatalogAppendResult:
    """Use the existing append-only catalog path after caller's exact rights approval."""
    from smithguard.advisory_catalog import _append_projection

    return _append_projection(
        session,
        source_id=record.source_id,
        projection=record.catalog_projection,
        evidence_id=evidence_id,
        governance_decision_id=governance_decision_id,
        observed_at=observed_at,
    )
