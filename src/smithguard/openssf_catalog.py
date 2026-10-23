"""Complete OpenSSF Git catalog collection without an ecosystem allowlist."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import time
from collections import Counter
from collections.abc import Callable
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from smithguard.advisory_catalog import (
    OPENSSF_SOURCE_ID,
    append_catalog_manifest,
    append_openssf_advisory,
    openssf_advisory_identity,
)
from smithguard.authority import load_authority_policy
from smithguard.catalog_health import (
    CATALOG_HEALTH_PATH,
    CATALOG_HEALTH_VARIABLE,
    CatalogHealthError,
    resource_measurement,
    write_catalog_health,
)
from smithguard.collectors import (
    COLLECTOR_SPECS,
    OPENSSF_MALICIOUS,
    CollectorRunner,
    CollectorSpec,
    TransportResponse,
)
from smithguard.db.models import (
    AdvisoryCatalogManifestRecord,
    AdvisoryCatalogRecord,
    AdvisoryPackageRecord,
    EvidenceFinalizationRecord,
    SourceRecord,
)
from smithguard.diagnostics import write_exception_diagnostic
from smithguard.evidence import (
    COLLECTION_LOCK_TIMEOUT_SECONDS,
    EvidenceCollectionBusy,
    LocalImmutableEvidenceStore,
)
from smithguard.evidence_finalization import (
    reconcile_evidence_finalizations,
    require_finalized,
)
from smithguard.fsio import atomic_write, read_private_file
from smithguard.identifiers import (
    canonical_json_bytes,
    parse_timestamp,
    sha256_id,
    strict_json_loads,
    timestamp,
)
from smithguard.openssf_budget import (
    bounded_timeout,
    catalog_budget,
    checkpoint,
    page_budget,
    set_statement_budget,
)
from smithguard.openssf_git import (
    COMMIT,
    MAX_PAGE_SIZE,
    OPENSSF_LICENSE_SHA256,
    LocalOpenSSFGitRepository,
    OpenSSFGitError,
    OpenSSFProvisionalIDError,
    OpenSSFRecord,
    raw_batches,
)
from smithguard.openssf_shadow import (
    BOOTSTRAP_COMMIT,
    OpenSSFStateBusy,
    ShadowPaths,
    _exclusive_lock,
    ensure_commit_available,
    maintain_repository,
    sync_official_repository,
)
from smithguard.runtime import (
    RuntimeConfigurationError,
    _engine,
    _session_factory,
    load_runtime_config,
)
from smithguard.source_governance import SourceGovernancePolicy
from smithguard.source_rights import RightsRegistry, SourceRightsError

DEFAULT_STATE_ROOT = Path("/var/lib/smithguard/advisory-catalog/openssf")
CATALOG_PROCESSING_VERSION = "openssf-full-catalog-3"
OPENSSF_CATALOG_RUN_LOCK = "openssf-catalog-run"
OPENSSF_CATALOG_ALREADY_RUNNING = 4
OPENSSF_CATALOG_DEFERRED = 75
CATALOG_VALIDATION_PAGE_SIZE = 1000
CATALOG_VALIDATION_SECONDS = 120.0


def _page_body(records: tuple[OpenSSFRecord, ...]) -> bytes:
    """Canonical page bytes; an out-of-range number in a reviewed record is a catalog
    error, not an unhandled encoder failure."""
    try:
        return canonical_json_bytes([record.projected for record in records])
    except ValueError as error:
        raise OpenSSFCatalogError("OpenSSF record contains an invalid JSON number") from error


class OpenSSFCatalogError(RuntimeError):
    """A complete OpenSSF catalog run could not prove full-tree ingestion."""


class OpenSSFCatalogValidationTimeout(OpenSSFCatalogError):
    """Final catalog verification exhausted its shared scan budget."""


class OpenSSFCatalogDeferred(OpenSSFCatalogError):
    """The exact candidate is temporarily incomplete; no catalog success is earned."""

    def __init__(self, commit: str) -> None:
        if COMMIT.fullmatch(commit) is None:
            raise ValueError("deferred catalog commit is invalid")
        self.commit = commit
        super().__init__("OpenSSF candidate retains a recognized provisional advisory identity")


def _openssf_catalog_validation_page(before: str | None = None):
    """Read a bounded latest-identity page and count its exact revision packages."""
    latest_query = (
        select(
            AdvisoryCatalogRecord.source_id,
            AdvisoryCatalogRecord.upstream_record_id,
            AdvisoryCatalogRecord.revision,
            AdvisoryCatalogRecord.source_sha256,
            AdvisoryCatalogRecord.state,
        )
        .where(AdvisoryCatalogRecord.source_id == OPENSSF_SOURCE_ID)
        .distinct(
            AdvisoryCatalogRecord.source_id,
            AdvisoryCatalogRecord.upstream_record_id,
        )
        .order_by(
            AdvisoryCatalogRecord.source_id.desc(),
            AdvisoryCatalogRecord.upstream_record_id.desc(),
            AdvisoryCatalogRecord.revision.desc(),
        )
        .limit(CATALOG_VALIDATION_PAGE_SIZE)
    )
    if before is not None:
        latest_query = latest_query.where(AdvisoryCatalogRecord.upstream_record_id < before)
    latest = latest_query.subquery()
    package_count = (
        select(func.count())
        .select_from(AdvisoryPackageRecord)
        .where(
            AdvisoryPackageRecord.source_id == latest.c.source_id,
            AdvisoryPackageRecord.upstream_record_id == latest.c.upstream_record_id,
            AdvisoryPackageRecord.revision == latest.c.revision,
        )
        .correlate(latest)
        .scalar_subquery()
    )
    return select(
        latest.c.upstream_record_id,
        latest.c.source_sha256,
        latest.c.state,
        package_count.label("package_count"),
    ).order_by(latest.c.upstream_record_id.desc())


def _read_catalog_validation(
    session: Session,
) -> tuple[dict[str, list[list[str]]], dict[str, int]]:
    """Read every identity in the caller's consistent manifest transaction."""
    records: dict[str, list[list[str]]] = {"malicious": [], "withdrawn": []}
    counts = {"malicious": 0, "withdrawn": 0}
    before = None
    deadline = time.monotonic() + bounded_timeout(CATALOG_VALIDATION_SECONDS)
    while True:
        if time.monotonic() >= deadline:
            raise OpenSSFCatalogValidationTimeout(
                "OpenSSF catalog validation exceeded its time budget"
            )
        set_statement_budget(session)
        rows = session.execute(_openssf_catalog_validation_page(before)).all()
        if time.monotonic() >= deadline:
            raise OpenSSFCatalogValidationTimeout(
                "OpenSSF catalog validation exceeded its time budget"
            )
        if not rows:
            break
        for upstream_record_id, source_sha256, state, package_count in rows:
            tree = "malicious" if state == "active" else "withdrawn"
            records[tree].append([str(upstream_record_id), str(source_sha256)])
            counts[tree] += int(package_count)
        before = rows[-1][0]
    # SQL keyset ordering follows the database collation. The existing full-tree
    # comparison and manifest digest use Python's canonical ordering instead.
    for tree_records in records.values():
        tree_records.sort()
    if time.monotonic() >= deadline:
        raise OpenSSFCatalogValidationTimeout("OpenSSF catalog validation exceeded its time budget")
    return records, counts


def _current_package_omissions(session: Session) -> dict[str, int]:
    """Count latest exact-record omissions inside the complete-tree transaction."""
    latest = (
        select(
            AdvisoryCatalogRecord.upstream_record_id,
            AdvisoryCatalogRecord.package_omission_counts.label("omissions"),
        )
        .where(AdvisoryCatalogRecord.source_id == OPENSSF_SOURCE_ID)
        .distinct(AdvisoryCatalogRecord.upstream_record_id)
        .order_by(AdvisoryCatalogRecord.upstream_record_id, AdvisoryCatalogRecord.revision.desc())
        .subquery()
    )
    set_statement_budget(session)
    counts: Counter[str] = Counter()
    for omissions in session.scalars(
        select(latest.c.omissions).where(latest.c.omissions != {}).execution_options(yield_per=256)
    ):
        checkpoint()
        counts.update(omissions)
    return dict(sorted(counts.items()))


def _state_root() -> Path:
    value = os.environ.get("SMITHGUARD_OPENSSF_CATALOG_ROOT")
    path = Path(value) if value is not None else DEFAULT_STATE_ROOT
    if not path.is_absolute():
        raise RuntimeConfigurationError("OpenSSF catalog root must be absolute")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700, parents=False)
        metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or path.resolve(strict=True) != path
    ):
        raise RuntimeConfigurationError("OpenSSF catalog root is unsafe")
    path.chmod(0o700)
    return path


def _page_transport(
    *,
    body: bytes,
    commit: str,
    first_path: str,
    last_path: str,
    observed_at: datetime,
    source_modified_at: datetime,
) -> Callable[[CollectorSpec, str | None], TransportResponse]:
    page_identity = sha256_id(
        canonical_json_bytes(
            [CATALOG_PROCESSING_VERSION, commit, first_path, last_path, sha256_id(body)]
        )
    )

    def transport(_spec: CollectorSpec, _checkpoint: str | None) -> TransportResponse:
        return TransportResponse(
            body=body,
            canonical_url=("https://github.com/ossf/malicious-packages/tree/" + commit),
            media_type="application/json",
            retrieved_at=observed_at,
            source_record_id=f"catalog-page:{page_identity}",
            source_modified_at=source_modified_at,
            declared_content_length=len(body),
            checkpoint_token=f"{commit}:{page_identity}",
        )

    return transport


def _latest_complete_pair(session: Session) -> tuple[AdvisoryCatalogManifestRecord, ...]:
    pair = tuple(
        session.scalars(
            select(AdvisoryCatalogManifestRecord)
            .where(
                AdvisoryCatalogManifestRecord.source_id == OPENSSF_SOURCE_ID,
                AdvisoryCatalogManifestRecord.state == "complete",
                AdvisoryCatalogManifestRecord.segment.in_(
                    ("openssf-malicious", "openssf-withdrawn")
                ),
            )
            .distinct(AdvisoryCatalogManifestRecord.segment)
            .order_by(
                AdvisoryCatalogManifestRecord.segment, AdvisoryCatalogManifestRecord.sequence.desc()
            )
        )
    )
    if (
        len(pair) != 2
        or len({r.source_snapshot.partition(":")[0] for r in pair}) != 1
        or len({r.observed_at for r in pair}) != 1
    ):
        return ()
    return pair


def _baseline_matches(pair, records, counts) -> bool:
    return len(pair) == 2 and all(
        row.manifest_sha256 == _array_digest(records[row.segment.removeprefix("openssf-")])
        and row.record_count == len(records[row.segment.removeprefix("openssf-")])
        and row.package_entry_count == counts[row.segment.removeprefix("openssf-")]
        for row in pair
    )


def _policy_digest(config) -> str:
    return sha256_id(
        canonical_json_bytes(
            [
                sha256_id(path.read_bytes())
                for path in (
                    config.rights_register_path,
                    config.authority_policy_path,
                    config.governance_policy_path,
                )
            ]
        )
    )


def _verification_marker(root, pair, policy_digest, now):
    try:
        marker = strict_json_loads(
            read_private_file(root / "verification.json", maximum=16384, uid=os.geteuid()).decode(
                "ascii"
            )
        )
        if not isinstance(marker, dict) or set(marker) != {
            "processing_version",
            "policy_sha256",
            "baseline_ids",
            "full_verified_at",
        }:
            return None
        verified_at = parse_timestamp(marker["full_verified_at"])
        if (
            marker["processing_version"] != CATALOG_PROCESSING_VERSION
            or marker["policy_sha256"] != policy_digest
            or marker["baseline_ids"] != [row.manifest_event_id for row in pair]
            or not pair
            or not timedelta(0) <= now - verified_at < timedelta(hours=24)
        ):
            return None
        return verified_at
    except (OSError, ValueError, TypeError, UnicodeError):
        return None


def _attempt(factory, state: str, commit: str = "pending") -> None:
    with factory() as session, session.begin():
        for tree in ("malicious", "withdrawn"):
            append_catalog_manifest(
                session,
                source_id=OPENSSF_SOURCE_ID,
                segment=f"openssf-{tree}",
                state=state,
                source_snapshot=commit,
                cursor_value=None,
                record_count=0,
                package_entry_count=0,
                manifest_sha256=sha256_id(canonical_json_bytes([])),
                observed_at=datetime.now(UTC),
            )


def _raw_batches(entries):
    return raw_batches(entries, maximum_records=MAX_PAGE_SIZE)


def _array_digest(rows) -> str:
    """Hash canonical array bytes without materializing its full JSON encoding."""
    digest = hashlib.sha256(b"[")
    for index, row in enumerate(rows):
        if index:
            digest.update(b",")
        digest.update(canonical_json_bytes(row))
    digest.update(b"]")
    return "sha256:" + digest.hexdigest()


def _entry_signature(entry) -> bytes:
    return hashlib.sha256(
        canonical_json_bytes([entry.path, entry.blob_oid, entry.source_state])
    ).digest()


def _projected_size(record) -> tuple[int, int]:
    try:
        size = len(canonical_json_bytes(record.projected))
    except ValueError as error:
        raise OpenSSFCatalogError("OpenSSF record contains an invalid JSON number") from error
    nodes = 0
    stack = [(record.projected, 2)]  # acquisition starts with the page list at depth 1
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 32 or nodes >= 100_000 or size + 2 > 8 * 1024 * 1024:
            raise OpenSSFCatalogError("OpenSSF single projected record exceeds acquisition budget")
        if isinstance(item, dict):
            stack.extend((value, depth + 1) for value in item.values())
        elif isinstance(item, list):
            stack.extend((value, depth + 1) for value in item)
    return size, nodes


def _semantic_pages(records):
    page = []
    size, nodes = 2, 1
    for record in records:
        item_size, item_nodes = _projected_size(record)
        if page and (
            len(page) >= MAX_PAGE_SIZE
            or size + item_size + 1 > 8 * 1024 * 1024
            or nodes + item_nodes > 100_000
        ):
            yield tuple(page)
            page, size, nodes = [], 2, 1
        page.append(record)
        size += item_size + int(len(page) > 1)
        nodes += item_nodes
    if page:
        yield tuple(page)


def _package_counts(session, identities):
    if not identities:
        return {}
    latest = (
        select(
            AdvisoryCatalogRecord.upstream_record_id.label("identity"),
            AdvisoryCatalogRecord.revision.label("revision"),
        )
        .where(
            AdvisoryCatalogRecord.source_id == OPENSSF_SOURCE_ID,
            AdvisoryCatalogRecord.upstream_record_id.in_(identities),
        )
        .distinct(AdvisoryCatalogRecord.upstream_record_id)
        .order_by(AdvisoryCatalogRecord.upstream_record_id, AdvisoryCatalogRecord.revision.desc())
        .subquery()
    )
    return dict(
        session.execute(
            select(latest.c.identity, func.count(AdvisoryPackageRecord.entry_key))
            .outerjoin(
                AdvisoryPackageRecord,
                (AdvisoryPackageRecord.source_id == OPENSSF_SOURCE_ID)
                & (AdvisoryPackageRecord.upstream_record_id == latest.c.identity)
                & (AdvisoryPackageRecord.revision == latest.c.revision),
            )
            .group_by(latest.c.identity)
        ).all()
    )


def _tree_manifest(snapshot, tree: str | None = None) -> str:
    return _array_digest(
        {
            "advisory_id": entry.advisory_id,
            "blob_oid": entry.blob_oid,
            "byte_count": entry.byte_count,
            "ecosystem": entry.ecosystem,
            "package_path": entry.package_path,
            "path": entry.path,
            "source_state": entry.source_state,
        }
        for entry in snapshot.entries
        if tree is None or entry.source_tree == tree
    )


def _tree_baseline_matches(snapshot, baseline) -> bool:
    return all(
        row.source_snapshot.partition(":")[2]
        == _tree_manifest(snapshot, row.segment.removeprefix("openssf-"))
        for row in baseline
    )


def _collect_openssf_catalog(config, engine, attempt) -> dict[str, object]:
    """Synchronize, validate, ingest, and exactly manifest both OpenSSF trees."""
    if config.evidence_root is None:
        raise RuntimeConfigurationError("collector evidence path is missing")
    root = _state_root()
    registry = RightsRegistry.from_path(config.rights_register_path)
    authority_policy = load_authority_policy(config.authority_policy_path)
    governance_policy = SourceGovernancePolicy.from_path(
        config.governance_policy_path,
        registry=registry,
    )
    factory = _session_factory(engine)
    with factory() as session:
        history = tuple(
            session.execute(
                select(SourceRecord.revision, SourceRecord.record_hash)
                .where(SourceRecord.id == OPENSSF_SOURCE_ID)
                .order_by(SourceRecord.revision)
            ).tuples()
        )
    try:
        registry.validate_persisted_history(OPENSSF_SOURCE_ID, history)
    except SourceRightsError as error:
        raise RuntimeConfigurationError(
            "stored OpenSSF source history differs from the reviewed register"
        ) from error
    evidence = LocalImmutableEvidenceStore(config.evidence_root, allow_group_read=True)
    try:
        with evidence.collection_lock(
            timeout_seconds=bounded_timeout(COLLECTION_LOCK_TIMEOUT_SECONDS)
        ):
            with factory() as session, session.begin():
                _finalized, failed = reconcile_evidence_finalizations(session, store=evidence)
                unresolved = session.scalar(
                    select(func.count())
                    .select_from(EvidenceFinalizationRecord)
                    .where(EvidenceFinalizationRecord.state != "finalized")
                )
            pending_stages = evidence.pending_manifest()
            if failed or unresolved or pending_stages:
                reason = (
                    "failed_finalizations"
                    if failed
                    else "unresolved_finalizations"
                    if unresolved
                    else "orphan_staging"
                )
                sys.stderr.write(f"collection_diagnostic:{reason}\n")
                raise RuntimeConfigurationError("evidence finalization requires operator recovery")

        with factory() as session, session.begin():
            session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
            baseline = _latest_complete_pair(session)
            stored_records, stored_counts = _read_catalog_validation(session)
        observed_at = datetime.now(UTC)
        policy_digest = _policy_digest(config)
        last_full = _verification_marker(root, baseline, policy_digest, observed_at)
        full_verification = last_full is None or not _baseline_matches(
            baseline, stored_records, stored_counts
        )
        # The validation API keeps canonical row lists for callers. Retain only
        # compact identity maps while inspecting Git trees; per-row list containers
        # otherwise add memory to both the prior and current inspection peaks.
        stored_records = {tree: dict(rows) for tree, rows in stored_records.items()}
        spec = COLLECTOR_SPECS[OPENSSF_MALICIOUS]
        if not registry.get(OPENSSF_MALICIOUS).is_public_output_approved:
            raise OpenSSFCatalogError("OpenSSF collection is not approved for public output")
        governance_policy.authorize_collection(
            connector_id=spec.connector_id,
            source_id=OPENSSF_MALICIOUS,
            acquisition_method=spec.collection_method,
            operating_mode="historical",
            canonical_url=spec.preflight_url,
            source_record_id=f"preflight:{OPENSSF_MALICIOUS}",
            authorized_at=observed_at,
        )
        shadow_paths = ShadowPaths.from_root(root)
        checkpoint()
        repository_path, current_commit = sync_official_repository(shadow_paths)
        commit = current_commit if baseline else BOOTSTRAP_COMMIT
        attempt["commit"] = commit
        if commit != current_commit:
            ensure_commit_available(shadow_paths, commit, allow_bootstrap_fetch=not baseline)
        reader = LocalOpenSSFGitRepository(repository_path)
        checkpoint()
        previous_entries = None
        previous_commit = baseline[0].source_snapshot.partition(":")[0] if baseline else None
        if not full_verification and previous_commit != commit:
            try:
                previous = reader.inspect_complete(
                    previous_commit, expected_license_sha256=OPENSSF_LICENSE_SHA256
                )
                if not _tree_baseline_matches(previous, baseline):
                    full_verification = True
                else:
                    previous_entries = {
                        entry.advisory_id: _entry_signature(entry) for entry in previous.entries
                    }
                del previous
            except OpenSSFGitError:
                full_verification = True
        checkpoint()
        try:
            snapshot = reader.inspect_complete(
                commit, expected_license_sha256=OPENSSF_LICENSE_SHA256
            )
        except OpenSSFProvisionalIDError as error:
            # Still a failed terminal manifest, not a partial/complete catalog. The
            # service permits one short retry, then the next natural hourly run.
            # Keep the strict 2.0.0 health receipt readable by the predecessor.
            raise OpenSSFCatalogDeferred(commit) from error
        if snapshot.unsupported_counts:
            raise OpenSSFCatalogError("full OpenSSF inspection unexpectedly filtered ecosystems")
        if not full_verification and previous_commit == commit:
            full_verification = not _tree_baseline_matches(snapshot, baseline)
        if full_verification:
            entries = snapshot.entries
        elif previous_commit == commit:
            entries = ()
        else:
            entries = tuple(
                entry
                for entry in snapshot.entries
                if previous_entries.get(entry.advisory_id) != _entry_signature(entry)
            )
        del previous_entries
        manifest_sha256 = _tree_manifest(snapshot)
        tree_manifest_sha256 = {
            tree: _tree_manifest(snapshot, tree) for tree in ("malicious", "withdrawn")
        }
        source_modified_at = reader.commit_time(commit)
        expected = {
            tree: {} if full_verification else dict(stored_records[tree])
            for tree in ("malicious", "withdrawn")
        }
        tree_package_counts = {
            tree: 0 if full_verification else stored_counts[tree] for tree in expected
        }
        stored_hashes = {
            identity: digest
            for rows in stored_records.values()
            for identity, digest in rows.items()
        }
        del stored_records
        removed_ids = sorted(
            stored_hashes.keys() - {entry.advisory_id for entry in snapshot.entries}
        )
        attempt["missing_upstream_count"] = len(removed_ids)
        attempt["missing_upstream_ids"] = removed_ids[:5]
        created_revision_count = 0
        physical_pages = 0
        parsed_count = 0
        for batch in _raw_batches(entries):
            checkpoint()
            bodies = reader.read_blobs(batch)
            records = []
            for entry, body in zip(batch, bodies, strict=True):
                checkpoint()
                record = reader.parse_record(entry, body)
                # Only future catalog pages omit unused metadata. The retained reader's
                # projection and historical evidence bytes remain unchanged.
                record = replace(
                    record,
                    raw_body=b"",
                    projected={
                        key: value
                        for key, value in record.projected.items()
                        if key != "database_specific"
                    },
                )
                records.append(record)
            del bodies
            with factory() as session:
                old_counts = (
                    _package_counts(session, [record.entry.advisory_id for record in records])
                    if not full_verification
                    else {}
                )
            changed_records = []
            for record in records:
                checkpoint()
                identity = record.entry.advisory_id
                digest, package_count = openssf_advisory_identity(
                    record.projected,
                    canonical_url=record.entry.canonical_url,
                    source_state=record.entry.source_state,
                )
                if not full_verification:
                    for tree in expected:
                        if identity in expected[tree]:
                            del expected[tree][identity]
                            tree_package_counts[tree] -= old_counts.get(identity, 0)
                expected[record.entry.source_tree][identity] = digest
                tree_package_counts[record.entry.source_tree] += package_count
                parsed_count += 1
                if stored_hashes.get(identity) != digest:
                    changed_records.append(record)
            del records
            for page_records in _semantic_pages(changed_records):
                checkpoint()
                with page_budget():
                    page_body = _page_body(page_records)
                    runner = CollectorRunner(
                        registry=registry,
                        evidence_store=evidence,
                        transport=_page_transport(
                            body=page_body,
                            commit=commit,
                            first_path=page_records[0].entry.path,
                            last_path=page_records[-1].entry.path,
                            observed_at=observed_at,
                            source_modified_at=source_modified_at,
                        ),
                        clock=lambda: observed_at,
                        authority_policy=authority_policy,
                        governance_policy=governance_policy,
                    )
                    with (
                        evidence.collection_lock(
                            timeout_seconds=bounded_timeout(COLLECTION_LOCK_TIMEOUT_SECONDS)
                        ),
                        factory() as session,
                        session.begin(),
                    ):
                        set_statement_budget(session)
                        run = runner.run_public(
                            session,
                            source_id=OPENSSF_MALICIOUS,
                            operating_mode="historical",
                            processing_version=CATALOG_PROCESSING_VERSION,
                            record_transform_override=lambda _records: (),
                        )
                        if (
                            run.outcome is None
                            or run.outcome.outcome != "accepted"
                            or run.outcome.raw_evidence_id is None
                            or run.outcome.governance_decision_id is None
                        ):
                            raise OpenSSFCatalogError(
                                "OpenSSF catalog evidence page was not accepted"
                            )
                        for record in page_records:
                            set_statement_budget(session)
                            appended = append_openssf_advisory(
                                session,
                                document=record.projected,
                                canonical_url=record.entry.canonical_url,
                                source_state=record.entry.source_state,
                                evidence_id=run.outcome.raw_evidence_id,
                                governance_decision_id=run.outcome.governance_decision_id,
                                observed_at=observed_at,
                            )
                            if (
                                appended.source_sha256
                                != expected[record.entry.source_tree][record.entry.advisory_id]
                            ):
                                raise OpenSSFCatalogError(
                                    "OpenSSF semantic identity changed during append"
                                )
                            created_revision_count += int(appended.created)
                    require_finalized(session)
                    physical_pages += 1
        checkpoint()
        if removed_ids:
            sys.stderr.write(
                "collection_diagnostic:upstream_ids_missing count="
                + str(len(removed_ids))
                + " sample="
                + ",".join(removed_ids[:5])
                + "\n"
            )
            raise OpenSSFCatalogError(
                "OpenSSF database identity differs from the full tree: upstream IDs missing"
            )
        # Inspection guarantees unique source IDs. Equal total size and membership
        # in the exact source tree prove equality without copying whole ID sets.
        if sum(len(values) for values in expected.values()) != len(snapshot.entries) or any(
            entry.advisory_id not in expected[entry.source_tree] for entry in snapshot.entries
        ):
            raise OpenSSFCatalogError("OpenSSF expected identity differs from the full tree")
        # Exact source membership is now proved. Keep only the result counters;
        # the full Git tree need not overlap the database validation inventory.
        record_count = len(snapshot.entries)
        ignored_nonrecord_count = snapshot.ignored_nonrecord_count
        del stored_hashes, snapshot, entries
        completed = []
        with factory() as session, session.begin():
            session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
            actual_records, actual_counts = _read_catalog_validation(session)
            package_omission_counts = _current_package_omissions(session)
            for tree in ("malicious", "withdrawn"):
                expected_records = expected[tree]
                if len(actual_records[tree]) != len(expected_records) or any(
                    expected_records.get(identity) != digest
                    for identity, digest in actual_records[tree]
                ):
                    raise OpenSSFCatalogError(
                        f"OpenSSF {tree} database identity differs from the full tree"
                    )
                if actual_counts[tree] != tree_package_counts[tree]:
                    raise OpenSSFCatalogError(
                        f"OpenSSF {tree} database package count differs from the full tree"
                    )
                completed.append(
                    append_catalog_manifest(
                        session,
                        source_id=OPENSSF_SOURCE_ID,
                        segment=f"openssf-{tree}",
                        state="complete",
                        source_snapshot=f"{commit}:{tree_manifest_sha256[tree]}",
                        cursor_value=None,
                        record_count=len(expected_records),
                        package_entry_count=actual_counts[tree],
                        manifest_sha256=_array_digest(actual_records[tree]),
                        observed_at=observed_at,
                    )
                )
        try:
            atomic_write(
                root / "verification.json",
                canonical_json_bytes(
                    {
                        "processing_version": CATALOG_PROCESSING_VERSION,
                        "policy_sha256": policy_digest,
                        "baseline_ids": [row.manifest_event_id for row in completed],
                        "full_verified_at": timestamp(
                            observed_at if full_verification else last_full
                        ),
                    }
                ),
            )
        except OSError:
            sys.stderr.write("collection_diagnostic:verification_marker_write_failed\n")
        result = {
            "commit": commit,
            "created_revision_count": created_revision_count,
            "ignored_nonrecord_count": ignored_nonrecord_count,
            "manifest_sha256": manifest_sha256,
            "package_entry_count": sum(tree_package_counts.values()),
            "record_count": record_count,
            "status": "complete",
            "unsupported_ecosystem_count": package_omission_counts.get(
                "untyped_upstream_ecosystem", 0
            ),
            "package_omission_counts": package_omission_counts,
            "full_verification": full_verification,
            "parsed_record_count": parsed_count,
            "physical_page_count": physical_pages,
        }
        # Git maintenance forks after validation. Drop the large completed tree and
        # database maps first so that child does not inherit their obsolete heap.
        # All exact comparisons and immutable manifests are already complete.
        del expected, expected_records, actual_records
        if not maintain_repository(repository_path):
            sys.stderr.write("collection_diagnostic:git_maintenance_failed\n")
        return result

    finally:
        evidence.close()


def collect_openssf_catalog() -> dict[str, object]:
    """Keep durable attempt state even when acquisition fails before the first page."""
    started = perf_counter()
    receipt_path = os.environ.get(CATALOG_HEALTH_VARIABLE)
    if receipt_path is not None and receipt_path != str(CATALOG_HEALTH_PATH):
        raise CatalogHealthError("catalog health receipt path differs from its fixed boundary")
    config = load_runtime_config(require_evidence=True)
    engine = _engine(config)
    factory = _session_factory(engine)
    attempt = {}
    succeeded = False
    try:
        with catalog_budget():
            _attempt(factory, "in_progress")
            try:
                result = _collect_openssf_catalog(config, engine, attempt)
                succeeded = True
                return result
            except Exception:
                try:
                    _attempt(factory, "failed", attempt.get("commit", "pending"))
                except Exception:
                    sys.stderr.write("collection_diagnostic:attempt_receipt_failed\n")
                raise
    finally:
        primary_error = sys.exception()
        try:
            receipt_path = os.environ.get(CATALOG_HEALTH_VARIABLE)
            if receipt_path is not None:
                with factory() as session:
                    complete_pair = _latest_complete_pair(session)
                write_catalog_health(
                    Path(receipt_path),
                    state_root=_state_root(),
                    complete_pair=complete_pair,
                    attempt=attempt,
                    succeeded=succeeded,
                    started=started,
                )
        except Exception:
            sys.stderr.write("collection_diagnostic:catalog_health_receipt_failed\n")
            if primary_error is None:
                raise
        finally:
            engine.dispose()
            sys.stdout.write(
                "openssf_catalog_resources "
                + " ".join(
                    f"{key}={value}" for key, value in sorted(resource_measurement(started).items())
                )
                + "\n"
            )


def main() -> int:
    lock_engine = None
    lock_connection = None
    lock_acquired = False
    try:
        lock_config = load_runtime_config(require_evidence=True)
        lock_engine = _engine(lock_config)
        # A session-level advisory lock belongs to one PostgreSQL connection. Hold that
        # connection open for the whole run; returning it to the pool would leave the
        # lock on an idle pooled connection and the unlock on a different one.
        lock_connection = lock_engine.connect()
        lock_acquired = bool(
            lock_connection.scalar(
                select(
                    func.pg_try_advisory_lock(func.hashtextextended(OPENSSF_CATALOG_RUN_LOCK, 0))
                )
            )
        )
        lock_connection.commit()
        if not lock_acquired:
            sys.stderr.write("openssf_catalog_already_running\n")
            return OPENSSF_CATALOG_ALREADY_RUNNING
        with _exclusive_lock(_state_root() / "run.lock"):
            result = collect_openssf_catalog()
        fields = {
            key: canonical_json_bytes(value).decode("ascii") if isinstance(value, dict) else value
            for key, value in result.items()
        }
        sys.stdout.write(
            "openssf_catalog_complete "
            + " ".join(f"{key}={value}" for key, value in sorted(fields.items()))
            + "\n"
        )
        return 0
    except OpenSSFStateBusy:
        sys.stderr.write("openssf_catalog_already_running\n")
        return OPENSSF_CATALOG_ALREADY_RUNNING
    except OpenSSFCatalogDeferred as error:
        sys.stderr.write(
            "runtime_error:openssf_catalog_deferred reason=provisional_upstream_ids "
            f"commit={error.commit} provisional_ids_at_least=1\n"
        )
        return OPENSSF_CATALOG_DEFERRED
    except OpenSSFCatalogValidationTimeout:
        sys.stderr.write("collection_diagnostic:validation_time_budget\n")
        sys.stderr.write("runtime_error:openssf_catalog_failed\n")
        return 3
    except EvidenceCollectionBusy:
        sys.stderr.write(
            "runtime_error:openssf_catalog_failed reason=evidence_coordination_timeout\n"
        )
        return 3
    except RuntimeConfigurationError as error:
        sys.stderr.write(f"configuration_error:{error}\n")
        return 2
    except Exception as error:
        write_exception_diagnostic(error)
        sys.stderr.write("runtime_error:openssf_catalog_failed\n")
        return 3
    finally:
        if lock_connection is not None:
            if lock_acquired:
                with suppress(Exception):
                    lock_connection.execute(
                        select(
                            func.pg_advisory_unlock(
                                func.hashtextextended(OPENSSF_CATALOG_RUN_LOCK, 0)
                            )
                        )
                    )
                    lock_connection.commit()
            lock_connection.close()
        if lock_engine is not None:
            lock_engine.dispose()
