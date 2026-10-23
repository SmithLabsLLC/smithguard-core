"""Bounded due-source collection under the existing ingestion authority."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from smithguard.acquisition import AcquisitionRequest, OperationDeadline
from smithguard.cve_enrichment import fetch_epss_current, fetch_kev
from smithguard.db.models import (
    SourceRecord,
    SupplementalFactRecord,
)
from smithguard.db.repository import append_contract
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.evidence_finalization import require_finalized
from smithguard.identifiers import canonical_json_bytes, sha256_id, timestamp
from smithguard.ingestion import (
    _raw_evidence_document,
    _reuse_raw_evidence,
    _stage_retained_evidence,
)
from smithguard.origin_advisories import append_origin_advisory, fetch_origin_snapshot
from smithguard.source_governance import SourceGovernancePolicy, append_governance_decision
from smithguard.source_rights import RightsRegistry
from smithguard.supplemental_store import (
    CVE,
    EPSS_SOURCE,
    GO_SOURCE,
    KEV_SOURCE,
    MAX_FACTS,
    RUST_SOURCE,
    append_snapshot,
    latest_snapshot,
    next_collection_at,
)

SOURCES = (EPSS_SOURCE, KEV_SOURCE, RUST_SOURCE, GO_SOURCE)
SOURCE_KEYS = {EPSS_SOURCE: "epss", KEV_SOURCE: "kev", RUST_SOURCE: "rustsec", GO_SOURCE: "go"}
SOURCE_URLS = {
    EPSS_SOURCE: "https://epss.empiricalsecurity.com",
    KEV_SOURCE: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    RUST_SOURCE: "https://github.com/RustSec/advisory-db",
    GO_SOURCE: "https://vuln.go.dev/vulndb.zip",
}
RUN_SECONDS = 12 * 60
MIN_FREE_BYTES = 20 * 1024**3
MIN_FREE_INODES = 20_000


@contextmanager
def _source_lock(factory, source_id, mode):
    """Hold one physical database connection across dispatch and receipt closure."""
    with factory() as session, session.get_bind().connect() as connection:
        key = func.hashtextextended("supplemental-run:" + source_id + ":" + mode, 0)
        acquired = bool(connection.scalar(select(func.pg_try_advisory_lock(key))))
        connection.commit()
        try:
            yield acquired
        finally:
            if acquired:
                try:
                    if not connection.scalar(select(func.pg_advisory_unlock(key))):
                        raise ValueError("supplementary run lock ownership lost")
                    connection.commit()
                except BaseException:
                    connection.invalidate()
                    raise


def _require_capacity(store, snapshot, source_id):
    # The immutable projection is at most64MiB; filesystem block overhead and
    # staging/finalization need additional headroom even when content is reused.
    objects = len(snapshot.records) if source_id in {RUST_SOURCE, GO_SOURCE} else 1000
    capacity = os.statvfs(store.root)
    if (
        capacity.f_bavail * capacity.f_frsize < MIN_FREE_BYTES + 128 * 1024**2
        or capacity.f_favail < MIN_FREE_INODES + 2 * objects
    ):
        raise ValueError("supplementary evidence capacity reserve unavailable")


def known_cves(session: Session) -> tuple[str, ...]:
    """Select current aliases for supported public package records, with a hard cap."""
    # Exclude catalogs without a possible CVE before the package/revision joins.
    # This is only a lossless prefix prefilter: the exact alias check below still
    # decides eligibility, and *all* newer revisions still supersede older ones.
    values = tuple(
        session.scalars(
            text("""
        SELECT DISTINCT alias FROM smithguard.advisory_catalog_records c,
        LATERAL jsonb_array_elements_text(c.aliases) AS alias
        WHERE alias ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'
          AND c.state = 'active'
          AND jsonb_path_exists(c.aliases, '$[*] ? (@ starts with "CVE-")')
          AND EXISTS (
              SELECT 1 FROM smithguard.advisory_package_records p
              WHERE p.catalog_event_id = c.catalog_event_id AND p.state = 'active'
          )
          AND NOT EXISTS (
              SELECT 1 FROM smithguard.advisory_catalog_records newer
              WHERE newer.source_id = c.source_id
                AND newer.upstream_record_id = c.upstream_record_id
                AND newer.revision > c.revision
          )
        ORDER BY alias LIMIT :cap
    """),
            {"cap": MAX_FACTS + 1},
        )
    )
    if len(values) > MAX_FACTS or any(CVE.fullmatch(value) is None for value in values):
        raise ValueError("known CVE inventory exceeds its bound")
    return values


def _authorization(policy, *, source_id, source_url, record_id, now):
    return policy.authorize_collection(
        connector_id="gbsec:connector:" + SOURCE_KEYS[source_id] + "-direct-v1",
        source_id=source_id,
        acquisition_method="download",
        operating_mode="updates",
        canonical_url=source_url,
        source_record_id=record_id,
        authorized_at=now,
    )


def _evidence(session, store, profile, authorization, payload: bytes, *, now, source_time):
    """Store only the exact governed minimal representation, before DB references."""
    accepted = authorization.project_body(payload)
    digest = sha256_id(accepted)
    decision, _ = append_governance_decision(
        session, authorization=authorization, accepted_sha256=digest, decided_at=now
    )
    request = AcquisitionRequest(
        source_record_id=authorization.source_record_id,
        canonical_url=authorization.canonical_url,
        retrieved_at=now,
        source_published_at=None,
        source_modified_at=source_time,
        media_type="application/json",
    )
    document, retain = _raw_evidence_document(
        source=profile.source,
        request=request,
        input_sha256=digest,
        byte_count=len(accepted),
        media_type="application/json",
    )
    if not retain:
        raise ValueError("supplementary immutable evidence is not authorized")
    existing, document, retain = _reuse_raw_evidence(session, document, retain)
    storage_key = _stage_retained_evidence(
        session,
        evidence_store=store,
        retain=retain,
        existing_evidence=existing,
        raw_evidence=document,
        accepted_body=accepted,
        accepted_request=request,
        input_sha256=digest,
        operation_deadline=OperationDeadline.start(60),
    )
    if existing is None:
        append_contract(session, "RawEvidence", document, storage_key=storage_key)
    return document["id"], decision.decision_id


def _persist_context(
    session, store, registry, policy, snapshot, source_id, *, mode, now, retry_of=None
):
    profile = registry.get(source_id)
    if source_id == EPSS_SOURCE:
        source_time = snapshot.score_timestamp or datetime.combine(
            snapshot.score_date, datetime.min.time(), UTC
        )
        facts = {
            score.cve: {
                "epss": score.epss,
                "percentile": score.percentile,
                "score_date": score.score_date.isoformat(),
                "model_version": score.model_version,
            }
            for score in snapshot.scores
        }
        records = [
            {
                "cve": score.cve,
                "epss": score.epss,
                "percentile": score.percentile,
                "date": score.score_date.isoformat(),
                "model_version": score.model_version,
            }
            for score in snapshot.scores
        ]
        extra = {
            "score_date": snapshot.score_date.isoformat(),
            "model_version": snapshot.model_version,
            "validated_rows": snapshot.validated_rows,
            "requested_cves_sha256": sha256_id(canonical_json_bytes(snapshot.requested_cves)),
            "requested_count": len(snapshot.requested_cves),
            "missing_count": len(snapshot.missing_cves),
        }
    else:
        source_time = snapshot.date_released
        facts = {
            entry.cve: {"date_added": entry.date_added.isoformat()} for entry in snapshot.entries
        }
        records = [
            {"cve": entry.cve, "date_added": entry.date_added.isoformat()}
            for entry in snapshot.entries
        ]
        extra = {"catalog_version": snapshot.catalog_version}
    previous = latest_snapshot(session, source_id, mode=mode, complete_only=True)
    if previous and previous.source_as_of and source_time < previous.source_as_of:
        raise ValueError("supplementary source date moved backward")
    evidence_ids = []
    for offset in range(0, max(1, len(records)), 1000):
        authorization = _authorization(
            policy,
            source_id=source_id,
            source_url=snapshot.source_url,
            record_id=snapshot.response_sha256 + ":" + str(offset),
            now=now,
        )
        # A zero-score EPSS selection is valid but has no fabricated score evidence.
        if records:
            evidence_id, _ = _evidence(
                session,
                store,
                profile,
                authorization,
                canonical_json_bytes(records[offset : offset + 1000]),
                now=now,
                source_time=source_time,
            )
            evidence_ids.append(evidence_id)
    if source_id == EPSS_SOURCE:
        # Keep score facts compatible with every schema-0032 reader. This is a
        # collector-derived absence inventory, not an upstream score payload.
        missing_evidence_ids = []
        for offset in range(0, len(snapshot.missing_cves), 1000):
            payload = canonical_json_bytes(
                [
                    {"cve": cve, "date": timestamp(source_time)}
                    for cve in snapshot.missing_cves[offset : offset + 1000]
                ]
            )
            authorization = _authorization(
                policy,
                source_id=source_id,
                source_url=snapshot.source_url,
                record_id=sha256_id(payload) + ":missing",
                now=now,
            )
            evidence_id, _ = _evidence(
                session,
                store,
                profile,
                authorization,
                payload,
                now=now,
                source_time=source_time,
            )
            missing_evidence_ids.append(evidence_id)
            evidence_ids.append(evidence_id)
        extra["missing_subject_evidence_ids"] = missing_evidence_ids
        extra["missing_subjects_sha256"] = sha256_id(canonical_json_bytes(snapshot.missing_cves))
    return append_snapshot(
        session,
        source_id=source_id,
        mode=mode,
        state="complete",
        observed_at=now,
        source_as_of=source_time,
        document={
            "source_url": snapshot.source_url,
            "transport_sha256": snapshot.response_sha256,
            "rights_revision": profile.source["revision"],
            "retry_of": retry_of,
            "policy_sha256": policy.policy_sha256,
            "evidence_ids": evidence_ids,
            **extra,
        },
        facts=facts,
    )


def _persist_origin(
    session, store, registry, policy, snapshot, *, mode, now, deadline, retry_of=None
):
    profile = registry.get(snapshot.source_id)
    previous = latest_snapshot(session, snapshot.source_id, mode=mode, complete_only=True)
    if previous and previous.source_as_of and snapshot.source_modified_at < previous.source_as_of:
        raise ValueError("origin source time moved backward")
    old_ids = (
        set(
            session.scalars(
                select(SupplementalFactRecord.subject_id).where(
                    SupplementalFactRecord.snapshot_id == previous.snapshot_id
                )
            )
        )
        if previous
        else set()
    )
    new_ids = {record.upstream_record_id for record in snapshot.records}
    # Upstream disappearance is ambiguous. Retain the old complete public snapshot;
    # never invent a withdrawal and never publish a partially reconciled archive.
    if old_ids - new_ids:
        raise ValueError("origin advisory disappeared without explicit withdrawal")
    facts = {}
    changed = 0
    for record in snapshot.records:
        if time.monotonic() >= deadline:
            raise ValueError("supplementary persistence deadline exceeded")
        authorization = _authorization(
            policy,
            source_id=record.source_id,
            source_url=record.canonical_url,
            # Immutable acquisition identity includes the exact origin location.
            # A new Rust commit/path can retain identical content; preserve both
            # provenance receipts while the content-addressed object is reused.
            record_id=record.upstream_record_id + ":" + sha256_id(record.canonical_url.encode()),
            now=now,
        )
        if mode == "public" and (
            not authorization.qualified_publication_decision_id
            or not authorization.rights_evidence_verified
        ):
            raise ValueError("origin public source authority is absent")
        evidence_id, decision_id = _evidence(
            session,
            store,
            profile,
            authorization,
            record.raw_body,
            now=now,
            source_time=record.source_modified_at,
        )
        if mode == "public":
            appended = append_origin_advisory(
                session,
                record=record,
                evidence_id=evidence_id,
                governance_decision_id=decision_id,
                observed_at=now,
            )
            changed += int(appended.created)
        facts[record.upstream_record_id] = {
            "source_sha256": record.source_sha256,
            "license_expression": record.license_expression,
            "attribution_urls": list(record.attribution_urls),
            "context": dict(record.context),
            "package_omission_counts": dict(record.catalog_projection["package_omission_counts"]),
            "catalog_event_id": appended.catalog_event_id if mode == "public" else None,
            "state": record.state,
            "evidence_id": evidence_id,
        }
    return append_snapshot(
        session,
        source_id=snapshot.source_id,
        mode=mode,
        state="complete",
        observed_at=now,
        source_as_of=snapshot.source_modified_at,
        document={
            "source_url": snapshot.acquisition_url,
            "transport_sha256": snapshot.transport_sha256,
            "manifest_sha256": snapshot.manifest_sha256,
            "checkpoint_token": snapshot.checkpoint_token,
            "rights_revision": profile.source["revision"],
            "retry_of": retry_of,
            "policy_sha256": policy.policy_sha256,
            "omission_counts": dict(snapshot.omission_counts),
            "created_catalog_revisions": changed,
        },
        facts=facts,
    )


def collect_sources(
    *,
    factory: Callable[[], Session],
    store: LocalImmutableEvidenceStore,
    registry: RightsRegistry,
    policy: SourceGovernancePolicy,
    mode: str,
    sources=SOURCES,
    now: datetime | None = None,
    fetch_epss=fetch_epss_current,
    fetch_cisa=fetch_kev,
    fetch_origin=fetch_origin_snapshot,
    retry_failed_snapshot: str | None = None,
) -> dict[str, str]:
    """One attempt per due source. Failure is durable; other source domains continue."""
    now = now or datetime.now(UTC)
    if (
        mode not in {"shadow", "public"}
        or not sources
        or (retry_failed_snapshot is not None and len(sources) != 1)
        or len(set(sources)) != len(sources)
        or any(source not in SOURCES for source in sources)
    ):
        raise ValueError("supplementary collection mode/sources invalid")
    deadline = time.monotonic() + RUN_SECONDS
    results = {}
    for source_id in sources:
        if time.monotonic() >= deadline:
            results[source_id] = "budget_exhausted"
            continue
        with _source_lock(factory, source_id, mode) as acquired:
            if not acquired:
                results[source_id] = "already_running"
                continue
            try:
                with factory() as session:
                    prior = latest_snapshot(session, source_id, mode=mode)
                    if retry_failed_snapshot is not None and (
                        prior is None
                        or prior.state != "failed"
                        or prior.snapshot_id != retry_failed_snapshot
                    ):
                        results[source_id] = "retry_refused"
                        continue
                    if (
                        prior
                        and retry_failed_snapshot is None
                        and now
                        < next_collection_at(
                            source_id,
                            prior.observed_at,
                            prior.source_as_of,
                            complete=prior.state == "complete",
                        )
                    ):
                        results[source_id] = (
                            "recent_failed" if prior.state == "failed" else "not_due"
                        )
                        continue
                    persisted = tuple(
                        session.execute(
                            select(SourceRecord.revision, SourceRecord.record_hash)
                            .where(SourceRecord.id == source_id)
                            .order_by(SourceRecord.revision)
                        ).tuples()
                    )
                    registry.validate_persisted_history(source_id, persisted)
                    requested = known_cves(session) if source_id == EPSS_SOURCE else ()
                profile = registry.get(source_id)
                profile.authorize_collection(
                    method="download", canonical_url=SOURCE_URLS[source_id], today=now.date()
                )
                _authorization(
                    policy,
                    source_id=source_id,
                    source_url=SOURCE_URLS[source_id],
                    record_id="preflight",
                    now=now,
                )
                if source_id == EPSS_SOURCE:
                    snapshot = fetch_epss(requested, profile=profile, observed_at=now)
                elif source_id == KEV_SOURCE:
                    snapshot = fetch_cisa(profile=profile, observed_at=now)
                else:
                    snapshot = fetch_origin(SOURCE_KEYS[source_id], observed_at=now)
                with (
                    store.collection_lock(
                        timeout_seconds=min(120, max(0.1, deadline - time.monotonic()))
                    ),
                    factory() as session,
                    session.begin(),
                ):
                    _require_capacity(store, snapshot, source_id)
                    append_contract(session, "Source", profile.source)
                    if source_id in {EPSS_SOURCE, KEV_SOURCE}:
                        _persist_context(
                            session,
                            store,
                            registry,
                            policy,
                            snapshot,
                            source_id,
                            mode=mode,
                            now=now,
                            retry_of=retry_failed_snapshot,
                        )
                    else:
                        _persist_origin(
                            session,
                            store,
                            registry,
                            policy,
                            snapshot,
                            mode=mode,
                            now=now,
                            deadline=deadline,
                            retry_of=retry_failed_snapshot,
                        )
                require_finalized(session)
                results[source_id] = "complete"
            except Exception as error:
                # No provider payload, SQL parameter or URL query enters the failure receipt.
                with factory() as session, session.begin():
                    append_snapshot(
                        session,
                        source_id=source_id,
                        mode=mode,
                        state="failed",
                        observed_at=now,
                        source_as_of=None,
                        document={
                            "error_type": type(error).__name__,
                            "retry_of": retry_failed_snapshot,
                            "policy_sha256": policy.policy_sha256,
                        },
                        facts={},
                    )
                results[source_id] = "failed"
    return results


def main() -> int:
    from smithguard.runtime import _engine, _session_factory, load_runtime_config

    parser = argparse.ArgumentParser(prog="smithguard-supplemental")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--shadow", action="store_true")
    modes.add_argument("--commit", action="store_true")
    parser.add_argument("--source", choices=tuple(SOURCE_KEYS.values()), action="append")
    parser.add_argument("--retry-failed-snapshot")
    args = parser.parse_args()
    try:
        config = load_runtime_config(require_evidence=True)
        if config.evidence_root is None:
            raise ValueError("evidence root missing")
        registry = RightsRegistry.from_path(config.rights_register_path)
        policy = SourceGovernancePolicy.from_path(config.governance_policy_path, registry=registry)
        engine = _engine(config)
        try:
            store = LocalImmutableEvidenceStore(config.evidence_root, allow_group_read=True)
            result = collect_sources(
                factory=_session_factory(engine),
                store=store,
                registry=registry,
                policy=policy,
                mode="shadow" if args.shadow else "public",
                retry_failed_snapshot=args.retry_failed_snapshot,
                sources=tuple(
                    source
                    for source in SOURCES
                    if not args.source or SOURCE_KEYS[source] in args.source
                ),
            )
        finally:
            if "store" in locals():
                store.close()
            engine.dispose()
        sys.stdout.write("supplemental_complete " + json.dumps(result, sort_keys=True) + "\n")
        return 0 if all(state in {"complete", "not_due"} for state in result.values()) else 1
    except Exception as error:
        sys.stderr.write("supplemental_error:" + type(error).__name__ + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
