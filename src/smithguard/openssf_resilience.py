"""Bounded record rejection and terminal partition proofs for the OpenSSF catalog.

The collector's source accounting lock precedes ingestion/catalog locks. A rejection
and its exact-read membership commit before any accepted pages. Failed attempts
retain those barriers; only fresh governed acceptance can append a resolution.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.acquisition import AcquisitionLimits, AcquisitionRequest
from smithguard.collection_records import append_outcome, append_replay_membership
from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import (
    CollectionRecordMembership,
    CollectionRecordOutcome,
    OpenSSFCatalogAttempt,
)
from smithguard.fsio import FsioError, read_private_file
from smithguard.identifiers import canonical_json_bytes, sha256_id, strict_json_loads, timestamp
from smithguard.ingestion import ingest_bytes
from smithguard.normalization import NormalizationRejected
from smithguard.openssf_budget import bounded_timeout, set_statement_budget
from smithguard.openssf_git import (
    COMMIT,
    OPENSSF_CONNECTOR_ID,
    OPENSSF_MALICIOUS,
    OpenSSFWithdrawalMismatch,
)

MAX_REJECTIONS = 10
READER_PROTOCOL = "openssf-rejection-readers-v1"
CONTROL_PATH = Path("/etc/SmithGuard/openssf-resilience.json")
RELEASE_ROOT = Path("/opt/SmithGuard/releases")
ROOT_UID = 0
# The fallback must ship exactly these readers. Writer-only changes can follow the
# bridge without silently falling back to a binary that ignores rejection state.
READER_FILES = (
    "openssf_resilience.py",
    "collection_records.py",
    "advisory_catalog.py",
    "assessment_evidence.py",
    "service.py",
    "coverage.py",
    "catalog_health.py",
    "operational_health.py",
    "contracts/generated.py",
    "db/models.py",
    "migration_head.py",
)


class OpenSSFResilienceError(RuntimeError):
    """A bounded partial run failed its accounting or rollout precondition."""


def _running_release() -> str | None:
    module = Path(__file__).resolve()
    for parent in module.parents:
        if parent.parent == RELEASE_ROOT and COMMIT.fullmatch(parent.name):
            return parent.name
    return None


def partial_writes_enabled() -> bool:
    """Missing control is disabled; invalid explicit control fails closed.

    Root's release-bound control is written only after checked active/fallback
    installation. The collector verifies both installed reader sets itself.
    No environment variable can enable this writer.
    """
    try:
        body = read_private_file(
            CONTROL_PATH, maximum=16384, uid=ROOT_UID, exact_mode=0o644, mode_mask=0o022
        )
    except FileNotFoundError:
        return False
    except FsioError as error:
        # fsio supplies an explicit missing code instead of FileNotFoundError.
        if getattr(error, "code", None) == "missing":
            return False
        raise OpenSSFResilienceError("OpenSSF resilience control is unsafe") from error
    parent = CONTROL_PATH.parent
    metadata = parent.stat()
    if (
        parent.resolve(strict=True) != parent
        or metadata.st_uid != ROOT_UID
        or metadata.st_mode & 0o022
    ):
        raise OpenSSFResilienceError("OpenSSF resilience control directory is unsafe")
    document = strict_json_loads(body.decode("ascii"))
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "reader_protocol",
        "active_release",
        "fallback_release",
        "readers",
    }:
        raise OpenSSFResilienceError("OpenSSF resilience control shape is invalid")
    if document["schema_version"] != "1.0.0" or document["reader_protocol"] != READER_PROTOCOL:
        raise OpenSSFResilienceError("OpenSSF resilience reader protocol is invalid")
    active, fallback = document["active_release"], document["fallback_release"]
    if (
        any(
            not isinstance(value, str) or COMMIT.fullmatch(value) is None
            for value in (active, fallback)
        )
        or active != _running_release()
        or active == fallback
    ):
        raise OpenSSFResilienceError("OpenSSF resilience releases are not bound")
    hashes = document["readers"]
    if not isinstance(hashes, dict) or set(hashes) != set(READER_FILES):
        raise OpenSSFResilienceError("OpenSSF resilience reader set is incomplete")
    for release in (active, fallback):
        if installed_reader_hashes(release) != hashes:
            raise OpenSSFResilienceError("OpenSSF active/fallback readers differ")
    return True


def installed_reader_hashes(release: str, *, root: Path | None = None) -> dict[str, str]:
    """Read the identical root-owned reader boundary used by collector and controller."""
    if COMMIT.fullmatch(release) is None:
        raise OpenSSFResilienceError("OpenSSF installed release identity is invalid")
    root = RELEASE_ROOT if root is None else root
    result = {}
    base = root / release
    if (
        base.resolve(strict=True) != base
        or base.stat().st_uid != ROOT_UID
        or base.stat().st_mode & 0o022
    ):
        raise OpenSSFResilienceError("OpenSSF resilience release root is unsafe")
    packages = tuple((base / "app/.venv/lib").glob("python*/site-packages/smithguard"))
    if len(packages) != 1:
        raise OpenSSFResilienceError("OpenSSF release has an ambiguous installed package")
    package = packages[0]
    if package.resolve(strict=True) != package:
        raise OpenSSFResilienceError("OpenSSF installed reader path is unsafe")
    for relative in READER_FILES:
        path = package / relative
        if path.resolve(strict=True) != path:
            raise OpenSSFResilienceError("OpenSSF installed reader file is unsafe")
        for parent in path.parents:
            if parent == root:
                break
            metadata = parent.stat()
            if metadata.st_uid != ROOT_UID or metadata.st_mode & 0o022:
                raise OpenSSFResilienceError("OpenSSF installed reader directory is unsafe")
        data = read_private_file(
            path, maximum=1024 * 1024, uid=ROOT_UID, exact_mode=0o644, mode_mask=0o022
        )
        result[relative] = sha256_id(data)
    return result


def provenance(entry, *, validated: bool, reason: str | None = None) -> dict:
    return {
        "commit": entry.commit,
        "tree": entry.source_tree,
        "path": entry.path,
        "blob_oid": entry.blob_oid,
        "byte_count": entry.byte_count,
        "validated": validated,
        "reason": reason,
    }


def reject_record(
    session,
    *,
    entry,
    body,
    registry,
    governance_policy,
    evidence,
    observed_at,
    run_id,
    processing_version,
):
    """A real rights-governed quarantine; rejected facts never reach the catalog."""
    set_statement_budget(session)
    advisory_xact_lock(session, "collection-accounting:" + OPENSSF_MALICIOUS)
    profile = registry.get(OPENSSF_MALICIOUS)
    authorization = governance_policy.authorize_collection(
        connector_id=OPENSSF_CONNECTOR_ID,
        source_id=OPENSSF_MALICIOUS,
        acquisition_method="git",
        operating_mode="historical",
        canonical_url=entry.canonical_url,
        source_record_id=entry.advisory_id,
        authorized_at=observed_at,
    )
    reason = OpenSSFWithdrawalMismatch.reason

    def reject(_records):
        raise NormalizationRejected(reason)

    outcome = ingest_bytes(
        session,
        evidence_store=evidence,
        source=profile.source,
        governance=authorization,
        request=AcquisitionRequest(
            source_record_id=entry.advisory_id,
            canonical_url=entry.canonical_url,
            retrieved_at=observed_at,
            source_published_at=None,
            source_modified_at=None,
            media_type="application/json",
            declared_content_length=len(body),
            redirect_count=0,
            transport_elapsed_seconds=0.0,
        ),
        body=body,
        idempotency_key="openssf-rejected:"
        + sha256_id(
            canonical_json_bytes(
                [
                    entry.path,
                    entry.blob_oid,
                    sha256_id(body),
                    authorization.policy_sha256,
                    processing_version,
                ]
            )
        ),
        collection_method="git",
        identity_verification="verified",
        signature_state="unsupported",
        limits=AcquisitionLimits(max_elapsed_seconds=bounded_timeout(180)),
        record_transform=reject,
        retry_quarantined=True,
        retry_token=run_id,
        processing_version=processing_version,
    )
    if outcome.outcome != "quarantined" or outcome.quarantine_reasons != (reason,):
        raise OpenSSFResilienceError("OpenSSF rejection was not governed quarantine")
    accounted = append_outcome(
        session,
        source_id=OPENSSF_MALICIOUS,
        segment="openssf-" + entry.source_tree,
        record_key=entry.advisory_id,
        input_sha256=sha256_id(body),
        processing_version=processing_version,
        policy_sha256=authorization.policy_sha256,
        rights_revision=profile.source["revision"],
        outcome=outcome,
        catalog_event_id=None,
        omissions={},
        source_updated_at=None,
        observed_at=observed_at,
        acquisition_lane="historical",
        input_encoding="exact_git_blob_v1",
        provenance=provenance(entry, validated=False, reason=reason),
    )
    member = append_replay_membership(
        session, outcome=accounted, transport_sha256=sha256_id(body), observed_at=observed_at
    )
    return {
        "record_key": entry.advisory_id,
        "input_sha256": sha256_id(body),
        **provenance(entry, validated=False, reason=reason),
        "outcome_id": accounted.outcome_id,
        "membership_id": member.membership_id,
    }


def append_attempt(
    session: Session, *, run_id: str, state: str, observed_at: datetime, document: dict
):
    """Bind a terminal proof to every exact rejection membership in its transaction."""
    if state not in {"partial", "complete", "failed"} or document.get("schema_version") != "1.0.0":
        raise OpenSSFResilienceError("OpenSSF attempt identity is invalid")
    if state == "failed" and set(document) != {"schema_version", "commit", "rejections"}:
        raise OpenSSFResilienceError("OpenSSF failed attempt cannot claim a partition")
    rejected = document.get("rejections", [])
    if len(rejected) > MAX_REJECTIONS or len({r["record_key"] for r in rejected}) != len(rejected):
        raise OpenSSFResilienceError("OpenSSF attempt rejection bound is invalid")
    for item in rejected:
        member = session.get(CollectionRecordMembership, item["membership_id"])
        outcome = session.get(CollectionRecordOutcome, item["outcome_id"])
        if (
            member is None
            or outcome is None
            or member.outcome_id != outcome.outcome_id
            or outcome.source_id != OPENSSF_MALICIOUS
            or outcome.record_key != item["record_key"]
            or outcome.disposition != "quarantined"
            or member.transport_sha256 != item["input_sha256"]
        ):
            raise OpenSSFResilienceError("OpenSSF attempt rejection membership differs")
    if state != "failed":
        if (
            document.get("scanned_count") != document.get("accepted_count", -1) + len(rejected)
            or document.get("rejected_count") != len(rejected)
            or (state == "partial") != bool(rejected)
        ):
            raise OpenSSFResilienceError("OpenSSF attempt partition is not exact")
        if set(document.get("tree_sha256", {})) != {"malicious", "withdrawn"} or set(
            document.get("accepted_sha256", {})
        ) != {"malicious", "withdrawn"}:
            raise OpenSSFResilienceError("OpenSSF attempt tree proof is missing")
    values = {"state": state, "observed_at": timestamp(observed_at), "document": document}
    record = OpenSSFCatalogAttempt(
        run_id=run_id,
        state=state,
        observed_at=observed_at,
        document=document,
        record_hash=sha256_id(canonical_json_bytes({"run_id": run_id, **values})),
    )
    session.add(record)
    session.flush()
    return record


def latest_attempt(session):
    return session.scalar(
        select(OpenSSFCatalogAttempt)
        .order_by(OpenSSFCatalogAttempt.observed_at.desc(), OpenSSFCatalogAttempt.run_id.desc())
        .limit(1)
    )
