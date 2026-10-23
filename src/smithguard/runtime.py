"""Fail-closed production entry points for the read-only public beta."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn
from sqlalchemy import Engine, create_engine, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from smithguard.anonymous_quota import AnonymousQuotaStore
from smithguard.api import create_public_beta_app
from smithguard.authority import DEFAULT_POLICY_PATH, load_authority_policy
from smithguard.collectors import GITHUB_ADVISORY, GitHubAdvisoryRestCollector
from smithguard.db.models import EvidenceFinalizationRecord, SourceRecord
from smithguard.diagnostics import write_exception_diagnostic
from smithguard.emerging_leads import expire_leads, overdue_lead_count
from smithguard.evidence import (
    COLLECTION_LOCK_TIMEOUT_SECONDS,
    EvidenceCollectionBusy,
    LocalImmutableEvidenceStore,
)
from smithguard.evidence_finalization import (
    EvidenceFinalizationError,
    reconcile_evidence_finalizations,
    require_finalized,
)
from smithguard.feeds import SnapshotSigner
from smithguard.fsio import FsioError, read_private_file
from smithguard.signals import (
    PreliminaryWarningDraft,
    XaiWarningRecheckProvider,
    create_preliminary_warning,
    due_warning_ids,
    expire_due_warnings,
    recheck_warning,
    transition_preliminary_warning,
)
from smithguard.snapshot_archive import PUBLIC_KEY_ID, SnapshotArchive
from smithguard.source_governance import (
    DEFAULT_GOVERNANCE_POLICY_PATH,
    SourceGovernancePolicy,
)
from smithguard.source_rights import RightsRegistry, SourceRightsError
from smithguard.spend import ExternalDispatchDisabled, load_spend_policy_path
from smithguard.warning_lane_outputs import purge_expired_outputs

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RIGHTS_REGISTER = PACKAGE_ROOT / "contracts" / "v1" / "source-rights-register.json"
DEFAULT_SPEND_POLICY = PACKAGE_ROOT / "contracts" / "v1" / "xai-spend-policy.json"
DEFAULT_AUTHORITY_POLICY = DEFAULT_POLICY_PATH
DEFAULT_GOVERNANCE_POLICY = DEFAULT_GOVERNANCE_POLICY_PATH
# Shared update attempt budgets, including failed/deferred attempts. Authenticated
# GitHub permits 5,000 requests/hour; 120 leaves room for an 18-page burst and its
# overlap in all three types. Anonymous runs use 48 of the 60/hour allowance,
# leaving room for the normal six historical pages. Server deferrals still apply;
# these caps do not reserve quota shared with other clients or repeated runs.
UPDATE_PAGE_ATTEMPTS_AUTHENTICATED = 120
UPDATE_PAGE_ATTEMPTS_ANONYMOUS = 48
COLLECTION_PAGE_BUDGET_SECONDS = 20 * 60
MAX_WARNING_DRAFT_BYTES = 16_384
MAX_GITHUB_TOKEN_BYTES = 2048
EMERGING_EXPIRY_BATCHES = 10
EMERGING_EXPIRY_BUDGET_SECONDS = 40


class RuntimeConfigurationError(ValueError):
    """Production configuration is absent, unsafe, or outside the fixed boundary."""


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    database_url: str
    evidence_root: Path | None
    rights_register_path: Path
    authority_policy_path: Path
    governance_policy_path: Path
    signing_key_path: Path | None
    xai_key_path: Path | None
    spend_policy_path: Path | None
    base_url: str
    bind_host: str
    bind_port: int
    snapshot_root: Path | None = None
    revoked_public_key_ids: frozenset[str] = frozenset()
    quota_secret_path: Path | None = None
    anonymous_quota_path: Path | None = None
    unix_socket: Path | None = None
    github_token_path: Path | None = None
    api_pressure_path: Path | None = None


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise RuntimeConfigurationError(f"{name} is required")
    return value


def _path_environment(
    name: str,
    *,
    required: bool,
    default: Path | None = None,
) -> Path | None:
    raw = os.environ.get(name)
    if raw is None:
        if required and default is None:
            raise RuntimeConfigurationError(f"{name} is required")
        return default
    path = Path(raw)
    if not path.is_absolute():
        raise RuntimeConfigurationError(f"{name} must be an absolute path")
    return path


def _validate_database_url(value: str) -> str:
    try:
        parsed = make_url(value)
    except Exception as error:
        raise RuntimeConfigurationError("SMITHGUARD_DATABASE_URL is invalid") from error
    if parsed.drivername != "postgresql+psycopg" or not parsed.database:
        raise RuntimeConfigurationError(
            "SMITHGUARD_DATABASE_URL must use local PostgreSQL through psycopg"
        )
    if parsed.host not in {None, "localhost", "127.0.0.1", "::1"}:
        raise RuntimeConfigurationError("the production database must be local")
    query_host = parsed.query.get("host")
    if query_host is not None and (
        not isinstance(query_host, str) or not query_host.startswith("/")
    ):
        raise RuntimeConfigurationError("the PostgreSQL socket host must be absolute")
    return value


def _validate_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise RuntimeConfigurationError("SMITHGUARD_BASE_URL must be an HTTPS origin")
    return value.rstrip("/")


def _revoked_public_key_ids() -> frozenset[str]:
    raw = os.environ.get("SMITHGUARD_REVOKED_PUBLIC_KEY_IDS", "")
    if not raw:
        return frozenset()
    values = raw.split(",")
    if (
        len(values) > 100
        or len(values) != len(set(values))
        or any(PUBLIC_KEY_ID.fullmatch(value) is None for value in values)
    ):
        raise RuntimeConfigurationError("revoked public key IDs are invalid")
    return frozenset(values)


def load_runtime_config(
    *,
    require_api_secrets: bool = False,
    require_evidence: bool = False,
    require_xai: bool = False,
) -> RuntimeConfig:
    """Load only named configuration; never inspect or print the full environment."""
    production_policies_required = require_api_secrets or require_evidence
    bind_host = os.environ.get("SMITHGUARD_BIND_HOST", "127.0.0.1")
    if bind_host not in {"127.0.0.1", "::1"}:
        raise RuntimeConfigurationError("the API bind host must be loopback")
    raw_port = os.environ.get("SMITHGUARD_BIND_PORT", "8771")
    try:
        bind_port = int(raw_port)
    except ValueError as error:
        raise RuntimeConfigurationError("the API bind port is invalid") from error
    if not 1024 <= bind_port <= 65535:
        raise RuntimeConfigurationError("the API bind port is outside its bound")
    return RuntimeConfig(
        database_url=_validate_database_url(_required_environment("SMITHGUARD_DATABASE_URL")),
        evidence_root=_path_environment(
            "SMITHGUARD_EVIDENCE_ROOT",
            required=require_evidence,
        ),
        rights_register_path=_path_environment(
            "SMITHGUARD_RIGHTS_REGISTER_PATH",
            required=production_policies_required,
            default=None if production_policies_required else DEFAULT_RIGHTS_REGISTER,
        ),
        authority_policy_path=_path_environment(
            "SMITHGUARD_AUTHORITY_POLICY_PATH",
            required=require_evidence,
            default=None if require_evidence else DEFAULT_AUTHORITY_POLICY,
        ),
        governance_policy_path=_path_environment(
            "SMITHGUARD_GOVERNANCE_POLICY_PATH",
            required=production_policies_required,
            default=None if production_policies_required else DEFAULT_GOVERNANCE_POLICY,
        ),
        signing_key_path=_path_environment(
            "SMITHGUARD_SIGNING_KEY_FILE",
            required=require_api_secrets,
        ),
        xai_key_path=_path_environment(
            "SMITHGUARD_XAI_KEY_FILE",
            required=require_xai,
        ),
        spend_policy_path=_path_environment(
            "SMITHGUARD_SPEND_POLICY_PATH",
            required=require_xai,
            default=None,
        ),
        base_url=_validate_base_url(
            os.environ.get(
                "SMITHGUARD_BASE_URL",
                "https://api.smithguard.io",
            )
        ),
        bind_host=bind_host,
        bind_port=bind_port,
        snapshot_root=_path_environment(
            "SMITHGUARD_SNAPSHOT_ROOT",
            required=require_api_secrets,
        ),
        revoked_public_key_ids=_revoked_public_key_ids(),
        quota_secret_path=_path_environment(
            "SMITHGUARD_QUOTA_SECRET_FILE",
            required=require_api_secrets,
        ),
        anonymous_quota_path=_path_environment(
            "SMITHGUARD_ANONYMOUS_QUOTA_PATH",
            required=require_api_secrets,
        ),
        unix_socket=_path_environment(
            "SMITHGUARD_UNIX_SOCKET",
            required=require_api_secrets,
        ),
        github_token_path=_path_environment(
            "SMITHGUARD_GITHUB_TOKEN_FILE",
            required=False,
        ),
        api_pressure_path=_path_environment("SMITHGUARD_API_PRESSURE_PATH", required=False),
    )


def _secure_file(path: Path, *, label: str, maximum: int) -> bytes:
    """Read a private configuration file (no group or other permission bits)."""
    if not path.is_absolute():
        raise RuntimeConfigurationError(f"{label} path must be absolute")
    try:
        return read_private_file(path, maximum=maximum, mode_mask=0o077)
    except FsioError as error:
        messages = {
            "missing": f"{label} file is missing",
            "not_regular": f"{label} must be a regular non-symlink file",
            "mode": f"{label} must not grant group or other permissions",
            "size": f"{label} has an invalid size",
            "changed": f"{label} changed during reading",
        }
        raise RuntimeConfigurationError(
            messages.get(error.code, f"{label} file could not be opened safely")
        ) from error


def _quota_secret(path: Path) -> bytes:
    value = _secure_file(path, label="anonymous quota secret", maximum=256).rstrip(b"\r\n")
    if not 32 <= len(value) <= 128:
        raise RuntimeConfigurationError("anonymous quota secret must contain 32 to 128 bytes")
    return value


def _xai_key(path: Path) -> str:
    body = _secure_file(path, label="xAI key", maximum=2048).strip()
    try:
        value = body.decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeConfigurationError("xAI key must be ASCII") from error
    if not 16 <= len(value) <= 1024:
        raise RuntimeConfigurationError("xAI key has an invalid size")
    return value


def _github_token(path: Path | None = None) -> str | None:
    if path is None:
        raw_path = os.environ.get("SMITHGUARD_GITHUB_TOKEN_FILE")
        if raw_path is None:
            return None
        path = Path(raw_path)
        if not path.is_absolute():
            raise RuntimeConfigurationError("SMITHGUARD_GITHUB_TOKEN_FILE must be absolute")
    if path is None:
        return None
    body = _secure_file(path, label="GitHub token", maximum=MAX_GITHUB_TOKEN_BYTES).strip()
    try:
        value = body.decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeConfigurationError("GitHub token must be ASCII") from error
    if not 16 <= len(value) <= 1024 or any(
        character.isspace() or ord(character) < 33 or ord(character) > 126 for character in value
    ):
        raise RuntimeConfigurationError("GitHub token has an invalid shape")
    return value


def _engine(config: RuntimeConfig) -> Engine:
    return create_engine(
        config.database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        pool_timeout=8,
        hide_parameters=True,
        connect_args={
            "connect_timeout": 8,
            "options": "-c statement_timeout=10000 -c lock_timeout=5000",
        },
    )


def _session_factory(engine: Engine) -> Callable[[], Session]:
    return sessionmaker(engine, expire_on_commit=False)


def api_main() -> int:
    """Start the public API only with local storage and restricted secret files."""
    try:
        worker_count = os.environ.get("WEB_CONCURRENCY")
        if worker_count not in {None, "1"}:
            raise RuntimeConfigurationError("WEB_CONCURRENCY must be unset or 1")
        config = load_runtime_config(require_api_secrets=True)
        if (
            config.signing_key_path is None
            or config.snapshot_root is None
            or config.quota_secret_path is None
            or config.anonymous_quota_path is None
            or config.unix_socket is None
        ):
            raise RuntimeConfigurationError("API secret paths are missing")
        signer = SnapshotSigner.from_private_key_bytes(
            _secure_file(
                config.signing_key_path,
                label="snapshot signing key",
                maximum=32,
            )
        )
        quota_secret = _quota_secret(config.quota_secret_path)
        registry = RightsRegistry.from_path(config.rights_register_path)
        governance_policy = SourceGovernancePolicy.from_path(
            config.governance_policy_path,
            registry=registry,
        )
        engine = _engine(config)
        application = create_public_beta_app(
            session_factory=_session_factory(engine),
            signer=signer,
            base_url=config.base_url,
            expected_governance_policy_sha256=governance_policy.policy_sha256,
            snapshot_archive=SnapshotArchive(config.snapshot_root),
            revoked_public_key_ids=config.revoked_public_key_ids,
            anonymous_quota_store=AnonymousQuotaStore(config.anonymous_quota_path),
            anonymous_quota_secret=quota_secret,
            trusted_proxy_header=True,
            pressure_path=config.api_pressure_path,
        )
        uvicorn.run(
            application,
            uds=str(config.unix_socket),
            proxy_headers=False,
            server_header=False,
            access_log=False,
            log_level="warning",
        )
        return 0
    except RuntimeConfigurationError as error:
        sys.stderr.write(f"configuration_error:{error}\n")
        return 2
    except Exception as error:
        # A bounded, redacted type and traceback so a failed start can be diagnosed.
        write_exception_diagnostic(error)
        sys.stderr.write(f"runtime_error:api_start_failed type={type(error).__name__}\n")
        return 3


def collect_main() -> int:
    """Run bounded update and history pages for every GitHub advisory type."""
    failure_stage = "configuration"
    try:
        config = load_runtime_config(require_evidence=True)
        if config.evidence_root is None:
            raise RuntimeConfigurationError("collector evidence path is missing")
        failure_stage = "database_initialization"
        engine = _engine(config)
        factory = _session_factory(engine)
        failure_stage = "policy_initialization"
        registry = RightsRegistry.from_path(config.rights_register_path)
        authority_policy = load_authority_policy(config.authority_policy_path)
        governance_policy = SourceGovernancePolicy.from_path(
            config.governance_policy_path,
            registry=registry,
        )
        failure_stage = "source_history_validation"
        with factory() as session:
            persisted_source_history = tuple(
                session.execute(
                    select(SourceRecord.revision, SourceRecord.record_hash)
                    .where(SourceRecord.id == GITHUB_ADVISORY)
                    .order_by(SourceRecord.revision)
                ).tuples()
            )
        try:
            registry.validate_persisted_history(
                GITHUB_ADVISORY,
                persisted_source_history,
            )
        except SourceRightsError as error:
            raise RuntimeConfigurationError(
                "stored source history differs from the reviewed register"
            ) from error
        failure_stage = "evidence_initialization"
        evidence = LocalImmutableEvidenceStore(
            config.evidence_root,
            allow_group_read=True,
        )
        failure_stage = "collector_initialization"
        history_cutoff_value = os.environ.get("SMITHGUARD_GITHUB_HISTORY_CUTOFF")
        history_cutoff: datetime | None = None
        if history_cutoff_value is not None:
            try:
                history_cutoff = datetime.fromisoformat(history_cutoff_value.replace("Z", "+00:00"))
            except ValueError as error:
                raise RuntimeConfigurationError("GitHub history cutoff is invalid") from error
            if (
                not history_cutoff_value.endswith("Z")
                or history_cutoff.tzinfo is None
                or history_cutoff.utcoffset() is None
                or history_cutoff.astimezone(UTC).isoformat().replace("+00:00", "Z")
                != history_cutoff_value
            ):
                raise RuntimeConfigurationError("GitHub history cutoff is invalid")
            history_cutoff = history_cutoff.astimezone(UTC)
        rate_limit_wait_value = os.environ.get("SMITHGUARD_GITHUB_RATE_LIMIT_WAIT", "0")
        if rate_limit_wait_value not in {"0", "1"}:
            raise RuntimeConfigurationError("GitHub rate-limit wait flag is invalid")
        rate_limit_wait = rate_limit_wait_value == "1"
        update_target = datetime.now(UTC)
        collectors = tuple(
            (
                advisory_type,
                GitHubAdvisoryRestCollector(
                    registry=registry,
                    evidence_store=evidence,
                    authority_policy=authority_policy,
                    governance_policy=governance_policy,
                    advisory_type=advisory_type,
                    catalog_mode=True,
                    historical_cutoff=history_cutoff,
                ),
            )
            for advisory_type in ("malware", "reviewed", "unreviewed")
        )
        token = _github_token(config.github_token_path)
        raw_history_page_limit = os.environ.get("SMITHGUARD_GITHUB_HISTORY_PAGE_LIMIT", "2")
        try:
            history_page_limit = int(raw_history_page_limit)
        except ValueError as error:
            raise RuntimeConfigurationError("GitHub history page limit is invalid") from error
        if not 1 <= history_page_limit <= 100_000:
            raise RuntimeConfigurationError("GitHub history page limit is outside its bound")
        # One budget covers reconciliation, lock waits and page starts, so the run
        # (plus at most one page in flight) ends well inside the unit's 30-minute limit.
        deadline = time.monotonic() + COLLECTION_PAGE_BUDGET_SECONDS
        failure_stage = "evidence_coordination"
        with evidence.collection_lock():
            failure_stage = "evidence_reconciliation"
            with factory() as session, session.begin():
                _finalized, failed = reconcile_evidence_finalizations(
                    session,
                    store=evidence,
                )
                unresolved_finalizations = session.scalar(
                    select(func.count())
                    .select_from(EvidenceFinalizationRecord)
                    .where(EvidenceFinalizationRecord.state != "finalized")
                )
                failure_stage = "evidence_reconciliation_commit"
            failure_stage = "evidence_reconciliation_inspection"
            unresolved_stages = evidence.pending_manifest()
            if failed or unresolved_finalizations or unresolved_stages:
                reason = (
                    "failed_finalizations"
                    if failed
                    else "unresolved_finalizations"
                    if unresolved_finalizations
                    else "orphan_staging"
                )
                sys.stderr.write(f"collection_diagnostic:{reason}\n")
                raise RuntimeConfigurationError("evidence finalization requires operator recovery")
        totals = {
            "pages": 0,
            "source_records": 0,
            "normalized_records": 0,
            "incidents": 0,
            "failed_lanes": 0,
            "scope_exclusions": 0,
            "scope_exclusion_reference_fragment": 0,
            "scope_exclusion_unsupported_ecosystem": 0,
            "scope_exclusion_unsupported_range": 0,
            "scope_exclusion_missing_package": 0,
            "scope_exclusion_missing_package_name": 0,
            "scope_exclusion_missing_version_range": 0,
        }

        def collect_page(advisory_type, collector, lane):
            """Collect one page, or return None once the shared budget is spent.

            The lock wait is bounded by the remaining budget, and the budget is checked
            again after the lock is granted, so no page starts after the deadline.
            """
            nonlocal failure_stage
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            lock_timeout = min(COLLECTION_LOCK_TIMEOUT_SECONDS, remaining)
            failure_stage = f"{advisory_type}_{lane}_coordination"
            with ExitStack() as held:
                try:
                    held.enter_context(evidence.collection_lock(timeout_seconds=lock_timeout))
                except EvidenceCollectionBusy:
                    # A wait cut short by the budget ends the run; a full-length wait
                    # is genuine contention and still fails it.
                    if lock_timeout < COLLECTION_LOCK_TIMEOUT_SECONDS:
                        return None
                    raise
                if time.monotonic() >= deadline:
                    return None
                with factory() as session, session.begin():
                    failure_stage = f"{advisory_type}_{lane}_collection"
                    run = collector.run(session, lane=lane, token=token)
                    totals["pages"] += int(run.page_processed)
                    totals["source_records"] += run.page_source_record_count
                    totals["normalized_records"] += run.page_normalized_record_count
                    totals["scope_exclusions"] += getattr(run, "page_excluded_scope_entry_count", 0)
                    for reason, count in getattr(run, "page_scope_exclusion_reasons", ()):
                        key = f"scope_exclusion_{reason}"
                        if key not in totals:
                            raise RuntimeConfigurationError(
                                "collector returned an unsupported scope exclusion reason"
                            )
                        totals[key] += count
                    failure_stage = f"{advisory_type}_{lane}_commit"
            require_finalized(session)
            return run

        def rate_limit_wait_done(advisory_type, lane, run) -> bool:
            """Sleep until GitHub's resume time when waiting is enabled; True if it waited."""
            nonlocal failure_stage
            if not (
                run.state == "failed"
                and getattr(run, "reason_code", None) == "github_rate_limited"
                and rate_limit_wait
            ):
                return False
            not_before = getattr(run, "not_before", None)
            if not_before is None:
                raise RuntimeConfigurationError(
                    "GitHub rate-limit deferral is missing its resume time"
                )
            delay = (not_before - datetime.now(UTC)).total_seconds()
            if delay > 0:
                failure_stage = f"{advisory_type}_{lane}_rate_limit_wait"
                # Never sleep past the budget; the next page attempt then ends the run.
                time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
            return True

        def finished(run) -> bool:
            if run.state in {"complete", "failed"}:
                if run.state == "failed" and not getattr(run, "has_scope_gap", False):
                    totals["failed_lanes"] += 1
                return True
            return False

        # Updates rotate one page per advisory type per round, so a backlog in one type
        # cannot starve the others, and no page starts after the shared budget.
        pending = [pair for pair in collectors]
        update_attempts_left = (
            UPDATE_PAGE_ATTEMPTS_AUTHENTICATED if token else UPDATE_PAGE_ATTEMPTS_ANONYMOUS
        )
        while pending and update_attempts_left:
            for advisory_type, collector in list(pending)[:update_attempts_left]:
                update_attempts_left -= 1
                run = collect_page(advisory_type, collector, "updates")
                if run is None:
                    pending.clear()
                    break
                if rate_limit_wait_done(advisory_type, "updates", run):
                    continue
                if finished(run):
                    # Completing a resumed window is not current coverage. Keep
                    # this type in the fair rotation until a window started in
                    # this invocation completes (or either shared budget expires).
                    # Never alter the collector's immutable cutoff or overlap.
                    cutoff = getattr(run, "window_ended_at", None)
                    if (
                        run.state == "complete"
                        and run.page_processed
                        and cutoff is not None
                        and cutoff < update_target
                    ):
                        continue
                    pending.remove((advisory_type, collector))
        for advisory_type, collector in collectors:
            processed_pages = 0
            while processed_pages < history_page_limit:
                run = collect_page(advisory_type, collector, "historical")
                if run is None:
                    break
                if run.page_processed:
                    processed_pages += 1
                if rate_limit_wait_done(advisory_type, "historical", run):
                    continue
                if finished(run):
                    break
        failure_stage = "reporting"
        sys.stdout.write(
            "collection_complete "
            + " ".join(f"{key}={value}" for key, value in totals.items())
            + "\n"
        )
        return 1 if totals["failed_lanes"] else 0
    except RuntimeConfigurationError as error:
        sys.stderr.write(f"configuration_error:{error}\n")
        return 2
    except EvidenceCollectionBusy:
        sys.stderr.write("runtime_error:collection_failed stage=evidence_coordination_timeout\n")
        return 3
    except EvidenceFinalizationError:
        sys.stderr.write("runtime_error:collection_failed stage=evidence_finalization\n")
        return 3
    except Exception:
        sys.stderr.write(f"runtime_error:collection_failed stage={failure_stage}\n")
        return 3


def _warning_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="smithguard-signals")
    operations = parser.add_mutually_exclusive_group(required=True)
    operations.add_argument("--create-from", type=Path)
    operations.add_argument("--expire-due", action="store_true")
    operations.add_argument("--recheck-due", action="store_true")
    operations.add_argument(
        "--transition",
        choices=("withdrawn", "contradicted"),
    )
    parser.add_argument("--reviewer-id")
    parser.add_argument("--policy-qualified", action="store_true")
    parser.add_argument("--limit", type=int, default=2)
    parser.add_argument("--warning-id")
    parser.add_argument("--expected-revision", type=int)
    parser.add_argument("--actor-id")
    parser.add_argument("--reason")
    parser.add_argument("--evidence-url", action="append", default=[])
    return parser


def _warning_draft(
    path: Path,
    *,
    reviewer_id: str,
    policy_qualified: bool = False,
) -> PreliminaryWarningDraft:
    body = _secure_file(
        path,
        label="warning draft",
        maximum=MAX_WARNING_DRAFT_BYTES,
    )
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeConfigurationError("warning draft is not valid JSON") from error
    expected = {
        "title",
        "claim",
        "affected_artifacts",
        "source_urls",
        "evidence_class",
        "independent_source_clusters",
        "observed_at",
    }
    if not isinstance(document, Mapping) or set(document) != expected:
        raise RuntimeConfigurationError("warning draft has unknown or missing fields")
    try:
        source_count = document["independent_source_clusters"]
        if isinstance(source_count, bool) or not isinstance(source_count, int):
            raise ValueError("source count must be an integer")
        observed_at = datetime.fromisoformat(str(document["observed_at"]).replace("Z", "+00:00"))
        return PreliminaryWarningDraft(
            title=str(document["title"]),
            claim=str(document["claim"]),
            affected_artifacts=tuple(document["affected_artifacts"]),
            source_urls=tuple(document["source_urls"]),
            evidence_class=str(document["evidence_class"]),
            independent_source_clusters=source_count,
            observed_at=observed_at,
            reviewer_id=reviewer_id,
            policy_qualified=policy_qualified,
        )
    except (TypeError, ValueError) as error:
        raise RuntimeConfigurationError("warning draft has invalid values") from error


def signals_main(argv: list[str] | None = None) -> int:
    """Create, expire, recheck, or terminally correct preliminary warnings."""
    try:
        arguments = _warning_parser().parse_args(argv)
        if arguments.recheck_due:
            from smithguard.warning_dispatch import dispatch_guard

            # A direct or boot-time start while paused must not even load credentials.
            # recheck_warning holds this guard again through the actual provider work.
            with dispatch_guard("recheck") as control:
                if control is None:
                    sys.stdout.write("signal_recheck_complete contained=1 due=0\n")
                    return 0
        config = load_runtime_config(require_xai=arguments.recheck_due)
        engine = _engine(config)
        factory = _session_factory(engine)
        now = datetime.now(UTC)
        if arguments.create_from is not None:
            if not arguments.reviewer_id:
                raise RuntimeConfigurationError("--reviewer-id is required with --create-from")
            draft = _warning_draft(
                arguments.create_from,
                reviewer_id=arguments.reviewer_id,
                policy_qualified=arguments.policy_qualified,
            )
            with factory() as session, session.begin():
                create_preliminary_warning(
                    session,
                    draft=draft,
                    reviewed_at=now,
                )
            sys.stdout.write("warning_created count=1\n")
            return 0
        if arguments.reviewer_id is not None or arguments.policy_qualified:
            raise RuntimeConfigurationError(
                "warning qualification flags are allowed only with --create-from"
            )
        if arguments.transition is not None:
            if (
                not arguments.warning_id
                or arguments.expected_revision is None
                or not arguments.actor_id
                or not arguments.reason
            ):
                raise RuntimeConfigurationError(
                    "warning transition identity, revision, actor, and reason are required"
                )
            with factory() as session, session.begin():
                document = transition_preliminary_warning(
                    session,
                    warning_id=arguments.warning_id,
                    expected_revision=arguments.expected_revision,
                    state=arguments.transition,
                    actor_id=arguments.actor_id,
                    reason=arguments.reason,
                    evidence_urls=tuple(arguments.evidence_url),
                    occurred_at=now,
                )
            sys.stdout.write(
                f"warning_transitioned state={document['state']} revision={document['revision']}\n"
            )
            return 0
        if arguments.expire_due:
            deadline = time.monotonic() + EMERGING_EXPIRY_BUDGET_SECONDS
            with factory() as session, session.begin():
                expired = expire_due_warnings(session, now=now)
                # The always-on expiry job also ends the 30-day private output retention.
                purged = purge_expired_outputs(session, now=now)
            emerging_expired = 0
            try:
                for _ in range(EMERGING_EXPIRY_BATCHES):
                    if time.monotonic() >= deadline:
                        break
                    with factory() as session, session.begin():
                        session.execute(select(func.set_config("statement_timeout", "5000", True)))
                        batch_expired = expire_leads(session, now=now, deadline=deadline)
                    emerging_expired += batch_expired
                    if batch_expired == 0:
                        break
                # Reserve five bounded seconds for the final count. A timeout is
                # an error, never proof that all overdue revisions were drained.
                remaining_ms = int((deadline + 5 - time.monotonic()) * 1000)
                if remaining_ms <= 0:
                    raise RuntimeError("emerging_expiry_count_budget_exhausted")
                with factory() as session, session.begin():
                    session.execute(
                        select(
                            func.set_config("statement_timeout", str(min(5000, remaining_ms)), True)
                        )
                    )
                    emerging_overdue = overdue_lead_count(session, now=now)
            except Exception:
                sys.stderr.write(
                    f"warning_expiry_partial expired={len(expired)} outputs_purged={purged} "
                    f"emerging_expired={emerging_expired} emerging_overdue=unknown "
                    "emerging_partial=1\n"
                )
                raise
            result = "partial" if emerging_overdue else "complete"
            sys.stdout.write(
                f"warning_expiry_{result} expired={len(expired)} outputs_purged={purged} "
                f"emerging_expired={emerging_expired} emerging_overdue={emerging_overdue} "
                f"emerging_partial={int(bool(emerging_overdue))}\n"
            )
            return 0
        if not 1 <= arguments.limit <= 2:
            raise RuntimeConfigurationError("warning recheck limit must be between 1 and 2")
        if config.xai_key_path is None or config.spend_policy_path is None:
            raise RuntimeConfigurationError("warning recheck configuration is missing")
        policy = load_spend_policy_path(config.spend_policy_path)
        provider = XaiWarningRecheckProvider(
            api_key=_xai_key(config.xai_key_path),
            maximum_request_bytes=policy.maximum_request_bytes,
            maximum_response_bytes=policy.maximum_response_bytes,
            maximum_elapsed_seconds=policy.maximum_elapsed_seconds,
        )
        with factory() as session, session.begin():
            expired = expire_due_warnings(session, now=now)
            due = due_warning_ids(session, now=now, limit=arguments.limit)
        outcomes: dict[str, int] = {}
        for warning_id in due:
            result = recheck_warning(
                factory,
                warning_id=warning_id,
                policy=policy,
                provider=provider,
                now=now,
            )
            outcomes[result.outcome] = outcomes.get(result.outcome, 0) + 1
        fields = [
            f"expired={len(expired)}",
            f"due={len(due)}",
            *(f"{key}={outcomes[key]}" for key in sorted(outcomes)),
        ]
        sys.stdout.write("signal_recheck_complete " + " ".join(fields) + "\n")
        return 0
    except RuntimeConfigurationError as error:
        sys.stderr.write(f"configuration_error:{error}\n")
        return 2
    except ExternalDispatchDisabled:
        sys.stderr.write("policy_denied:warning_recheck_dispatch_disabled\n")
        return 4
    except Exception:
        sys.stderr.write("runtime_error:signal_operation_failed\n")
        return 3
