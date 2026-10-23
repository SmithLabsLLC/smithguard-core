"""Production entry-point configuration fails closed before external work."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import smithguard.runtime as runtime_module
from smithguard.db.models import (
    EmergingLeadRecord,
    EvidenceFinalizationRecord,
    PreliminaryWarningRecord,
    WarningLaneOutputRecord,
)
from smithguard.emerging_leads import overdue_lead_count, record_lead
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.evidence_finalization import register_evidence_stage
from smithguard.identifiers import stable_id
from smithguard.runtime import (
    DEFAULT_AUTHORITY_POLICY,
    DEFAULT_GOVERNANCE_POLICY,
    DEFAULT_RIGHTS_REGISTER,
    DEFAULT_SPEND_POLICY,
    RuntimeConfig,
    RuntimeConfigurationError,
    _engine,
    _secure_file,
    _warning_draft,
    api_main,
    collect_main,
    load_runtime_config,
    signals_main,
)
from smithguard.source_governance import governance_policy_sha256
from smithguard.warning_lane_outputs import record_output

from .test_emerging_leads import candidate
from .test_signals import _draft


def _base_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(
        "SMITHGUARD_DATABASE_URL",
        "postgresql+psycopg://smithguard@/smithguard?host=/run/postgresql",
    )
    monkeypatch.setenv("SMITHGUARD_EVIDENCE_ROOT", str(tmp_path / "evidence"))


def test_runtime_defaults_resolve_inside_the_repository(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _base_environment(monkeypatch, tmp_path)
    config = load_runtime_config()
    assert config.rights_register_path == DEFAULT_RIGHTS_REGISTER
    assert config.authority_policy_path == DEFAULT_AUTHORITY_POLICY
    assert config.governance_policy_path == DEFAULT_GOVERNANCE_POLICY
    assert DEFAULT_RIGHTS_REGISTER.is_file()
    assert DEFAULT_AUTHORITY_POLICY.is_file()
    assert DEFAULT_GOVERNANCE_POLICY.is_file()
    assert DEFAULT_SPEND_POLICY.is_file()
    assert config.bind_host == "127.0.0.1"
    assert config.bind_port == 8771
    assert config.base_url == "https://api.smithguard.io"
    assert config.revoked_public_key_ids == frozenset()


def test_runtime_validates_bounded_revoked_public_key_ids(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _base_environment(monkeypatch, tmp_path)
    public_key_id = "gbsec:snapshot-public-key:" + "a" * 40
    monkeypatch.setenv("SMITHGUARD_REVOKED_PUBLIC_KEY_IDS", public_key_id)
    assert load_runtime_config().revoked_public_key_ids == frozenset({public_key_id})
    monkeypatch.setenv("SMITHGUARD_REVOKED_PUBLIC_KEY_IDS", "invalid")
    with pytest.raises(RuntimeConfigurationError, match="revoked public key"):
        load_runtime_config()


def test_production_runtime_requires_explicit_release_policy_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _base_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("SMITHGUARD_SIGNING_KEY_FILE", str(tmp_path / "signing.key"))
    with pytest.raises(RuntimeConfigurationError, match="RIGHTS_REGISTER_PATH"):
        load_runtime_config(require_api_secrets=True)
    monkeypatch.setenv("SMITHGUARD_RIGHTS_REGISTER_PATH", str(DEFAULT_RIGHTS_REGISTER))
    with pytest.raises(RuntimeConfigurationError, match="GOVERNANCE_POLICY_PATH"):
        load_runtime_config(require_api_secrets=True)


def test_runtime_accepts_an_explicit_absolute_authority_policy_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _base_environment(monkeypatch, tmp_path)
    policy = tmp_path / "authority-policy.json"
    monkeypatch.setenv("SMITHGUARD_AUTHORITY_POLICY_PATH", str(policy))
    assert load_runtime_config().authority_policy_path == policy
    monkeypatch.setenv("SMITHGUARD_AUTHORITY_POLICY_PATH", "relative-policy.json")
    with pytest.raises(RuntimeConfigurationError, match="absolute path"):
        load_runtime_config()


def test_runtime_accepts_an_explicit_absolute_governance_policy_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _base_environment(monkeypatch, tmp_path)
    policy = tmp_path / "governance-policy.json"
    monkeypatch.setenv("SMITHGUARD_GOVERNANCE_POLICY_PATH", str(policy))
    assert load_runtime_config().governance_policy_path == policy
    monkeypatch.setenv(
        "SMITHGUARD_GOVERNANCE_POLICY_PATH",
        "relative-policy.json",
    )
    with pytest.raises(RuntimeConfigurationError, match="absolute path"):
        load_runtime_config()


def test_api_runtime_threads_the_configured_governance_policy_digest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = RuntimeConfig(
        database_url=("postgresql+psycopg://smithguard@/smithguard?host=/run/postgresql"),
        evidence_root=None,
        rights_register_path=DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=tmp_path / "signing.key",
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
        snapshot_root=tmp_path / "snapshots",
        quota_secret_path=tmp_path / "quota.key",
        anonymous_quota_path=tmp_path / "anonymous-access" / "quota.sqlite3",
        unix_socket=tmp_path / "api.sock",
    )
    config.snapshot_root.mkdir(mode=0o750)
    config.anonymous_quota_path.parent.mkdir(mode=0o700)
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        runtime_module,
        "load_runtime_config",
        lambda **_kwargs: config,
    )
    monkeypatch.setattr(
        runtime_module,
        "_secure_file",
        lambda _path, **_kwargs: b"x" * 32,
    )
    monkeypatch.setattr(
        runtime_module,
        "_quota_secret",
        lambda _path: b"synthetic-quota-secret-32-bytes!",
    )
    monkeypatch.setattr(
        runtime_module.SnapshotSigner,
        "from_private_key_bytes",
        staticmethod(lambda _value: "synthetic-signer"),
    )
    monkeypatch.setattr(runtime_module, "_engine", lambda _config: "synthetic-engine")
    monkeypatch.setattr(
        runtime_module,
        "_session_factory",
        lambda _engine: "synthetic-session-factory",
    )

    def create_app(**kwargs):
        captured.update(kwargs)
        return "synthetic-app"

    monkeypatch.setattr(runtime_module, "create_public_beta_app", create_app)
    monkeypatch.setattr(runtime_module.uvicorn, "run", lambda *_args, **_kwargs: None)

    assert api_main() == 0
    assert captured["expected_governance_policy_sha256"] == governance_policy_sha256(
        DEFAULT_GOVERNANCE_POLICY
    )
    assert captured["snapshot_archive"].root == config.snapshot_root
    assert captured["revoked_public_key_ids"] == frozenset()
    assert captured["anonymous_quota_secret"] == b"synthetic-quota-secret-32-bytes!"


@pytest.mark.audit_ids("API-06")
def test_runtime_engine_uses_an_eight_second_pool_checkout_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _base_environment(monkeypatch, tmp_path)
    captured: dict[str, object] = {}

    def capture_engine(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return "synthetic-engine"

    monkeypatch.setattr(runtime_module, "create_engine", capture_engine)
    assert _engine(load_runtime_config()) == "synthetic-engine"
    assert captured["pool_timeout"] == 8


@pytest.mark.audit_ids("API-10")
def test_api_runtime_rejects_more_than_one_worker_before_loading_secrets(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    monkeypatch.setattr(
        runtime_module,
        "load_runtime_config",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("must not load")),
    )
    assert api_main() == 2
    assert capsys.readouterr().err == "configuration_error:WEB_CONCURRENCY must be unset or 1\n"


@pytest.mark.parametrize(
    "database_url",
    (
        "postgresql+psycopg://user@example.test/database",
        "postgresql://user@localhost/database",
        "sqlite:///tmp/database.db",
    ),
)
def test_runtime_rejects_remote_or_non_postgresql_database(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    database_url: str,
) -> None:
    _base_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("SMITHGUARD_DATABASE_URL", database_url)
    with pytest.raises(RuntimeConfigurationError):
        load_runtime_config()


@pytest.mark.parametrize("mode", ("committed_missing_stage", "orphan_stage"))
def test_collector_runtime_reconciles_evidence_before_network_work(
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mode: str,
) -> None:
    evidence_root = tmp_path / "evidence"
    missing_digest = "sha256:" + "0" * 64
    now = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
    if mode == "committed_missing_stage":
        with Session(database.engine) as session, session.begin():
            session.add(
                EvidenceFinalizationRecord(
                    finalization_id=stable_id(
                        "evidence-finalization",
                        missing_digest,
                    ),
                    evidence_id="gbsec:evidence:runtime-missing-stage",
                    digest=missing_digest,
                    staging_key=missing_digest,
                    byte_count=1,
                    state="pending",
                    attempts=0,
                    last_error_code=None,
                    staged_at=now,
                    updated_at=now,
                    finalized_at=None,
                )
            )
    else:
        store = LocalImmutableEvidenceStore(
            evidence_root,
            allow_group_read=True,
        )
        store.stage_bytes(b"synthetic orphan runtime stage")
        store.close()

    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=evidence_root,
        rights_register_path=DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
    )
    collector_calls = 0

    class MustNotCollect:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def run(self, *_args: object, **_kwargs: object) -> None:
            nonlocal collector_calls
            collector_calls += 1
            raise AssertionError("collection must wait for evidence reconciliation")

    monkeypatch.setattr(runtime_module, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(runtime_module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(
        runtime_module,
        "GitHubAdvisoryRestCollector",
        MustNotCollect,
    )

    assert collect_main() == 2
    assert collector_calls == 0
    assert "evidence finalization requires operator recovery" in (capsys.readouterr().err)
    if mode == "committed_missing_stage":
        with Session(database.engine) as session:
            record = session.get(
                EvidenceFinalizationRecord,
                stable_id("evidence-finalization", missing_digest),
            )
            assert record is not None
            assert record.state == "failed"
            assert record.attempts == 1


def test_collector_runtime_reports_only_the_allowlisted_failure_stage(
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
    )

    class FailingHistoricalCollector:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def run(
            self,
            _session: Session,
            *,
            lane: str,
            token: str | None = None,
        ) -> SimpleNamespace:
            assert token is None
            if lane == "historical":
                raise ValueError("raw exception detail must remain private")
            return SimpleNamespace(
                page_processed=False,
                page_source_record_count=0,
                page_normalized_record_count=0,
                collections=(),
                state="complete",
            )

    monkeypatch.setattr(runtime_module, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(runtime_module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(
        runtime_module,
        "GitHubAdvisoryRestCollector",
        FailingHistoricalCollector,
    )

    assert collect_main() == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ("runtime_error:collection_failed stage=malware_historical_collection\n")
    assert "raw exception detail" not in captured.err


def test_collector_runtime_does_not_fail_a_durable_scope_gap(
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
    )

    class ScopeGapCollector:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def run(
            self,
            _session: Session,
            *,
            lane: str,
            token: str | None = None,
        ) -> SimpleNamespace:
            assert token is None
            return SimpleNamespace(
                page_processed=False,
                page_source_record_count=0,
                page_normalized_record_count=0,
                collections=(),
                state="failed" if lane == "historical" else "complete",
                has_scope_gap=lane == "historical",
            )

    monkeypatch.setattr(runtime_module, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(runtime_module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(runtime_module, "GitHubAdvisoryRestCollector", ScopeGapCollector)

    assert collect_main() == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == (
        "collection_complete pages=0 source_records=0 "
        "normalized_records=0 incidents=0 failed_lanes=0 scope_exclusions=0 "
        "scope_exclusion_reference_fragment=0 scope_exclusion_unsupported_ecosystem=0 "
        "scope_exclusion_unsupported_range=0 "
        "scope_exclusion_missing_package=0 scope_exclusion_missing_package_name=0 "
        "scope_exclusion_missing_version_range=0\n"
    )


def test_catalog_backfill_shares_one_cutoff_and_waits_inside_the_service(
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
    )
    cutoff = datetime(2026, 8, 31, 4, 8, 40, tzinfo=UTC)
    constructed: list[datetime | None] = []
    sleeps: list[float] = []

    class ResumableCollector:
        def __init__(self, **kwargs: object) -> None:
            constructed.append(kwargs.get("historical_cutoff"))
            self.waited = False

        def run(
            self,
            _session: Session,
            *,
            lane: str,
            token: str | None = None,
        ) -> SimpleNamespace:
            assert token is None
            if lane == "historical" and not self.waited:
                self.waited = True
                return SimpleNamespace(
                    page_processed=False,
                    page_source_record_count=0,
                    page_normalized_record_count=0,
                    collections=(),
                    state="failed",
                    reason_code="github_rate_limited",
                    not_before=datetime.now(UTC) + timedelta(seconds=1),
                    has_scope_gap=False,
                )
            return SimpleNamespace(
                page_processed=False,
                page_source_record_count=0,
                page_normalized_record_count=0,
                collections=(),
                state="complete",
                has_scope_gap=False,
            )

    monkeypatch.setenv("SMITHGUARD_GITHUB_HISTORY_CUTOFF", "2026-08-31T04:08:40Z")
    monkeypatch.setenv("SMITHGUARD_GITHUB_RATE_LIMIT_WAIT", "1")
    monkeypatch.setattr(runtime_module, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(runtime_module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(runtime_module, "GitHubAdvisoryRestCollector", ResumableCollector)
    monkeypatch.setattr(runtime_module.time, "sleep", sleeps.append)

    assert collect_main() == 0
    assert constructed == [cutoff, cutoff, cutoff]
    assert len(sleeps) == 3
    assert all(0 < delay <= 1 for delay in sleeps)
    assert capsys.readouterr().err == ""


def test_collector_runtime_refuses_an_unattributed_scope_exclusion(
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
    )

    class UnknownReasonCollector:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def run(
            self,
            _session: Session,
            *,
            lane: str,
            token: str | None = None,
        ) -> SimpleNamespace:
            assert token is None
            return SimpleNamespace(
                page_processed=True,
                page_source_record_count=1,
                page_normalized_record_count=0,
                page_excluded_scope_entry_count=1,
                page_scope_exclusion_reasons=(("unexpected", 1),),
                collections=(),
                state="complete",
            )

    monkeypatch.setattr(runtime_module, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(runtime_module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(runtime_module, "GitHubAdvisoryRestCollector", UnknownReasonCollector)

    assert collect_main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "configuration_error:collector returned an unsupported scope exclusion reason\n"
    )


def test_collector_runtime_distinguishes_post_commit_evidence_failure(
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
    )

    class StagingCollector:
        def __init__(
            self,
            *,
            evidence_store: LocalImmutableEvidenceStore,
            **_kwargs: object,
        ) -> None:
            self.evidence_store = evidence_store

        def run(
            self,
            session: Session,
            *,
            lane: str,
            token: str | None = None,
        ) -> SimpleNamespace:
            assert token is None
            assert lane == "updates"
            stage = self.evidence_store.stage_bytes(b"synthetic runtime evidence")
            register_evidence_stage(
                session,
                store=self.evidence_store,
                stage=stage,
                evidence_id=stable_id("evidence", stage.digest),
                staged_at=datetime(2026, 8, 7, 22, 16, 36, tzinfo=UTC),
            )
            return SimpleNamespace(
                page_processed=False,
                page_source_record_count=0,
                page_normalized_record_count=0,
                collections=(),
                state="complete",
            )

    def fail_finalization(
        _store: LocalImmutableEvidenceStore,
        _stage: object,
    ) -> None:
        raise OSError("raw finalization exception must remain private")

    monkeypatch.setattr(runtime_module, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(runtime_module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(runtime_module, "GitHubAdvisoryRestCollector", StagingCollector)
    monkeypatch.setattr(
        LocalImmutableEvidenceStore,
        "finalize_stage",
        fail_finalization,
    )

    assert collect_main() == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert lines[0].startswith("evidence_finalization_pending count=1 ids=")
    assert lines[1:] == ["runtime_error:collection_failed stage=evidence_finalization"]
    assert "raw finalization exception" not in captured.err
    with Session(database.engine) as session:
        finalization = session.scalar(select(EvidenceFinalizationRecord))
        assert finalization is not None
        assert finalization.state == "failed"


def test_secure_file_rejects_permissions_and_symlinks(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_bytes(b"x" * 32)
    secret.chmod(0o644)
    with pytest.raises(RuntimeConfigurationError, match="permissions"):
        _secure_file(secret, label="test secret", maximum=64)
    secret.chmod(0o600)
    assert _secure_file(secret, label="test secret", maximum=64) == b"x" * 32
    link = tmp_path / "secret-link"
    link.symlink_to(secret)
    with pytest.raises(RuntimeConfigurationError, match="safely"):
        _secure_file(link, label="test secret", maximum=64)


def test_warning_draft_rejects_boolean_source_count(tmp_path: Path) -> None:
    draft = tmp_path / "draft.json"
    draft.write_text(
        json.dumps(
            {
                "title": "Synthetic warning",
                "claim": "Synthetic claim",
                "affected_artifacts": ["npm:synthetic@1.0.0"],
                "source_urls": [
                    "https://example.test/one",
                    "https://example.test/two",
                ],
                "evidence_class": "web_and_social",
                "independent_source_clusters": True,
                "observed_at": "2026-08-05T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    os.chmod(draft, 0o600)
    with pytest.raises(RuntimeConfigurationError, match="invalid values"):
        _warning_draft(draft, reviewer_id="reviewer:owner")


def test_signal_runtime_accepts_policy_qualification_only_with_manual_creation(
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(
        "SMITHGUARD_DATABASE_URL",
        database.url.render_as_string(hide_password=False),
    )
    monkeypatch.setenv("SMITHGUARD_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    draft = tmp_path / "policy-qualified-warning.json"
    draft.write_text(
        json.dumps(
            {
                "title": "Synthetic policy-qualified warning",
                "claim": "One public lead describes a possible package compromise.",
                "affected_artifacts": ["npm:synthetic@1.0.0"],
                "source_urls": ["https://example.com/public-lead"],
                "evidence_class": "social_only",
                "independent_source_clusters": 1,
                "observed_at": "2026-08-05T12:00:00Z",
            }
        ),
        encoding="ascii",
    )
    os.chmod(draft, 0o600)

    assert (
        signals_main(
            [
                "--create-from",
                str(draft),
                "--reviewer-id",
                "scanner:grok-social",
                "--policy-qualified",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == "warning_created count=1\n"
    with Session(database.engine) as session:
        warning = session.scalar(select(PreliminaryWarningRecord))
        assert warning is not None
        assert warning.document["qualification_basis"] == ("owner_authorized_early_lead_policy")
        assert warning.document["qualification_actor_id"] == "scanner:grok-social"
        assert warning.document["human_reviewed"] is False
        assert warning.document["confirmation_status"] == "unverified"
        assert warning.document["automation_allowed"] is False
        assert warning.document["max_action_level"] == 0

    assert signals_main(["--expire-due", "--policy-qualified"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "configuration_error:warning qualification flags are allowed only with --create-from\n"
    )


def test_signal_timer_runs_expiry_without_xai_configuration(
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(
        "SMITHGUARD_DATABASE_URL",
        database.url.render_as_string(hide_password=False),
    )
    monkeypatch.setenv(
        "SMITHGUARD_EVIDENCE_ROOT",
        str(tmp_path / "evidence"),
    )
    assert signals_main(["--expire-due"]) == 0
    output = capsys.readouterr().out
    assert output == (
        "warning_expiry_complete expired=0 outputs_purged=0 "
        "emerging_expired=0 emerging_overdue=0 emerging_partial=0\n"
    )


@pytest.mark.parametrize("bounded", [False, True])
def test_signal_expiry_drains_multiple_v4_batches_and_preserves_legacy_cleanup(
    database, monkeypatch, tmp_path, capsys, bounded
):
    monkeypatch.setenv(
        "SMITHGUARD_DATABASE_URL", database.url.render_as_string(hide_password=False)
    )
    monkeypatch.setenv("SMITHGUARD_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    now = datetime.now(UTC)
    first_seen = now - timedelta(hours=25)
    with Session(database.engine) as session, session.begin():
        for i in range(205):
            record_lead(
                session,
                candidate(url=f"https://research.example/expiry/{i}", subject=f"Expiry lead {i}"),
                state="unverified" if i % 2 else "needs_enrichment",
                reason="attributable_security_report",
                now=first_seen,
            )
        runtime_module.create_preliminary_warning(
            session, draft=replace(_draft(), observed_at=first_seen), reviewed_at=first_seen
        )
        record_output(
            session,
            run_id="gbsec:ai-warning-run:expiry-runtime",
            job_id="job-expiry-runtime",
            attempt=1,
            stage="discovery",
            response_id="response-expiry-runtime",
            output_text="Synthetic final output.",
            citation_urls=(),
            now=now - timedelta(days=31),
        )
    if bounded:
        monkeypatch.setattr(runtime_module, "EMERGING_EXPIRY_BATCHES", 1)
    assert signals_main(["--expire-due"]) == 0
    expired = 100 if bounded else 205
    overdue = 205 - expired
    status = "partial" if bounded else "complete"
    assert capsys.readouterr().out == (
        f"warning_expiry_{status} expired=1 outputs_purged=1 "
        f"emerging_expired={expired} emerging_overdue={overdue} emerging_partial={int(bounded)}\n"
    )
    with Session(database.engine) as session:
        assert overdue_lead_count(session, now=now) == overdue
        assert session.scalar(select(func.count()).select_from(EmergingLeadRecord)) == 205 + expired
        assert session.scalar(select(func.count()).select_from(WarningLaneOutputRecord)) == 0
        assert (
            session.scalar(
                select(PreliminaryWarningRecord).order_by(PreliminaryWarningRecord.revision.desc())
            ).state
            == "expired"
        )
    if bounded:
        monkeypatch.setattr(runtime_module, "EMERGING_EXPIRY_BATCHES", 10)
        assert signals_main(["--expire-due"]) == 0
        assert (
            "emerging_expired=105 emerging_overdue=0 emerging_partial=0" in capsys.readouterr().out
        )


def test_signal_expiry_time_budget_reports_undrained_v4_leads(
    database, monkeypatch, tmp_path, capsys
):
    monkeypatch.setenv(
        "SMITHGUARD_DATABASE_URL", database.url.render_as_string(hide_password=False)
    )
    monkeypatch.setenv("SMITHGUARD_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    monkeypatch.setattr(runtime_module, "EMERGING_EXPIRY_BUDGET_SECONDS", 0)
    with Session(database.engine) as session, session.begin():
        record_lead(
            session,
            candidate(),
            state="needs_enrichment",
            reason="missing_source_context",
            now=datetime.now(UTC) - timedelta(hours=25),
        )
    assert signals_main(["--expire-due"]) == 0
    assert capsys.readouterr().out == (
        "warning_expiry_partial expired=0 outputs_purged=0 "
        "emerging_expired=0 emerging_overdue=1 emerging_partial=1\n"
    )


def test_signal_expiry_failed_overdue_count_is_never_reported_as_complete(
    database, monkeypatch, tmp_path, capsys
):
    monkeypatch.setenv(
        "SMITHGUARD_DATABASE_URL", database.url.render_as_string(hide_password=False)
    )
    monkeypatch.setenv("SMITHGUARD_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    with Session(database.engine) as session, session.begin():
        record_lead(
            session,
            candidate(),
            state="unverified",
            reason="attributable_security_report",
            now=datetime.now(UTC) - timedelta(hours=25),
        )

    def fail_count(*_args, **_kwargs):
        raise RuntimeError("synthetic count timeout")

    monkeypatch.setattr(runtime_module, "overdue_lead_count", fail_count)
    assert signals_main(["--expire-due"]) == 3
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == (
        "warning_expiry_partial expired=0 outputs_purged=0 "
        "emerging_expired=1 emerging_overdue=unknown emerging_partial=1\n"
        "runtime_error:signal_operation_failed\n"
    )
    with Session(database.engine) as session:
        # Completed batches stay committed even if the closing measurement fails.
        assert overdue_lead_count(session, now=datetime.now(UTC)) == 0


def test_signal_recheck_reports_a_deliberate_policy_denial(
    enabled_warning_dispatch,
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(
        "SMITHGUARD_DATABASE_URL",
        database.url.render_as_string(hide_password=False),
    )
    monkeypatch.setenv(
        "SMITHGUARD_EVIDENCE_ROOT",
        str(tmp_path / "evidence"),
    )
    xai_key = tmp_path / "xai.key"
    xai_key.write_text("synthetic-xai-key", encoding="ascii")
    os.chmod(xai_key, 0o600)
    monkeypatch.setenv("SMITHGUARD_XAI_KEY_FILE", str(xai_key))
    monkeypatch.setenv("SMITHGUARD_SPEND_POLICY_PATH", str(DEFAULT_SPEND_POLICY))
    monkeypatch.setattr(runtime_module, "due_warning_ids", lambda *_args, **_kwargs: ("x",))

    def deny_recheck(*_args, **_kwargs):
        raise runtime_module.ExternalDispatchDisabled("synthetic policy denial")

    monkeypatch.setattr(runtime_module, "recheck_warning", deny_recheck)

    assert signals_main(["--recheck-due"]) == 4
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "policy_denied:warning_recheck_dispatch_disabled\n"


def test_update_backlogs_rotate_across_types_and_stop_at_the_budget(
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A slow backlog in every type is shared fairly and no page starts after the budget."""
    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
    )
    calls: list[tuple[str, str]] = []
    clock = [0.0]

    class SlowBacklogCollector:
        def __init__(self, *, advisory_type: str, **_kwargs: object) -> None:
            self.advisory_type = advisory_type

        def run(self, _session: Session, *, lane: str, token: str | None = None):
            calls.append((self.advisory_type, lane))
            clock[0] += 130  # each page takes most of its 120-second bound and more
            return SimpleNamespace(
                page_processed=True,
                page_source_record_count=100,
                page_normalized_record_count=100,
                collections=(),
                state="in_progress",
                has_scope_gap=False,
            )

    monkeypatch.setenv("SMITHGUARD_GITHUB_HISTORY_CUTOFF", "2026-08-31T04:08:40Z")
    monkeypatch.setattr(runtime_module, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(runtime_module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(runtime_module, "GitHubAdvisoryRestCollector", SlowBacklogCollector)
    monkeypatch.setattr(runtime_module.time, "monotonic", lambda: clock[0])

    assert collect_main() == 0
    updates = [kind for kind, lane in calls if lane == "updates"]
    assert updates[:6] == ["malware", "reviewed", "unreviewed"] * 2
    assert {kind: updates.count(kind) for kind in set(updates)} == {
        "malware": 4,
        "reviewed": 3,
        "unreviewed": 3,
    }
    # The last page started before the budget; nothing started after it.
    assert len(calls) == -(-runtime_module.COLLECTION_PAGE_BUDGET_SECONDS // 130)
    assert all(lane == "updates" for _kind, lane in calls)


def test_lock_waits_count_against_the_collection_budget(
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Reconciliation and every lock wait spend the shared budget; a wait the budget cuts
    short ends the run cleanly and no page starts after the deadline."""
    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
    )
    clock = [0.0]
    page_starts: list[float] = []
    lock_timeouts: list[float] = []
    contention = 250.0

    class Collector:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def run(self, _session: Session, *, lane: str, token: str | None = None):
            page_starts.append(clock[0])
            clock[0] += 130
            return SimpleNamespace(
                page_processed=True,
                page_source_record_count=1,
                page_normalized_record_count=1,
                collections=(),
                state="in_progress",
                has_scope_gap=False,
            )

    @contextmanager
    def contended_lock(_store, *, timeout_seconds=runtime_module.COLLECTION_LOCK_TIMEOUT_SECONDS):
        lock_timeouts.append(timeout_seconds)
        if timeout_seconds < contention:
            clock[0] += timeout_seconds
            raise runtime_module.EvidenceCollectionBusy("busy")
        clock[0] += contention
        yield

    monkeypatch.setenv("SMITHGUARD_GITHUB_HISTORY_CUTOFF", "2026-08-31T04:08:40Z")
    monkeypatch.setattr(runtime_module, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(runtime_module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(runtime_module, "GitHubAdvisoryRestCollector", Collector)
    monkeypatch.setattr(runtime_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        runtime_module.LocalImmutableEvidenceStore, "collection_lock", contended_lock
    )

    assert collect_main() == 0
    budget = runtime_module.COLLECTION_PAGE_BUDGET_SECONDS
    # Reconciliation waited 250 s inside the budget; two pages fit; the third wait was
    # cut to the remaining 190 s and ended the run exactly at the deadline.
    assert page_starts == [500.0, 880.0]
    assert lock_timeouts == [300.0, 300.0, 300.0, budget - 1010.0]
    assert clock[0] == budget


def test_rate_limit_waits_never_sleep_past_the_budget(
    database,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://guard.smithlabs.ai",
        bind_host="127.0.0.1",
        bind_port=8771,
    )
    clock = [0.0]
    sleeps: list[float] = []
    calls: list[str] = []

    class RateLimited:
        def __init__(self, *, advisory_type: str, **_kwargs: object) -> None:
            self.advisory_type = advisory_type

        def run(self, _session: Session, *, lane: str, token: str | None = None):
            calls.append(self.advisory_type)
            clock[0] += 10
            return SimpleNamespace(
                page_processed=False,
                page_source_record_count=0,
                page_normalized_record_count=0,
                collections=(),
                state="failed",
                reason_code="github_rate_limited",
                not_before=datetime.now(UTC) + timedelta(hours=1),
                has_scope_gap=False,
            )

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setenv("SMITHGUARD_GITHUB_HISTORY_CUTOFF", "2026-08-31T04:08:40Z")
    monkeypatch.setenv("SMITHGUARD_GITHUB_RATE_LIMIT_WAIT", "1")
    monkeypatch.setattr(runtime_module, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(runtime_module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(runtime_module, "GitHubAdvisoryRestCollector", RateLimited)
    monkeypatch.setattr(runtime_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(runtime_module.time, "sleep", fake_sleep)

    assert collect_main() == 0
    budget = runtime_module.COLLECTION_PAGE_BUDGET_SECONDS
    assert sleeps == [budget - 10.0]
    assert calls == ["malware"]
    assert clock[0] == budget


@pytest.mark.parametrize("authenticated", [False, True])
def test_update_burst_finishes_old_and_overlapping_current_windows(
    database, monkeypatch, tmp_path, authenticated
):
    """An 18-page burst can occur in an old window and its overlap re-read.

    A single slow segment must not starve the other two. Authenticated collection
    also has room for this burst in all three segments in the same hourly run.
    """
    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://api.smithguard.io",
        bind_host="127.0.0.1",
        bind_port=8771,
    )
    now = datetime.now(UTC)
    calls = []
    completed = {}

    class BurstCollector:
        def __init__(self, *, advisory_type, **_kwargs):
            self.kind = advisory_type
            self.pages = 0

        def run(self, _session, *, lane, token=None):
            if lane == "historical":
                return SimpleNamespace(
                    state="complete",
                    page_processed=False,
                    page_source_record_count=0,
                    page_normalized_record_count=0,
                )
            self.pages += 1
            calls.append(self.kind)
            burst = authenticated or self.kind == "unreviewed"
            old = burst and self.pages <= 18
            cutoff = now - timedelta(hours=1) if old else datetime.now(UTC)
            done = not burst or self.pages in (18, 36)
            if done:
                completed[self.kind] = cutoff
            return SimpleNamespace(
                state="complete" if done else "in_progress",
                page_processed=True,
                page_source_record_count=100,
                page_normalized_record_count=0,
                window_ended_at=cutoff,
            )

    monkeypatch.setattr(runtime_module, "load_runtime_config", lambda **_kw: config)
    monkeypatch.setattr(runtime_module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(runtime_module, "GitHubAdvisoryRestCollector", BurstCollector)
    monkeypatch.setattr(
        runtime_module, "_github_token", lambda _path: "synthetic" if authenticated else None
    )
    assert collect_main() == 0
    assert calls[:3] == ["malware", "reviewed", "unreviewed"]
    assert len(calls) == (108 if authenticated else 38)
    assert set(completed) == {"malware", "reviewed", "unreviewed"}
    assert all(cutoff >= now for cutoff in completed.values())


@pytest.mark.parametrize("authenticated,limit", [(False, 48), (True, 120)])
def test_update_attempt_budget_bounds_fast_nonterminating_pages(
    database, monkeypatch, tmp_path, authenticated, limit
):
    config = RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://api.smithguard.io",
        bind_host="127.0.0.1",
        bind_port=8771,
    )
    calls = []

    class EndlessCollector:
        def __init__(self, *, advisory_type, **_kwargs):
            self.kind = advisory_type

        def run(self, _session, *, lane, token=None):
            if lane == "updates":
                calls.append(self.kind)
            return SimpleNamespace(
                state="in_progress" if lane == "updates" else "complete",
                page_processed=lane == "updates",
                page_source_record_count=0,
                page_normalized_record_count=0,
            )

    monkeypatch.setattr(runtime_module, "load_runtime_config", lambda **_kw: config)
    monkeypatch.setattr(runtime_module, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(runtime_module, "GitHubAdvisoryRestCollector", EndlessCollector)
    monkeypatch.setattr(
        runtime_module, "_github_token", lambda _path: "synthetic" if authenticated else None
    )
    assert collect_main() == 0
    assert calls == ["malware", "reviewed", "unreviewed"] * (limit // 3)


def test_api_pressure_path_is_optional_and_absolute(monkeypatch, tmp_path):
    _base_environment(monkeypatch, tmp_path)
    monkeypatch.delenv("SMITHGUARD_API_PRESSURE_PATH", raising=False)
    assert load_runtime_config().api_pressure_path is None
    path = tmp_path / "latest.json"
    monkeypatch.setenv("SMITHGUARD_API_PRESSURE_PATH", str(path))
    assert load_runtime_config().api_pressure_path == path
    monkeypatch.setenv("SMITHGUARD_API_PRESSURE_PATH", "relative.json")
    with pytest.raises(RuntimeConfigurationError):
        load_runtime_config()


def test_direct_recheck_start_while_paused_does_not_load_credentials(monkeypatch, capsys):
    from smithguard.warning_dispatch import DISPATCH_FLAG

    monkeypatch.delenv(DISPATCH_FLAG, raising=False)

    def forbidden(*args, **kwargs):
        raise AssertionError("paused recheck must not load provider configuration")

    monkeypatch.setattr(runtime_module, "load_runtime_config", forbidden)
    assert signals_main(["--recheck-due"]) == 0
    assert "contained=1" in capsys.readouterr().out
