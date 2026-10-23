"""The manual reconciliation command stays bounded, resumable, and fail closed."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard import reconciliation_runtime as runtime
from smithguard.acquisition import AcquisitionRejected, OperationDeadline
from smithguard.collectors import GITHUB_ADVISORY
from smithguard.db.models import (
    CollectorProgressRecord,
    EvidenceFinalizationRecord,
    SourceReconciliationRunRecord,
)
from smithguard.db.repository import append_contract
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.evidence_finalization import register_evidence_stage
from smithguard.identifiers import canonical_json_bytes, sha256_id, stable_id, timestamp
from smithguard.normalization import NormalizationRejected
from smithguard.reconciliation import HistoricalAuthorityReport
from smithguard.retained_replay import RetainedReplayReport

from .governance_fixtures import active_governance_policy

NOW = datetime(2026, 8, 9, 6, 0, tzinfo=UTC)
CUTOFF = NOW - timedelta(minutes=1)


def test_latest_evidence_state_uses_the_newest_revision(
    database,
    contract_examples: list[dict],
) -> None:
    evidence = next(
        deepcopy(entry["value"])
        for entry in contract_examples
        if entry["definition"] == "RawEvidence"
    )
    newer = deepcopy(evidence)
    newer.update(
        {
            "revision": 2,
            "updated_at": "2026-08-05T00:01:00Z",
            "storage_state": "quarantined",
            "rights_decision": "quarantined",
            "quarantine_reasons": ["synthetic_revision_test"],
        }
    )

    with Session(database.engine) as session, session.begin():
        append_contract(session, "RawEvidence", evidence, storage_key=evidence["sha256"])
        append_contract(session, "RawEvidence", newer)

    with Session(database.engine) as session:
        assert runtime._latest_evidence_state(session, evidence["id"]) == "quarantined"


def _advisory(
    advisory_id: str = "GHSA-aaaa-bbbb-1111",
    *,
    ecosystem: str = "npm",
    updated_at: datetime = CUTOFF,
) -> dict:
    return {
        "ghsa_id": advisory_id,
        "type": "malware",
        "published_at": "2026-08-01T00:00:00Z",
        "updated_at": timestamp(updated_at),
        "withdrawn_at": None,
        "html_url": f"https://github.com/advisories/{advisory_id}",
        "identifiers": [{"type": "GHSA", "value": advisory_id}],
        "references": [],
        "vulnerabilities": [
            {
                "package": {"ecosystem": ecosystem, "name": advisory_id.lower()},
                "vulnerable_version_range": "= 1.0.0",
            }
        ],
    }


def _client(
    body: bytes,
    *,
    headers: dict[str, str] | None = None,
    status: int = 200,
    inspect_request=None,
) -> httpx.Client:
    def transport(request: httpx.Request) -> httpx.Response:
        if inspect_request is not None:
            inspect_request(request)
        return httpx.Response(
            status,
            headers={"content-type": "application/json", **(headers or {})},
            content=body,
            request=request,
        )

    return httpx.Client(transport=httpx.MockTransport(transport), follow_redirects=False)


def test_inventory_page_projects_only_the_exact_publication_scope() -> None:
    body = json.dumps([_advisory(), _advisory("GHSA-cccc-dddd-2222", ecosystem="swift")]).encode()
    with _client(body) as client:
        page = runtime.fetch_github_inventory_page(
            client=client,
            cutoff=CUTOFF,
            now=NOW,
        )
    assert [item.source_record_id for item in page.observations] == ["GHSA-aaaa-bbbb-1111"]
    assert page.excluded_advisory_count == 1
    assert page.excluded_entry_count == 1
    assert not page.has_more


@pytest.mark.parametrize("expression", ["> 0", "<= 1.3"])
def test_inventory_page_reports_supported_range_ids_for_private_backfill(expression) -> None:
    advisory = _advisory()
    advisory["vulnerabilities"][0]["vulnerable_version_range"] = expression
    with _client(json.dumps([advisory]).encode()) as client:
        page = runtime.fetch_github_inventory_page(
            client=client,
            cutoff=CUTOFF,
            now=NOW,
        )
    assert page.range_advisory_ids == ("GHSA-aaaa-bbbb-1111",)
    assert page.excluded_entry_count == 0


def test_inventory_does_not_misclassify_partial_exact_entries_as_ranges() -> None:
    advisory = _advisory()
    advisory["vulnerabilities"][0]["vulnerable_version_range"] = "= 1.2"
    with _client(json.dumps([advisory]).encode()) as client:
        page = runtime.fetch_github_inventory_page(
            client=client,
            cutoff=CUTOFF,
            now=NOW,
        )
    assert page.range_advisory_ids == ()
    assert [item.source_record_id for item in page.observations] == ["GHSA-aaaa-bbbb-1111"]


@pytest.mark.parametrize(
    "reference",
    [
        "http://example.com/inventory-exclusion",
        "https://user@example.com/inventory-exclusion",
        "https://example.com:444/inventory-exclusion",
        "https:///inventory-exclusion",
        "https://example.com:invalid/inventory-exclusion",
        "x" * 2049,
        None,
        42,
    ],
)
def test_inventory_page_excludes_only_the_advisory_with_an_invalid_reference(
    reference: object,
) -> None:
    excluded = _advisory("GHSA-aaaa-bbbb-1111")
    excluded["references"] = [reference]
    retained = _advisory("GHSA-cccc-dddd-2222")
    body = json.dumps([excluded, retained]).encode()

    with _client(body) as client:
        page = runtime.fetch_github_inventory_page(
            client=client,
            cutoff=CUTOFF,
            now=NOW,
        )

    assert [item.source_record_id for item in page.observations] == ["GHSA-cccc-dddd-2222"]
    assert page.excluded_advisory_count == 1
    assert page.excluded_entry_count == 1
    assert not page.has_more


def test_inventory_page_retains_an_advisory_with_a_unicode_reference() -> None:
    advisory = _advisory()
    advisory["references"] = [
        "https://example.com/non-ascii-\u00e9",
        "https://example.com/non-ascii-%C3%A9",
    ]
    with _client(json.dumps([advisory]).encode()) as client:
        page = runtime.fetch_github_inventory_page(
            client=client,
            cutoff=CUTOFF,
            now=NOW,
        )
    assert [item.source_record_id for item in page.observations] == ["GHSA-aaaa-bbbb-1111"]
    assert page.excluded_advisory_count == 0
    assert page.excluded_entry_count == 0


@pytest.mark.parametrize(
    "references",
    [
        {"not": "a-list"},
        "not-a-list",
    ],
)
def test_inventory_page_keeps_non_list_reference_containers_fail_closed(
    references: object,
) -> None:
    advisory = _advisory()
    advisory["references"] = references

    with (
        _client(json.dumps([advisory]).encode()) as client,
        pytest.raises(NormalizationRejected, match="invalid_github_references"),
    ):
        runtime.fetch_github_inventory_page(
            client=client,
            cutoff=CUTOFF,
            now=NOW,
        )


def test_inventory_page_treats_official_null_references_as_empty() -> None:
    advisory = _advisory()
    advisory["references"] = None
    with _client(json.dumps([advisory]).encode()) as client:
        page = runtime.fetch_github_inventory_page(
            client=client,
            cutoff=CUTOFF,
            now=NOW,
        )
    assert [item.source_record_id for item in page.observations] == [advisory["ghsa_id"]]


def test_inventory_page_includes_a_valid_high_reference_advisory() -> None:
    advisory = _advisory()
    advisory["references"] = [
        f"https://example.com/inventory-reference/{index}" for index in range(150)
    ]

    with _client(json.dumps([advisory]).encode()) as client:
        page = runtime.fetch_github_inventory_page(
            client=client,
            cutoff=CUTOFF,
            now=NOW,
        )

    assert [item.source_record_id for item in page.observations] == [advisory["ghsa_id"]]
    assert page.excluded_advisory_count == 0
    assert page.excluded_entry_count == 0


@pytest.mark.parametrize("reference_count", [1_001, 1_500])
def test_inventory_page_excludes_an_over_limit_reference_list_and_keeps_safe_siblings(
    reference_count: int,
) -> None:
    excluded = _advisory("GHSA-aaaa-bbbb-1111")
    excluded["references"] = [
        f"https://example.com/inventory-reference/{index}" for index in range(reference_count)
    ]
    retained = _advisory("GHSA-cccc-dddd-2222")

    with _client(json.dumps([excluded, retained]).encode()) as client:
        page = runtime.fetch_github_inventory_page(
            client=client,
            cutoff=CUTOFF,
            now=NOW,
        )

    assert [item.source_record_id for item in page.observations] == ["GHSA-cccc-dddd-2222"]
    assert page.excluded_advisory_count == 1
    assert page.excluded_entry_count == 1
    assert not page.has_more


def test_inventory_page_uses_optional_bearer_without_changing_fixed_query() -> None:
    seen: dict[str, str] = {}

    def inspect(request: httpx.Request) -> None:
        seen["authorization"] = request.headers["authorization"]
        seen["url"] = str(request.url)

    with _client(json.dumps([_advisory()]).encode(), inspect_request=inspect) as client:
        runtime.fetch_github_inventory_page(
            client=client,
            cutoff=CUTOFF,
            token="synthetic-token-value",
            now=NOW,
        )
    assert seen["authorization"] == "Bearer synthetic-token-value"
    parsed = httpx.URL(seen["url"])
    assert dict(parsed.params) == {
        "type": "malware",
        "sort": "updated",
        "direction": "asc",
        "per_page": "100",
        "updated": "<=2026-08-09T05:59:00Z",
    }


def test_inventory_page_accepts_only_an_exact_next_link() -> None:
    parameters = runtime._inventory_parameters(
        cutoff=CUTOFF,
        cursor_parameter=None,
        cursor_value=None,
    )
    next_url = runtime._inventory_endpoint({**parameters, "after": "next-page"})
    with _client(
        json.dumps([_advisory()]).encode(),
        headers={"link": f'<{next_url}>; rel="next"'},
    ) as client:
        page = runtime.fetch_github_inventory_page(
            client=client,
            cutoff=CUTOFF,
            now=NOW,
        )
    assert page.continuation_parameter == "after"
    assert page.continuation_value == "next-page"
    assert page.has_more

    changed = next_url.replace("type=malware", "type=reviewed")
    with (
        _client(
            json.dumps([_advisory()]).encode(),
            headers={"link": f'<{changed}>; rel="next"'},
        ) as client,
        pytest.raises(runtime.ReconciliationRuntimeError, match="fixed parameters"),
    ):
        runtime.fetch_github_inventory_page(client=client, cutoff=CUTOFF, now=NOW)


@pytest.mark.parametrize(
    ("body", "match"),
    [
        (b'[{"type":"malware","type":"reviewed"}]', "duplicate JSON key"),
        (b"{}", "page shape"),
        (json.dumps([{**_advisory(), "type": "reviewed"}]).encode(), "non-malware"),
        (
            json.dumps([_advisory(updated_at=NOW + timedelta(minutes=1))]).encode(),
            "fixed cutoff",
        ),
    ],
)
def test_inventory_page_rejects_unsafe_provider_shapes(body: bytes, match: str) -> None:
    with _client(body) as client, pytest.raises(runtime.ReconciliationRuntimeError, match=match):
        runtime.fetch_github_inventory_page(client=client, cutoff=CUTOFF, now=NOW)


def test_inventory_page_defers_without_parsing_a_rate_limited_body() -> None:
    reset = int((NOW + timedelta(minutes=10)).timestamp())
    with (
        _client(
            b"not-json",
            status=403,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(reset)},
        ) as client,
        pytest.raises(runtime.ReconciliationDeferred) as raised,
    ):
        runtime.fetch_github_inventory_page(client=client, cutoff=CUTOFF, now=NOW)
    assert raised.value.not_before == NOW + timedelta(minutes=10)


def test_inventory_page_rejects_a_non_success_status_and_encoded_body() -> None:
    with (
        _client(json.dumps([_advisory()]).encode(), status=201) as client,
        pytest.raises(
            runtime.ReconciliationRuntimeError,
            match="status",
        ),
    ):
        runtime.fetch_github_inventory_page(client=client, cutoff=CUTOFF, now=NOW)
    with (
        _client(
            json.dumps([_advisory()]).encode(),
            headers={"content-encoding": "gzip"},
        ) as client,
        pytest.raises(runtime.ReconciliationRuntimeError, match="encoding|request failed"),
    ):
        runtime.fetch_github_inventory_page(client=client, cutoff=CUTOFF, now=NOW)


def test_cutoff_and_continuation_are_narrow() -> None:
    assert runtime._validated_cutoff(timestamp(CUTOFF), now=NOW) == CUTOFF
    with pytest.raises(runtime.ReconciliationRuntimeError, match="allowed window"):
        runtime._validated_cutoff(timestamp(NOW + timedelta(seconds=1)), now=NOW)
    with pytest.raises(runtime.ReconciliationRuntimeError, match="allowed window"):
        runtime._validated_cutoff(timestamp(NOW - timedelta(days=2)), now=NOW)
    assert runtime._cursor_pair("after", "opaque-next") == "after:opaque-next"
    with pytest.raises(runtime.ReconciliationRuntimeError, match="incomplete"):
        runtime._cursor_pair("after", None)
    with pytest.raises(runtime.ReconciliationRuntimeError, match="value"):
        runtime._cursor_pair("after", "has whitespace")
    for unsafe in ("semi;colon", "$(command)", "`command`", '"quoted"'):
        with pytest.raises(runtime.ReconciliationRuntimeError, match="value"):
            runtime._cursor_pair("after", unsafe)


def _progress(
    *,
    terminal: bool,
    occurred_at: datetime = CUTOFF,
    sequence: int = 1,
    suffix: str = "base",
) -> CollectorProgressRecord:
    values = {
        "progress_event_id": (
            f"gbsec:collector-progress:github-terminal:{suffix}"
            if terminal
            else f"gbsec:collector-progress:github-in-progress:{suffix}"
        ),
        "source_id": GITHUB_ADVISORY,
        "lane": "historical",
        "sequence": sequence,
        "state": "complete" if terminal else "in_progress",
        "cursor_value": None if terminal else "next",
        "cursor_parameter": None if terminal else "after",
        "page_count": 1,
        "source_record_count": 1,
        "normalized_record_count": 1,
        "window_started_at": None,
        "window_ended_at": None,
        "oldest_published_at": occurred_at,
        "newest_published_at": occurred_at,
        "not_before": None,
        "reason_code": "github_lane_complete" if terminal else "github_page_accepted",
        "occurred_at": occurred_at,
    }
    return CollectorProgressRecord(
        **values,
        record_hash=sha256_id(
            canonical_json_bytes(
                {
                    **values,
                    "oldest_published_at": timestamp(occurred_at),
                    "newest_published_at": timestamp(occurred_at),
                    "occurred_at": timestamp(occurred_at),
                }
            )
        ),
    )


def test_terminal_history_gate_rejects_an_open_cursor(database) -> None:
    with Session(database.engine) as session, session.begin():
        session.add(_progress(terminal=False))
    with (
        Session(database.engine) as session,
        pytest.raises(
            runtime.ReconciliationRuntimeError,
            match="not terminal",
        ),
    ):
        runtime._terminal_history(session)


def test_terminal_history_gate_accepts_an_exact_terminal_record(database) -> None:
    with Session(database.engine) as session, session.begin():
        session.add(_progress(terminal=True))
    with Session(database.engine) as session:
        assert runtime._terminal_history(session).reason_code == "github_lane_complete"


@pytest.mark.audit_ids("COL-15")
def test_github_token_requires_an_absolute_private_regular_file(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = tmp_path / "github.token"
    token.write_text("synthetic-token-value\n", encoding="ascii")
    token.chmod(0o600)
    monkeypatch.setenv("SMITHGUARD_GITHUB_TOKEN_FILE", str(token))
    assert runtime._github_token() == "synthetic-token-value"
    token.chmod(0o644)
    with pytest.raises(runtime.RuntimeConfigurationError, match="permissions"):
        runtime._github_token()


def test_parser_keeps_database_writes_explicit() -> None:
    inventory = runtime._parser().parse_args(
        [
            "github-inventory",
            "--inventory-run-id",
            "gbsec:source-inventory-run:test",
            "--page-index",
            "1",
            "--cutoff",
            timestamp(CUTOFF),
        ]
    )
    authority = runtime._parser().parse_args(["historical-authority"])
    retained = runtime._parser().parse_args(
        [
            "retained-github-replay",
            "--inventory-run-id",
            "gbsec:source-inventory-run:test",
        ]
    )
    backfill = runtime._parser().parse_args(
        ["github-range-backfill", "--advisory-id", "GHSA-aaaa-bbbb-1111"]
    )
    missing = runtime._parser().parse_args(["provider-missing-review"])
    assert not inventory.commit
    assert not authority.apply
    assert retained.limit == 100
    assert not retained.commit
    assert not backfill.commit
    assert missing.limit == 100


def test_provider_missing_review_is_bounded_aggregate_only_and_read_only(
    database,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_id = "GHSA-aaaa-bbbb-1111"
    values = {
        "reconciliation_event_id": stable_id("source-reconciliation", "missing-review"),
        "inventory_run_id": stable_id("source-inventory-run", "missing-review"),
        "source_id": GITHUB_ADVISORY,
        "connector_id": "gbsec:connector:github-advisory-rest",
        "sequence": 1,
        "page_index": 1,
        "state": "unresolved",
        "complete_inventory": True,
        "scanned_count": 1,
        "observed_count": 1,
        "observed_record_ids": ["GHSA-cccc-dddd-2222"],
        "late_record_ids": [],
        "modified_record_ids": [],
        "deleted_record_ids": [],
        "missing_record_ids": [missing_id],
        "unresolved_record_ids": [missing_id],
        "drift_truncated": False,
        "continuation_in_hash": None,
        "continuation_out_hash": None,
        "has_more": False,
        "policy_id": "gbsec:source-governance-policy:phase-0a-v1",
        "policy_sha256": sha256_id(b"policy"),
        "observation_sha256": sha256_id(b"observation"),
        "reason_code": "inventory_drift_detected",
        "reconciled_at": CUTOFF,
        "next_due_at": CUTOFF + timedelta(days=1),
        "record_hash": sha256_id(b"record"),
    }
    with Session(database.engine) as session, session.begin():
        session.add(SourceReconciliationRunRecord(**values))
    config = SimpleNamespace(
        database_url=database.url.render_as_string(hide_password=False),
    )
    monkeypatch.setattr(runtime, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(runtime, "_engine", lambda _config: database.engine)
    arguments = runtime._parser().parse_args(["provider-missing-review", "--limit", "1"])
    assert runtime._provider_missing_main(arguments) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "read_only"
    assert output["provider_missing_count"] == 1
    assert output["classification_counts"] == {"no_public_link": 1}
    assert output["apply_allowed"] is False
    assert missing_id not in json.dumps(output)
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(SourceReconciliationRunRecord)) == 1


def _patch_runtime_database(
    monkeypatch: pytest.MonkeyPatch,
    *,
    database,
    tmp_path,
) -> list[str]:
    evidence = tmp_path / "evidence"
    evidence.mkdir(exist_ok=True)
    evidence.chmod(0o750)
    config = SimpleNamespace(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=evidence,
        rights_register_path=tmp_path / "rights.json",
        governance_policy_path=tmp_path / "governance.json",
        authority_policy_path=tmp_path / "authority.json",
    )
    policy = active_governance_policy()
    registry = SimpleNamespace(register_id="gbsec:rights-register:phase-0a-v1")
    calls: list[str] = []
    monkeypatch.setattr(runtime, "load_runtime_config", lambda **_kwargs: config)
    monkeypatch.setattr(runtime, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(runtime.RightsRegistry, "from_path", lambda _path: registry)
    monkeypatch.setattr(
        runtime.SourceGovernancePolicy,
        "from_path",
        lambda _path, *, registry: policy,
    )
    monkeypatch.setattr(
        runtime,
        "_validate_source_history",
        lambda _session, _registry: calls.append("source_history"),
    )
    return calls


def test_inventory_orchestration_rolls_back_then_commits_one_exact_page(
    database,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cutoff = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=1)
    with Session(database.engine) as session, session.begin():
        session.add(
            _progress(
                terminal=True,
                occurred_at=cutoff - timedelta(minutes=1),
                suffix="inventory-main",
            )
        )
    source_history_calls = _patch_runtime_database(
        monkeypatch,
        database=database,
        tmp_path=tmp_path,
    )
    monkeypatch.setattr(runtime, "_github_token", lambda: None)
    monkeypatch.setattr(
        runtime,
        "fetch_github_inventory_page",
        lambda **_kwargs: runtime.GitHubInventoryPage(
            observations=(),
            continuation_parameter=None,
            continuation_value=None,
            excluded_advisory_count=0,
            excluded_entry_count=0,
        ),
    )
    base_arguments = [
        "github-inventory",
        "--inventory-run-id",
        "gbsec:source-inventory-run:orchestration-test",
        "--page-index",
        "1",
        "--cutoff",
        timestamp(cutoff),
    ]
    assert runtime._inventory_main(runtime._parser().parse_args(base_arguments)) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["mode"] == "rollback_preview"
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(SourceReconciliationRunRecord)) == 0

    assert runtime._inventory_main(runtime._parser().parse_args([*base_arguments, "--commit"])) == 0
    committed = json.loads(capsys.readouterr().out)
    assert committed["mode"] == "commit"
    assert committed["state"] == "complete"
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(SourceReconciliationRunRecord)) == 1
        runtime._validate_inventory_continuation(
            session,
            inventory_run_id="gbsec:source-inventory-run:orchestration-test",
            page_index=2,
            cutoff=cutoff,
        )
        with pytest.raises(runtime.ReconciliationRuntimeError, match="cutoff changed"):
            runtime._validate_inventory_continuation(
                session,
                inventory_run_id="gbsec:source-inventory-run:orchestration-test",
                page_index=2,
                cutoff=cutoff + timedelta(seconds=1),
            )
    assert source_history_calls == ["source_history"] * 4


@pytest.mark.parametrize("segment", [None, "malware", "reviewed", "unreviewed"])
def test_range_backfill_orchestration_previews_then_commits_the_same_bounded_ids(
    segment,
    database,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_history_calls = _patch_runtime_database(
        monkeypatch,
        database=database,
        tmp_path=tmp_path,
    )
    monkeypatch.setattr(runtime, "_github_token", lambda: None)
    monkeypatch.setattr(runtime, "load_authority_policy", lambda _path: object())

    calls: list[str] = []

    class Collector:
        def __init__(self, **_kwargs: object) -> None:
            assert _kwargs["advisory_type"] == (segment or "legacy-malware")
            assert _kwargs["catalog_mode"] is (segment is not None)

        def backfill_advisory(
            self,
            _session: Session,
            *,
            advisory_id: str,
            token: str | None,
            deadline,
        ) -> SimpleNamespace:
            assert token is None
            calls.append(advisory_id)
            return SimpleNamespace(
                collection=SimpleNamespace(outcome=SimpleNamespace(record_count=1)),
                scope_exclusion_reasons=(),
                catalog_package_entry_count=2,
                catalog_append_result=SimpleNamespace(
                    catalog_event_id="gbsec:advisory-catalog:test",
                    revision=2,
                    created=True,
                    source_sha256="sha256:" + "a" * 64,
                ),
            )

    monkeypatch.setattr(runtime, "GitHubAdvisoryRestCollector", Collector)

    def publish(*_args, **_kwargs):
        assert segment is None, "catalog repair must not publish legacy incidents"
        return ({"id": "gbsec:incident:range-backfill"},)

    monkeypatch.setattr(runtime, "publish_github_malware_incidents", publish)
    arguments = [
        "github-range-backfill",
        "--advisory-id",
        "GHSA-aaaa-bbbb-1111",
        "--advisory-id",
        "GHSA-cccc-dddd-2222",
    ]
    if segment is not None:
        arguments += ["--catalog-segment", segment]
    assert runtime._range_backfill_main(runtime._parser().parse_args(arguments)) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["mode"] == "rollback_preview"
    assert preview["normalized_record_count"] == 2
    assert preview["published_incident_count"] == (2 if segment is None else 0)
    assert preview["catalog_segment"] == segment
    if segment is not None:
        assert len(preview["catalog_revisions"]) == 2
        assert all(
            r["created"] is True and r["revision"] == 2 for r in preview["catalog_revisions"]
        )
    else:
        assert preview["catalog_revisions"] == []
    assert preview["catalog_package_entry_count"] == (0 if segment is None else 4)
    assert preview["scope_exclusion_counts"] == {}

    assert runtime._range_backfill_main(runtime._parser().parse_args([*arguments, "--commit"])) == 0
    committed = json.loads(capsys.readouterr().out)
    assert committed["mode"] == "commit"
    assert calls == [
        "GHSA-aaaa-bbbb-1111",
        "GHSA-cccc-dddd-2222",
        "GHSA-aaaa-bbbb-1111",
        "GHSA-cccc-dddd-2222",
    ]
    assert source_history_calls == ["source_history", "source_history"]


def test_range_backfill_failure_rolls_back_staged_evidence(
    database,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_history_calls = _patch_runtime_database(
        monkeypatch,
        database=database,
        tmp_path=tmp_path,
    )
    monkeypatch.setattr(runtime, "_github_token", lambda: None)
    monkeypatch.setattr(runtime, "load_authority_policy", lambda _path: object())

    class Collector:
        def __init__(self, *, evidence_store, **_kwargs: object) -> None:
            self.evidence_store = evidence_store

        def backfill_advisory(
            self,
            session: Session,
            *,
            advisory_id: str,
            token: str | None,
            deadline,
        ) -> SimpleNamespace:
            assert token is None
            if advisory_id == "GHSA-cccc-dddd-2222":
                assert len(self.evidence_store.pending_manifest()) == 1
                raise runtime.ReconciliationError("source member identity conflicts with history")
            body = b"staged before a later advisory fails"
            stage = self.evidence_store.stage_bytes(body)
            register_evidence_stage(
                session,
                store=self.evidence_store,
                stage=stage,
                evidence_id=stable_id("evidence", stage.digest),
                staged_at=NOW,
            )
            return SimpleNamespace(
                collection=SimpleNamespace(outcome=SimpleNamespace(record_count=1)),
                scope_exclusion_reasons=(),
            )

    monkeypatch.setattr(runtime, "GitHubAdvisoryRestCollector", Collector)
    monkeypatch.setattr(
        runtime,
        "publish_github_malware_incidents",
        lambda *_args, **_kwargs: (),
    )
    arguments = runtime._parser().parse_args(
        [
            "github-range-backfill",
            "--advisory-id",
            "GHSA-aaaa-bbbb-1111",
            "--advisory-id",
            "GHSA-cccc-dddd-2222",
            "--commit",
        ]
    )

    with pytest.raises(
        runtime.ReconciliationError,
        match="source member identity conflicts with history",
    ):
        runtime._range_backfill_main(arguments)

    store = LocalImmutableEvidenceStore(tmp_path / "evidence", allow_group_read=True)
    assert store.pending_manifest() == []
    assert store.manifest() == []
    store.close()
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(EvidenceFinalizationRecord)) == 0
    assert source_history_calls == ["source_history"]


def test_range_backfill_uses_one_deadline_and_rolls_back_the_whole_expired_batch(
    database, tmp_path, monkeypatch
):
    _patch_runtime_database(monkeypatch, database=database, tmp_path=tmp_path)
    monkeypatch.setattr(runtime, "_github_token", lambda: None)
    monkeypatch.setattr(runtime, "load_authority_policy", lambda _path: object())
    elapsed = [0.0]
    shared = OperationDeadline(deadline=120.0, clock=lambda: elapsed[0])
    monkeypatch.setattr(runtime.OperationDeadline, "start", lambda seconds: shared)
    calls = []

    class Collector:
        def __init__(self, *, evidence_store, **_kwargs):
            self.store = evidence_store

        def backfill_advisory(self, session, *, advisory_id, token, deadline):
            assert deadline is shared
            deadline.check()
            calls.append(advisory_id)
            stage = self.store.stage_bytes(advisory_id.encode())
            register_evidence_stage(
                session,
                store=self.store,
                stage=stage,
                evidence_id=stable_id("evidence", stage.digest),
                staged_at=NOW,
            )
            elapsed[0] += 70.0
            return SimpleNamespace(
                collection=SimpleNamespace(outcome=SimpleNamespace(record_count=1)),
                scope_exclusion_reasons=(),
            )

    monkeypatch.setattr(runtime, "GitHubAdvisoryRestCollector", Collector)
    monkeypatch.setattr(runtime, "publish_github_malware_incidents", lambda *args, **kwargs: ())
    ids = ["GHSA-aaaa-bbbb-1111", "GHSA-cccc-dddd-2222", "GHSA-eeee-ffff-3333"]
    args = ["github-range-backfill", "--commit"]
    for advisory_id in ids:
        args.extend(["--advisory-id", advisory_id])
    with pytest.raises(AcquisitionRejected, match="operation_time_limit"):
        runtime._range_backfill_main(runtime._parser().parse_args(args))
    assert calls == ids[:2]
    store = LocalImmutableEvidenceStore(tmp_path / "evidence", allow_group_read=True)
    try:
        with store.collection_lock(timeout_seconds=0):
            assert store.manifest() == store.pending_manifest() == []
        with Session(database.engine) as session:
            assert session.scalar(select(func.count()).select_from(EvidenceFinalizationRecord)) == 0
    finally:
        store.close()


def test_range_backfill_commit_finalizes_staged_evidence(
    database,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_history_calls = _patch_runtime_database(
        monkeypatch,
        database=database,
        tmp_path=tmp_path,
    )
    monkeypatch.setattr(runtime, "_github_token", lambda: None)
    monkeypatch.setattr(runtime, "load_authority_policy", lambda _path: object())

    class Collector:
        def __init__(self, *, evidence_store, **_kwargs: object) -> None:
            self.evidence_store = evidence_store

        def backfill_advisory(
            self,
            session: Session,
            *,
            advisory_id: str,
            token: str | None,
            deadline,
        ) -> SimpleNamespace:
            assert advisory_id == "GHSA-aaaa-bbbb-1111"
            assert token is None
            body = b"committed range backfill evidence"
            stage = self.evidence_store.stage_bytes(body)
            register_evidence_stage(
                session,
                store=self.evidence_store,
                stage=stage,
                evidence_id=stable_id("evidence", stage.digest),
                staged_at=NOW,
            )
            return SimpleNamespace(
                collection=SimpleNamespace(outcome=SimpleNamespace(record_count=1)),
                scope_exclusion_reasons=(),
            )

    monkeypatch.setattr(runtime, "GitHubAdvisoryRestCollector", Collector)
    monkeypatch.setattr(
        runtime,
        "publish_github_malware_incidents",
        lambda *_args, **_kwargs: (),
    )

    result = runtime._range_backfill_main(
        runtime._parser().parse_args(
            [
                "github-range-backfill",
                "--advisory-id",
                "GHSA-aaaa-bbbb-1111",
                "--commit",
            ]
        )
    )

    assert result == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "commit"
    store = LocalImmutableEvidenceStore(tmp_path / "evidence", allow_group_read=True)
    assert store.pending_manifest() == []
    assert len(store.manifest()) == 1
    store.close()
    with Session(database.engine) as session:
        finalization = session.scalar(select(EvidenceFinalizationRecord))
        assert finalization is not None
        assert finalization.state == "finalized"
    assert source_history_calls == ["source_history"]


def test_authority_orchestration_dry_run_rolls_back_and_apply_commits(
    database,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cutoff = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=1)
    with Session(database.engine) as session, session.begin():
        session.add(
            _progress(
                terminal=True,
                occurred_at=cutoff,
                suffix="authority-main",
            )
        )
    source_history_calls = _patch_runtime_database(
        monkeypatch,
        database=database,
        tmp_path=tmp_path,
    )
    monkeypatch.setattr(
        runtime,
        "load_authority_policy",
        lambda _path: SimpleNamespace(
            source_rights_register_id="gbsec:rights-register:phase-0a-v1"
        ),
    )
    apply_values: list[bool] = []

    def reconcile(session: Session, *, apply: bool, **_kwargs) -> HistoricalAuthorityReport:
        apply_values.append(apply)
        session.add(
            _progress(
                terminal=True,
                occurred_at=cutoff,
                sequence=2,
                suffix="authority-marker",
            )
        )
        return HistoricalAuthorityReport(
            mode="apply" if apply else "dry_run",
            scanned_count=1,
            eligible_count=1,
            changed_count=int(apply),
            skipped_count=0,
            items=(),
            has_more=False,
            next_after=None,
        )

    monkeypatch.setattr(runtime, "reconcile_historical_malware_authority", reconcile)
    assert runtime._authority_main(runtime._parser().parse_args(["historical-authority"])) == 0
    dry_run = json.loads(capsys.readouterr().out)
    assert dry_run["mode"] == "dry_run"
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(CollectorProgressRecord)) == 1

    assert (
        runtime._authority_main(runtime._parser().parse_args(["historical-authority", "--apply"]))
        == 0
    )
    applied = json.loads(capsys.readouterr().out)
    assert applied["mode"] == "apply"
    assert applied["changed_count"] == 1
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(CollectorProgressRecord)) == 2
    assert apply_values == [False, True]
    assert source_history_calls == ["source_history", "source_history"]


def test_retained_replay_orchestration_rolls_back_then_commits_without_network(
    database,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cutoff = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=1)
    with Session(database.engine) as session, session.begin():
        session.add(
            _progress(
                terminal=True,
                occurred_at=cutoff,
                suffix="retained-main",
            )
        )
    source_history_calls = _patch_runtime_database(
        monkeypatch,
        database=database,
        tmp_path=tmp_path,
    )
    monkeypatch.setattr(
        runtime,
        "load_authority_policy",
        lambda _path: SimpleNamespace(
            source_rights_register_id="gbsec:rights-register:phase-0a-v1"
        ),
    )
    monkeypatch.setattr(
        runtime,
        "_github_token",
        lambda: pytest.fail("retained replay must not read a GitHub token"),
    )
    monkeypatch.setattr(
        runtime,
        "fetch_github_inventory_page",
        lambda **_kwargs: pytest.fail("retained replay must not call GitHub"),
    )
    commit_values: list[bool] = []

    def replay(session: Session, *, inventory_run_id: str, **_kwargs):
        assert inventory_run_id == "gbsec:source-inventory-run:retained-main"
        commit_values.append(True)
        session.add(
            _progress(
                terminal=True,
                occurred_at=cutoff,
                sequence=2,
                suffix="retained-marker",
            )
        )
        return RetainedReplayReport(
            inventory_observation_count=10,
            eligible_candidate_count=2,
            selected_count=1,
            replayed_count=1,
            normalized_record_count=1,
            published_incident_count=1,
            has_more=True,
            next_after_evidence_id="gbsec:evidence:opaque-position",
        )

    monkeypatch.setattr(runtime, "replay_retained_github_evidence", replay)
    arguments = [
        "retained-github-replay",
        "--inventory-run-id",
        "gbsec:source-inventory-run:retained-main",
        "--limit",
        "1",
    ]
    assert runtime._retained_replay_main(runtime._parser().parse_args(arguments)) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["mode"] == "rollback_preview"
    assert preview["replayed_count"] == 1
    assert preview["next_after_evidence_id"] == "gbsec:evidence:opaque-position"
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(CollectorProgressRecord)) == 1

    assert (
        runtime._retained_replay_main(runtime._parser().parse_args([*arguments, "--commit"])) == 0
    )
    committed = json.loads(capsys.readouterr().out)
    assert committed["mode"] == "commit"
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(CollectorProgressRecord)) == 2
    assert commit_values == [True, True]
    assert source_history_calls == ["source_history", "source_history"]


def test_retained_replay_failure_rolls_back_staged_evidence(
    database,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cutoff = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=1)
    with Session(database.engine) as session, session.begin():
        session.add(
            _progress(
                terminal=True,
                occurred_at=cutoff,
                suffix="retained-failure",
            )
        )
    source_history_calls = _patch_runtime_database(
        monkeypatch,
        database=database,
        tmp_path=tmp_path,
    )
    monkeypatch.setattr(runtime, "load_authority_policy", lambda _path: object())

    def replay(session: Session, *, evidence_store, **_kwargs):
        body = b"retained replay evidence before failure"
        stage = evidence_store.stage_bytes(body)
        register_evidence_stage(
            session,
            store=evidence_store,
            stage=stage,
            evidence_id=stable_id("evidence", stage.digest),
            staged_at=NOW,
        )
        assert len(evidence_store.pending_manifest()) == 1
        raise runtime.RetainedReplayError("synthetic retained replay failure")

    monkeypatch.setattr(runtime, "replay_retained_github_evidence", replay)
    arguments = runtime._parser().parse_args(
        [
            "retained-github-replay",
            "--inventory-run-id",
            "gbsec:source-inventory-run:retained-failure",
            "--commit",
        ]
    )

    with pytest.raises(
        runtime.RetainedReplayError,
        match="synthetic retained replay failure",
    ):
        runtime._retained_replay_main(arguments)

    store = LocalImmutableEvidenceStore(tmp_path / "evidence", allow_group_read=True)
    assert store.pending_manifest() == []
    assert store.manifest() == []
    store.close()
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(EvidenceFinalizationRecord)) == 0
    assert source_history_calls == ["source_history"]


def test_main_maps_deferred_expected_and_unexpected_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def deferred(_arguments):
        raise runtime.ReconciliationDeferred(NOW + timedelta(minutes=5))

    monkeypatch.setattr(runtime, "_authority_main", deferred)
    assert runtime.main(["historical-authority"]) == 4
    assert "reconciliation_deferred" in capsys.readouterr().err

    def expected(_arguments):
        raise runtime.ReconciliationRuntimeError("synthetic expected failure")

    monkeypatch.setattr(runtime, "_authority_main", expected)
    assert runtime.main(["historical-authority"]) == 2
    assert "reconciliation_error" in capsys.readouterr().err

    def revision_conflict(_arguments):
        raise runtime.RevisionConflict("synthetic canonical revision conflict")

    monkeypatch.setattr(runtime, "_authority_main", revision_conflict)
    assert runtime.main(["historical-authority"]) == 2
    assert "synthetic canonical revision conflict" in capsys.readouterr().err

    def unexpected(_arguments):
        raise RuntimeError("synthetic unexpected failure")

    monkeypatch.setattr(runtime, "_authority_main", unexpected)
    assert runtime.main(["historical-authority"]) == 3
    assert "runtime_error:reconciliation_failed" in capsys.readouterr().err


def test_retained_replay_refuses_completion_after_a_post_commit_finalization_failure(
    database,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from smithguard.evidence import LocalImmutableEvidenceStore
    from smithguard.evidence_finalization import EvidenceFinalizationError

    cutoff = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=1)
    with Session(database.engine) as session, session.begin():
        session.add(_progress(terminal=True, occurred_at=cutoff, suffix="retained-post-commit"))
    _patch_runtime_database(monkeypatch, database=database, tmp_path=tmp_path)
    monkeypatch.setattr(runtime, "load_authority_policy", lambda _path: object())

    def replay(session: Session, *, evidence_store, **_kwargs):
        stage = evidence_store.stage_bytes(b"retained replay evidence after commit")
        register_evidence_stage(
            session,
            store=evidence_store,
            stage=stage,
            evidence_id=stable_id("evidence", stage.digest),
            staged_at=NOW,
        )
        return SimpleNamespace(inventory_observation_count=1)

    def fail_finalization(_store, _stage):
        raise OSError("raw finalization exception must remain private")

    monkeypatch.setattr(runtime, "replay_retained_github_evidence", replay)
    monkeypatch.setattr(LocalImmutableEvidenceStore, "finalize_stage", fail_finalization)
    arguments = runtime._parser().parse_args(
        [
            "retained-github-replay",
            "--inventory-run-id",
            "gbsec:source-inventory-run:retained-post-commit",
            "--commit",
        ]
    )
    with pytest.raises(EvidenceFinalizationError, match="require reconciliation"):
        runtime._retained_replay_main(arguments)
    captured = capsys.readouterr()
    assert "retained_github_replay" not in captured.out
    assert "raw finalization exception" not in captured.err
    with Session(database.engine) as session:
        record = session.scalar(select(EvidenceFinalizationRecord))
        assert record is not None and record.state == "failed"


@pytest.mark.parametrize("source", ["openssf", "rustsec", "go", "epss"])
def test_source_omissions_cli_reads_migrated_storage(database, monkeypatch, capsys, source):
    from tests.test_supplemental_store import add

    monkeypatch.setattr(runtime, "load_runtime_config", lambda: object())
    monkeypatch.setattr(runtime, "_engine", lambda _: database.engine)
    if source == "epss":
        with Session(database.engine) as session, session.begin():
            snapshot = add(session)
            snapshot_id = snapshot.snapshot_id
    args = ["source-omissions", "--source", source, "--limit", "1"]
    if source == "epss":
        args += ["--snapshot-id", snapshot_id]
    assert runtime.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["has_more"] is False and result["next_cursor"] is None
    if source == "epss":
        assert result["snapshot_id"] == snapshot_id
        assert result["identity_accounting"] == "unavailable_legacy_receipt"
    else:
        assert result["records"] == []
        assert result["historical_coverage"] == "retained_catalog_revisions_only"


@pytest.mark.parametrize(
    "source,extra",
    [
        ("openssf", ["--snapshot-id", "wrong"]),
        ("openssf", ["--limit", "0"]),
        ("openssf", ["--limit", "101"]),
        ("openssf", ["--after", "not-a-catalog-id"]),
        ("epss", ["--after", "not-a-cve"]),
        ("epss", ["--snapshot-id", "not-a-snapshot-id"]),
    ],
)
def test_source_omissions_cli_refuses_invalid_selection(
    database, monkeypatch, capsys, source, extra
):
    monkeypatch.setattr(runtime, "load_runtime_config", lambda: object())
    monkeypatch.setattr(runtime, "_engine", lambda _: database.engine)
    assert runtime.main(["source-omissions", "--source", source, *extra]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "reconciliation_error:" in captured.err
