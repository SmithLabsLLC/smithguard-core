"""Injected collectors have no default network and preserve only reviewed fields."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import httpx
import pytest
from sqlalchemy import event, func, select
from sqlalchemy.orm import Session

from smithguard.acquisition import AcquisitionRejected, OperationDeadline
from smithguard.advisory_catalog import AdvisoryCatalogStaleRevision
from smithguard.collectors import (
    COLLECTOR_SPECS,
    GITHUB_ADVISORY,
    OPENSSF_MALICIOUS,
    CollectorBoundaryError,
    CollectorRunner,
    GitHubAdvisoryRestCollector,
    TransportResponse,
    filter_github_advisory,
    transform_github_advisories,
    transform_osv_records,
)
from smithguard.coverage import build_coverage_report
from smithguard.db.models import (
    AdvisoryCatalogInventoryRecord,
    AdvisoryCatalogManifestRecord,
    AdvisoryCatalogRecord,
    AdvisoryPackageRecord,
    AffectedRangeRecord,
    ClaimRecord,
    CollectionRecordMembership,
    CollectionRecordOutcome,
    CollectorCheckpointRecord,
    CollectorProgressRecord,
    EvidenceRecord,
    IngestionBatchRecord,
    SourceGovernanceDecisionRecord,
)
from smithguard.db.repository import RevisionConflict
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.ingestion import IngestionReplayConflict, IngestionSourceError
from smithguard.normalization import NormalizationRejected
from smithguard.publication import publish_github_malware_incidents
from smithguard.source_governance import (
    DEFAULT_GOVERNANCE_POLICY_PATH,
    SourceGovernancePolicy,
)
from smithguard.source_rights import RightsRegistry

from .governance_fixtures import active_governance_policy

REPO_ROOT = Path(__file__).resolve().parents[1]
RIGHTS_REGISTER = REPO_ROOT / "contracts/v1/source-rights-register.json"
NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


class TrackingStream(httpx.SyncByteStream):
    def __init__(
        self,
        chunks: tuple[bytes, ...],
        *,
        before_yield=None,
    ) -> None:
        self.chunks = chunks
        self.before_yield = before_yield
        self.read_count = 0

    def __iter__(self):
        for chunk in self.chunks:
            if self.before_yield is not None:
                self.before_yield()
            self.read_count += 1
            yield chunk


def _osv_body(count: int = 1) -> bytes:
    return json.dumps(
        {
            "records": [
                {
                    "id": f"MAL-2026-{index + 1}",
                    "summary": "Source prose is preserved only in permitted raw evidence.",
                    "affected": [
                        {
                            "package": {"ecosystem": "npm", "name": f"package-{index}"},
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "1.0.0"},
                                        {"fixed": "1.2.0"},
                                    ],
                                }
                            ],
                        }
                    ],
                }
                for index in range(count)
            ]
        },
        sort_keys=True,
    ).encode("ascii")


def _github_advisory(
    *,
    advisory_id: str,
    name: str,
    version: str,
    published_at: str,
    updated_at: str,
    withdrawn_at: str | None = None,
) -> dict:
    return {
        "ghsa_id": advisory_id,
        "type": "malware",
        "published_at": published_at,
        "updated_at": updated_at,
        "withdrawn_at": withdrawn_at,
        "html_url": f"https://github.com/advisories/{advisory_id}",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": name},
                "vulnerable_version_range": f"= {version}",
                "first_patched_version": None,
            }
        ],
    }


def test_missing_transport_records_disabled_without_calling_external_code(
    database,
    tmp_path: Path,
) -> None:
    registry = RightsRegistry.from_path(RIGHTS_REGISTER)
    runner = CollectorRunner(
        registry=registry,
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
    )
    with Session(database.engine) as session, session.begin():
        result = runner.run_public(session, source_id=OPENSSF_MALICIOUS)
        assert result.outcome is None
        checkpoint = session.get(CollectorCheckpointRecord, result.checkpoint_event_id)
        assert checkpoint is not None
        assert checkpoint.result == "disabled"
        assert checkpoint.reason_code == "transport_not_injected"


def test_injected_public_collector_is_retry_safe_and_traceable(
    database,
    tmp_path: Path,
) -> None:
    calls: list[str | None] = []

    def transport(_spec, checkpoint):
        calls.append(checkpoint)
        return TransportResponse(
            body=_osv_body(),
            canonical_url="https://github.com/ossf/malicious-packages/synthetic.json",
            media_type="application/json",
            retrieved_at=NOW + timedelta(hours=len(calls) - 1),
            source_record_id="synthetic-github-batch-1",
            source_published_at=NOW,
            elapsed_seconds=0.125,
            checkpoint_token="synthetic-cursor-1",
        )

    evidence = LocalImmutableEvidenceStore(tmp_path / "evidence")
    runner = CollectorRunner(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence,
        transport=transport,
        governance_policy=active_governance_policy(OPENSSF_MALICIOUS),
    )
    with Session(database.engine) as session, session.begin():
        first = runner.run_public(session, source_id=OPENSSF_MALICIOUS)
        second = runner.run_public(
            session,
            source_id=OPENSSF_MALICIOUS,
            previous_checkpoint="synthetic-cursor-1",
        )
        assert first.outcome is not None and first.outcome.created
        assert second.outcome is not None and not second.outcome.created
        assert first.outcome.normalized_record_ids == second.outcome.normalized_record_ids
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 1
        assert session.scalar(select(func.count()).select_from(ClaimRecord)) == 1
        assert session.scalar(select(func.count()).select_from(CollectorCheckpointRecord)) == 2
        claim = session.scalar(select(ClaimRecord))
        assert claim is not None
        assert claim.provenance["source_record_id"] == "synthetic-github-batch-1"
    assert calls == [None, "synthetic-cursor-1"]
    assert len(evidence.manifest()) == 1


def test_collector_rejects_an_injected_off_endpoint_response(
    database,
    tmp_path: Path,
) -> None:
    def transport(_spec, _checkpoint):
        return TransportResponse(
            body=_osv_body(),
            canonical_url="https://api.github.com/users/example",
            media_type="application/json",
            retrieved_at=NOW,
            source_record_id="synthetic-wrong-endpoint",
        )

    runner = CollectorRunner(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        transport=transport,
        governance_policy=active_governance_policy(OPENSSF_MALICIOUS),
    )
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(CollectorBoundaryError, match="fixed endpoint"),
    ):
        runner.run_public(session, source_id=OPENSSF_MALICIOUS)


def test_rights_staleness_uses_the_trusted_clock_not_transport_time(
    database,
    tmp_path: Path,
) -> None:
    calls = 0

    def transport(_spec, _checkpoint):
        nonlocal calls
        calls += 1
        return TransportResponse(
            body=_osv_body(),
            canonical_url="https://github.com/ossf/malicious-packages/synthetic.json",
            media_type="application/json",
            retrieved_at=NOW,
            source_record_id="synthetic-backdated-response",
        )

    runner = CollectorRunner(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        transport=transport,
        clock=lambda: datetime(2027, 1, 1, tzinfo=UTC),
        governance_policy=active_governance_policy(OPENSSF_MALICIOUS),
    )
    with Session(database.engine) as session, session.begin():
        result = runner.run_public(session, source_id=OPENSSF_MALICIOUS)
        assert result.outcome is None
        checkpoint = session.get(CollectorCheckpointRecord, result.checkpoint_event_id)
        assert checkpoint is not None
        assert checkpoint.result == "disabled"
        assert checkpoint.reason_code == "source_governance_rejected"
    assert calls == 0


def test_public_collector_fails_closed_for_an_undeclared_parser(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def transport(_spec, _checkpoint):
        nonlocal calls
        calls += 1
        raise AssertionError("unsupported parser must fail before transport")

    monkeypatch.setitem(
        COLLECTOR_SPECS,
        OPENSSF_MALICIOUS,
        replace(COLLECTOR_SPECS[OPENSSF_MALICIOUS], parser="pypi_minimal"),
    )
    runner = CollectorRunner(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        transport=transport,
    )
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(CollectorBoundaryError, match="parser"),
    ):
        runner.run_public(session, source_id=OPENSSF_MALICIOUS)
    assert calls == 0


def test_osv_multi_interval_ranges_are_not_collapsed() -> None:
    transformed = transform_osv_records(
        (
            {
                "id": "GHSA-synthetic-multi-range",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "example"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "1.0.0"},
                                    {"fixed": "1.1.0"},
                                    {"introduced": "2.0.0"},
                                    {"fixed": "2.0.6"},
                                ],
                            }
                        ],
                    }
                ],
            },
        ),
        source_id=GITHUB_ADVISORY,
    )
    assert transformed[0]["affected_ranges"] == [
        {
            "range_type": "ECOSYSTEM",
            "expression": ">=1.0.0, <1.1.0",
            "introduced": "1.0.0",
            "fixed": "1.1.0",
            "last_affected": None,
            "evaluation_state": "supported",
        },
        {
            "range_type": "ECOSYSTEM",
            "expression": ">=2.0.0, <2.0.6",
            "introduced": "2.0.0",
            "fixed": "2.0.6",
            "last_affected": None,
            "evaluation_state": "supported",
        },
    ]


def test_openssf_exact_versions_do_not_silently_drop_nonexact_ranges() -> None:
    transformed = transform_osv_records(
        (
            {
                "id": "MAL-2026-999",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "mixed-scope"},
                        "versions": ["1.0.0"],
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "2.0.0"},
                                    {"fixed": "2.1.0"},
                                ],
                            }
                        ],
                    }
                ],
            },
        ),
        source_id=OPENSSF_MALICIOUS,
        source_url="https://github.com/ossf/malicious-packages/"
        + "blob/"
        + "a" * 40
        + "/osv/malicious/pypi/example/MAL-2026-999.json",
    )
    assert len(transformed) == 2
    assert {record["artifact"]["version"] for record in transformed} == {"1.0.0", None}
    assert {record["source_lineage"]["public_status"] for record in transformed} == {
        "confirmed",
        "reported",
    }


@pytest.mark.parametrize(
    ("provider_ecosystem", "canonical_ecosystem"),
    (
        ("pip", "pypi"),
        ("actions", "github-actions"),
        ("PyPI", "pypi"),
        ("github-actions", "github-actions"),
    ),
)
def test_github_provider_ecosystem_aliases_use_existing_canonical_scope(
    provider_ecosystem: str,
    canonical_ecosystem: str,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-alias",
        name="provider-alias-package",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"][0]["package"]["ecosystem"] = provider_ecosystem
    transformed = transform_github_advisories((filter_github_advisory(advisory),))
    assert len(transformed) == 1
    assert transformed[0]["artifact"]["ecosystem"] == canonical_ecosystem


def test_github_npm_comparator_ranges_become_one_reported_package_record() -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-range",
        name="broad-range-package",
        version="1.0.0",
        published_at="2020-01-01T00:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"] = [
        {
            "package": {"ecosystem": "npm", "name": "broad-range-package"},
            "vulnerable_version_range": "> 0",
        },
        {
            "package": {"ecosystem": "npm", "name": "broad-range-package"},
            "vulnerable_version_range": ">= 2.0.0, < 3.0.0",
        },
        {
            "package": {"ecosystem": "npm", "name": "broad-range-package"},
            "vulnerable_version_range": "= 4",
        },
    ]
    transformed = transform_github_advisories((filter_github_advisory(advisory),))
    assert len(transformed) == 2
    assert transformed[0]["artifact"] == {
        "ecosystem": "npm",
        "name": "broad-range-package",
        "version": "4",
        "digest": None,
    }
    assert transformed[0]["affected_ranges"][0]["expression"] == "4"
    assert transformed[1]["artifact"] == {
        "ecosystem": "npm",
        "name": "broad-range-package",
        "version": None,
        "digest": None,
    }
    assert [item["expression"] for item in transformed[1]["affected_ranges"]] == [
        "*",
        ">=2.0.0 <3.0.0",
    ]
    assert transformed[1]["source_lineage"]["public_status"] == "reported"
    assert transformed[1]["source_lineage"]["confirmation_reason_code"] == (
        "source_scope_not_exact"
    )


def test_github_backfill_preserves_an_expired_shared_deadline_before_network(database, tmp_path):
    requests = []

    def handler(request):
        requests.append(request)
        raise AssertionError("expired batch must not fetch another advisory")

    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    try:
        with (
            Session(database.engine) as session,
            session.begin(),
            pytest.raises(AcquisitionRejected, match="operation_time_limit"),
        ):
            collector.backfill_advisory(
                session,
                advisory_id="GHSA-aaaa-bbbb-fill",
                deadline=OperationDeadline(deadline=1.0, clock=lambda: 2.0),
            )
        assert requests == []
        assert store.pending_manifest() == []
    finally:
        store.close()


def test_github_targeted_range_backfill_is_fixed_bounded_and_does_not_move_lane_progress(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-fill",
        name="backfilled-range-package",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"][0]["vulnerable_version_range"] = "> 0"
    advisory["vulnerabilities"].append(
        {
            "package": {"ecosystem": "rubygems", "name": "unrelated-sibling"},
            "vulnerable_version_range": "> 0",
        }
    )
    advisory["references"] = ["https://example.com/context#section"]
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.backfill_advisory(
            session,
            advisory_id="GHSA-aaaa-bbbb-fill",
        )
        assert result.collection.outcome.record_count == 1
        assert result.excluded_scope_entry_count == 2
        assert result.scope_exclusion_reasons == (
            ("reference_fragment", 1),
            ("unsupported_ecosystem", 1),
        )
        published = publish_github_malware_incidents(
            session,
            collection=result.collection,
            published_at=NOW,
            governance_policy=active_governance_policy(),
        )
        assert len(published) == 1
        assert published[0]["status"] == "reported"
        repeated = collector.backfill_advisory(
            session,
            advisory_id="GHSA-aaaa-bbbb-fill",
        )
        assert not repeated.collection.outcome.created
        assert repeated.scope_exclusion_reasons == result.scope_exclusion_reasons
        repeated_publication = publish_github_malware_incidents(
            session,
            collection=repeated.collection,
            published_at=NOW,
            governance_policy=active_governance_policy(),
        )
        assert [item["id"] for item in repeated_publication] == [published[0]["id"]]
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 1
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 1
        assert session.scalar(select(func.count()).select_from(CollectorProgressRecord)) == 0
    assert len(requests) == 2
    assert dict(requests[0].url.params) == {
        "type": "malware",
        "ghsa_id": "GHSA-aaaa-bbbb-fill",
        "per_page": "1",
    }


def test_github_targeted_range_backfill_refuses_an_unsupported_npm_range(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-stop",
        name="unsupported-range-package",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"][0]["vulnerable_version_range"] = "!= 1.0.0"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(CollectorBoundaryError, match="range is not publishable"),
    ):
        collector.backfill_advisory(
            session,
            advisory_id="GHSA-aaaa-bbbb-stop",
        )


def test_github_provider_aliases_do_not_widen_the_osv_parser() -> None:
    record = json.loads(_osv_body())["records"][0]
    record["affected"][0]["package"]["ecosystem"] = "pip"
    with pytest.raises(NormalizationRejected) as raised:
        transform_osv_records((record,), source_id=GITHUB_ADVISORY)
    assert raised.value.code == "unsupported_osv_ecosystem"


def test_github_historical_backfill_resumes_provider_cursor_and_completes(
    database,
    tmp_path: Path,
) -> None:
    first_advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-0001",
        name="legacy-malware",
        version="1.0.0",
        published_at="2020-01-01T00:00:00Z",
        updated_at="2020-01-02T00:00:00Z",
    )
    second_advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-0002",
        name="older-malware",
        version="0.1.0",
        published_at="2019-01-01T00:00:00Z",
        updated_at="2019-01-02T00:00:00Z",
    )
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            next_url = (
                "https://api.github.com/advisories"
                "?type=malware&sort=published&direction=desc&per_page=100"
                "&after=cursor-one"
            )
            return httpx.Response(
                200,
                headers={
                    "content-type": "application/json",
                    "link": f'<{next_url}>; rel="next"',
                },
                json=[first_advisory],
                request=request,
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[second_advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        first = collector.run(session, lane="historical")
        assert first.state == "in_progress"
        assert first.source_record_count == 1
        assert first.normalized_record_count == 1
    with Session(database.engine) as session, session.begin():
        second = collector.run(session, lane="historical")
        assert second.state == "complete"
        assert second.source_record_count == 2
        assert second.normalized_record_count == 2
    with Session(database.engine) as session, session.begin():
        completed = collector.run(session, lane="historical")
        assert completed.state == "complete"
        assert completed.collections == ()
        progress = list(
            session.scalars(
                select(CollectorProgressRecord).order_by(CollectorProgressRecord.sequence)
            )
        )
        assert [item.state for item in progress] == ["in_progress", "complete"]
        assert progress[0].cursor_parameter == "after"
        assert progress[0].cursor_value == "cursor-one"
        assert progress[1].oldest_published_at == datetime(
            2019,
            1,
            1,
            tzinfo=UTC,
        )
    assert len(requests) == 2
    assert requests[1].url.params["after"] == "cursor-one"


def test_github_catalog_types_have_isolated_cursors_and_exact_manifests(
    database,
    tmp_path: Path,
) -> None:
    reviewed_first = _github_advisory(
        advisory_id="GHSA-2345-6789-cfgh",
        name="reviewed-one",
        version="1.0.0",
        published_at="2020-01-01T00:00:00Z",
        updated_at="2020-01-02T00:00:00Z",
    )
    reviewed_first["type"] = "reviewed"
    reviewed_first["cwes"] = [{"cwe_id": "CWE-506"}]
    reviewed_second = _github_advisory(
        advisory_id="GHSA-2345-6789-cfgj",
        name="reviewed-two",
        version="2.0.0",
        published_at="2019-01-01T00:00:00Z",
        updated_at="2019-01-02T00:00:00Z",
    )
    reviewed_second["type"] = "reviewed"
    reviewed_requests: list[httpx.Request] = []

    def reviewed_handler(request: httpx.Request) -> httpx.Response:
        reviewed_requests.append(request)
        if len(reviewed_requests) == 1:
            next_url = request.url.copy_add_param("after", "reviewed-cursor")
            return httpx.Response(
                200,
                headers={
                    "content-type": "application/json",
                    "link": f'<{next_url}>; rel="next"',
                },
                json=[reviewed_first],
                request=request,
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[reviewed_second],
            request=request,
        )

    malware_requests: list[httpx.Request] = []

    def malware_handler(request: httpx.Request) -> httpx.Response:
        malware_requests.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[],
            request=request,
        )

    common = {
        "registry": RightsRegistry.from_path(RIGHTS_REGISTER),
        "evidence_store": LocalImmutableEvidenceStore(tmp_path / "evidence"),
        "clock": lambda: NOW,
        "governance_policy": active_governance_policy(),
        "catalog_mode": True,
    }
    reviewed = GitHubAdvisoryRestCollector(
        **common,
        client=httpx.Client(transport=httpx.MockTransport(reviewed_handler)),
        advisory_type="reviewed",
    )
    malware = GitHubAdvisoryRestCollector(
        **common,
        client=httpx.Client(transport=httpx.MockTransport(malware_handler)),
        advisory_type="malware",
    )
    with Session(database.engine) as session, session.begin():
        assert reviewed.run(session, lane="historical").state == "in_progress"
    with Session(database.engine) as session, session.begin():
        assert malware.run(session, lane="historical").state == "complete"
    with Session(database.engine) as session, session.begin():
        completed = reviewed.run(session, lane="historical")
        assert completed.state == "complete"
        assert completed.source_record_count == 2
        assert completed.normalized_record_count == 2

    assert reviewed_requests[1].url.params["after"] == "reviewed-cursor"
    assert "after" not in malware_requests[0].url.params
    assert reviewed_requests[0].url.params["type"] == "reviewed"
    assert malware_requests[0].url.params["type"] == "malware"
    assert reviewed_requests[0].url.params["published"] == ("<=2026-08-05T12:00:00Z")
    with Session(database.engine) as session:
        assert session.query(AdvisoryCatalogRecord).count() == 2
        assert session.query(AdvisoryPackageRecord).count() == 2
        progress = session.query(CollectorProgressRecord).order_by(
            CollectorProgressRecord.segment,
            CollectorProgressRecord.sequence,
        )
        assert [(row.segment, row.state) for row in progress] == [
            ("malware", "complete"),
            ("reviewed", "in_progress"),
            ("reviewed", "complete"),
        ]
        manifests = session.query(AdvisoryCatalogManifestRecord).order_by(
            AdvisoryCatalogManifestRecord.segment
        )
        assert [(row.segment, row.record_count, row.package_entry_count) for row in manifests] == [
            ("malware", 0, 0),
            ("reviewed", 2, 2),
        ]


def test_github_catalog_preserves_nullable_fields_and_surfaces_other_ecosystem_gap(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-2345-6789-cfgx",
        name="nullable-catalog",
        version="1.0.0",
        published_at="2020-01-01T00:00:00Z",
        updated_at="2020-01-02T00:00:00Z",
    )
    advisory["type"] = "reviewed"
    advisory["references"] = None
    advisory["identifiers"] = None
    advisory["cwes"] = None
    advisory["vulnerabilities"] = [
        {"package": None, "vulnerable_version_range": None},
        {
            "package": {"ecosystem": "other", "name": "outside-map"},
            "vulnerable_version_range": "= 1.0.0",
        },
        {
            "package": {"ecosystem": "npm", "name": "nullable-catalog"},
            "vulnerable_version_range": None,
        },
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
        advisory_type="reviewed",
        catalog_mode=True,
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "failed"
        assert result.page_processed
        assert result.page_scope_exclusion_reasons == (
            ("missing_package", 1),
            ("missing_version_range", 1),
            ("unsupported_ecosystem", 1),
        )
        assert result.page_normalized_record_count == 1
    with Session(database.engine) as session:
        record = session.query(AdvisoryCatalogRecord).one()
        assert record.package_omission_counts == {
            "missing_package": 1,
            "missing_version_range": 1,
            "unsupported_ecosystem": 1,
        }
        assert session.query(AdvisoryPackageRecord).one().affected_ranges == []
        progress = session.query(CollectorProgressRecord).one()
        assert progress.reason_code == "github_lane_complete_with_scope_exclusion"
        assert session.query(AdvisoryCatalogManifestRecord).count() == 0


def test_github_catalog_same_advisory_converges_across_update_and_history_lanes(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-2345-6789-cfgh",
        name="cross-lane-catalog",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
        advisory_type="malware",
        catalog_mode=True,
        historical_cutoff=NOW,
    )

    with Session(database.engine) as session, session.begin():
        update = collector.run(session, lane="updates")
        assert update.state == "complete"
        assert update.page_source_record_count == 1
        assert update.page_normalized_record_count == 1

    with Session(database.engine) as session, session.begin():
        historical = collector.run(session, lane="historical")
        assert historical.state == "complete"
        assert historical.page_source_record_count == 1
        assert historical.page_normalized_record_count == 1

    with Session(database.engine) as session:
        batches = tuple(session.scalars(select(IngestionBatchRecord)))
        assert len(batches) == 2
        assert len({item.idempotency_key_hash for item in batches}) == 2
        assert len({item.governance_decision_id for item in batches}) == 2
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 1
        assert session.scalar(select(func.count()).select_from(AdvisoryCatalogRecord)) == 1
        assert session.scalar(select(func.count()).select_from(AdvisoryPackageRecord)) == 1
        assert session.scalar(select(func.count()).select_from(AdvisoryCatalogInventoryRecord)) == 1
        manifest = session.scalar(select(AdvisoryCatalogManifestRecord))
        assert manifest is not None
        assert manifest.segment == "malware"
        assert manifest.record_count == 1
        assert manifest.package_entry_count == 1
    assert len(evidence_store.manifest()) == 1


def test_github_full_page_has_a_fixed_database_statement_budget(
    database,
    tmp_path: Path,
) -> None:
    advisories = [
        _github_advisory(
            advisory_id=f"GHSA-aaaa-bbbb-{index:04d}",
            name=f"full-page-package-{index}",
            version=f"1.0.{index}",
            published_at="2026-08-05T09:00:00Z",
            updated_at="2026-08-05T11:00:00Z",
        )
        for index in range(100)
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=advisories,
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    statement_count = 0

    def count_statement(*_args) -> None:
        nonlocal statement_count
        statement_count += 1

    event.listen(database.engine, "before_cursor_execute", count_statement)
    try:
        with Session(database.engine) as session, session.begin():
            result = collector.run(session, lane="historical")
    finally:
        event.remove(database.engine, "before_cursor_execute", count_statement)
    assert result.state == "complete"
    assert result.source_record_count == 100
    assert result.normalized_record_count == 100
    assert statement_count <= 3_400


@pytest.mark.audit_ids("COL-09")
@pytest.mark.parametrize("lane", ["historical", "updates"])
@pytest.mark.parametrize(
    ("conflict", "reason_code"),
    (
        (IngestionReplayConflict("synthetic replay"), "github_advisory_replay_conflict"),
        (RevisionConflict("synthetic revision"), "github_advisory_revision_conflict"),
        (AdvisoryCatalogStaleRevision("synthetic stale"), "github_advisory_stale_revision"),
    ),
)
def test_github_advisory_persistent_conflict_is_quarantined_without_stalling_lane(
    database, tmp_path, monkeypatch, conflict, reason_code, lane
):
    requests = []
    conflicts = 0
    bad = _github_advisory(
        advisory_id="GHSA-2345-6789-cfgh",
        name="conflicting-package",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    good = [
        _github_advisory(
            advisory_id="GHSA-2345-6789-" + suffix,
            name="sibling-" + suffix,
            version="1.0.0",
            published_at="2026-08-05T09:00:00Z",
            updated_at="2026-08-05T11:00:00Z",
        )
        for suffix in ("cfgj", "cfgm")
    ]

    def handler(request):
        requests.append(request)
        page2 = "after" in request.url.params
        headers = {"content-type": "application/json"}
        if not page2:
            headers["link"] = f'<{request.url.copy_add_param("after", "page2")}>; rel="next"'
        return httpx.Response(200, headers=headers, json=[bad, good[int(page2)]], request=request)

    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
        advisory_type="malware",
        catalog_mode=True,
        historical_cutoff=NOW,
    )
    original = collector._ingest_advisory

    def conflict_every_time(*args, **kwargs):
        nonlocal conflicts
        result = original(*args, **kwargs)
        if kwargs["advisory"]["ghsa_id"] == bad["ghsa_id"]:
            conflicts += 1
            raise conflict
        return result

    monkeypatch.setattr(collector, "_ingest_advisory", conflict_every_time)
    for index in range(2):
        with Session(database.engine) as session, session.begin():
            result = collector.run(session, lane=lane)
            assert result.page_processed and result.page_source_record_count == 2
            assert len(result.collections) == 1
            assert result.state == (
                "in_progress" if index == 0 else "complete" if lane == "updates" else "failed"
            )
    assert conflicts == 2 and requests[1].url.params["after"] == "page2"
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(AdvisoryCatalogRecord)) == 2
        assert session.scalar(select(func.count()).select_from(CollectionRecordOutcome)) == 3
        assert session.scalar(select(func.count()).select_from(CollectionRecordMembership)) == 4
        quarantine = session.scalar(
            select(CollectionRecordOutcome).where(
                CollectionRecordOutcome.disposition == "quarantined"
            )
        )
        assert quarantine.record_key == bad["ghsa_id"]
        assert quarantine.document["quarantine_reasons"] == [reason_code]
        if lane == "updates":
            assert not session.scalar(
                select(func.count())
                .select_from(CollectorProgressRecord)
                .where(CollectorProgressRecord.state == "failed")
            )
    assert not store.pending_manifest()


@pytest.mark.audit_ids("COL-05")
def test_two_collector_lanes_allocate_checkpoint_sequences_without_source_lock_conflict(
    database,
    tmp_path: Path,
) -> None:
    def collector_for(suffix: str, *, barrier: Barrier | None = None):
        advisory = _github_advisory(
            advisory_id=f"GHSA-aaaa-bbbb-{suffix}",
            name=f"parallel-package-{suffix}",
            version="1.0.0",
            published_at="2026-08-05T09:00:00Z",
            updated_at="2026-08-05T11:00:00Z",
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if barrier is not None:
                barrier.wait()
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json=[advisory],
                request=request,
            )

        return GitHubAdvisoryRestCollector(
            registry=RightsRegistry.from_path(RIGHTS_REGISTER),
            evidence_store=LocalImmutableEvidenceStore(tmp_path / f"evidence-{suffix}"),
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            clock=lambda: NOW,
            governance_policy=active_governance_policy(),
        )

    with Session(database.engine) as session, session.begin():
        assert collector_for("0001").run(session, lane="updates").page_processed

    barrier = Barrier(2, timeout=5)

    def run_lane(collector, lane):
        with Session(database.engine) as session, session.begin():
            return collector.run(session, lane=lane)

    with ThreadPoolExecutor(max_workers=2) as executor:
        historical = executor.submit(run_lane, collector_for("0002", barrier=barrier), "historical")
        updates = executor.submit(run_lane, collector_for("0003", barrier=barrier), "updates")
        results = (historical.result(timeout=10), updates.result(timeout=10))
    assert all(result.page_processed for result in results)
    with Session(database.engine) as session:
        sequences = tuple(
            session.scalars(
                select(CollectorCheckpointRecord.sequence).order_by(
                    CollectorCheckpointRecord.sequence
                )
            )
        )
    assert len(sequences) == len(set(sequences))


def test_github_accepts_two_valid_advisories_updated_in_the_same_second(
    database,
    tmp_path: Path,
) -> None:
    shared_updated_at = "2026-08-05T11:00:00Z"
    advisories = [
        _github_advisory(
            advisory_id="GHSA-aaaa-bbbb-same1",
            name="same-second-one",
            version="1.0.0",
            published_at="2026-08-05T09:00:00Z",
            updated_at=shared_updated_at,
        ),
        _github_advisory(
            advisory_id="GHSA-aaaa-bbbb-same2",
            name="same-second-two",
            version="2.0.0",
            published_at="2026-08-05T10:00:00Z",
            updated_at=shared_updated_at,
        ),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=advisories,
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "complete"
        assert result.page_source_record_count == 2
        assert result.page_normalized_record_count == 2
        assert [item.advisory_id for item in result.collections] == [
            "GHSA-aaaa-bbbb-same1",
            "GHSA-aaaa-bbbb-same2",
        ]
        batches = tuple(session.scalars(select(IngestionBatchRecord)))
        assert len(batches) == 2
        assert len({item.idempotency_key_hash for item in batches}) == 2


def test_github_retains_only_reviewed_fields_and_source_modification_time(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-line",
        name="lineage-malware",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory.update(
        {
            "summary": "Provider prose must not enter immutable evidence.",
            "credits": [{"user": {"login": "must-not-survive"}}],
            "references": [
                "https://github.com/ossf/malicious-packages/blob/"
                + "a" * 40
                + "/osv/malicious/npm/lineage-malware/MAL-2026-123.json"
            ],
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    evidence_sha256: str | None = None
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "complete"
        evidence = session.scalar(select(EvidenceRecord))
        claim = session.scalar(select(ClaimRecord))
        assert evidence is not None and claim is not None
        assert evidence.source_modified_at == datetime(2026, 8, 5, 11, tzinfo=UTC)
        evidence_sha256 = evidence.sha256
        lineage = claim.provenance["claim_lineage"]
        assert lineage["transport_source_id"] == GITHUB_ADVISORY
        assert lineage["assertion_source_id"] == OPENSSF_MALICIOUS
        assert lineage["confirming_authority_id"] == OPENSSF_MALICIOUS
        assert lineage["public_status"] == "confirmed"
    assert evidence_sha256 is not None
    retained = json.loads(evidence_store.read_bytes(evidence_sha256))
    assert "summary" not in retained[0]
    assert "credits" not in retained[0]


def test_github_replay_appends_missing_lineage_and_publishes_latest_revision(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import smithguard.collectors as collectors_module

    advisory_id = "GHSA-aaaa-bbbb-legacy"
    legacy_advisory = _github_advisory(
        advisory_id=advisory_id,
        name="legacy-lineage-malware",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    current_advisory = {**legacy_advisory}
    current_advisory["identifiers"] = [{"type": "GHSA", "value": advisory_id}]
    responses = iter(([legacy_advisory], [current_advisory]))
    clocks = iter((NOW, NOW + timedelta(hours=1)))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=next(responses),
            request=request,
        )

    original_transform = collectors_module.transform_github_advisories

    def legacy_transform(records, *, authority_policy=None):
        transformed = original_transform(records, authority_policy=authority_policy)
        return tuple(
            {key: value for key, value in record.items() if key != "source_lineage"}
            for record in transformed
        )

    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: next(clocks),
        governance_policy=active_governance_policy(),
    )
    monkeypatch.setattr(collectors_module, "transform_github_advisories", legacy_transform)
    with Session(database.engine) as session, session.begin():
        legacy = collector.run(session, lane="updates")
        assert legacy.state == "complete"
        legacy_collection = legacy.collections[0]
        legacy_claim = session.scalar(select(ClaimRecord))
        legacy_range = session.scalar(select(AffectedRangeRecord))
        assert legacy_claim is not None and legacy_range is not None
        assert legacy_claim.provenance["claim_lineage"] is None
        assert legacy_range.provenance["claim_lineage"] is None
        claim_id = legacy_claim.id
        range_id = legacy_range.id

    monkeypatch.setattr(
        collectors_module,
        "transform_github_advisories",
        original_transform,
    )
    with Session(database.engine) as session, session.begin():
        current = collector.run(session, lane="updates")
        assert current.state == "complete"
        collection = current.collections[0]
        assert collection.outcome.raw_evidence_id != legacy_collection.outcome.raw_evidence_id
        claims = tuple(
            session.scalars(
                select(ClaimRecord).where(ClaimRecord.id == claim_id).order_by(ClaimRecord.revision)
            )
        )
        ranges = tuple(
            session.scalars(
                select(AffectedRangeRecord)
                .where(AffectedRangeRecord.id == range_id)
                .order_by(AffectedRangeRecord.revision)
            )
        )
        assert [item.revision for item in claims] == [1, 2]
        assert [item.revision for item in ranges] == [1, 2]
        assert claims[0].provenance["claim_lineage"] is None
        assert ranges[0].provenance["claim_lineage"] is None
        assert isinstance(claims[1].provenance["claim_lineage"], dict)
        assert isinstance(ranges[1].provenance["claim_lineage"], dict)
        assert claims[1].provenance["evidence_id"] == collection.outcome.raw_evidence_id
        assert ranges[1].provenance["evidence_id"] == collection.outcome.raw_evidence_id
        published = publish_github_malware_incidents(
            session,
            collection=collection,
            published_at=NOW + timedelta(hours=1),
            governance_policy=active_governance_policy(),
        )
        assert len(published) == 1

    assert len(evidence_store.manifest()) == 2


def test_github_update_lane_uses_fixed_bounded_time_windows(
    database,
    tmp_path: Path,
) -> None:
    requests: list[httpx.Request] = []
    clocks = iter((NOW, NOW + timedelta(hours=1)))

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: next(clocks),
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        first = collector.run(session, lane="updates")
        assert first.state == "complete"
    with Session(database.engine) as session, session.begin():
        second = collector.run(session, lane="updates")
        assert second.state == "complete"
    assert len(requests) == 2
    first_window = requests[0].url.params["modified"]
    second_window = requests[1].url.params["modified"]
    assert first_window == ("2026-08-04T12:00:00Z..2026-08-05T12:00:00Z")
    assert second_window == ("2026-08-05T11:00:00Z..2026-08-05T13:00:00Z")  # one-hour overlap


def test_github_rejects_untrusted_next_page_link_and_records_failure(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-0003",
        name="bounded-malware",
        version="2.0.0",
        published_at="2021-01-01T00:00:00Z",
        updated_at="2021-01-02T00:00:00Z",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "link": '<https://example.com/steal?after=bad>; rel="next"',
            },
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "failed"
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.reason_code == "github_request_or_page_rejected"


def test_github_records_source_governance_rejection_before_network_use(
    database,
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise AssertionError(f"unexpected network request: {request.url.host}")

    registry = RightsRegistry.from_path(RIGHTS_REGISTER)
    collector = GitHubAdvisoryRestCollector(
        registry=registry,
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: datetime(2026, 11, 8, tzinfo=UTC),
        governance_policy=SourceGovernancePolicy.from_path(
            DEFAULT_GOVERNANCE_POLICY_PATH,
            registry=registry,
        ),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="updates")
        assert result.state == "failed"
        assert not result.page_processed
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.reason_code == "github_source_governance_rejected"
    assert calls == 0


def test_github_records_per_advisory_governance_rejection_without_quarantine_fallback(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-policy",
        name="policy-rejected-malware",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )

    def reject_advisory(*_args, **_kwargs):
        raise IngestionSourceError("synthetic policy rejection")

    monkeypatch.setattr(collector, "_ingest_advisory", reject_advisory)
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="updates")
        assert result.state == "failed"
        assert not result.page_processed
        assert result.collections == ()
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.reason_code == "github_source_governance_rejected"
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 0


def test_github_advances_reviewed_unsupported_scope_without_claiming_complete_coverage(
    database,
    tmp_path: Path,
) -> None:
    excluded = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-ruby",
        name="out-of-scope-gem",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    excluded["vulnerabilities"][0]["package"]["ecosystem"] = "rubygems"
    first_valid = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-npm1",
        name="supported-npm-one",
        version="2.0.0",
        published_at="2026-08-05T08:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    second_valid = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-npm2",
        name="supported-npm-two",
        version="3.0.0",
        published_at="2026-08-05T07:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            next_url = (
                "https://api.github.com/advisories"
                "?type=malware&sort=published&direction=desc&per_page=100"
                "&after=cursor-after-scope-gap"
            )
            return httpx.Response(
                200,
                headers={
                    "content-type": "application/json",
                    "link": f'<{next_url}>; rel="next"',
                },
                json=[excluded, first_valid],
                request=request,
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[second_valid],
            request=request,
        )

    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        first = collector.run(session, lane="historical")
        assert first.state == "in_progress"
        assert first.has_scope_gap
        assert first.page_processed
        assert first.source_record_count == 2
        assert first.normalized_record_count == 1
        assert len(first.collections) == 2
        assert sorted(item.outcome.record_count for item in first.collections) == [0, 1]
        batches = tuple(session.scalars(select(IngestionBatchRecord)))
        assert len(batches) == 2
        assert all(item.outcome == "accepted" for item in batches)
        assert all(not item.quarantine_reasons for item in batches)
    with Session(database.engine) as session, session.begin():
        second = collector.run(session, lane="historical")
        assert second.state == "failed"
        assert second.has_scope_gap
        assert second.page_processed
        assert second.source_record_count == 3
        assert second.normalized_record_count == 2
        reasons = tuple(
            session.scalars(
                select(CollectorProgressRecord.reason_code).order_by(
                    CollectorProgressRecord.sequence
                )
            )
        )
        assert reasons == (
            "github_page_accepted_with_scope_exclusion",
            "github_lane_complete_with_scope_exclusion",
        )
        source_lanes = build_coverage_report(session, measured_at=NOW).source_lanes
        assert len(source_lanes) == 11
        assert all(lane.state == "not_started" for lane in source_lanes)
    with Session(database.engine) as session, session.begin():
        terminal = collector.run(session, lane="historical")
        assert terminal.state == "failed"
        assert terminal.has_scope_gap
        assert not terminal.page_processed
    assert len(requests) == 2
    assert requests[1].url.params["after"] == "cursor-after-scope-gap"
    assert len(evidence_store.manifest()) == 3
    retained_bodies = tuple(
        evidence_store.read_bytes(blob.digest) for blob in evidence_store.manifest()
    )
    assert all(b"out-of-scope-gem" not in body for body in retained_bodies)
    assert all(b"rubygems" not in body for body in retained_bodies)


def test_github_minimizes_unsupported_siblings_and_publishes_exact_and_range_siblings(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-mixed",
        name="supported-sibling",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"].append(
        {
            "package": {"ecosystem": "rubygems", "name": "excluded-sibling"},
            "vulnerable_version_range": "= 2.0.0",
            "first_patched_version": None,
        }
    )
    advisory["references"] = [
        "https://example.com/retained-report",
        "https://example.com/excluded-report#details",
    ]
    advisory["vulnerabilities"].append(
        {
            "package": {"ecosystem": "npm", "name": "excluded-range-sibling"},
            "vulnerable_version_range": ">= 3.0.0, < 4.0.0",
            "first_patched_version": None,
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "failed"
        assert result.has_scope_gap
        assert result.page_processed
        assert result.page_source_record_count == 1
        assert result.page_normalized_record_count == 2
        assert len(result.collections) == 1
        assert result.collections[0].outcome.record_count == 2
        published = publish_github_malware_incidents(
            session,
            collection=result.collections[0],
            published_at=NOW,
            governance_policy=active_governance_policy(),
        )
        assert len(published) == 2
        assert {item["title"] for item in published} == {
            "Malicious npm package: supported-sibling",
            "Malicious npm package range: excluded-range-sibling",
        }
        assert {item["status"] for item in published} == {"reported"}
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.reason_code == "github_lane_complete_with_scope_exclusion"
    retained = evidence_store.read_bytes(evidence_store.manifest()[0].digest)
    assert b"supported-sibling" in retained
    assert b"excluded-sibling" not in retained
    assert b"excluded-range-sibling" in retained
    assert b"rubygems" not in retained
    assert b">= 3.0.0" in retained
    assert b"retained-report" in retained
    assert b"excluded-report" not in retained


@pytest.mark.parametrize(
    "reference",
    [
        "http://example.com/remains-retryable",
        "https://user@example.com/remains-retryable",
        "https://example.com:444/remains-retryable",
        "https:///remains-retryable",
        "https://example.com:invalid/remains-retryable",
    ],
)
def test_github_keeps_an_unreviewed_reference_shape_retryable(
    database,
    tmp_path: Path,
    reference: str,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-reference",
        name="unsafe-reference",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["references"] = [reference]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "failed"
        assert not result.has_scope_gap
        assert not result.page_processed
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.reason_code == "github_page_quarantined_retryable"


def test_github_accepts_a_valid_high_reference_advisory(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-manyrefs",
        name="high-reference-advisory",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["references"] = [f"https://example.com/live-reference/{index}" for index in range(150)]
    advisory["vulnerabilities"] = [
        {
            "package": {"ecosystem": "npm", "name": "high-reference-advisory"},
            "vulnerable_version_range": f"= 1.0.{index}",
            "first_patched_version": None,
        }
        for index in range(147)
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
        advisory_type="malware",
        catalog_mode=True,
        historical_cutoff=NOW,
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        quarantine_reasons = [
            batch.quarantine_reasons
            for batch in session.scalars(select(IngestionBatchRecord)).all()
            if batch.outcome == "quarantined"
        ]
        assert result.state == "complete", quarantine_reasons
        assert result.page_processed
        assert result.source_record_count == 1
        assert result.normalized_record_count == 147
        batch = session.scalar(select(IngestionBatchRecord))
        assert batch is not None
        assert batch.outcome == "accepted"
        assert batch.processing_version == "github-advisory-catalog-7-malware"


def test_github_accepts_a_high_reference_unreviewed_advisory_without_packages(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-w2q5-6q6x-x959",
        name="unused-without-vulnerabilities",
        version="1.0.0",
        published_at="2026-05-26T13:30:18Z",
        updated_at="2026-08-13T15:34:06Z",
    )
    advisory["type"] = "unreviewed"
    advisory["references"] = [
        f"https://example.com/unreviewed-reference/{index}" for index in range(120)
    ]
    advisory["vulnerabilities"] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
        advisory_type="unreviewed",
        catalog_mode=True,
        historical_cutoff=NOW,
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "complete"
        assert result.page_processed
        assert result.source_record_count == 1
        assert result.normalized_record_count == 0
        catalog = session.scalar(select(AdvisoryCatalogRecord))
        assert catalog is not None
        assert catalog.upstream_record_id == "GHSA-w2q5-6q6x-x959"
        assert catalog.source_type == "unreviewed"
        assert session.scalar(select(func.count()).select_from(AdvisoryPackageRecord)) == 0


def test_github_catalog_accepts_a_reviewed_action_subpath(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-r79c-pqj3-577x",
        name="super-linter/super-linter",
        version="8.3.0",
        published_at="2026-02-09T17:46:31Z",
        updated_at="2026-02-09T22:39:41Z",
    )
    advisory["type"] = "reviewed"
    advisory["vulnerabilities"] = [
        {
            "package": {"ecosystem": "actions", "name": "super-linter/super-linter"},
            "vulnerable_version_range": ">= 6.0.0, < 8.3.1",
            "first_patched_version": "8.3.1",
        },
        {
            "package": {
                "ecosystem": "actions",
                "name": "super-linter/super-linter/slim",
            },
            "vulnerable_version_range": ">= 6.0.0, < 8.3.1",
            "first_patched_version": "8.3.1",
        },
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
        advisory_type="reviewed",
        catalog_mode=True,
        historical_cutoff=NOW,
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "complete"
        assert result.normalized_record_count == 2
        names = set(session.scalars(select(AdvisoryPackageRecord.name)))
        assert names == {
            "super-linter/super-linter",
            "super-linter/super-linter/slim",
        }


def test_github_catalog_accepts_a_reviewed_action_https_path(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-hw6r-g8gj-2987",
        name="unused-action-name",
        version="2.0.0",
        published_at="2023-08-30T20:47:13Z",
        updated_at="2023-08-30T20:47:26Z",
    )
    advisory["type"] = "reviewed"
    advisory["cwes"] = []
    advisory["vulnerabilities"] = [
        {
            "package": {
                "ecosystem": "actions",
                "name": ("https://github.com/pytorch/pytorch/.github/actions/filter-test-configs"),
            },
            "vulnerable_version_range": "< 2.0.1",
            "first_patched_version": None,
        }
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
        advisory_type="reviewed",
        catalog_mode=True,
        historical_cutoff=NOW,
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "complete"
        assert result.normalized_record_count == 1
        package = session.scalar(select(AdvisoryPackageRecord))
        assert package is not None
        assert package.ecosystem == "github-actions"
        assert package.name == "pytorch/pytorch/.github/actions/filter-test-configs"


@pytest.mark.parametrize(
    "advisory_id",
    ("GHSA-wg24-7m7r-fcx2", "GHSA-rq28-x6fq-j954"),
)
def test_github_catalog_accepts_an_unreviewed_unicode_reference(
    database,
    tmp_path: Path,
    advisory_id: str,
) -> None:
    advisory = _github_advisory(
        advisory_id=advisory_id,
        name="unused-without-vulnerabilities",
        version="1.0.0",
        published_at="2022-05-24T22:28:57Z",
        updated_at="2023-12-27T05:05:09Z",
    )
    advisory["type"] = "unreviewed"
    advisory["references"] = [
        "https://www.wordfence.com/blog/nested-pages-pat\u2026on-vulnerability/",
        "https://www.wordfence.com/blog/nested-pages-pat%E2%80%A6on-vulnerability/",
        f"https://github.com/advisories/{advisory_id}",
    ]
    advisory["vulnerabilities"] = []
    filtered = filter_github_advisory(advisory)
    assert filtered["references"] == [
        "https://www.wordfence.com/blog/nested-pages-pat%E2%80%A6on-vulnerability/",
        f"https://github.com/advisories/{advisory_id}",
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
        advisory_type="unreviewed",
        catalog_mode=True,
        historical_cutoff=NOW,
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "complete"
        assert result.source_record_count == 1
        assert result.normalized_record_count == 0
        catalog = session.scalar(select(AdvisoryCatalogRecord))
        assert catalog is not None
        assert catalog.upstream_record_id == advisory_id


def test_github_catalog_version_retries_a_preserved_unicode_reference_quarantine(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import smithguard.collectors as collectors_module

    advisory = _github_advisory(
        advisory_id="GHSA-wg24-7m7r-fcx2",
        name="unused-without-vulnerabilities",
        version="1.0.0",
        published_at="2022-05-24T22:29:02Z",
        updated_at="2023-12-18T18:31:27Z",
    )
    advisory["type"] = "unreviewed"
    advisory["references"] = [
        "https://www.wordfence.com/blog/nested-pages-pat\u2026on-vulnerability/"
    ]
    advisory["vulnerabilities"] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
        advisory_type="unreviewed",
        catalog_mode=True,
        historical_cutoff=NOW,
    )
    canonical_reference = collectors_module._canonical_github_reference

    def reject_unicode_reference(value: object) -> str:
        if not isinstance(value, str) or not value.isascii():
            raise NormalizationRejected("invalid_github_reference")
        return value

    monkeypatch.setattr(
        collectors_module,
        "_canonical_github_reference",
        reject_unicode_reference,
    )
    monkeypatch.setattr(
        collector,
        "_catalog_processing_version",
        "github-advisory-catalog-4-unreviewed",
    )
    with Session(database.engine) as session, session.begin():
        first = collector.run(session, lane="historical")
        assert first.state == "failed"
        assert first.page_processed
        prior_outcome_id = session.scalar(select(CollectionRecordOutcome.outcome_id))

    monkeypatch.setattr(
        collectors_module,
        "_canonical_github_reference",
        canonical_reference,
    )
    monkeypatch.setattr(
        collector,
        "_catalog_processing_version",
        "github-advisory-catalog-7-unreviewed",
    )
    with Session(database.engine) as session, session.begin():
        repaired = collector.backfill_advisory(
            session, advisory_id=advisory["ghsa_id"], resolve_outcome_id=prior_outcome_id
        )
        assert repaired.collection.outcome.outcome == "accepted"
        # The original cutoff cannot be retrospectively called a complete scan.
        second = collector.run(session, lane="historical")
        assert second.state == "failed"
        assert not second.page_processed
        batches = tuple(
            session.scalars(
                select(IngestionBatchRecord).order_by(IngestionBatchRecord.completed_at)
            )
        )
        assert [item.processing_version for item in batches] == [
            "github-advisory-catalog-4-unreviewed",
            "github-advisory-catalog-7-unreviewed",
        ]
        assert [item.outcome for item in batches] == ["quarantined", "accepted"]


def test_github_catalog_version_retries_a_preserved_high_reference_quarantine(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import smithguard.collectors as collectors_module

    advisory = _github_advisory(
        advisory_id="GHSA-2345-6789-cfgh",
        name="high-reference-retry",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["references"] = [f"https://example.com/live-reference/{index}" for index in range(150)]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
        advisory_type="malware",
        catalog_mode=True,
        historical_cutoff=NOW,
    )
    monkeypatch.setattr(collectors_module, "GITHUB_MAX_REFERENCES", 100)
    monkeypatch.setattr(
        collector, "_catalog_processing_version", "github-advisory-catalog-3-malware"
    )
    with Session(database.engine) as session, session.begin():
        first = collector.run(session, lane="historical")
        assert first.state == "failed"
        assert first.page_processed
        prior_outcome_id = session.scalar(select(CollectionRecordOutcome.outcome_id))

    monkeypatch.setattr(collectors_module, "GITHUB_MAX_REFERENCES", 1_000)
    monkeypatch.setattr(
        collector, "_catalog_processing_version", "github-advisory-catalog-4-malware"
    )
    with Session(database.engine) as session, session.begin():
        repaired = collector.backfill_advisory(
            session, advisory_id=advisory["ghsa_id"], resolve_outcome_id=prior_outcome_id
        )
        assert repaired.collection.outcome.outcome == "accepted"
        # The original cutoff cannot be retrospectively called a complete scan.
        second = collector.run(session, lane="historical")
        assert second.state == "failed"
        assert not second.page_processed
        batches = tuple(
            session.scalars(
                select(IngestionBatchRecord).order_by(IngestionBatchRecord.completed_at)
            )
        )
        assert [item.processing_version for item in batches] == [
            "github-advisory-catalog-3-malware",
            "github-advisory-catalog-4-malware",
        ]
        assert [item.outcome for item in batches] == ["quarantined", "accepted"]


@pytest.mark.parametrize("reference_count", [1_001, 1_500])
def test_github_keeps_an_over_limit_reference_list_retryable(
    database,
    tmp_path: Path,
    reference_count: int,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-manyrefs",
        name="too-many-references",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["references"] = [
        f"https://example.com/live-reference/{index}" for index in range(reference_count)
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "failed"
        assert not result.has_scope_gap
        assert not result.page_processed
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.reason_code == "github_page_quarantined_retryable"


def test_github_supported_update_range_starts_a_fresh_followup_window(
    database,
    tmp_path: Path,
) -> None:
    excluded = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-window",
        name="broad-range-window",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    excluded["vulnerabilities"][0]["vulnerable_version_range"] = "> 0"
    requests: list[httpx.Request] = []
    clocks = iter((NOW, NOW + timedelta(hours=1)))

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[excluded] if len(requests) == 1 else [],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: next(clocks),
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        first = collector.run(session, lane="updates")
        assert first.state == "complete"
        assert not first.has_scope_gap
        assert first.page_normalized_record_count == 1
        assert first.page_excluded_scope_entry_count == 0
    with Session(database.engine) as session:
        source_lanes = build_coverage_report(session, measured_at=NOW).source_lanes
        assert len(source_lanes) == 11
        assert all(lane.state == "not_started" for lane in source_lanes)
    with Session(database.engine) as session, session.begin():
        second = collector.run(session, lane="updates")
        assert second.state == "complete"
        assert not second.has_scope_gap
        progress = tuple(
            session.scalars(
                select(CollectorProgressRecord).order_by(CollectorProgressRecord.sequence)
            )
        )
        assert [item.reason_code for item in progress] == [
            "github_lane_complete",
            "github_lane_complete",
        ]
        assert progress[1].window_started_at == NOW - timedelta(hours=1)  # one-hour overlap
        assert progress[1].window_ended_at == NOW + timedelta(hours=1)
    assert len(requests) == 2
    assert requests[0].url.params["modified"] == ("2026-08-04T12:00:00Z..2026-08-05T12:00:00Z")
    assert requests[1].url.params["modified"] == (
        "2026-08-05T11:00:00Z..2026-08-05T13:00:00Z"
    )  # one-hour overlap


def test_github_update_deliberate_exclusion_is_private_and_not_an_outage(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-scope",
        name="unsupported-comparator-package",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"][0]["vulnerable_version_range"] = "!= 1.0.0"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="updates")
        assert result.state == "complete"
        assert result.has_scope_gap
        assert result.page_excluded_scope_entry_count == 1
        assert result.page_scope_exclusion_reasons == (("unsupported_range", 1),)
    with Session(database.engine) as session:
        source_lanes = build_coverage_report(session, measured_at=NOW).source_lanes
        assert len(source_lanes) == 11
        assert all(lane.freshness_state == "missing" for lane in source_lanes)


def test_github_update_recovers_forward_from_a_legacy_failed_terminal_scope_gap(
    database,
    tmp_path: Path,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW + timedelta(hours=1),
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        collector._append_progress(
            session,
            lane="updates",
            state="failed",
            cursor_parameter=None,
            cursor_value=None,
            page_count=398,
            source_record_count=6_354,
            normalized_record_count=2_767,
            window_started_at=NOW - timedelta(hours=1),
            window_ended_at=NOW,
            oldest_published_at=None,
            newest_published_at=None,
            reason_code="github_lane_complete_with_scope_exclusion",
            occurred_at=NOW,
        )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="updates")
        assert result.state == "complete"
        assert not result.has_scope_gap
        assert result.page_count == 399

    assert len(requests) == 1
    assert requests[0].url.params["modified"] == (
        "2026-08-05T11:00:00Z..2026-08-05T13:00:00Z"
    )  # one-hour overlap


def test_github_keeps_an_unreviewed_ecosystem_retryable(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-future",
        name="future-registry-package",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"][0]["package"]["ecosystem"] = "future-registry"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "failed"
        assert not result.has_scope_gap
        assert not result.page_processed
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.page_count == 0
        assert progress.reason_code == "github_page_quarantined_retryable"


def test_github_processing_version_converges_a_preserved_alias_quarantine(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import smithguard.collectors as collectors_module

    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-pip1",
        name="python-alias-package",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"][0]["package"]["ecosystem"] = "pip"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    original_transform = collectors_module.transform_github_advisories

    def reject_alias(_records, **_kwargs):
        raise collectors_module.NormalizationRejected("unsupported_osv_ecosystem")

    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    monkeypatch.setattr(collector, "PROCESSING_VERSION", "github-advisory-rest-1")
    monkeypatch.setattr(collectors_module, "transform_github_advisories", reject_alias)
    with Session(database.engine) as session, session.begin():
        first = collector.run(session, lane="historical")
        assert first.state == "failed"
        assert not first.page_processed

    monkeypatch.setattr(collector, "PROCESSING_VERSION", "github-advisory-rest-5")
    monkeypatch.setattr(
        collectors_module,
        "transform_github_advisories",
        original_transform,
    )
    with Session(database.engine) as session, session.begin():
        second = collector.run(session, lane="historical")
        assert second.state == "complete"
        assert second.page_processed
        assert second.normalized_record_count == 1
        batches = tuple(
            session.scalars(
                select(IngestionBatchRecord).order_by(IngestionBatchRecord.completed_at)
            )
        )
        assert [item.processing_version for item in batches] == [
            "github-advisory-rest-1",
            "github-advisory-rest-5",
        ]
        assert [item.outcome for item in batches] == ["quarantined", "accepted"]
    assert len(evidence_store.manifest()) == 1


def test_github_processing_version_converges_a_preserved_nonexact_range_quarantine(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import smithguard.collectors as collectors_module

    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-range",
        name="valid-provider-range",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"][0]["package"]["ecosystem"] = "pip"
    advisory["vulnerabilities"][0]["vulnerable_version_range"] = ">= 1.0.0, < 2.0.0"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    original_minimize = collectors_module._minimize_github_publication_scope_with_reasons
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    monkeypatch.setattr(collector, "PROCESSING_VERSION", "github-advisory-rest-2")
    monkeypatch.setattr(
        collectors_module,
        "_minimize_github_publication_scope_with_reasons",
        lambda item: (collectors_module.filter_github_advisory(item), ()),
    )
    with Session(database.engine) as session, session.begin():
        first = collector.run(session, lane="historical")
        assert first.state == "failed"
        assert not first.has_scope_gap
        assert not first.page_processed

    monkeypatch.setattr(collector, "PROCESSING_VERSION", "github-advisory-rest-5")
    monkeypatch.setattr(
        collectors_module,
        "_minimize_github_publication_scope_with_reasons",
        original_minimize,
    )
    with Session(database.engine) as session, session.begin():
        second = collector.run(session, lane="historical")
        assert second.state == "failed"
        assert second.has_scope_gap
        assert second.page_processed
        assert second.normalized_record_count == 0
        batches = tuple(
            session.scalars(
                select(IngestionBatchRecord).order_by(IngestionBatchRecord.completed_at)
            )
        )
        assert [item.processing_version for item in batches] == [
            "github-advisory-rest-2",
            "github-advisory-rest-5",
        ]
        assert [item.outcome for item in batches] == ["quarantined", "accepted"]
    assert len(evidence_store.manifest()) == 1


def test_github_processing_version_converges_a_preserved_fragment_reference_quarantine(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import smithguard.collectors as collectors_module

    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-fragment",
        name="fragment-reference",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["references"] = [
        "https://example.com/retained-reference",
        "https://example.com/excluded-reference#details",
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    original_minimize = collectors_module._minimize_github_publication_scope_with_reasons
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    monkeypatch.setattr(collector, "PROCESSING_VERSION", "github-advisory-rest-3")
    monkeypatch.setattr(
        collectors_module,
        "_minimize_github_publication_scope_with_reasons",
        lambda item: (collectors_module.filter_github_advisory(item), ()),
    )
    with Session(database.engine) as session, session.begin():
        first = collector.run(session, lane="historical")
        assert first.state == "failed"
        assert not first.has_scope_gap
        assert not first.page_processed

    monkeypatch.setattr(collector, "PROCESSING_VERSION", "github-advisory-rest-5")
    monkeypatch.setattr(
        collectors_module,
        "_minimize_github_publication_scope_with_reasons",
        original_minimize,
    )
    with Session(database.engine) as session, session.begin():
        second = collector.run(session, lane="historical")
        assert second.state == "failed"
        assert second.has_scope_gap
        assert second.page_processed
        assert second.normalized_record_count == 1
        batches = tuple(
            session.scalars(
                select(IngestionBatchRecord).order_by(IngestionBatchRecord.completed_at)
            )
        )
        assert [item.processing_version for item in batches] == [
            "github-advisory-rest-3",
            "github-advisory-rest-5",
        ]
        assert [item.outcome for item in batches] == ["quarantined", "accepted"]
    assert len(evidence_store.manifest()) == 1
    retained = evidence_store.read_bytes(evidence_store.manifest()[0].digest)
    assert b"retained-reference" in retained
    assert b"excluded-reference" not in retained


def test_github_processing_version_converges_a_preserved_provider_size_quarantine(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import smithguard.collectors as collectors_module

    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-many1",
        name="provider-size-boundary",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"] = [
        {
            "package": {"ecosystem": "rubygems", "name": f"excluded-{index}"},
            "vulnerable_version_range": "= 1.0.0",
            "first_patched_version": None,
        }
        for index in range(506)
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    original_minimize = collectors_module._minimize_github_publication_scope_with_reasons
    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    monkeypatch.setattr(collector, "PROCESSING_VERSION", "github-advisory-rest-4")
    monkeypatch.setattr(
        collectors_module,
        "_minimize_github_publication_scope_with_reasons",
        lambda item: (collectors_module.filter_github_advisory(item), ()),
    )
    with Session(database.engine) as session, session.begin():
        first = collector.run(session, lane="historical")
        assert first.state == "failed"
        assert not first.has_scope_gap
        assert not first.page_processed

    monkeypatch.setattr(collector, "PROCESSING_VERSION", "github-advisory-rest-5")
    monkeypatch.setattr(
        collectors_module,
        "_minimize_github_publication_scope_with_reasons",
        original_minimize,
    )
    with Session(database.engine) as session, session.begin():
        second = collector.run(session, lane="historical")
        assert second.state == "failed"
        assert second.has_scope_gap
        assert second.page_processed
        assert second.source_record_count == 1
        assert second.normalized_record_count == 0
        batches = tuple(
            session.scalars(
                select(IngestionBatchRecord).order_by(IngestionBatchRecord.completed_at)
            )
        )
        assert [item.processing_version for item in batches] == [
            "github-advisory-rest-4",
            "github-advisory-rest-5",
        ]
        assert [item.outcome for item in batches] == ["quarantined", "accepted"]
    retained = json.loads(evidence_store.read_bytes(evidence_store.manifest()[0].digest))
    assert retained[0]["vulnerabilities"] == []


def test_github_keeps_an_oversized_provider_vulnerability_list_retryable(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-many2",
        name="oversized-provider-boundary",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"] = [
        {
            "package": {"ecosystem": "rubygems", "name": "excluded"},
            "vulnerable_version_range": "= 1.0.0",
            "first_patched_version": None,
        }
        for _index in range(1001)
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "failed"
        assert not result.has_scope_gap
        assert not result.page_processed
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.reason_code == "github_page_quarantined_retryable"


def test_github_keeps_an_oversized_retained_vulnerability_list_retryable(
    database,
    tmp_path: Path,
) -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-many3",
        name="retained-size-boundary",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"] = [
        {
            "package": {"ecosystem": "npm", "name": f"retained-{index}"},
            "vulnerable_version_range": "= 1.0.0",
            "first_patched_version": None,
        }
        for index in range(501)
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[advisory],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "failed"
        assert not result.has_scope_gap
        assert not result.page_processed
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.reason_code == "github_page_quarantined_retryable"


def test_github_quarantine_keeps_the_page_retryable_without_storing_its_body(
    database,
    tmp_path: Path,
) -> None:
    malformed = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-bad1",
        name="malformed-malware",
        version="1.0.0",
        published_at="not-a-time",
        updated_at="2026-08-05T11:00:00Z",
    )
    malformed["summary"] = "This omitted prose must not enter immutable evidence."
    malformed["credits"] = [{"user": {"login": "must-not-survive"}}]
    valid = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-good",
        name="valid-malware",
        version="2.0.0",
        published_at="2026-08-05T10:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[malformed, valid],
            request=request,
        )

    evidence_store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=evidence_store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="historical")
        assert result.state == "failed"
        assert not result.page_processed
        assert result.page_source_record_count == 0
        assert result.page_normalized_record_count == 0
        assert len(result.collections) == 1
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.page_count == 0
        assert progress.source_record_count == 0
        assert progress.normalized_record_count == 0
        assert progress.cursor_parameter is None
        assert progress.cursor_value is None
        assert progress.reason_code == "github_page_quarantined_retryable"
        batches = tuple(
            session.scalars(select(IngestionBatchRecord).order_by(IngestionBatchRecord.outcome))
        )
        assert len(batches) == 2
        quarantined = next(item for item in batches if item.outcome == "quarantined")
        assert quarantined.raw_evidence_id is None
        assert quarantined.quarantine_reasons == [
            "invalid_github_advisory_envelope_ghsa_aaaa_bbbb_bad1"
        ]
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 1
    assert len(evidence_store.manifest()) == 1

    with Session(database.engine) as session, session.begin():
        second = collector.run(session, lane="historical")
        assert second.state == "failed"
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 3

    with Session(database.engine) as session, session.begin():
        third = collector.run(session, lane="historical")
        assert third.state == "failed"
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 3


def test_github_quarantine_deadline_records_retryable_page_failure(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-expired",
        name="expired-quarantine",
        version="1.0.0",
        published_at="not-a-time",
        updated_at="2026-08-05T11:00:00Z",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[malformed],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )

    def expire_quarantine(*_args, **_kwargs):
        raise AcquisitionRejected("operation_time_limit")

    monkeypatch.setattr(collector, "_quarantine_advisory_envelope", expire_quarantine)
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="updates")
        assert result.state == "failed"
        assert not result.page_processed
        assert result.collections == ()
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.page_count == 0
        assert progress.source_record_count == 0
        assert progress.normalized_record_count == 0
        assert progress.reason_code == "github_operation_deadline"
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 0


def test_github_quarantine_retries_the_same_page_before_advancing(
    database,
    tmp_path: Path,
) -> None:
    malformed = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-bad2",
        name="unsupported-range",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    malformed["vulnerabilities"][0]["vulnerable_version_range"] = "not-a-range"
    first_valid = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-good1",
        name="first-valid",
        version="2.0.0",
        published_at="2026-08-05T08:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    second_valid = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-good2",
        name="second-valid",
        version="3.0.0",
        published_at="2026-08-05T07:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    requests: list[httpx.Request] = []
    corrected = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-bad2",
        name="unsupported-range",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) <= 2:
            next_url = (
                "https://api.github.com/advisories"
                "?type=malware&sort=published&direction=desc&per_page=100"
                "&after=cursor-after-gap"
            )
            return httpx.Response(
                200,
                headers={
                    "content-type": "application/json",
                    "link": f'<{next_url}>; rel="next"',
                },
                json=[
                    malformed if len(requests) == 1 else corrected,
                    first_valid,
                ],
                request=request,
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[second_valid],
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        first = collector.run(session, lane="historical")
        assert first.state == "failed"
        assert not first.page_processed
        assert first.source_record_count == 0
        assert first.normalized_record_count == 0
        assert len(first.collections) == 1
    with Session(database.engine) as session, session.begin():
        second = collector.run(session, lane="historical")
        assert second.state == "in_progress"
        assert second.page_processed
        assert second.source_record_count == 2
        assert second.normalized_record_count == 2
        assert len(second.collections) == 2
        assert requests[0].url == requests[1].url
    with Session(database.engine) as session, session.begin():
        third = collector.run(session, lane="historical")
        assert third.state == "complete"
        assert third.page_processed
        assert third.source_record_count == 3
        assert third.normalized_record_count == 3
        assert len(third.collections) == 1
        reasons = tuple(
            session.scalars(
                select(CollectorProgressRecord.reason_code).order_by(
                    CollectorProgressRecord.sequence
                )
            )
        )
        assert reasons == (
            "github_page_quarantined_retryable",
            "github_page_accepted_after_quarantine",
            "github_lane_complete",
        )
        source_lanes = build_coverage_report(session, measured_at=NOW).source_lanes
        assert len(source_lanes) == 11
        assert all(lane.state == "not_started" for lane in source_lanes)
    with Session(database.engine) as session, session.begin():
        terminal = collector.run(session, lane="historical")
        assert terminal.state == "complete"
        assert not terminal.page_processed
    assert len(requests) == 3
    assert requests[2].url.params["after"] == "cursor-after-gap"


def test_github_rate_limit_persists_not_before_and_early_run_makes_no_request(
    database,
    tmp_path: Path,
) -> None:
    requests: list[httpx.Request] = []
    clock = iter((NOW, NOW + timedelta(minutes=1)))

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            429,
            headers={
                "content-type": "application/json",
                "retry-after": "3600",
            },
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: next(clock),
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        first = collector.run(session, lane="updates")
        assert first.state == "failed"
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.not_before == NOW + timedelta(hours=1)
    with Session(database.engine) as session, session.begin():
        second = collector.run(session, lane="updates")
        assert second.state == "failed"
        assert not second.page_processed
        assert session.scalar(select(func.count()).select_from(CollectorProgressRecord)) == 1
    assert len(requests) == 1


def test_github_reset_header_alone_does_not_hide_a_forbidden_response(
    database,
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            headers={
                "content-type": "application/json",
                "x-ratelimit-reset": str(int((NOW + timedelta(hours=1)).timestamp())),
            },
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="updates")
        assert result.state == "failed"
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.reason_code == "github_request_or_page_rejected"
        assert progress.not_before is None


def test_github_forces_redirects_off_even_for_a_redirecting_injected_client(
    database,
    tmp_path: Path,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers={"location": "https://example.invalid/redirected"},
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=True,
        ),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="updates")
        assert result.state == "failed"
        progress = session.scalar(select(CollectorProgressRecord))
        assert progress is not None
        assert progress.reason_code == "github_request_or_page_rejected"
    assert len(requests) == 1
    assert requests[0].headers["accept-encoding"] == "identity"


def test_github_declared_size_is_rejected_before_stream_read(
    database,
    tmp_path: Path,
) -> None:
    stream = TrackingStream((b"[]",))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "content-length": "100",
            },
            stream=stream,
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    collector.MAX_RESPONSE_BYTES = 32
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="updates")
        assert result.state == "failed"
    assert stream.read_count == 0


@pytest.mark.parametrize(
    "headers",
    [
        {"content-type": "text/html"},
        {
            "content-type": "application/json",
            "content-encoding": "gzip",
        },
    ],
)
def test_github_rejects_unexpected_media_and_encoding_before_ingestion(
    database,
    tmp_path: Path,
    headers: dict[str, str],
) -> None:
    stream = TrackingStream((b"[]",))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=headers,
            stream=stream,
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="updates")
        assert result.state == "failed"
        assert session.scalar(select(func.count()).select_from(IngestionBatchRecord)) == 0
    assert stream.read_count == 0


def test_github_stream_limit_and_operation_deadline_fail_closed(
    database,
    tmp_path: Path,
) -> None:
    responses = iter(("overflow", "deadline"))
    clock_state = {"value": 0.0}

    def handler(request: httpx.Request) -> httpx.Response:
        mode = next(responses)
        if mode == "overflow":
            stream = TrackingStream((b"x" * 33,))
        else:
            stream = TrackingStream(
                (b"[]",),
                before_yield=lambda: clock_state.update(value=121.0),
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=stream,
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        monotonic_clock=lambda: clock_state["value"],
        governance_policy=active_governance_policy(),
    )
    collector.MAX_RESPONSE_BYTES = 32
    with Session(database.engine) as session, session.begin():
        overflow = collector.run(session, lane="updates")
        assert overflow.state == "failed"
        assert (
            session.scalar(
                select(CollectorProgressRecord.reason_code).order_by(
                    CollectorProgressRecord.sequence.desc()
                )
            )
            == "github_request_or_page_rejected"
        )

    clock_state["value"] = 0.0
    with Session(database.engine) as session, session.begin():
        expired = collector.run(session, lane="updates")
        assert expired.state == "failed"
        assert (
            session.scalar(
                select(CollectorProgressRecord.reason_code).order_by(
                    CollectorProgressRecord.sequence.desc()
                )
            )
            == "github_operation_deadline"
        )


def test_github_page_deadline_allows_a_bounded_transport_over_ten_seconds(
    database,
    tmp_path: Path,
) -> None:
    clock_state = {"value": 0.0}
    body = json.dumps(
        [
            _github_advisory(
                advisory_id="GHSA-aaaa-bbbb-slow",
                name="bounded-slow-transport",
                version="1.0.0",
                published_at="2026-08-05T10:00:00Z",
                updated_at="2026-08-05T11:00:00Z",
            )
        ]
    ).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=TrackingStream(
                (body,),
                before_yield=lambda: clock_state.update(value=11.0),
            ),
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
        monotonic_clock=lambda: clock_state["value"],
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        result = collector.run(session, lane="updates")
        assert result.state == "complete"
        assert result.page_processed
        assert result.page_source_record_count == 1
        assert result.page_normalized_record_count == 1


def test_github_json_decode_uses_the_shared_operation_deadline() -> None:
    clock_values = iter((0.0, 0.0, 121.0))
    deadline = OperationDeadline.start(
        120.0,
        clock=lambda: next(clock_values),
    )
    with pytest.raises(AcquisitionRejected, match="operation_time_limit"):
        GitHubAdvisoryRestCollector._decode_page(
            b'[{"ghsa_id":"GHSA-aaaa-bbbb-cccc"}]',
            deadline=deadline,
        )


def test_github_same_upstream_timestamp_accepts_a_new_governed_representation(
    database,
    tmp_path: Path,
) -> None:
    base = _github_advisory(
        advisory_id="GHSA-aaaa-bbbb-drift",
        name="representation-drift",
        version="1.0.0",
        published_at="2026-08-05T09:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    changed = dict(base)
    changed["references"] = ["https://github.com/advisories/GHSA-aaaa-bbbb-drift"]
    responses = iter(([base], [changed]))
    clocks = iter((NOW, NOW + timedelta(hours=1)))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=next(responses),
            request=request,
        )

    collector = GitHubAdvisoryRestCollector(
        registry=RightsRegistry.from_path(RIGHTS_REGISTER),
        evidence_store=LocalImmutableEvidenceStore(tmp_path / "evidence"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: next(clocks),
        governance_policy=active_governance_policy(),
    )
    with Session(database.engine) as session, session.begin():
        assert collector.run(session, lane="updates").state == "complete"
    with Session(database.engine) as session, session.begin():
        assert collector.run(session, lane="updates").state == "complete"
        batches = tuple(
            session.scalars(
                select(IngestionBatchRecord).order_by(IngestionBatchRecord.completed_at)
            )
        )
        assert len(batches) == 2
        assert batches[0].idempotency_key_hash != batches[1].idempotency_key_hash
        assert all(batch.representation_hash == batch.input_sha256 for batch in batches)


def test_retained_osv_transform_uses_sorted_events_and_never_invents_a_fix() -> None:
    from smithguard.collectors import _osv_ranges

    value = {
        "ranges": [
            {
                "type": "ECOSYSTEM",
                "events": [{"limit": "2.0.0"}, {"fixed": "4.0.0"}, {"introduced": "0"}],
            }
        ]
    }
    ranges = _osv_ranges(value, ecosystem="pypi")
    assert len(ranges) == 1
    assert ranges[0]["expression"] == "<2.0.0"
    assert ranges[0]["evaluation_state"] == "supported"
    assert ranges[0]["fixed"] is None
    value["ranges"][0]["events"].append({"last_affected": "3.0.0"})
    assert _osv_ranges(value, ecosystem="pypi")[0]["evaluation_state"] == "partial"


def test_partial_comparator_remains_in_github_evidence_and_transformation() -> None:
    advisory = _github_advisory(
        advisory_id="GHSA-pchf-755w-jj6v",
        name="partial-range",
        version="1.0.0",
        published_at="2020-01-01T00:00:00Z",
        updated_at="2026-08-05T11:00:00Z",
    )
    advisory["vulnerabilities"][0]["vulnerable_version_range"] = "<= 1.3"
    from smithguard.collectors import project_github_advisory_publication_scope

    projected, excluded = project_github_advisory_publication_scope(advisory)
    assert excluded == 0
    assert projected["vulnerabilities"] == [
        {
            "package": {"ecosystem": "npm", "name": "partial-range"},
            "vulnerable_version_range": "<= 1.3",
        }
    ]
    transformed = transform_github_advisories((filter_github_advisory(projected),))
    assert transformed[0]["affected_ranges"][0]["expression"] == "<=1.3"
    assert transformed[0]["source_lineage"]["public_status"] == "reported"


@pytest.mark.parametrize(
    "event", [None, {"introduced": "0", "fixed": "2.0.0"}, {"mystery": "1.0.0"}]
)
def test_retained_osv_transform_still_rejects_malformed_event_structure(event) -> None:
    from smithguard.collectors import _osv_ranges
    from smithguard.normalization import NormalizationRejected

    with pytest.raises(NormalizationRejected):
        _osv_ranges({"ranges": [{"type": "ECOSYSTEM", "events": [event]}]}, ecosystem="npm")


@pytest.mark.parametrize("old_filter", [True, False])
def test_catalog_patch_backfill_preserves_history_and_package_boundaries(
    database, tmp_path, monkeypatch, old_filter
):
    from smithguard.advisory_catalog import catalog_evidence_for_package

    advisory = _github_advisory(
        advisory_id="GHSA-mh6f-8j2x-4483",
        name="event-stream",
        version="3.3.6",
        published_at="2018-11-26T00:00:00Z",
        updated_at="2023-01-30T05:02:00Z",
    )
    advisory["type"] = "reviewed"
    advisory["cwes"] = [{"cwe_id": "CWE-506"}]
    advisory["vulnerabilities"][0]["first_patched_version"] = "4.0.0"
    advisory["vulnerabilities"].append(
        {
            "package": {"ecosystem": "npm", "name": "flatmap-stream"},
            "vulnerable_version_range": ">= 0",
            "first_patched_version": None,
        }
    )
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200, headers={"content-type": "application/json"}, json=[advisory], request=request
        )

    with closing(LocalImmutableEvidenceStore(tmp_path / "evidence")) as store:
        collector = GitHubAdvisoryRestCollector(
            registry=RightsRegistry.from_path(RIGHTS_REGISTER),
            evidence_store=store,
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            clock=lambda: NOW,
            governance_policy=active_governance_policy(),
            advisory_type="reviewed",
            catalog_mode=True,
        )
        # Reproduce the shipped v5 filter, then refresh the unchanged upstream body
        # through v6. Only new append-only revisions may change the answer.
        policy_document = json.loads(
            (REPO_ROOT / "contracts/v1/source-governance-policy.json").read_text()
        )
        policy_document["policy_version"] = "1.0.0"
        github_rule = next(
            r for r in policy_document["sources"] if r["source_id"] == GITHUB_ADVISORY
        )
        github_rule["field_policy_id"] = "gbsec:field-policy:github-advisory-catalog-v2"
        github_rule["accepted_field_paths"].remove("vulnerabilities.first_patched_version")
        old_policy = SourceGovernancePolicy(
            policy_document, registry=RightsRegistry.from_path(RIGHTS_REGISTER)
        )
        with monkeypatch.context() as old_code:
            old_code.setattr(collector, "_governance_policy", old_policy)
            old_code.setattr(
                collector, "_catalog_processing_version", "github-advisory-catalog-5-reviewed"
            )
            if old_filter:
                old_code.setattr(
                    "smithguard.collectors.filter_github_advisory",
                    lambda document, **_kwargs: filter_github_advisory(document),
                )
            with Session(database.engine) as session, session.begin():
                collector.backfill_advisory(session, advisory_id=advisory["ghsa_id"])
                old = session.scalar(select(AdvisoryCatalogRecord))
                old_id, old_hash = old.catalog_event_id, old.record_hash
                old_evidence = [(e.id, e.sha256) for e in session.scalars(select(EvidenceRecord))]
                old_evidence_id = old.evidence_id
                family = catalog_evidence_for_package(
                    session, ecosystem="npm", name="event-stream", version="3.3.6"
                ).families[0]
                assert family.fixed_versions == ()
        for created in (True, False):
            with Session(database.engine) as session, session.begin():
                result = collector.backfill_advisory(session, advisory_id=advisory["ghsa_id"])
                assert result.catalog_package_entry_count == 2
                assert result.catalog_append_result.created is created
                assert result.catalog_append_result.revision == 2
        with Session(database.engine) as session:
            assert session.query(AdvisoryCatalogRecord).count() == 2
            assert session.get(AdvisoryCatalogRecord, old_id).record_hash == old_hash
            current = session.scalar(
                select(AdvisoryCatalogRecord).order_by(AdvisoryCatalogRecord.revision.desc())
            )
            assert current.evidence_id != old_evidence_id
            evidence = session.scalar(
                select(EvidenceRecord).where(EvidenceRecord.id == current.evidence_id)
            )
            governed_bytes = store.read_bytes(evidence.sha256)
            retained = json.loads(governed_bytes)
            assert retained[0]["vulnerabilities"][0]["first_patched_version"] == "4.0.0"
            decision = session.get(SourceGovernanceDecisionRecord, current.governance_decision_id)
            assert decision.accepted_sha256 == evidence.sha256
            assert decision.policy_version == "1.3.0"
            assert decision.field_policy_id == "gbsec:field-policy:github-advisory-catalog-v4"
            for id, digest in old_evidence:
                assert (
                    session.scalar(select(EvidenceRecord.sha256).where(EvidenceRecord.id == id))
                    == digest
                )
                assert store.read_bytes(digest)
            assert session.query(CollectorProgressRecord).count() == 0
            for name, version, applies, fixes in (
                ("event-stream", "3.3.6", True, ("4.0.0",)),
                ("event-stream", "4.0.0", False, ("4.0.0",)),
                ("flatmap-stream", "0.1.1", True, ()),
            ):
                family = catalog_evidence_for_package(
                    session, ecosystem="npm", name=name, version=version
                ).families[0]
                assert family.applies is applies
                assert family.fixed_versions == fixes
        assert all(
            r.url.params["type"] == "reviewed" and r.url.params["ghsa_id"] == advisory["ghsa_id"]
            for r in requests
        )
        assert store.pending_manifest() == []


@pytest.mark.parametrize("patch", ["", " 4.0.0", "4.0.0\n", "4.0.0\x00", "x" * 201, 4, {}, []])
def test_catalog_filter_rejects_invalid_explicit_patch(patch):
    advisory = _github_advisory(
        advisory_id="GHSA-mh6f-8j2x-4483",
        name="event-stream",
        version="3.3.6",
        published_at="2018-11-26T00:00:00Z",
        updated_at="2023-01-30T05:02:00Z",
    )
    advisory["vulnerabilities"][0]["first_patched_version"] = patch
    with pytest.raises(NormalizationRejected, match="invalid_github_first_patched_version"):
        filter_github_advisory(advisory, preserve_patched_versions=True)
    assert "first_patched_version" not in filter_github_advisory(advisory)["vulnerabilities"][0]
