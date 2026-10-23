"""Exercise catch-up through real pagination, transactions and immutable membership."""

from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import smithguard.runtime as runtime
from smithguard.collectors import GitHubAdvisoryRestCollector
from smithguard.coverage import catalog_collection_freshness
from smithguard.db.models import (
    AdvisoryCatalogRecord,
    CollectionRecordMembership,
    CollectorProgressRecord,
)
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.source_rights import RightsRegistry

from .test_collectors import NOW, _github_advisory


def test_hourly_catchup_preserves_overlap_membership_and_window_cutoffs(
    database, tmp_path, monkeypatch
):
    clock = [NOW]
    requests = []
    evidence = LocalImmutableEvidenceStore(tmp_path / "evidence", allow_group_read=True)

    class RuntimeClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0].astimezone(tz or UTC)

    def handler(request):
        requests.append(request)
        headers = {"content-type": "application/json"}
        records = []
        if request.url.params["type"] == "unreviewed" and "modified" in request.url.params:
            page = int(request.url.params.get("after", "1"))
            advisory = _github_advisory(
                advisory_id=f"GHSA-aaaa-bbbb-burst{page}",
                name="synthetic",
                version="1.0.0",
                published_at="2026-08-05T09:00:00Z",
                updated_at="2026-08-05T11:30:00Z",
            )
            advisory["type"] = "unreviewed"
            advisory["vulnerabilities"] = []
            records = [advisory]
            if page < 18:
                headers["link"] = (
                    f'<{request.url.copy_set_param("after", str(page + 1))}>; rel="next"'
                )
        return httpx.Response(200, headers=headers, json=records, request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))

    def collector(**kwargs):
        return GitHubAdvisoryRestCollector(**kwargs, clock=lambda: clock[0], client=client)

    seed = collector(
        registry=RightsRegistry.from_path(runtime.DEFAULT_RIGHTS_REGISTER),
        evidence_store=evidence,
        advisory_type="unreviewed",
        catalog_mode=True,
    )
    for _ in range(10):
        with evidence.collection_lock(), Session(database.engine) as session, session.begin():
            result = seed.run(session, lane="updates")
            assert result.state == "in_progress"
            assert result.window_ended_at == NOW

    config = runtime.RuntimeConfig(
        database_url=database.url.render_as_string(hide_password=False),
        evidence_root=tmp_path / "evidence",
        rights_register_path=runtime.DEFAULT_RIGHTS_REGISTER,
        authority_policy_path=runtime.DEFAULT_AUTHORITY_POLICY,
        governance_policy_path=runtime.DEFAULT_GOVERNANCE_POLICY,
        signing_key_path=None,
        xai_key_path=None,
        spend_policy_path=None,
        base_url="https://api.smithguard.io",
        bind_host="127.0.0.1",
        bind_port=8771,
    )
    monkeypatch.setattr(runtime, "datetime", RuntimeClock)
    monkeypatch.setattr(runtime, "load_runtime_config", lambda **_kw: config)
    monkeypatch.setattr(runtime, "_engine", lambda _config: database.engine)
    monkeypatch.setattr(runtime, "GitHubAdvisoryRestCollector", collector)
    for hour in (1, 2):
        clock[0] = NOW + timedelta(hours=hour)
        assert runtime.collect_main() == 0
        with Session(database.engine) as session:
            freshness = catalog_collection_freshness(session, lane="updates", measured_at=clock[0])
            assert freshness.state == "fresh"
            assert freshness.last_success_at == clock[0]
            assert session.scalar(select(func.count()).select_from(AdvisoryCatalogRecord)) == 18

    with Session(database.engine) as session:
        progress = list(
            session.scalars(
                select(CollectorProgressRecord)
                .where(
                    CollectorProgressRecord.segment == "unreviewed",
                    CollectorProgressRecord.lane == "updates",
                )
                .order_by(CollectorProgressRecord.sequence)
            )
        )
        assert len(progress) == 54
        assert [r.window_ended_at for r in progress] == [NOW] * 18 + [
            NOW + timedelta(hours=1)
        ] * 18 + [NOW + timedelta(hours=2)] * 18
        assert progress[18].window_started_at == NOW - timedelta(hours=1)
        assert progress[36].window_started_at == NOW
        assert session.scalar(select(func.count()).select_from(CollectionRecordMembership)) == 54
    assert not evidence.pending_manifest()
    client.close()
