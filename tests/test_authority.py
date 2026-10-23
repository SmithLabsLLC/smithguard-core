"""Closed malware authority policy and source-lineage decisions."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from smithguard.authority import (
    AuthorityPolicyError,
    evaluate_direct_openssf,
    evaluate_github_malware,
    evaluation_from_lineage,
    load_authority_policy,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "contracts/v1/malware-authority-policy.json"
COMMIT = "a" * 40


def _advisory(
    *,
    published_at: str = "2026-08-05T00:00:00Z",
    references: list[str] | None = None,
    withdrawn_at: str | None = None,
) -> dict:
    return {
        "ghsa_id": "GHSA-aaaa-bbbb-1234",
        "type": "malware",
        "published_at": published_at,
        "updated_at": "2026-08-05T01:00:00Z",
        "withdrawn_at": withdrawn_at,
        "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-1234",
        "references": references or [],
        "vulnerabilities": [],
    }


def _openssf_reference(
    identifier: str,
    *,
    ecosystem: str = "npm",
    package_name: str = "example",
    source_tree: str = "malicious",
) -> str:
    return (
        "https://github.com/ossf/malicious-packages/blob/"
        f"{COMMIT}/osv/{source_tree}/{ecosystem}/{package_name}/{identifier}.json"
    )


def test_commit_pinned_openssf_origin_confirms_without_claiming_independent_analysis() -> None:
    policy = load_authority_policy()
    evaluation = evaluate_github_malware(
        _advisory(
            references=[
                _openssf_reference(
                    "MAL-2026-123",
                    ecosystem="pypi",
                )
            ]
        ),
        ecosystem="pypi",
        package_name="example",
        version="1.0.0",
        policy=policy,
    )
    assert evaluation.public_status == "confirmed"
    assert evaluation.assertion_source_id == "gbsec:source:openssf-malicious-packages"
    assert evaluation.confirming_authority_id == "gbsec:source:openssf-malicious-packages"
    lineage = evaluation.lineage(policy=policy)
    recovered = evaluation_from_lineage(lineage, policy=policy)
    assert recovered == evaluation


def test_direct_withdrawn_openssf_tree_path_preserves_the_source_reference() -> None:
    reference = (
        "https://github.com/ossf/malicious-packages/blob/"
        f"{COMMIT}/osv/withdrawn/npm/example/MAL-2026-123.json"
    )
    evaluation = evaluate_direct_openssf(
        advisory_id="MAL-2026-123",
        source_url=reference,
        ecosystem="npm",
        exact=True,
        withdrawn=True,
        policy=load_authority_policy(),
    )
    assert evaluation.public_status == "withdrawn"
    assert reference in evaluation.source_references


def test_active_github_record_cannot_use_withdrawn_openssf_record_as_confirmation() -> None:
    evaluation = evaluate_github_malware(
        _advisory(
            references=[
                _openssf_reference(
                    "MAL-2026-123",
                    ecosystem="pypi",
                    source_tree="withdrawn",
                )
            ]
        ),
        ecosystem="pypi",
        package_name="example",
        version="1.0.0",
        policy=load_authority_policy(),
    )
    assert evaluation.public_status == "reported"
    assert evaluation.assertion_source_id is None
    assert evaluation.confirming_authority_id is None


def test_withdrawn_github_record_keeps_withdrawn_openssf_origin_identity() -> None:
    evaluation = evaluate_github_malware(
        _advisory(
            references=[_openssf_reference("MAL-2026-123", source_tree="withdrawn")],
            withdrawn_at="2026-08-06T00:00:00Z",
        ),
        ecosystem="npm",
        package_name="example",
        version="1.0.0",
        policy=load_authority_policy(),
    )
    assert evaluation.public_status == "withdrawn"
    assert evaluation.assertion_source_id == "gbsec:source:openssf-malicious-packages"
    assert evaluation.upstream_ids == ("GHSA-aaaa-bbbb-1234", "MAL-2026-123")


def test_recent_unproven_origin_is_reported_but_legacy_npm_is_confirmed() -> None:
    policy = load_authority_policy()
    recent = evaluate_github_malware(
        _advisory(),
        ecosystem="pypi",
        package_name="example",
        version="1.0.0",
        policy=policy,
    )
    assert recent.public_status == "reported"
    assert recent.confirming_authority_id is None
    assert not recent.exception_required

    legacy = evaluate_github_malware(
        _advisory(published_at="2020-01-01T00:00:00Z"),
        ecosystem="npm",
        package_name="example",
        version="1.0.0",
        policy=policy,
    )
    assert legacy.public_status == "confirmed"
    assert legacy.reason_code == "github_legacy_npm_exact_malware"


def test_github_nonexact_range_stays_reported_and_unconfirmed() -> None:
    policy = load_authority_policy()
    evaluation = evaluate_github_malware(
        _advisory(published_at="2020-01-01T00:00:00Z"),
        ecosystem="npm",
        package_name="example",
        version=None,
        policy=policy,
    )
    assert evaluation.public_status == "reported"
    assert evaluation.assertion_source_id == "gbsec:source:github-advisory-database"
    assert evaluation.confirming_authority_id is None
    assert evaluation.authority_rule_id == "gbsec:authority-rule:reported-nonexact-scope-v1"
    assert evaluation.reason_code == "source_scope_not_exact"
    assert evaluation_from_lineage(evaluation.lineage(policy=policy), policy=policy) == evaluation


def test_ambiguous_origins_route_to_exception_and_withdrawal_stops_active_status() -> None:
    policy = load_authority_policy()
    ambiguous = evaluate_github_malware(
        _advisory(
            references=[
                _openssf_reference("MAL-2026-123"),
                _openssf_reference("MAL-2026-456"),
            ]
        ),
        ecosystem="npm",
        package_name="example",
        version="1.0.0",
        policy=policy,
    )
    assert ambiguous.public_status == "reported"
    assert ambiguous.exception_reason_code == "ambiguous_openssf_origin"

    withdrawn = evaluate_github_malware(
        _advisory(
            references=[_openssf_reference("MAL-2026-123")],
            withdrawn_at="2026-08-05T02:00:00Z",
        ),
        ecosystem="npm",
        package_name="example",
        version="1.0.0",
        policy=policy,
    )
    assert withdrawn.public_status == "withdrawn"
    assert withdrawn.confirmation_method == "withdrawal"


def test_policy_and_lineage_tampering_fail_closed(tmp_path: Path) -> None:
    policy_document = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    tampered = deepcopy(policy_document)
    tampered["supported_ecosystems"].append("unknown")
    tampered_path = tmp_path / "tampered-policy.json"
    tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(AuthorityPolicyError, match="ecosystem scope"):
        load_authority_policy(tampered_path)

    policy = load_authority_policy()
    evaluation = evaluate_github_malware(
        _advisory(references=[_openssf_reference("MAL-2026-123")]),
        ecosystem="npm",
        package_name="example",
        version="1.0.0",
        policy=policy,
    )
    lineage = evaluation.lineage(policy=policy)
    lineage["authority_policy_version"] = "2099-01-01.1"
    with pytest.raises(AuthorityPolicyError, match="active authority policy"):
        evaluation_from_lineage(lineage, policy=policy)


def test_non_https_or_unpinned_reference_cannot_confirm() -> None:
    policy = load_authority_policy()
    unpinned = evaluate_github_malware(
        _advisory(
            references=[
                "https://github.com/ossf/malicious-packages/blob/main/"
                "osv/malicious/npm/example/MAL-2026-123.json"
            ]
        ),
        ecosystem="pypi",
        package_name="example",
        version="1.0.0",
        policy=policy,
    )
    assert unpinned.public_status == "reported"
    with pytest.raises(AuthorityPolicyError, match="source reference"):
        evaluate_github_malware(
            {
                **_advisory(),
                "html_url": "http://github.com/advisories/GHSA-aaaa-bbbb-1234",
            },
            ecosystem="pypi",
            package_name="example",
            version="1.0.0",
            policy=policy,
        )


def test_authority_reference_summary_keeps_late_origin_evidence_within_contract_limit() -> None:
    policy = load_authority_policy()
    references = [f"https://example.com/reference-{index}" for index in range(99)] + [
        _openssf_reference("MAL-2026-999")
    ]
    evaluation = evaluate_github_malware(
        _advisory(
            references=[
                *references[:-1],
                _openssf_reference(
                    "MAL-2026-999",
                    ecosystem="pypi",
                ),
            ]
        ),
        ecosystem="pypi",
        package_name="example",
        version="1.0.0",
        policy=policy,
    )
    assert evaluation.public_status == "confirmed"
    assert len(evaluation.source_references) == 20
    assert _openssf_reference("MAL-2026-999", ecosystem="pypi") in evaluation.source_references


def test_openssf_reference_must_match_the_exact_ecosystem_and_package() -> None:
    policy = load_authority_policy()
    mismatched = evaluate_github_malware(
        _advisory(references=[_openssf_reference("MAL-2026-123")]),
        ecosystem="pypi",
        package_name="example",
        version="1.0.0",
        policy=policy,
    )
    assert mismatched.public_status == "reported"
    assert mismatched.exception_reason_code == "mixed_upstream_identity"

    scoped = evaluate_github_malware(
        _advisory(
            references=[
                _openssf_reference(
                    "MAL-2026-456",
                    package_name="@scope/example",
                )
            ]
        ),
        ecosystem="npm",
        package_name="@scope/example",
        version="1.0.0",
        policy=policy,
    )
    assert scoped.public_status == "confirmed"
