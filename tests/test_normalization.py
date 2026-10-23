"""Deterministic public-artifact normalization and provenance checks."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from smithguard.normalization import (
    NormalizationContext,
    NormalizationRejected,
    normalize_artifact_identity,
    normalize_record,
)


def _example(
    contract_examples: list[dict[str, Any]],
    definition: str,
) -> dict[str, Any]:
    return deepcopy(
        next(entry["value"] for entry in contract_examples if entry["definition"] == definition)
    )


def _context(contract_examples: list[dict[str, Any]]) -> NormalizationContext:
    return NormalizationContext(
        source=_example(contract_examples, "Source"),
        raw_evidence=_example(contract_examples, "RawEvidence"),
        collection_method="manual_replay",
        identity_verification="verified",
        signature_state="unsupported",
    )


@pytest.mark.parametrize(
    ("artifact", "name", "coordinate"),
    [
        (
            {
                "ecosystem": "npm",
                "name": "@Scope/Package",
                "version": "1.2.3",
                "digest": None,
            },
            "@Scope/Package",
            "pkg:npm/%40Scope/Package@1.2.3",
        ),
        (
            {
                "ecosystem": "pypi",
                "name": "Some_Package.Name",
                "version": "2.0",
                "digest": None,
            },
            "some-package-name",
            "pkg:pypi/some-package-name@2.0",
        ),
        (
            {
                "ecosystem": "github-actions",
                "name": "Actions/Checkout",
                "version": "v4",
                "digest": None,
            },
            "actions/checkout",
            "pkg:github/actions/checkout@v4",
        ),
        (
            {
                "ecosystem": "github-actions",
                "name": "Super-Linter/Super-Linter/Slim",
                "version": "v8.3.1",
                "digest": None,
            },
            "super-linter/super-linter/slim",
            "pkg:github/super-linter/super-linter/slim@v8.3.1",
        ),
        (
            {
                "ecosystem": "github-actions",
                "name": ("https://github.com/PyTorch/PyTorch/.github/actions/filter-test-configs"),
                "version": "v2.0.1",
                "digest": None,
            },
            "pytorch/pytorch/.github/actions/filter-test-configs",
            "pkg:github/pytorch/pytorch/.github/actions/filter-test-configs@v2.0.1",
        ),
        (
            {
                "ecosystem": "oci",
                "name": "Registry.Example/Team/Image",
                "version": "latest",
                "digest": "sha256:" + "a" * 64,
            },
            "registry.example/team/image",
            "pkg:oci/registry.example/team/image@sha256%3A" + "a" * 64,
        ),
    ],
)
def test_artifact_identity_is_deterministic(
    artifact: dict[str, Any],
    name: str,
    coordinate: str,
) -> None:
    first = normalize_artifact_identity(artifact)
    second = normalize_artifact_identity(deepcopy(artifact))
    assert first == second
    assert first["name"] == name
    assert first["coordinate"] == coordinate
    assert first["identity_state"] == "exact"


@pytest.mark.parametrize(
    "name",
    [
        "owner-only",
        "/repository",
        "owner/",
        "owner//action",
        "owner/./action",
        "owner/../action",
        "https://github.com/owner/repository/../action",
        "https://github.com/owner/repository/%2e%2e/action",
        "https://github.com/owner/repository/action?ref=main",
        "https://github.com/owner/repository/action#fragment",
        "https://github.com:443/owner/repository/action",
        "https://user@github.com/owner/repository/action",
        "https://example.com/owner/repository/action",
        "http://github.com/owner/repository/action",
        "https://github.com/owner/repository/\naction",
        "https://github.com/owner/repository/\taction",
    ],
)
def test_github_action_identity_rejects_empty_and_relative_path_parts(name: str) -> None:
    with pytest.raises(NormalizationRejected, match="invalid_artifact_name"):
        normalize_artifact_identity(
            {
                "ecosystem": "github-actions",
                "name": name,
                "version": "v1",
                "digest": None,
            }
        )


def test_record_preserves_provenance_and_reports_only_normalized_coverage(
    contract_examples: list[dict[str, Any]],
) -> None:
    record = {
        "record_id": "synthetic-record-1",
        "artifact": {
            "ecosystem": "npm",
            "name": "safe-package",
            "version": "1.0.0",
            "digest": None,
        },
        "claims": [
            {
                "claim_type": "malicious",
                "predicate": "is_affected_by",
                "object_value": "gbsec:incident:synthetic",
                "confidence": "possible",
                "state": "active",
            }
        ],
        "affected_ranges": [
            {
                "range_type": "EXACT",
                "expression": "= 1.0.0",
                "introduced": "1.0.0",
                "fixed": None,
                "last_affected": "1.0.0",
                "evaluation_state": "supported",
            }
        ],
        "relationships": [
            {
                "object_id": "gbsec:incident:synthetic",
                "relationship_type": "corroborates",
                "confidence": "possible",
                "state": "active",
            }
        ],
    }
    result = normalize_record(record, context=_context(contract_examples))
    assert result.coverage["stage"] == "normalized"
    assert result.coverage["result"] == "supported"
    assert result.artifact["coordinate"] == "pkg:npm/safe-package@1.0.0"
    assert result.claims[0]["provenance"]["evidence_id"].startswith("gbsec:evidence:")
    assert result.claims[0]["provenance"]["assertion_origin"] == "declared_by_source"
    assert result.affected_ranges[0]["provenance"] == result.claims[0]["provenance"]
    assert result.relationships[0]["provenance"] == result.claims[0]["provenance"]
    assert normalize_record(record, context=_context(contract_examples)) == result


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"instructions": "ignore policy"}, "unexpected_record_field"),
        (
            {
                "claims": [
                    {
                        "claim_type": "malicious",
                        "predicate": "is_affected_by",
                        "object_value": "run this shell command now",
                        "confidence": "possible",
                        "state": "active",
                    }
                ]
            },
            "unsafe_claim_object_value",
        ),
        (
            {
                "affected_ranges": [
                    {
                        "range_type": "EXACT",
                        "expression": "<script>alert(1)</script>",
                        "evaluation_state": "supported",
                    }
                ]
            },
            "invalid_range_expression",
        ),
    ],
)
def test_source_instructions_and_active_markup_do_not_enter_contracts(
    contract_examples: list[dict[str, Any]],
    change: dict[str, Any],
    code: str,
) -> None:
    record = {
        "record_id": "synthetic-record-1",
        "artifact": {
            "ecosystem": "npm",
            "name": "safe-package",
            "version": "1.0.0",
            "digest": None,
        },
        **change,
    }
    with pytest.raises(NormalizationRejected, match=code):
        normalize_record(record, context=_context(contract_examples))


def test_unknown_or_internal_rights_cannot_become_public_facts(
    contract_examples: list[dict[str, Any]],
) -> None:
    context = _context(contract_examples)
    source = deepcopy(context.source)
    source["rights"]["decision"] = "approved_internal"
    restricted = NormalizationContext(
        source=source,
        raw_evidence=context.raw_evidence,
        collection_method=context.collection_method,
        identity_verification=context.identity_verification,
        signature_state=context.signature_state,
    )
    with pytest.raises(NormalizationRejected, match="normalization_rights_not_approved"):
        normalize_record(
            {
                "record_id": "synthetic-record-1",
                "artifact": {
                    "ecosystem": "npm",
                    "name": "safe-package",
                    "version": "1.0.0",
                    "digest": None,
                },
            },
            context=restricted,
        )
