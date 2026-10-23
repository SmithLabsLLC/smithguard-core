"""Hostile byte, archive, encoding, and parser limits."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

import pytest

from smithguard.acquisition import (
    AcquisitionLimits,
    AcquisitionRejected,
    AcquisitionRequest,
    OperationDeadline,
    inspect_evidence,
)

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _source(contract_examples: list[dict[str, Any]]) -> dict[str, Any]:
    return deepcopy(
        next(entry["value"] for entry in contract_examples if entry["definition"] == "Source")
    )


def _request(**changes: Any) -> AcquisitionRequest:
    values = {
        "source_record_id": "synthetic-001",
        "canonical_url": "https://github.com/advisories/GHSA-example",
        "retrieved_at": NOW,
        "source_published_at": NOW,
        "media_type": "application/json",
        "declared_content_length": None,
        "redirect_count": 0,
        "transport_elapsed_seconds": 0.25,
    }
    values.update(changes)
    return AcquisitionRequest(**values)


def _record(index: int = 1) -> dict[str, Any]:
    return {
        "record_id": f"synthetic-{index}",
        "artifact": {
            "ecosystem": "npm",
            "name": "safe-package",
            "version": "1.0.0",
            "digest": None,
        },
    }


def test_direct_json_is_bounded_and_duplicate_keys_fail(
    contract_examples: list[dict[str, Any]],
) -> None:
    body = json.dumps({"records": [_record()]}).encode()
    result = inspect_evidence(
        source=_source(contract_examples),
        request=_request(declared_content_length=len(body)),
        body=body,
    )
    assert len(result.records) == 1
    assert result.digest.startswith("sha256:")
    assert result.member_names == ()

    with pytest.raises(AcquisitionRejected, match="duplicate_json_key"):
        inspect_evidence(
            source=_source(contract_examples),
            request=_request(),
            body=b'{"record_id":"one","record_id":"two"}',
        )
    with pytest.raises(AcquisitionRejected, match="malformed_utf8"):
        inspect_evidence(
            source=_source(contract_examples),
            request=_request(),
            body=b'{"record_id":"bad-\xff"}',
        )


@pytest.mark.parametrize(
    ("request_changes", "body", "code"),
    [
        ({"canonical_url": "http://github.com/unsafe"}, b"{}", "source_url_not_allowed"),
        (
            {"canonical_url": "https://example.invalid/unsafe"},
            b"{}",
            "source_url_not_allowed",
        ),
        ({"redirect_count": 3}, b"{}", "redirect_limit"),
        ({"transport_elapsed_seconds": 11}, b"{}", "transport_time_limit"),
        ({"media_type": "text/html"}, b"{}", "unexpected_content_type"),
        ({"declared_content_length": 999}, b"{}", "content_length_mismatch"),
    ],
)
def test_transport_metadata_fails_closed(
    contract_examples: list[dict[str, Any]],
    request_changes: dict[str, Any],
    body: bytes,
    code: str,
) -> None:
    with pytest.raises(AcquisitionRejected, match=code):
        inspect_evidence(
            source=_source(contract_examples),
            request=_request(**request_changes),
            body=body,
        )


def test_json_byte_depth_node_and_record_limits(
    contract_examples: list[dict[str, Any]],
) -> None:
    source = _source(contract_examples)
    with pytest.raises(AcquisitionRejected, match="input_byte_limit"):
        inspect_evidence(
            source=source,
            request=_request(),
            body=b'{"record_id":"too-large"}',
            limits=AcquisitionLimits(max_input_bytes=8, max_expanded_bytes=8),
        )
    with pytest.raises(AcquisitionRejected, match="json_depth_limit"):
        inspect_evidence(
            source=source,
            request=_request(),
            body=b'{"a":{"b":{"c":{"record_id":"deep"}}}}',
            limits=AcquisitionLimits(max_json_depth=3),
        )
    with pytest.raises(AcquisitionRejected, match="json_node_limit"):
        inspect_evidence(
            source=source,
            request=_request(),
            body=b'{"record_id":"many","values":[1,2,3,4]}',
            limits=AcquisitionLimits(max_json_nodes=4),
        )
    body = json.dumps([_record(1), _record(2)]).encode()
    with pytest.raises(AcquisitionRejected, match="record_limit"):
        inspect_evidence(
            source=source,
            request=_request(),
            body=body,
            limits=AcquisitionLimits(max_records=1),
        )


def test_expired_source_rights_fail_closed(
    contract_examples: list[dict[str, Any]],
) -> None:
    source = _source(contract_examples)
    source["rights"]["review_due_on"] = "2026-08-04"
    with pytest.raises(AcquisitionRejected, match="source_rights_review_expired"):
        inspect_evidence(
            source=source,
            request=_request(),
            body=json.dumps(_record()).encode(),
        )


def test_shared_deadline_expires_during_json_object_creation(
    contract_examples: list[dict[str, Any]],
) -> None:
    readings = iter((0.0, 0.0, 0.0, 4.0))
    deadline = OperationDeadline(deadline=3.0, clock=lambda: next(readings, 4.0))

    with pytest.raises(AcquisitionRejected, match="inspection_time_limit"):
        inspect_evidence(
            source=_source(contract_examples),
            request=_request(),
            body=json.dumps({"records": [_record()]}).encode(),
            deadline=deadline,
        )
