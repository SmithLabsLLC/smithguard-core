"""REST proxy errors are disjoint from application/MCP summary error envelopes."""

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from smithguard import hosted_mcp
from smithguard import summary_contract as contract

ROOT = Path(__file__).resolve().parents[1]
OPENAPI = json.loads(
    (ROOT / "src/smithguard/generated_artifacts/openapi-public-beta.json").read_bytes()
)
RESPONSES = OPENAPI["paths"][contract.REST_PATH]["post"]["responses"]
PROXY_CODES = {
    405: "method_not_allowed",
    413: "request_limit_exceeded",
    429: "rate_limit_exceeded",
    503: "service_unavailable",
}


def validator(schema):
    return Draft202012Validator({**schema, "components": OPENAPI["components"]})


def response_validator(status):
    return validator(RESPONSES[str(status)]["content"]["application/json"]["schema"])


@pytest.mark.parametrize("config", ["smithguard.conf", "smithguard-domain.conf.example"])
@pytest.mark.parametrize("status", sorted(PROXY_CODES))
def test_actual_proxy_bodies_match_only_generic_rest_branch(config, status):
    text = (ROOT / "deploy/nginx" / config).read_text()
    bodies = [
        json.loads(body)
        for code, body in re.findall(r"return (405|413|429|503) '([^']+)';", text)
        if int(code) == status
    ]
    assert len(bodies) == 1
    body = bodies[0]
    assert body["error"]["code"] == PROXY_CODES[status]
    generic = validator({"$ref": "#/components/schemas/ErrorResponse"})
    assert generic.is_valid(body)
    assert not contract.ERROR_VALIDATOR.is_valid(body)
    response_validator(status).validate(body)


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (413, "request_limit_exceeded"),
        (429, "anonymous_burst_limit_exceeded"),
        (503, "service_unavailable"),
    ],
)
def test_application_error_is_exactly_one_branch_and_both_remain_closed(status, code):
    schema = RESPONSES[str(status)]["content"]["application/json"]["schema"]
    assert schema == {
        "oneOf": [
            {"$ref": "#/components/schemas/PublicArtifactSummaryError"},
            {"$ref": "#/components/schemas/ErrorResponse"},
        ]
    }
    body = contract.error_document(code, retryable=True, retry_after="7")
    assert body["error"]["retry_after_seconds"] == 7
    assert sum(validator(branch).is_valid(body) for branch in schema["oneOf"]) == 1
    response_validator(status).validate(body)
    assert not response_validator(status).is_valid({**body, "unexpected": True})
    generic = {
        "error": {
            "code": PROXY_CODES[status],
            "message": "synthetic proxy refusal",
            "retryable": True,
        }
    }
    assert sum(validator(branch).is_valid(generic) for branch in schema["oneOf"]) == 1
    assert not response_validator(status).is_valid(
        {"error": {**generic["error"], "unexpected": True}}
    )


def test_only_proxy_capable_statuses_change_and_method_error_is_generic_only():
    assert contract.openapi_path()["post"]["responses"] == RESPONSES
    for status in [400, 409, 415, 500]:
        assert RESPONSES[str(status)]["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/PublicArtifactSummaryError"
        }
    assert RESPONSES["405"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorResponse"
    }
    assert "502" not in RESPONSES and "504" not in RESPONSES


def test_application_and_mcp_validation_do_not_accept_proxy_errors():
    assert "rate_limit_exceeded" not in contract.ERROR_CODES
    assert contract.error_document("rate_limit_exceeded")["error"]["code"] == "summary_unavailable"
    summary = contract.error_document("anonymous_burst_limit_exceeded", retryable=True)
    proxy = {
        "error": {
            "code": "rate_limit_exceeded",
            "message": "public request limit exceeded",
            "retryable": True,
        }
    }
    contract.ERROR_VALIDATOR.validate(summary)
    assert not contract.ERROR_VALIDATOR.is_valid(proxy)
    tool_schema = hosted_mcp._summary_definitions()[0].output_schema
    assert tool_schema["oneOf"] == [contract.SUMMARY, contract.ERROR]
    Draft202012Validator(tool_schema).validate(summary)
    assert not Draft202012Validator(tool_schema).is_valid(proxy)
