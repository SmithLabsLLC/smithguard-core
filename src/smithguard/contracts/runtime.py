"""Strict runtime entry point for generated SmithGuard contracts."""

import json
from collections.abc import Mapping
from functools import cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from pydantic import BaseModel

from . import generated

CONTRACT_MODEL_NAMES: tuple[str, ...] = (
    "Source",
    "RawEvidence",
    "AuthorityDecision",
    "Claim",
    "Artifact",
    "AffectedRange",
    "Relationship",
    "Incident",
    "IncidentEvent",
    "PreliminaryWarning",
    "RecommendedAction",
    "PublicArtifactAssessmentRequest",
    "PublicArtifactAssessment",
    "InventorySnapshot",
    "DependencyDelta",
    "ExposurePath",
    "RemediationFrontier",
    "PolicyDecision",
    "ApprovalRecord",
    "PolicyException",
    "AssessmentReceipt",
    "RestOperation",
    "McpOperation",
    "ReplayCase",
)

RUNTIME_AUXILIARY_MODEL_NAMES: tuple[str, ...] = (
    "ClaimLineage",
    "PreliminaryWarningPage",
    "SourceCoverageReport",
)


def model_for(definition: str) -> type[BaseModel]:
    """Return an allowlisted generated model for a frozen contract definition."""
    if definition not in {
        *CONTRACT_MODEL_NAMES,
        *RUNTIME_AUXILIARY_MODEL_NAMES,
    }:
        raise ValueError(f"unsupported contract definition: {definition}")
    model = getattr(generated, definition, None)
    if not isinstance(model, type) or not issubclass(model, BaseModel):
        raise RuntimeError(f"generated contract model is unavailable: {definition}")
    return model


@cache
def _source_contract() -> dict[str, Any]:
    resource = files("smithguard.generated_artifacts").joinpath(
        "source-contract-bundle.schema.json"
    )
    value = json.loads(resource.read_text(encoding="ascii"))
    if not isinstance(value, dict) or not isinstance(value.get("$defs"), dict):
        raise RuntimeError("source contract artifact is invalid")
    return value


@cache
def _source_validator(definition: str) -> Draft202012Validator:
    source = _source_contract()
    if definition not in source["$defs"]:
        raise ValueError(f"unsupported source contract definition: {definition}")
    schema = {
        "$schema": source["$schema"],
        "$ref": f"#/$defs/{definition}",
        "$defs": source["$defs"],
    }
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def parse_contract(definition: str, payload: Mapping[str, Any]) -> BaseModel:
    """Validate one JSON value against the source schema and strict runtime model."""
    value = json.loads(json.dumps(dict(payload), ensure_ascii=True))
    try:
        _source_validator(definition).validate(value)
    except ValidationError as error:
        raise ValueError(f"{definition} does not match its source contract") from error
    return model_for(definition).model_validate(value)
