"""Frozen contract and generated public-artifact checks."""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from copy import deepcopy
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError

from smithguard import __version__
from smithguard.contracts.generated import PublicIncidentUri
from smithguard.contracts.runtime import (
    CONTRACT_MODEL_NAMES,
    model_for,
    parse_contract,
)
from tools.generate_artifacts import GENERATOR_VERSION

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_SCHEMA = REPO_ROOT / "contracts/v1/contract-bundle.schema.json"
GENERATED_ROOT = PACKAGE_ROOT / "src/smithguard/generated_artifacts"


def _component_refs(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "$ref" and isinstance(item, str) and item.startswith("#/components/schemas/"):
                refs.add(item.removeprefix("#/components/schemas/"))
            else:
                refs.update(_component_refs(item))
    elif isinstance(value, list):
        for item in value:
            refs.update(_component_refs(item))
    return refs


def test_all_frozen_examples_match_json_schema_and_pydantic(
    contract_examples: list[dict[str, Any]],
) -> None:
    schema = json.loads(UPSTREAM_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    assert len(contract_examples) == 27
    assert len(CONTRACT_MODEL_NAMES) == 24
    assert set(CONTRACT_MODEL_NAMES) < {entry["definition"] for entry in contract_examples}

    for example in contract_examples:
        validator.validate(example["value"])
        if example["definition"] in CONTRACT_MODEL_NAMES:
            parsed = parse_contract(example["definition"], example["value"])
            validator.validate(parsed.model_dump(mode="json", exclude_none=False))


def test_contracts_are_closed_and_require_canonical_utc(
    contract_examples: list[dict[str, Any]],
) -> None:
    source = next(entry["value"] for entry in contract_examples if entry["definition"] == "Source")
    with pytest.raises(ValidationError):
        model_for("Source").model_validate({**source, "unexpected": True})
    with pytest.raises(ValidationError):
        model_for("Source").model_validate({**source, "created_at": "2026-08-05T00:00:00+00:00"})
    with pytest.raises(ValueError, match="unsupported contract definition"):
        model_for("NotAContract")


def test_preliminary_warning_runtime_accepts_legacy_and_requires_new_provenance(
    contract_examples: list[dict[str, Any]],
) -> None:
    warning = next(
        deepcopy(entry["value"])
        for entry in contract_examples
        if entry["definition"] == "PreliminaryWarning"
    )
    missing_actor = deepcopy(warning)
    missing_actor.pop("qualification_actor_id")
    with pytest.raises(ValueError, match="source contract"):
        parse_contract("PreliminaryWarning", missing_actor)

    legacy = deepcopy(warning)
    legacy["schema_version"] = "1.0.0"
    for field in (
        "qualification_basis",
        "qualification_actor_id",
        "qualification_reason",
        "qualification_sha256",
        "source_origins",
        "latest_recheck_reason",
        "latest_recheck_source_urls",
        "terminal_actor_id",
        "terminal_evidence_urls",
        "terminal_expected_revision",
    ):
        legacy.pop(field)
    parsed = parse_contract("PreliminaryWarning", legacy)
    assert parsed.schema_version.value == "1.0.0"


def test_runtime_rejects_the_same_type_uniqueness_and_uri_drift_as_source_schema(
    contract_examples: list[dict[str, Any]],
) -> None:
    schema = json.loads(UPSTREAM_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    source = next(entry["value"] for entry in contract_examples if entry["definition"] == "Source")
    incident = next(
        entry["value"] for entry in contract_examples if entry["definition"] == "Incident"
    )
    candidates = (
        ("Source", {**source, "name": 12}),
        ("Source", {**source, "canonical_url": "not-a-uri"}),
        ("Incident", {**incident, "alias_ids": [incident["id"], incident["id"]]}),
    )
    for definition, candidate in candidates:
        assert not validator.is_valid(candidate)
        with pytest.raises(ValueError, match="source contract"):
            parse_contract(definition, candidate)


def test_authority_decision_evidence_bound_matches_persistence(
    contract_examples: list[dict[str, Any]],
) -> None:
    authority = next(
        entry["value"] for entry in contract_examples if entry["definition"] == "AuthorityDecision"
    )
    with pytest.raises(ValidationError):
        model_for("AuthorityDecision").model_validate(
            {
                **authority,
                "evidence_ids": [],
            }
        )
    with pytest.raises(ValidationError):
        model_for("AuthorityDecision").model_validate(
            {
                **authority,
                "evidence_ids": [f"gbsec:evidence:authority-bound-{index}" for index in range(101)],
            }
        )


def test_public_incident_uri_accepts_only_https() -> None:
    assert str(PublicIncidentUri.model_validate("https://example.test/incident").root) == (
        "https://example.test/incident"
    )
    with pytest.raises(ValidationError):
        PublicIncidentUri.model_validate("http://example.test/incident")
    with pytest.raises(ValidationError):
        PublicIncidentUri.model_validate("ftp://example.test/incident")


def test_generated_manifest_hashes_every_artifact() -> None:
    project = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    generator_pins = [
        pin.removeprefix("datamodel-code-generator==")
        for pin in project["dependency-groups"]["dev"]
        if pin.startswith("datamodel-code-generator==")
    ]
    assert generator_pins == [GENERATOR_VERSION]
    assert version("datamodel-code-generator") == GENERATOR_VERSION
    manifest = json.loads((GENERATED_ROOT / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "1.0.0"
    assert manifest["generator"] == {
        "name": "datamodel-code-generator",
        "version": GENERATOR_VERSION,
    }
    for relative, expected in manifest["artifacts"].items():
        actual = "sha256:" + sha256((PACKAGE_ROOT / relative).read_bytes()).hexdigest()
        assert actual == expected


def test_package_metadata_is_the_single_application_version_source() -> None:
    project = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert __version__ == project["project"]["version"]


def test_generator_check_is_reproducible() -> None:
    result = subprocess.run(
        [sys.executable, str(PACKAGE_ROOT / "tools/generate_artifacts.py"), "--check"],
        cwd=PACKAGE_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == "generated artifacts are current"


def test_public_openapi_is_the_only_generated_service_contract() -> None:
    public_openapi = json.loads(
        (GENERATED_ROOT / "openapi-public-beta.json").read_text(encoding="utf-8")
    )
    assert public_openapi["info"]["title"] == "SmithGuard contract"
    assert public_openapi["x-smithguard-service-state"] == "public_beta"
    assert public_openapi["servers"] == [{"url": "https://api.smithguard.io"}]
    assert _component_refs(public_openapi) <= set(public_openapi["components"]["schemas"])
    assert {path.name for path in GENERATED_ROOT.glob("openapi*.json")} == {
        "openapi-public-beta.json"
    }
