#!/usr/bin/env python3
"""Generate Pydantic models, JSON Schemas, and public OpenAPI deterministically."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from typing import Any

from pydantic import BaseModel

from smithguard.identifiers import pretty_json_bytes

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PROJECT_ROOT
UPSTREAM_SCHEMA = REPO_ROOT / "contracts/v1/contract-bundle.schema.json"
OPERATION_CATALOG = REPO_ROOT / "contracts/v1/operation-catalog.json"
DEPLOY_APPROVAL_SCHEMA = REPO_ROOT / "contracts/v1/deploy-approval.schema.json"
MODEL_RELATIVE = Path("src/smithguard/contracts/generated.py")
ARTIFACT_RELATIVE = Path("src/smithguard/generated_artifacts")
PRIMARY_MODELS: tuple[str, ...] = (
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
GENERATOR_VERSION = "0.82.0"
PROJECT_VERSION = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
    "project"
]["version"]
PUBLIC_API_SERVER = "https://api.smithguard.io"
SHORT_ASSESSMENT_REQUEST = "PublicArtifactAssessmentShortRequest"
ASSESSMENT_REQUEST_EXAMPLES = {
    "npm": {
        "summary": "An npm package version",
        "value": {"ecosystem": "npm", "name": "event-stream", "version": "3.3.6"},
    },
    "maven": {
        "summary": "A Maven artifact (group:artifact)",
        "value": {
            "ecosystem": "maven",
            "name": "org.apache.logging.log4j:log4j-core",
            "version": "2.14.1",
        },
    },
    "github-actions": {
        "summary": "A GitHub Action tag",
        "value": {
            "ecosystem": "github-actions",
            "name": "tj-actions/changed-files",
            "version": "v45.0.7",
        },
    },
}
PUBLIC_BETA_HIDDEN_OPERATIONS = {
    "list_incidents",
    "get_incident",
    "list_incident_changes",
    "get_recommended_actions",
    "list_delivery_events",
    "list_emerging_signals",
    "get_emerging_signal",
}


def _canonical_json(value: Any) -> bytes:
    return pretty_json_bytes(value)


def _hash_file(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _rewrite_refs(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                item.replace("#/$defs/", "#/components/schemas/")
                if key == "$ref" and isinstance(item, str)
                else _rewrite_refs(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_rewrite_refs(item) for item in value]
    return value


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


def _reachable_components(
    roots: Any,
    definitions: dict[str, Any],
) -> dict[str, Any]:
    pending = list(_component_refs(roots))
    reachable: set[str] = set()
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        definition = definitions.get(name)
        if definition is None:
            raise RuntimeError(f"OpenAPI component reference is unavailable: {name}")
        reachable.add(name)
        pending.extend(_component_refs(_rewrite_refs(definition)) - reachable)
    return {name: _rewrite_refs(deepcopy(definitions[name])) for name in sorted(reachable)}


def _patch_generated_model(text: str) -> str:
    text = text.replace(
        "from datetime import date\n",
        "from datetime import date, datetime, timedelta\n",
    )
    # The generator emits one flat pydantic import line whose members vary by
    # generator version (0.82 adds constr). Rebuild it as a sorted block that also
    # carries the validators the UTC timestamp helper below needs.
    import_match = re.search(r"^from pydantic import ([A-Za-z0-9_, ]+)$", text, re.MULTILINE)
    if import_match is None:
        raise RuntimeError("generated pydantic import line not found")
    members = {name.strip() for name in import_match.group(1).split(",") if name.strip()}
    members |= {"BeforeValidator", "UrlConstraints"}
    block = "from pydantic import (\n" + "".join(f"    {name},\n" for name in sorted(members)) + ")"
    text = text[: import_match.start()] + block + text[import_match.end() :]
    marker = "\n\nclass Timestamp("
    helper = '''

def _require_utc_z(value: object) -> object:
    """Require canonical UTC input before Pydantic parses the timestamp."""
    if isinstance(value, str) and not value.endswith("Z"):
        raise ValueError("timestamp must use the canonical UTC Z suffix")
    if isinstance(value, datetime) and value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be UTC")
    return value


UtcTimestamp = Annotated[AwareDatetime, BeforeValidator(_require_utc_z)]
'''
    if marker not in text:
        raise RuntimeError("generated Timestamp model marker not found")
    text = text.replace(marker, helper + marker, 1)
    text = text.replace("RootModel[AwareDatetime]", "RootModel[UtcTimestamp]")
    text = text.replace(
        'Annotated[AwareDatetime, Field(pattern="Z$")]',
        "UtcTimestamp",
    )
    text = text.replace(
        "public_incident_url: AnyUrl",
        "public_incident_url: Annotated[\n"
        '        AnyUrl, UrlConstraints(allowed_schemes=["https"], max_length=2048)\n'
        "    ]",
    )
    text = text.replace(
        "class PublicIncidentUri(RootModel[AnyUrl]):\n    root: AnyUrl",
        "class PublicIncidentUri(\n"
        "    RootModel[\n"
        '        Annotated[AnyUrl, UrlConstraints(allowed_schemes=["https"], max_length=2048)]\n'
        "    ]\n"
        "):\n"
        "    root: Annotated[\n"
        '        AnyUrl, UrlConstraints(allowed_schemes=["https"], max_length=2048)\n'
        "    ]",
    )
    return text


def _generate_models(destination: Path) -> Path:
    output = destination / MODEL_RELATIVE
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "datamodel-codegen",
        "--input",
        str(UPSTREAM_SCHEMA),
        "--input-file-type",
        "jsonschema",
        "--output",
        str(output),
        "--output-model-type",
        "pydantic_v2.BaseModel",
        "--target-python-version",
        "3.12",
        "--use-annotated",
        "--use-union-operator",
        "--use-standard-collections",
        "--use-schema-description",
        "--use-field-description",
        "--use-double-quotes",
        "--collapse-root-models",
        "--disable-timestamp",
        "--formatters",
        "builtin",
    ]
    subprocess.run(command, check=True, cwd=PROJECT_ROOT)  # noqa: S603 - fixed generator flags and repository schema/output paths, no shell
    output.write_text(_patch_generated_model(output.read_text(encoding="utf-8")), encoding="utf-8")
    ruff_config = PROJECT_ROOT / "pyproject.toml"
    subprocess.run(  # noqa: S603 - fixed Ruff flags and generated output path, no shell
        [  # noqa: S607 - Ruff is supplied by the locked development environment
            "ruff",
            "check",
            "--fix",
            "--ignore",
            "E501",
            "--config",
            str(ruff_config),
            str(output),
        ],
        check=True,
        cwd=PROJECT_ROOT,
    )
    subprocess.run(  # noqa: S603 - fixed Ruff flags and generated output path, no shell
        ["ruff", "format", "--config", str(ruff_config), str(output)],  # noqa: S607 - locked development environment
        check=True,
        cwd=PROJECT_ROOT,
    )
    return output


def _load_models(path: Path) -> ModuleType:
    module_name = "_smithguard_generated_contracts"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load generated contracts")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    for value in vars(module).values():
        if (
            isinstance(value, type)
            and value.__module__ == module_name
            and issubclass(value, BaseModel)
        ):
            value.model_rebuild()
    return module


def _operation_parameters(
    request_definition: str,
    path: str,
    definitions: dict[str, Any],
) -> list[dict[str, Any]]:
    request_schema = definitions[request_definition]
    properties: dict[str, Any] = request_schema.get("properties", {})
    required = set(request_schema.get("required", []))
    parameters: list[dict[str, Any]] = []
    for name, schema in properties.items():
        location = "path" if "{" + name + "}" in path else "query"
        parameters.append(
            {
                "in": location,
                "name": name,
                "required": location == "path" or name in required,
                "schema": _rewrite_refs(schema),
            }
        )
    return parameters


def _build_public_beta_openapi(
    schema: dict[str, Any],
    catalog: dict[str, Any],
) -> dict[str, Any]:
    definitions = schema["$defs"]
    paths: dict[str, Any] = {}
    for operation in catalog["rest_operations"]:
        if (
            not operation["public_service_allowed"]
            or operation["operation"] in PUBLIC_BETA_HIDDEN_OPERATIONS
        ):
            continue
        method = operation["method"].lower()
        request_definition = operation["request_definition"]
        entry: dict[str, Any] = {
            "operationId": operation["operation"],
            "summary": operation["operation"].replace("_", " ").title(),
            "x-smithguard-availability": "public_beta",
            "x-smithguard-read-only": operation["read_only"],
            "x-smithguard-public-service-allowed": operation["public_service_allowed"],
            "x-smithguard-limits": {
                "max_input_bytes": operation["max_input_bytes"],
                "max_output_bytes": operation["max_output_bytes"],
                "timeout_seconds": operation["timeout_seconds"],
            },
            "responses": {
                "200": {
                    "description": (
                        "Successful response from the explicitly activated read-only service."
                    ),
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": ("#/components/schemas/" + operation["response_definition"])
                            }
                        }
                    },
                },
                "503": {
                    "description": "SmithGuard is not available.",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                        }
                    },
                },
            },
        }
        for status, description in (
            ("400", "The request is invalid."),
            ("404", "The requested public resource is unavailable."),
            ("413", "A fixed request or response limit was exceeded."),
            ("415", "The request media type is unsupported."),
            ("429", "The public request or connection limit was exceeded."),
            ("500", "Stored public state is inconsistent."),
        ):
            entry["responses"][status] = {
                "description": description,
                "content": {
                    "application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}
                },
            }
        if operation["operation"] == "assess_public_artifact":
            entry["responses"]["409"] = {
                "description": "An identical anonymous assessment is already in progress.",
                "content": {
                    "application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}
                },
            }
        if method == "get":
            entry["parameters"] = _operation_parameters(
                request_definition,
                operation["path"],
                definitions,
            )
        elif operation["operation"] == "assess_public_artifact":
            # The short form is the documented default; the full contract form stays
            # accepted for existing callers. A GET form takes the short fields as query
            # parameters.
            entry["summary"] = "Assess one exact public package version"
            entry["requestBody"] = {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "oneOf": [
                                {"$ref": "#/components/schemas/" + SHORT_ASSESSMENT_REQUEST},
                                {"$ref": "#/components/schemas/" + request_definition},
                            ]
                        },
                        "examples": ASSESSMENT_REQUEST_EXAMPLES,
                    }
                },
            }
            get_entry = deepcopy(entry)
            del get_entry["requestBody"]
            get_entry["operationId"] = "assess_public_artifact_by_query"
            get_entry["summary"] = "Assess one exact public package version (query form)"
            get_entry["parameters"] = _operation_parameters(
                SHORT_ASSESSMENT_REQUEST, operation["path"], definitions
            )
            del get_entry["responses"]["415"]
            paths.setdefault(operation["path"], {})["get"] = get_entry
        else:
            entry["requestBody"] = {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/" + request_definition}
                    }
                },
            }
        paths.setdefault(operation["path"], {})[method] = entry

    public_documents = {
        "/": ("get_quick_start", "Public beta quick start."),
        "/healthz": ("get_liveness", "Process liveness."),
        "/readyz": ("get_readiness", "Public-data readiness."),
        "/v1/public-key.json": ("get_public_key", "Current signing-key status."),
        "/v1/public-keys/{public_key_id}.json": (
            "get_archived_public_key",
            "Retained verification key for a signed historical snapshot.",
        ),
        "/openapi.json": ("get_public_openapi", "This generated public contract."),
    }
    for path, (operation_id, description) in public_documents.items():
        schema_ref = (
            "#/components/schemas/PublicKeyDocument" if path.startswith("/v1/public-key") else None
        )
        operation: dict[str, Any] = {
            "operationId": operation_id,
            "summary": operation_id.replace("_", " ").title(),
            "x-smithguard-availability": "public_beta",
            "x-smithguard-read-only": True,
            "x-smithguard-public-service-allowed": True,
            "responses": {
                "200": {
                    "description": description,
                    "content": {
                        "application/json": {
                            "schema": (
                                {"$ref": schema_ref}
                                if schema_ref is not None
                                else {"type": "object"}
                            )
                        }
                    },
                },
                "503": {
                    "description": "The service is not ready.",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                        }
                    },
                },
            },
        }
        if "{public_key_id}" in path:
            operation["parameters"] = [
                {
                    "in": "path",
                    "name": "public_key_id",
                    "required": True,
                    "schema": {
                        "type": "string",
                        "pattern": r"^gbsec:snapshot-public-key:[a-f0-9]{40}$",
                        "maxLength": 160,
                    },
                }
            ]
            for status, status_description in (
                ("400", "The public key identifier is invalid."),
                ("404", "The retained public key is unavailable."),
            ):
                operation["responses"][status] = {
                    "description": status_description,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                        }
                    },
                }
        operation["responses"]["429"] = {
            "description": "The public request limit was exceeded.",
            "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}
            },
        }
        paths[path] = {
            "get": {
                **operation,
            }
        }

    error_response = {
        "type": "object",
        "additionalProperties": False,
        "required": ["error"],
        "properties": {
            "error": {
                "type": "object",
                "additionalProperties": False,
                "required": ["code", "message", "retryable"],
                "properties": {
                    "code": {"type": "string", "minLength": 3, "maxLength": 80},
                    "message": {"type": "string", "minLength": 1, "maxLength": 500},
                    "retryable": {"type": "boolean"},
                },
            }
        },
    }
    public_key_document = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "algorithm",
            "public_key_id",
            "public_key_base64",
            "status",
            "canonicalization",
        ],
        "properties": {
            "algorithm": {"const": "Ed25519"},
            "public_key_id": {"$ref": "#/components/schemas/StableId"},
            "public_key_base64": {"type": "string", "minLength": 44, "maxLength": 44},
            "status": {"enum": ["active", "verification_only", "revoked"]},
            "canonicalization": {
                "enum": [
                    "goodboy-canonical-json-v1",
                    "smithguard-canonical-json-v1",
                ]
            },
        },
    }
    from smithguard.bulletin_contract import COMPONENTS as BULLETIN_COMPONENTS
    from smithguard.bulletin_contract import openapi_paths as bulletin_paths
    from smithguard.lead_public_contract import LEAD, PAGE, PATH

    paths["/v1/emerging-leads.json"] = deepcopy(PATH)
    paths.update(deepcopy(bulletin_paths()))
    all_components = {
        **deepcopy(definitions),
        **deepcopy(BULLETIN_COMPONENTS),
        "EmergingLead": deepcopy(LEAD),
        "EmergingLeadPage": deepcopy(PAGE),
        "ErrorResponse": error_response,
        "PublicKeyDocument": public_key_document,
    }
    components = _reachable_components(paths, all_components)
    return {
        "openapi": "3.1.0",
        "servers": [{"url": PUBLIC_API_SERVER}],
        "info": {
            "title": "SmithGuard contract",
            "version": PROJECT_VERSION,
            "description": (
                "Generated contract for the explicitly activated read-only public beta."
            ),
        },
        "paths": paths,
        "components": {"schemas": components},
        "x-smithguard-contract-version": schema["x-smithguard-contract-version"],
        "x-smithguard-service-state": "public_beta",
        "x-smithguard-mcp": {
            "url": f"{PUBLIC_API_SERVER}/mcp",
            "transport": "streamable-http",
            "authentication": "none",
            "read_only": True,
            "tools": [
                "assess_public_artifact",
                "get_coverage",
                "get_emerging_leads",
                "get_verification_key",
                "list_bulletins",
                "get_bulletin",
                "get_bulletin_changes",
                "get_bulletin_status",
            ],
            "boundary": "Exact public artifact coordinates only; no private data or uploads.",
        },
    }


def _generate_tree(destination: Path) -> None:
    model_path = _generate_models(destination)
    module = _load_models(model_path)
    artifact_root = destination / ARTIFACT_RELATIVE
    schema_root = artifact_root / "schemas"
    schema_root.mkdir(parents=True, exist_ok=True)
    (artifact_root / "__init__.py").write_text(
        '"""Deterministic generated schemas and OpenAPI contract."""\n',
        encoding="utf-8",
    )

    schema = json.loads(UPSTREAM_SCHEMA.read_text(encoding="utf-8"))
    catalog = json.loads(OPERATION_CATALOG.read_text(encoding="utf-8"))
    for name in PRIMARY_MODELS:
        model = getattr(module, name)
        output = model.model_json_schema(mode="validation")
        (schema_root / f"{name}.schema.json").write_bytes(_canonical_json(output))
    (schema_root / "contract-models.schema.json").write_bytes(
        _canonical_json(module.SmithguardV1ContractBundle.model_json_schema(mode="validation"))
    )
    (artifact_root / "openapi-public-beta.json").write_bytes(
        _canonical_json(_build_public_beta_openapi(schema, catalog))
    )
    (artifact_root / "source-contract-bundle.schema.json").write_bytes(_canonical_json(schema))
    deploy_approval_schema = json.loads(DEPLOY_APPROVAL_SCHEMA.read_text(encoding="utf-8"))
    (artifact_root / "deploy-approval.schema.json").write_bytes(
        _canonical_json(deploy_approval_schema)
    )

    artifact_files = sorted(
        path
        for path in artifact_root.rglob("*")
        if path.is_file()
        and path.name != "manifest.json"
        and path.name != "__init__.py"
        and path.suffix != ".pyc"
        and "__pycache__" not in path.parts
    )
    manifest = {
        "schema_version": "1.0.0",
        "generator": {
            "name": "datamodel-code-generator",
            "version": GENERATOR_VERSION,
        },
        "inputs": {
            str(UPSTREAM_SCHEMA.relative_to(REPO_ROOT)): _hash_file(UPSTREAM_SCHEMA),
            str(OPERATION_CATALOG.relative_to(REPO_ROOT)): _hash_file(OPERATION_CATALOG),
            str(DEPLOY_APPROVAL_SCHEMA.relative_to(REPO_ROOT)): _hash_file(DEPLOY_APPROVAL_SCHEMA),
        },
        "artifacts": {
            str(path.relative_to(destination)): _hash_file(path) for path in artifact_files
        },
    }
    (artifact_root / "manifest.json").write_bytes(_canonical_json(manifest))


def _tree_bytes(root: Path) -> dict[str, bytes]:
    paths = [MODEL_RELATIVE, ARTIFACT_RELATIVE]
    output: dict[str, bytes] = {}
    for relative in paths:
        target = root / relative
        if target.is_file():
            output[str(relative)] = target.read_bytes()
        elif target.exists():
            for path in sorted(
                item
                for item in target.rglob("*")
                if item.is_file() and item.suffix != ".pyc" and "__pycache__" not in item.parts
            ):
                output[str(path.relative_to(root))] = path.read_bytes()
    return output


def generate(*, check: bool) -> None:
    if check:
        with tempfile.TemporaryDirectory(
            prefix=".smithguard-generation-",
            dir=PROJECT_ROOT,
        ) as temporary:
            candidate_root = Path(temporary)
            _generate_tree(candidate_root)
            expected = _tree_bytes(PROJECT_ROOT)
            actual = _tree_bytes(candidate_root)
            if expected != actual:
                missing = sorted(set(expected) - set(actual))
                extra = sorted(set(actual) - set(expected))
                changed = sorted(
                    path for path in set(expected) & set(actual) if expected[path] != actual[path]
                )
                raise SystemExit(
                    "generated artifacts differ: "
                    f"missing={missing}, extra={extra}, changed={changed}"
                )
        print("generated artifacts are current")
        return
    _generate_tree(PROJECT_ROOT)
    print("generated Pydantic models, schemas, and OpenAPI")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    generate(check=arguments.check)


if __name__ == "__main__":
    main()
