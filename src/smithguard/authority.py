"""Closed, deterministic authority decisions for public malware claims."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from smithguard.ecosystems import THREAT_SEARCH_ECOSYSTEMS
from smithguard.identifiers import (
    REASON_CODE_LONG,
    REGISTER_JSON_MAX_DEPTH,
    REGISTER_JSON_MAX_NODES,
    stable_id,
    strict_json_loads,
    timestamp,
)

GITHUB_ADVISORY = "gbsec:source:github-advisory-database"
OPENSSF_MALICIOUS = "gbsec:source:openssf-malicious-packages"
DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parents[2] / "contracts" / "v1" / "malware-authority-policy.json"
)
POLICY_KEYS = {
    "schema_version",
    "policy_id",
    "policy_version",
    "source_rights_register_id",
    "attribution_policy_version",
    "legacy_github_npm_published_before",
    "supported_ecosystems",
    "rules",
    "exception_reason_codes",
}
RULE_KEYS = {
    "rule_id",
    "transport_source_id",
    "assertion_source_id",
    "confirming_authority_id",
    "origin_requirement",
    "scope_requirement",
    "active_status",
    "confirmation_method",
    "reason_code",
}
EXPECTED_RULES = {
    "gbsec:authority-rule:github-openssf-exact-malware-v1",
    "gbsec:authority-rule:github-legacy-npm-exact-malware-v1",
    "gbsec:authority-rule:openssf-direct-exact-malware-v1",
}
EXPECTED_RULE_VALUES = {
    "gbsec:authority-rule:github-openssf-exact-malware-v1": {
        "rule_id": "gbsec:authority-rule:github-openssf-exact-malware-v1",
        "transport_source_id": GITHUB_ADVISORY,
        "assertion_source_id": OPENSSF_MALICIOUS,
        "confirming_authority_id": OPENSSF_MALICIOUS,
        "origin_requirement": "commit_pinned_openssf_report",
        "scope_requirement": "exact_artifact_version",
        "active_status": "confirmed",
        "confirmation_method": "automated_source_policy",
        "reason_code": "openssf_exact_malware_via_github",
    },
    "gbsec:authority-rule:github-legacy-npm-exact-malware-v1": {
        "rule_id": "gbsec:authority-rule:github-legacy-npm-exact-malware-v1",
        "transport_source_id": GITHUB_ADVISORY,
        "assertion_source_id": GITHUB_ADVISORY,
        "confirming_authority_id": GITHUB_ADVISORY,
        "origin_requirement": "legacy_github_npm_before_cutoff",
        "scope_requirement": "exact_artifact_version",
        "active_status": "confirmed",
        "confirmation_method": "automated_source_policy",
        "reason_code": "github_legacy_npm_exact_malware",
    },
    "gbsec:authority-rule:openssf-direct-exact-malware-v1": {
        "rule_id": "gbsec:authority-rule:openssf-direct-exact-malware-v1",
        "transport_source_id": OPENSSF_MALICIOUS,
        "assertion_source_id": OPENSSF_MALICIOUS,
        "confirming_authority_id": OPENSSF_MALICIOUS,
        "origin_requirement": "direct_openssf_report",
        "scope_requirement": "exact_artifact_version",
        "active_status": "confirmed",
        "confirmation_method": "automated_source_policy",
        "reason_code": "openssf_direct_exact_malware",
    },
}
EXPECTED_EXCEPTIONS = {
    "ambiguous_openssf_origin",
    "conflicting_authoritative_source",
    "invalid_source_policy",
    "mixed_upstream_identity",
    "source_policy_change_required",
}
SUPPORTED_ECOSYSTEMS = set(THREAT_SEARCH_ECOSYSTEMS)
SAFE_POLICY_VERSION = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[0-9]+$")
SAFE_REASON = REASON_CODE_LONG
OPENSSF_REFERENCE = re.compile(
    r"^/ossf/malicious-packages/blob/[a-f0-9]{40}/"
    r"osv/(?P<source_tree>malicious|withdrawn)/"
    r"(?P<ecosystem>[A-Za-z0-9._+-]{1,80})/"
    r"(?P<package>[A-Za-z0-9._%+@/-]{1,400})/"
    r"(?P<advisory>MAL-[0-9]{4}-[0-9]+)\.json$"
)
OPENSSF_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "pypi",
    "crates.io": "rust",
    "go": "go",
}
PYPI_NORMALIZE = re.compile(r"[-_.]+")


class AuthorityPolicyError(ValueError):
    """The authority policy or source claim is invalid."""


@dataclass(frozen=True, slots=True)
class AuthorityPolicy:
    policy_id: str
    policy_version: str
    source_rights_register_id: str
    attribution_policy_version: str
    legacy_github_npm_published_before: datetime
    supported_ecosystems: frozenset[str]
    rules: Mapping[str, Mapping[str, str]]
    exception_reason_codes: frozenset[str]


@dataclass(frozen=True, slots=True)
class AuthorityEvaluation:
    public_status: str
    confirmation_method: str
    transport_source_id: str
    assertion_source_id: str | None
    confirming_authority_id: str | None
    authority_rule_id: str
    reason_code: str
    upstream_ids: tuple[str, ...]
    source_references: tuple[str, ...]
    exception_reason_code: str | None = None

    @property
    def exception_required(self) -> bool:
        return self.exception_reason_code is not None

    @property
    def claim_confidence(self) -> str:
        return {
            "confirmed": "confirmed",
            "corroborated": "probable",
            "reported": "unverified",
            "disputed": "disputed",
            "withdrawn": "confirmed",
        }[self.public_status]

    def lineage(
        self,
        *,
        policy: AuthorityPolicy,
    ) -> dict[str, Any]:
        return {
            "transport_source_id": self.transport_source_id,
            "assertion_source_state": (
                "identified" if self.assertion_source_id is not None else "unknown"
            ),
            "assertion_source_id": self.assertion_source_id,
            "confirming_authority_id": self.confirming_authority_id,
            "confirmation_method": self.confirmation_method,
            "confirmation_reason_code": self.reason_code,
            "authority_policy_id": policy.policy_id,
            "authority_policy_version": policy.policy_version,
            "authority_rule_id": self.authority_rule_id,
            "source_rights_register_id": policy.source_rights_register_id,
            "attribution_policy_version": policy.attribution_policy_version,
            "upstream_ids": list(self.upstream_ids),
            "source_references": list(self.source_references),
            "public_status": self.public_status,
            "exception_reason_code": self.exception_reason_code,
        }


@dataclass(frozen=True, slots=True)
class OpenSSFReference:
    advisory_id: str
    ecosystem: str
    package_name: str
    source_tree: str


def _timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise AuthorityPolicyError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AuthorityPolicyError(f"{field} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorityPolicyError(f"{field} is invalid")
    return parsed.astimezone(UTC)


def load_authority_policy(path: Path = DEFAULT_POLICY_PATH) -> AuthorityPolicy:
    """Load one closed policy whose rule identifiers have executable code."""
    try:
        document = strict_json_loads(
            path.read_text(encoding="utf-8"),
            max_nodes=REGISTER_JSON_MAX_NODES,
            max_depth=REGISTER_JSON_MAX_DEPTH,
        )
    except ValueError as error:
        raise AuthorityPolicyError("authority policy is not strict JSON") from error
    if not isinstance(document, Mapping) or set(document) != POLICY_KEYS:
        raise AuthorityPolicyError("authority policy shape is invalid")
    if document["schema_version"] != "1.0.0":
        raise AuthorityPolicyError("authority policy schema is unsupported")
    if document["policy_id"] != "gbsec:authority-policy:malware-v1":
        raise AuthorityPolicyError("authority policy identity is unsupported")
    if not isinstance(document["policy_version"], str) or not SAFE_POLICY_VERSION.fullmatch(
        document["policy_version"]
    ):
        raise AuthorityPolicyError("authority policy version is invalid")
    if document["source_rights_register_id"] != "gbsec:rights-register:phase-0a-v1":
        raise AuthorityPolicyError("authority policy rights register is unsupported")
    if document["attribution_policy_version"] != document["policy_version"]:
        raise AuthorityPolicyError("authority attribution policy is inconsistent")
    ecosystems = document["supported_ecosystems"]
    if (
        not isinstance(ecosystems, list)
        or len(ecosystems) != len(set(ecosystems))
        or set(ecosystems) != SUPPORTED_ECOSYSTEMS
    ):
        raise AuthorityPolicyError("authority policy ecosystem scope is invalid")
    rules = document["rules"]
    if not isinstance(rules, list) or not rules:
        raise AuthorityPolicyError("authority policy rules are absent")
    by_id: dict[str, Mapping[str, str]] = {}
    for value in rules:
        if (
            not isinstance(value, Mapping)
            or set(value) != RULE_KEYS
            or not all(isinstance(item, str) and item for item in value.values())
            or not SAFE_REASON.fullmatch(value["reason_code"])
            or value["active_status"] != "confirmed"
            or value["confirmation_method"] != "automated_source_policy"
            or value["scope_requirement"] != "exact_artifact_version"
        ):
            raise AuthorityPolicyError("authority policy rule is invalid")
        if dict(value) != EXPECTED_RULE_VALUES.get(value["rule_id"]):
            raise AuthorityPolicyError("authority policy rule content is unsupported")
        by_id[value["rule_id"]] = dict(value)
    if set(by_id) != EXPECTED_RULES or len(by_id) != len(rules):
        raise AuthorityPolicyError("authority policy rule set is unsupported")
    exceptions = document["exception_reason_codes"]
    if (
        not isinstance(exceptions, list)
        or len(exceptions) != len(set(exceptions))
        or not all(isinstance(value, str) and SAFE_REASON.fullmatch(value) for value in exceptions)
        or set(exceptions) != EXPECTED_EXCEPTIONS
    ):
        raise AuthorityPolicyError("authority exception reasons are invalid")
    legacy_cutoff = _timestamp(
        document["legacy_github_npm_published_before"],
        field="legacy cutoff",
    )
    if legacy_cutoff != datetime(2026, 7, 28, tzinfo=UTC):
        raise AuthorityPolicyError("authority legacy cutoff is unsupported")
    return AuthorityPolicy(
        policy_id=document["policy_id"],
        policy_version=document["policy_version"],
        source_rights_register_id=document["source_rights_register_id"],
        attribution_policy_version=document["attribution_policy_version"],
        legacy_github_npm_published_before=legacy_cutoff,
        supported_ecosystems=frozenset(ecosystems),
        rules=by_id,
        exception_reason_codes=frozenset(exceptions),
    )


def _references(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if (
        not isinstance(value, list)
        or len(value) > 101
        or not all(isinstance(item, str) and 1 <= len(item) <= 2048 for item in value)
    ):
        raise AuthorityPolicyError("source references are invalid")
    output: list[str] = []
    for item in value:
        try:
            parsed = urlsplit(item)
            port = parsed.port
        except ValueError as error:
            raise AuthorityPolicyError("source reference is invalid") from error
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
            or parsed.fragment
        ):
            raise AuthorityPolicyError("source reference is invalid")
        if item not in output:
            output.append(item)
    return tuple(output)


def _canonical_package_name(ecosystem: str, package_name: str) -> str:
    if ecosystem == "pypi":
        return PYPI_NORMALIZE.sub("-", package_name).lower()
    if ecosystem in {"github-actions", "oci", "docker"}:
        return package_name.lower()
    return package_name


def _openssf_references(references: tuple[str, ...]) -> tuple[OpenSSFReference, ...]:
    found: list[OpenSSFReference] = []
    for reference in references:
        parsed = urlsplit(reference)
        if parsed.hostname != "github.com" or parsed.query:
            continue
        matched = OPENSSF_REFERENCE.fullmatch(parsed.path)
        if matched is None:
            continue
        ecosystem = OPENSSF_ECOSYSTEMS.get(matched.group("ecosystem").lower())
        package_name = unquote(matched.group("package")).strip("/")
        if ecosystem is None or not package_name or not package_name.isascii():
            continue
        origin = OpenSSFReference(
            advisory_id=matched.group("advisory"),
            ecosystem=ecosystem,
            package_name=_canonical_package_name(ecosystem, package_name),
            source_tree=matched.group("source_tree"),
        )
        if origin not in found:
            found.append(origin)
    return tuple(found)


def _decision_references(references: tuple[str, ...]) -> tuple[str, ...]:
    openssf = [
        value
        for value in references
        if OPENSSF_REFERENCE.fullmatch(urlsplit(value).path) is not None
    ]
    ordered = [references[0], *openssf, *references[1:]]
    return tuple(dict.fromkeys(ordered))[:20]


def _reported(
    *,
    advisory_id: str,
    references: tuple[str, ...],
    exception_reason_code: str | None = None,
) -> AuthorityEvaluation:
    return AuthorityEvaluation(
        public_status="reported",
        confirmation_method="reported_source",
        transport_source_id=GITHUB_ADVISORY,
        assertion_source_id=None,
        confirming_authority_id=None,
        authority_rule_id="gbsec:authority-rule:reported-unproven-origin-v1",
        reason_code="source_assertion_not_authoritative",
        upstream_ids=(advisory_id,),
        source_references=references,
        exception_reason_code=exception_reason_code,
    )


def _reported_nonexact(
    *,
    advisory_id: str,
    references: tuple[str, ...],
) -> AuthorityEvaluation:
    return AuthorityEvaluation(
        public_status="reported",
        confirmation_method="reported_source",
        transport_source_id=GITHUB_ADVISORY,
        assertion_source_id=GITHUB_ADVISORY,
        confirming_authority_id=None,
        authority_rule_id="gbsec:authority-rule:reported-nonexact-scope-v1",
        reason_code="source_scope_not_exact",
        upstream_ids=(advisory_id,),
        source_references=references,
    )


def evaluate_github_malware(
    advisory: Mapping[str, Any],
    *,
    ecosystem: str,
    package_name: str,
    version: str | None,
    policy: AuthorityPolicy,
) -> AuthorityEvaluation:
    """Classify one GitHub malware artifact or range without trusting source prose."""
    advisory_id = advisory.get("ghsa_id")
    if (
        not isinstance(advisory_id, str)
        or not re.fullmatch(r"GHSA-[A-Za-z0-9-]{8,75}", advisory_id)
        or ecosystem not in policy.supported_ecosystems
        or not isinstance(package_name, str)
        or not package_name
        or len(package_name) > 300
        or not package_name.isascii()
        or (version is not None and (not isinstance(version, str) or not version))
    ):
        raise AuthorityPolicyError("GitHub malware identity is invalid")
    canonical_url = advisory.get("html_url")
    if not isinstance(canonical_url, str):
        raise AuthorityPolicyError("GitHub malware canonical URL is invalid")
    supplied_references = advisory.get("references")
    if supplied_references is None:
        supplied_references = []
    if not isinstance(supplied_references, list):
        raise AuthorityPolicyError("source references are invalid")
    references = _references([canonical_url, *supplied_references])
    openssf_references = _openssf_references(references)
    canonical_name = _canonical_package_name(ecosystem, package_name)
    matched_openssf = tuple(
        value
        for value in openssf_references
        if value.ecosystem == ecosystem and value.package_name == canonical_name
    )
    openssf_ids = tuple(dict.fromkeys(value.advisory_id for value in matched_openssf))
    active_openssf_ids = tuple(
        dict.fromkeys(
            value.advisory_id for value in matched_openssf if value.source_tree == "malicious"
        )
    )
    decision_references = _decision_references(references)
    if advisory.get("withdrawn_at") is not None:
        assertion = OPENSSF_MALICIOUS if len(openssf_ids) == 1 else GITHUB_ADVISORY
        return AuthorityEvaluation(
            public_status="withdrawn",
            confirmation_method="withdrawal",
            transport_source_id=GITHUB_ADVISORY,
            assertion_source_id=assertion,
            confirming_authority_id=assertion,
            authority_rule_id="gbsec:authority-rule:upstream-withdrawal-v1",
            reason_code="upstream_malware_claim_withdrawn",
            upstream_ids=(advisory_id, *openssf_ids),
            source_references=decision_references,
        )
    if openssf_references and len(matched_openssf) != len(openssf_references):
        return _reported(
            advisory_id=advisory_id,
            references=decision_references,
            exception_reason_code="mixed_upstream_identity",
        )
    if len(openssf_ids) > 1:
        return _reported(
            advisory_id=advisory_id,
            references=decision_references,
            exception_reason_code="ambiguous_openssf_origin",
        )
    if version is None:
        return _reported_nonexact(
            advisory_id=advisory_id,
            references=decision_references,
        )
    if len(active_openssf_ids) == 1:
        rule = policy.rules["gbsec:authority-rule:github-openssf-exact-malware-v1"]
        return AuthorityEvaluation(
            public_status=rule["active_status"],
            confirmation_method=rule["confirmation_method"],
            transport_source_id=rule["transport_source_id"],
            assertion_source_id=rule["assertion_source_id"],
            confirming_authority_id=rule["confirming_authority_id"],
            authority_rule_id=rule["rule_id"],
            reason_code=rule["reason_code"],
            upstream_ids=(advisory_id, active_openssf_ids[0]),
            source_references=decision_references,
        )
    published_at = _timestamp(advisory.get("published_at"), field="GitHub published_at")
    if ecosystem == "npm" and published_at < policy.legacy_github_npm_published_before:
        rule = policy.rules["gbsec:authority-rule:github-legacy-npm-exact-malware-v1"]
        return AuthorityEvaluation(
            public_status=rule["active_status"],
            confirmation_method=rule["confirmation_method"],
            transport_source_id=rule["transport_source_id"],
            assertion_source_id=rule["assertion_source_id"],
            confirming_authority_id=rule["confirming_authority_id"],
            authority_rule_id=rule["rule_id"],
            reason_code=rule["reason_code"],
            upstream_ids=(advisory_id,),
            source_references=decision_references,
        )
    return _reported(advisory_id=advisory_id, references=decision_references)


def evaluation_from_lineage(
    lineage: Mapping[str, Any],
    *,
    policy: AuthorityPolicy,
) -> AuthorityEvaluation:
    """Recover a collector decision only when it matches the active closed policy."""
    if (
        lineage.get("authority_policy_id") != policy.policy_id
        or lineage.get("authority_policy_version") != policy.policy_version
        or lineage.get("source_rights_register_id") != policy.source_rights_register_id
        or lineage.get("attribution_policy_version") != policy.attribution_policy_version
    ):
        raise AuthorityPolicyError("claim lineage does not match the active authority policy")
    assertion_source = lineage.get("assertion_source_id")
    confirming_authority = lineage.get("confirming_authority_id")
    if lineage.get("assertion_source_state") == "unknown":
        assertion_source = None
        confirming_authority = None
    if assertion_source is not None and not isinstance(assertion_source, str):
        raise AuthorityPolicyError("claim assertion source is invalid")
    if confirming_authority is not None and not isinstance(confirming_authority, str):
        raise AuthorityPolicyError("claim confirming authority is invalid")
    upstream_ids = lineage.get("upstream_ids")
    if (
        not isinstance(upstream_ids, list)
        or not upstream_ids
        or not all(isinstance(value, str) and value for value in upstream_ids)
    ):
        raise AuthorityPolicyError("claim upstream identities are invalid")
    exception_reason = lineage.get("exception_reason_code")
    if exception_reason is not None and exception_reason not in policy.exception_reason_codes:
        raise AuthorityPolicyError("claim exception reason is not authorized")
    evaluation = AuthorityEvaluation(
        public_status=str(lineage.get("public_status")),
        confirmation_method=str(lineage.get("confirmation_method")),
        transport_source_id=str(lineage.get("transport_source_id")),
        assertion_source_id=assertion_source,
        confirming_authority_id=confirming_authority,
        authority_rule_id=str(lineage.get("authority_rule_id")),
        reason_code=str(lineage.get("confirmation_reason_code")),
        upstream_ids=tuple(upstream_ids),
        source_references=_references(lineage.get("source_references")),
        exception_reason_code=exception_reason,
    )
    if (
        evaluation.public_status
        not in {"reported", "corroborated", "confirmed", "disputed", "withdrawn"}
        or evaluation.confirmation_method
        not in {
            "reported_source",
            "automated_source_policy",
            "automated_corroboration",
            "human_review",
            "withdrawal",
            "dispute",
        }
        or not SAFE_REASON.fullmatch(evaluation.reason_code)
    ):
        raise AuthorityPolicyError("claim lineage decision is unsupported")
    if evaluation.confirmation_method == "automated_source_policy":
        expected = policy.rules.get(evaluation.authority_rule_id)
        if (
            expected is None
            or evaluation.public_status != "confirmed"
            or evaluation.transport_source_id != expected["transport_source_id"]
            or evaluation.assertion_source_id != expected["assertion_source_id"]
            or evaluation.confirming_authority_id != expected["confirming_authority_id"]
            or evaluation.reason_code != expected["reason_code"]
        ):
            raise AuthorityPolicyError("claim lineage authority rule is inconsistent")
    elif evaluation.confirmation_method == "reported_source":
        if (
            evaluation.public_status != "reported"
            or evaluation.confirming_authority_id is not None
            or evaluation.authority_rule_id
            not in {
                "gbsec:authority-rule:reported-unproven-origin-v1",
                "gbsec:authority-rule:reported-nonexact-scope-v1",
            }
        ):
            raise AuthorityPolicyError("reported claim lineage is inconsistent")
    elif evaluation.confirmation_method == "withdrawal":
        if (
            evaluation.public_status != "withdrawn"
            or evaluation.authority_rule_id != "gbsec:authority-rule:upstream-withdrawal-v1"
        ):
            raise AuthorityPolicyError("withdrawn claim lineage is inconsistent")
    else:
        raise AuthorityPolicyError("collector claim lineage method is unsupported")
    return evaluation


def evaluate_direct_openssf(
    *,
    advisory_id: str,
    source_url: str,
    ecosystem: str,
    exact: bool,
    withdrawn: bool,
    policy: AuthorityPolicy,
) -> AuthorityEvaluation:
    """Classify one direct OpenSSF malware record under the same policy."""
    if (
        not re.fullmatch(r"MAL-[0-9]{4}-[0-9]+", advisory_id)
        or ecosystem not in policy.supported_ecosystems
    ):
        raise AuthorityPolicyError("OpenSSF malware identity is invalid")
    references = _references([source_url])
    if withdrawn:
        status = "withdrawn"
        method = "withdrawal"
        rule_id = "gbsec:authority-rule:upstream-withdrawal-v1"
        reason = "upstream_malware_claim_withdrawn"
        authority = OPENSSF_MALICIOUS
    elif exact:
        rule = policy.rules["gbsec:authority-rule:openssf-direct-exact-malware-v1"]
        status = rule["active_status"]
        method = rule["confirmation_method"]
        rule_id = rule["rule_id"]
        reason = rule["reason_code"]
        authority = rule["confirming_authority_id"]
    else:
        status = "reported"
        method = "reported_source"
        rule_id = "gbsec:authority-rule:reported-nonexact-scope-v1"
        reason = "source_scope_not_exact"
        authority = None
    return AuthorityEvaluation(
        public_status=status,
        confirmation_method=method,
        transport_source_id=OPENSSF_MALICIOUS,
        assertion_source_id=OPENSSF_MALICIOUS,
        confirming_authority_id=authority,
        authority_rule_id=rule_id,
        reason_code=reason,
        upstream_ids=(advisory_id,),
        source_references=references,
    )


def authority_decision_document(
    *,
    evaluation: AuthorityEvaluation,
    policy: AuthorityPolicy,
    incident_id: str,
    claim_id: str,
    artifact_id: str,
    evidence_id: str,
    decided_at: datetime,
) -> dict[str, Any]:
    """Build the public, append-only explanation for one status decision."""
    rendered_at = timestamp(decided_at)
    body = {
        "kind": "authority_decision",
        "schema_version": "1.0.0",
        "revision": 1,
        "created_at": rendered_at,
        "updated_at": rendered_at,
        "data_classification": "public",
        "incident_id": incident_id,
        "claim_id": claim_id,
        "artifact_id": artifact_id,
        "evidence_ids": [evidence_id],
        "public_status": evaluation.public_status,
        "confirmation_method": evaluation.confirmation_method,
        "transport_source_id": evaluation.transport_source_id,
        "assertion_source_id": evaluation.assertion_source_id,
        "confirming_authority_id": evaluation.confirming_authority_id,
        "authority_policy_id": policy.policy_id,
        "authority_policy_version": policy.policy_version,
        "authority_rule_id": evaluation.authority_rule_id,
        "source_rights_register_id": policy.source_rights_register_id,
        "attribution_policy_version": policy.attribution_policy_version,
        "reason_code": evaluation.reason_code,
        "automated": evaluation.confirmation_method != "human_review",
        "independent_goodboy_analysis": False,
        "upstream_ids": list(evaluation.upstream_ids),
        "source_references": list(evaluation.source_references),
        "exception_required": evaluation.exception_required,
        "exception_reason_code": evaluation.exception_reason_code,
        "decided_at": rendered_at,
    }
    body["id"] = stable_id(
        "authority-decision",
        incident_id,
        claim_id,
        artifact_id,
        evidence_id,
        evaluation.public_status,
        policy.policy_version,
        evaluation.authority_rule_id,
    )
    return body
