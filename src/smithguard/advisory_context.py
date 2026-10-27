"""Literal source context and narrowly reviewed, revision-bound conditions."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from smithguard.identifiers import sha256_id

MAX_SOURCE_TEXT_BYTES = 1_048_576


def permitted_github_context(document: Mapping[str, Any]) -> dict[str, Any]:
    """Preserve permitted source fields; never interpret source prose as commands."""
    result = {}
    for key in ("summary", "description", "severity"):
        if key not in document:
            continue
        value = document[key]
        if value is not None:
            try:
                valid = (
                    isinstance(value, str)
                    and not any(
                        (ord(char) < 32 and char not in "\n\t\r")
                        or 127 <= ord(char) <= 159
                        or ord(char) in {0x061C, 0x200E, 0x200F}
                        or 0x202A <= ord(char) <= 0x202E
                        or 0x2066 <= ord(char) <= 0x2069
                        for char in value
                    )
                    and len(value.encode("utf-8")) <= MAX_SOURCE_TEXT_BYTES
                )
            except UnicodeEncodeError:
                valid = False
            if not valid:
                # Optional prose must not quarantine valid package/range evidence.
                # Drop the context as a unit; SQL JSONB cannot retain NUL/surrogates.
                return {}
        result[key] = value
    return result


def unknown_conditions() -> dict[str, Any]:
    return {
        "state": "unknown",
        "coverage": "unknown",
        "extraction_method": None,
        "source_field": None,
        "source_text_sha256": None,
        "reviewed_on": None,
        "any_of": [],
        "local_applicability": "not_evaluated",
    }


def github_public_context(document: Mapping[str, Any]) -> dict[str, Any] | None:
    fields = permitted_github_context(document)
    if not fields:
        return None
    title = fields.get("summary")
    description = fields.get("description")
    severity = fields.get("severity")
    # Bounds are Unicode characters, with at most four UTF-8 bytes per character.
    # Full source text stays in governed evidence, not in the public excerpt.
    context = {
        "title": title[:300] if title else None,
        "description": description[:2000] if description else None,
        "severity": severity
        if severity in {"low", "medium", "high", "critical", "unknown"}
        else None,
        "attribution": "GitHub Advisory Database",
        "license_expression": "CC-BY-4.0",
        "source_url": document["html_url"],
        "title_sha256": sha256_id(title.encode()) if title is not None else None,
        "description_sha256": (
            sha256_id(description.encode()) if description is not None else None
        ),
        "title_truncated": bool(title and len(title) > 300),
        "description_truncated": bool(description and len(description) > 2000),
        "conditions": unknown_conditions(),
    }
    # This reviewed extraction is pinned to the complete source text and timestamp.
    # Any upstream change returns unknown until separately reviewed. We do not infer
    # PEP 706 capability from the scanner's Python version or the user's OS.
    if (
        document.get("ghsa_id") == "GHSA-4xh5-x5gv-qwph"
        and document.get("updated_at") == "2025-12-19T16:46:02Z"
        and context["description_sha256"]
        == "sha256:2988af235d7805e287e740209ff042d037681c90a1067a160465eb2d8f580e0b"
    ):
        context["conditions"] = {
            "state": "recorded",
            "coverage": "partial",
            "extraction_method": "reviewed_source_text",
            "source_field": "description",
            "source_text_sha256": context["description_sha256"],
            "reviewed_on": "2026-10-26",
            "any_of": [
                {
                    "all_of": [
                        {"fact": "pip_tar_extraction", "values": ["enabled"]},
                        {"fact": "python_tarfile_pep706", "values": ["false"]},
                    ]
                }
            ],
            "local_applicability": "not_evaluated",
        }
    return context


def evaluate_conditions(conditions: Mapping[str, Any], facts: Mapping[str, str]) -> str:
    """Evaluate explicit facts about the target, never facts inferred from this host.

    Disjunctive normal form represents OR alternatives, each containing AND facts.
    False requires every alternative to have a proven unmet necessary condition.
    Unknown facts cannot become exclusions. Even true means only listed conditions.
    """
    if conditions.get("state") != "recorded":
        return "uncertain"
    alternatives = conditions.get("any_of")
    if not isinstance(alternatives, list) or not 1 <= len(alternatives) <= 16:
        return "uncertain"
    outcomes = []
    for alternative in alternatives:
        atoms = alternative.get("all_of") if isinstance(alternative, Mapping) else None
        if not isinstance(atoms, list) or not 1 <= len(atoms) <= 16:
            return "uncertain"
        values = []
        for atom in atoms:
            if not isinstance(atom, Mapping):
                return "uncertain"
            key, allowed = atom.get("fact"), atom.get("values")
            if (
                not isinstance(key, str)
                or not isinstance(allowed, list)
                or not 1 <= len(allowed) <= 32
                or any(not isinstance(value, str) for value in allowed)
            ):
                return "uncertain"
            values.append(None if key not in facts else facts[key] in allowed)
        outcomes.append(False if False in values else None if None in values else True)
    if True in outcomes:
        return "conditions_met"
    return "uncertain" if None in outcomes else "conditions_not_met"
