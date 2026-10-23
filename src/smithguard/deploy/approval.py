"""Strict, short-lived deployment approval validation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from smithguard.identifiers import parse_timestamp

TIER_ACTIONS = {
    "runtime-only": frozenset({"activate", "rollback"}),
    "migration": frozenset({"activate", "migrate", "unit_change", "policy_change", "rollback"}),
    "infra": frozenset(
        {"timer_change", "unit_change", "policy_change", "credential_change", "rollback"}
    ),
    "timer-change": frozenset({"timer_change", "rollback"}),
    "unit-change": frozenset({"unit_change", "rollback"}),
    "policy-change": frozenset({"policy_change", "rollback"}),
    "credential-change": frozenset({"credential_change", "rollback"}),
}


class ApprovalError(RuntimeError):
    """An approval is malformed, expired, or does not authorize an action."""


def _parse_time(value: str) -> datetime:
    # The shared parser bounds the string at 64 characters; approval timestamps are
    # schema-validated ISO 8601 values well inside that bound.
    try:
        return parse_timestamp(value)
    except ValueError as error:
        if getattr(error, "reason", None) == "naive":
            raise ApprovalError("approval timestamp must include an offset") from error
        raise ApprovalError("approval timestamp is invalid") from error


def _schema() -> Mapping[str, Any]:
    resource = files("smithguard.generated_artifacts").joinpath("deploy-approval.schema.json")
    try:
        value = json.loads(resource.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApprovalError("deploy approval schema is unavailable") from error
    if not isinstance(value, Mapping):
        raise ApprovalError("deploy approval schema is invalid")
    Draft202012Validator.check_schema(value)
    return value


@dataclass(frozen=True, slots=True)
class DeployApproval:
    schema_version: str
    operation_id: str
    tier: str
    artifact_sha256: str
    artifact_commit: str
    allowed_actions: tuple[str, ...]
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    note: str
    timer_name: str | None = None
    timer_stamp_epoch: int | None = None

    def authorize(
        self,
        action: str,
        *,
        artifact_sha256: str,
        artifact_commit: str,
        now: datetime | None = None,
    ) -> None:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if current < self.approved_at or current >= self.expires_at:
            raise ApprovalError("deploy approval is not currently valid")
        if action not in self.allowed_actions:
            raise ApprovalError(f"deploy approval does not allow action: {action}")
        if action not in TIER_ACTIONS.get(self.tier, frozenset()):
            raise ApprovalError("deploy approval tier does not allow this action")
        if artifact_sha256 != self.artifact_sha256:
            raise ApprovalError("deploy approval artifact digest differs")
        if artifact_commit != self.artifact_commit:
            raise ApprovalError("deploy approval artifact commit differs")


def load_approval(
    source: str | Path | bytes | Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> DeployApproval:
    try:
        if isinstance(source, Mapping):
            document = dict(source)
        elif isinstance(source, bytes):
            document = json.loads(source.decode("ascii"))
        else:
            document = json.loads(Path(source).read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApprovalError("deploy approval file is invalid") from error
    if not isinstance(document, Mapping):
        raise ApprovalError("deploy approval must be one JSON object")
    try:
        Draft202012Validator(_schema(), format_checker=FormatChecker()).validate(document)
    except ValidationError as error:
        raise ApprovalError("deploy approval does not match its schema") from error
    approved_at = _parse_time(document["approved_at"])
    expires_at = _parse_time(document["expires_at"])
    if expires_at <= approved_at or expires_at - approved_at > timedelta(hours=4):
        raise ApprovalError(
            "deploy approval lifetime must be greater than zero and at most 4 hours"
        )
    approval = DeployApproval(
        schema_version=document["schema_version"],
        operation_id=document["operation_id"],
        tier=document["tier"],
        artifact_sha256=document["artifact_sha256"],
        artifact_commit=document["artifact_commit"],
        allowed_actions=tuple(document["allowed_actions"]),
        approved_by=document["approved_by"],
        approved_at=approved_at,
        expires_at=expires_at,
        note=document["note"],
        timer_name=document.get("timer_name"),
        timer_stamp_epoch=document.get("timer_stamp_epoch"),
    )
    if not set(approval.allowed_actions) <= TIER_ACTIONS.get(approval.tier, frozenset()):
        raise ApprovalError("deploy approval actions differ from its tier")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if current < approval.approved_at or current >= approval.expires_at:
        raise ApprovalError("deploy approval is not currently valid")
    return approval
