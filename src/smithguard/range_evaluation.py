"""Shared deterministic ranges; comparator ranges deliberately include prereleases."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import total_ordering
from typing import Any

from packaging.version import InvalidVersion, Version

SEMVER = re.compile(
    r"^[v=]?(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
COMPARATOR = re.compile(r"^(<=|>=|<|>|==|=)?(.+)$")
COMPARATOR_WITH_SPACE = re.compile(r"(<=|>=|==|=|<|>)\s+(?=[v=]?[0-9])")
GITHUB_NPM_ALL_VERSION_RANGES = frozenset({">0", ">=0", ">=0.0", ">=0.0.0"})


class RangeEvaluationError(ValueError):
    """A version cannot be interpreted by the supported deterministic subset."""


@total_ordering
@dataclass(frozen=True, slots=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[int | str, ...]

    @classmethod
    def parse(cls, value: str) -> SemVer:
        match = SEMVER.fullmatch(value)
        if match is None:
            raise RangeEvaluationError("unsupported_semver")
        prerelease: tuple[int | str, ...] = ()
        if match.group(4):
            parts: list[int | str] = []
            for part in match.group(4).split("."):
                if not part or (part.isdigit() and len(part) > 1 and part.startswith("0")):
                    raise RangeEvaluationError("unsupported_semver")
                parts.append(int(part) if part.isdigit() else part)
            prerelease = tuple(parts)
        return cls(
            major=int(match.group(1)),
            minor=int(match.group(2) or 0),
            patch=int(match.group(3) or 0),
            prerelease=prerelease,
        )

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        core = (self.major, self.minor, self.patch)
        other_core = (other.major, other.minor, other.patch)
        if core != other_core:
            return core < other_core
        if not self.prerelease:
            return False
        if not other.prerelease:
            return True
        for left, right in zip(self.prerelease, other.prerelease, strict=False):
            if left == right:
                continue
            if isinstance(left, int) and isinstance(right, str):
                return True
            if isinstance(left, str) and isinstance(right, int):
                return False
            return left < right
        return len(self.prerelease) < len(other.prerelease)


def _compare(left: Any, operator: str, right: Any) -> bool:
    return {
        "=": left == right,
        "==": left == right,
        ">": left > right,
        ">=": left >= right,
        "<": left < right,
        "<=": left <= right,
    }[operator]


def _semver_operand(value: str) -> tuple[SemVer, int]:
    match = SEMVER.fullmatch(value)
    if match is None:
        raise RangeEvaluationError("unsupported_semver")
    precision = 1 + int(match.group(2) is not None) + int(match.group(3) is not None)
    if match.group(4) is not None and precision != 3:
        raise RangeEvaluationError("unsupported_semver")
    return SemVer.parse(value), precision


def semver_matches(version: str, expression: str) -> bool | None:
    try:
        candidate = SemVer.parse(version)
        normalized = normalize_semver_comparator_range(expression)
        if normalized is None:
            return None
        tokens = normalized.split()
        comparisons = []
        for token in tokens:
            match = COMPARATOR.fullmatch(token)
            if match is None:
                return None
            operator = match.group(1) or "="
            value, precision = _semver_operand(match.group(2))
            if operator in {"=", "==", "<="} and precision != 3:
                return None
            comparisons.append((operator, value))
        return all(_compare(candidate, operator, operand) for operator, operand in comparisons)
    except (KeyError, RangeEvaluationError):
        return None


def normalize_semver_comparator_range(expression: object) -> str | None:
    """Return SmithGuard's canonical comparator subset, or None when unsupported."""
    if (
        not isinstance(expression, str)
        or not expression
        or len(expression) > 1000
        or not expression.isascii()
        or any(character in expression for character in "\r\n\t")
    ):
        return None
    compact = COMPARATOR_WITH_SPACE.sub(r"\1", expression.strip())
    if any(not segment.strip() for segment in compact.split(",")):
        return None
    tokens = compact.replace(",", " ").split()
    if not tokens:
        return None
    normalized: list[str] = []
    for token in tokens:
        match = COMPARATOR.fullmatch(token)
        if match is None:
            return None
        operator = match.group(1) or "="
        try:
            _semver_operand(match.group(2))
        except RangeEvaluationError:
            return None
        normalized.append(operator + match.group(2))
    return " ".join(normalized)


def normalize_github_npm_advisory_range(expression: object) -> str | None:
    """Canonicalize the reviewed GitHub npm range subset for exposure checks."""
    if isinstance(expression, str) and expression.strip() == "*":
        return "*"
    normalized = normalize_semver_comparator_range(expression)
    if normalized in GITHUB_NPM_ALL_VERSION_RANGES:
        return "*"
    return normalized


def pep440_matches(version: str, expression: str) -> bool | None:
    """PEP 440 ordering against advisory comparators. A local build compares as its
    public version unless the comparator names a local label; prereleases order below
    their release (an advisory "< 2.0" includes 2.0rc1), as GitHub and OSV intend."""
    try:
        candidate = Version(version)
        public = Version(candidate.public)
        tokens = expression.replace(",", " ").split()
        if not tokens:
            return None
        comparisons = []
        for token in tokens:
            match = COMPARATOR.fullmatch(token)
            if match is None:
                return None
            operator = match.group(1) or "=="
            if operator == "=":
                operator = "=="
            comparisons.append((operator, Version(match.group(2))))
        return all(
            _compare(candidate if operand.local is not None else public, operator, operand)
            for operator, operand in comparisons
        )
    except (KeyError, InvalidVersion):
        return None


@dataclass(frozen=True, slots=True)
class OSVInterval:
    """A sorted linear interval; a limit is never described as an upstream fix."""

    introduced: str | None
    upper: str | None
    upper_kind: str | None


def _osv_version(value: str, ecosystem: str) -> Any:
    if ecosystem == "pypi":
        return Version(value)
    if ecosystem in {"semver", "npm"}:
        parsed, precision = _semver_operand(value)
        if precision != 3 or value.startswith(("v", "=")):
            raise RangeEvaluationError("unsupported_osv_semver")
        return parsed
    # Other ecosystems order with their registry's own rules (imported lazily because
    # version_order builds on this module's SemVer).
    from smithguard.version_order import VersionOrderError, version_key

    try:
        return version_key(ecosystem, value)
    except VersionOrderError as error:
        raise RangeEvaluationError("unsupported_osv_version") from error


def _osv_ordering(ecosystem: str, range_type: object) -> str | None:
    from smithguard.version_order import ORDERED_ECOSYSTEMS

    # Preserve the deployed PyPI comparison policy for SEMVER-labelled records.
    if ecosystem == "pypi" and range_type in ("SEMVER", "ECOSYSTEM"):
        return "pypi"
    if range_type == "SEMVER":
        return "semver"
    if range_type == "ECOSYSTEM" and ecosystem in ORDERED_ECOSYSTEMS:
        return ecosystem
    return None


def osv_intervals(
    ecosystem: str, affected_range: Mapping[str, Any]
) -> tuple[OSVInterval, ...] | None:
    """Validate and normalize bounded OSV events before making any verdict.

    OSV events may be unordered. Limits filter the union of intervals separately;
    multiple limits form a union, so the largest limit wins for linear versions.
    Unsupported or ambiguous ranges remain unknown, including GIT ancestry.
    """
    ordering = _osv_ordering(ecosystem, affected_range.get("type"))
    if ordering is None:
        return None
    events = affected_range.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= 1000:
        return None
    boundaries: dict[Any, dict[str, str]] = {}
    limits: list[tuple[Any, str]] = []
    kinds: set[str] = set()
    unlimited = False
    try:
        for event in events:
            if not isinstance(event, Mapping) or len(event) != 1:
                return None
            kind, raw = next(iter(event.items()))
            if kind not in ("introduced", "fixed", "last_affected", "limit"):
                return None
            if not isinstance(raw, str) or not raw or len(raw) > 200:
                return None
            kinds.add(kind)
            if kind == "limit" and raw == "*":
                unlimited = True
                continue
            boundary = None if kind == "introduced" and raw == "0" else _osv_version(raw, ordering)
            if kind == "limit":
                limits.append((boundary, raw))
                continue
            at_boundary = boundaries.setdefault(boundary, {})
            at_boundary[kind] = raw
            if len(at_boundary) > 1 and set(at_boundary) != {"introduced", "last_affected"}:
                return None
        if "introduced" not in kinds or {"fixed", "last_affected"} <= kinds:
            return None
        ceiling = max(limits) if limits and not unlimited else None
        result: list[OSVInterval] = []
        inside = False
        lower: str | None = None
        for _, at_boundary in sorted(
            boundaries.items(), key=lambda pair: (pair[0] is not None, pair[0])
        ):
            if "introduced" in at_boundary:
                raw = at_boundary["introduced"]
                if not inside:
                    lower = None if raw == "0" else raw
                inside = True
            for kind in ("fixed", "last_affected"):
                if kind in at_boundary and inside:
                    result.append(OSVInterval(lower, at_boundary[kind], kind))
                    inside = False
        if inside:
            result.append(OSVInterval(lower, None, None))
        if ceiling is None:
            return tuple(result)
        limited: list[OSVInterval] = []
        for interval in result:
            if (
                interval.introduced is not None
                and _osv_version(interval.introduced, ordering) >= ceiling[0]
            ):
                continue
            if interval.upper is None or _osv_version(interval.upper, ordering) >= ceiling[0]:
                interval = OSVInterval(interval.introduced, ceiling[1], "limit")
            limited.append(interval)
        return tuple(limited)
    except (InvalidVersion, RangeEvaluationError):
        return None


def _covers_every_version(ecosystem: str, affected_range: Mapping[str, Any]) -> bool:
    """Only ``introduced: 0`` events: every version is affected, whatever the ordering.

    GIT ranges describe source commits, not package versions, so they say this only
    for the ``git`` ecosystem itself.
    """
    range_type = affected_range.get("type")
    if range_type not in ("ECOSYSTEM", "SEMVER") and not (
        range_type == "GIT" and ecosystem == "git"
    ):
        return False
    events = affected_range.get("events")
    return (
        isinstance(events, list)
        and bool(events)
        and all(
            isinstance(event, Mapping) and dict(event) == {"introduced": "0"} for event in events
        )
    )


def osv_range_matches(
    ecosystem: str, version: str, affected_range: Mapping[str, Any]
) -> bool | None:
    if _covers_every_version(ecosystem, affected_range):
        return True
    intervals = osv_intervals(ecosystem, affected_range)
    if intervals is None:
        return None
    try:
        ordering = _osv_ordering(ecosystem, affected_range.get("type"))
        candidate = (
            # PEP 440: a local build is its public version for range checks.
            Version(Version(version).public)
            if ordering == "pypi"
            else SemVer.parse(version)
            if ordering in {"semver", "npm"}
            else _osv_version(version, ordering)
        )
        return any(
            (
                interval.introduced is None
                or candidate >= _osv_version(interval.introduced, ordering)
            )
            and (
                interval.upper is None
                or _compare(
                    candidate,
                    "<=" if interval.upper_kind == "last_affected" else "<",
                    _osv_version(interval.upper, ordering),
                )
            )
            for interval in intervals
        )
    except (InvalidVersion, RangeEvaluationError):
        return None


def range_result(
    *,
    artifact: Mapping[str, Any],
    affected_range: Mapping[str, Any],
) -> bool | None:
    """Return True, False, or None when the supported subset cannot decide."""
    if affected_range["evaluation_state"] != "supported":
        return None
    range_type = affected_range["range_type"]
    expression = affected_range["expression"].strip()
    if range_type == "DIGEST":
        if artifact["digest"] is None:
            return None
        return artifact["digest"] == expression.removeprefix("=").strip()
    if range_type == "EXACT":
        values = tuple(
            value for value in (artifact["version"], artifact["digest"]) if value is not None
        )
        if not values:
            return None
        expected = expression.removeprefix("=").strip()
        if artifact["digest"] is not None and artifact["digest"] == expected:
            return True
        if artifact["version"] is None:
            return False
        from smithguard.version_order import exact_version_matches

        return exact_version_matches(artifact["ecosystem"], artifact["version"], expected)
    value = artifact["version"]
    if value is None:
        return None
    if expression == "*" and range_type in {"SEMVER", "ECOSYSTEM"}:
        return True
    if range_type == "SEMVER" and artifact["ecosystem"] == "npm":
        return semver_matches(value, expression)
    if range_type == "ECOSYSTEM":
        if artifact["ecosystem"] == "npm":
            return semver_matches(value, expression)
        if artifact["ecosystem"] == "pypi":
            return pep440_matches(value, expression)
    if range_type in {"SEMVER", "ECOSYSTEM"}:
        from smithguard.version_order import comparator_list_matches

        return comparator_list_matches(artifact["ecosystem"], value, expression)
    return None
