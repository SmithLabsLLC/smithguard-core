"""Per-ecosystem version ordering for advisory range evaluation.

``version_key(ecosystem, value)`` returns an object that orders exactly like the
ecosystem's registry does, or raises ``VersionOrderError``. Each ecosystem accepts only
the version forms whose registry ordering is implemented here; anything else (branch
names, unusual qualifiers, build numbers where the registry compares them) raises, so
callers answer "unknown" instead of guessing. ``comparator_list_matches`` evaluates
GitHub-style comparator lists (``">= 2.0, < 2.15.0"``) and returns True, False or None.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import Any

from packaging.version import InvalidVersion, Version

from smithguard.range_evaluation import RangeEvaluationError, SemVer

MAX_VERSION_LENGTH = 200
COMPARATOR = re.compile(r"^\s*(<=|>=|==|!=|<|>|=)?\s*([^\s<>=!,]+)\s*$")
# Source spellings of "every version". A strict bound such as "> 0.0.0" is an ordinary
# comparison (it excludes 0.0.0 itself), never a sentinel.
ALL_VERSIONS = frozenset({"*", ">=0", ">=0.0", ">=0.0.0"})
SEMVER_ECOSYSTEMS = frozenset(
    {"go", "rust", "github-actions", "swift", "erlang", "vscode", "open-vsx", "pub"}
)
ORDERED_ECOSYSTEMS = SEMVER_ECOSYSTEMS | {"npm", "pypi", "maven", "rubygems", "nuget", "composer"}


class VersionOrderError(ValueError):
    """The value is not a version this ecosystem's implemented ordering covers."""


def _prerelease_identifier(part: str, *, fold_case: bool) -> tuple[int, int | str]:
    """SemVer 2: numeric identifiers compare numerically and below alphanumeric ones."""
    if part.isdigit():
        return (0, int(part))
    return (1, part.lower() if fold_case else part)


@total_ordering
@dataclass(frozen=True, slots=True)
class _Release:
    """Numeric core plus SemVer-style prerelease; no prerelease is the release itself."""

    core: tuple[int, ...]
    prerelease: tuple[tuple[int, int | str], ...]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _Release):
            return NotImplemented
        return (self.core, self.prerelease) == (other.core, other.prerelease)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, _Release):
            return NotImplemented
        if self.core != other.core:
            return self.core < other.core
        if not self.prerelease or not other.prerelease:
            return bool(self.prerelease) and not other.prerelease
        return self.prerelease < other.prerelease

    def __hash__(self) -> int:
        return hash((self.core, self.prerelease))


# SemVer 2 (Go with its "v", Cargo, Swift, Hex, VS Code, Open VSX, pub, GitHub Actions
# tags such as "v4"): one to three numeric parts, padded; build metadata is ignored,
# except for pub, which orders by it (so pub versions with metadata are refused).
_SEMVER = re.compile(
    r"^v?(?P<core>(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,2})"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


def _semver(ecosystem: str, value: str) -> _Release:
    match = _SEMVER.fullmatch(value)
    if match is None or (ecosystem == "pub" and match.group("build")):
        raise VersionOrderError("not an ordered version")
    pre = match.group("pre")
    if pre and any(p.isdigit() and len(p) > 1 and p.startswith("0") for p in pre.split(".")):
        raise VersionOrderError("prerelease has a leading zero")
    core = tuple(int(part) for part in match.group("core").split("."))
    prerelease = (
        tuple(_prerelease_identifier(p, fold_case=False) for p in pre.split(".")) if pre else ()
    )
    return _Release(core + (0,) * (3 - len(core)), prerelease)


# NuGet: up to four numeric parts (a missing part is 0), SemVer 2 prerelease labels
# compared case-insensitively, metadata ignored.
_NUGET = re.compile(
    r"^(?P<core>[0-9]+(?:\.[0-9]+){0,3})"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def _nuget(value: str) -> _Release:
    match = _NUGET.fullmatch(value)
    if match is None:
        raise VersionOrderError("not an ordered version")
    core = tuple(int(part) for part in match.group("core").split("."))
    pre = match.group("pre")
    prerelease = (
        tuple(_prerelease_identifier(p, fold_case=True) for p in pre.split(".")) if pre else ()
    )
    return _Release(core + (0,) * (4 - len(core)), prerelease)


@total_ordering
@dataclass(frozen=True, slots=True)
class _Qualified:
    """A numeric release (trailing zeros removed) with one ranked qualifier and number."""

    core: tuple[int, ...]
    rank: int
    number: int

    def _key(self, width: int) -> tuple[Any, ...]:
        return (self.core + (0,) * (width - len(self.core)), self.rank, self.number)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _Qualified):
            return NotImplemented
        width = max(len(self.core), len(other.core))
        return self._key(width) == other._key(width)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, _Qualified):
            return NotImplemented
        width = max(len(self.core), len(other.core))
        return self._key(width) < other._key(width)

    def __hash__(self) -> int:
        return hash(self._key(len(self.core)))


def _trim(core: tuple[int, ...]) -> tuple[int, ...]:
    while core and core[-1] == 0:
        core = core[:-1]
    return core


# Maven: the numeric release plus at most one well-known qualifier, compared the way
# ComparableVersion does for these forms (trailing zeros are insignificant, a qualifier
# sorts below the plain release except "sp" above it, and a larger number anywhere in
# the release outranks any qualifier). Other qualifiers, "1-1" style build numbers and
# separators inside a qualifier are refused.
_MAVEN = re.compile(
    r"^(?P<core>[0-9]+(?:\.[0-9]+)*)"
    r"(?:[-.](?P<qualifier>alpha|beta|milestone|rc|cr|snapshot|ga|final|release|sp"
    r"|[abm](?=[0-9]))(?P<number>[0-9]+)?)?$",
    re.IGNORECASE,
)
_MAVEN_RANK = {
    "alpha": 0,
    "a": 0,
    "beta": 1,
    "b": 1,
    "milestone": 2,
    "m": 2,
    "rc": 3,
    "cr": 3,
    "snapshot": 4,
    "": 5,
    "ga": 5,
    "final": 5,
    "release": 5,
    "sp": 6,
}


def _maven(value: str) -> _Qualified:
    match = _MAVEN.fullmatch(value)
    if match is None:
        raise VersionOrderError("not an ordered version")
    qualifier = (match.group("qualifier") or "").lower()
    number = int(match.group("number") or 0)
    if _MAVEN_RANK[qualifier] == 5 and number:
        raise VersionOrderError("release qualifiers take no number")
    core = _trim(tuple(int(part) for part in match.group("core").split(".")))
    return _Qualified(core, _MAVEN_RANK[qualifier], number)


# Composer: up to four numeric parts and one stability suffix, ordered
# alpha < beta < RC < stable < patch as Composer's version normalization does. Branch
# forms (dev-main, 1.x-dev) are refused.
_COMPOSER = re.compile(
    r"^v?(?P<core>[0-9]+(?:\.[0-9]+){0,3})"
    r"(?:[-._]?(?P<stability>stable|alpha|a|beta|b|rc|patch|pl|p)(?:[-.]?(?P<number>[0-9]+))?)?"
    r"(?:\+[0-9A-Za-z.-]+)?$",  # build metadata is ignored, as Composer normalizes it away
    re.IGNORECASE,
)
_COMPOSER_RANK = {
    "stable": 3,
    "alpha": 0,
    "a": 0,
    "beta": 1,
    "b": 1,
    "rc": 2,
    "": 3,
    "patch": 4,
    "pl": 4,
    "p": 4,
}


def _composer(value: str) -> _Qualified:
    match = _COMPOSER.fullmatch(value)
    if match is None:
        raise VersionOrderError("not an ordered version")
    stability = (match.group("stability") or "").lower()
    core = tuple(int(part) for part in match.group("core").split("."))
    # PHP's comparison orders "beta" before "beta0": an absent number sorts first.
    # Composer drops a "stable" suffix entirely, number included (1.0.0-stable1 is 1.0.0).
    number = (
        int(match.group("number"))
        if match.group("number") is not None and stability != "stable"
        else -1
    )
    return _Qualified(_trim(core), _COMPOSER_RANK[stability], number)


@total_ordering
@dataclass(frozen=True, slots=True)
class _Gem:
    """Gem::Version: canonical segments with insignificant zeros removed from both the
    release and the prerelease part; a word segment sorts below any number."""

    segments: tuple[int | str, ...]

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Gem) and self.segments == other.segments

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, _Gem):
            return NotImplemented
        left, right = self.segments, other.segments
        for index in range(max(len(left), len(right))):
            a = left[index] if index < len(left) else 0
            b = right[index] if index < len(right) else 0
            if a == b:
                continue
            if isinstance(a, str) and isinstance(b, int):
                return True
            if isinstance(a, int) and isinstance(b, str):
                return False
            return a < b  # type: ignore[operator]
        return False

    def __hash__(self) -> int:
        return hash(self.segments)


def _drop_trailing_zeros(part: list[int | str]) -> list[int | str]:
    while part and part[-1] == 0:
        part = part[:-1]
    return part


def _gem(value: str) -> _Gem:
    # Gem compares words case-sensitively; upper-case words are refused rather than
    # guessed.
    if not re.fullmatch(r"[0-9]+(?:[.-][0-9a-z]+)*", value):
        raise VersionOrderError("not an ordered version")
    tokens: list[int | str] = [
        int(token) if token.isdigit() else token
        for token in re.findall(r"[0-9]+|[a-z]+", value.replace("-", ".pre."))
    ]
    first_word = next((i for i, token in enumerate(tokens) if isinstance(token, str)), None)
    release = tokens if first_word is None else tokens[:first_word]
    prerelease = [] if first_word is None else tokens[first_word:]
    return _Gem(tuple(_drop_trailing_zeros(release) + _drop_trailing_zeros(prerelease)))


# npm exact versions are full X.Y.Z; "1" and "1.2" are ranges there.
_NPM_FULL = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+].*)?$")


def version_key(ecosystem: str, value: object) -> Any:
    """Return an ordering key for one version, or raise VersionOrderError."""
    if not isinstance(value, str) or not value or len(value) > MAX_VERSION_LENGTH:
        raise VersionOrderError("version is missing or too long")
    if not value.isascii() or any(character.isspace() for character in value):
        raise VersionOrderError("version is not an ASCII value")
    try:
        if ecosystem == "npm":
            if not _NPM_FULL.fullmatch(value):
                raise VersionOrderError("npm versions are full X.Y.Z")
            return SemVer.parse(value)
        if ecosystem == "pypi":
            return Version(value)
    except (RangeEvaluationError, InvalidVersion) as error:
        raise VersionOrderError("not an ordered version") from error
    if ecosystem == "maven":
        return _maven(value)
    if ecosystem == "rubygems":
        return _gem(value)
    if ecosystem == "nuget":
        return _nuget(value)
    if ecosystem == "composer":
        return _composer(value)
    if ecosystem in SEMVER_ECOSYSTEMS:
        return _semver(ecosystem, value)
    raise VersionOrderError("ecosystem has no implemented version ordering")


def is_exact_version(ecosystem: str, value: object) -> bool:
    try:
        version_key(ecosystem, value)
    except VersionOrderError:
        return False
    return True


def exact_version_matches(ecosystem: str, version: str, expected: str) -> bool | None:
    """Whether ``version`` is the exact advisory version ``expected``; None if unsure.

    Equality uses the ecosystem's ordering (Go ``v1.2.3`` is ``1.2.3``; Maven ``1.0`` is
    ``1``); PyPI follows PEP 440 ``==``, so a local build ``1.0+ubuntu1`` is version
    ``1.0`` unless the advisory names a local label itself. When either spelling is
    outside the implemented ordering of an ordered ecosystem, only identical strings
    are decided (True); different ones are undecided, never "not this version".
    Ecosystems without a version order (git, containers) compare byte for byte.
    """
    if ecosystem not in ORDERED_ECOSYSTEMS:
        return version == expected
    try:
        candidate = version_key(ecosystem, version)
        target = version_key(ecosystem, expected)
    except VersionOrderError:
        return True if version == expected else None
    if ecosystem == "pypi" and target.local is None:
        return bool(Version(candidate.public) == target)
    return bool(candidate == target)


def _compare(left: Any, operator: str, right: Any) -> bool:
    return {
        "=": left == right,
        "==": left == right,
        "!=": left != right,
        ">": left > right,
        ">=": left >= right,
        "<": left < right,
        "<=": left <= right,
    }[operator]


def comparator_list_matches(ecosystem: str, version: str, expression: object) -> bool | None:
    """Evaluate a comma-separated comparator list; None when it cannot be decided."""
    if not isinstance(expression, str) or not expression.strip() or len(expression) > 1000:
        return None
    if expression.replace(" ", "") in ALL_VERSIONS:
        return True
    try:
        candidate = version_key(ecosystem, version)
        results = []
        for part in expression.split(","):
            match = COMPARATOR.fullmatch(part)
            if match is None:
                return None
            operator = match.group(1) or "="
            results.append(_compare(candidate, operator, version_key(ecosystem, match.group(2))))
    except VersionOrderError:
        return None
    return all(results)
