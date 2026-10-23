"""Every ecosystem orders versions the way its registry does, or refuses the form."""

from __future__ import annotations

import pytest

from smithguard.range_evaluation import osv_range_matches, range_result
from smithguard.version_order import (
    comparator_list_matches,
    exact_version_matches,
    is_exact_version,
    version_key,
)


@pytest.mark.parametrize(
    ("ecosystem", "ordered"),
    [
        # Maven ComparableVersion order for single well-known qualifiers.
        (
            "maven",
            [
                "1-alpha1",
                "1-alpha2",
                "1-beta1",
                "1-milestone1",
                "1-rc1",
                "1-snapshot",
                "1",
                "1-sp",
                "1-sp2",
                "1.0.1",
                "1.1",
            ],
        ),
        ("maven", ["2.0", "2.0.2", "2.0.123", "2.1.0", "2.2", "2.123", "11"]),
        ("maven", ["2.0-beta9", "2.0", "2.14.1", "2.15.0", "2.17.1", "2.24.3"]),
        # RubyGems: words sort below numbers; "-" means ".pre.".
        ("rubygems", ["1.0.0.pre1", "1.0.0.rc1", "1.0.0", "1.0.1", "1.10"]),
        ("go", ["v0.9.0", "v1.6.0", "v1.6.3", "v1.7.0-rc.1", "v1.7.0", "v1.10.0"]),
        ("github-actions", ["v45.0.7", "v46", "46.0.1", "v47.0.0"]),
        # NuGet: case-insensitive labels, numeric identifiers numerically, four parts.
        (
            "nuget",
            ["1.0.0-alpha", "1.0.0-beta.2", "1.0.0-beta.10", "1.0.0-RC1", "1.0.0", "1.0.0.1"],
        ),
        # Composer stabilities: alpha < beta < RC < stable < patch.
        (
            "composer",
            [
                "1.0.0-alpha1",
                "1.0.0-beta1",
                "1.0.0-beta2",
                "1.0.0-RC1",
                "1.0.0",
                "1.0.0-p1",
                "1.0.1",
            ],
        ),
        ("rust", ["0.2.9", "0.3.0-alpha.1", "0.3.0-alpha.2", "0.3.0"]),
        ("npm", ["1.2.3-alpha", "1.2.3", "1.10.0"]),
        ("pypi", ["1.0.dev1", "1.0a1", "1.0", "1.0.post1", "1.1"]),
    ],
)
def test_versions_order_like_their_registry(ecosystem, ordered):
    keys = [version_key(ecosystem, value) for value in ordered]
    for lower, higher in zip(keys, keys[1:], strict=False):
        assert lower < higher, (ecosystem, lower, higher)


@pytest.mark.parametrize(
    ("ecosystem", "left", "right"),
    [
        ("maven", "1", "1.0.0"),
        ("maven", "1.0-alpha1", "1-a1"),
        ("maven", "1-cr1", "1-rc1"),
        ("maven", "1-b2", "1-beta2"),
        ("maven", "1-m3", "1-milestone3"),
        ("maven", "1.0.final", "1-ga"),
        ("maven", "2.0.0.RC1", "2-rc1"),
        ("rubygems", "1.0.a", "1.a"),
        ("rubygems", "1.0.0", "1"),
        ("go", "v1.2.3", "1.2.3"),
        ("go", "v2.0.0+incompatible", "v2.0.0"),
        ("github-actions", "v4", "4.0.0"),
        ("nuget", "1.0.0-BETA1", "1.0.0-beta1"),
        ("nuget", "1.0", "1.0.0.0"),
        ("nuget", "1.0.0+meta", "1.0.0"),
        ("composer", "v1.2", "1.2.0"),
        ("composer", "1.0.0-patch1", "1.0.0-pl1"),
        ("composer", "1.0.0-stable", "1.0.0"),
        ("composer", "1.0.0-stable1", "1.0.0"),
        ("composer", "1.0.0+build.5", "1.0.0"),
    ],
)
def test_equivalent_spellings_are_equal(ecosystem, left, right):
    assert version_key(ecosystem, left) == version_key(ecosystem, right)


@pytest.mark.parametrize(
    ("ecosystem", "value"),
    [
        # Forms whose registry ordering is not implemented are refused, never guessed.
        ("maven", "1-1"),
        ("maven", "2.1b"),
        ("maven", "1-beta-2"),
        ("maven", "1-abc"),
        ("maven", "1-pom-1"),
        ("maven", "latest"),
        ("maven", "1-ga2"),
        ("rubygems", "1.0.A"),
        ("rubygems", "1.0.0.RC1"),
        ("composer", "dev-main"),
        ("composer", "1.x-dev"),
        ("composer", "1.0.0-dev"),
        ("pub", "1.0.0+1"),
        ("rust", "1.0.0-01"),
        ("go", "latest"),
        ("npm", "1.2"),
        ("npm", "^4.17.21"),
        ("github-actions", "8f4b7f84864484a7bf31766abe9204da3cbe65b3"),
        ("docker", "1.0"),
    ],
)
def test_unsupported_forms_are_refused(ecosystem, value):
    assert not is_exact_version(ecosystem, value)


@pytest.mark.parametrize(
    ("ecosystem", "version", "expression", "expected"),
    [
        ("maven", "2.14.1", ">= 2.0-beta9, < 2.15.0", True),
        ("maven", "2.24.3", ">= 2.0-beta9, < 2.15.0", False),
        ("maven", "2.0-beta9", ">= 2.0-beta9, < 2.15.0", True),
        ("github-actions", "v45.0.7", "<= 45.0.7", True),
        ("github-actions", "v47.0.0", "<= 45.0.7", False),
        ("nuget", "12.0.1", "< 13.0.1", True),
        ("nuget", "1.0.0-BETA1", "= 1.0.0-beta1", True),
        ("composer", "1.0.0-beta1", "< 1.0.0-RC1", True),
        # PHP orders an absent qualifier number before 0.
        ("composer", "1.0.0-beta", "< 1.0.0-beta0", True),
        ("composer", "1.0.0-beta0", "< 1.0.0-beta", False),
        ("rubygems", "1.0.a", "<= 1.a", True),
        ("go", "v1.2.2", "< 1.2.3", True),
        ("rust", "1.0.0", ">= 0", True),
        # A strict bound excludes its own value; only real sentinels match everything.
        ("rust", "0.0.0", "> 0.0.0", False),
        ("rust", "0.0.1", "> 0.0.0", True),
        ("vscode", "0.0.1", ">= 0", True),
    ],
)
def test_comparator_lists_decide_for_every_ecosystem(ecosystem, version, expression, expected):
    assert comparator_list_matches(ecosystem, version, expression) is expected


@pytest.mark.parametrize(
    ("ecosystem", "version", "expression"),
    [
        ("maven", "1-1", "< 1.1"),  # "1-1" orders below "1.1" in Maven; refused here
        ("maven", "latest", "< 2.0"),
        ("npm", "^4.17.21", "< 5.0.0"),
        ("go", "v1.2.3", "~> 1.2"),
        ("maven", "1.0", ""),
        ("docker", "1.0", "< 2.0"),
    ],
)
def test_undecidable_inputs_stay_unknown(ecosystem, version, expression):
    assert comparator_list_matches(ecosystem, version, expression) is None


@pytest.mark.parametrize(
    ("ecosystem", "version", "expected", "matches"),
    [
        ("pypi", "1.0+ubuntu1", "1.0", True),  # PEP 440 "==": local builds of 1.0
        ("pypi", "1.0", "1.0+ubuntu1", False),
        ("pypi", "1.0.0", "1.0", True),
        ("go", "v1.2.3", "1.2.3", True),
        ("maven", "1.0.0", "1", True),
        ("nuget", "1.0.0-BETA1", "1.0.0-beta1", True),
        ("rubygems", "1.0.a", "1.a", True),
        ("npm", "1.0.0", "1.0.1", False),
        ("git", "abc123", "abc123", True),  # no ordering: byte equality
        ("git", "ABC123", "abc123", False),
        ("maven", "1-1", "1-1", True),
        # Outside the implemented order: identical strings decide, others stay unknown.
        ("maven", "1-foo", "1-FOO", None),
        ("maven", "1-foo", "1-bar", None),
    ],
)
def test_exact_advisory_versions_match_by_ecosystem_rules(ecosystem, version, expected, matches):
    assert exact_version_matches(ecosystem, version, expected) is matches


@pytest.mark.parametrize("ecosystem", ["git", "vscode", "rust", "maven", "swift"])
def test_introduced_zero_alone_affects_every_version(ecosystem):
    every = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}
    assert osv_range_matches(ecosystem, "anything-1", every) is True
    bounded = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}
    if ecosystem == "git":
        assert osv_range_matches(ecosystem, "anything-1", bounded) is None
    # A commit range says nothing about package versions outside the git ecosystem.
    commits = {"type": "GIT", "events": [{"introduced": "0"}]}
    assert osv_range_matches(ecosystem, "1.0.0", commits) is (True if ecosystem == "git" else None)


def test_legacy_ranges_use_ecosystem_rules():
    def result(ecosystem, version, range_type, expression):
        return range_result(
            artifact={"ecosystem": ecosystem, "version": version, "digest": None},
            affected_range={
                "evaluation_state": "supported",
                "range_type": range_type,
                "expression": expression,
            },
        )

    assert result("go", "v1.2.3", "EXACT", "= 1.2.3") is True
    assert result("go", "v1.2.4", "EXACT", "= 1.2.3") is False
    assert result("maven", "2.14.1", "ECOSYSTEM", ">= 2.0, < 2.15.0") is True
    assert result("maven", "2.24.3", "ECOSYSTEM", ">= 2.0, < 2.15.0") is False
    assert result("maven", "latest", "ECOSYSTEM", ">= 2.0, < 2.15.0") is None


@pytest.mark.parametrize(
    ("version", "expression", "expected"),
    [
        ("1.0+ubuntu1", "<=1.0", True),
        ("1.0+ubuntu1", "==1.0", True),
        ("1.0+ubuntu1", "==1.0+ubuntu2", False),
        ("1.0.1+ubuntu1", "<1.0.1", False),
        ("2.0rc1", "<2.0", True),
    ],
)
def test_pypi_comparators_treat_local_builds_as_their_public_version(version, expression, expected):
    from smithguard.range_evaluation import pep440_matches

    assert pep440_matches(version, expression) is expected
