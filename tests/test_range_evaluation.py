"""The public and local paths share exact npm and PyPI range decisions."""

from smithguard.range_evaluation import (
    normalize_github_npm_advisory_range,
    normalize_semver_comparator_range,
    range_result,
)


def _artifact(ecosystem: str, version: str) -> dict:
    return {"ecosystem": ecosystem, "version": version, "digest": None}


def _range(range_type: str, expression: str) -> dict:
    return {
        "range_type": range_type,
        "expression": expression,
        "evaluation_state": "supported",
    }


def test_npm_semver_range_returns_true_and_false_for_exact_requested_versions() -> None:
    affected = _range("SEMVER", ">=1.2.0 <2.0.0")
    assert range_result(artifact=_artifact("npm", "1.5.0"), affected_range=affected) is True
    assert range_result(artifact=_artifact("npm", "2.1.0"), affected_range=affected) is False


def test_github_style_spaced_npm_comparators_are_canonical_and_executable() -> None:
    assert normalize_semver_comparator_range("> 0") == ">0"
    assert normalize_semver_comparator_range(">= 1.2.0, < 2.0.0") == ">=1.2.0 <2.0.0"
    assert normalize_semver_comparator_range("!= 1.2.0") is None
    assert normalize_semver_comparator_range(">=1.0.0,,<2.0.0") is None
    assert normalize_github_npm_advisory_range("> 0") == "*"
    assert normalize_github_npm_advisory_range(">= 0") == "*"
    assert normalize_github_npm_advisory_range(">= 0.0.0") == "*"
    affected = _range("SEMVER", "*")
    assert range_result(artifact=_artifact("npm", "0.0.0"), affected_range=affected) is True
    assert range_result(artifact=_artifact("npm", "0.9.9"), affected_range=affected) is True
    assert range_result(artifact=_artifact("npm", "1.0.0-beta.1"), affected_range=affected) is True


def test_npm_range_evaluation_preserves_exposure_matching_for_existing_evidence() -> None:
    greater_minor = _range("SEMVER", ">1.2")
    assert range_result(artifact=_artifact("npm", "1.2.99"), affected_range=greater_minor) is True
    assert range_result(artifact=_artifact("npm", "1.3.0"), affected_range=greater_minor) is True
    broad = _range("SEMVER", ">=1.0.0")
    assert range_result(artifact=_artifact("npm", "2.0.0-beta.1"), affected_range=broad) is True
    explicit_prerelease = _range("SEMVER", ">=2.0.0-beta.1 <2.0.0")
    assert (
        range_result(
            artifact=_artifact("npm", "2.0.0-beta.2"),
            affected_range=explicit_prerelease,
        )
        is True
    )
    partial_equal = _range("SEMVER", "= 1.2")
    assert range_result(artifact=_artifact("npm", "1.2.0"), affected_range=partial_equal) is None
    assert range_result(artifact=_artifact("npm", "1.2.9"), affected_range=partial_equal) is None


def test_pypi_pep440_range_returns_true_and_false_for_exact_requested_versions() -> None:
    affected = _range("ECOSYSTEM", ">=3.8,<4")
    assert range_result(artifact=_artifact("pypi", "3.11"), affected_range=affected) is True
    assert range_result(artifact=_artifact("pypi", "4.0"), affected_range=affected) is False


def test_unsupported_range_stays_unknown_instead_of_guessing() -> None:
    affected = _range("ECOSYSTEM", "~=1.4")
    assert range_result(artifact=_artifact("npm", "1.5.0"), affected_range=affected) is None


def test_exact_range_matches_either_version_or_digest() -> None:
    digest = "sha256:" + "a" * 64
    artifact = {"ecosystem": "oci", "version": "latest", "digest": digest}
    assert (
        range_result(
            artifact=artifact,
            affected_range=_range("EXACT", digest),
        )
        is True
    )
    assert (
        range_result(
            artifact=artifact,
            affected_range=_range("EXACT", "latest"),
        )
        is True
    )


def test_partial_npm_comparators_are_unknown_even_after_a_nonmatch() -> None:
    from smithguard.range_evaluation import pep440_matches, semver_matches

    for expression in ("<=1.2", ">=9.0.0 <=1.2", "<=1.2 >=9.0.0", ">=9.0.0 =1.2"):
        assert semver_matches("1.2.5", expression) is None
    assert pep440_matches("0.5", ">=1.0 garbage") is None
    assert pep440_matches("0.5", "garbage >=1.0") is None


def test_osv_event_order_and_limits_are_independent() -> None:
    from itertools import permutations

    from smithguard.range_evaluation import osv_range_matches

    cases = [
        (
            [{"fixed": "2.0.0"}, {"introduced": "1.0.0"}],
            {"0.9.0": False, "1.0.0": True, "2.0.0": False, "3.0.0": False},
        ),
        (
            [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}, {"limit": "3.0.0"}],
            {"1.5.0": True, "2.5.0": False},
        ),
        (
            [{"introduced": "0"}, {"fixed": "4.0.0"}, {"limit": "2.0.0"}],
            {"1.9.0": True, "2.0.0": False, "2.5.0": False},
        ),
        (
            [{"introduced": "0"}, {"limit": "2.0.0"}, {"limit": "3.0.0"}],
            {"2.5.0": True, "3.0.0": False},
        ),
        ([{"introduced": "0"}, {"limit": "2.0.0"}, {"limit": "*"}], {"3.0.0": True}),
        ([{"introduced": "1.0.0"}, {"last_affected": "2.0.0"}], {"2.0.0": True, "2.0.1": False}),
        (
            [
                {"introduced": "1.0.0"},
                {"fixed": "2.0.0"},
                {"introduced": "3.0.0"},
                {"fixed": "4.0.0"},
            ],
            {"1.5.0": True, "2.5.0": False, "3.0.0": True, "4.0.0": False},
        ),
    ]
    for events, expected in cases:
        for permutation in permutations(events):
            for version, verdict in expected.items():
                for ecosystem in ("npm", "pypi"):
                    assert (
                        osv_range_matches(
                            ecosystem, version, {"type": "ECOSYSTEM", "events": list(permutation)}
                        )
                        is verdict
                    )


def test_malformed_osv_ranges_never_return_a_definite_verdict() -> None:
    from smithguard.range_evaluation import osv_range_matches

    invalid_events = [
        [],
        None,
        {},
        [None],
        [{"fixed": "2.0.0"}],
        [{"introduced": "0"}, {"fixed": "2.0.0"}, {"last_affected": "3.0.0"}],
        [{"introduced": "0"}, {"fixed": "unknown"}],
        [{"introduced": "0", "fixed": "2.0.0"}],
        [{"introduced": "0"}, {"limit": []}],
        [{"introduced": "1.0.0"}, {"fixed": "1.0.0"}],
    ]
    for events in invalid_events:
        assert osv_range_matches("npm", "9.0.0", {"type": "SEMVER", "events": events}) is None
    for kind in ("GIT", "OTHER", [], {}):
        assert (
            osv_range_matches("npm", "1.0.0", {"type": kind, "events": [{"introduced": "0"}]})
            is None
        )
    assert (
        osv_range_matches(
            "npm", "1.2.5", {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2"}]}
        )
        is None
    )
    assert (
        osv_range_matches(
            "pypi",
            "2.0rc1",
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]},
        )
        is True
    )


def test_osv_singleton_intervals_and_inclusive_limit_boundary() -> None:
    from smithguard.range_evaluation import osv_range_matches

    events = [{"introduced": "1.0.0"}, {"last_affected": "1.0.0"}]
    for order in (events, list(reversed(events))):
        for ecosystem in ("npm", "pypi", "rust"):
            for version, expected in (("0.9.0", False), ("1.0.0", True), ("1.0.1", False)):
                assert (
                    osv_range_matches(ecosystem, version, {"type": "SEMVER", "events": order})
                    is expected
                )
    limited = {
        "type": "SEMVER",
        "events": [{"introduced": "0"}, {"last_affected": "1.0.0"}, {"limit": "1.0.0"}],
    }
    assert osv_range_matches("npm", "0.9.0", limited) is True
    assert osv_range_matches("npm", "1.0.0", limited) is False


def test_osv_pypi_semver_label_preserves_existing_pep440_policy() -> None:
    from smithguard.range_evaluation import osv_range_matches

    for version in ("1.0rc1", "1.0.post1", "1!2.0"):
        assert (
            osv_range_matches("pypi", version, {"type": "SEMVER", "events": [{"introduced": "0"}]})
            is True
        )
