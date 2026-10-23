"""Canonical identifiers reject JSON values without a portable representation."""

import math

import pytest

from smithguard.identifiers import canonical_json_bytes


def test_canonical_json_rejects_non_finite_numbers() -> None:
    with pytest.raises(ValueError):
        canonical_json_bytes({"value": math.nan})
