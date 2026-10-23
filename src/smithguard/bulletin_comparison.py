"""Versioned factual comparison beside, never instead of, immutable content hashes."""

from copy import deepcopy

from smithguard.identifiers import canonical_json_bytes, sha256_id

COMPARISON_VERSION = "bulletin_factual_v1"


def factual_hash(document):
    """Exclude only a source's modification timestamp and acquisition commitments.

    Publisher identity, attribution, rights, dates of publication, lifecycle and
    every reported claim still participate. Unknown future fields participate too.
    This compares the public projection, not the publisher's complete source body.
    """
    facts = deepcopy(document)
    facts.pop("source_modified_at", None)
    for source in facts["sources"]:
        source.pop("source_evidence_hash", None)
    return sha256_id(canonical_json_bytes({"version": COMPARISON_VERSION, "facts": facts}))


def comparison(previous, current):
    return {
        "version": COMPARISON_VERSION,
        "previous_factual_hash": factual_hash(previous),
        "current_factual_hash": factual_hash(current),
    }
