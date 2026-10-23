"""Fixed official notice projection: source prose never becomes automatic advice."""

from smithguard.bulletin_contract import BulletinError, validate_content
from smithguard.identifiers import canonical_json_bytes, sha256_id
from smithguard.official_notice_parser import source_url

PROJECTION_VERSION = "official-notice-and-kev-facts-v2"
NOTICE_PROFILES = {
    "php": ("gbsec:source:php-security-notices", "PHP", "The PHP Group"),
    "mozilla": ("gbsec:source:mozilla-security-blog", "Mozilla", "Mozilla"),
}
NOTICE_FIELDS = ["url", "published_at", "modified_at", "withdrawn", "security_notice"]


def project_notice(evidence, registry, *, now):
    """Only an immutable accepted notice envelope can authorize this projection.

    No copied headline, excerpt, inferred CVE, range, severity or remediation.
    Richer incident summaries remain an individually reviewed path.
    """
    if not isinstance(evidence, dict) or set(evidence) != {
        "schema_version",
        "source",
        "record_key",
        "document",
        "semantic_hash",
        "fetch_url",
        "transport",
        "accepted_at",
        "retrospective",
    }:
        raise BulletinError("bulletin_input_shape")
    doc = evidence["document"]
    source = evidence["source"]
    if (
        evidence["schema_version"] != 1
        or source not in NOTICE_PROFILES
        or evidence["transport"] != "publisher_endpoint_tls"
        or not isinstance(doc, dict)
        or set(doc)
        != {
            "source",
            "url",
            "title",
            "context",
            "published_at",
            "modified_at",
            "withdrawn",
            "entry_sha256",
            "content_sha256",
        }
        or doc["source"] != source
        or type(doc["withdrawn"]) is not bool
        or type(evidence["retrospective"]) is not bool
    ):
        raise BulletinError("bulletin_input_invalid")
    from smithguard.official_notice_fetch import ENDPOINTS
    from smithguard.official_notice_store import semantic_hash

    source_url(source, doc["url"])
    if (
        evidence["fetch_url"] != ENDPOINTS[source][0]
        or evidence["record_key"] != sha256_id(doc["url"].encode())[7:]
        or evidence["semantic_hash"] != semantic_hash(doc)
    ):
        raise BulletinError("bulletin_input_integrity")
    source_id, product, publisher = NOTICE_PROFILES[source]
    profile = registry.get(source_id)
    result = {
        "schema_version": "1.0.0",
        "source_key": source,
        "record_url": doc["url"],
        "evidence_class": "official_notice",
        "verification": "publisher_endpoint_tls",
        "applicability": "not_evaluated",
        "lifecycle": "withdrawn" if doc["withdrawn"] else "current",
        "title": f"{product} security notice",
        "summary": (
            f"{publisher} withdrew a security-related announcement. Read the linked source."
            if doc["withdrawn"]
            else f"{publisher} published a security-related announcement. "
            "Read the linked source for its details and guidance."
        ),
        "subjects": [product],
        "aliases": [],
        "source_published_at": doc["published_at"],
        "source_modified_at": doc["modified_at"],
        "time_precision": "exact",
        "severity": "unknown",
        "exploitation": "no_claim",
        "remediation": "unknown",
        "conditions": [],
        "guidance": [],
        "unknowns": [
            "Affected versions, severity and fixes are not extracted by this notice feed.",
            "Applicability to any particular installation has not been assessed.",
        ],
        "sources": [
            {
                "source_id": source_id,
                "record_url": doc["url"],
                "source_evidence_hash": sha256_id(canonical_json_bytes(evidence)),
                "rights_revision": profile.source["revision"],
                "attribution": profile.source["rights"]["attribution_text"],
                "used_fields": NOTICE_FIELDS,
            }
        ],
        "related_bulletins": [],
        "retrospective": evidence["retrospective"],
    }
    return validate_content(result, now=now)
