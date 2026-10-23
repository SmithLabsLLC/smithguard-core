"""Deterministic, attributed public facts from qualified official source evidence."""

from smithguard.bulletin_contract import BulletinError, validate_content
from smithguard.bulletin_source_parser import PARSER_VERSION
from smithguard.bulletin_sources import CATALOG_SOURCES, NETWORK_SOURCES, SOURCE_IDS
from smithguard.identifiers import canonical_json_bytes, sha256_id

FACT_FIELDS = [
    "url",
    "published_at",
    "modified_at",
    "record_id",
    "aliases",
    "severity",
    "subjects",
    "fixed_versions",
    "withdrawn",
    "time_precision",
]


def semantic_hash(document):
    return sha256_id(canonical_json_bytes(document))


def envelope(candidate, *, now, retrospective):
    from smithguard.identifiers import timestamp

    document = candidate.document()
    return {
        "schema_version": 2,
        "source": candidate.source,
        "record_key": candidate.record_key,
        "document": document,
        "semantic_hash": semantic_hash(document),
        "transport": "publisher_endpoint_tls",
        "accepted_at": timestamp(now),
        "retrospective": retrospective,
    }


def project_facts(evidence, registry, *, now):
    if not isinstance(evidence, dict) or set(evidence) != {
        "schema_version",
        "source",
        "record_key",
        "document",
        "semantic_hash",
        "transport",
        "accepted_at",
        "retrospective",
    }:
        raise BulletinError("bulletin_facts_envelope")
    source = evidence["source"]
    doc = evidence["document"]
    if (
        evidence["schema_version"] != 2
        or source not in SOURCE_IDS
        or evidence["transport"] != "publisher_endpoint_tls"
        or type(evidence["retrospective"]) is not bool
        or not isinstance(doc, dict)
        or set(doc) != {"source", "url", "published_at", "modified_at", "facts", "needs_detail"}
        or doc["source"] != source
        or doc["needs_detail"] is not False
        or evidence["record_key"] != sha256_id(doc["url"].encode())[7:]
        or evidence["semantic_hash"] != semantic_hash(doc)
    ):
        raise BulletinError("bulletin_facts_integrity")
    facts = doc["facts"]
    if facts.get("parser") != PARSER_VERSION:
        raise BulletinError("bulletin_facts_parser")
    if source in NETWORK_SOURCES:
        spec = NETWORK_SOURCES[source]
        spec.record_url(doc["url"])
        publisher = spec.publisher
        used_fields = FACT_FIELDS
    else:
        from smithguard.bulletin_catalog import validate_catalog_url

        validate_catalog_url(source, doc["url"])
        publisher = CATALOG_SOURCES[source][1]
        used_fields = (
            [
                "ghsa_id",
                "html_url",
                "identifiers",
                "published_at",
                "updated_at",
                "withdrawn_at",
                "vulnerabilities.package",
                "vulnerabilities.first_patched_version",
                "vulnerabilities.vulnerable_version_range",
            ]
            if source == "ghsa-bulletin"
            else ["id", "aliases", "affected", "references", "published", "modified", "withdrawn"]
        )
    profile = registry.get(SOURCE_IDS[source])
    withdrawn = facts["withdrawn"]
    identity = facts["record_id"]
    subjects = facts["subjects"][:16]
    fixes = facts["fixed_versions"]
    conditions = facts.get("conditions", [])[:16]
    omitted = facts.get("omissions", 0)
    unknowns = ["Applicability to any particular installation has not been assessed."]
    if not fixes:
        unknowns.append("Fixes and workarounds are not extracted here; check the linked source.")
    if omitted:
        unknowns.append(f"{omitted} package or range facts were omitted from this bounded summary.")
    if facts.get("alias_omissions", 0):
        unknowns.append(
            f"{facts['alias_omissions']} additional identifiers were omitted; "
            "consult the source for the full list."
        )
    summary = (
        f"{publisher} "
        + ("withdrew" if withdrawn else "published")
        + f" security advisory {identity}."
    )
    if subjects:
        summary += " Listed products or packages: " + ", ".join(subjects[:4]) + "."
    summary += " Read the source for full conditions and guidance."
    result = {
        "schema_version": "1.0.0",
        "source_key": source,
        "record_url": doc["url"],
        "evidence_class": "official_advisory",
        "verification": "publisher_endpoint_tls",
        "applicability": "not_evaluated",
        "lifecycle": "withdrawn" if withdrawn else "current",
        "title": f"{publisher}: {identity}"[:200],
        "summary": summary[:1200],
        "subjects": subjects,
        "aliases": facts["aliases"],
        "source_published_at": doc["published_at"],
        "source_modified_at": doc["modified_at"],
        "time_precision": facts["time_precision"],
        "severity": facts["severity"],
        "exploitation": "no_claim",
        "remediation": "vendor_fix_available" if fixes else "unknown",
        "conditions": conditions,
        "guidance": [f"Source-listed fix: {value}" for value in fixes[:8]],
        "unknowns": unknowns,
        "related_bulletins": [],
        "retrospective": evidence["retrospective"],
        "sources": [
            {
                "source_id": SOURCE_IDS[source],
                "record_url": doc["url"],
                "source_evidence_hash": sha256_id(canonical_json_bytes(evidence)),
                "rights_revision": profile.source["revision"],
                "attribution": profile.source["rights"]["attribution_text"],
                "used_fields": used_fields,
            }
        ],
    }
    for url in facts.get("attribution_urls", []):
        result["sources"].append(
            {
                **result["sources"][0],
                "record_url": url,
                "used_fields": ["references"],
            }
        )
    return validate_content(result, now=now)
