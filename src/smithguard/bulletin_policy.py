"""Release-bound bulletin grants and decision-time source rights enforcement."""

from __future__ import annotations

import json
import os
import re
import stat
from copy import deepcopy
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from smithguard.bulletin_contract import BulletinError, validate_content
from smithguard.bulletin_manual_sources import MANUAL_SOURCE_PATHS
from smithguard.bulletin_projection import PROJECTION_VERSION, project_notice
from smithguard.bulletin_sources import SOURCE_IDS
from smithguard.identifiers import (
    canonical_json_bytes,
    require_aware_utc,
    sha256_id,
    strict_json_loads,
)
from smithguard.official_notice_parser import source_url
from smithguard.source_rights import RightsRegistry

CONTROL_DIRECTORY = Path("/etc/SmithGuard/policies")
CONTROL_PATH = CONTROL_DIRECTORY / "bulletins.json"
CONTROL_UID = 0


POLICY_ID = "official-bulletins-v1"
MAX_ADDITIONAL_BYTES = 512 * 1024 * 1024
CORRECTION_RESERVE = MAX_ADDITIONAL_BYTES // 5
MAX_PUBLIC_IDENTITIES = 10_000
MAX_SOURCE_IDENTITIES = 20_000
MAX_CHANGES_PER_SOURCE = 100
MAX_CHANGES_PER_RUN = 500
MAX_KEV_IDENTITIES = 1000
MAX_KEV_VERIFICATIONS = 200
MAX_PREVIEW = 20
FEED_SOURCES = {
    "php": "gbsec:source:php-security-notices",
    "mozilla": "gbsec:source:mozilla-security-blog",
    "node": "gbsec:source:node-security-notices",
    "ubuntu": "gbsec:source:ubuntu-security-notices",
    "apple": "gbsec:source:apple-security-releases",
    "kev": "gbsec:source:cisa-kev",
    **SOURCE_IDS,
}


def policy_hash():
    return sha256_id(
        canonical_json_bytes(
            {
                "policy": POLICY_ID,
                "projection": PROJECTION_VERSION,
                "source_profiles": FEED_SOURCES,
                "max_bytes": MAX_ADDITIONAL_BYTES,
                "correction_reserve": CORRECTION_RESERVE,
                "public_identities": MAX_PUBLIC_IDENTITIES,
                "source_identities": MAX_SOURCE_IDENTITIES,
                "per_source": MAX_CHANGES_PER_SOURCE,
                "per_run": MAX_CHANGES_PER_RUN,
                "calendar_admission_limits": False,
                "manual_source_paths": MANUAL_SOURCE_PATHS,
                "kev_identities": MAX_KEV_IDENTITIES,
                "kev_verifications_per_run": MAX_KEV_VERIFICATIONS,
                "preview": MAX_PREVIEW,
                "automation": {
                    "parser": "official-facts-v1",
                    "initial_days": 14,
                    "active_days": 90,
                    "source_changes": 50,
                    "source_details": 4,
                    "network_seconds": 600,
                    "network_attempts": 64,
                    "identity": "exact_publisher_url_and_ghsa_v1",
                    "unchanged_receipts": "compact_batches_v1",
                },
            }
        )
    )


def validate_grant(value):
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "policy_id",
        "policy_hash",
        "operation_id",
        "artifact_commit",
        "mode",
        "source_keys",
        "effective_at",
        "rights_register_hash",
        "review_due_at",
    }:
        raise BulletinError("bulletin_grant_shape")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["policy_id"] != POLICY_ID
        or value["policy_hash"] != policy_hash()
        or value["mode"] not in {"paused", "manual_preview", "automatic"}
        or not isinstance(value["operation_id"], str)
        or not re.fullmatch(r"[0-9]{8}-[a-f0-9]{32}", value["operation_id"])
        or not isinstance(value["artifact_commit"], str)
        or not re.fullmatch(r"[a-f0-9]{40}", value["artifact_commit"])
        or not isinstance(value["rights_register_hash"], str)
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", value["rights_register_hash"])
        or not isinstance(value["source_keys"], list)
        or not value["source_keys"]
        or not all(isinstance(key, str) for key in value["source_keys"])
        or len(value["source_keys"]) != len(set(value["source_keys"]))
        or not set(value["source_keys"]) <= set(FEED_SOURCES)
    ):
        raise BulletinError("bulletin_grant_invalid")
    for key in ("effective_at", "review_due_at"):
        if not isinstance(value[key], str) or not value[key].endswith("Z"):
            raise BulletinError("bulletin_grant_time")
        try:
            datetime.fromisoformat(value[key].replace("Z", "+00:00"))
        except ValueError as error:
            raise BulletinError("bulletin_grant_time") from error
    effective = datetime.fromisoformat(value["effective_at"].replace("Z", "+00:00"))
    due = datetime.fromisoformat(value["review_due_at"].replace("Z", "+00:00"))
    if not effective < due <= effective + timedelta(days=30):
        raise BulletinError("bulletin_grant_time")
    return value


def grant_bytes(value):
    validate_grant(value)
    return (json.dumps(value, sort_keys=True) + "\n").encode("ascii")


def read_grant(*, release, registry_path, now):
    require_aware_utc(now)
    directory = CONTROL_DIRECTORY.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != CONTROL_UID
        or directory.st_mode & 0o022
    ):
        raise BulletinError("bulletin_grant_directory")
    descriptor = os.open(CONTROL_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != CONTROL_UID
            or stat.S_IMODE(meta.st_mode) != 0o644
            or meta.st_nlink != 1
            or meta.st_size > 8192
        ):
            raise BulletinError("bulletin_grant_permissions")
        grant = validate_grant(strict_json_loads(stream.read(8193)))
    if grant["artifact_commit"] != release:
        raise BulletinError("bulletin_grant_release")
    if sha256_id(registry_path.read_bytes()) != grant["rights_register_hash"]:
        raise BulletinError("bulletin_grant_registry")
    if datetime.fromisoformat(grant["effective_at"].replace("Z", "+00:00")) > now:
        raise BulletinError("bulletin_grant_not_effective")
    if now >= datetime.fromisoformat(grant["review_due_at"].replace("Z", "+00:00")):
        raise BulletinError("bulletin_capacity_review_due")
    return grant


def same_publication_content(previous, current, registry):
    """Compare exact projections allowing only explicitly renewed rights references.

    This does not authorize either document: publish/verify still check current
    policy and accepted source evidence. All non-revision bytes must match, and
    the newly projected reference must name the current register head.
    """
    if previous == current:
        return True
    if len(previous["sources"]) != len(current["sources"]):
        return False
    retained = deepcopy(previous)
    for old, new in zip(retained["sources"], current["sources"], strict=True):
        if old["source_id"] != new["source_id"]:
            return False
        if old["rights_revision"] != new["rights_revision"]:
            if new["rights_revision"] != registry.get(new["source_id"]).source[
                "revision"
            ] or not registry.permits_publication_revision(
                old["source_id"], old["rights_revision"]
            ):
                return False
            old["rights_revision"] = new["rights_revision"]
    return retained == current


def publication_rights(document, registry: RightsRegistry, *, now):
    """Stored evidence is subject to the current register, not a historical boolean."""
    validate_content(document, now=now)
    from smithguard.bulletin_licenses import CVE_LICENSE_NOTICES, CVE_SOURCE

    for reference in document["sources"]:
        if reference["source_id"] == CVE_SOURCE:
            if reference.get(
                "license_notice"
            ) not in CVE_LICENSE_NOTICES.values() or not reference.get("cna_provider"):
                raise BulletinError("bulletin_cve_notice_required")
        elif "license_notice" in reference or "cna_provider" in reference:
            raise BulletinError("bulletin_source_notice_unexpected")
        profile = registry.get(reference["source_id"])
        rights = profile.source["rights"]
        if (
            not profile.is_public_output_approved
            or not profile.source["kill_switch"]
            or date.fromisoformat(rights["review_due_on"]) < now.date()
            or not registry.permits_publication_revision(
                reference["source_id"], reference["rights_revision"]
            )
            or reference["attribution"] != rights["attribution_text"]
        ):
            raise BulletinError("bulletin_rights_not_current")
        allowed = set()
        prohibited = set()
        for rule in profile.field_rules:
            if rule["public_output"].startswith(("allowed", "normalized_fact")):
                allowed.update(rule["fields"])
            else:
                prohibited.update(rule["fields"])
        used = set(reference["used_fields"])
        if not used <= allowed or used & prohibited:
            raise BulletinError("bulletin_source_fields_not_approved")
        try:
            parsed = urlsplit(reference["record_url"])
            port = parsed.port
        except ValueError as error:
            raise BulletinError("bulletin_source_url") from error
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or port is not None
            or parsed.query
            or parsed.hostname not in profile.source["allowed_hosts"]
            or any(c.isspace() for c in reference["record_url"])
        ):
            raise BulletinError("bulletin_source_url")
        manual_paths = MANUAL_SOURCE_PATHS.get(reference["source_id"].removeprefix("gbsec:source:"))
        if manual_paths is not None and not re.fullmatch(
            manual_paths.get(parsed.hostname, r"(?!)"), parsed.path
        ):
            raise BulletinError("bulletin_source_url")
        if reference["source_id"] in {
            FEED_SOURCES["php"],
            "gbsec:source:php-reviewed-security-facts",
        }:
            source_url("php", reference["record_url"])
        elif parsed.fragment:
            raise BulletinError("bulletin_source_fragment")
        if reference["source_id"] == CVE_SOURCE:
            match = re.fullmatch(
                r"/CVEProject/cvelistV5/blob/(?:main|[a-f0-9]{40})/cves/"
                r"([0-9]{4})/([0-9]+)xxx/(CVE-([0-9]{4})-([0-9]{4,19}))\.json",
                parsed.path,
            )
            if (
                parsed.hostname != "github.com"
                or match is None
                or match[1] != match[4]
                or match[2] != match[5][:-3]
                or match[3] not in document["aliases"]
            ):
                raise BulletinError("bulletin_cve_source_identity")
        if reference["source_id"] == FEED_SOURCES["node"] and not re.fullmatch(
            r"/en/blog/vulnerability/[a-z0-9-]+/?", parsed.path
        ):
            raise BulletinError("bulletin_source_url")
        if reference[
            "source_id"
        ] == "gbsec:source:maintainer-security-advisories" and not re.fullmatch(
            r"/(?:advisories|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/security/advisories)"
            r"/GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}"
            r"-[23456789cfghjmpqrvwx]{4}",
            parsed.path,
        ):
            raise BulletinError("bulletin_source_url")
    if document["record_url"] != document["sources"][0]["record_url"]:
        raise BulletinError("bulletin_primary_source")


def authorize(document, grant, registry, *, now, manual_approval=None, accepted_input=None):
    require_aware_utc(now)
    validate_grant(grant)
    if now < datetime.fromisoformat(grant["effective_at"].replace("Z", "+00:00")):
        raise BulletinError("bulletin_grant_not_effective")
    if grant["mode"] == "paused":
        raise BulletinError("bulletin_publication_paused")
    if now >= datetime.fromisoformat(grant["review_due_at"].replace("Z", "+00:00")):
        raise BulletinError("bulletin_capacity_review_due")
    publication_rights(document, registry, now=now)
    if manual_approval is not None:
        if not isinstance(manual_approval, str) or not re.fullmatch(
            r"[a-f0-9]{64}", manual_approval
        ):
            raise BulletinError("bulletin_manual_approval_invalid")
        return "manual_preview" if grant["mode"] == "manual_preview" else "reviewed"
    source = document["source_key"]
    if (
        grant["mode"] != "automatic"
        or source not in grant["source_keys"]
        or document["evidence_class"] == "emerging_report"
        or document["verification"] != "publisher_endpoint_tls"
        or (source not in SOURCE_IDS and len(document["sources"]) != 1)
        or document["sources"][0]["source_id"] != FEED_SOURCES.get(source)
    ):
        raise BulletinError("bulletin_manual_review_required")
    if accepted_input is None:
        raise BulletinError("bulletin_accepted_input_required")
    if source == "kev":
        from smithguard.bulletin_kev import project_kev

        expected = project_kev(accepted_input, registry, now=now)
    elif source in SOURCE_IDS:
        from smithguard.bulletin_facts import project_facts

        expected = project_facts(accepted_input, registry, now=now)
    else:
        expected = project_notice(accepted_input, registry, now=now)
    if not same_publication_content(document, expected, registry):
        raise BulletinError("bulletin_projection_mismatch")
    return "automatic"
