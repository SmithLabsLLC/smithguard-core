"""The PHP factual profile is manual-only and binds a real dated archive permalink."""

from copy import deepcopy
from datetime import UTC, datetime

import pytest

from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_policy import authorize, publication_rights
from smithguard.official_notice_parser import NoticeError
from smithguard.source_rights import SourceRightsError

from .test_bulletins import GRANT, REGISTRY, content

NOW = datetime(2026, 10, 23, 18, tzinfo=UTC)
SOURCE = "gbsec:source:php-reviewed-security-facts"


def php_document():
    doc = content()
    doc["record_url"] = "https://www.php.net/archive/2026.php#2026-10-23-1"
    doc["sources"] = [
        {
            "source_id": SOURCE,
            "record_url": doc["record_url"],
            "source_evidence_hash": "sha256:" + "c" * 64,
            "rights_revision": 1,
            "attribution": "The PHP Group",
            "used_fields": [
                "url",
                "published_at",
                "advisory_ids",
                "prerequisites",
                "remediation_guidance",
            ],
        }
    ]
    return doc


def test_php_factual_profile_requires_manual_approval_and_preserves_feed_scope():
    doc = php_document()
    publication_rights(doc, REGISTRY, now=NOW)
    assert authorize(doc, GRANT, REGISTRY, now=NOW, manual_approval="1" * 64) == "manual_preview"
    with pytest.raises(BulletinError, match="manual_review_required"):
        authorize(doc, {**GRANT, "mode": "automatic"}, REGISTRY, now=NOW)
    with pytest.raises(SourceRightsError, match="not a Phase 1 path"):
        REGISTRY.get(SOURCE).authorize_gateway_dispatch(today=NOW.date())
    feed_doc = deepcopy(doc)
    feed_doc["sources"][0]["source_id"] = "gbsec:source:php-security-notices"
    with pytest.raises(BulletinError, match="source_fields_not_approved"):
        publication_rights(feed_doc, REGISTRY, now=NOW)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.php.net/archive/2026.php",
        "https://www.php.net/archive/2026.php#other",
        "https://www.php.net/archive/2026.php#2025-10-23-1",
        "https://www.php.net/archive/2026.php#2026-02-30-1",
        "https://www.php.net/archive/2026.php?redirect=elsewhere#2026-10-23-1",
        "https://www.php.net/archive/2026.php/other#2026-10-23-1",
        "https://www.php.net/archive/%32%30%32%36.php#2026-10-23-1",
        "https://php.net/archive/2026.php#2026-10-23-1",
        "https://www.php.net:443/archive/2026.php#2026-10-23-1",
    ],
)
def test_php_factual_profile_rejects_ambiguous_or_foreign_permalink(url):
    doc = php_document()
    doc["record_url"] = doc["sources"][0]["record_url"] = url
    with pytest.raises((BulletinError, NoticeError)):
        publication_rights(doc, REGISTRY, now=NOW)


def test_php_factual_profile_refuses_article_fields_and_expired_rights():
    doc = php_document()
    doc["sources"][0]["used_fields"].append("article_body")
    with pytest.raises(BulletinError, match="source_fields_not_approved"):
        publication_rights(doc, REGISTRY, now=NOW)
    with pytest.raises(BulletinError, match="rights_not_current"):
        publication_rights(php_document(), REGISTRY, now=datetime(2026, 11, 6, tzinfo=UTC))
