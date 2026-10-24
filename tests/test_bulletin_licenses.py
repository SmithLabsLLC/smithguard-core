"""CVE publication carries its required license on machine and syndication copies."""

from copy import deepcopy
from xml.etree.ElementTree import fromstring

import pytest
from sqlalchemy.orm import Session

from smithguard import bulletin_store as store
from smithguard.bulletin_api import ATOM, atom_feed
from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_licenses import CVE_LICENSE_NOTICE, CVE_SOURCE
from smithguard.bulletin_policy import publication_rights
from tests.test_bulletins import GRANT, NOW, REGISTRY, content


def cve_content():
    document = content()
    url = (
        "https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/1000xxx/CVE-2026-1000000.json"
    )
    document["record_url"] = url
    document["aliases"] = ["CVE-2026-1000000"]
    document["sources"] = [
        {
            "source_id": CVE_SOURCE,
            "record_url": url,
            "source_evidence_hash": "sha256:" + "b" * 64,
            "rights_revision": 1,
            "attribution": "CVE Program and MITRE",
            "used_fields": ["containers"],
            "license_notice": CVE_LICENSE_NOTICE,
            "cna_provider": {
                "organization_id": "11111111-1111-4111-8111-111111111111",
                "short_name": "Synthetic CNA",
            },
        }
    ]
    return document


@pytest.mark.parametrize("mutation", ["absent", "truncated", "provider_missing", "other_source"])
def test_missing_or_misbound_cve_notice_cannot_publish(mutation):
    document = cve_content()
    source = document["sources"][0]
    if mutation == "absent":
        del source["license_notice"]
    elif mutation == "truncated":
        source["license_notice"] = "Copyright MITRE"
    elif mutation == "provider_missing":
        del source["cna_provider"]
    else:
        source["source_id"] = "gbsec:source:github-advisory-database"
    with pytest.raises(BulletinError, match="notice"):
        publication_rights(document, REGISTRY, now=NOW)


def test_cve_license_survives_public_json_history_and_atom(database):
    document = cve_content()
    publication_rights(document, REGISTRY, now=NOW)
    with Session(database.engine) as session, session.begin():
        result = store.publish(
            session, document, grant=GRANT, registry=REGISTRY, now=NOW, manual_approval="a" * 64
        )
        identity = result["bulletin_id"]
        public = store.detail(session, identity, now=NOW)
        assert public["content"]["sources"] == document["sources"]
        old = deepcopy(public)
        page = {
            "items": [
                {
                    "bulletin_id": identity,
                    "sequence": 1,
                    "kind": "published",
                    "occurred_at": "2026-10-21T12:00:00Z",
                }
            ],
            "next_cursor": "synthetic",
        }
        atom = fromstring(atom_feed(session, page, now=NOW, query={}))
        assert atom.find(f"{{{ATOM}}}entry/{{{ATOM}}}rights").text == CVE_LICENSE_NOTICE
        assert store.detail(session, identity, now=NOW)["content_hash"] == old["content_hash"]


@pytest.mark.parametrize("change", ["notice", "provider", "identity"])
def test_renewed_cve_rights_keep_notice_provider_and_exact_identity_checks(change):
    from smithguard.source_rights import RightsRegistry
    from tests.test_source_rights import renewed_register

    registry = RightsRegistry(renewed_register(CVE_SOURCE))
    document = cve_content()
    publication_rights(document, registry, now=NOW)
    if change == "notice":
        del document["sources"][0]["license_notice"]
    elif change == "provider":
        del document["sources"][0]["cna_provider"]
    else:
        document["aliases"] = ["CVE-2026-1000001"]
    with pytest.raises(BulletinError, match="cve"):
        publication_rights(document, registry, now=NOW)
