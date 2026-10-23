"""Closed public-source definitions for the ongoing bulletin worker.

Definitions are code-reviewed capabilities, never URLs supplied by feed content or
an agent. Source rights and the active release grant remain independent gates.
"""

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from smithguard.bulletin_contract import BulletinError


@dataclass(frozen=True)
class BulletinSource:
    key: str
    source_id: str
    publisher: str
    endpoint: str
    format: str
    record_host: str
    record_path: str
    maximum_bytes: int = 2 * 1024 * 1024
    detail_bytes: int = 512 * 1024
    scope: str = "Published official security notices"
    discovery_only: bool = False

    def record_url(self, value):
        if not isinstance(value, str) or len(value) > 2048:
            raise BulletinError("bulletin_source_url")
        try:
            parsed = urlsplit(value)
            valid = (
                parsed.scheme == "https"
                and parsed.netloc == self.record_host
                and parsed.port is None
                and parsed.username is None
                and not parsed.query
                and not parsed.fragment
                and re.fullmatch(self.record_path, parsed.path) is not None
                and not any(c.isspace() or ord(c) < 32 for c in value)
            )
        except ValueError as error:
            raise BulletinError("bulletin_source_url") from error
        if not valid:
            raise BulletinError("bulletin_source_url")
        return value


NETWORK_SOURCES = {
    "mozilla-mfsa": BulletinSource(
        "mozilla-mfsa",
        "gbsec:source:mozilla-mfsa",
        "Mozilla",
        "https://www.mozilla.org/en-US/security/advisories/",
        "mozilla",
        "www.mozilla.org",
        r"/en-US/security/advisories/mfsa[12][0-9]{3}-[0-9]{1,4}/",
        maximum_bytes=1024 * 1024,
        scope="Mozilla advisories: Firefox, ESR, Thunderbird and mobile products",
    ),
    "ubuntu-usn": BulletinSource(
        "ubuntu-usn",
        "gbsec:source:ubuntu-usn-feed",
        "Canonical / Ubuntu",
        "https://ubuntu.com/security/notices/rss.xml",
        "rss",
        "ubuntu.com",
        r"/security/notices/USN-[0-9]{1,8}-[0-9]{1,4}",
        scope="Ubuntu Security Notices; applicability remains distribution and package specific",
    ),
    "node-releases": BulletinSource(
        "node-releases",
        "gbsec:source:node-security-feed",
        "The Node.js Project",
        "https://nodejs.org/en/feed/blog.xml",
        "rss",
        "nodejs.org",
        r"/en/blog/vulnerability/[a-zA-Z0-9-]{1,220}/?",
        scope="Security announcements in the official Node.js blog feed",
    ),
    "gitlab-releases": BulletinSource(
        "gitlab-releases",
        "gbsec:source:gitlab-security-feed",
        "GitLab",
        "https://docs.gitlab.com/releases/patch-releases.xml",
        "atom",
        "docs.gitlab.com",
        r"/releases/patches/(?:other-patches/)?[a-z0-9-]{1,220}/",
        maximum_bytes=3 * 1024 * 1024,
        scope="Official GitLab patch releases containing security fixes",
    ),
    "zdi-published": BulletinSource(
        "zdi-published",
        "gbsec:source:zdi-published-feed",
        "Trend Micro Zero Day Initiative",
        "https://www.zerodayinitiative.com/rss/published/",
        "rss",
        "www.zerodayinitiative.com",
        r"/advisories/ZDI-[0-9]{2}-[0-9]{1,8}/",
        scope="Published ZDI advisories; upcoming reports are a separate discovery source",
    ),
    "cisco-advisories": BulletinSource(
        "cisco-advisories",
        "gbsec:source:cisco-security-feed",
        "Cisco",
        "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "rss",
        "sec.cloudapps.cisco.com",
        r"/security/center/content/CiscoSecurityAdvisory/[A-Za-z0-9_-]{1,220}",
        scope="Cisco PSIRT security advisory RSS",
    ),
    "fortinet-advisories": BulletinSource(
        "fortinet-advisories",
        "gbsec:source:fortinet-security-feed",
        "Fortinet",
        "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
        "rss",
        "fortiguard.fortinet.com",
        r"/psirt/FG-IR-[0-9]{2}-[0-9]{1,8}",
        scope="Fortinet PSIRT advisory RSS",
    ),
}
NETWORK_SOURCES.update(
    {
        "aws-bulletins": BulletinSource(
            "aws-bulletins",
            "gbsec:source:aws-bulletin-feed",
            "Amazon Web Services",
            "https://aws.amazon.com/security/security-bulletins/rss/feed/",
            "rss",
            "aws.amazon.com",
            r"/security/security-bulletins/[0-9]{4}-[0-9]{1,6}-aws/",
            detail_bytes=1024 * 1024,
            scope="AWS security bulletins",
        ),
        "apple-releases": BulletinSource(
            "apple-releases",
            "gbsec:source:apple-release-index",
            "Apple",
            "https://support.apple.com/en-us/100100",
            "apple",
            "support.apple.com",
            r"/en-us/[0-9]{6}",
            maximum_bytes=1024 * 1024,
            detail_bytes=1024 * 1024,
            scope="Apple security releases with individual security-content pages",
        ),
        "paloalto-advisories": BulletinSource(
            "paloalto-advisories",
            "gbsec:source:paloalto-advisory-index",
            "Palo Alto Networks",
            "https://security.paloaltonetworks.com/",
            "paloalto",
            "security.paloaltonetworks.com",
            r"/(?:CVE|PAN-SA)-[0-9]{4}-[0-9]{4,19}",
            scope="Palo Alto Networks security advisory index",
        ),
        "zdi-upcoming": BulletinSource(
            "zdi-upcoming",
            "gbsec:source:zdi-upcoming-discovery",
            "Trend Micro Zero Day Initiative",
            "https://www.zerodayinitiative.com/advisories/upcoming/",
            "zdi-discovery",
            "www.zerodayinitiative.com",
            r"/advisories/upcoming/",
            maximum_bytes=4 * 1024 * 1024,
            discovery_only=True,
            scope="ZDI upcoming disclosure reports in the private analyst queue",
        ),
        "oss-security": BulletinSource(
            "oss-security",
            "gbsec:source:oss-security-discovery",
            "Openwall oss-security archive",
            "https://www.openwall.com/lists/oss-security/",
            "mail-discovery",
            "www.openwall.com",
            r"/lists/oss-security/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{1,6}",
            maximum_bytes=2 * 1024 * 1024,
            discovery_only=True,
            scope="Recent public oss-security messages; private analyst queue",
        ),
        "linux-security": BulletinSource(
            "linux-security",
            "gbsec:source:linux-security-discovery",
            "Public Linux kernel archive",
            "https://lists.openwall.net/linux-kernel/",
            "mail-discovery",
            "lists.openwall.net",
            r"/linux-kernel/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{1,6}",
            maximum_bytes=2 * 1024 * 1024,
            discovery_only=True,
            scope="Recent Linux kernel subjects matching security terms; private analyst queue",
        ),
    }
)

CATALOG_SOURCES = {
    "ghsa-bulletin": (
        "gbsec:source:github-advisory-database",
        "GitHub Advisory Database",
        "reviewed",
    ),
    "go-bulletin": ("gbsec:source:go-vulnerability-database", "Go Vulnerability Database", "go"),
    "rustsec-bulletin": (
        "gbsec:source:rustsec-advisory-database",
        "RustSec Advisory Database",
        "rustsec",
    ),
}
SOURCE_IDS = {
    key: value.source_id for key, value in NETWORK_SOURCES.items() if not value.discovery_only
} | {key: value[0] for key, value in CATALOG_SOURCES.items()}

INTAKE_SOURCE_IDS = {key: value.source_id for key, value in NETWORK_SOURCES.items()} | SOURCE_IDS


def fetch_target(source, url=None):
    specification = NETWORK_SOURCES.get(source)
    if specification is None:
        raise BulletinError("bulletin_source_not_network")
    url = url or specification.endpoint
    day_index = specification.format == "mail-discovery" and re.fullmatch(
        re.escape(specification.endpoint) + r"[0-9]{4}/[0-9]{2}/[0-9]{2}/", url
    )
    if url == specification.endpoint or day_index:
        return (
            url,
            specification.maximum_bytes,
            frozenset(
                {
                    "text/html",
                    "application/xml",
                    "text/xml",
                    "application/rss+xml",
                    "application/atom+xml",
                }
            ),
        )
    specification.record_url(url)
    return url, specification.detail_bytes, frozenset({"text/html", "application/xhtml+xml"})


def coverage(source):
    """Public capability descriptions are independent from observed run state."""
    if source in NETWORK_SOURCES:
        spec = NETWORK_SOURCES[source]
        return {
            "publisher": spec.publisher,
            "coverage_mode": "discovery_only" if spec.discovery_only else "automatic_facts",
            "coverage_description": spec.scope,
            "pending_kind": "analyst_review" if spec.discovery_only else "source_processing",
            "active_window_days": None if spec.discovery_only else 90,
        }
    if source in CATALOG_SOURCES:
        description = {
            "ghsa-bulletin": "Reviewed GitHub advisories across 12 ecosystems; omissions disclosed",
            "go-bulletin": "Go advisories from the existing completed catalog",
            "rustsec-bulletin": "RustSec advisories with verified membership and attribution",
        }[source]
        return {
            "publisher": CATALOG_SOURCES[source][1],
            "coverage_mode": "automatic_facts",
            "coverage_description": description,
            "pending_kind": "source_processing",
            "active_window_days": 90,
        }
    return {
        "publisher": {"php": "PHP", "mozilla": "Mozilla security blog", "kev": "CISA KEV"}.get(
            source, source
        ),
        "coverage_mode": "automatic_facts",
        "coverage_description": "Qualified official source updates",
        "pending_kind": "source_processing",
        "active_window_days": None,
    }


# Owner explicitly included every supported source in ongoing free factual output.
QUALIFIED_SOURCE_KEYS = tuple(INTAKE_SOURCE_IDS)
