"""Exact publisher/path pairs for individually reviewed factual bulletins.

These are citation boundaries, not new network collectors or article licenses.
"""

MANUAL_SOURCE_PATHS = {
    "zdi-linux-security-reports": {
        "www.zerodayinitiative.com": r"/advisories/upcoming/",
        "lists.openwall.net": r"/linux-kernel/2026/10/21/(?:2666|2694|2711)",
    },
    "linux-kernel-maintainer-facts": {
        "lists.openwall.net": r"/linux-kernel/2026/10/(?:21/2732|22/(?:297|1149)|23/(?:739|971))",
        "github.com": r"/torvalds/linux/commit/68f410faedaf6ee74d81e574733c50ebcc1bd8ed",
    },
    "aws-security-facts": {
        "aws.amazon.com": (
            r"/(?:blogs/security/[a-z0-9-]+|security/security-bulletins/[0-9]{4}-[0-9]+-aws)/"
        ),
    },
    "gitlab-security-releases": {
        "docs.gitlab.com": r"/releases/patches/patch-release-gitlab-[0-9]+-[0-9]+-[0-9]+-released/",
    },
    "litellm-security-incidents": {
        "docs.litellm.ai": r"/blog/security-incident-[a-z0-9-]+",
    },
    "railway-security-incidents": {
        "blog.railway.com": r"/p/security-disclosure-[a-z0-9-]+",
    },
    "ubuntu-security-notices": {
        "ubuntu.com": r"/security/notices/USN-[0-9]+-[0-9]+",
    },
    "siteguard-security-advisories": {
        "www.eg-secure.co.jp": r"/siteguard/news/alert-[0-9]{6}-[0-9]+",
    },
    "plex-security-advisories": {
        "forums.plex.tv": r"/t/important-security-update-for-plex-media-server-[a-z0-9-]+/[0-9]+",
    },
    "siemens-security-advisories": {
        "productcert.siemens.com": r"/productcert/html/ssa-[0-9]+\.html",
    },
    "beyondtrust-security-advisories": {
        "www.beyondtrust.com": r"/trust-center/security-advisories/bt[0-9]{2}-[0-9]+",
    },
    "fortinet-security-advisories": {
        "fortiguard.fortinet.com": r"/psirt/FG-IR-[0-9]{2}-[0-9]+",
    },
    "atlassian-security-advisories": {
        "confluence.atlassian.com": r"/security/cve-[0-9]{4}-[0-9]+-[a-z0-9-]+\.html",
    },
    "ahsay-security-advisories": {
        "www.ahsay.com": r"/en/company/announcements/patch-cve-[a-z0-9-]+",
    },
    "cisco-security-advisories": {
        "sec.cloudapps.cisco.com": (
            r"/security/center/content/CiscoSecurityAdvisory/cisco-sa-[A-Za-z0-9-]+"
        ),
    },
    "paloalto-security-advisories": {
        "security.paloaltonetworks.com": r"/CVE-[0-9]{4}-[0-9]+",
        "unit42.paloaltonetworks.com": r"/active-exploitation-of-pan-os-cve-[0-9]{4}-[0-9]+/",
    },
    "ivanti-security-advisories": {
        "www.ivanti.com": r"/blog/[a-z]+-[0-9]{4}-patch-tuesday",
        "hub.ivanti.com": r"/s/article/Security-Advisory-[A-Za-z0-9-]+",
    },
    "microsoft-security-advisories": {
        "msrc.microsoft.com": r"/update-guide/(?:en-US/)?vulnerability/CVE-[0-9]{4}-[0-9]+",
    },
    "cisa-reviewed-security-facts": {
        "raw.githubusercontent.com": (
            r"/cisagov/kev-data/main/known_exploited_vulnerabilities\.json"
        ),
        "www.cisa.gov": r"/known-exploited-vulnerabilities-catalog",
    },
}
