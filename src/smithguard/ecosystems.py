"""The one ecosystem vocabulary.

The canonical member strings are frozen: they are embedded in the generated contract
schemas (whose digests are pinned), in the PostgreSQL CHECK constraints and in migration
0020. Adding or renaming a member is a contract change, never a refactor.
"""

from __future__ import annotations

from types import MappingProxyType

CANONICAL_ECOSYSTEMS: tuple[str, ...] = (
    "npm",
    "pypi",
    "github-actions",
    "oci",
    "docker",
    "go",
    "rust",
    "composer",
    "erlang",
    "git",
    "maven",
    "nuget",
    "open-vsx",
    "pub",
    "rubygems",
    "swift",
    "vscode",
)
# The seven ecosystems the threat-search discovery lane and the malware authority policy
# cover; the policy JSON is asserted equal to this set at load time.
THREAT_SEARCH_ECOSYSTEMS: frozenset[str] = frozenset(
    {"npm", "pypi", "github-actions", "oci", "docker", "go", "rust"}
)
# purl types for the ecosystems whose package names are kept verbatim by normalization.
PURL_TYPE_BY_ECOSYSTEM = MappingProxyType(
    {
        "composer": "composer",
        "erlang": "hex",
        "git": "generic",
        "go": "golang",
        "maven": "maven",
        "nuget": "nuget",
        "open-vsx": "vscode",
        "pub": "pub",
        "rubygems": "gem",
        "rust": "cargo",
        "swift": "swift",
        "vscode": "vscode",
    }
)
REGISTRY_HOSTS_BY_ECOSYSTEM = MappingProxyType(
    {
        "npm": frozenset({"registry.npmjs.org"}),
        "pypi": frozenset({"pypi.org"}),
        "github-actions": frozenset({"github.com"}),
        "oci": frozenset({"docker.io", "ghcr.io", "public.ecr.aws", "quay.io"}),
        "docker": frozenset({"docker.io", "ghcr.io", "public.ecr.aws", "quay.io"}),
        "go": frozenset({"proxy.golang.org"}),
        "rust": frozenset({"crates.io"}),
        "composer": frozenset({"repo.packagist.org"}),
        "erlang": frozenset({"hex.pm"}),
        "git": frozenset({"github.com"}),
        "maven": frozenset({"repo1.maven.org"}),
        "nuget": frozenset({"api.nuget.org"}),
        "open-vsx": frozenset({"open-vsx.org"}),
        "pub": frozenset({"pub.dev"}),
        "rubygems": frozenset({"rubygems.org"}),
        "swift": frozenset({"swiftpackageindex.com"}),
        "vscode": frozenset({"marketplace.visualstudio.com"}),
    }
)
