"""Bounded Linux metadata discovery. No imports, hooks, package code or network."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from email import policy
from email.parser import BytesParser
from pathlib import PurePath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .verification import canonical

MAX_ENTRIES = 5000
MAX_METADATA_BYTES = 128 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_RELATIONSHIPS = 10000
MAX_MEMBERSHIPS = 10000
POLICY_VERSION = "public-coordinate-consent-v1"
NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


def open_directory(path: str) -> int:
    """Walk every component by descriptor, refusing symlinks including ancestors."""
    parts = PurePath(path).parts
    if not parts or parts[0] != "/" or ".." in parts:
        raise ValueError("select an absolute directory without parent traversal")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_regular(directory: int, name: str, limit: int) -> bytes:
    if "/" in name or name in {".", ".."}:
        raise ValueError("one file component required")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("metadata is not a bounded regular file")
        chunks = bytearray()
        while len(chunks) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > limit:
            raise ValueError("metadata byte limit exceeded")
        return bytes(chunks)
    finally:
        os.close(fd)


def artifact(name: str, version: str) -> dict[str, Any]:
    if not NAME.fullmatch(name) or len(name) > 300 or len(version) > 200:
        raise ValueError("invalid public Python coordinate")
    parsed = Version(version)
    if parsed.local is not None:
        raise ValueError("local version has ambiguous public provenance")
    return {
        "ecosystem": "pypi",
        "registry_host": "pypi.org",
        "name": canonicalize_name(name),
        "version": str(parsed),
        "digest": None,
        "public_visibility": "asserted_public",
    }


def coordinate_id(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _metadata(scope: str, parent: int, entry: str, remaining: int) -> dict[str, Any]:
    result = {
        "installation_id": hashlib.sha256((scope + "\0" + entry).encode()).hexdigest(),
        "scope": scope,
        "metadata_directory": entry,
        "activity": "unknown",
        "identity_assurance": "unverified_local_metadata",
        "status": "skipped",
        "reason": "unreadable_metadata",
        "requires_dist": [],
        "metadata_sha256": None,
        "coordinate": None,
        "parent_application": "unassigned/uncertain",
    }
    if remaining <= 0:
        result["reason"] = "metadata_byte_budget_exhausted"
        return result
    fd = None
    try:
        fd = os.open(entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        # Any direct/local/editable provenance is ambiguous, including a malformed
        # or symlinked marker. Do not follow/read private origin URLs at all.
        try:
            os.stat("direct_url.json", dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            result["reason"] = "direct_or_editable_origin"
            return result
        raw = read_regular(fd, "METADATA", min(MAX_METADATA_BYTES, remaining))
        result["metadata_bytes"] = len(raw)
        result["metadata_sha256"] = hashlib.sha256(raw).hexdigest()
        metadata = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
        names = metadata.get_all("Name", [])
        versions = metadata.get_all("Version", [])
        requirements = metadata.get_all("Requires-Dist", [])
        if metadata.defects or len(names) != 1 or len(versions) != 1 or len(requirements) > 1000:
            result["reason"] = "ambiguous_metadata"
            return result
        result["coordinate"] = artifact(str(names[0]), str(versions[0]))
        result["requires_dist"] = [str(x) for x in requirements]
        result["status"] = "discovered"
        result["reason"] = "public_disclosure_not_authorized"
    except OSError, ValueError, InvalidVersion, UnicodeError:
        result["reason"] = "unreadable_or_unsupported_metadata"
    finally:
        if fd is not None:
            os.close(fd)
    return result


def discover(
    scopes: list[str],
    *,
    approved_public: list[dict[str, Any]],
    application_roots: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Preview only. approved_public is an owner's explicit public identity assertion.

    It is not network consent or installed-artifact verification. Exact coordinates
    absent from this allowlist cannot become requests. No registry probe occurs.
    """
    scopes = [str(PurePath(scope)) for scope in scopes]
    roots = {}
    for scope, names in (application_roots or {}).items():
        normalized = str(PurePath(scope))
        if normalized not in scopes or normalized in roots:
            raise ValueError("application roots must name distinct selected scopes")
        if not isinstance(names, list) or any(
            not isinstance(name, str) or not NAME.fullmatch(name) or len(name) > 300
            for name in names
        ):
            raise ValueError("application roots require bounded package names")
        roots[normalized] = list(dict.fromkeys(names))
    application_roots = roots
    if sum(len(names) for names in roots.values()) > 100:
        raise ValueError("at most 100 explicit application roots")
    if not 1 <= len(scopes) <= 32 or len(scopes) != len(set(scopes)):
        raise ValueError("select 1..32 distinct site-packages directories")
    allow = {}
    for value in approved_public:
        normalized = artifact(value["name"], value["version"])
        if normalized != value:
            raise ValueError("public allowlist must contain exact normalized PyPI coordinates")
        allow[coordinate_id(value)] = value
    if len(allow) > MAX_ENTRIES:
        raise ValueError("public allowlist limit exceeded")
    installations = []
    gaps = []
    used = 0
    count = 0
    for scope_index, scope in enumerate(scopes):
        fd = None
        try:
            fd = open_directory(scope)
            with os.scandir(fd) as entries:
                for entry in entries:
                    count += 1
                    if count > MAX_ENTRIES:
                        gaps.append({"scope": scope, "reason": "directory_entry_limit"})
                        break
                    if entry.name.endswith(".dist-info"):
                        item = _metadata(scope, fd, entry.name, max(0, MAX_TOTAL_BYTES - used))
                        used += item.get("metadata_bytes", 0)
                        coord = item["coordinate"]
                        if coord is not None and coordinate_id(coord) in allow:
                            item["status"] = "eligible_for_preview"
                            item["reason"] = "owner_asserted_public_identity_weak"
                        elif coord is not None:
                            # A local metadata name is not a public-identity assertion.
                            # Only the explicit allowlist produces service coordinates.
                            coord["public_visibility"] = "not_asserted_public"
                        installations.append(item)
                    elif entry.name.endswith((".egg-info", ".egg-link", ".pth")):
                        gaps.append(
                            {
                                "scope": scope,
                                "entry": entry.name,
                                "reason": "unsupported_metadata_or_path_hook_not_executed",
                            }
                        )
        except OSError, ValueError:
            gaps.append({"scope": scope, "reason": "directory_unreadable_or_linked"})
        finally:
            if fd is not None:
                os.close(fd)
        if count > MAX_ENTRIES:
            gaps.extend(
                {"scope": later, "reason": "not_scanned_directory_entry_limit"}
                for later in scopes[scope_index + 1 :]
            )
            break
    installations.sort(key=lambda x: x["installation_id"])
    coordinates = {
        coordinate_id(x["coordinate"]): x["coordinate"]
        for x in installations
        if x["status"] == "eligible_for_preview"
    }
    graph = relationships(installations, application_roots or {})
    for item in installations:
        memberships = {entry["root"] for entry in item.get("application_memberships", [])}
        if len(memberships) == 1:
            item["parent_application"] = next(iter(memberships))
    for scope, names in roots.items():
        for name in names:
            matches = [
                item
                for item in installations
                if item["scope"] == scope
                and item["coordinate"] is not None
                and item["coordinate"]["name"] == canonicalize_name(name)
            ]
            if len(matches) != 1:
                gaps.append(
                    {
                        "scope": scope,
                        "application": name,
                        "reason": "application_root_missing_or_ambiguous",
                    }
                )
    if any(x["state"] == "relationship_limit" for x in graph):
        gaps.append({"reason": "relationship_limit"})
    preview = {
        "schema_version": "1.0.0",
        "policy_version": POLICY_VERSION,
        "scopes": scopes,
        "installations": sorted(installations, key=lambda x: x["installation_id"]),
        "gaps": sorted(gaps, key=canonical),
        "discovery_complete": not gaps and all(x["status"] != "skipped" for x in installations),
        "coordinates": [coordinates[k] for k in sorted(coordinates)],
        "relationships": sorted(graph, key=canonical),
        "application_roots": application_roots or {},
        "disclosure": (
            "Only these public coordinates and protocol metadata lea"
            "ve; the service sees your IP, timing and coordinate set"
            ". Paths, relationships and local facts stay local."
        ),
    }
    preview["approval_sha256"] = hashlib.sha256(canonical(preview)).hexdigest()
    return preview


def relationships(
    installations: list[dict[str, Any]], roots: dict[str, list[str]]
) -> list[dict[str, Any]]:
    """Record metadata edges without evaluating markers against the scanning host."""
    edges = []
    by_name = {}
    by_id = {x["installation_id"]: x for x in installations}
    for item in installations:
        if item["coordinate"] is not None:
            by_name.setdefault((item["scope"], item["coordinate"]["name"]), []).append(item)
    for item in installations:
        for raw in item["requires_dist"]:
            if len(edges) >= MAX_RELATIONSHIPS:
                edges.append(
                    {
                        "parent": item["installation_id"],
                        "child": None,
                        "state": "relationship_limit",
                    }
                )
                return edges
            try:
                requirement = Requirement(raw)
            except InvalidRequirement:
                edges.append(
                    {
                        "parent": item["installation_id"],
                        "child": None,
                        "evidence": raw,
                        "state": "invalid_requirement",
                    }
                )
                continue
            candidates = by_name.get((item["scope"], canonicalize_name(requirement.name)), [])
            state = "metadata_dependency"
            if requirement.url or requirement.marker is not None or requirement.extras:
                state = "conditional_or_origin_uncertain"
            elif len(candidates) != 1:
                state = "missing_or_ambiguous_installation"
            elif not requirement.specifier.contains(
                candidates[0]["coordinate"]["version"], prereleases=True
            ):
                state = "installed_version_outside_requirement"
            edges.append(
                {
                    "parent": item["installation_id"],
                    "child": candidates[0]["installation_id"] if len(candidates) == 1 else None,
                    "evidence": raw,
                    "state": state,
                }
            )
    # Root membership is explicit owner input. Walk only unambiguous unconditional
    # metadata edges. This shows declared dependency relationships, not actual use.
    adjacency = {}
    for edge in edges:
        if edge["state"] == "metadata_dependency":
            adjacency.setdefault(edge["parent"], []).append(edge)
    if sum(len(names) for names in roots.values()) > 100:
        raise ValueError("at most 100 explicit application roots")
    memberships = 0
    for scope, names in roots.items():
        for name in names:
            root = by_name.get((scope, canonicalize_name(name)), [])
            if len(root) != 1:
                continue
            if memberships >= MAX_MEMBERSHIPS:
                edges.append(
                    {
                        "parent": root[0]["installation_id"],
                        "child": None,
                        "state": "relationship_limit",
                    }
                )
                return edges
            memberships += 1
            root[0].setdefault("application_memberships", []).append(
                {"root": root[0]["installation_id"], "relation": "root"}
            )
            pending = [(root[0]["installation_id"], 0)]
            seen = set()
            queued = {root[0]["installation_id"]}
            while pending:
                parent, depth = pending.pop(0)
                if parent in seen:
                    continue
                seen.add(parent)
                for edge in adjacency.get(parent, []):
                    child = by_id[edge["child"]]
                    if child["installation_id"] in queued:
                        continue
                    queued.add(child["installation_id"])
                    if memberships >= MAX_MEMBERSHIPS:
                        edges.append(
                            {"parent": parent, "child": None, "state": "relationship_limit"}
                        )
                        return edges
                    memberships += 1
                    child.setdefault("application_memberships", []).append(
                        {
                            "root": root[0]["installation_id"],
                            "relation": "direct" if depth == 0 else "transitive",
                        }
                    )
                    pending.append((child["installation_id"], depth + 1))
    return edges
