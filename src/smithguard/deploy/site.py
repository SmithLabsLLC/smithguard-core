"""Closed, manifest-bound product assets inside an immutable runtime release."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from smithguard.identifiers import (
    INGEST_JSON_MAX_DEPTH,
    INGEST_JSON_MAX_NODES,
    SHA1_HEX,
    DuplicateJsonKeyError,
    strict_json_loads,
)

PROVENANCE_PATH = "SITE-PROVENANCE.json"
MANIFEST_PATH = "site/artifact-manifest.json"
CONTRACT_PATH = "site/agents/smithguard-openapi.json"
WHEEL_CONTRACT_PATH = "smithguard/generated_artifacts/openapi-public-beta.json"
MAX_SITE_FILES = 128
MAX_SITE_MEMBER_BYTES = 4 * 1024 * 1024
MAX_SITE_BYTES = 16 * 1024 * 1024
COMMIT = SHA1_HEX
PUBLIC_PATHS = frozenset(
    {
        ".well-known/security.txt",
        "404.html",
        "_headers",
        "_redirects",
        "agents/index.html",
        "agents/index.json",
        "agents/smithguard-openapi.json",
        "assets/bulletins.js",
        "apple-touch-icon.png",
        "artifact-manifest.json",
        "favicon.ico",
        "icon-192.png",
        "icon-512.png",
        "index.html",
        "llms.txt",
        "llms-full.txt",
        "privacy/index.html",
        "robots.txt",
        "security.txt",
        "site.webmanifest",
        "sitemap.xml",
        "terms/index.html",
        "threats/index.html",
        "trust/index.html",
    }
)
OPTIONAL_PATHS = frozenset(
    {
        "_headers",
        "_redirects",
        "security.txt",
        "llms-full.txt",
        "assets/bulletins.js",
        "threats/index.html",
    }
)
REQUIRED_PATHS = frozenset(f"site/{path}" for path in PUBLIC_PATHS - OPTIONAL_PATHS)
ASSET_SUFFIXES = frozenset({".css", ".svg", ".png", ".ico", ".otf", ".woff2", ".txt"})


class SiteError(ValueError):
    """The product payload is incomplete, unbounded, or inconsistent."""


def allowed_site_path(path: str) -> bool:
    if path == PROVENANCE_PATH:
        return True
    if not path.startswith("site/") or not path.isascii() or "\\" in path:
        return False
    relative = path.removeprefix("site/")
    parts = PurePosixPath(relative).parts
    if not relative or PurePosixPath(relative).as_posix() != relative:
        return False
    if relative in PUBLIC_PATHS:
        return True
    return (
        relative.startswith("assets/")
        and len(parts) <= 5
        and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", part) for part in parts)
        and PurePosixPath(relative).suffix in ASSET_SUFFIXES
    )


def _document(body: bytes) -> Mapping[str, Any]:
    try:
        # Site metadata comes from another repository; the bound is sized well above
        # MAX_SITE_MEMBER_BYTES so a size problem is reported as one, not as bad JSON.
        value = strict_json_loads(
            body, max_nodes=INGEST_JSON_MAX_NODES, max_depth=INGEST_JSON_MAX_DEPTH
        )
    except (UnicodeDecodeError, RecursionError) as error:
        raise SiteError("product metadata is not valid JSON") from error
    except DuplicateJsonKeyError as error:
        raise SiteError("product JSON contains duplicate keys") from error
    except ValueError as error:
        if getattr(error, "reason", None) in {"too_many_nodes", "too_deep"}:
            raise SiteError("product metadata exceeds its bounded shape") from error
        raise SiteError("product metadata is not valid JSON") from error
    if not isinstance(value, Mapping):
        raise SiteError("product metadata must be an object")
    return value


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def verify_site_files(files: Mapping[str, bytes], *, contract_bytes: bytes) -> None:
    """Accept legacy absence or a complete product; never accept partial presence."""
    selected = {
        path: body
        for path, body in files.items()
        if path.startswith("site/") or path == PROVENANCE_PATH
    }
    if not selected:
        return
    if not REQUIRED_PATHS.union({PROVENANCE_PATH}).issubset(selected):
        raise SiteError("product payload is missing required files")
    if len(selected) > MAX_SITE_FILES or sum(map(len, selected.values())) > MAX_SITE_BYTES:
        raise SiteError("product payload exceeds its size or file limit")
    if any(
        not allowed_site_path(path) or len(body) > MAX_SITE_MEMBER_BYTES
        for path, body in selected.items()
    ):
        raise SiteError("product payload contains an unsafe or oversized member")
    provenance = _document(selected[PROVENANCE_PATH])
    if (
        set(provenance)
        != {
            "schema_version",
            "source_repository",
            "source_commit",
            "build_entrypoint",
            "build_profile",
            "artifact_manifest_sha256",
            "contract_sha256",
        }
        or provenance.get("schema_version") != "1.0.0"
        or provenance.get("source_repository") != "SmithLabsLLC/smithlabs_website"
        or not isinstance(provenance.get("source_commit"), str)
        or COMMIT.fullmatch(provenance["source_commit"]) is None
        or provenance.get("build_entrypoint") != "src/build.mjs"
        or provenance.get("build_profile") != "product"
        or provenance.get("artifact_manifest_sha256") != _digest(selected[MANIFEST_PATH])
        or provenance.get("contract_sha256") != _digest(contract_bytes)
        or selected[CONTRACT_PATH] != contract_bytes
    ):
        raise SiteError("product source or API-contract provenance differs")
    manifest = _document(selected[MANIFEST_PATH])
    if (
        set(manifest) != {"schema_version", "as_of", "profile", "canonical_url", "files"}
        or manifest.get("schema_version") != "1.1.0"
        or manifest.get("profile") != "product"
        or manifest.get("canonical_url") != "https://smithguard.io"
        or not isinstance(manifest.get("as_of"), str)
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", manifest["as_of"]) is None
        or not isinstance(manifest.get("files"), Mapping)
    ):
        raise SiteError("product manifest identity is invalid")
    expected = manifest["files"]
    if {f"site/{path}" for path in expected} != set(selected) - {MANIFEST_PATH, PROVENANCE_PATH}:
        raise SiteError("product manifest and payload file sets differ")
    for path, entry in expected.items():
        body = selected[f"site/{path}"]
        if (
            not isinstance(entry, Mapping)
            or set(entry) != {"sha256", "size"}
            or type(entry.get("size")) is not int
            or entry["size"] != len(body)
            or entry.get("sha256") != _digest(body)
        ):
            raise SiteError("product file differs from its manifest")
    machine = _document(selected["site/agents/index.json"])
    product = machine.get("product")
    snapshot = machine.get("reviewed_contract_snapshot")
    if (
        machine.get("schema_version") != "1.1.0"
        or not isinstance(product, Mapping)
        or product.get("name") != "SmithGuard"
        or product.get("website_url") != "https://smithguard.io/"
        or not isinstance(snapshot, Mapping)
        or snapshot.get("sha256") != _digest(contract_bytes)
    ):
        raise SiteError("product machine index disagrees with its identity or contract")


def installed_site_files(release: Path) -> dict[str, bytes]:
    """Read only a bounded regular-file tree; reject links before reading content."""
    release_owner = release.stat().st_uid
    pending = [release / "site", release / PROVENANCE_PATH]
    paths: list[Path] = []
    directories: set[str] = set()
    total = 0
    while pending:
        path = pending.pop()
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        relative = path.relative_to(release).as_posix()
        if metadata.st_uid != release_owner:
            raise SiteError("installed product owner differs from its release")
        if stat.S_ISDIR(metadata.st_mode):
            if relative != "site" and (
                not relative.startswith("site/") or len(path.relative_to(release).parts) > 5
            ):
                raise SiteError("installed product directory is invalid")
            if stat.S_IMODE(metadata.st_mode) != 0o755:
                raise SiteError("installed product directory mode differs")
            directories.add(relative)
            if len(directories) > MAX_SITE_FILES:
                raise SiteError("installed product directory limit exceeded")
            with os.scandir(path) as children:
                for child in children:
                    if len(pending) + len(paths) + len(directories) >= MAX_SITE_FILES * 2:
                        raise SiteError("installed product entry limit exceeded")
                    pending.append(Path(child.path))
        elif stat.S_ISREG(metadata.st_mode) and allowed_site_path(relative):
            if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o644:
                raise SiteError("installed product file is linked or has an invalid mode")
            paths.append(path)
            total += metadata.st_size
            if (
                len(paths) > MAX_SITE_FILES
                or total > MAX_SITE_BYTES
                or metadata.st_size > MAX_SITE_MEMBER_BYTES
            ):
                raise SiteError("installed product size or file limit exceeded")
        else:
            raise SiteError("installed product contains a link or unsafe member")
    expected_directories = set()
    for path in paths:
        parent = path.relative_to(release).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    if directories != expected_directories:
        raise SiteError("installed product has an unmanifested empty directory")
    result = {}
    for path in paths:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise SiteError("installed product file type changed")
            body = stream.read(MAX_SITE_MEMBER_BYTES + 1)
        if len(body) > MAX_SITE_MEMBER_BYTES:
            raise SiteError("installed product file grew beyond its byte limit")
        result[path.relative_to(release).as_posix()] = body
    if sum(map(len, result.values())) > MAX_SITE_BYTES:
        raise SiteError("installed product grew beyond its total byte limit")
    return result
