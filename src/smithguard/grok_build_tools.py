"""Translate approved search boundaries into the pinned native agent profile."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from typing import Any


def search_profile(payload: Mapping[str, Any], *, qualification: bool) -> dict:
    tools = payload.get("tools")
    if not isinstance(tools, list) or (qualification and tools):
        raise ValueError("native tool contract invalid")
    allowed: list[str] = []
    overrides = {}
    restricted_web = False
    for tool in tools:
        if not isinstance(tool, dict) or tool.get("type") in allowed:
            raise ValueError("native search contract invalid")
        kind = tool.get("type")
        if kind == "x_search":
            # Build 1.0.41 supports dates, but not handle allowlists. Refuse before
            # inference so the already-authorized paid fallback preserves that filter.
            if set(tool) != {"type", "from_date", "to_date"}:
                raise ValueError("native X filter unsupported")
            start, end = tool["from_date"], tool["to_date"]
            if (
                date.fromisoformat(start).isoformat() != start
                or date.fromisoformat(end).isoformat() != end
                or start > end
            ):
                raise ValueError("native X date boundary invalid")
            overrides["xSearch"] = {"dateBound": {"fromDate": start, "toDate": end}}
        elif kind == "web_search":
            if set(tool) not in ({"type"}, {"type", "filters"}):
                raise ValueError("native web filter unsupported")
            if "filters" in tool:
                filters = tool["filters"]
                if not isinstance(filters, dict) or set(filters) != {"allowed_domains"}:
                    raise ValueError("native web filter unsupported")
                domains = filters["allowed_domains"]
                if (
                    not isinstance(domains, list)
                    or not 1 <= len(domains) <= 5
                    or any(not isinstance(d, str) or not d or "/" in d for d in domains)
                ):
                    raise ValueError("native web filter invalid")
                overrides["webSearch"] = {"allowedDomains": domains}
                restricted_web = True
        else:
            raise ValueError("native tool unsupported")
        allowed.append(kind)
    if not qualification and not allowed:
        raise ValueError("native discovery requires search")
    if not qualification and not restricted_web:
        allowed.append("web_fetch")
    # Empty native allowlists inherit every tool; use an explicitly denied sentinel.
    return {
        "name": "smithguard-public-check",
        "description": "Bounded public software advisory check",
        "discoverSkills": False,
        "inheritSkills": False,
        "agentsMd": False,
        # Hosted x_search is not a local registry tool. Its presence in an author
        # allowlist triggers Build's unresolved-name fallback. Start with an exact
        # minimal registry so that fallback cannot expose shell/file/action tools.
        "injectDefaultTools": False,
        # Build rejects an empty curated registry before applying disallowedTools.
        # Seed only fetch, then remove it for qualification and restricted searches.
        "toolConfig": {"tools": [{"id": "GrokBuild:web_fetch"}]},
        "tools": allowed or ["web_search"],
        "disallowedTools": [t for t in ("web_search", "x_search", "web_fetch") if t not in allowed],
        "toolOverrides": overrides,
    }
