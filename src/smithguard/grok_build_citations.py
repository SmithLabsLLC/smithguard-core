"""Fetched public provenance, with structured first-party proof for X posts."""

from __future__ import annotations

import json
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from smithguard.discovery import X_HOSTS, canonical_public_url, citation_key


def _x_host(host: str | None) -> bool:
    return (host or "").removeprefix("www.").removeprefix("mobile.").removeprefix("m.") in X_HOSTS


class _PostMarkup(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.post = False
        self.paragraph = False
        self.text: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "blockquote" and "twitter-tweet" in (attrs.get("class") or "").split():
            self.post = True
        elif self.post and tag == "p":
            self.paragraph = True
        elif self.post and tag == "a" and isinstance(attrs.get("href"), str):
            self.links.append(attrs["href"])

    def handle_endtag(self, tag):
        if tag == "p":
            self.paragraph = False
        elif tag == "blockquote":
            self.post = False

    def handle_data(self, data):
        if self.post and self.paragraph:
            self.text.append(data)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate public embed field")
        result[key] = value
    return result


def _has_post_link(links: list[str], key: str) -> bool:
    for link in links:
        try:
            if citation_key(link) == key:
                return True
        except ValueError:
            # Post markup can contain unrelated HTTP, relative or malformed links.
            # None proves a citation, but none invalidates a separate exact match.
            continue
    return False


def fetched_citations(requested: str, content: dict) -> list[str]:
    try:
        final = canonical_public_url(content["url"])
    except (KeyError, TypeError, ValueError):
        return []
    initial, resolved = urlsplit(requested), urlsplit(final)
    # HTTP200 from an X SPA/login shell does not prove the requested post exists.
    if _x_host(initial.hostname) or _x_host(resolved.hostname):
        return []
    if initial.hostname != "publish.x.com" and resolved.hostname != "publish.x.com":
        return [requested, final]
    if initial.hostname != "publish.x.com" or final != requested or initial.path != "/oembed":
        return []
    try:
        query = parse_qs(initial.query, strict_parsing=True, max_num_fields=3)
        if (
            set(query) != {"url", "omit_script"}
            or query["omit_script"] != ["true"]
            or len(query["url"]) != 1
        ):
            return []
        target = canonical_public_url(query["url"][0])
        key = citation_key(target)
        if not key.startswith("x-status:"):
            return []
        data = json.loads(content["content"], object_pairs_hook=_unique)
        if (
            not isinstance(data, dict)
            or data.get("type") != "rich"
            or data.get("version") != "1.0"
            or data.get("provider_url") not in {"https://x.com", "https://twitter.com"}
        ):
            return []
        post = canonical_public_url(data["url"])
        if citation_key(post) != key or not isinstance(data.get("html"), str):
            return []
        markup = _PostMarkup()
        markup.feed(data["html"])
        if not "".join(markup.text).strip() or not _has_post_link(markup.links, key):
            return []
        # This URL comes from X's structured post response, matched to the exact
        # requested post and nonempty post markup, not a link in arbitrary prose.
        return [post]
    except (KeyError, TypeError, ValueError, RecursionError):
        return []
