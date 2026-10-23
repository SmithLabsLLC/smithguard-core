"""Strict parsing of two official feeds; all publisher content stays untrusted data."""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit

ATOM = "{http://www.w3.org/2005/Atom}"
XHTML = "{http://www.w3.org/1999/xhtml}"
CONTENT = "{http://purl.org/rss/1.0/modules/content/}encoded"
TOMBSTONE = "{http://purl.org/atompub/tombstones/1.0}deleted-entry"
SOURCES = {
    "php": ("https://www.php.net/feed.atom", 2 * 1024 * 1024),
    "mozilla": ("https://blog.mozilla.org/security/feed/", 256 * 1024),
}
SECURITY = re.compile(
    r"\b(security|vulnerabilit\w*|compromis\w*|exploit\w*|CVE-\d{4}-\d{4,}|certificate\w*|attack\w*)\b",
    re.I,
)


class NoticeError(ValueError):
    pass


class BoundedTree(ET.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.nodes = 0

    def start(self, tag, attrs):
        self.depth += 1
        self.nodes += 1
        if self.depth > 32 or self.nodes > 100_000:
            raise NoticeError("xml_structure_budget")
        return super().start(tag, attrs)

    def end(self, tag):
        value = super().end(tag)
        self.depth -= 1
        return value


class TextOnly(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, value):
        if not self.hidden:
            self.parts.append(value)


def clean(value, maximum):
    value = " ".join(value.split())
    if not value or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise NoticeError("notice_text_invalid")
    return value


def html_text(value):
    parser = TextOnly()
    parser.feed(value)
    parser.close()
    return " ".join(" ".join(parser.parts).split())


def one_text(node, tag):
    values = node.findall(tag)
    if len(values) != 1 or values[0].text is None:
        raise NoticeError("required_feed_field")
    return values[0].text


def instant(value, rss=False):
    try:
        date = (
            parsedate_to_datetime(value)
            if rss
            else datetime.fromisoformat(value.replace("Z", "+00:00"))
        )
        if date.tzinfo is None or date.utcoffset() is None:
            raise ValueError()
        return date.astimezone(UTC)
    except (ValueError, TypeError, OverflowError) as error:
        raise NoticeError("notice_timestamp_invalid") from error


def source_url(source, value):
    if len(value) > 2048 or any(c.isspace() or ord(c) < 32 for c in value):
        raise NoticeError("notice_url_invalid")
    try:
        parts = urlsplit(value)
        if (
            parts.scheme != "https"
            or parts.username is not None
            or parts.password is not None
            or parts.port is not None
            or parts.query
        ):
            raise ValueError()
        if source == "php":
            match = re.fullmatch(r"/archive/([12][0-9]{3})\.php", parts.path)
            if (
                parts.netloc != "www.php.net"
                or not match
                or not re.fullmatch(match[1] + r"-[0-9]{2}-[0-9]{2}-[0-9]{1,3}", parts.fragment)
            ):
                raise ValueError()
            datetime.strptime(parts.fragment.rsplit("-", 1)[0], "%Y-%m-%d")
        elif source == "mozilla":
            if (
                parts.netloc != "blog.mozilla.org"
                or parts.fragment
                or not re.fullmatch(
                    r"/security/[12][0-9]{3}/[0-9]{2}/[0-9]{2}/[a-z0-9-]{1,200}/", parts.path
                )
            ):
                raise ValueError()
        else:
            raise ValueError()
    except ValueError as error:
        raise NoticeError("notice_url_invalid") from error
    return value


@dataclass(frozen=True)
class Notice:
    source: str
    url: str
    title: str
    context: str
    published: datetime
    modified: datetime | None
    withdrawn: bool
    entry_sha256: str
    content_sha256: str | None = None


def parse_feed(
    source, body, *, now, known_urls=frozenset(), diagnostics=None, include_old_unknown=False
):
    if source not in SOURCES or now.tzinfo is None:
        raise NoticeError("source_or_clock_invalid")
    if not isinstance(body, bytes) or not 0 < len(body) <= SOURCES[source][1]:
        raise NoticeError("feed_bytes_budget")
    try:
        text = body.decode("utf-8-sig")
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise NoticeError("xml_declaration_forbidden")
        # Strict UTF-8 plus the declaration refusal above excludes DTD/entity
        # expansion; the byte, node and depth budgets bound ordinary XML work.
        root = ET.fromstring(  # noqa: S314 - declarations refused before parsing
            text,
            parser=ET.XMLParser(target=BoundedTree()),  # noqa: S314 - bounded tree
        )
    except (UnicodeError, ET.ParseError) as error:
        raise NoticeError("feed_parse_failed") from error
    if source == "php":
        if root.tag != ATOM + "feed":
            raise NoticeError("feed_shape_changed")
        entries = root.findall(ATOM + "entry")
        tombstones = root.findall(TOMBSTONE)
    else:
        if root.tag != "rss" or len(root.findall("channel")) != 1:
            raise NoticeError("feed_shape_changed")
        entries = root.find("channel").findall("item")
        tombstones = []
    if not (entries or tombstones) or len(entries) + len(tombstones) > 1024:
        raise NoticeError("feed_entry_budget")
    counts = {
        "feed_entries": len(entries) + len(tombstones),
        "entry_limit": 1024,
        "excluded_old_unknown_entries": 0,
        "excluded_non_security_entries": 0,
        "identical_duplicates": 0,
        "unknown_publication_cutoff": (now - timedelta(hours=24)).isoformat(),
    }
    result, seen = [], {}
    for entry in entries:
        published = instant(
            one_text(entry, ATOM + "published" if source == "php" else "pubDate"),
            rss=source == "mozilla",
        )
        url = one_text(entry, ATOM + "id" if source == "php" else "link")
        if (
            not include_old_unknown
            and published < now - timedelta(hours=24)
            and url not in known_urls
        ):
            counts["excluded_old_unknown_entries"] += 1
            continue
        if published > now + timedelta(minutes=5):
            raise NoticeError("notice_timestamp_future")
        url = source_url(source, url)
        title = clean(one_text(entry, ATOM + "title" if source == "php" else "title"), 200)
        modified = instant(one_text(entry, ATOM + "updated")) if source == "php" else None
        if modified and (modified < published or modified > now + timedelta(minutes=5)):
            raise NoticeError("notice_modified_invalid")
        encoded = ET.tostring(entry, encoding="utf-8")
        if source == "php":
            content = entry.find(ATOM + "content")
            if (
                content is None
                or content.get("type") != "xhtml"
                or len(content) != 1
                or content[0].tag != XHTML + "div"
            ):
                raise NoticeError("notice_content_changed")

            # Keep adjacent text while excluding executable/style subtrees.
            def visible(node):
                if node.tag not in {XHTML + "script", XHTML + "style"}:
                    if node.text:
                        yield node.text
                    for child in node:
                        yield from visible(child)
                        if child.tail:
                            yield child.tail

            context = " ".join(" ".join(visible(content)).split())
        else:
            context = html_text(one_text(entry, CONTENT))
        if len(context) > 64 * 1024 or not context:
            raise NoticeError("notice_content_budget")
        if not SECURITY.search(title + " " + context) and url not in known_urls:
            counts["excluded_non_security_entries"] += 1
            continue
        notice = Notice(
            source,
            url,
            title,
            context[:1200],
            published,
            modified,
            False,
            hashlib.sha256(encoded).hexdigest(),
            hashlib.sha256(context.encode("utf-8")).hexdigest(),
        )
        if url in seen:
            if seen[url] != replace(notice, entry_sha256=seen[url].entry_sha256):
                raise NoticeError("duplicate_notice_identity")
            counts["identical_duplicates"] += 1
            continue
        seen[url] = notice
        result.append(notice)
    for entry in tombstones:
        url = source_url(source, entry.get("ref", ""))
        if url not in known_urls:
            continue
        modified = instant(entry.get("when", ""))
        if modified > now + timedelta(minutes=5):
            raise NoticeError("notice_timestamp_future")
        if url in seen:
            raise NoticeError("duplicate_notice_identity")
        seen[url] = None
        result.append(
            Notice(
                source,
                url,
                "Publisher withdrawal",
                "The official feed contains an explicit deletion marker.",
                modified,
                modified,
                True,
                hashlib.sha256(ET.tostring(entry, encoding="utf-8")).hexdigest(),
            )
        )
    if diagnostics is not None:
        diagnostics.update(counts)
    return tuple(result)
