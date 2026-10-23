"""Complete bounded official XML parsing without the legacy recent-only cutoff.

Streaming bounds structural memory; the existing strict per-entry validator keeps
publisher URL, timestamp and text rules identical to the original intake.
"""

from dataclasses import replace
from io import StringIO
from xml.etree import ElementTree as ET

from smithguard.identifiers import require_aware_utc
from smithguard.official_notice_parser import (
    ATOM,
    SOURCES,
    TOMBSTONE,
    NoticeError,
    instant,
    one_text,
    parse_feed,
)

ENTRY_LIMITS = {"php": 8192, "mozilla": 2048}


def parse_complete(
    source, body, *, now, known_urls=frozenset(), earliest_unseen=None, diagnostics=None
):
    if earliest_unseen is not None:
        require_aware_utc(earliest_unseen)
        if earliest_unseen > now:
            raise NoticeError("checkpoint_time_invalid")
    if source not in ENTRY_LIMITS or now.tzinfo is None or now.utcoffset() is None:
        raise NoticeError("source_or_clock_invalid")
    if not isinstance(body, bytes) or not 0 < len(body) <= SOURCES[source][1]:
        raise NoticeError("feed_bytes_budget")
    try:
        raw = body.decode("utf-8-sig")
    except UnicodeError as error:
        raise NoticeError("feed_parse_failed") from error
    if "<!DOCTYPE" in raw.upper() or "<!ENTITY" in raw.upper():
        raise NoticeError("xml_declaration_forbidden")
    counts = {
        "feed_entries": 0,
        "entry_limit": ENTRY_LIMITS[source],
        "nodes": 0,
        "max_depth": 0,
        "excluded_non_security_entries": 0,
        "identical_duplicates": 0,
        "excluded_before_checkpoint": 0,
        "oldest_published_at": None,
        "newest_published_at": None,
    }
    stack, seen = [], {}
    channels = 0
    try:
        # DTD/entities are refused before iterparse; bytes/depth/nodes bound input.
        for action, node in ET.iterparse(StringIO(raw), events=("start", "end")):  # noqa: S314 - declarations refused; structural and byte limits enforced
            if action == "start":
                stack.append(node)
                counts["nodes"] += 1
                counts["max_depth"] = max(counts["max_depth"], len(stack))
                if counts["nodes"] > 100_000 or len(stack) > 32:
                    raise NoticeError("xml_structure_budget")
                if len(stack) == 1 and node.tag != (ATOM + "feed" if source == "php" else "rss"):
                    raise NoticeError("feed_shape_changed")
                if source == "mozilla" and len(stack) == 2 and node.tag == "channel":
                    channels += 1
                continue
            is_entry = (
                source == "php" and len(stack) == 2 and node.tag in {ATOM + "entry", TOMBSTONE}
            ) or (
                source == "mozilla"
                and len(stack) == 3
                and stack[-2].tag == "channel"
                and node.tag == "item"
            )
            if is_entry:
                counts["feed_entries"] += 1
                if counts["feed_entries"] > ENTRY_LIMITS[source]:
                    raise NoticeError("feed_entry_budget")
                if node.tag != TOMBSTONE:
                    published = instant(
                        one_text(node, ATOM + "published" if source == "php" else "pubDate"),
                        rss=source == "mozilla",
                    )
                    value = published.isoformat().replace("+00:00", "Z")
                    counts["oldest_published_at"] = min(
                        counts["oldest_published_at"] or value, value
                    )
                    counts["newest_published_at"] = max(
                        counts["newest_published_at"] or value, value
                    )
                    record_url = one_text(node, ATOM + "id" if source == "php" else "link")
                    if (
                        earliest_unseen is not None
                        and published < earliest_unseen
                        and record_url not in known_urls
                    ):
                        # Examine the complete document, but validate eligible
                        # records against the durable coverage boundary. Ancient
                        # unrelated feed markup is not silently claimed as covered.
                        # Known corrections bypass this exclusion regardless of age.
                        counts["excluded_before_checkpoint"] += 1
                        stack[-2].remove(node)
                        node.clear()
                        stack.pop()
                        continue
                    # Parse every date, including old unseen records; policy selection
                    # happens against the durable complete-through checkpoint later.
                wrapper = ET.Element(ATOM + "feed" if source == "php" else "rss")
                parent = wrapper if source == "php" else ET.SubElement(wrapper, "channel")
                parent.append(node)
                entry_counts = {}
                notices = parse_feed(
                    source,
                    ET.tostring(wrapper, encoding="utf-8"),
                    now=now,
                    known_urls=known_urls,
                    include_old_unknown=True,
                    diagnostics=entry_counts,
                )
                counts["excluded_non_security_entries"] += entry_counts[
                    "excluded_non_security_entries"
                ]
                for notice in notices:
                    previous = seen.get(notice.url)
                    if previous is not None:
                        if previous != replace(notice, entry_sha256=previous.entry_sha256):
                            raise NoticeError("duplicate_notice_identity")
                        counts["identical_duplicates"] += 1
                    else:
                        seen[notice.url] = notice
                stack[-2].remove(node)
                node.clear()
            stack.pop()
        if not counts["feed_entries"] or source == "mozilla" and channels != 1:
            raise NoticeError("feed_shape_changed")
    except ET.ParseError as error:
        raise NoticeError("feed_parse_failed") from error
    if diagnostics is not None:
        diagnostics.update(counts)
    return tuple(seen.values())
