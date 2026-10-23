"""Bounded, source-specific parsing into facts, never copied advisory prose."""

from __future__ import annotations

import re
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_sources import NETWORK_SOURCES
from smithguard.identifiers import canonical_json_bytes, sha256_id, timestamp
from smithguard.official_notice_parser import ATOM, BoundedTree, html_text, instant

CVE = re.compile(r"\bCVE-[12][0-9]{3}-[0-9]{4,19}\b", re.I)
LEVELS = frozenset({"low", "moderate", "medium", "high", "critical", "unknown"})
PARSER_VERSION = "official-facts-v1"


def safe_text(value, maximum=200):
    value = " ".join(value.split())
    if (
        not value
        or len(value) > maximum
        or any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value)
    ):
        raise BulletinError("bulletin_source_text")
    return value


@dataclass(frozen=True)
class SourceCandidate:
    source: str
    url: str
    published: datetime
    modified: datetime | None
    facts: dict
    needs_detail: bool = False

    @property
    def record_key(self):
        return sha256_id(self.url.encode())[7:]

    def document(self):
        return {
            "source": self.source,
            "url": self.url,
            "published_at": timestamp(self.published),
            "modified_at": timestamp(self.modified) if self.modified else None,
            "facts": self.facts,
            "needs_detail": self.needs_detail,
        }


@dataclass
class Element:
    tag: str
    attrs: dict = field(default_factory=dict)
    children: list = field(default_factory=list)

    def walk(self):
        yield self
        for child in self.children:
            if isinstance(child, Element):
                yield from child.walk()

    def text(self):
        return " ".join(
            value.text() if isinstance(value, Element) else value for value in self.children
        ).strip()


class FactHTML(HTMLParser):
    """No scripts, resources, entity resolution, browser, or arbitrary attributes."""

    VOID = frozenset(
        {
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        }
    )
    HIDDEN = frozenset({"script", "style", "template"})

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Element("root")
        self.stack = [self.root]
        self.nodes = 0
        self.hidden = []

    def handle_starttag(self, tag, attrs):
        self.nodes += 1
        if self.nodes > 100_000 or len(self.stack) > 64:
            raise BulletinError("bulletin_html_structure")
        if self.hidden:
            if tag in self.HIDDEN:
                self.hidden.append(tag)
            return
        if tag in self.HIDDEN:
            self.hidden.append(tag)
            return
        attrs = [
            (k, v)
            for k, v in attrs
            if k != "content"
            or dict(attrs).get("property", dict(attrs).get("name"))
            in {"og:url", "date", "article:published_time", "article:modified_time"}
        ]
        attributes = {
            k: (v or "")
            for k, v in attrs
            if k in {"class", "id", "href", "datetime", "rel", "name", "property", "content"}
        }
        if any(len(v) > 4096 for v in attributes.values()):
            raise BulletinError("bulletin_html_attribute")
        node = Element(tag, attributes)
        self.stack[-1].children.append(node)
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if self.hidden:
            if tag == self.hidden[-1]:
                self.hidden.pop()
            return
        for position in range(len(self.stack) - 1, 0, -1):
            if self.stack[position].tag == tag:
                del self.stack[position:]
                break

    def handle_data(self, value):
        if not self.hidden and value.strip():
            self.stack[-1].children.append(value)


def parse_html(body, *, maximum):
    if not isinstance(body, bytes) or not 0 < len(body) <= maximum:
        raise BulletinError("bulletin_source_bytes")
    try:
        value = body.decode("utf-8-sig")
    except UnicodeError as error:
        raise BulletinError("bulletin_source_encoding") from error
    if "<!ENTITY" in value.upper():
        raise BulletinError("bulletin_html_entity")
    parser = FactHTML()
    parser.feed(value)
    parser.close()
    return parser.root


def day(value, *, now):
    try:
        parsed = datetime.strptime(" ".join(value.split()), "%B %d, %Y").replace(tzinfo=UTC)
    except ValueError as error:
        raise BulletinError("bulletin_source_day") from error
    if parsed > now:
        raise BulletinError("bulletin_source_future")
    return parsed


def basic_facts(
    *,
    record_id,
    aliases=(),
    body_hash,
    precision="exact",
    severity="unknown",
    subjects=(),
    fixed=(),
):
    return {
        "record_id": safe_text(record_id, 160),
        "aliases": sorted(set(aliases)),
        "severity": severity,
        "subjects": sorted(set(subjects)),
        "fixed_versions": sorted(set(fixed)),
        "withdrawn": False,
        "time_precision": precision,
        "body_hash": body_hash,
        "parser": PARSER_VERSION,
    }


def mozilla_index(body, *, now, earliest=None):
    spec = NETWORK_SOURCES["mozilla-mfsa"]
    root = parse_html(body, maximum=spec.maximum_bytes)
    mains = [n for n in root.walk() if n.tag == "main"]
    if len(mains) != 1:
        raise BulletinError("mozilla_index_shape")
    published = None
    rows = []
    for node in mains[0].walk():
        if node.tag == "h2" and re.fullmatch(
            r"[A-Z][a-z]+ [0-9]{1,2}, [12][0-9]{3}", node.text().strip()
        ):
            published = day(node.text(), now=now)
        if node.tag != "a":
            continue
        path = node.attrs.get("href", "")
        if not re.fullmatch(spec.record_path, path):
            continue
        if published is None:
            raise BulletinError("mozilla_index_date")
        if earliest is not None and published < earliest:
            continue
        url = spec.record_url(urljoin(spec.endpoint, path))
        identity = "MFSA-" + path.rstrip("/").rsplit("/", 1)[-1][4:]
        levels = [
            n
            for n in node.walk()
            if n.tag == "span" and "level" in n.attrs.get("class", "").split()
        ]
        if len(levels) != 1:
            raise BulletinError("mozilla_index_impact")
        classes = set(levels[0].attrs.get("class", "").split())
        # Older MFSA entries used severe for the high-impact category.
        values = classes & LEVELS
        if not values and "severe" in classes:
            values = {"high"}
        if len(values) != 1:
            raise BulletinError("mozilla_index_impact")
        facts = basic_facts(
            record_id=identity,
            aliases=[identity],
            severity=values.pop(),
            precision="day",
            body_hash=sha256_id(" ".join(node.text().split()).encode()),
        )
        rows.append(SourceCandidate(spec.key, url, published, None, facts, True))
    return unique(rows)


def mozilla_detail(candidate, body, *, now):
    spec = NETWORK_SOURCES[candidate.source]
    root = parse_html(body, maximum=spec.detail_bytes)
    articles = [n for n in root.walk() if n.tag == "article"]
    if len(articles) != 1:
        raise BulletinError("mozilla_detail_shape")
    article = articles[0]
    headings = [n for n in article.walk() if n.tag == "h1"]
    expected = "Mozilla Foundation Security Advisory " + candidate.facts["record_id"][5:]
    if len(headings) != 1 or " ".join(headings[0].text().split()) != expected:
        raise BulletinError("mozilla_detail_identity")
    summaries = [
        n for n in article.walk() if n.tag == "dl" and "summary" in n.attrs.get("class", "").split()
    ]
    if not summaries:
        raise BulletinError("mozilla_detail_summary")
    pairs, key = {}, None
    for node in summaries[0].children:
        if not isinstance(node, Element):
            continue
        if node.tag == "dt":
            key = safe_text(node.text())
            if key in pairs:
                raise BulletinError("mozilla_detail_duplicate_field")
        elif node.tag == "dd" and key:
            pairs[key] = node
            key = None
    if not {"Announced", "Impact", "Products", "Fixed in"} <= pairs.keys():
        raise BulletinError("mozilla_detail_fields")
    published = day(pairs["Announced"].text(), now=now)
    severity = safe_text(pairs["Impact"].text()).lower()
    if severity not in LEVELS:
        raise BulletinError("mozilla_detail_conflict")
    products = [safe_text(p, 120) for p in pairs["Products"].text().split(",")]
    fixed = [safe_text(n.text(), 200) for n in pairs["Fixed in"].walk() if n.tag == "li"]
    aliases = [candidate.facts["record_id"]]
    for n in article.walk():
        if n.tag == "h4" and CVE.fullmatch(n.attrs.get("id", "")):
            aliases.append(n.attrs["id"].upper())
    if not fixed or len(fixed) > 16 or len(products) > 16 or len(aliases) > 100:
        raise BulletinError("mozilla_detail_budget")
    facts = basic_facts(
        record_id=candidate.facts["record_id"],
        aliases=aliases,
        body_hash=sha256_id(" ".join(article.text().split()).encode()),
        precision="day",
        severity=severity,
        subjects=products,
        fixed=fixed,
    )
    facts["index_hash"] = candidate.facts.get("index_hash", candidate.facts["body_hash"])
    if published != candidate.published:
        facts["conditions"] = [
            "The publisher index date differs from the announcement date; "
            "the detail page announcement date is shown."
        ]
    return SourceCandidate(candidate.source, candidate.url, published, None, facts)


def unique(rows):
    identities = {}
    for row in rows:
        previous = identities.get(row.url)
        if previous is not None and previous != row:
            raise BulletinError("bulletin_duplicate_source_identity")
        identities[row.url] = row
    if not identities or len(identities) > 10_000:
        raise BulletinError("bulletin_feed_shape")
    return tuple(identities.values())


def feed(source, body, *, now):
    spec = NETWORK_SOURCES[source]
    if not isinstance(body, bytes) or not 0 < len(body) <= spec.maximum_bytes:
        raise BulletinError("bulletin_source_bytes")
    try:
        value = body.decode("utf-8-sig")
        if "<!DOCTYPE" in value.upper() or "<!ENTITY" in value.upper():
            raise BulletinError("bulletin_xml_declaration")
        root = ET.fromstring(value, parser=ET.XMLParser(target=BoundedTree()))  # noqa: S314 - UTF-8 only; DTD/entities refused; bounded tree target
    except (UnicodeError, ET.ParseError) as error:
        raise BulletinError("bulletin_feed_parse") from error
    atom = spec.format == "atom"
    if root.tag != (ATOM + "feed" if atom else "rss"):
        raise BulletinError("bulletin_feed_shape")
    entries = root.findall(ATOM + "entry") if atom else root.findall("./channel/item")
    if not 1 <= len(entries) <= 10_000:
        raise BulletinError("bulletin_feed_shape")
    rows = []
    for entry in entries:

        def one(name, *, required=True, entry=entry):
            matches = entry.findall((ATOM if atom else "") + name)
            if not matches and not required:
                return None
            if len(matches) != 1 or not matches[0].text:
                raise BulletinError("bulletin_feed_field")
            return matches[0].text.strip()

        url = one("id" if atom else "link")
        # The publisher's ZDI feed still advertises HTTP links. Only an exact
        # same-publisher advisory path is upgraded; no redirects are followed.
        if source == "zdi-published" and url.startswith(
            "http://www.zerodayinitiative.com/advisories/"
        ):
            url = "https://" + url[len("http://") :]
        if source == "node-releases" and not re.fullmatch(spec.record_path, urlsplit(url).path):
            continue
        if source == "cisco-advisories":
            canonical = one("guid")
            spec.record_url(canonical)
            if url.split("?", 1)[0] != canonical:
                raise BulletinError("bulletin_feed_identity")
            url = canonical
        if source == "aws-bulletins" and re.fullmatch(
            r"https://aws\.amazon\.com/security/security-bulletins/rss/[0-9]{4}-[0-9]{1,6}-aws/",
            url,
        ):
            # Feed-relative links insert /rss/; the official index and canonical
            # detail metadata bind this exact same-publisher path normalization.
            url = url.replace("/security/security-bulletins/rss/", "/security/security-bulletins/")
        spec.record_url(url)
        raw_date = one("published" if atom else "pubDate")
        precision = "exact"
        if source == "cisco-advisories":
            # Cisco omits the zone. Preserve its calendar day, not an invented instant.
            if not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.0", raw_date
            ):
                raise BulletinError("cisco_feed_date")
            published = datetime.fromisoformat(raw_date[:10]).replace(tzinfo=UTC)
            precision = "day"
        else:
            published = instant(raw_date, rss=not atom)
        raw_modified = one("updated", required=False) if atom else None
        modified = instant(raw_modified) if raw_modified else None
        if published > now or modified and modified > now:
            raise BulletinError("bulletin_source_future")
        title = one("title")
        raw_context = one("content" if atom else "description", required=False) or ""
        context = html_text(raw_context)
        if source == "gitlab-releases" and not re.search(
            r"\b(security|vulnerabilit\w*)\b", context, re.I
        ):
            continue
        record_id = url.rstrip("/").rsplit("/", 1)[-1]
        if len(record_id) > 160:
            record_id = source + "-" + published.strftime("%Y%m%d")
        aliases = sorted({m.upper() for m in CVE.findall(title + " " + context)})
        if source == "zdi-published":
            guid = one("guid", required=False)
            if guid and re.fullmatch(r"ZDI-CAN-[0-9]{1,12}", guid):
                aliases.append(guid)
        if re.fullmatch(
            r"(?:USN-[0-9]+-[0-9]+|ZDI-[0-9]{2}-[0-9]+|FG-IR-[0-9]{2}-[0-9]+)", record_id
        ):
            aliases.append(record_id)
        if len(aliases) > 100:
            raise BulletinError("bulletin_alias_budget")
        # Keep only a content commitment, not headlines/body or personal fields.
        digest = sha256_id(canonical_json_bytes([title, context]))
        facts = basic_facts(
            record_id=record_id, aliases=aliases, body_hash=digest, precision=precision
        )
        if source == "node-releases":
            facts["subjects"] = ["Node.js"]
        elif source == "gitlab-releases":
            facts["subjects"] = ["GitLab"]
        rows.append(SourceCandidate(source, url, published, modified, facts, True))
    return unique(rows)


def parse_index(source, body, *, now):
    if source == "mozilla-mfsa":
        return mozilla_index(body, now=now)
    if source in {"apple-releases", "paloalto-advisories"}:
        return structured_index(source, body, now=now)
    return feed(source, body, now=now)


def publisher_detail(candidate, body, *, now):
    """Recheck a retained publisher URL independently of finite feed membership."""
    if candidate.source == "mozilla-mfsa":
        return mozilla_detail(candidate, body, now=now)
    source = candidate.source
    spec = NETWORK_SOURCES[source]
    if source == "cisco-advisories":
        # The observed Cisco template mixes UTF-8 with lone Windows NBSP bytes.
        # Normalize precisely that whitespace byte; any other bad encoding fails.
        decoded = body.decode("utf-8", errors="surrogateescape")
        body = decoded.replace("\udca0", "\xa0").encode("utf-8")
    root = parse_html(body, maximum=spec.detail_bytes)
    canonicals = [
        n.attrs.get("href", "").strip()
        for n in root.walk()
        if n.tag == "link" and n.attrs.get("rel") == "canonical"
    ]
    canonicals += [
        n.attrs.get("content", "").strip()
        for n in root.walk()
        if n.tag == "meta" and n.attrs.get("property", n.attrs.get("name")) == "og:url"
    ]
    if source not in {"zdi-published", "paloalto-advisories"} and (
        not canonicals or set(canonicals) != {candidate.url}
    ):
        raise BulletinError("bulletin_detail_identity")
    if source in {"apple-releases", "paloalto-advisories"}:
        regions = [n for n in root.walk() if n.attrs.get("id") == "content"]
    elif source == "gitlab-releases":
        regions = [n for n in root.walk() if "docs-content" in n.attrs.get("class", "").split()]
    elif source == "cisco-advisories":
        regions = [n for n in root.walk() if n.attrs.get("id") == "advisorycontentcontainer"]
    else:
        regions = [
            n for n in root.walk() if n.tag == ("article" if source == "zdi-published" else "main")
        ]
    if len(regions) != 1:
        raise BulletinError("bulletin_detail_shape")
    region = regions[0]
    if source == "zdi-published" and not re.search(
        r"\b" + re.escape(candidate.facts["record_id"]) + r"\b", region.text()
    ):
        raise BulletinError("bulletin_detail_identity")
    facts = basic_facts(
        record_id=candidate.facts["record_id"],
        aliases=sorted({v.upper() for v in CVE.findall(region.text())}),
        body_hash=sha256_id(" ".join(region.text().split()).encode()),
        precision=candidate.facts["time_precision"],
    )
    if re.fullmatch(
        r"(?:USN-[0-9]+-[0-9]+|ZDI-[0-9]{2}-[0-9]+|FG-IR-[0-9]{2}-[0-9]+)",
        candidate.facts["record_id"],
    ):
        facts["aliases"].append(candidate.facts["record_id"])
    if source == "zdi-published":
        facts["aliases"] += sorted(set(re.findall(r"\bZDI-CAN-[0-9]{1,12}\b", region.text())))
    facts["index_hash"] = candidate.facts.get("index_hash", candidate.facts["body_hash"])
    modified = candidate.modified
    if source == "ubuntu-usn":
        headers = [n.text() for n in region.walk() if n.tag == "h1"]
        if len(headers) != 1 or not headers[0].startswith(candidate.facts["record_id"] + ":"):
            raise BulletinError("ubuntu_detail_identity")
        tables = [
            n
            for n in region.walk()
            if n.tag == "table" and "cve-table" in n.attrs.get("class", "").split()
        ]
        fixed, subjects, release, omitted = [], set(), None, 0
        for table in tables:
            for row in [n for n in table.walk() if n.tag == "tr"]:
                cells = [
                    n for n in row.children if isinstance(n, Element) and n.tag in {"th", "td"}
                ]
                if (
                    cells
                    and cells[0].tag == "th"
                    and re.match(r"[0-9]{2}\.[0-9]{2}", cells[0].text().strip())
                ):
                    release = safe_text(cells[0].text(), 80)
                for cell in [n for n in cells if n.tag == "td"]:
                    match = re.fullmatch(
                        r"([a-z0-9+.-]+)\s+\u2013\s+([0-9A-Za-z.+:~_-]+)",
                        " ".join(cell.text().split()),
                    )
                    if match and release:
                        if len(fixed) < 8:
                            subjects.add("Ubuntu " + release)
                            fixed.append(safe_text(f"Ubuntu {release}: {match[1]} {match[2]}", 200))
                        else:
                            omitted += 1
        facts.update(
            subjects=sorted(subjects) or ["Ubuntu"], fixed_versions=fixed, omissions=omitted
        )
    elif source == "node-releases":
        facts["subjects"] = ["Node.js"]
        downloads = False
        fixed = set()
        for node in region.walk():
            if node.tag in {"h1", "h2"}:
                downloads = node.attrs.get("id") == "downloads-and-release-details"
            if downloads and node.tag == "a":
                match = re.fullmatch(
                    r"(?:https://nodejs\.org)?/en/blog/release/(v[0-9]+\.[0-9]+\.[0-9]+)/?",
                    node.attrs.get("href", ""),
                )
                if match:
                    fixed.add("Node.js " + match[1])
        facts["fixed_versions"] = sorted(fixed)[:8]
    elif source == "gitlab-releases":
        headers = [n.text() for n in region.walk() if n.tag == "h1"]
        if len(headers) != 1 or "Patch Release" not in headers[0]:
            raise BulletinError("gitlab_detail_identity")
        product = "GitLab AI Gateway" if "AI Gateway" in headers[0] else "GitLab"
        facts["subjects"] = [product]
        facts["fixed_versions"] = [
            product + " " + v
            for v in sorted(set(re.findall(r"\b[0-9]+\.[0-9]+\.[0-9]+\b", headers[0])))[:8]
        ]
    elif source == "fortinet-advisories":
        tables = [
            n
            for n in region.walk()
            if n.tag == "table" and "meta" in n.attrs.get("class", "").split()
        ]
        meta = {}
        for table in tables:
            for row in [n for n in table.walk() if n.tag == "tr"]:
                cells = [n.text() for n in row.children if isinstance(n, Element) and n.tag == "td"]
                if len(cells) == 2:
                    meta[" ".join(cells[0].split())] = " ".join(cells[1].split())
        if meta.get("IR Number") != candidate.facts["record_id"]:
            raise BulletinError("fortinet_detail_identity")
        severity = meta.get("Severity", "unknown").lower()
        if severity not in LEVELS:
            raise BulletinError("fortinet_detail_severity")
        facts["severity"] = severity
        if meta.get("Updated Date"):
            modified = datetime.strptime(meta["Updated Date"], "%b %d, %Y").replace(tzinfo=UTC)
            if modified > now:
                raise BulletinError("bulletin_source_future")
            facts["time_precision"] = "day"
    if source == "apple-releases":
        facts["subjects"] = ["Apple"]
        facts["fixed_versions"] = candidate.facts["fixed_versions"]
        facts["aliases"].append(candidate.facts["record_id"])
    elif source == "paloalto-advisories":
        headers = [n.text() for n in region.walk() if n.tag == "h2"]
        if not headers or not headers[0].startswith(candidate.facts["record_id"] + " "):
            raise BulletinError("paloalto_detail_identity")
        facts["subjects"] = ["Palo Alto Networks"]
    elif source == "aws-bulletins":
        facts["subjects"] = ["AWS"]
    facts["aliases"] = sorted(set(facts["aliases"]))
    if len(facts["aliases"]) > 100:
        identity = candidate.facts["record_id"]
        others = [value for value in facts["aliases"] if value != identity]
        retained = [identity] + others[:99]
        facts["alias_omissions"] = len(set(facts["aliases"]) - set(retained))
        facts["aliases"] = sorted(retained)
    return SourceCandidate(source, candidate.url, candidate.published, modified, facts)


def structured_index(source, body, *, now):
    """Publisher tables with explicit dates, IDs and product names."""
    spec = NETWORK_SOURCES[source]
    root = parse_html(body, maximum=spec.maximum_bytes)
    rows = []
    for row in [n for n in root.walk() if n.tag == "tr"]:
        cells = [n for n in row.children if isinstance(n, Element) and n.tag == "td"]
        if not cells:
            continue
        if source == "apple-releases":
            if len(cells) != 3:
                raise BulletinError("apple_index_shape")
            links = [
                n
                for n in cells[0].walk()
                if n.tag == "a"
                and re.fullmatch(
                    r"https://support\.apple\.com/en-us/[0-9]{6}", n.attrs.get("href", "")
                )
            ]
            if not links:
                continue  # Apple explicitly lists some releases without a CVE page.
            published = datetime.strptime(" ".join(cells[2].text().split()), "%d %b %Y").replace(
                tzinfo=UTC
            )
            if published > now:
                raise BulletinError("bulletin_source_future")
            if published < now - timedelta(days=90):
                continue
            for link in links:
                url = spec.record_url(link.attrs["href"])
                product = safe_text(link.text(), 200)
                record_id = "APPLE-" + url.rsplit("/", 1)[-1]
                facts = basic_facts(
                    record_id=record_id,
                    aliases=[record_id],
                    precision="day",
                    subjects=["Apple"],
                    fixed=[product],
                    body_hash=sha256_id(canonical_json_bytes([url, product, timestamp(published)])),
                )
                rows.append(SourceCandidate(source, url, published, None, facts, True))
        else:
            if len(cells) != 7:
                raise BulletinError("paloalto_index_shape")
            links = [
                n
                for n in cells[1].walk()
                if n.tag == "a"
                and re.fullmatch(r"/(?:CVE|PAN-SA)-[0-9]{4}-[0-9]{4,19}", n.attrs.get("href", ""))
            ]
            if len(links) != 1:
                raise BulletinError("paloalto_index_identity")
            url = spec.record_url(urljoin(spec.endpoint, links[0].attrs["href"]))
            published, modified = [
                datetime.strptime(" ".join(c.text().split()), "%Y-%m-%d").replace(tzinfo=UTC)
                for c in cells[-2:]
            ]
            if max(published, modified) > now:
                raise BulletinError("bulletin_source_future")
            record_id = url.rsplit("/", 1)[-1]
            facts = basic_facts(
                record_id=record_id,
                aliases=[record_id],
                precision="day",
                body_hash=sha256_id(" ".join(row.text().split()).encode()),
            )
            rows.append(SourceCandidate(source, url, published, modified, facts, True))
    return unique(rows)
