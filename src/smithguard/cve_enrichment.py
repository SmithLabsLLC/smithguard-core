"""Bounded exact-CVE EPSS and KEV context; neither source determines affectedness.

FIRST recommends its dated CSV for synchronization (first.org/epss/data.html).
CISA's kev-data repository licenses the dataset under CC0. Fetches additionally
require an active reviewed source profile; parsing alone does not grant rights.
Successful bulk parsing proves transport/framing integrity, not an independently
attested upstream population count. No request is retried or redirected here.
"""

from __future__ import annotations

import math
import re
import zlib
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from hashlib import sha256
from time import monotonic
from urllib.parse import urlencode, urljoin

import httpx

from smithguard.acquisition import AcquisitionRejected, OperationDeadline
from smithguard.identifiers import (
    StrictJsonError,
    TimestampError,
    parse_timestamp,
    require_aware_utc,
    sha256_id,
    strict_json_loads,
)
from smithguard.source_rights import SourceProfile, SourceRightsError

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_BULK_ROOT = "https://epss.empiricalsecurity.com"
EPSS_CURRENT_URL = f"{EPSS_BULK_ROOT}/epss_scores-current.csv.gz"
EPSS_MAX_CURRENT_AGE = timedelta(hours=36)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
_DECIMAL = re.compile(r"[0-9]{1,20}(?:\.[0-9]{1,60})?(?:[eE][+-]?[0-9]{1,3})?\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class CveEnrichmentError(ValueError):
    """A sanitized, stable failure reason; never contains provider payloads."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class EnrichmentLimits:
    max_compressed_bytes: int = 8 * 1024 * 1024
    max_expanded_bytes: int = 64 * 1024 * 1024
    max_rows: int = 1_000_000
    max_selected_cves: int = 200_000
    max_line_bytes: int = 256
    max_elapsed_seconds: float = 60.0

    def __post_init__(self) -> None:
        for value in (
            self.max_compressed_bytes,
            self.max_expanded_bytes,
            self.max_rows,
            self.max_selected_cves,
            self.max_line_bytes,
        ):
            if type(value) is not int or value < 1:
                raise CveEnrichmentError("invalid_limits")
        if (
            isinstance(self.max_elapsed_seconds, bool)
            or not isinstance(self.max_elapsed_seconds, (int, float))
            or not math.isfinite(self.max_elapsed_seconds)
            or self.max_elapsed_seconds <= 0
        ):
            raise CveEnrichmentError("invalid_limits")


DEFAULT_LIMITS = EnrichmentLimits()


@dataclass(frozen=True, slots=True)
class EpssScore:
    cve: str
    epss: str
    percentile: str
    score_date: date
    model_version: str | None = None

    def is_stale(self, *, as_of: datetime, max_age_days: int = 2) -> bool:
        if type(max_age_days) is not int or max_age_days < 0:
            raise CveEnrichmentError("invalid_freshness_limit")
        age = (_observed(as_of).date() - self.score_date).days
        return age < 0 or age > max_age_days


@dataclass(frozen=True, slots=True)
class EpssSnapshot:
    source_url: str
    observed_at: datetime
    response_sha256: str
    requested_cves: tuple[str, ...]
    scores: tuple[EpssScore, ...]
    missing_cves: tuple[str, ...]
    validated_rows: int
    score_date: date | None
    model_version: str | None = None
    score_timestamp: datetime | None = None


@dataclass(frozen=True, slots=True)
class KevEntry:
    cve: str
    date_added: date


@dataclass(frozen=True, slots=True)
class KevSnapshot:
    source_url: str
    observed_at: datetime
    response_sha256: str
    catalog_version: str
    date_released: datetime
    entries: tuple[KevEntry, ...]

    def removed_since(self, previous: KevSnapshot) -> tuple[str, ...]:
        """Removed membership in two complete snapshots, never a safety verdict."""
        if self.observed_at < previous.observed_at or self.date_released < previous.date_released:
            raise CveEnrichmentError("snapshot_time_regression")
        current = {entry.cve for entry in self.entries}
        return tuple(sorted(entry.cve for entry in previous.entries if entry.cve not in current))


def _observed(value: datetime) -> datetime:
    try:
        return require_aware_utc(value)
    except TimestampError as error:
        raise CveEnrichmentError("invalid_observed_at") from error


def _cve(value: object) -> str:
    if not isinstance(value, str) or not _CVE.fullmatch(value):
        raise CveEnrichmentError("invalid_cve")
    return value


def _selected(values: Iterable[str], maximum: int) -> tuple[str, ...]:
    selected: set[str] = set()
    for count, value in enumerate(values, 1):
        if count > maximum:
            raise CveEnrichmentError("selection_limit")
        canonical = _cve(value)
        if canonical in selected:
            raise CveEnrichmentError("duplicate_requested_cve")
        selected.add(canonical)
    if not selected:
        raise CveEnrichmentError("empty_selection")
    return tuple(sorted(selected))


def _score(value: object) -> str:
    if not isinstance(value, str) or len(value) > 64 or not _DECIMAL.fullmatch(value):
        raise CveEnrichmentError("invalid_score")
    # Fixed-point rendering avoids binary floats and context-dependent rounding.
    parsed = Decimal(value)
    if not parsed.is_finite() or not Decimal(0) <= parsed <= Decimal(1):
        raise CveEnrichmentError("invalid_score")
    rendered = format(parsed, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    # PublicEpssValue permits at most 32 characters in either numeric field.
    if len(rendered) > 32:
        raise CveEnrichmentError("invalid_score")
    return rendered


def _day(value: object, maximum: date) -> date:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        raise CveEnrichmentError("invalid_date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise CveEnrichmentError("invalid_date") from error
    if parsed > maximum:
        raise CveEnrichmentError("future_date")
    return parsed


def _version(value: object) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise CveEnrichmentError("invalid_version")
    return value


def _json(body: bytes, maximum: int) -> dict:
    if not isinstance(body, bytes) or not body or len(body) > maximum:
        raise CveEnrichmentError("body_size_limit")
    try:
        value = strict_json_loads(body.decode("utf-8"), max_nodes=500_000, max_depth=16)
    except (UnicodeError, StrictJsonError, ValueError, RecursionError) as error:
        raise CveEnrichmentError("invalid_json") from error
    if not isinstance(value, dict):
        raise CveEnrichmentError("invalid_envelope")
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, float) and not math.isfinite(node):
            raise CveEnrichmentError("non_finite_json")
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return value


def epss_api_url(requested_cves: Iterable[str]) -> str:
    selected = _selected(requested_cves, 100)
    joined = ",".join(selected)
    if len(joined) > 2000:
        raise CveEnrichmentError("selection_limit")
    return EPSS_API_URL + "?" + urlencode({"cve": joined, "limit": 100})


def parse_epss(
    body: bytes, requested_cves: Iterable[str], *, observed_at: datetime
) -> EpssSnapshot:
    observed = _observed(observed_at)
    selected = _selected(requested_cves, 100)
    source_url = epss_api_url(selected)
    value = _json(body, 256 * 1024)
    rows = value.get("data")
    total, offset, limit = (value.get(key) for key in ("total", "offset", "limit"))
    if (
        value.get("status") != "OK"
        or type(value.get("status-code")) is not int
        or value["status-code"] != 200
        or not isinstance(rows, list)
        or type(total) is not int
        or type(offset) is not int
        or type(limit) is not int
        or offset != 0
        or not 0 <= total <= len(selected)
        or not total <= limit <= 1000
        or len(rows) != total
    ):
        raise CveEnrichmentError("incomplete_epss_page")
    scores: dict[str, EpssScore] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise CveEnrichmentError("invalid_row")
        cve = _cve(row.get("cve"))
        if cve not in selected or cve in scores:
            raise CveEnrichmentError("unexpected_or_duplicate_cve")
        model = _version(row["model_version"]) if "model_version" in row else None
        scores[cve] = EpssScore(
            cve,
            _score(row.get("epss")),
            _score(row.get("percentile")),
            _day(row.get("date"), observed.date()),
            model,
        )
    dates = {score.score_date for score in scores.values()}
    if len(dates) > 1:
        raise CveEnrichmentError("mixed_score_dates")
    return EpssSnapshot(
        source_url,
        observed,
        sha256_id(body),
        selected,
        tuple(scores[key] for key in sorted(scores)),
        tuple(key for key in selected if key not in scores),
        len(rows),
        next(iter(dates), None),
    )


def parse_kev(body: bytes, *, observed_at: datetime) -> KevSnapshot:
    observed = _observed(observed_at)
    value = _json(body, 8 * 1024 * 1024)
    version = _version(value.get("catalogVersion"))
    try:
        released = parse_timestamp(value.get("dateReleased"))
    except TimestampError as error:
        raise CveEnrichmentError("invalid_date_released") from error
    if released > observed:
        raise CveEnrichmentError("future_date")
    rows, count = value.get("vulnerabilities"), value.get("count")
    if (
        type(count) is not int
        or not 1 <= count <= 10_000
        or not isinstance(rows, list)
        or len(rows) != count
    ):
        raise CveEnrichmentError("incomplete_kev_feed")
    entries: dict[str, KevEntry] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise CveEnrichmentError("invalid_row")
        cve = _cve(row.get("cveID"))
        if cve in entries:
            raise CveEnrichmentError("duplicate_cve")
        entries[cve] = KevEntry(cve, _day(row.get("dateAdded"), released.date()))
    return KevSnapshot(
        KEV_URL,
        observed,
        sha256_id(body),
        version,
        released,
        tuple(entries[key] for key in sorted(entries)),
    )


def epss_bulk_url(score_date: date) -> str:
    if type(score_date) is not date:
        raise CveEnrichmentError("invalid_date")
    if score_date < date(2021, 4, 14):
        raise CveEnrichmentError("invalid_date")
    return f"{EPSS_BULK_ROOT}/epss_scores-{score_date.isoformat()}.csv.gz"


def _expanded_lines(
    chunks: Iterable[bytes],
    *,
    limits: EnrichmentLimits,
    digest,
    check: Callable[[], None],
) -> Iterator[bytes]:
    decoder = zlib.decompressobj(31)
    compressed = expanded = 0
    pending = b""
    for chunk in chunks:
        check()
        if not isinstance(chunk, bytes):
            raise CveEnrichmentError("invalid_stream_chunk")
        compressed += len(chunk)
        if compressed > limits.max_compressed_bytes:
            raise CveEnrichmentError("compressed_size_limit")
        digest.update(chunk)
        remaining = chunk
        while remaining:
            check()
            if decoder.eof:
                raise CveEnrichmentError("gzip_trailing_data")
            try:
                output = decoder.decompress(remaining, 64 * 1024)
            except zlib.error as error:
                raise CveEnrichmentError("invalid_gzip") from error
            remaining = decoder.unconsumed_tail
            expanded += len(output)
            if expanded > limits.max_expanded_bytes:
                raise CveEnrichmentError("expanded_size_limit")
            pending += output
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                if len(line) > limits.max_line_bytes:
                    raise CveEnrichmentError("line_size_limit")
                yield line.removesuffix(b"\r")
            if len(pending) > limits.max_line_bytes:
                raise CveEnrichmentError("line_size_limit")
            if decoder.unused_data:
                raise CveEnrichmentError("gzip_trailing_data")
    check()
    if not decoder.eof or pending or not compressed:
        raise CveEnrichmentError("incomplete_gzip_csv")


def parse_epss_csv_gzip(
    body: bytes | Iterable[bytes],
    requested_cves: Iterable[str],
    *,
    score_date: date,
    observed_at: datetime,
    limits: EnrichmentLimits = DEFAULT_LIMITS,
    check: Callable[[], None] = lambda: None,
) -> EpssSnapshot:
    observed = _observed(observed_at)
    source_url = epss_bulk_url(score_date)
    if score_date > observed.date():
        raise CveEnrichmentError("future_date")
    selected = _selected(requested_cves, limits.max_selected_cves)
    wanted = set(selected)
    digest = sha256()
    chunks = (body,) if isinstance(body, bytes) else body
    lines = iter(_expanded_lines(chunks, limits=limits, digest=digest, check=check))
    try:
        metadata = next(lines).decode("ascii")
        header = next(lines)
    except (StopIteration, UnicodeError) as error:
        raise CveEnrichmentError("invalid_csv_header") from error
    matched = re.fullmatch(r"#model_version:([^,]+),score_date:([^,]+)", metadata)
    if matched is None or header != b"cve,epss,percentile":
        raise CveEnrichmentError("invalid_csv_header")
    model = _version(matched[1])
    score_time = None
    if "T" in matched[2]:
        try:
            score_time = parse_timestamp(matched[2])
        except TimestampError as error:
            raise CveEnrichmentError("invalid_score_timestamp") from error
        metadata_date = score_time.date()
        if score_time > observed:
            raise CveEnrichmentError("future_date")
    else:
        metadata_date = _day(matched[2], observed.date())
    if metadata_date != score_date:
        raise CveEnrichmentError("score_date_mismatch")
    seen: set[str] = set()
    scores: dict[str, EpssScore] = {}
    for line in lines:
        if len(seen) >= limits.max_rows:
            raise CveEnrichmentError("row_limit")
        try:
            parts = line.decode("ascii").split(",")
        except UnicodeError as error:
            raise CveEnrichmentError("invalid_csv_row") from error
        if len(parts) != 3:
            raise CveEnrichmentError("invalid_csv_row")
        cve, epss, percentile = _cve(parts[0]), _score(parts[1]), _score(parts[2])
        if cve in seen:
            raise CveEnrichmentError("duplicate_cve")
        seen.add(cve)
        if cve in wanted:
            scores[cve] = EpssScore(cve, epss, percentile, score_date, model)
    if not seen:
        raise CveEnrichmentError("empty_epss_feed")
    return EpssSnapshot(
        source_url,
        observed,
        "sha256:" + digest.hexdigest(),
        selected,
        tuple(scores[key] for key in sorted(scores)),
        tuple(key for key in selected if key not in scores),
        len(seen),
        score_date,
        model,
        score_time,
    )


def _authorize(
    profile: SourceProfile,
    *,
    source_id: str,
    url: str,
    method: str,
    fields: set[str],
    observed: datetime,
) -> None:
    try:
        if profile.source_id != source_id or not profile.is_public_output_approved:
            raise CveEnrichmentError("source_rights_rejected")
        profile.authorize_collection(method=method, canonical_url=url, today=observed.date())
        allowed = set(profile.allowed_root_fields())
        public_fields: set[str] = set()
        # Existing EPSS policy explicitly uses dated immutable storage.
        for rule in profile.field_rules:
            if rule["storage"] == "immutable_by_date":
                allowed.update(rule["fields"])
            if rule["public_output"] in {
                "allowed",
                "allowed_with_attribution",
                "allowed_with_attribution_and_as_of_date",
                "allowed_with_attribution_and_source_date",
            }:
                public_fields.update(rule["fields"])
        if (
            not fields <= allowed
            or not fields <= public_fields
            or fields & profile.prohibited_root_fields()
        ):
            raise CveEnrichmentError("field_rights_rejected")
    except SourceRightsError as error:
        raise CveEnrichmentError("source_rights_rejected") from error


@contextmanager
def _download(
    url: str,
    *,
    maximum: int,
    media_types: set[str],
    deadline: OperationDeadline,
    transport: httpx.BaseTransport | None,
) -> Iterator[Iterable[bytes]]:
    try:
        timeout = min(10.0, deadline.remaining_seconds())
        with (
            httpx.Client(
                follow_redirects=False,
                trust_env=False,
                timeout=timeout,
                transport=transport,
            ) as client,
            client.stream(
                "GET",
                url,
                headers={"Accept-Encoding": "identity", "User-Agent": "SmithGuard/EPSS-KEV"},
            ) as response,
        ):
            deadline.check()
            if response.status_code != 200:
                raise CveEnrichmentError(
                    "http_not_found" if response.status_code == 404 else "http_status_rejected"
                )
            if str(response.url) != url:
                raise CveEnrichmentError("response_url_mismatch")
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise CveEnrichmentError("content_encoding_rejected")
            media = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if media not in media_types:
                raise CveEnrichmentError("media_type_rejected")
            lengths = response.headers.get_list("content-length")
            if len(lengths) > 1 or (
                lengths and (len(lengths[0]) > 20 or not re.fullmatch(r"[0-9]+", lengths[0]))
            ):
                raise CveEnrichmentError("content_length_rejected")
            declared = int(lengths[0]) if lengths else None
            if declared is not None and declared > maximum:
                raise CveEnrichmentError("body_size_limit")

            def chunks() -> Iterator[bytes]:
                count = 0
                for chunk in response.iter_raw(chunk_size=64 * 1024):
                    deadline.check()
                    count += len(chunk)
                    if count > maximum:
                        raise CveEnrichmentError("body_size_limit")
                    yield chunk
                deadline.check()
                if declared is not None and count != declared:
                    raise CveEnrichmentError("content_length_mismatch")

            yield chunks()
            deadline.check()
    except AcquisitionRejected as error:
        raise CveEnrichmentError("operation_time_limit") from error
    except httpx.HTTPError as error:
        raise CveEnrichmentError("transport_unavailable") from error


def fetch_epss(
    requested_cves: Iterable[str],
    *,
    profile: SourceProfile,
    observed_at: datetime,
    transport: httpx.BaseTransport | None = None,
    clock: Callable[[], float] = monotonic,
) -> EpssSnapshot:
    observed = _observed(observed_at)
    selected = _selected(requested_cves, 100)
    url = epss_api_url(selected)
    _authorize(
        profile,
        source_id="gbsec:source:first-epss",
        url=url,
        method="rest_api",
        fields={"cve", "epss", "percentile", "date", "model_version"},
        observed=observed,
    )
    deadline = OperationDeadline.start(20, clock=clock)
    with _download(
        url,
        maximum=256 * 1024,
        media_types={"application/json"},
        deadline=deadline,
        transport=transport,
    ) as chunks:
        result = parse_epss(b"".join(chunks), selected, observed_at=observed)
        deadline.check()
        return result


def fetch_epss_bulk(
    requested_cves: Iterable[str],
    *,
    score_date: date,
    profile: SourceProfile,
    observed_at: datetime,
    limits: EnrichmentLimits = DEFAULT_LIMITS,
    transport: httpx.BaseTransport | None = None,
    clock: Callable[[], float] = monotonic,
) -> EpssSnapshot:
    observed = _observed(observed_at)
    selected = _selected(requested_cves, limits.max_selected_cves)
    url = epss_bulk_url(score_date)
    if score_date > observed.date():
        raise CveEnrichmentError("future_date")
    _authorize(
        profile,
        source_id="gbsec:source:first-epss",
        url=url,
        method="download",
        fields={"cve", "epss", "percentile", "date", "model_version"},
        observed=observed,
    )
    deadline = OperationDeadline.start(limits.max_elapsed_seconds, clock=clock)
    with _download(
        url,
        maximum=limits.max_compressed_bytes,
        media_types={
            "application/gzip",
            "application/x-gzip",
            "application/octet-stream",
            "binary/octet-stream",
        },
        deadline=deadline,
        transport=transport,
    ) as chunks:
        return parse_epss_csv_gzip(
            chunks,
            selected,
            score_date=score_date,
            observed_at=observed,
            limits=limits,
            check=deadline.check,
        )


def _current_epss_date(
    *, observed: datetime, deadline: OperationDeadline, transport: httpx.BaseTransport | None
) -> date:
    """Resolve one official redirect without reading or trusting its response body."""
    try:
        with (
            httpx.Client(
                follow_redirects=False,
                trust_env=False,
                timeout=min(10.0, deadline.remaining_seconds()),
                transport=transport,
            ) as client,
            client.stream(
                "GET",
                EPSS_CURRENT_URL,
                headers={"Accept-Encoding": "identity", "User-Agent": "SmithGuard/EPSS-KEV"},
            ) as response,
        ):
            deadline.check()
            if str(response.url) != EPSS_CURRENT_URL:
                raise CveEnrichmentError("response_url_mismatch")
            if response.status_code not in {301, 302, 303, 307, 308}:
                raise CveEnrichmentError("current_redirect_rejected")
            locations = response.headers.get_list("location")
            if len(locations) != 1 or len(locations[0]) > 256:
                raise CveEnrichmentError("current_redirect_rejected")
            target = urljoin(EPSS_CURRENT_URL, locations[0])
            match = re.fullmatch(
                re.escape(EPSS_BULK_ROOT) + r"/epss_scores-([0-9]{4}-[0-9]{2}-[0-9]{2})\.csv\.gz",
                target,
            )
            if match is None:
                raise CveEnrichmentError("current_redirect_rejected")
            leaf = target.rsplit("/", 1)[1]
            if locations[0] not in {target, "/" + leaf, leaf}:
                raise CveEnrichmentError("current_redirect_rejected")
            score_date = _day(match[1], observed.date())
            if target != epss_bulk_url(score_date):
                raise CveEnrichmentError("current_redirect_rejected")
            if observed.date() - score_date > timedelta(days=2):
                raise CveEnrichmentError("stale_epss_feed")
            deadline.check()
            return score_date
    except AcquisitionRejected as error:
        raise CveEnrichmentError("operation_time_limit") from error
    except httpx.HTTPError as error:
        raise CveEnrichmentError("transport_unavailable") from error


def fetch_epss_current(
    requested_cves: Iterable[str],
    *,
    profile: SourceProfile,
    observed_at: datetime,
    limits: EnrichmentLimits = DEFAULT_LIMITS,
    transport: httpx.BaseTransport | None = None,
    clock: Callable[[], float] = monotonic,
) -> EpssSnapshot:
    """Fetch the official current file with one exact dated redirect and no retries.

    The redirect date and CSV metadata must agree. Retain the dated source URL and
    raw compressed-body hash, and require source data no older than 36h on acquisition.
    This leaves refresh time before the retained public data's 48h freshness limit.
    Resolution and streaming share the same total operation deadline.
    """
    observed = _observed(observed_at)
    selected = _selected(requested_cves, limits.max_selected_cves)
    fields = {"cve", "epss", "percentile", "date", "model_version"}
    _authorize(
        profile,
        source_id="gbsec:source:first-epss",
        url=EPSS_CURRENT_URL,
        method="download",
        fields=fields,
        observed=observed,
    )
    deadline = OperationDeadline.start(limits.max_elapsed_seconds, clock=clock)
    score_date = _current_epss_date(observed=observed, deadline=deadline, transport=transport)
    url = epss_bulk_url(score_date)
    _authorize(
        profile,
        source_id="gbsec:source:first-epss",
        url=url,
        method="download",
        fields=fields,
        observed=observed,
    )
    with _download(
        url,
        maximum=limits.max_compressed_bytes,
        media_types={
            "application/gzip",
            "application/x-gzip",
            "application/octet-stream",
            "binary/octet-stream",
        },
        deadline=deadline,
        transport=transport,
    ) as chunks:
        result = parse_epss_csv_gzip(
            chunks,
            selected,
            score_date=score_date,
            observed_at=observed,
            limits=limits,
            check=deadline.check,
        )
        source_time = result.score_timestamp or datetime.combine(
            score_date, datetime.min.time(), UTC
        )
        if observed - source_time > EPSS_MAX_CURRENT_AGE:
            raise CveEnrichmentError("stale_epss_feed")
        deadline.check()
        return result


def fetch_kev(
    *,
    profile: SourceProfile,
    observed_at: datetime,
    transport: httpx.BaseTransport | None = None,
    clock: Callable[[], float] = monotonic,
) -> KevSnapshot:
    observed = _observed(observed_at)
    _authorize(
        profile,
        source_id="gbsec:source:cisa-kev",
        url=KEV_URL,
        method="download",
        fields={"cve", "date_added"},
        observed=observed,
    )
    deadline = OperationDeadline.start(30, clock=clock)
    with _download(
        KEV_URL,
        maximum=8 * 1024 * 1024,
        media_types={"application/json"},
        deadline=deadline,
        transport=transport,
    ) as chunks:
        result = parse_kev(b"".join(chunks), observed_at=observed)
        deadline.check()
        return result
