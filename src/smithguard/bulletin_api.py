"""Bounded read-only bulletin routes, including an escaped Atom projection."""

from datetime import UTC, datetime
from email.utils import format_datetime
from urllib.parse import urlencode
from xml.etree.ElementTree import Element, SubElement, tostring

from fastapi import Path, Query, Request
from fastapi.responses import JSONResponse, Response

from smithguard import bulletin_store as store
from smithguard.assessment_cache import AssessmentCacheCapacityError
from smithguard.bulletin_contract import BulletinError
from smithguard.identifiers import canonical_json_bytes, sha256_id

ROUTES = frozenset(
    {
        ("GET", "/v1/bulletins.json"),
        ("GET", "/v1/bulletins/{identity}.json"),
        ("GET", "/v1/bulletin-events.json"),
        ("GET", "/v1/bulletin-status.json"),
        ("GET", "/v1/bulletins.atom"),
    }
)
ORIGIN = "https://api.smithguard.io"
ATOM = "http://www.w3.org/2005/Atom"


def _query(request, allowed):
    keys = [key for key, _value in request.query_params.multi_items()]
    if set(keys) - set(allowed) or len(keys) != len(set(keys)):
        raise BulletinError("bulletin_query_invalid")


def _response(request, data, headers, *, atom=False, modified=None):
    body = data if atom else canonical_json_bytes(data)
    tag = '"' + sha256_id(body) + '"'
    output_headers = {**headers, "Cache-Control": "no-store", "ETag": tag}
    if modified is not None:
        output_headers["Last-Modified"] = format_datetime(modified.astimezone(UTC), usegmt=True)
    if request.headers.get("if-none-match") == tag:
        return Response(status_code=304, headers=output_headers)
    return Response(
        body,
        media_type="application/atom+xml" if atom else "application/json",
        headers=output_headers,
    )


def atom_feed(session, page, *, now, query):
    root = Element("feed", {"xmlns": ATOM})
    SubElement(root, "id").text = ORIGIN + "/v1/bulletins.atom"
    SubElement(root, "title").text = "SmithGuard bulletin changes"
    SubElement(root, "updated").text = (
        page["items"][-1]["occurred_at"] if page["items"] else store.timestamp(now)
    )
    SubElement(SubElement(root, "author"), "name").text = "SmithGuard"
    SubElement(root, "subtitle").text = (
        "Attributed reports. Applicability is not evaluated. "
        "Reading a bulletin authorizes no machine action."
    )
    SubElement(
        root,
        "link",
        {
            "rel": "self",
            "href": ORIGIN + "/v1/bulletins.atom" + ("?" + urlencode(query) if query else ""),
        },
    )
    SubElement(
        root,
        "link",
        {
            "rel": "next",
            "href": ORIGIN
            + "/v1/bulletins.atom?"
            + urlencode({**query, "cursor": page["next_cursor"]}),
        },
    )
    for event in page["items"]:
        record = store.detail(session, event["bulletin_id"], now=now)
        entry = SubElement(root, "entry")
        SubElement(entry, "id").text = f"urn:smithguard:bulletin-event:v1:{event['sequence']}"
        SubElement(entry, "updated").text = event["occurred_at"]
        SubElement(
            entry,
            "link",
            {"rel": "alternate", "href": "https://smithguard.io/threats/#" + event["bulletin_id"]},
        )
        SubElement(
            entry,
            "link",
            {
                "rel": "related",
                "type": "application/json",
                "href": ORIGIN + "/v1/bulletins/" + event["bulletin_id"] + ".json",
            },
        )
        content = record["content"]
        SubElement(entry, "title", {"type": "text"}).text = (
            content["title"] if content else "Public bulletin removed"
        )
        SubElement(entry, "summary", {"type": "text"}).text = (
            f"Change: {event['kind']}. Current revision: {record['current_revision']}. "
            f"Freshness: {record['freshness']}. Applicability: not evaluated. "
            + (
                content["summary"]
                if content
                else "Public content was revoked; only the audit reference remains."
            )
        )
        SubElement(entry, "category", {"term": event["kind"]})
    return tostring(root, encoding="utf-8", xml_declaration=True)


def register(local, *, session_factory, clock, run_bounded, headers):
    # Public credential-free GET projection for the approved product website.
    # Do not broaden CORS on inventory/assessment or other service routes.
    headers = {**headers, "Access-Control-Allow-Origin": "https://smithguard.io"}

    async def read(request, operation, *, atom=False):
        def load():
            with session_factory() as session:
                return operation(session, clock())

        try:
            document = await run_bounded(load)
        except AssessmentCacheCapacityError:
            return JSONResponse(
                {
                    "error": {
                        "code": "service_capacity_exceeded",
                        "message": "Bulletin read capacity is temporarily full.",
                        "retryable": True,
                    }
                },
                status_code=429,
                headers={**headers, "Cache-Control": "no-store", "Retry-After": "1"},
            )
        except BulletinError as error:
            code = str(error)
            status = 400
            if code in {"bulletin_not_found", "bulletin_revision_not_found"}:
                status = 404
            elif code == "bulletin_cursor_expired":
                status = 410
            elif code == "bulletin_stream_unavailable":
                status = 503
            return JSONResponse(
                {
                    "error": {
                        "code": code,
                        "message": "The bulletin request could not be completed.",
                        "retryable": status == 503,
                    }
                },
                status_code=status,
                headers={**headers, "Cache-Control": "no-store"},
            )
        except Exception:
            # Never reflect source text, SQL, grant bytes or private evidence.
            return JSONResponse(
                {
                    "error": {
                        "code": "bulletin_unavailable",
                        "message": "Bulletin data is temporarily unavailable.",
                        "retryable": True,
                    }
                },
                status_code=503,
                headers={**headers, "Cache-Control": "no-store"},
            )
        modified = None
        if isinstance(document, dict) and "bulletin_id" in document:
            modified = datetime.fromisoformat(document["updated_at"].replace("Z", "+00:00"))
            if document["freshness_reason"] == "verification_overdue":
                modified = max(
                    modified,
                    datetime.fromisoformat(document["verification_due_at"].replace("Z", "+00:00")),
                )
        return _response(request, document, headers, atom=atom, modified=modified)

    @local.get("/v1/bulletins.json")
    async def bulletins(
        request: Request,
        limit: int = Query(50, ge=1, le=100),
        cursor: str | None = Query(None, max_length=2048),
        source: str | None = Query(None, min_length=1, max_length=40),
        evidence_class: str | None = Query(None, max_length=30),
        subject: str | None = Query(None, min_length=1, max_length=120),
    ):
        def load(session, now):
            _query(request, {"limit", "cursor", "source", "evidence_class", "subject"})
            return store.snapshot(
                session,
                now=now,
                limit=limit,
                cursor=cursor,
                source=source,
                evidence_class=evidence_class,
                subject=subject,
            )

        return await read(request, load)

    @local.get("/v1/bulletins/{identity}.json")
    async def bulletin(
        request: Request,
        identity: str = Path(pattern="^[a-f0-9]{64}$", max_length=64),
        revision: int | None = Query(None, ge=1, le=2147483647),
    ):
        def load(session, now):
            _query(request, {"revision"})
            return store.detail(session, identity, now=now, revision=revision)

        return await read(request, load)

    @local.get("/v1/bulletin-events.json")
    async def changes(
        request: Request,
        limit: int = Query(100, ge=1, le=100),
        cursor: str | None = Query(None, max_length=2048),
        identity: str | None = Query(None, pattern="^[a-f0-9]{64}$", max_length=64),
    ):
        def load(session, now):
            _query(request, {"limit", "cursor", "identity"})
            return store.events(session, now=now, limit=limit, cursor=cursor, identity=identity)

        return await read(request, load)

    @local.get("/v1/bulletin-status.json")
    async def status(request: Request):
        def load(session, now):
            _query(request, {})
            return store.source_status(session, now=now)

        return await read(request, load)

    @local.get("/v1/bulletins.atom")
    async def atom(
        request: Request,
        limit: int = Query(50, ge=1, le=100),
        cursor: str | None = Query(None, max_length=2048),
        identity: str | None = Query(None, pattern="^[a-f0-9]{64}$", max_length=64),
    ):
        def load(session, now):
            _query(request, {"limit", "cursor", "identity"})
            page = store.events(session, now=now, limit=limit, cursor=cursor, identity=identity)
            return atom_feed(session, page, now=now, query=dict(request.query_params))

        return await read(request, load, atom=True)
