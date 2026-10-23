"""Source of the generated public emerging-lead feed contract."""

LEAD = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "id": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "status": {"const": "Emerging / Unverified", "type": "string"},
        "subject": {"type": "string", "maxLength": 200},
        "reported_allegation": {"type": "string", "maxLength": 1000},
        "source_url": {"type": "string", "format": "uri", "maxLength": 2048},
        "published_at": {"type": ["string", "null"], "maxLength": 80},
        "time_precision": {"type": "string", "enum": ["exact", "day", "unknown"]},
        "first_seen_at": {"type": "string", "format": "date-time"},
        "expires_at": {"type": "string", "format": "date-time"},
        "unknowns": {"type": "array", "items": {"type": "string"}, "maxItems": 3},
    },
    "required": [
        "id",
        "status",
        "subject",
        "reported_allegation",
        "source_url",
        "published_at",
        "time_precision",
        "first_seen_at",
        "expires_at",
        "unknowns",
    ],
}
PAGE = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string", "enum": ["active", "publication_disabled"]},
        "as_of": {"type": "string", "format": "date-time"},
        "notice": {"type": "string"},
        "leads": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/EmergingLead"},
            "maxItems": 100,
        },
        "next_cursor": {"type": ["string", "null"], "pattern": "^[a-f0-9]{64}$"},
    },
    "required": ["status", "as_of", "notice", "leads", "next_cursor"],
}
PATH = {
    "get": {
        "operationId": "list_emerging_leads",
        "summary": "Source-attributed Emerging / Unverified leads",
        "description": (
            "Available only under the separately activated emerging-lead publication policy. "
            "Approximate subjects never imply exact-artifact matches. Unknown publication "
            "times stay unknown. Expiry is enforced on every read; responses must not be cached."
        ),
        "x-smithguard-read-only": True,
        "x-smithguard-availability": "public_beta",
        "parameters": [
            {
                "name": "limit",
                "in": "query",
                "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
            },
            {
                "name": "after",
                "in": "query",
                "schema": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
            },
        ],
        "responses": {
            "200": {
                "description": "Bounded active lead page or explicit publication_disabled state",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/EmergingLeadPage"}
                    }
                },
            },
            "400": {"description": "Invalid query"},
            "503": {"description": "Service unavailable"},
        },
    }
}
