"""Offline escaped HTML and text reports, with no scripts or external resources."""

from __future__ import annotations

import hashlib
import html
import json
from urllib.parse import urlsplit

from .discovery import coordinate_id

MAX_RENDER_BYTES = 24 * 1024 * 1024
DETAIL_INPUT_BYTES = 128 * 1024


class RenderLimit(ValueError):
    pass


class Parts(list):
    def __init__(self, values=()):
        super().__init__()
        self.size = 0
        for value in values:
            self.append(value)

    def append(self, value):
        size = len(value.encode())
        if self.size + size > MAX_RENDER_BYTES - 1024:
            raise RenderLimit("readable output limit")
        self.size += size
        super().append(value)


def evidence_label(assessment):
    return (
        "Verified current version evidence"
        if assessment.get("current_decision_eligible")
        else "Unverified answer; not decision evidence"
    )


def text_report(report):
    counts = report["counts"]
    lines = Parts(
        [
            "SmithGuard local assessment report\n",
            report["notice"] + "\n",
            f"{counts['installations']} installations; "
            f"{counts['approved_coordinates']} approved coordinates; "
            f"{counts['unique_incidents']} verified current incidents; "
            f"{counts['unique_source_reports']} verified current source reports.\n",
            f"Unverified answers: {counts.get('unverified_unique_incidents', 0)} incidents; "
            f"{counts.get('unverified_unique_source_reports', 0)} source reports.\n",
            f"Run complete: {report['run_complete']}. "
            f"Discovery scope complete: {report['scope_complete']}.\n",
            f"Evidence complete: {report['evidence_complete']}. "
            f"Interpretation complete: {report['interpretation_complete']}. "
            "Supplied fact sets not fully evaluated: "
            f"{counts['supplied_facts_not_fully_evaluated']}.\n",
            f"Service incomplete answers: {counts['service_incomplete_answers']}; "
            f"service truncated answers: {counts['service_truncated_answers']}.\n",
            "Complete retained evidence, source context, local facts and relationship "
            "accounting are in the companion JSON report.\n",
        ]
    )
    try:
        for item in report["installations"]:
            coordinate = item["coordinate"]
            label = (
                (coordinate["name"] + " " + coordinate["version"])
                if coordinate
                else item["metadata_directory"]
            )
            lines.append(
                json.dumps(
                    f"Installation {item['installation_id']}: {label}; {item['run_status']}; "
                    "activity unknown; installed identity unverified",
                    ensure_ascii=True,
                )
                + "\n"
            )
            lines.append(
                "Local conditions: "
                + item.get("local_applicability_status", "not_evaluated")
                + "\n"
            )
        for row in report["coordinate_results"].values():
            coordinate = row["coordinate"]
            assessment = row.get("assessment", {})
            lines.append(
                json.dumps(
                    f"{coordinate['name']} {coordinate['version']}: {row['status']}; "
                    f"{evidence_label(assessment)}: {assessment.get('result', 'not assessed')}; "
                    f"reason: {row.get('reason', 'none')}",
                    ensure_ascii=True,
                )
                + "\n"
            )
            if assessment:
                lines.append(
                    "Service limits: "
                    + json.dumps(
                        {
                            k: assessment.get(k)
                            for k in (
                                "reason_codes",
                                "incidents_truncated",
                                "preliminary_warnings_truncated",
                                "service_evidence_omissions",
                            )
                        },
                        ensure_ascii=True,
                    )
                    + "\n"
                )
            if assessment.get("evidence_truncated"):
                lines.append(
                    "Evidence truncated: compact outcome and incident IDs retained; "
                    "source detail omitted.\n"
                )
                lines.append(
                    json.dumps(
                        {
                            k: assessment[k]
                            for k in (
                                "retained_incident_ids",
                                "preliminary_warning_count",
                                "preliminary_warning_ids",
                                "incidents_truncated",
                                "preliminary_warnings_truncated",
                                "coverage_result",
                                "registry_state",
                                "unknown_count",
                            )
                        },
                        ensure_ascii=True,
                    )
                    + "\n"
                )
            for incident in assessment.get("incidents", []):
                lines.append(json.dumps("  " + incident["title"], ensure_ascii=True) + "\n")
    except RenderLimit:
        # Counts remain complete; the bounded plain-text index is explicitly partial.
        return (
            "".join(lines)
            + (
                "\nText index truncated at output limit. "
                "See the companion JSON report for all retained entries.\n"
            )
        ).encode()
    return "".join(lines).encode()


def html_report(report):
    try:
        return _html_report(report, compact=False)
    except RenderLimit:
        try:
            return _html_report(report, compact=True)
        except RenderLimit:
            # Very large local labels can exceed even the compact index. Preserve
            # complete counts and clearly direct the reader to the unchanged JSON.
            counts = html.escape(json.dumps(report["counts"], ensure_ascii=True, indent=2))
            return (
                '<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1">'
                '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
                "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
                "<title>SmithGuard local report</title><style>"
                "body{font:16px/1.5 system-ui;max-width:900px;margin:2rem auto;padding:1rem}"
                "pre{white-space:pre-wrap;overflow-wrap:anywhere}</style></head><body>"
                "<h1>SmithGuard local assessment report</h1>"
                "<p>HTML index omitted at the output limit. The companion JSON report "
                "retains every installation and all derived evidence.</p>"
                "<p>Counts describe this selected run. Completion does not mean packages "
                "are safe. Installed identity is unverified; active use is unknown.</p>"
                "<h2>Complete counts</h2><pre>" + counts + "</pre></body></html>"
            ).encode()


def _html_report(report, *, compact):
    def text(value):
        # Escape terminal/bidi controls as literal JSON escapes as well as HTML.
        return html.escape(json.dumps(str(value), ensure_ascii=True)[1:-1], quote=True)

    def literal(value):
        return html.escape(json.dumps(value, ensure_ascii=True, indent=2), quote=True)

    def details(label, value):
        if compact or len(json.dumps(value, ensure_ascii=True).encode()) > DETAIL_INPUT_BYTES:
            return "<p>" + text(label) + ": see the companion JSON report for retained detail.</p>"
        return (
            "<details><summary>"
            + text(label)
            + "</summary><pre>"
            + literal(value)
            + "</pre></details>"
        )

    counts = report["counts"]
    items = {x["installation_id"]: x for x in report["installations"]}
    groups = {}
    for item in items.values():
        roots = {x["root"] for x in item.get("application_memberships", [])}
        group = next(iter(roots)) if len(roots) == 1 else "unassigned/uncertain"
        groups.setdefault(group, []).append(item)
    parts = Parts(
        [
            '<!doctype html><html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
            "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
            "<title>SmithGuard local report</title><style>"
            "body{font:16px/1.5 system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem;"
            "color:#18262f;background:#f7f9fa;overflow-wrap:anywhere}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.85rem}"
            "details,article{padding:.9rem;border:1px solid #9baeb8;"
            "margin:.8rem 0;background:white}"
            "summary{cursor:pointer;font-weight:600}a{color:#125c81}h2{margin-top:2rem}"
            ".notice{padding:1rem;background:#e7eef2;border-left:4px solid #28718e}"
            "</style></head><body>",
            "<h1>SmithGuard local assessment report</h1>",
            '<p class="notice">' + text(report["notice"]) + "</p>",
            f"<p><strong>{counts['installations']}</strong> installations / "
            f"<strong>{counts['approved_coordinates']}</strong> approved coordinates / "
            f"<strong>{counts['unique_incidents']}</strong> verified current incidents / "
            f"<strong>{counts['unique_source_reports']}</strong> "
            "verified current source reports.</p>",
            f"<p>Unverified answers: {counts.get('unverified_unique_incidents', 0)} incidents / "
            f"{counts.get('unverified_unique_source_reports', 0)} source reports.</p>",
            "<p>Checks complete: "
            + text(report["run_complete"])
            + ". Selected discovery complete: "
            + text(report["scope_complete"])
            + ". Completion does not mean the packages are safe.</p>",
            "<p>Evidence complete: "
            + text(report["evidence_complete"])
            + ". Interpretation complete: "
            + text(report["interpretation_complete"])
            + ". Supplied fact sets not fully evaluated: "
            + text(counts["supplied_facts_not_fully_evaluated"])
            + ".</p>",
            details("Installation completion counts", counts["installation_statuses"]),
            f"<p>Service incomplete answers: {counts['service_incomplete_answers']}; "
            f"service truncated answers: {counts['service_truncated_answers']}.</p>",
        ]
    )
    if compact:
        parts.append(
            '<p class="notice">HTML detail is limited to keep this file bounded. '
            "The companion JSON report retains the full derived evidence.</p>"
        )
    for group, members in sorted(groups.items()):
        root = items.get(group)
        label = (
            root["coordinate"]["name"]
            if root and root["coordinate"]
            else "Unassigned or uncertain application"
        )
        parts.append("<h2>" + text(label) + "</h2>")
        if root:
            parts.append("<p>Selected environment: " + text(root["scope"]) + "</p>")
        for item in members:
            coordinate = item["coordinate"]
            label = (
                coordinate["name"] + " " + coordinate["version"]
                if coordinate
                else item["metadata_directory"]
            )
            parts.append(
                "<details><summary>" + text(label) + " - " + text(item["run_status"]) + "</summary>"
            )
            parts.append("<p>Installed identity: unverified metadata. Active use: unknown.</p>")
            if coordinate:
                identity = coordinate_id(coordinate)
                row = report["coordinate_results"].get(identity)
                if row:
                    result = row.get("assessment", {}).get("result", "not assessed")
                    parts.append(
                        "<p>"
                        + text(evidence_label(row.get("assessment", {})))
                        + ": <strong>"
                        + text(result)
                        + "</strong>. "
                        '<a href="#coordinate-'
                        + identity
                        + '">Shared assessment and sources</a></p>'
                    )
            if item.get("run_reason"):
                parts.append("<p>Reason: " + text(item["run_reason"]) + "</p>")
            parts.append(
                "<p>Local condition evaluation: "
                + text(item.get("local_applicability_status", "not_evaluated"))
                + ".</p>"
            )
            if item["local_applicability"]:
                parts.append(
                    "<p>Target conditions: "
                    + text(", ".join(sorted({x["outcome"] for x in item["local_applicability"]})))
                    + ". "
                    "This does not remove the version finding or establish exploitability.</p>"
                )
            parts.append(details("Installation, relationship and local condition evidence", item))
            parts.append("</details>")
    parts.append("<h2>Unique coordinate assessments</h2>")
    incidents = {}
    for identity, row in report["coordinate_results"].items():
        coordinate = row["coordinate"]
        parts.append(
            '<article id="coordinate-'
            + identity
            + '"><h3>'
            + text(coordinate["name"] + " " + coordinate["version"])
            + "</h3><p>Run status: "
            + text(row["status"])
            + "</p>"
        )
        if row.get("reason"):
            parts.append("<p>Reason: " + text(row["reason"]) + "</p>")
        assessment = row.get("assessment")
        if assessment:
            parts.append(
                "<p>"
                + text(evidence_label(assessment))
                + ": <strong>"
                + text(assessment["result"])
                + "</strong>. "
                "Signature: " + text(assessment["signature_status"]) + ". "
                "Answer time: " + text(assessment["assessed_at"]) + ".</p>"
            )
            parts.append(
                "<p>Limits: "
                + text(", ".join(assessment["reason_codes"]) or "See source scope below")
                + "</p>"
            )
            parts.append("<p>" + text(assessment["next_step"]) + "</p>")
            if assessment.get("service_evidence_omissions"):
                parts.append(
                    "<p>Service evidence omitted: "
                    + text(", ".join(assessment["service_evidence_omissions"]))
                    + ". Evidence is incomplete; local conditions were not evaluated.</p>"
                )
            if assessment.get("evidence_truncated"):
                parts.append(
                    "<p><strong>Evidence truncated:</strong> compact outcome and incident IDs "
                    "retained; source detail omitted. Recheck this coordinate separately "
                    "for full evidence.</p>"
                )
                parts.append(
                    "<p>Preliminary warnings: "
                    + text(assessment["preliminary_warning_count"])
                    + "; unknowns: "
                    + text(assessment["unknown_count"])
                    + "; coverage: "
                    + text(assessment["coverage_result"])
                    + "; registry: "
                    + text(assessment["registry_state"])
                    + "; incident list truncated: "
                    + text(assessment["incidents_truncated"])
                    + "; warning list truncated: "
                    + text(assessment["preliminary_warnings_truncated"])
                    + ".</p>"
                )
                parts.append(details("Compact evidence and retained identities", assessment))
            for incident in [] if compact else assessment["incidents"]:
                anchor = hashlib.sha256(incident["incident_id"].encode()).hexdigest()
                incidents.setdefault(anchor, incident["incident_id"])
                parts.append(
                    '<h4><a href="#incident-'
                    + anchor
                    + '">'
                    + text(incident["title"])
                    + "</a></h4>"
                )
                parts.append(
                    "<p>Applies to this version: " + text(incident["applies_to_version"]) + ".</p>"
                )
                for source in incident["source_reports"]:
                    context = source.get("source_context") or {}
                    parts.append(
                        "<details><summary>"
                        + text(context.get("title") or source["source_name"])
                        + "</summary>"
                    )
                    parts.append(
                        "<p>Source: "
                        + text(source["source_name"])
                        + " / "
                        + text(source["upstream_record_id"])
                        + ". Observed: "
                        + text(source["observed_at"])
                        + "</p>"
                    )
                    parts.append(
                        "<p>Source severity: "
                        + text(context.get("severity") or "not supplied")
                        + "</p>"
                    )
                    url = context.get("source_url")
                    if isinstance(url, str):
                        try:
                            parsed = urlsplit(url)
                        except ValueError:
                            parsed = urlsplit("")
                        if (
                            parsed.scheme == "https"
                            and parsed.hostname
                            and not parsed.username
                            and not parsed.password
                        ):
                            parts.append(
                                '<p><a href="'
                                + html.escape(url, quote=True)
                                + '" rel="noopener noreferrer">Open the original source</a></p>'
                            )
                    if context.get("description"):
                        parts.append("<p>" + text(context["description"]) + "</p>")
                    if context.get("attribution"):
                        parts.append(
                            "<p>Attribution: "
                            + text(context["attribution"])
                            + " / "
                            + text(context.get("license_expression"))
                            + "</p>"
                        )
                    parts.append(
                        "<p>Explicit source fixes across branches: "
                        + text(
                            ", ".join(source.get("source_fixed_versions") or [])
                            or "none listed; not proof no fix exists"
                        )
                        + ". These are evidence candidates, not upgrade instructions.</p>"
                    )
                    if source.get("fix_evidence_incomplete") is not False:
                        parts.append("<p><strong>Fix evidence is incomplete.</strong></p>")
                    parts.append(details("Complete source and branch evidence", source))
                    parts.append("</details>")
            parts.append(
                details("Full derived assessment, freshness and exploitation context", row)
            )
        else:
            parts.append(details("Failure or unchecked result", row))
        parts.append("</article>")
    parts.append("<h2>Distinct incident index</h2>")
    for anchor, identity in incidents.items():
        parts.append('<p id="incident-' + anchor + '">' + text(identity) + "</p>")
    parts.append(
        "<h2>Discovery gaps and relationships</h2>"
        + details(
            "Complete discovery evidence",
            {"gaps": report["discovery_gaps"], "relationships": report["relationships"]},
        )
        + "</body></html>"
    )
    return "".join(parts).encode()
