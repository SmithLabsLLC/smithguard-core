# Hosted assessment summaries

The summary profile returns a bounded service-issued report for one exact public
npm or PyPI package version. It does not perform client signature verification or
decide whether software may be installed. Release availability and the exact
qualified T3 configurations are recorded separately; source support is not proof
that a running service has been upgraded.

Current T3 qualification outcome (November 7, 2026 UTC): NO-GO / UNQUALIFIED.
Four Claude cases were consumed: three incomplete primary cases and one failed
candidate case, with zero assessment calls against one expected in each case.
Forty Claude cases remain unrun and all 44 Codex cases were unavailable and unrun.
No supported T3 configuration or completion of the 88-case matrix is claimed;
no further matrix dispatch is authorized. Backend API delivery remains subject
to its separate acceptance gates. The maintainer proposal remains a no-go draft
and UNSENT. This outcome does not evaluate the separate legacy skill 0.3.0.

`POST /v1/artifacts/assessment-summary` accepts `ecosystem`, `name`, `version` and
optional `registry_host`. Unsupported ecosystems, private registries, extra fields,
moving versions and digests are rejected. Existing normalization/exact-version
rules apply. A public name is a caller assertion, not proof of installed provenance.

`/mcp/summaries` is a separate hosted Streamable HTTP profile exposing only
`assess_public_artifact_summary`. The original `/mcp` and full assessment API keep
their existing behavior. The summary profile calls the same controlled assessment
operation in-process, sharing its network quota, cache, single-flight, capacity,
deadline, cancellation and cleanup. It never invokes a separate assessment engine
or falls back to a full-response tool.

The generated OpenAPI contains closed `PublicArtifactSummaryRequest`,
`PublicArtifactSummary` and `PublicArtifactSummaryError` schemas. Summary and
projection versions are `1.0.0`, consuming assessment `2.4.0` or `2.5.0`. Unknown
underlying schemas and mismatched artifact identities fail closed. Both MCP representations
contain exactly the same derived document, without the full-tool `data/source_url`
wrapper. Returned errors are content-free. REST statuses 413, 429 and 503 accept
either the closed summary error or the generic `ErrorResponse` used by the origin
proxy; unsupported methods return a generic 405 error. These schemas are distinct.
Transport/proxy errors remain incomplete, even when they are not tool results.
The summary-only MCP tool still accepts only its closed summary error envelope.

Reports preserve the assessment result, original revision/times, exact caller
coordinate, coverage, registry state, reason codes and source freshness. Incident
and source applicability remain separate. A report with explicit current source
state retains source patches, package-entry/range association and distinct range
ends. A historical unresolved source, an unresolved source lane, or missing source
state cannot supply current fixes: its patch, fixed-version and range-bound arrays
are omitted, their omissions are counted and the report is partial. Version2.4
did not supply source-state provenance; its source state is labeled `unknown`,
and those current-fix arrays are omitted. This deliberately changes the earlier
unreleased2.4 summary candidate's behavior. Version2.5 retains the nullable
unresolved-record count at each source-freshness entry and requires explicit
source state in each source report. It is rejected if a negative result contradicts
an unresolved source lane. No engine verdict is rewritten by the projection.
Missing historical patch metadata remains explicit. Citations are limited to
canonical GitHub advisory, OSV, NVD and CVE record pages. Other or encoded URLs,
service aliases, raw assessment locators, titles and source prose are omitted.
Returned links are not automatically followed.

Selection keeps upstream order: at most eight incidents, four source reports per
incident, eight fix and eight range-bound records per source, four citations per
incident. Numeric omission counts compare the complete input arrays with the
retained fields. Upstream truncation remains separately flagged. If needed, whole
incidents are removed from the tail until canonical JSON fits 32,768 bytes. The
result and limitations remain; no truncation turns affected/unknown evidence into
a negative result. MCP's complete serialized response, including duplicated text
and structured content, is limited to 81,920 bytes.

`valid_until` is the original assessment's update time plus five minutes, never
five minutes from a newly generated wrapper. Answers over thirty seconds in the
future are refused. Expired assessments remain visibly stale. Source clocks are
copied without renewal. Missing, failed, stale or incomplete lanes, omitted fields
and upstream truncation make the report partial; a successful check is not a
complete view of all software risk. `not_affected` concerns evaluated evidence
only, and `unknown` provides no safety conclusion.

`report_origin: hosted_projection`, `client_signature_verified: false` and
`action_authorized: false` are mandatory. The derived report is not a signed copy
of its original assessment. It may persist in the specifically authorized
provider/client conversation. Re-read evidence for a later decision. HTTP
`Cache-Control: no-store` is a cache directive, not deletion of model or T3 history.
Original-response retention rules remain separate.

The optional instruction artifact is
`integrations/t3/assess-public-artifact-summary/SKILL.md`. It selects this profile,
requires one intentionally selected exact public coordinate, forbids inventory
enumeration, automatic retries and raw fallback, and reports incomplete checks.
These instructions do not constitute a deterministic consent or network boundary.
T3 and provider state must be tested for each claimed configuration. Native UI,
local signature verification, background scanning and automatic remediation are
outside this integration.

A `partial` report can reflect deliberate exclusions such as titles or raw source
text as well as missing evidence. It is not synonymous with a failed lookup;
inspect the omission counts, result, source freshness and assurance together.

Measured unresolved counts describe an entire relevant source segment, including
quarantines for other packages or ecosystems. Any positive count prevents a signed
`not_affected` result: the service reports `unknown` with `source_unavailable` while
preserving the measured count. Summary and website consumers can then display the
uncertainty instead of rejecting a contradictory negative result. Current fix and
range advice from that source is suppressed conservatively for every report. In
2.5, a null count also suppresses that advice, but does not invent a positive gap,
zero count or negative-result failure.

A deterministic summary refusal can reuse a contract-valid full assessment through
the ordinary bounded cache, correction watermark and expiry checks. It never caches
the error as an assessment. No delivered summary means no completed daily charge;
the admitted burst attempt remains counted. Cancellation and cache ownership rules
still apply, and a correction or expiry forces a fresh computation.

Maintainers can check a reviewed live release with
`python tools/verify_hosted_mcp.py --summary --output /absolute/new/local/operation`.
The output parent must exist under the checkout's ignored `local/` directory.
This fixed public smoke check tests the separate one-tool summary catalog,
closed schemas, exact identity, clocks, unsigned assurance, matching text/structured
content and REST/MCP parity. It does not fall back to raw assessment, coverage or
key tools. It is separate from the synthetic-only native qualification matrix,
does not call a model provider and does not prove local applicability or safety.
