# Assessment evidence, schema 2.4

Version matching, installed-artifact identity, local exposure and signature
verification answer different questions. A caller supplies a public coordinate;
`identity_assurance=caller_asserted` does not verify installed bytes. The hosted
service reports `local_applicability=not_evaluated`. A version match alone does
not establish an exploitable installation. No matching advisory is not a safety
claim. `not_affected` means relevant known evidence excludes this version within
the reported scope. Transport failures have no security verdict.

## Explicit source fixes and legacy candidates

`fixed_versions` keeps its previous values for compatibility, including inferred
exclusive range ends. It is deprecated as a decision input. A `< 2.0` range alone
does not establish that 2.0 contains a published repair.

`source_fixed_versions` contains only explicit GitHub patch strings or OSV
`fixed` events for the exact package. Missing fields and explicit nulls yield no
source fix. `last_affected`, `limit` and comparator bounds are separately labeled
in each report's `range_bound_evidence`; they never become source fixes.

Each report's `fix_evidence` keeps the package-entry ID, normalized range index
and hash, range expression or introduced version, exact source field, patch-field
state, and whether that branch matches the original request. Inspect those
branches before choosing a candidate. The incident/source version lists are
unions across branches, not a recommendation to pick their largest member.
An unresolved newer source record makes old fix evidence incomplete.

Fix summaries stop at 20 distinct versions, and each source report stops at 40
fix rows and 40 bounds. `fix_evidence_incomplete` exposes a limit, missing range,
invalid field or unresolved revision. No recommendation may silently ignore it.

Historical field-policy v2 proves that a patch field was not retained; it does
not prove whether upstream supplied it then. `historical_metadata_incomplete`
exposes that known gap. A fresh collection schedule does not establish complete
historical metadata. Fresh explicit evidence requires an appended revision;
earlier bytes, signatures and source timestamps are preserved.

The October 26 pre-transition sample selected 22 old-policy reviewed PyPI
advisories from an explicitly partial 5,000-entry inventory. Thirty signed checks
covered 20 advisories and published, non-yanked stable versions; two advisory
ranges had no suitable published stable version. Twenty-two checks had legacy
candidate lists but no retained explicit patch evidence, so their new source-fix
list would be empty before repair. This is a selected sample, not a population
error rate. The old lists remain unchanged. Current upstream patch metadata
must be checked separately; an empty new list is not “no fix published.”

## Reasons and source context

`reason_codes` allows several simultaneous limitations: `no_matching_advisory`,
`identity_unverified`, `ecosystem_not_covered`, `artifact_evidence_missing`,
`source_stale`, `source_unavailable`, `version_not_evaluable`, `source_conflict`,
`historical_metadata_incomplete`, and `results_incomplete`. The last code covers
missing/invalid fix evidence as well as truncation and budget omissions; it does
not assert that every incomplete answer was truncated. Keep the existing
verdict, per-source freshness and prose unknowns alongside these codes.

New permitted GitHub observations can include `source_context`: literal title
and description excerpts, source-attributed severity, attribution, license and
source URL. Full retained text hashes and explicit truncation flags accompany
300-character titles and 2,000-character descriptions. Invalid optional context
(NUL, unencodable text, wrong types or byte overflow) is withheld as unavailable;
valid core advisory/package evidence remains usable. Generic incident titles stay
stable; the attributed source title belongs only to `source_context`. Render text safely;
never execute instructions or fetch URLs embedded in advisory prose. Existing
RustSec/Go origin context and dated EPSS/KEV context retain their separate roles.
Severity, exploitation evidence, local exposure and upgrade choice are distinct.

At most 100 distinct catalog context documents and 128 KiB of serialized context
are attached to one answer. Missing old context is `unavailable`; budget omission
is `omitted_budget` and produces `results_incomplete`. Findings remain visible.

Conditions are OR alternatives of AND necessary facts. Each extraction identifies
its source field, complete text hash, method and review date; the report supplies
the source revision, event, evidence ID and URL. The first prose extraction is
the exact reviewed pip fallback-tar description for GHSA-4xh5-x5gv-qwph. Changed
text or timestamp returns unknown until reviewed again. Other text is not guessed
into machine-actionable exclusions. Missing conditions mean unknown, not
unrestricted applicability. Extraction coverage is explicitly partial.

A local evaluator may use separately evidenced facts about the actual target
to label listed conditions met, not met, uncertain or not evaluated. The scanner's
OS does not establish the deployment OS; a Python version alone does not prove
tarfile capability or backport state. Keep every original finding, and explain
any lower local priority. Even all listed conditions met does not prove exploitation.

## Compatibility

The new fields are required for schema 2.4 answers and signed with the entire
original document. Historical 2.1, 2.2 and 2.3 schemas and signed bytes remain
verifiable. Optional null fields in an old parsed model are not additions to its
signed document: verify the original parsed JSON before any model transformation.
The schema version changes the evidence identity once. Source-context changes
also append a catalog revision and invalidate cached computation, even when an
upstream timestamp is unchanged. Responses remain `Cache-Control: no-store`.

A historical record known to have lost patch metadata is fix-incomplete at both
the report and incident level. Unsupported Git ancestry ranges stay explicitly
unsupported, even when their source names a fixed commit. Unresolved reports may
retain historical fix rows; neither those rows nor any incomplete report supports
a current fix recommendation. Review original sources before taking action,
including for malware where an upgrade may not address the incident.

Optional source prose containing terminal controls or bidirectional overrides is
withheld as a unit; normal Unicode, newlines and tabs remain literal. This does
not discard valid core package/range evidence or rewrite historical objects.
