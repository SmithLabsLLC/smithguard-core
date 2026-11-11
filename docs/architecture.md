# Architecture and trust boundaries

SmithGuard turns public source observations into evidence-linked assessments and
bulletins. The API and hosted MCP expose the same underlying service results.

1. Collectors fetch only supported public sources and preserve provenance.
2. Normalization retains source identities, revisions, package coordinates and
   affected-version ranges. Missing information stays unknown.
3. Evidence and governance checks determine which facts can support an answer.
4. Exact-artifact assessment evaluates the requested coordinate. It does not infer
   local installation or deployment exposure from an advisory alone.
5. Official-source bulletin processing handles identity, corrections, expiry and
   independently checked freshness. Discovery-only leads remain separate.
6. API, Atom and hosted MCP handlers return the stored, bounded result with its
   evidence and limits. A request does not authorize new operator actions.

## Main code areas

| Area | Paths |
| --- | --- |
| HTTP API and hosted MCP | `src/smithguard/api.py`, `src/smithguard/hosted_mcp.py` |
| Advisory and source handling | `src/smithguard/advisory_catalog.py`, `src/smithguard/collectors.py` |
| Official bulletins | `src/smithguard/bulletin_*.py`, `src/smithguard/official_notice_*.py` |
| Persistent records | `src/smithguard/db/`, `migrations/` |
| Contracts and generated output | `contracts/v1/`, `src/smithguard/generated_artifacts/` |
| Synthetic behavior tests | `tests/` |

Bulletin detail qualification records bounded failure categories, consecutive counts
and retry deadlines without retaining raw error messages. Storage pressure preserves
existing cooldown and stale-state bookkeeping while withholding new diagnostic
receipts. Intake liveness compares a packaged expected source profile, checked
control, actual timer/service state and matching hourly closure; bounded planned
transitions remain visibly degraded. Closure deadlines follow the hourly run epoch
and allow the next scheduled run to finish within its bounded runtime. The
maintenance expiry repair requires exact
live record identities and an active grant, and preserves original content and dates.

The [summary projection](product/assessment-summary.md) shares the assessment
operation and its quota, cache, deadline and cancellation ownership. Its separate
MCP profile exposes one bounded derived-report tool and never returns a raw
assessment fallback. Hosted projection does not run client signature verification.

## Important boundaries

External content and model output are untrusted data. They cannot select arbitrary
fetch targets, authorize publication, change rights or become operator commands.
Provider failures, missing data, stale facts and incomplete source windows must
remain distinguishable from a successful empty result. A corrected or withdrawn
record retains its identity and history.

The hosted service does not accept customer source code, private dependency
inventories or credentials through these public interfaces. Public API access does
not imply write access to evidence, private review queues or operating controls.
Database roles and explicit grant checks enforce the boundary. Tests use temporary
local data and fake providers to exercise both allowed and denied behavior.

## Publication and source code

The service core in this repository is shared source. Private deployment controllers,
production targets, accepted operating receipts, credentials and retained datasets
are outside this distribution. Generic deployment assets describe Linux process and
database isolation; they are reference material, not a turnkey installer. Production
publication still requires current source rights and checked operating authority.
A code contribution or successful unit test never grants that authority.

Migration `0038_openssf_resilience` is forward-only. A compatible fallback build
must understand both that migration and catalog-health receipt schema `3.0.0`,
which is emitted even while partial writes are disabled. An older build expecting
migration 0037 or only receipt `2.0.0` is not a compatible fallback. This is a
format-compatibility requirement, not a deployment or rollback instruction;
production selection and verification remain outside this source distribution.

The source-rights register is an application policy input. It is not a substitute
for a third party's terms and does not relicense their content. Contributors adding
sources must make acquisition, output rights and coverage limits explicit.
The checked-in register supports contributor fixtures; it does not describe the
current hosted rights or deployment state. Elapsed review dates fail closed; do
not extend them to run live collectors. This source snapshot and the service's
deployed policy are separate records.

### Product browser assessment reads

The existing product origin `https://smithguard.io` may read anonymous GET
responses from `/v1/artifacts/assess`, including application errors. The hosted
Nginx origin also exposes its 429 rate-limit and 503 outage responses on that
exact GET route, while retaining all security headers. This exact-origin,
exact-route response policy grants no credential access or permission on other
routes or methods. Responses vary by Origin. Inputs, quota, signed response
bytes and assessment authority are unchanged. The product omits credentials,
referrers, caching and redirects; it stores no coordinates in browser history or
local storage. Public coordinate query strings can still appear in provider
operational logs. Browser presentation does not verify response signatures.
