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

The source-rights register is an application policy input. It is not a substitute
for a third party's terms and does not relicense their content. Contributors adding
sources must make acquisition, output rights and coverage limits explicit.
