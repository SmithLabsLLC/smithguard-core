# SmithGuard operating guide

Validated October 26, 2026. Use the hosted service to assess an explicitly selected
public package coordinate. The optional smithguard-client 0.1.0 performs local
orchestration; its assessment engine and evidence database remain hosted.

## Start with identity and permission

An exact package request identifies ecosystem, registry host, normalized package
name and exact version. Use an immutable digest where the supported artifact
contract requires it. Never substitute a mutable image tag for a platform digest.
A name found in local metadata does not prove that installed files came from the
public registry. A public name can collide with private or altered software.

Only send coordinates the user has authorized for disclosure. Public availability
alone is not permission to reveal use. Never send source code, lockfiles, raw
inventories, paths, dependency relationships, private names, environment variables,
credentials or local facts. The service and its infrastructure see the requested
coordinates, network address and timing. The relationship between those requests
can itself be sensitive.

The Linux/Python adapter reads only explicitly selected real site-packages
folders. It does not search a home directory, import packages, run hooks or follow
symlinks. Supply the exact public-coordinate allowlist, read the local preview,
and approve its hash before network use. A changed scope or metadata requires a
new preview. Installation, active use and parent-application identity remain
separate facts. Read the [client instructions](../clients/python/README.md).

## Verify before interpreting

Use the maintained client verification module on the complete original response.
It rejects ambiguous JSON, unsupported formats, changed fields, wrong coordinates,
wrong key identity and invalid Ed25519 signatures. It does not verify a hand-picked
summary. Public REST and hosted MCP return the same assessment contract.

- **Verified** means the signature matched the original response and expected key.
- **Invalid** means a check failed; do not use the response as trusted evidence.
- **Unchecked** means necessary verification was unavailable or unsupported; display
  that limit and do not silently promote it into a decision.

A current decision additionally requires a fresh response and fresh active-key
status. The client uses a five-minute window for both; it checks key HTTP Date/Age
and does not save a key cache to disk. A verification-only key can authenticate a
historical answer but cannot authorize a current decision. A revoked key is
rejected. Offline key bytes do not establish current revocation status. Fetching
a key from the same HTTPS service trusts that service; it is not independent
protection against compromise of both the key and answer.

Signatures authenticate what the service said. They do not establish source
truth, complete coverage, installed-file identity, exploitability or safety.
The product's browser checker presents evidence but does not itself verify
signatures. Use the maintained verifier for decisions that require that proof.

## Keep findings, conditions and fixes separate

An affected-version match is source evidence about a public version. Preserve it
when the environment is inactive or local exposure is unknown. Evaluate necessary
conditions only against explicit, dated target facts; never assume the target OS
is the scanner's OS. Missing, stale, malformed or prose-only conditions remain
uncertain. A condition that does not match does not erase the version finding.

The [schema 2.4 evidence guide](assessment-evidence.md) separates source-listed
fixes from legacy inferred candidates. Check
source, affected branch, exact patch field state, provenance, corrected or withdrawn
records and evidence limits. An exclusive upper range boundary alone does not
prove a published fix. A null or absent patch field does not mean no fix exists.
A multi-branch list is not an instruction to install its greatest version.

Before describing an exact candidate as suitable for application testing, require
current verified original and candidate assessments from the same source revision,
complete supported coverage, available registry state, no unresolved warnings or
unknowns, explicit source fixes for every matched issue and branch, independently
verified installed identity and reviewed application compatibility. The client
helper returns no verified recommendation when these qualifications are absent.
Even its positive outcome is only candidate_for_application_testing; it never
chooses, downloads or installs an upgrade. Removal and vendor repair can be more
appropriate than a version change for malicious or supplier-managed software.

Unknown or no matching advisory is not a clean bill of health. Keep request
failure, unsupported identity, no match, stale source, partial history, truncated
output and unavailable context visible as distinct limits.

## Run within finite limits

The hosted baseline is 100,000 distinct successful coordinates per network address
per UTC day, 100 cache-miss attempts per ten seconds, origin ten requests per second
with burst twenty, and a recommendation of at most four concurrent requests.
The API deadline is ten seconds and the hosted MCP deadline is twelve seconds.
Shared addresses share quotas; these are ceilings, not throughput promises.

The initial client is more conservative: serial reads, at least 0.3 seconds between
request starts, a default five-minute overall budget (1–3,600 seconds configurable),
a ten-second request deadline, bounded response bodies and at most one delayed
retry for eligible temporary network failures or HTTP 502/503/504. A valid
Retry-After is respected with jitter and only when the delay fits the remaining
budget. HTTP 429 stops the run; do not evade the limit by changing addresses or
starting parallel copies. Other HTTP failures and hosted-MCP error results are
not successful empty assessments. Invalid inputs require correction, not retries.
Cancellation stops further coordinates; an in-flight connection/header wait can
last up to the request deadline. Remaining entries are explicitly not_run.

Deduplicate exact coordinates while retaining every installation and relationship.
Current assessment responses are Cache-Control: no-store. Keep original signed
bodies in memory only. The client saves derived private reports and minimal
progress references; resume rechecks every approved coordinate and never treats
an earlier saved conclusion as current evidence. An interrupted run does not earn
a fresh decision merely because time has passed.

## Read the local report

Reports group selected parent applications, installations, shared coordinates and
source evidence. Counts for installations, coordinates, incidents and source
reports are different. Unverified counts are separate from verified current
counts. The JSON, HTML and text files stay local with private permissions; HTML
contains no scripts, analytics or external resources. Source links are optional
user-initiated navigation, not automatic requests.

The derived JSON cap is 16 MiB. A result over 256 KiB retains compact outcome,
verification facts, incident IDs, counts and response digest, and is visibly
marked evidence_truncated. Later coordinates continue. Aggregate budget exhaustion
accounts for remaining coordinates as not_run. HTML/text have 24 MiB limits and
explicitly identify omitted display detail. Condition annotations have a 1 MiB /
10,000-row limit. These limits never imply complete coverage. Inspect export
status when a report could not be fully written.

The initial adapter is Linux only and requires Python 3.14 for its own runtime;
it does not provide an OS, container, generic Git or private-registry scanner.
See [complementary checks](complementary-checks.md) for supplier package versions,
backports and the qualified limits of container and Git evidence.
