# Dependency checks during project work

These workflows are optional project practices. They apply when the owner requests
them or adopts a project policy; installing the skill alone does not adopt a policy.
SmithGuard supplements the project's dependency audits, lockfile/integrity checks,
tests and release controls. It does not replace them or automatically block tools.

## Before adding or upgrading a dependency

Check the proposed exact public version or digest **before** installing, executing
its package scripts, generating code with it or implementing against it. If the
request names only a range or `latest`, obtain the intended exact public coordinate
from the owner or an already authorized public-registry lookup; do not install a
package to discover its version. This skill itself does not resolve ranges.

Send only the named coordinate. Report the result and apply the adopted policy in
[project-policy.md](project-policy.md). An affected answer calls for review of the
actual evidence and alternatives; a source-listed fix must be checked separately
before being selected. Package compatibility, maintenance, license and test results
remain separate decisions. Do not assume the newest release is safe or suitable.

If authorized implementation later selects a different version, registry or
digest, the old assessment does not cover it. Check the newly selected exact
coordinate before its use. A resolved dependency graph may contain other packages;
checking the named direct dependency says nothing about unchecked transitives,
build tools, plugins, action tags, base images or vendored code. Report that gap.

## Before deployment

At the project's release-readiness step, obtain the specifically authorized public
coordinates for this release check. Recheck existing selected packages even when
their versions have not changed: evidence can change. Default to fresh lookups
for this release attempt instead of relying on a previous deployment's answer.

For an existing public package the owner explicitly selected by name, an adopted
project policy may authorize the host agent to read its exact pinned version or
digest and registry from that release candidate's local manifest/lockfile entry.
This is a narrow identity lookup for an already selected package, never selection
by file enumeration. Read only what reliably identifies that entry; do not list,
upload or query unrelated dependencies, private names, graph edges or file content.
If the entry is a range, several versions exist, or the agent cannot isolate the
identity reliably, report the ambiguity and ask for the intended exact coordinate.
Do not resolve it by installing/running a package or by dumping the whole lockfile.
Without authorized local access, use the owner's explicitly curated exact public
check request in the release record or ask for the missing version. An ordinary
private inventory cannot be relabeled as that check request.

This is a targeted evidence check, not a private-repository inventory scan. Do not
read manifests/lockfiles/SBOMs to enumerate requests, accept an exported private
inventory, or split a private inventory into many calls. If asked to check every
dependency, explain this boundary and mark that wider task **not run**. Ask for
the specific public coordinates the owner intends to disclose. A project wanting
a complete dependency audit should also use its separately approved local tooling.

The project's own release process must establish that selected coordinates match
the actual release candidate; SmithGuard cannot discover that relationship. Report
identity assurance as unverified if it has not been established. Never claim
"all dependencies checked" or "deployment cleared" from a few named lookups.

Record locally, under the project's existing data policy:

- Release attempt/candidate identity and project-policy version.
- Exact coordinates requested, selection scope, and explicit unchecked areas.
- Actual lookup time, returned assessment ID/feed revision/schema, source links,
  source freshness, unknowns, preliminary warnings with status/expiry/source links,
  registry state, truncation and signature-verification status.
- Evidence result separately from the project decision.
- Any existing exception's approver/reference, coordinate, release scope, rationale
  and expiry; missing, expired or mismatched exceptions do not authorize proceeding.

Do not transmit this local release record or project identity to SmithGuard. Do
not store raw responses against a `no-store` policy by inventing a cache; the
project can retain a minimal decision record with links/identifiers and honest
verification status. Follow the service's current published terms and the
project's retention policy for any separately authorized evidence retention.

If the release candidate, selected coordinates, relevant evidence or applicable
exception changes, reopen affected checks. If deployment is delayed past the
project's chosen freshness window, recheck. Choose that window before relying on
reuse; there is no universal "safe for 24 hours" promise. Without an adopted reuse
policy, recheck for the next release attempt. A fresh answer may still report a
stale source, and temporary PyPI context has its own shorter validity.

## Avoiding noise and accidental enforcement

One coverage call and one assessment per distinct authorized coordinate are enough
for a normal review. Avoid repeated checks for every file edit or agent turn.
An explicit release-readiness trigger and version change are useful boundaries.
Do not create a cron job, hook, CI workflow, paid task or automatic updater merely
because this skill is installed.

If connection, rate limits or incomplete evidence prevent a check, record the gap
and continue independent permitted work. The project's adopted policy decides
whether the release waits or a named exception is required. Do not silently
override that policy to make a deployment succeed. Conversely, do not impose a
new global blocking policy merely because the service is unavailable.
