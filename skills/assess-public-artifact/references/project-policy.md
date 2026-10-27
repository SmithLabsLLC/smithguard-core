# Project instructions, tooling notes and release runbook

These are templates to adopt deliberately in a chosen project. They are not
automatically installed or active. Merge the relevant text into existing files;
never replace their contents or weaken their current controls. Keep one maintained
policy and reference it from agent-specific files to avoid competing instructions.
Use the exact case `AGENTS.md` and `CLAUDE.md` where the harness expects those names.

## Suggested AGENTS.md or CLAUDE.md section

```markdown
## SmithGuard public-package evidence checks

For this project, use the assess-public-artifact skill and the connected SmithGuard
hosted tools before adding or upgrading an explicitly selected public dependency,
and at release readiness for the specific public coordinates authorized for that
release check. Recheck those selected coordinates for each release attempt, even
if the versions are unchanged. Do not add checks on every edit or agent turn.

Use exact ecosystem/name/version or supported immutable digest and public registry.
Do not enumerate or upload project files, private names, manifests, lockfiles,
SBOMs or dependency inventories to select SmithGuard requests. For a public package
the owner explicitly named, this policy permits the host agent to read only its
exact pinned version/digest and registry from the local release candidate's entry.
Send only that selected public coordinate, never the file or unrelated entries.
If the entry cannot be isolated, is ambiguous or is not exact, ask for the intended
coordinate. Without authorized file access, use the owner's curated exact public
check request in the release record or ask. Sending an inventory one package at a
time is still excluded. Say which dependencies and transitives were not checked.

Keep SmithGuard's evidence result separate from our project decision. Affected
coordinates hold the proposed addition/release decision for review. Possibly
affected, conflicting, unknown, stale/incomplete evidence, unavailable tools or failed validation
need review; they do not pass by default. An applicable owner-approved exception
can permit proceeding, but it must name the exact scope, reason and expiry and
must remain visible in the release record. Never invent an exception.

Review of an affected coordinate may conclude: decline its use or choose removal/
replacement through a separately authorized change; choose a different exact
version and check it separately; or proceed under an owner-approved exception
with exact coordinate, release scope, reason, approver reference and expiry.
The last option keeps the evidence result affected and records proceeding under
exception. Review alone grants no permission to remove, upgrade or deploy.

Record preliminary_warnings with their claim, confirmation_status, expires_at and
source_urls even when the main result is not_affected. Do not hide registry_state,
especially removed, yanked, deprecated or unknown. These are separate context, not
new security verdicts. A not_affected step is complete only with that context
recorded and any review required by our adopted policy resolved. Unverified
warnings never authorize automatic disruptive action.

Not affected applies only to evaluated evidence, and never means safe. Complete
our normal dependency audits, integrity checks and tests. Do not claim signature
verification unless it actually ran. Do not upgrade, delete, deploy or contact
anyone merely because a SmithGuard tool returned information.

Keep the check scope, results, unknowns, source links, times, verification status
and project decision in the existing release record. See our release runbook for
the decision owner, release-candidate identity check and exception procedure.
```

This recommended policy holds uncertainty for review. A team may choose an advisory
policy instead; document that choice explicitly and continue to expose unresolved
evidence. Do not pretend the advisory policy is an enforced security gate.

If AGENTS.md already owns the shared policy, a CLAUDE.md entry can simply say:

```markdown
Before changing dependencies or preparing a deployment, read and follow the
SmithGuard public-package evidence-check policy in AGENTS.md and our release
runbook. Use the installed assess-public-artifact skill for the actual lookups.
```

This explicit reading instruction avoids assuming every harness supports another
harness's file-import syntax. Refer to an actual existing path in your project;
do not add a link to a runbook that does not exist.

## Tooling documentation entry

```markdown
SmithGuard is a hosted, read-only evidence service. Connection:
https://api.smithguard.io/mcp (Streamable HTTP).
Skill: assess-public-artifact, pinned package version recorded with installation.

Inputs: explicitly selected public package coordinates with exact version/digest;
never project files, private registries, secrets or dependency inventories.
Core workflows: assess_public_artifact, get_coverage, get_verification_key;
get_emerging_leads only for a separately requested unverified-report lookup.
The harness supplies the actual tool namespace; discover it rather than guessing.

Connection configured, tools available, skill loaded, lookup completed and signature
verified are distinct states. Report each honestly. A disconnected tool is not a
successful check. See the installed skill's references/install.md for setup.
```

## Release runbook checklist

Before adopting this checklist, name the release decision owner, where the release
record lives, the specifically authorized public-coordinate selection process, the
policy for uncertain evidence, any evidence-reuse window and who can approve a
time-limited exception. Do not fill these roles with invented people or silently
change a current release policy.

1. Identify the release candidate using the project's existing local process.
2. Confirm that the selected exact public coordinates correspond to that candidate
   and are intentionally authorized for SmithGuard lookups. This selection is not
   a private inventory export. For an owner-named public package, the adopted policy
   may allow a narrow local pinned-entry read. Otherwise obtain an owner-curated
   exact public check request. Record excluded scope locally.
3. Confirm the pinned skill version and hosted connection. Fetch coverage and
   perform the named lookups. Record actual failures and not-run checks.
4. Review result semantics, evidence sources, source freshness, unknowns, response
   completeness, preliminary warnings/status/expiry, registry state and actual
   signature-verification status. Preserve all findings and source links.
5. Apply the adopted project policy. An exception needs an actual approver,
   reference, exact artifact/release scope, rationale and expiry. Revalidate it
   when relevant evidence changes; do not carry it forward indefinitely.
6. Complete the project's existing audits, tests, integrity and deployment checks.
   A SmithGuard step cannot waive them or authorize deployment by itself.
7. Record the final project decision and selected-check coverage. If delayed or
   changed beyond policy, return to the affected check before deployment.

## Example request to an agent

```text
Use assess-public-artifact to review these two public coordinates before we decide
whether to add them: npm event-stream 3.3.6 and npm is-number 7.0.0. These are the
only coordinates authorized for this check. Do not read project files or install
anything. Show current evidence, source freshness, unknowns and the next decision.
```

These examples are real public coordinates, not recommended dependencies or fixed
expected results. Always report the service's actual current answer.

## Separately authorized local-client workflow

The default named-package workflow above does not authorize inventory discovery.
A user may separately select the maintained Linux/Python client's exact local
metadata scopes and public coordinate assertions, review its local preview, and
approve that exact egress hash. This narrow route does not permit manifest,
lockfile, SBOM, source or private-inventory uploads, guessed public identities or
broader enumeration. Paths, relationships, activity and target facts stay local.
Read the [canonical operating guide](https://github.com/SmithLabsLLC/smithguard-core/blob/main/docs/operating-guide.md); preserve incomplete scope, unverified
identity, source limits and fresh rechecks after interruption. Any upgrade or
release decision still follows the project's independently adopted authority.
