# SmithGuard agent skill 0.2.0

The maintained skill source is in `skills/assess-public-artifact/`. The six-file
instruction-only distribution contains SKILL.md, the Apache-2.0 license, and four
references. It includes no executable, hook, local MCP server or automatic updater.
It does not inspect repositories or submit dependency inventories.

## Installation

Use the complete versioned folder with the client conventions in the
[installation guide](../skills/assess-public-artifact/references/install.md).
Codex local clients discover project skills under `.agents/skills/`; Claude Code
local sessions use `.claude/skills/`. Avoid duplicate installations and inspect
existing folders before replacing anything. Keep unrelated settings unchanged.
The hosted Streamable HTTP endpoint is `https://api.smithguard.io/mcp` and requires
no SmithGuard account or API key. The agent client may have its own requirements.

## What changed

Version 0.2.0 adds exact public-package workflows before adding or upgrading a
package and before a project-approved release decision. A project can explicitly
adopt a policy for selected coordinates; installation alone adopts no global
release gate. A scoped exception retains the original result and needs actual
project authority, exact identity/release, reason and expiry. Changes to evidence,
identity or expiry reopen the decision under the adopted policy.

The workflow preserves affected, possibly affected, conflicting, not affected and
unknown outcomes. Source freshness, incomplete evidence, warnings and registry
context remain part of the answer. Missing tools or evidence cannot become a
successful check. A signature field is not proof that the agent verified it.
No automatic installation, upgrade, removal, deployment or communication follows.

## Distribution and limits

Smith Labs maintains the authored instructions alongside the hosted API contract.
Public source hosting, a downloadable archive and an accepted marketplace listing
are separate states. This source publication does not claim a marketplace listing,
cloud/mobile compatibility, complete detection coverage or guaranteed enforcement.
Other Agent Skills-compatible clients require their own discovery and workflow
checks. Agent providers may retain prompts and tool responses under their terms.

Use the release checksum to detect changed download bytes. It is not an independent
publisher signature. Review new instructions and changed data permissions before
updating the whole folder; do not install from an automatically changing branch.

The [project-policy template](../skills/assess-public-artifact/references/project-policy.md)
is guidance for explicit adoption in a chosen project. It has not been installed
in arbitrary projects. Hard enforcement needs a separately designed and authorized
project release gate.


## Dated client qualification

The following checks were completed on October 25, 2026 using skill 0.2.0 in
disposable synthetic projects and deliberately selected public packages. Results
are observations for these local CLI versions, not a guarantee for every agent run.

| Qualification level | Codex CLI 0.164.0 | Claude Code 2.1.310 |
| --- | --- | --- |
| Project skill discovery and loading | Verified, with explicit skill invocation | Verified in the native skill catalog and through skill invocation |
| Installed references | All four opened from the installed folder | All four opened from the installed folder |
| Hosted workflow | Coverage and exact public assessment calls completed | Coverage and exact public assessment calls completed |
| Before-addition and release reports | Affected and unknown results held for review under an adopted test policy; unchecked scope shown | Same bounded workflows verified |
| Missing input, private inventory and disconnected tools | No guessed version, inventory read or invented successful check | Same bounded cases verified |
| Selected local entry and unrelated work | One specifically authorized pinned entry read; unrelated-work control made no calls | Same bounded cases verified |
| Cryptographic signature verification in these skill runs | Not performed; reported as unverified | Not performed; reported as unverified |

The affected example used public npm `event-stream` 3.3.6. The uncertain release
example used public Swift `apple/swift-argument-parser` 1.5.0. These were results
at the test time; use fresh evidence for a new decision. The local-entry test
supplied the selected entry's location in advance and does not establish reliable
entry discovery across arbitrary lockfiles.

Separate structured interpretation tests covered nineteen supplied synthetic
scenarios per client, including warning/registry context, stale or incomplete
answers, source injection and changed-version or expired exceptions. The current
fixture grades pass using eighteen unchanged scenarios from a prior run plus a
fresh rerun of one corrected scenario. Initial strict runs scored 16/19 and 18/19;
clarifying the observation output conventions without changing the expected
decisions yielded 19/19 per client before that one-case wording correction.
These are interpretations of supplied
states, not actual hosted fault injection, observed exception enforcement or
unattended deployment interception. No signature verification, detection-recall
or customer-demand result is inferred.

This qualification does not establish a marketplace listing or support for
cloud, mobile, IDE or other client versions. Installation, live tool availability,
workflow completion and signature verification remain separate states.
