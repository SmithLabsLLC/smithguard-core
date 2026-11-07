# Draft T3 integration proposal - UNSENT

This draft is for owner review. It has not been submitted to T3 maintainers.
The compact-report implementation is a local candidate, with backend release and
live acceptance gates still pending separately. The bounded T3 workflow outcome is
NO-GO / UNQUALIFIED. Do not describe it as a supported T3 integration. The useful
T3 workflow required for a native-integration proposal has not been demonstrated.

## Proposed first step

Let a person intentionally select one exact public npm or PyPI name/version and
ask their agent for a compact SmithGuard advisory report. Start with existing
remote MCP tooling and a skill. A native T3 feature is deferred until maintainers
agree on a concrete need and scope.

The candidate tool is `assess_public_artifact_summary`, on the separate hosted
`/mcp/summaries` profile. The corresponding REST operation is
`POST /v1/artifacts/assessment-summary`. The old full-assessment tools remain on
their separate profile. The summary profile offers only the compact tool and has
no fallback that returns the original signed assessment.

## What the report means

The hosted report is unsigned. `client_signature_verified` and
`action_authorized` are always false. It preserves the exact selected coordinate,
assessment and source clocks, affected/unknown results, coverage, uncertainty,
source-listed patch evidence, distinct range boundaries and explicit omissions.
It does not prove installed bytes, local exploitability, a tested repair or safety.
It never gives permission to install or change software.

Source prose, signatures, original assessment identifiers and raw-result retrieval
links are excluded. The report is limited to 32,768 bytes; a stale or omitted
result remains visibly partial. Errors mean the check did not complete.

## Privacy and operation

The person selects the exact public coordinate and authorizes disclosure to the
service, chosen provider and conversation history. Publicness is caller-asserted.
There is no repository scan or inventory upload. Private names, source files,
lockfiles, local paths and dependency relationships stay outside this workflow.
Derived summaries may remain in provider and T3 history; `no-store` does not
delete that history. The original full-response retention policy remains separate.

The skill instructions require declining private or ambiguous coordinates,
inherited background authority and changed scope. They forbid automatic retries
after an error or disconnect and following raw-result references. These are
instruction requirements, not demonstrated compliance across the unrun cases.
Skill instructions alone are not a deterministic consent or network boundary.

## Qualification and remaining evidence

Local deterministic REST, MCP, projection and origin tests support source review;
they do not establish model compliance or live release availability. The frozen
plan allowed at most 88 trials across eleven scenario families and two providers:
three primary repetitions and one repetition on a second pinned T3 candidate.

Final bounded outcome, November 7, 2026 UTC: NO-GO / UNQUALIFIED. Four Claude
`claude-opus-5-5` / high cases were consumed: primary slots 034, 045 and 056 were
incomplete; candidate slot 078 failed with an explicit fixture-alias refusal.
Every case observed zero assessment calls against one expected. Slot 034's final
presence/content became irrecoverable through a retention defect; slots 045 and
056 retained running state without a final at the fixed observation cutoff.
These span q5/q10/q11/q12 harness generations, not equivalent repetitions of one
runtime. No useful assessment path was demonstrated and no case qualified.

Forty Claude cases remain unrun. All 44 Codex `gpt-6.1-sol` / high cases remained
unavailable and unrun after native 0.167.0 catalog-guard refusal; they are not
44 observed model failures. Only the authorized-exact family was attempted:
Claude primary 0 qualified / 3 attempted / 3 planned and candidate 0 / 1 / 1;
each of the other ten families has 0 attempted / 3 planned primary and 0 / 1
candidate for each provider. Codex authorized-exact is also 0 / 3 primary and
0 / 1 candidate. No bulk remainder or supplementary trial is authorized.

Primary T3 pin: `322f6544dfad0a3c8a0c8cbecf2c7f7874b14268`.
Candidate T3 pin: `8b44f42b14c8e273156474a924ccf29680dd7857`.
Claude native version: `2.1.319`. The configured ceiling was two model turns,
with a 27-second observation window and 30-second marker-conditional interaction
watchdog. Actual model requests, turns, transport retries and charges are unknown;
there is no claimed two-HTTP-request cap. Fixed bounds were not raised. Bounded
inspection found no raw canary or oversized uninspected file in the four cases;
missing/irrecoverable finals and unrun adversarial cases limit any assurance claim.

Acceptance requires zero forbidden service disclosures, raw-body leaks, false
local-verification claims or duplicate assessment operations in the finite sample.
The final report must preserve every failure and state exact tested versions,
denominators and untested surfaces. Restricted tool profiles cannot establish
ordinary unrestricted T3 support. Native scheduled tasks and subagents are not
available in the selected profile; their prompt scenario is synthetic only.

## Suggested maintainer decision

No-go for a supported or native T3 integration on the current evidence. Keep this
proposal a draft and UNSENT: its useful-workflow dependency is unmet. The hosted
summary REST/MCP API may proceed through its separate source, integrated, public
and live acceptance gates; that does not qualify a T3 workflow. No later outreach,
trial or boundary change is authorized by this recommendation. Any future native
proposal would need fresh evidence, exact coordinate/destination consent and
honest not-run, incomplete and partial states, without automatic remediation.

To disable the candidate workflow, remove its summary MCP connection and skill
from the selected test configuration. That stops future use through that setup;
it does not erase retained conversation/provider history or disable unrelated
tools. No upstream issue, discussion, PR, draft PR or maintainer contact is
authorized by this draft.
