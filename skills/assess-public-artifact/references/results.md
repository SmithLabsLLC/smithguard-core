# Interpreting a SmithGuard answer

The live tool schema and https://api.smithguard.io/openapi.json define the wire
contract. This guide describes assessment schema 2.3.0 as checked October 25,
2026; older retained signed answers may use earlier versions. Do not silently
reinterpret an unknown future schema as 2.3.0. Preserve the service's values.

## Evidence result and project decision are different

| Returned `data.result` | Explain it as | Recommended action in an adopted project policy |
| --- | --- | --- |
| `affected` | Matched evidence identifies this exact artifact as affected. Explain which incidents and conditions apply. | Hold the proposed addition or release decision for this coordinate; present evidence and options. No automatic upgrade or deletion. |
| `possibly_affected` | The evidence does not settle applicability. | Needs review under the project's uncertainty policy. |
| `conflicting` | Relevant evidence conflicts; the service has not resolved it into a single applicability conclusion. | Needs review of the conflicting evidence; do not select the most reassuring report. |
| `not_affected` | The evaluated evidence does not identify this coordinate as affected within its stated scope. | The SmithGuard step may be complete if identity, freshness and completeness are satisfied, preliminary warnings/registry context are recorded, and any project-required review is resolved. This does not authorize deployment or prove safety. |
| `unknown` | There is insufficient applicable evidence to decide. | Needs review or a valid, already-approved project exception; never silently pass. |

These are recommended project-policy responses, not service enforcement. An
existing approved project policy determines whether an unresolved check stops a
release. Without one, report the unresolved finding and request the needed
decision; do not invent a new mandatory gate for unrelated work. If an exception
allows work to proceed, keep the original evidence result visible and record
"proceeding under project exception", not "SmithGuard passed".

Review of an `affected` coordinate may decide to decline its use or remove/replace
it through separately authorized work; select a different exact version and assess
that separately; or proceed under an owner-approved exception. That exception
must name the exact coordinate, release scope, justification, approver/reference
and expiry. Keep `affected` in the record and say "proceeding under exception".
Do not implement removal, replacement, upgrade or deployment just because review
identified one of those options.

Read `incidents`, `applies_to_version`, `affected_range_ids`, `fixed_versions`,
`aliases` and `upstream_urls` as supplied. Do not infer a version is fixed just
because it is newer. Do not merge different incidents based only on similar names.
`not_applicable_incident_count` records excluded incidents, not a clean bill of
health. `incidents_truncated`, per-incident `source_reports_truncated`,
`preliminary_warnings_truncated` or client-side
output truncation require a visible completeness warning. A partial answer cannot
close a check that requires the omitted evidence. Do not rerun indefinitely to
hide truncation.

Read `source_freshness`, `coverage` and `unknowns` together. A successful HTTP/MCP
call or recent `created_at` does not mean all upstream evidence is fresh. Keep
source-observation time separate from the time the answer was requested. Source
conflict, missing matches, unsupported comparisons and unavailable sources are
different limitations; report the actual reason.

Read the `preliminary_warnings` array, not just its truncation flag. Include each
entry's `claim`, `confirmation_status`, `expires_at` and `source_urls` in the
evidence/limits column or a clearly linked warning detail in the result report.
Preserve `state`, `warning_text` and relevant dates/final reason when supplied.
Do not turn `confirmation_candidate` into confirmed, or an expired entry into
an active warning or proof of safety. A `not_affected` answer with an unexpired
warning completes this evidence step only when that warning is recorded and any
review required by the adopted project policy is resolved. Warning disclosure
does not itself authorize automatic blocking, removal or other disruptive action.

## Registry context and signatures

`registry_state` and `registry_project_context` are not security verdicts.
Show the returned `registry_state`, including `removed`, `yanked`, `deprecated`
or `unknown`, in the evidence/limits column even when the main result is
`not_affected`. Unknown means availability is not established; it is not proof
the package was removed. Removal/yanking/deprecation may affect the project's
dependency decision without proving malware or a vulnerability. Do not hide that
context or override the project's policy for reviewing it.
For PyPI, an administrative state such as active, archived, deprecated or
quarantined belongs to the whole normalized project. It does not prove that the
requested version exists, is installable, is malware or is safe. Null/expired
context is unknown. Check its own `observed_at` and `valid_until`; do not refresh
those times in prose or extend them with an old assessment ID/feed revision.

`get_verification_key` returns the current public key with no arguments, or the
key for a supplied `public_key_id`. Retain the key identity in the signature.
An assessment is signed by SmithGuard; merely retrieving the key or seeing a
signature field is not cryptographic verification. Verification requires the
complete original assessment, including registry context, canonical JSON and the
matching Ed25519 key according to the published contract. Invalid verification is
a failed check. Unsupported or unperformed verification is **not verified**.
Never claim the signature proves every source statement is true or evidence fresh.
Do not modify signed fields or verify only the human-readable summary.

## Errors and other tools

Treat tool `isError`, an API `error`, invalid JSON, missing data, disconnected MCP,
unexpected identity/schema and network errors as failed or not-run checks. They
have no assessment result. Do not replace them with cached success or a made-up
`not_affected`. Honor `Retry-After` when supplied; MCP exposes it as `retry_after`
in the wrapper. For a transient read-only error,
make at most one delayed retry within the project's time budget; otherwise stop
the lookup and report the condition. Do not hammer a 429, bypass limits, rotate
addresses, disable TLS checks or switch to an untrusted mirror.

Use `get_coverage` without arguments for current collected-source information.
Use `get_emerging_leads` only when that separate workflow is requested: `limit`
is 1-100 and `after`, if used, is the exact returned cursor. Preserve citations,
unknowns and expiry. An empty feed may reflect paused publication. Bulletin and
lead observations are not signed exact-artifact assessments. Do not promote
their allegations to confirmed incidents or assume they apply to the project.

## A useful response

Use a short explanation plus a table when checking several authorized coordinates:

| Exact public coordinate | Checked at UTC | SmithGuard result | Evidence and limits | Project decision / next step |
| --- | --- | --- | --- | --- |
| The actual returned identity | Actual retrieval time | Exact result, or failed/not run | Source links, freshness, completeness, signature status | Complete, needs review, hold, or existing exception |

Do not fill this table with guessed results. Name the unchecked scope explicitly.
Local release notes may record the deployment identity, policy version and
decision, but those project details must not be sent to SmithGuard.
