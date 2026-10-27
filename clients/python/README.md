# SmithGuard optional local client

This tool reads Python package metadata from Linux directories you select. It
shows an exact list of public package versions before sending any requests to the
hosted SmithGuard service. It does not install or upgrade dependencies, execute
package code, scan your home folder, upload files, or run an assessment database.
Python 3.14 is the initially qualified tool interpreter; the inspected environment
can use a different Python version because its code is never run.

## Install the released client

Download the wheel, source archive and `SHA256SUMS.txt` from the
[client 0.1.0 release](https://github.com/SmithLabsLLC/smithguard-core/releases/tag/client-v0.1.0).
Keep all three in a new directory you control and compare the checksums before
extracting or installing. Checksums detect changed bytes; they are not an
independent publisher signature. The wheel contains the client; the source archive
supplies its exact dependency lock and notices.

With Linux, Python 3.14.7 and uv 0.13.4 available, use a dedicated tool environment:

```sh
sha256sum --check SHA256SUMS.txt
tar -xzf smithguard_client-0.1.0.tar.gz
uv sync --locked --no-dev --no-install-project --project smithguard_client-0.1.0
uv pip install --python smithguard_client-0.1.0/.venv/bin/python --no-deps smithguard_client-0.1.0-py3-none-any.whl
smithguard_client-0.1.0/.venv/bin/smithguard-client --help
```

Run the later examples with that full executable path, or activate only that
dedicated tool environment. The lock pins transitive dependencies as well as the
four direct requirements; do not silently substitute a newly resolved dependency
set. Installation downloads dependencies from their package provider. No package
metadata scan or SmithGuard assessment happens during installation. To remove the
tool, delete only its dedicated environment and extracted release directory;
your selected environments and reports are separate.

## Preview first

Install the reviewed wheel in an isolated tool environment. Check its release
SHA-256 before installation. Do not install into an application or system Python.
The console entry point is `smithguard-client`; `python -m smithguard_client` also
works inside the tool's isolated environment.

```sh
smithguard-client preview \
  --scope /absolute/path/to/environment/lib/python3.12/site-packages \
  --public public-demo==1.0 \
  --application 1:public-demo \
  --output /absolute/private/parent/new-preview
```

This example is synthetic. Select the real metadata directory yourself. Each
`--public NAME==VERSION` is your explicit assertion that the local coordinate is
public; it is not permission to send it yet, and does not prove that the installed
files are the public package. Private packages can share public names. Skip any
uncertain identity. The tool never looks up a name to discover whether it is public.
Repeat `--scope` for up to 32 directories and `--public` for each selected exact
coordinate. The optional application argument uses the 1-based scope number and
the explicitly selected root package name. It records declared metadata links;
it does not prove that the application loads a dependency.

Read `preview.txt` and `preview.json` in the new directory. The text file lists
exactly what would leave. The JSON also shows every discovered installation,
local paths, relationship evidence and gaps. The preview makes no network requests.
No administrator permission is needed. All directory components must be real
rather than symbolic links; select the actual directory explicitly if necessary.
Editable/direct-origin packages, local versions, ambiguous metadata and unreadable
entries are skipped with reasons. Common `.pth`, `.egg-info` and `.egg-link` entries
remain discovery gaps, including virtual-environment or setuptools path hooks.
Their presence keeps scope incomplete and causes exit 2; the client never runs
those hooks or assumes they are harmless. Path hooks and package imports are never run.

## Explicitly approve disclosure

After inspecting the preview, copy its complete SHA-256 into:

```sh
smithguard-client run \
  --directory /absolute/private/parent/new-preview \
  --approve THE_EXACT_PREVIEW_SHA256 \
  --budget-seconds 300
```

This is explicit consent to send that exact public coordinate set. The tool rereads
metadata and refuses if the preview changed. Only public ecosystem, registry,
package name and exact version are sent. The service and hosting path also see
your network address, timing and protocol metadata. A set of public packages can
reveal private use. Paths, environment/application names, dependency relationships,
private names, source code, lockfiles, credentials and local facts stay local.
There is no telemetry, account, remote upload or third-party URL fetch.

The tool sends serial HTTPS requests to api.smithguard.io, ignores environment
proxies and credentials, refuses redirects and cookies, bounds responses to 1 MiB,
and gives a request at most ten seconds. It retries an eligible transient read
once with delay/jitter only when the run budget allows it. A quota response stops
the run. Ctrl-C and termination signals request cancellation; an in-flight request
ends within its request deadline. HTTP errors are run failures, not safety verdicts.

## Read the local report

The run creates private JSON, text and HTML reports, plus a minimal state file.
The HTML works offline with no scripts or network resources. It groups installations
by explicit application roots, leaves uncertain ownership unassigned, and links
duplicate installations to one shared coordinate result. Counts separate
installations, checked coordinates, incidents and source reports. Active use stays
unknown; neither old directory names nor access times establish inactivity.

The report preserves source findings, conditions, severity, dates, known limitations
and source-specific fixes. A range limit is not a published patch. Empty fix fields
do not prove that no fix exists. A valid signature authenticates the service answer;
it does not prove source truth, installed identity or local exploitability.
`not_affected` means the assessed known evidence excludes that version. No match,
unknown coverage, stale sources, failed requests and unchecked signatures are
separate outcomes. None establishes safety. Fixes require parent application review.

State and derived reports are local exports, not response caches. Original signed
response bodies are never persisted. A report records the response hash and what
verification established at that time; the saved report is not itself a signed
service answer. Never use an old report as current evidence. Resume with:

```sh
smithguard-client run --directory /absolute/private/parent/new-preview \
  --approve THE_SAME_PREVIEW_SHA256 --resume state-PREVIOUS_RUN_ID.json
```

Every approved coordinate is checked again; previous completed work starts stale.
Scope, metadata, policy or tool changes require a new preview/run. Reports account
for completed, unchecked, failed, skipped and not-run installations. Partial discovery
and bounded-output failures remain visible. Exit 0 means checks and selected
discovery completed; it does not mean no vulnerabilities. Exit 2 means incomplete
work or invalid input. A complete approved subset can still exclude private items.

Directories use mode 700 and files mode 600. Keep them on a private local filesystem
outside shared or synchronized folders if you do not intend to disclose them there.
The tool does not upload or delete them. Delete your own preview/report directory
when you no longer need its local history. No crash-resume claim is made for a
power loss before the latest state write completes.

## Verification and local facts

The reusable `verify_assessment` function verifies original bytes with strict JSON,
source JSON Schema, expected coordinate, Ed25519, canonicalization and key identity.
It reports verified, invalid or unchecked. Offline keys may establish signature
math but cannot establish current revocation status. Retired keys are accepted only
in explicit historical mode and never support current decisions; revoked keys fail.

The live reader requests key revalidation and checks HTTP Date/Age, preserving
upstream age in a five-minute in-memory key-status bound. Missing/stale key freshness
metadata leaves the answer unchecked. Response age is separately bounded to five
minutes. The key and answer use the same HTTPS service, not an independent trust
anchor. Source freshness and source truth remain separate from both clocks.

Optional `--local-facts facts.json` reads a file in the preview directory owned by
you with mode 600 (`chmod 600 facts.json`). Other ownership or permissions are
refused.
Each installation ID maps to `target`, timezone-qualified `observed_at`, `evidence`
and a `values` object. These are explicit user-supplied facts about that target,
not facts inferred from the scanner. Only facts observed within five minutes are
used to compare source conditions. Older facts remain visible without lowering
priority. Missing conditions or facts stay uncertain. OR alternatives and AND
requirements remain distinct; original version findings are never removed.

`candidate_decision` is a narrow library helper, not a version picker or automatic
upgrade command. It checks an exact source-named patch against all current findings,
same source revision, key/answer/source freshness, registry state, completeness,
application compatibility and independently verified installed identity. It never
selects the largest branch version. At most it returns a candidate for application
testing. Missing, changed, conflicting or incomplete evidence yields no verified
recommendation. Real remediation requires separate authorization and application tests.

## Limits

Initial adapter: Linux, Python .dist-info/METADATA only. No recursive discovery,
Windows/macOS adapter, npm/OS/container inventory, Git ancestry, SBOM upload,
private registry, local MCP, hosted accounts or automatic remediation. Discovery
is capped at 5,000 directory entries, 128 KiB per metadata file, 16 MiB metadata
and 10,000 relationship edges. Skipped or bounded scope is explicit. These limits
are not coverage or accuracy claims. Derived JSON is limited to 16 MiB; local
condition annotations have a separate 1 MiB / 10,000-row budget. HTML/text indexes
are limited to 24 MiB and explicitly point to the complete companion JSON when
readable detail is omitted. Metadata relationships and application memberships
each have a 10,000-row limit; an exceeded limit remains a discovery gap. The synchronous library transport runs its
own event loop and must be called outside an already running asyncio loop.

## Contributor checks

From this client directory, use Python 3.14.7 and uv 0.13.4:

```sh
uv sync --locked
uv run --locked pytest -q tests
uv run --locked ruff check src tests
uv audit --locked --preview-features audit-command
```

Tests use synthetic metadata, generated signing keys and mocked requests. Select
a real temporary directory with no symlink ancestors when the machine's default
temporary root is a symbolic link; link refusal is part of the privacy boundary.
The service repository also tests interoperability with its independent signer.
The standalone client has no service/database dependency.

A single result over the 256 KiB detail budget keeps a compact outcome, signature
status, response digest, incident IDs and counts. It is marked evidence_truncated;
other coordinates continue. Only the aggregate report budget stops remaining
checks. Compact results cannot support local condition evaluation. Exit 2 also
marks incomplete evidence or interpretation. Unverified answers and their counts
are separately labelled and cannot support decisions. Stale supplied local facts
have their own visible not-evaluated status. Progress records separately report
which JSON, HTML and text exports were written, including rendering failures.

Every supplied fact set that cannot be fully evaluated makes interpretation
incomplete, with visible counts and exit 2. Facts are checked before requests and
again at evaluation time; stale-at-start facts trigger a CLI warning. Long runs
can make initially current facts stale; refresh them and make a separately
authorized recheck rather than treating old target facts as current. Assessment
timestamps tolerate at most 30 seconds of future clock skew, matching the key
HTTP-time check. Larger future timestamps remain not fresh and unqualified.

Service-side omissions also make evidence incomplete and cause exit 2: shortened
incident or warning lists, omitted source reports, and source context omitted at
its budget. Supplied local facts are not evaluated against these partial answers.
Full and compact reports retain the omission reasons and counts. The broader
`results_incomplete` reason is counted separately: missing patch evidence alone
stays a visible limit without implying the service shortened the evidence or
forcing exit 2. It still cannot support a verified upgrade recommendation.

A near-expiry cached answer may arrive outside the five-minute freshness bound.
It stays unchecked and the run exits 2. The client does not silently relax that
bound or repeat the assessment; authorize a fresh run when current evidence is
needed.
