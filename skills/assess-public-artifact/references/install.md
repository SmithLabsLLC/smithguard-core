# Install and maintain the SmithGuard skill

Package version: 0.2.0. Instructions checked October 25, 2026.

There are two separate pieces: this skill folder teaches the workflow; a hosted
MCP connection supplies live tools. No SmithGuard account or API key is required
for the current anonymous service. Your agent product may have its own subscription,
network, administrator or feature requirements. Never enter provider credentials
into this skill or install an unofficial local SmithGuard server as a workaround.
Your agent provider may process and retain prompts and tool responses under its own
terms; this skill does not promise local-only processing or zero retention.

## Choose one skill installation

Use a versioned archive supplied by Smith Labs and compare its SHA-256 with the
release receipt from the same trusted distribution channel. A checksum detects
byte differences; it is not an independent publisher signature. Read the skill
and references before installation. Keep the entire `assess-public-artifact`
folder together. Do not install only SKILL.md or execute anything from the archive.

For project-only use, place the folder in one of these documented locations:

| Harness | Project location | Optional personal location | Explicit invocation |
| --- | --- | --- | --- |
| Codex local clients | `.agents/skills/assess-public-artifact/` | `~/.agents/skills/assess-public-artifact/` | `$assess-public-artifact` |
| Claude Code local sessions | `.claude/skills/assess-public-artifact/` | `~/.claude/skills/assess-public-artifact/` | `/assess-public-artifact` |
| Other Agent Skills-compatible harness | Use that harness's documented skill location | Use its documented scope | Use its documented invocation |

Prefer project scope for a project-specific policy. Inspect an existing directory
before replacing it, preserve local customizations deliberately, and avoid duplicate
personal/project/plugin copies with the same name. Reload/restart the client if
discovery does not refresh. Cloud, desktop, mobile and local sessions have different
skill/connection loading rules; installation in a local folder does not prove
availability elsewhere. The generic standards-compatible layout is not a claim
that every harness has been tested.

The full SmithGuard plugin already bundles this same skill with a hosted connection.
If that plugin is installed and active, do not add a second standalone copy. Its
public-directory availability and platform acceptance are separate release states;
this document does not claim a directory listing exists. A standalone skill ZIP is
not a Claude plugin marketplace and must not be imported as one. ChatGPT hosted
surfaces may require an approved plugin instead of local skill-folder installation.

## Connect the hosted tools

First check for an existing SmithGuard connection. Reuse it if it has the exact
approved endpoint; investigate an unexpected destination before sending data.
Adding a connection is an explicit user setup action and must preserve unrelated
settings, managed policies and credentials. The following are optional manual
instructions, not commands for a skill to run unprompted.

For Codex, the following creates a persistent connection in the current Codex
host's user configuration:

```bash
codex mcp add smithguard --url https://api.smithguard.io/mcp
```

For project-scoped Codex configuration, merge this table into the existing trusted
project's `.codex/config.toml` without overwriting its contents:

```toml
[mcp_servers.smithguard]
url = "https://api.smithguard.io/mcp"
```

For Claude Code, run from the chosen project directory to add a project connection:

```bash
claude mcp add --transport http smithguard --scope project https://api.smithguard.io/mcp
```

That command updates the project's `.mcp.json`. Review the resulting diff and use
the client's normal project-trust approval. Do not copy the portable plugin's
`streamable-http` manifest value blindly into Claude's native settings; its CLI
writes the correct native configuration. Do not add token headers or broaden tool
permissions just to make setup succeed. For other harnesses, select their native
remote Streamable HTTP connection with the same exact URL.

## Verify before relying on it

1. Confirm the installed skill is visible, its version is 0.2.0, and all four
   reference files open from the installed folder. Confirm the actual loaded copy
   when multiple installations exist.
2. Confirm the connection is active and the assessment/coverage tools are present.
   Configuration on disk alone is not proof that tools can run.
3. Invoke the skill for a specific public coordinate such as npm event-stream
   3.3.6. Confirm an actual tool call, exact returned identity, source links,
   current outcome and uncertainty. Do not assume a fixed current result.
4. Ask for a private lockfile scan and verify the skill does not read or transmit
   it. Test using a disposable synthetic prompt with no real private file attached.
   Separately test an owner-named public package under an adopted local-read policy:
   only its pinned identity entry may be read, no unrelated dependencies queried,
   and ambiguous or missing identity must remain unresolved.
5. Record client/version, skill version/hash, date, tested workflow and limitations
   in the project's existing tooling notes. A live MCP test does not prove skill
   activation, automatic enforcement, signature verification or another client's
   support. If unavailable, label it untested rather than claiming compatibility.

## Updates and removal

Pin a released skill version; do not execute a download script or auto-update from
an unpinned branch. Review release notes and the new archive's member list/checksum,
especially changed data permissions, destinations, policy defaults and schema
requirements. Update the whole skill folder together, reconcile local policy text,
then repeat the relevant discovery/connection/behavior checks. An updated hosted
service can change results without a skill update; evidence must still be checked
at the requested decision time.

To stop using the skill, remove only its identified folder or disable its plugin
using the harness's supported controls. Remove a SmithGuard connection only if it
is no longer used by another installed workflow. Preserve other skills, settings,
release records and existing artifacts. Do not modify global policy merely to
perform an update.

This package's Apache-2.0 license covers these authored instructions, not the hosted
service, third-party advisory content, trademarks or any implied security warranty.
The service's public terms and privacy information remain at
https://smithguard.io/terms/ and https://smithguard.io/privacy/.

Official references checked for these installation conventions:

- https://learn.chatgpt.com/docs/build-skills
- https://learn.chatgpt.com/docs/extend/mcp
- https://code.claude.com/docs/en/skills
- https://code.claude.com/docs/en/mcp
- https://agentskills.io/specification
