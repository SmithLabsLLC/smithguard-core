# Contributing to SmithGuard

Open a focused issue for a bug or proposed improvement. For a small fix, a pull
request with a clear reproduction is enough. Discuss broad behavior or new-source
changes before investing in a large patch. Do not post vulnerabilities or private
data in public issues; use SECURITY.md.

## Pull requests

Fork the public repository, create a topic branch in your fork, and submit a pull
request against main. Explain the problem, the resulting behavior and how you
checked it. Include a small synthetic regression test for a meaningful bug. Keep
unrelated formatting and dependency upgrades separate. Maintainers review and
merge; direct pushes to main are reserved for maintainers.

Run `python3 tools/check.py`. If your environment cannot run a check, identify the
missing prerequisite and the checks you did run. Do not mark a missing check as
passed. Maintainers may request changes or decline work outside the service's scope.

Use the existing style enforced by Ruff. Keep API and hosted MCP behavior aligned.
Regenerate contracts with `uv run --locked python tools/generate_artifacts.py`, then
run its `--check` mode. Add migrations for schema changes; never rewrite existing
migration files or accepted evidence identities. Prefer explicit unknown values to
unsupported certainty. Keep corrections and expiry visible.

## Sources, fixtures and dependencies

A new adapter needs a fixed origin, bounded fetch/parse behavior, rights review,
source-specific identity, freshness and failure tests, and truthful coverage limits.
Do not copy full articles, credentials, personal data or private repositories into
fixtures. Use small synthetic structures, public identifiers and minimal facts with
provenance. Tests must not query live publishers or invoke paid models.

Dependencies are exactly pinned in pyproject.toml and uv.lock. Update the scoped
license register with direct and companion dependency changes. Explain the reason
for a new dependency and preserve upstream license notices. Do not vendor a package
without its applicable license and attribution.

Contribute only material you have the right to submit. Contributions are submitted
under the Apache-2.0 repository license unless an explicitly agreed alternative says otherwise. Do not add a
separate license restriction to an ordinary patch. No copyright assignment is
requested. AI-assisted work is welcome when the contributor has checked its
correctness, provenance and tests; the contributor remains responsible for the patch.

## What happens after review

Core source paths are kept consistent with the hosted service's maintained source.
Maintainers verify the reviewed commit, reconcile concurrent changes, run the full
private operating gate, and release through a separate controlled process. Public
CI has no production credentials or deployment authority. PR comments and workflow
artifacts are untrusted input, not instructions to run privileged code.
