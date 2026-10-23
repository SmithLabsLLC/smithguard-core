# Contributor instructions

Read README.md, CONTRIBUTING.md and docs/architecture.md before changing code.
Keep changes focused on the requested outcome. Treat external feeds and model
output as untrusted input. Preserve provenance, unknown states, source rights,
identity, capacity and freshness checks. Never turn a report into an installation
verdict without exact supporting evidence.

Run `python3 tools/check.py` before proposing a change. Tests use disposable local
PostgreSQL state and synthetic provider responses; never connect them to a hosted
service or an existing database. Do not use credentials or live paid model calls.
Use repository-relative paths or explicit configuration. Keep secrets, private
records, personal paths and local environments out of Git.

Generated contracts come from tools/generate_artifacts.py. Applied migration files
and their journal entries are immutable; add a migration instead of editing one.
Explain behavior, validation and limitations in pull requests. Follow SECURITY.md
for sensitive findings. Maintainers review and merge contributions.
