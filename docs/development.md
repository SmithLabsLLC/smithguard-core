# Development

Use a normal, unprivileged Linux user. Python 3.14.7 and uv 0.13.4 are pinned;
PostgreSQL `initdb` and `pg_ctl` must be available. The test helper searches PATH,
`pg_config --bindir`, then the usual Linux PostgreSQL package directories. Windows
native execution is not supported; use WSL. macOS is not yet a verified full-suite
platform because some tests exercise Linux process and filesystem behavior.

All paths resolve from the checkout or an explicit argument. Temporary databases
are created under the platform's local temporary storage and removed at the end of
their test session. The suite checks that service installation directories remain
unchanged. Never point tests at an existing database or run the suite as root.

```sh
uv sync --locked
uv run --locked pytest -q tests/test_bulletins.py
uv run --locked pytest -q -n 4 tests
uv run --locked ruff check src tests tools migrations
uv run --locked ruff format --check src tests tools migrations
python3 tools/check.py
```

The final command validates the build lock, synchronizes exact dependencies, checks
generated contracts and the migration journal, checks dependency metadata, runs
style checks and tests, scans the public tree, and audits the locked dependencies.
Network access is needed for dependency installation and the vulnerability audit.
The tests themselves use local/synthetic providers. Do not add tests that call a
live model, need an account or send data to a production API.

Use `SMITHGUARD_TEST_WORKERS` to choose a positive worker count, up to sixteen.
Report actual test counts and any platform limitations; the supported contributor
suite currently has no skips. Tests associated with private production
controllers and historical operating records run in the maintainer environment,
not in this source distribution.

## Generated files and migrations

Edit reviewed definitions under contracts/v1, then run:

```sh
uv run --locked python tools/generate_artifacts.py
uv run --locked python tools/generate_artifacts.py --check
```

Commit the definition and generated output together. The generator must produce
identical bytes in check mode. Keep the public API and hosted MCP semantics aligned.
Never hand-edit generated Python, OpenAPI or schemas.

Existing migrations and journal entries are immutable. Add a new migration and
regenerate the journal using `uv run --locked python tools/migration_journal.py --write`.
Read the tool's help before adding flags. Check both migration behavior and narrow
database-role permissions with synthetic data.

## Credentials and configuration

Contributor checks require no credentials. Ignore local `.env`, `.secrets`, virtual
environments and databases. Tracked `.env.example` files contain placeholders only.
Runtime service paths such as `/var/lib/smithguard` are explicit Linux installation
conventions, not a contributor home directory; tests override them with temporary
state. Changing a service layout requires coordinated configuration and tests.

## Maintainer integration

Public pull requests are reviewed at an exact commit. The [source baseline](source-baseline.json) records the initial file hashes and
which files are byte-identical to maintained service files. Files marked shared=false
are public-edition packaging or isolated contributor tests and need manual reconciliation. Maintainers compare each proposed change against
that common base, preserve concurrent changes, and run the service's full checks
before release. An import must never overwrite private configuration or operate
from a patch supplied by an untrusted workflow artifact. Keep public contribution
attribution when integrating changes. Public CI does not deploy.

## Dependency updates and retained references

The gate launcher works with Python 3.10 or newer and selects the exact managed
Python from .python-version before validating the build lock. It does not replace
system Python. Dependencies are installed only after that lock check passes.

Dependabot updates pinned GitHub Actions weekly. Python dependency updates are
maintainer-reviewed changes using uv 0.13.4: update the exact pyproject.toml pins,
run `uv lock`, update dependency-license-register.json when applicable, and run
`python3 tools/check.py`. The gate includes `uv audit`. Dependabot's bundled uv
cannot satisfy this project's exact version requirement, so automated Python
update PRs are not configured. Reassess compatibility before enabling them.

References in shared source and reference deployment assets to docs/operations,
docs/plans, audit identifiers or omitted release tools refer to maintainer-only
material. They are not contributor setup prerequisites. Public checks do not need
those files; production controllers and operating records are excluded.
