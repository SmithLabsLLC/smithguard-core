# SmithGuard

Evidence-first software supply-chain assessment and security bulletin service.

SmithGuard connects public advisory and package evidence to exact package versions
and artifacts. It keeps confirmed facts, uncertain reports and missing evidence
separate. A warning does not mean an installation is affected, and a lack of known
findings does not establish safety.

This repository contains the service core: API and hosted MCP handlers, evidence
validation, advisory collectors, version/range evaluation, official-source bulletin
processing, database migrations, contracts and contributor tests. The hosted service
is available at [smithguard.io](https://smithguard.io). Its current API and source
coverage are described by the [live API contract](https://api.smithguard.io/openapi.json)
and [coverage document](https://api.smithguard.io/v1/coverage.json).

## Use the agent skill

The [assess-public-artifact skill](skills/assess-public-artifact/SKILL.md) teaches an
agent to check one explicitly selected public package or image through the hosted
SmithGuard service. Version 0.3.0 includes installation, result interpretation,
before-addition and before-deployment workflows, and opt-in project policy templates.
Read the [installation guide](skills/assess-public-artifact/references/install.md)
and [release notes](docs/agent-skill.md). Keep all six files together.

These are instructions, not a local scanner, server, automatic deployment gate or
permission to inspect private inventories. The service runs remotely. Installing
a skill and connecting its hosted tools are separate setup steps.

## Optional local Python client

The [client](clients/python/README.md) reads metadata from Linux directories you
explicitly select, shows a local public-coordinate preview, and requires approval
before hosted requests. Reports and local relationships stay on your computer.
It does not install fixes, upload files, provide a local assessment database or
scan every environment. Read the [operating guide](docs/operating-guide.md) and
[coverage limits](docs/complementary-checks.md) before use.

## Work on the code

The supported contributor environment is Linux, including Linux under WSL, with
Git, PostgreSQL server tools, system Python **3.10 or newer**, and uv **0.13.4**. The project pins Python **3.14.7**
and all Python dependencies. Tests create isolated temporary PostgreSQL clusters
with Unix sockets and no TCP listener. Run them as a normal user, not root.

On Ubuntu, install prerequisites with your package manager:

```sh
sudo apt-get install git postgresql postgresql-contrib pipx
pipx install uv==0.13.4
pipx ensurepath
```

Open a new shell if uv is not yet on PATH. Clone the repository and run:

```sh
git clone https://github.com/SmithLabsLLC/smithguard-core.git
cd smithguard-core
uv python install 3.14.7
uv sync --locked
uv run --locked pytest -q tests/test_version_order.py
python3 tools/check.py
```

The full check also audits locked dependencies over the network. Contributor tests
use synthetic/local state and do not need cloud credentials, a running SmithGuard
service or paid inference. See [development](docs/development.md) for focused checks,
platform limits and generated files.

## Contribute

Bug fixes, parser fixtures, range-evaluation cases, API improvements and clearer
documentation are welcome. Start with a focused issue or pull request and describe
the behavior you want to improve. Read [CONTRIBUTING.md](CONTRIBUTING.md),
[the architecture](docs/architecture.md) and [the code of conduct](CODE_OF_CONDUCT.md).
Report sensitive vulnerabilities using [SECURITY.md](SECURITY.md).

The public source is the contribution surface. The production deployment controller,
operator records, credentials, databases and marketing website are maintained
separately. Merging a pull request does not deploy it. Maintainers integrate reviewed
core changes into the hosted service and run its additional deployment checks.
Local development is supported for contributing; no managed self-hosting support or
service-level commitment is offered. The code license governs reuse rights.

## License and data

The code is licensed under Apache-2.0. See [LICENSE](LICENSE) for the
terms and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency and fixture
attribution. Upstream advisory content and hosted datasets retain their own terms;
the code license does not relicense them. SmithGuard and Smith Labs names are not a
trademark license or an endorsement of forks.
