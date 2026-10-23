# Preparation validation — October 23, 2026

This is an unpublished source preparation. License approval and public repository
creation are pending. These results describe local validation, not hosted CI,
production authorization or a complete security audit.

## Reproduce

Use an unprivileged Linux account with PostgreSQL server tools and uv 0.13.4:

```sh
python3 tools/check.py
```

The launcher supports Python 3.10 or newer and selects managed Python 3.14.7 for
the application checks. No cloud credentials, paid models or running SmithGuard
service are required. The locked dependency audit uses the public network.

## Results and evidence

- Final contributor gate: **2,537 passed, zero skipped**. Generated contracts,
  immutable migration journal, dependency pins, privacy guard, Ruff checks and
  formatting passed. The audit reported no known vulnerabilities or adverse
  project statuses in all 81 audited packages.
- The corrected launcher was also run using Python 3.10.22, an empty inherited
  environment and a fresh HOME. It installed the pinned Python/dependencies and
  passed 2,534 tests before the three archive-pacing regression tests were added.
- The earlier candidate passed 2,530 tests in a path containing spaces, with a
  fresh HOME and no inherited credentials. That earlier check preceded the
  privacy-guard cases, historical-metadata test removal and pacing repair.
- The final source scan has zero findings/errors from the four configured Python
  rules. Five redacted secret-scan matches are reviewed public/synthetic test
  identifiers; their file hashes and reasons are recorded below.
- All distributed migration files and the journal are byte-identical to the
  maintained service source. Applied migrations were not rewritten for release.

The complete sanitized gate outputs are [the fresh Python 3.10 run](clean-python310-check.log)
and [the final run](final-contributor-check.log). Machine/home-specific paths have
been replaced with `${HOME}`, `${CHECKOUT}` and `uv`; output and outcomes are otherwise
preserved. [Tested file hashes](tested-files.json), [migration parity](migration-parity.json)
and [scan dispositions](security-results.json) bind this evidence to the source.
The acceptance packet itself was added after the full gate and checked by the
privacy guard; it changes no application, test or dependency behavior.

## Independent reviews and their limits

One GPT-6 Astra high review and one Opus 5.5 high review examined the earlier
readiness candidate. Both returned NEEDS CHANGES. They inspected code and metadata
read-only; they did not run the full contributor gate or see its logs. The evidence
packet supplied here closes the documentation gap for maintainers, not retroactively
for those reviews. Existing core algorithms were outside their complete-audit scope.

Accepted findings were fixed and locally tested after review: managed-Python
selection, incompatible automatic uv dependency updates, the HTTPS security-report
link, Windows personal-path detection, missing/private-reference documentation and
certificate fixture refresh dates. The owner account used by CODEOWNERS was
verified as a user account. Private operating metadata and history were removed
from the publication source. The three later archive-pacing tests protect shared
request pacing, fixed budgets and sanitized timeout reasons.

No second external review was run after these fixes because the selected mode was
one completed review per reviewer. Do not describe the corrected tree as externally
approved. No GitHub settings or hosted CI result have been tested before publication.
