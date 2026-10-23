# Public certificate trust regression fixtures

These are public certificate chains from the October 2026 eMudhra trust incident.
They contain no private keys. tests/test_dependency_trust.py checks the actual
running Python/OpenSSL trust engine, including positive controls, without sockets.
An expired certificate is not evidence that a compromised trust path was rejected.

The twelve leaf certificates expire on May 3, 2027, between 01:04:36 and 02:27:42
UTC. SmithGuard maintainers own fixture refresh before that date; inspect upstream
public incident evidence and update the provenance hashes with any replacement.
Do not skip the positive controls or treat an expiry failure as trust remediation.
If authentic replacement evidence is unavailable, retire the time-bound runtime
fixture explicitly and retain an independently verified historical test; do not
fabricate a replacement chain or silently change the verification clock.
