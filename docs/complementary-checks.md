# Complementary checks and coverage limits

Validated October 26, 2026. SmithGuard's package-version evidence is one input to a
software decision. It does not inventory an operating system, prove that installed
files match a public package, or determine whether a service is exposed.

## Use the supplier's package identity

For Ubuntu packages, use the exact Ubuntu release, support state, architecture,
package origin and full Debian package revision. Compare with Ubuntu's own
security notices and machine-readable OVAL data. Ubuntu can backport a fix without
adopting the newest upstream version; comparing only the upstream version can
produce a false alarm. Record unsupported releases and unavailable vendor evidence
as unknown. Do not infer that every no-match Python result represents an Ubuntu
package or a required upgrade.

Start with [Ubuntu security updates](https://documentation.ubuntu.com/security/security-updates/)
and [Ubuntu Security Notices](https://ubuntu.com/security/notices). These are
supplier references, not a claim that SmithGuard has run or integrated an Ubuntu
scanner. No Ubuntu tool installation or machine assessment was performed for this
release. Any local assessment needs its own selected scope and access authority.

Keep language packages, distribution packages, snaps, Flatpaks, vendor binaries,
bundled runtimes and container contents associated with their actual supplier.
Do not substitute a similarly named public package for an unidentified local
binary. Application compatibility and vendor support matter independently of a
source-listed patch. Preserve findings in dormant or unknown-activity environments;
prioritize known exposed active services using actual target evidence.

## Container identity and contents are separate

A mutable tag, a multi-platform index digest and a platform-specific image digest
are different identities. Record registry/repository, immutable digest, selected
OS/architecture and which manifest is actually used. A direct compromised-image
notice is different evidence from vulnerabilities in packages inside the image.
A successful check of a few components does not establish that the image was
fully inspected. See [Docker's platform model](https://docs.docker.com/build/building/multi-platform/).

A maintained local content scanner can complement direct artifact evidence. Our
bounded feasibility study used Trivy 0.76.0 on Linux amd64, its verified upstream
release archive, a fixed database and one public Alpine image plus two synthetic
controls. Network was disabled during scans; no container was executed and no
Docker daemon, private registry credentials or owner inventory was supplied.
Read [Trivy's current coverage](https://trivy.dev/docs/latest/scanner/vulnerability/)
and [its verified release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.0)
before choosing a tool. This dated study is not a recommendation to assume that
version remains current, safe or suitable for every platform.

We defer a bundled container adapter and a hosted container-content lane. The
small selected corpus does not qualify distroless images, vendored/non-packaged
software, other distributions or architectures, private registries, platform
mismatches or unknown base-image provenance. Database downloads, source rights,
update cost, release verification and resource ownership need ongoing maintenance.
The study observed a roughly 1.64 GB database; it is not a small embedded client
feature. An image with no recognized package metadata remained unassessed despite
returning no findings. Images, SBOMs, private names and relationships stay local;
any extracted public-coordinate disclosure still needs an exact preview and
explicit permission.

## Generic Git remains unqualified

A full commit ID must be bound to a canonical public repository and authoritative
repository-specific advisory evidence. Commit hashes and dates do not define
version order. Forks, merge ancestry, shallow history, cherry-picked/backported
fixes, submodules, vendored code and the mapping to a built artifact all matter.
The [OSV format](https://ossf.github.io/osv-schema/) describes Git ranges; format
support alone does not establish a qualified source or a safe commit.

We defer generic Git coverage. Four local synthetic Git controls verified simple ancestry inclusion/exclusion
and the limits of side branches and same-content backports. This did not qualify
a public repository-bound advisory corpus or a maintenance source, and did not reactivate
the disabled OSV connector, clone private repositories, run hooks or execute code.
Prefer an ecosystem release only when the exact mapping is independently proven.
Unsupported identity remains unknown, even if some components have known evidence.

## Make a bounded decision

Keep four outcomes distinct: a supplier fix is available; investigation is needed;
no matching advisory was found within a stated scope; or the item is unsupported
or unassessed. None means all risk is removed. Upgrade, removal, cleanup, reboot,
account changes and purchases are separate authorized actions with application
compatibility checks and meaningful tests.
