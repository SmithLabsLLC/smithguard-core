# Third-party notices

SmithGuard source and original synthetic fixtures are maintained by Smith Labs, LLC
and contributors. See LICENSE for the proposed project license. Preserve any
file-specific copyright and license notices.

Python dependencies are downloaded from their upstream distributions; their source
and binaries are not vendored in this repository. Exact versions and artifact
hashes are in uv.lock. The dependency-license-register.json records the licenses
and source URLs for direct dependencies, build tools and selected companion
packages. It is not a complete transitive attribution statement for a binary
redistribution. Anyone distributing a built bundle must retain the licenses and
notices of every dependency included in that bundle.

Generated API models use datamodel-code-generator and Pydantic; the project
contract definitions remain their source of truth. No upstream advisory database,
full publisher article archive or production database is distributed here.

The small PHP and Mozilla feed fixtures are reduced parser examples with factual
paraphrases and synthetic entries; their provenance hashes are in
`tests/fixtures/social-security/feed-provenance.json`. Public certificate-chain
fixtures contain public certificate data for trust-regression tests, not private
keys. Source names, CVE/GHSA identifiers, URLs and version facts identify external
materials; they do not transfer rights to those materials. Source access and output
conditions remain defined by each upstream provider and the source-rights register.

The Apache License text is reproduced from the Apache Software Foundation's
published license at https://www.apache.org/licenses/LICENSE-2.0.txt. The foundation
is not affiliated with or endorsing this project.

The dated interpretation boundary fixture contains minimal version/range facts
and identifiers derived from the GitHub Advisory Database under CC-BY-4.0
(https://creativecommons.org/licenses/by/4.0/). Each record retains its source URL,
update/observation times and source digest. It omits full advisory prose and is
a finite regression corpus, not a redistributed advisory database.
