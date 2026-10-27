# SmithGuard canonical JSON and assessment verification, version 1

Status: normative description of the existing `smithguard-canonical-json-v1`
wire format and the optional Python client's decision-eligibility rules. It does
not change historical signatures or schema semantics. This is not RFC 8785/JCS.
Implementations must preserve the distinctions below; generic JSON reserialization
is insufficient. The current executable reference is the Python 3.14 client in
`clients/python/src/smithguard_client/verification.py`.

## Input and canonical bytes

1. Accept a UTF-8 JSON object, without a BOM, at most 1,048,576 bytes. Reject
   invalid UTF-8, duplicate object keys at every depth (including equivalent
   escaped names), NaN, infinity and numeric overflow to infinity. Root depth is
   zero; each object key/value or array element adds one; reject depths above 64.
2. Decode JSON string escapes. Reject unpaired UTF-16 surrogates; combine valid
   surrogate pairs into their Unicode scalar. Do not normalize Unicode. Sort
   object keys lexicographically by Unicode scalar values, not UTF-16 code units,
   locale order or escaped spelling. Preserve array order.
3. Serialize objects and arrays with comma separators and colon key/value
   separators, with no spaces, BOM or trailing newline. Emit `true`, `false`,
   `null` in lowercase. Quote strings. Escape quote and backslash, use `\b`,
   `\f`, `\n`, `\r`, `\t` for those controls, and lowercase `\u00xx` for other
   U+0000–001F controls. Leave slash unchanged. Emit every character at or above
   U+007F as lowercase four-hex-digit `\u` escapes; supplementary scalars
   use the corresponding high/low surrogate escape pair. The result is ASCII.
4. Number *token type* matters. A JSON number without a decimal point or exponent
   is an exact integer: serialize its decimal value without leading zeros (`-0`
   becomes `0`). Preserve integers beyond 2^53; never convert them to binary64.
   The reference parser supports at most 4,300 decimal digits in integer tokens.
   For this reference-client conformance profile, reject larger tokens; do not
   silently round or truncate them.
5. Numbers with a point or exponent are IEEE-754 binary64, rounded to nearest,
   ties to even on input. Underflow to signed zero is accepted. Emit the shortest
   decimal representation that round-trips to the same binary64 value, choosing
   the nearest representation and ties to even. Use fixed notation when the
   resulting decimal exponent is -4 through 15 inclusive, otherwise scientific
   notation. Fixed integral floats retain `.0`; signed floating zero is `-0.0`.
   Scientific notation uses lowercase `e`, an explicit exponent sign and at least
   two exponent digits, without a redundant `.0` in its mantissa. Thus `1e0`
   becomes `1.0`, `1e-7` stays `1e-07`, and `1e20` becomes `1e+20`. Python 3.14
   `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=True,
   allow_nan=False)` over the strict parsed object is the executable tie-breaker.
   Languages that lose integer/float token type must retain it during parsing.

## Signature and key checks

Parse and validate the original document. The client recognizes assessment schema
versions 2.1.0, 2.2.0, 2.3.0 and 2.4.0 and validates them with its bundled assessment
JSON Schema (including format checks). Unknown schemas or signature formats are
`unchecked`, never successful evidence. This list is a client compatibility list,
not permission to skip fields required by the bundled schema.

Remove only the top-level `signature` member. Canonicalize **every other member**,
including nested fields, using the rules above. Verify the detached Ed25519
signature in `signature.value` against those bytes. Require exact algorithm
`Ed25519` and canonicalization `smithguard-canonical-json-v1` in both the signature
and key document. Use standard base64 with the Python 3.14 `b64decode(validate=True)`
acceptance rules: reject invalid alphabet characters, misplaced/missing padding
and wrong key/signature lengths. This decoder accepts non-zero unused pad bits;
these bits do not change decoded bytes. Do not require canonical pad bits for
version-1 compatibility. Ed25519 validation uses the reference client's locked
`cryptography` implementation; stricter language-library variants need compatibility
tests before claiming conformance. This document does not introduce a new signature
variant or change verification of historical bytes. Do not rebuild a
smaller object from selected fields or verify a model's summary.

The key document is limited to 16,384 bytes. The public key is 32 raw bytes. Its
identifier is `gbsec:snapshot-public-key:` followed by the first 40 lowercase hex
characters of SHA256 over the ASCII text `sha256:` plus the lowercase SHA256 hex
digest of those raw key bytes. Both key document and signature must name this
derived identifier. The artifact object must exactly equal the requested public
coordinate object, including its supplied identity fields.

`revoked` keys are invalid. `verification_only` keys can verify history only when
historical mode is explicitly selected; they cannot support current decisions.
Unknown key states are unchecked. A missing key is unchecked. A mathematically
valid signature with an offline key is still unchecked for current decisions.
Key status is current only after an authenticated fixed-origin HTTPS read whose
age is between zero and 300 seconds inclusive. Callers supply that read time;
the verification function itself performs no network request. Key and answer from
one HTTPS service share a trust anchor; they are not independent corroboration.

Answer freshness is separate: `updated_at` must have a timezone and be no more
than 30 seconds in the future or the chosen maximum age in the past. Default age
is 300 seconds; callers may select 1–3,600 seconds. `verified` can describe valid
old signature math; a current decision additionally requires an active key,
current key status and a fresh answer. The client exposes that conjunction as
`current_decision_eligible`. Failure never means safe, trustworthy or approved.
Signatures prove service authorship/integrity, not source truth, applicability to
a local installation, absence of other threats, or permission to install.

## Verification outcomes and precedence

The portable outcome is `(status, reason, signature_valid,
current_decision_eligible)`. `signature_valid` means **this verifier reached and
successfully completed the cryptographic check**. False also covers a check that
was never attempted; it does not assert that the document's signature is
mathematically wrong. A rejection before that check must keep it false even if a
separate signature-only calculation would succeed.

Apply the following steps in order. Stop at the first returned outcome. For an
exception, return the corresponding exception outcome below at the step where it
occurs; do not continue to a later check to replace the earlier result.

| Order | Condition or operation | Returned status / reason | Signature valid |
| --- | --- | --- | --- |
| 1 | Strictly parse assessment JSON | Continue, or exception outcome | false until step 12 |
| 2 | Schema version outside the four listed versions | `unchecked` / `unsupported_schema` | false |
| 3 | Signature member absent or not an object | `unchecked` / `missing_signature` | false |
| 4 | Signature algorithm or canonicalization unsupported | `unchecked` / `unsupported_signature_format` | false |
| 5 | Validate the bundled assessment schema and formats | Continue, or `invalid` / `schema_validation_failed` | false |
| 6 | Artifact object differs from requested coordinate | `invalid` / `coordinate_mismatch` | false |
| 7 | Key document unavailable | `unchecked` / `key_unavailable` | false |
| 8 | Strictly parse key; algorithm/canonicalization unsupported | `unchecked` / `unsupported_key_format` (or parse exception) | false |
| 9 | Key status is revoked | `invalid` / `key_revoked` | false |
| 10 | Key status neither active nor verification-only | `unchecked` / `key_status_unknown` | false |
| 11 | Verification-only key without historical mode | `invalid` / `retired_key_for_current_answer` | false |
| 12 | Decode key, derive ID, compare both IDs, then verify signature | ID mismatch: `invalid` / `key_identity_mismatch`; math failure: `invalid` / `signature_mismatch`; otherwise continue | true only after successful math |
| 13 | Supplied key-fetch timestamp has no timezone | `unchecked` / `key_time_unknown` | true |
| 14 | Compute current key status and response freshness; no key-fetch timestamp or key age outside 0–300 seconds | `unchecked` / `key_status_not_current` | true |
| 15 | All preceding checks passed | `verified` / `historical_signature` in historical mode, otherwise `signature_verified` | true |

Malformed JSON, key fields, base64 or byte lengths, missing required key fields,
Unicode/depth/number failures and related type/value failures return `invalid` /
`malformed_document_or_key`, with signature-valid false. JSON Schema validation
failures use `schema_validation_failed`; cryptographic mismatch uses
`signature_mismatch`. Invalid caller configuration (timezone-naive evaluation
clock or maximum age outside 1–3,600 seconds) is a caller error rather than a
verification result.

Historical mode still requires a current key-status read from the last 300 seconds
to return `verified`; it only permits verification-only keys and selects the
historical success reason. Response freshness does not change the status/reason
of an otherwise verified answer. `current_decision_eligible` is exactly the
conjunction `status == verified`, key state active, current key status and fresh
response. It is false for every early rejection/unchecked result. Historical mode
alone does not force eligibility false: an active, current, fresh historical-mode
answer also satisfies that conjunction. None of these flags grants action authority.

## Portable conformance fixtures

`clients/python/tests/conformance/canonical-v1.json` contains exact input strings,
canonical ASCII/hex bytes, SHA256 digests and required rejection cases.
Rejection inputs use exactly one of `input_utf8` (UTF-8 encode the string) or
`input_hex` (decode exact bytes, including invalid UTF-8).
`assessment-v1.json` contains one synthetic signed assessment and its public key,
with exact signed-message bytes/digest and a fixed evaluation clock.
`verification-cases-v1.json` supplies complete assessment/key input strings, exact
coordinates, clocks and expected outcomes for language-independent test runners.
Its signing key was generated temporarily and was
not saved. No production key or response is included. The companion
`test_client_conformance.py` exercises current, offline, stale, future, revoked,
historical, coordinate, schema and tampering outcomes using those fixed bytes.
Vectors include inclusive freshness/depth boundaries, non-zero base64 pad bits
and rejection of a noncanonical Ed25519 S scalar. Additional byte/depth/schema limits are covered by `test_client_verification.py`.

Passing the Python tests establishes the reference behavior only. A Rust consumer
must reproduce the supported bytes and rejection/verification outcomes before a
native integration can be qualified. No Rust conformance or live Guard hook
integration is claimed by this package.
