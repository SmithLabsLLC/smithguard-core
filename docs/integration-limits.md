# Hosted integration limits and retention

These are the current implementation limits, not a reserved capacity or latency
promise. Check the returned HTTP/tool error and current coverage. A public read
does not authorize source upload, private inventories, file disclosure or package
installation.

| Surface | Bound and behavior |
| --- | --- |
| Origin, all public routes | Per address: 10 requests/second, burst 20, 20 connections; origin 429 may omit `Retry-After` |
| `POST /v1/artifacts/assess` and all `/mcp` traffic | Also share a service-wide 100 requests/second origin limiter, burst 200; key/metadata MCP calls consume this route budget too |
| Exact assessment quota | 100 cache-miss attempts per 10 seconds and 100,000 distinct successful checks per network per UTC day; 429 on limits, 409 for an identical running request |
| MCP application | 16 concurrent requests, 12-second elapsed limit, 16,384 request bytes, 1,048,576 document bytes and 2,200,000 wire-response bytes |
| Origin proxy | 15-second read timeout; this is not a client budget or a cancellation guarantee for every downstream operation |

Protocol initialization, tool listing, key/coverage reads and assessments are
separate requests. Do not treat the daily quota as a throughput promise or add
these limits together. REST metadata avoids the shared `/mcp` assessment-route
limiter but still has origin and application limits. Error envelopes may differ:
an MCP transport error is not a successful tool result, and an HTTP 200 MCP call
can carry `isError: true`. Honor both layers.

Assessment, bulletin and MCP responses use `Cache-Control: no-store`. Keep full
answers in memory only for the current operation; do not save them as reusable
decisions. A local derived report can retain public coordinates, identifiers,
hashes, assessment outcomes, verification status, source conditions and timestamps under an explicit
local retention policy; it is not a signature-verifiable copy of the raw answer.
Re-read current status rather than reusing a prior report as current authority.
The service's internal assessment cache and immutable upstream evidence storage
have different purposes and do not grant downstream response-retention rights.

Bound connect/read/write/pool time, total wall time, response bytes, concurrency
and the total number of requests. In an interactive policy hook, additionally cap
the provider budget by the enclosing deadline and reserve time for the host's
original checks. Never extend a host deadline to wait for SmithGuard. Timeout,
429/503, missing evidence and cancellation mean unavailable evidence; they cannot
relax an existing approval or block. An explicit background/manual retry can
honor `Retry-After`; no retry should run inside a short policy-decision budget.

The optional Python client and contributor smoke checker have their own documented
budgets. Their successful runs do not prove suitability for a two-second Guard
hook. That native integration requires separate latency, cancellation,
cross-language verification and unchanged-host-decision tests.
