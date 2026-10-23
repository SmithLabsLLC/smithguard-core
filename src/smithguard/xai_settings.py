"""Shared xAI model settings for SmithGuard threat-search requests.

One spelling of every request bound. The model string is also a member of every hashed
warning-lane receipt (through ProviderUsage.model), and the frozen spend policy JSON
repeats it as an independent gate: a model change is a policy change, not a refactor.
"""

XAI_THREAT_SEARCH_MODEL = "grok-4.7"
XAI_THREAT_SEARCH_REASONING_EFFORT = "high"
XAI_RESPONSES_ENDPOINT = "https://api.x.ai/v1/responses"
XAI_MAX_REQUEST_BYTES = 65_536
XAI_MAX_RESPONSE_BYTES = 1_048_576
XAI_MAX_ELAPSED_SECONDS = 120
XAI_MAX_INPUT_TOKENS = 2_000_000
# Exact JSON integer representation bounds for retained counters, not generation
# budgets. Early-warning output has no SmithGuard token cap (owner October 10).
XAI_MAX_OUTPUT_TOKENS = 2**53 - 1
XAI_MAX_TOTAL_TOKENS = 2**53 - 1
XAI_RECHECK_MAX_INPUT_TOKENS = 1_500_000
XAI_QUALIFICATION_MAX_OUTPUT_TOKENS = 8_192
# Distinct policy numbers that happen to share a value keep their own names so a
# future change to one bound cannot silently move another.
XAI_STAGE_MAX_INPUT_TOKENS_PER_TURN = 500_000
XAI_MAX_RECEIPT_REQUEST_BYTES = 1_048_576
XAI_RECHECK_MAX_OUTPUT_TOKENS = 8_192
XAI_RECHECK_MAX_TOTAL_TOKENS = XAI_RECHECK_MAX_INPUT_TOKENS + XAI_RECHECK_MAX_OUTPUT_TOKENS
XAI_MAX_OUTPUT_TOKENS_PER_REQUEST = 8_192
XAI_DISCOVERY_STAGE_MAX_OUTPUT_TOKENS = 8_192
XAI_DISCOVERY_DEFAULT_MAX_INPUT_TOKENS = 1_500_000
XAI_DISCOVERY_DEFAULT_MAX_OUTPUT_TOKENS = None
XAI_DISCOVERY_DEFAULT_MAX_TOTAL_TOKENS = None
