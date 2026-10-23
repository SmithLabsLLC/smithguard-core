"""Frozen baseline and opt-in comparison candidate; neither changes enforcement."""

BASELINE = (
    b"Continue the same bounded discovery after the completed tool results. "
    b"Do not repeat completed searches or fetches. All original instructions, "
    b"source boundaries and the shared tool budget still apply. Return only "
    b"the required final JSON when the cited evidence is sufficient."
)
CANDIDATE = "remaining-budget-v1"
CANDIDATE_TEMPLATE = (
    " Observed remaining allowance at this reminder: {calls} tool calls and "
    "{milliseconds} milliseconds before the original shared deadline, including "
    "launch and cleanup. This is a snapshot, not a fresh allowance. "
    "{tool_instruction} Finish the required JSON using only evidence already obtained "
    "or obtained within that remaining allowance. Keep unsupported details unknown; "
    "return an empty list if no lead has the required cited support."
)


def reminder(mode: str, *, remaining_calls: int, remaining_ms: int) -> bytes:
    if mode not in {"baseline", CANDIDATE}:
        raise ValueError("unknown native continuation mode")
    if type(remaining_calls) is not int or not 0 <= remaining_calls <= 4:
        raise ValueError("invalid remaining tool allowance")
    if type(remaining_ms) is not int or not 0 <= remaining_ms <= 120_000:
        raise ValueError("invalid remaining time allowance")
    if mode == "baseline":
        return BASELINE
    instruction = (
        "No tool calls remain: do not search or fetch again."
        if remaining_calls == 0
        else "Use a remaining call only if needed for required citation binding."
    )
    return BASELINE + CANDIDATE_TEMPLATE.format(
        calls=remaining_calls,
        milliseconds=remaining_ms,
        tool_instruction=instruction,
    ).encode("ascii")
