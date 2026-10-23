"""Closed, separately observed states for the staged private warning schedules."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

DISCOVERY_TIMER = "smithguard-discovery.timer"
RECHECK_TIMER = "smithguard-warning-recheck.timer"
LEGACY_CONTAINED = "contained_enabled_but_stopped"
CONTAINED = "contained_disabled_and_stopped"
DISCOVERY_ONLY = "discovery_active_recheck_stopped"
PRIVATE_ACTIVE = "private_observation_active"
TIMER_STATES = {
    CONTAINED: (False, False),
    LEGACY_CONTAINED: (False, False),
    DISCOVERY_ONLY: (True, False),
    PRIVATE_ACTIVE: (True, True),
}


def warning_timer_activity(warning: Any) -> dict[str, bool]:
    """Return exact expectations; missing legacy metadata means both stopped."""
    if warning is None:
        state = CONTAINED
    elif not isinstance(warning, Mapping):
        raise ValueError("warning lane metadata must be an object")
    else:
        state = warning.get("timers_state")
        if not isinstance(state, str) or state not in TIMER_STATES:
            raise ValueError("warning timer state is unknown")
        if warning.get("publication_active") is not False:
            raise ValueError("private warning observation cannot authorize publication")
    discovery, recheck = TIMER_STATES[state]
    return {DISCOVERY_TIMER: discovery, RECHECK_TIMER: recheck}


def contained_topology(topology: Mapping[str, Any]) -> dict[str, Any]:
    """Release phases withhold both warning timers; preserve every other expectation."""
    warning_timer_activity(topology.get("warning_lane"))
    result = dict(topology)
    result["warning_lane"] = {
        **(topology.get("warning_lane") or {}),
        "timers_state": CONTAINED,
        "publication_active": False,
    }
    result["timers"] = [
        {**row, "active": False, "enabled": False}
        if row.get("unit") in {DISCOVERY_TIMER, RECHECK_TIMER}
        else dict(row)
        for row in topology["timers"]
    ]
    return result
