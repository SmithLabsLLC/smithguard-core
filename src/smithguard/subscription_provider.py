"""Current subscription routing, separate from the frozen Grok comparison source."""

from collections.abc import Callable

from smithguard.grok_build import GrokBuildWarningProvider
from smithguard.scheduled_discovery import ScheduledProviderError


class SubscriptionFirstProvider:
    """Select one route per durable job attempt, never call both inside one receipt."""

    def __init__(
        self,
        *,
        primary: GrokBuildWarningProvider,
        fallback_factory: Callable,
        primary_unavailable_reason: str | None = None,
    ) -> None:
        self.primary = primary
        self.fallback_factory = fallback_factory
        if primary_unavailable_reason not in {
            None,
            "allowance_exhausted",
            "trust_not_qualified",
        }:
            raise ValueError("primary unavailability reason invalid")
        self.primary_unavailable_reason = primary_unavailable_reason

    def for_attempt(self, *, attempt: int, prior_uncharged_native: bool):
        if attempt == 1 and self.primary_unavailable_reason is None:
            return self.primary
        if (attempt == 1 and self.primary_unavailable_reason is not None) or (
            attempt == 2 and prior_uncharged_native and self.primary_unavailable_reason is None
        ):
            try:
                return self.fallback_factory()
            except Exception as error:
                raise ScheduledProviderError(
                    "claude_preflight_uncharged", retryable=False, usage_uncertain=False
                ) from error
        raise ValueError("native fallback attempt outside bound")
