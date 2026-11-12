"""LLM budget: token, request and cost limits for one scan, and the pre-flight estimate (E22-03).

Owning epic: E22 to E24. Normative layout: docs/ARCHITECTURE.md section 3.

``ScanBudget`` counts what a scan has used (requests, input and output tokens as the provider
reports them, and the estimated cost) and says when a limit of ``llm.budget`` is reached. The
stage asks it before every request; once it is exhausted no further request is sent, the
candidates left are failed with ``llm_budget_exhausted`` and the deterministic findings stay as
they are. Exhausting a budget is not a privacy block and does not use the privacy exit code.

**Prices are not shipped.** Vendor prices change and differ per contract, so a table in the code
would be wrong sooner or later and a wrong cost limit is worse than none. A provider's price is
read from its options, ``price_input_per_mtok`` and ``price_output_per_mtok`` (US dollars per
million tokens); without them the cost is reported as unknown and ``max_cost_usd`` cannot be
enforced, which ``estimate_scan`` says explicitly.
"""

from dataclasses import dataclass
from typing import Final

from codekavach.config.models.llm import BudgetSettings, ProviderSettings
from codekavach.llm.providers.base import Usage

BUDGET_EXHAUSTED: Final = "llm_budget_exhausted"
_PER_MILLION: Final = 1_000_000
# A verdict is a few hundred tokens of JSON; reasoning models add their hidden reasoning.
DEFAULT_OUTPUT_TOKENS_PER_REQUEST: Final = 800
BYTES_PER_TOKEN: Final = 4


@dataclass(frozen=True, slots=True)
class Prices:
    """US dollars per million tokens; ``None`` when unknown."""

    input_per_mtok: float | None = None
    output_per_mtok: float | None = None

    @property
    def known(self) -> bool:
        """Whether both prices are configured."""
        return self.input_per_mtok is not None and self.output_per_mtok is not None

    def cost(self, input_tokens: int, output_tokens: int) -> float | None:
        """The cost of the given tokens, or ``None`` when a price is unknown."""
        if self.input_per_mtok is None or self.output_per_mtok is None:
            return None
        return (
            input_tokens * self.input_per_mtok + output_tokens * self.output_per_mtok
        ) / _PER_MILLION


def _price(value: object) -> float | None:
    if isinstance(value, int | float) and not isinstance(value, bool) and value >= 0:
        return float(value)
    return None


def prices_for(provider: ProviderSettings) -> Prices:
    """The prices configured on ``provider`` (options ``price_input_per_mtok`` and output)."""
    return Prices(
        _price(provider.options.get("price_input_per_mtok")),
        _price(provider.options.get("price_output_per_mtok")),
    )


@dataclass(slots=True)
class ScanBudget:
    """What one scan has spent, against ``llm.budget``."""

    limits: BudgetSettings
    prices: Prices
    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_hits: int = 0
    in_flight: int = 0  # requests reserved by ``ManagedSession`` and not answered yet

    @property
    def cost_usd(self) -> float | None:
        """The estimated cost so far, or ``None`` when the prices are unknown."""
        return self.prices.cost(self.input_tokens, self.output_tokens)

    def exhausted(self) -> str | None:
        """The name of the first limit reached, or ``None`` while another request may go."""
        limits = self.limits
        used = self.requests + self.in_flight  # concurrent requests cannot overshoot the cap
        if limits.max_requests is not None and used >= limits.max_requests:
            return "max_requests"
        if (
            limits.max_total_input_tokens is not None
            and self.input_tokens >= limits.max_total_input_tokens
        ):
            return "max_total_input_tokens"
        if (
            limits.max_total_output_tokens is not None
            and self.output_tokens >= limits.max_total_output_tokens
        ):
            return "max_total_output_tokens"
        cost = self.cost_usd
        if limits.max_cost_usd is not None and cost is not None and cost >= limits.max_cost_usd:
            return "max_cost_usd"
        return None

    def record(self, usage: Usage, *, request_bytes: int = 0) -> None:
        """Count one sent request; without reported usage the input is estimated from its size."""
        self.requests += 1
        self.input_tokens += usage.input_tokens or max(1, request_bytes // BYTES_PER_TOKEN)
        self.output_tokens += usage.output_tokens

    def summary(self) -> dict[str, object]:
        """The figures for the scan summary and the log."""
        return {
            "requests": self.requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_hits": self.cache_hits,
            "cost_usd": None if self.cost_usd is None else round(self.cost_usd, 6),
        }


@dataclass(frozen=True, slots=True)
class Estimate:
    """A pre-flight estimate: what a scan of ``requests`` payloads would cost."""

    requests: int
    input_tokens: int
    output_tokens: int
    cost_usd: float | None

    def describe(self) -> str:
        """One line for the operator."""
        cost = "cost unknown" if self.cost_usd is None else f"about ${self.cost_usd:.4f}"
        return (
            f"{self.requests} requests, about {self.input_tokens} input and "
            f"{self.output_tokens} output tokens, {cost}"
        )


def estimate_scan(
    payload_sizes: list[int],
    provider: ProviderSettings,
    *,
    prompt_overhead_bytes: int = 4000,
    output_tokens_per_request: int = DEFAULT_OUTPUT_TOKENS_PER_REQUEST,
) -> Estimate:
    """Estimate a scan from the payload sizes in bytes; contacts nothing (no token-count API)."""
    input_tokens = sum(
        max(1, (size + prompt_overhead_bytes) // BYTES_PER_TOKEN) for size in payload_sizes
    )
    output_tokens = output_tokens_per_request * len(payload_sizes)
    cost = prices_for(provider).cost(input_tokens, output_tokens)
    return Estimate(len(payload_sizes), input_tokens, output_tokens, cost)
