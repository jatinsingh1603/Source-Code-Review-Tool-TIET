"""The token budget of a slice and its local estimator.

Owning epic: E11.

``estimate`` divides the length of a text by 3.5 characters per token and rounds up. It is local on
purpose: a provider's token-counting endpoint would transmit the very content the privacy layer
exists to minimise, so none is ever called. The figure is a planning number for the budget, not a
billing figure; the real count differs by model and by language.

Budgets are measured on the assembled text (labels, separators and elision markers included) so
that what is counted is what would be sent. ``SliceBudget.used`` takes the assembled text for
that reason; the strategies assemble with placeholder labels of the same shape as the real ones.
"""

from dataclasses import dataclass
from typing import Final

CHARS_PER_TOKEN_TIMES_TWO: Final = 7  # 3.5 characters per token, kept in integers


def estimate(text: str) -> int:
    """Tokens in ``text`` at 3.5 characters per token, rounded up; ``0`` for the empty text."""
    return (2 * len(text) + CHARS_PER_TOKEN_TIMES_TWO - 1) // CHARS_PER_TOKEN_TIMES_TWO


@dataclass(frozen=True, slots=True)
class SliceBudget:
    """At most ``max_tokens`` estimated tokens for one slice."""

    max_tokens: int

    def __post_init__(self) -> None:
        if self.max_tokens < 1:
            raise ValueError("a slice budget is at least one token")

    def remaining(self, used: int) -> int:
        """Tokens left after ``used`` have been spent; negative when over budget."""
        return self.max_tokens - used

    def fits(self, used: int, addition: str = "") -> bool:
        """Whether ``used`` tokens plus the estimate of ``addition`` stay within the budget."""
        return used + estimate(addition) <= self.max_tokens
