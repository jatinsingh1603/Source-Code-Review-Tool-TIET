"""Integer budgets (LLM requests, tokens, cost) and a wall-clock deadline for one scan.

Owning epic: E04.

``charge`` is atomic and refuses an amount that would exceed a limit without recording it, so a
refused LLM request is not counted. Money is counted in micro-USD; the runner (E04-16) converts
``llm.budget.max_cost_usd``. Names without a limit are only counted.
"""

import threading
import time
from collections.abc import Callable, Mapping
from typing import Final

from codekavach.core.pipeline.errors import PipelineError

LLM_REQUESTS: Final = "llm.requests"
LLM_INPUT_TOKENS: Final = "llm.input_tokens"
LLM_OUTPUT_TOKENS: Final = "llm.output_tokens"
LLM_COST_MICRO_USD: Final = "llm.cost_micro_usd"


class BudgetExceededError(PipelineError):
    """Charging would exceed the limit of ``name``."""

    def __init__(self, name: str, limit: int) -> None:
        self.name = name
        self.limit = limit
        super().__init__(f"budget {name!r} would exceed its limit of {limit}")


class Budget:
    """Thread-safe counters with optional limits and an optional wall-clock limit."""

    def __init__(
        self,
        limits: Mapping[str, int] | None = None,
        wall_seconds: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        for name, limit in (limits or {}).items():
            if limit < 0:
                raise ValueError(f"budget limit {name!r} must not be negative")
        if wall_seconds is not None and wall_seconds < 0:
            raise ValueError("wall_seconds must not be negative")
        self._limits = dict(limits or {})
        self._wall_seconds = wall_seconds
        self._monotonic = monotonic
        self._started: float | None = None
        self._used: dict[str, int] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the wall clock (idempotent)."""
        with self._lock:
            if self._started is None:
                self._started = self._monotonic()

    def charge(self, name: str, amount: int) -> int:
        """Add ``amount`` to ``name`` and return the new total.

        Raises:
            BudgetExceededError: the total would exceed the limit; nothing is recorded.
            ValueError: ``amount`` is negative.
        """
        if amount < 0:
            raise ValueError("a budget charge must not be negative")
        with self._lock:
            total = self._used.get(name, 0) + amount
            limit = self._limits.get(name)
            if limit is not None and total > limit:
                raise BudgetExceededError(name, limit)
            self._used[name] = total
            return total

    def try_charge(self, name: str, amount: int) -> bool:
        """``charge`` that returns False instead of raising when over the limit."""
        try:
            self.charge(name, amount)
        except BudgetExceededError:
            return False
        return True

    def used(self, name: str) -> int:
        """The amount charged so far."""
        with self._lock:
            return self._used.get(name, 0)

    def remaining(self, name: str) -> int | None:
        """What is left under the limit, or ``None`` when ``name`` is unlimited."""
        with self._lock:
            limit = self._limits.get(name)
            return None if limit is None else limit - self._used.get(name, 0)

    def remaining_seconds(self) -> float | None:
        """Seconds left, or ``None`` without a wall limit or before ``start``."""
        with self._lock:
            if self._wall_seconds is None or self._started is None:
                return None
            return self._wall_seconds - (self._monotonic() - self._started)

    def deadline_exceeded(self) -> bool:
        """True when the wall-clock limit has been used up."""
        remaining = self.remaining_seconds()
        return remaining is not None and remaining <= 0

    def snapshot(self) -> dict[str, int]:
        """A copy of the amounts charged so far."""
        with self._lock:
            return dict(self._used)
