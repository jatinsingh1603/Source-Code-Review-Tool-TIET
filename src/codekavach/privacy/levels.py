"""The privacy levels as first-class pipeline modes (E25-02).

``LEVEL_PLANS`` states, for each level, which transformations the prepare stage applies and on
which unit. The semantics (also in ``docs/privacy/levels.md``):

* **L0**: nothing crosses the client trust boundary. No payload is built. The LLM review stage is
  dropped from the plan unless the configured provider has trust tier ``local``.
* **L1**: typed placeholders only. Secrets, personal data and domain terms are replaced; names,
  comments and structure are untouched. Applied to the enclosing unit.
* **L2**: L1 plus consistent pseudonymisation of identifiers, on the enclosing unit.
* **L3**: L2 on the minimal slice (default).
* **L4**: abstract facts only; no code. Not delivered yet, so it fails closed.

``unit`` is the granularity the code is cut to: ``function`` for L1 to L3 in this build (an
enclosing function is the largest unit the slicer produces; whole-file units are a documented
follow-up), ``slice`` for L3, ``none`` for L0 and L4.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from codekavach.core.models import PrivacyLevel
from codekavach.core.models.enums import SliceStrategy, TrustTier

Unit = Literal["none", "function", "slice"]


@dataclass(frozen=True, slots=True)
class LevelPlan:
    """What the prepare stage does at one level."""

    level: PrivacyLevel
    unit: Unit
    redact: bool
    pseudonymise: bool
    slice_: bool
    abstract: bool
    sends_code: bool
    description: str

    @property
    def strategy_ceiling(self) -> SliceStrategy | None:
        """The richest slicing strategy allowed: whole functions for L1 and L2."""
        if self.unit == "function":
            return SliceStrategy.ENCLOSING_FUNCTION
        return None


LEVEL_PLANS: Final[dict[PrivacyLevel, LevelPlan]] = {
    PrivacyLevel.L0: LevelPlan(
        PrivacyLevel.L0,
        "none",
        False,
        False,
        False,
        False,
        False,
        "Nothing leaves the machine; no payload is built.",
    ),
    PrivacyLevel.L1: LevelPlan(
        PrivacyLevel.L1,
        "function",
        True,
        False,
        False,
        False,
        True,
        "Typed placeholders for secrets, personal data and domain terms; code otherwise intact.",
    ),
    PrivacyLevel.L2: LevelPlan(
        PrivacyLevel.L2,
        "function",
        True,
        True,
        False,
        False,
        True,
        "Placeholders plus pseudonymised identifiers, on the whole enclosing function.",
    ),
    PrivacyLevel.L3: LevelPlan(
        PrivacyLevel.L3,
        "slice",
        True,
        True,
        True,
        False,
        True,
        "Placeholders plus pseudonyms on the minimal slice around the candidate.",
    ),
    PrivacyLevel.L4: LevelPlan(
        PrivacyLevel.L4,
        "none",
        False,
        False,
        False,
        True,
        False,
        "Abstract facts only, no code (not yet delivered: fails closed).",
    ),
}


def plan_for(level: PrivacyLevel) -> LevelPlan:
    """The plan of ``level``."""
    return LEVEL_PLANS[level]


def level_available(level: PrivacyLevel) -> bool:
    """False for L4, which no pipeline delivers yet; callers must fail closed, not downgrade."""
    return level is not PrivacyLevel.L4


def llm_review_allowed(level: PrivacyLevel, tier: TrustTier) -> bool:
    """False at L0 unless the provider is local: the review stage is removed from the plan."""
    return level is not PrivacyLevel.L0 or tier is TrustTier.LOCAL


def needs_reconsent(previous: PrivacyLevel | None, requested: PrivacyLevel) -> bool:
    """True when ``requested`` is less strict than the level that was consented to.

    No previous consent also needs consent. Moving to a stricter level never does.
    """
    return previous is None or not requested.at_least(previous)
