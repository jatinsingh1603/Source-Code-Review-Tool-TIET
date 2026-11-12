"""The privacy levels as first-class pipeline modes (E25-02).

``LEVEL_PLANS`` states, for each level, which transformations the prepare stage applies and on
which unit. The semantics (also in ``docs/privacy/levels.md``):

* **L0**: nothing crosses the client trust boundary. No payload is built. The LLM review stage is
  dropped from the plan unless the configured provider has trust tier ``local``.
* **L1**: typed placeholders only. Secrets, personal data and domain terms are replaced; names,
  comments and structure are untouched. Applied to every file the candidate touches, whole.
* **L2**: L1 plus consistent pseudonymisation of identifiers (comments removed), on the same
  whole-file unit.
* **L3**: L2 on the minimal slice (default).
* **L4**: abstract facts only; no code. Not delivered yet, so it fails closed.

``unit`` is the granularity the code is cut to: ``file`` for L1 and L2, ``slice`` for L3,
``none`` for L0 and L4. A file over ``privacy.slice.max_tokens`` falls back to the enclosing
function, then the sink window, and the slice records ``fallback_reason = "over_budget"``.
The decision is recorded in ``docs/adr/0010-privacy-level-semantics.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from codekavach.core.models import PrivacyLevel
from codekavach.core.models.enums import SliceStrategy, TrustTier

Unit = Literal["none", "file", "slice"]
# A whole-file unit may use this many times ``privacy.slice.max_tokens`` (8,192 at the default)
# before it falls back to the enclosing function; the fallback is then made within the same budget.
UNIT_BUDGET_FACTOR: Final = 4


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
    def comments_retained(self) -> bool:
        """True only at L1: code is sent and identifiers are not pseudonymised, comments stay."""
        return self.sends_code and not self.pseudonymise

    @property
    def names_retained(self) -> bool:
        """True only at L1: code is sent with the client's identifiers in clear, by definition.

        The egress guard's vault scanner (E12-02) does not apply to such a payload: the vault
        holds the identifiers that a pseudonymising level renamed, and L1 renames none. Its
        secret, personal-data and domain-term scanners still run (ADR-0010).
        """
        return self.sends_code and not self.pseudonymise

    @property
    def strategy_ceiling(self) -> SliceStrategy | None:
        """The richest slicing strategy allowed: whole files for L1 and L2."""
        if self.unit == "file":
            return SliceStrategy.WHOLE_FILE
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
        "file",
        True,
        False,
        False,
        False,
        True,
        "Typed placeholders for secrets, personal data and domain terms; whole files, "
        "code otherwise intact.",
    ),
    PrivacyLevel.L2: LevelPlan(
        PrivacyLevel.L2,
        "file",
        True,
        True,
        False,
        False,
        True,
        "Placeholders plus pseudonymised identifiers, on every file of the candidate, whole.",
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


def _yes(flag: bool) -> str:
    return "yes" if flag else "no"


def render_level_table() -> str:
    """The Markdown table of ``LEVEL_PLANS`` that ``docs/reference/privacy-levels.md`` embeds."""
    rows = [
        "| Level | Unit | Redact | Pseudonymise | Comments retained | Minimise | Sends code "
        "| Description |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for level in sorted(LEVEL_PLANS, key=lambda item: item.value):
        plan = LEVEL_PLANS[level]
        rows.append(
            f"| {level.value} | {plan.unit} | {_yes(plan.redact)} | {_yes(plan.pseudonymise)} "
            f"| {_yes(plan.comments_retained)} | {_yes(plan.slice_)} | {_yes(plan.sends_code)} "
            f"| {plan.description} |"
        )
    return "\n".join(rows) + "\n"


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
