"""The per-scan privacy score: named components, each measured or indicative (E28-03).

There is no single headline number that stands for "how private": the components are reported
individually and ``score`` is only a documented summary of them (``docs/privacy/score.md``).

Components (value is always points 0 to 100, higher is better; ``raw`` is the unscaled figure):

=====================  ==========  ================================================================
component              kind        meaning
=====================  ==========  ================================================================
``level_strength``     indicative  the weakest level any payload was prepared at (L1 25 ... L0 100)
``disclosure_volume``  measured    union share of the repository disclosed: 100 - 4 * pct
``residual_terms``     measured    configured domain terms found verbatim in ledger payloads
``linkability``        measured    placeholder tokens shared by more than one payload
``budget_usage``       measured    disclosed share against the aggregation ceiling (if set)
``ledger_integrity``   measured    the hash chain verifies
``naming_channel``     not_computed  structural leakage; owned by the leakage harness
=====================  ==========  ================================================================

Summary: ``score = round(0.35 level + 0.30 disclosure + 0.25 residual + 0.10 linkability)``, then
capped at 40 when a residual term was found and at 50 when the ledger chain is broken. A budget
over its ceiling caps the score at 60. Nothing is sent, so a scan with no payloads scores 100.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from codekavach.core.models import PrivacyLevel

Kind = Literal["measured", "indicative", "not_computed"]

LEVEL_POINTS: Final[dict[PrivacyLevel, int]] = {
    PrivacyLevel.L1: 25,
    PrivacyLevel.L2: 50,
    PrivacyLevel.L3: 75,
    PrivacyLevel.L4: 90,
    PrivacyLevel.L0: 100,
}
WEIGHTS: Final = {
    "level_strength": 0.35,
    "disclosure_volume": 0.30,
    "residual_terms": 0.25,
    "linkability": 0.10,
}
FORMULA: Final = (
    "score = round(0.35*level_strength + 0.30*disclosure_volume + 0.25*residual_terms "
    "+ 0.10*linkability); capped at 40 when a residual term is found, at 50 when the ledger "
    "chain is broken, at 60 when the aggregation budget is exceeded."
)


class ScoreComponent(BaseModel):
    """One named figure of the score."""

    model_config = ConfigDict(frozen=True)

    name: str
    value: float | None = Field(description="points 0..100, None when not computed")
    raw: str = ""
    unit: str = "points"
    kind: Kind
    basis: str


class PrivacyScore(BaseModel):
    """The components, the summary and the formula that produced it."""

    model_config = ConfigDict(frozen=True)

    score: int = Field(ge=0, le=100)
    components: tuple[ScoreComponent, ...]
    formula: str = FORMULA
    caps: tuple[str, ...] = ()

    def component(self, name: str) -> ScoreComponent:
        """The component called ``name``."""
        return next(c for c in self.components if c.name == name)


@dataclass(frozen=True, slots=True)
class ScoreInputs:
    """Everything the score needs, already extracted from the scan (no code, no paths)."""

    payload_levels: tuple[PrivacyLevel, ...]
    repo_pct: float
    budget_ceiling_pct: float
    residual_checked: bool
    residual_occurrences: int
    tokens_total: int
    tokens_shared: int
    chain_ok: bool


def count_words(count: int, word: str) -> str:
    """``"0 occurrences"``, ``"1 occurrence"``: a count with its noun, for display."""
    return f"{count} {word}{'' if count == 1 else 's'}"


def compute_privacy_score(inputs: ScoreInputs) -> PrivacyScore:
    """Compute the components and the summary score from ``inputs``."""
    parts: list[ScoreComponent] = []
    if inputs.payload_levels:
        weakest = min(inputs.payload_levels)
        level = float(LEVEL_POINTS[weakest])
        raw = weakest.value
    else:
        level, raw = 100.0, "no payload"
    parts.append(
        ScoreComponent(
            name="level_strength",
            value=level,
            raw=raw,
            kind="indicative",
            basis="weakest level in use; a level is a policy, not a proof",
        )
    )
    disclosure = max(0.0, 100.0 - 4.0 * inputs.repo_pct)
    parts.append(
        ScoreComponent(
            name="disclosure_volume",
            value=round(disclosure, 1),
            raw=f"{inputs.repo_pct:.2f}% of repository lines",
            kind="measured",
            basis="union of disclosed lines over inventory lines",
        )
    )
    if not inputs.payload_levels:
        residual, raw = 100.0, "no payload to search"
    elif inputs.residual_checked:
        residual = 100.0 if inputs.residual_occurrences == 0 else 0.0
        raw = count_words(inputs.residual_occurrences, "occurrence")
    else:
        residual, raw = 50.0, "not checked"
    parts.append(
        ScoreComponent(
            name="residual_terms",
            value=residual,
            raw=raw,
            kind="measured",
            basis="verbatim search of ledger payloads for configured terms",
        )
    )
    shared = inputs.tokens_shared / inputs.tokens_total if inputs.tokens_total else 0.0
    parts.append(
        ScoreComponent(
            name="linkability",
            value=round(100.0 * (1 - shared), 1),
            raw=(
                f"{inputs.tokens_shared} of {inputs.tokens_total} placeholders shared"
                if inputs.tokens_total
                else "no placeholders to link"
            ),
            kind="measured",
            basis="placeholder tokens appearing in 2+ payloads",
        )
    )
    over = inputs.budget_ceiling_pct < 100.0 and inputs.repo_pct > inputs.budget_ceiling_pct
    if inputs.budget_ceiling_pct < 100.0:
        used = min(100.0, inputs.repo_pct / inputs.budget_ceiling_pct * 100.0)
        parts.append(
            ScoreComponent(
                name="budget_usage",
                value=round(100.0 - used, 1),
                raw=f"{used:.0f}% of the {inputs.budget_ceiling_pct:g}% ceiling",
                kind="measured",
                basis="aggregation budget",
            )
        )
    else:
        parts.append(
            ScoreComponent(
                name="budget_usage",
                value=None,
                raw="no ceiling configured",
                kind="not_computed",
                basis="privacy.egress.aggregation_budget_pct",
            )
        )
    parts.append(
        ScoreComponent(
            name="ledger_integrity",
            value=100.0 if inputs.chain_ok else 0.0,
            raw="verified" if inputs.chain_ok else "BROKEN",
            kind="measured",
            basis="hash-chain verification",
        )
    )
    parts.append(
        ScoreComponent(
            name="naming_channel",
            value=None,
            raw="leakage harness",
            kind="not_computed",
            basis="structural and naming leakage need attacker models",
        )
    )
    values = {c.name: c.value for c in parts}
    total = sum(weight * float(values[name] or 0.0) for name, weight in WEIGHTS.items())
    score = round(total)
    caps: list[str] = []
    if inputs.residual_checked and inputs.residual_occurrences:
        score, caps = min(score, 40), [*caps, "residual term found (cap 40)"]
    if not inputs.chain_ok:
        score, caps = min(score, 50), [*caps, "ledger chain broken (cap 50)"]
    if over:
        score, caps = min(score, 60), [*caps, "aggregation budget exceeded (cap 60)"]
    return PrivacyScore(score=max(0, min(100, score)), components=tuple(parts), caps=tuple(caps))
