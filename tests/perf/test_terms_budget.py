"""Performance budgets of the domain-term detector (E08-03).

Building the automaton for 5 000 terms must take under 200 ms once per scan, and matching a
2 000-line slice must stay inside the 50 ms per-candidate budget of E08-01. Budgets are scaled by
the performance factor.
"""

import random

import pytest

from codekavach.core.models import Language, RawCode
from codekavach.privacy.detect.terms import DomainTermDetector
from tests.perf.test_detect_budget import secret_slice
from tests.support.perf import assert_within_budget, measure

TERMS = 5_000
BUILD_BUDGET_SECONDS = 0.200
MATCH_BUDGET_SECONDS = 0.050
_LETTERS = "abcdefghijklmnopqrstuvwxyz"


def dictionary() -> list[str]:
    """5 000 invented two-word terms, joined by a space or a hyphen."""
    generator = random.Random(8)  # noqa: S311 - fixed test data
    terms = []
    for _ in range(TERMS):
        words = [
            "".join(generator.choice(_LETTERS) for _ in range(generator.randint(4, 9)))
            for _ in range(2)
        ]
        terms.append(generator.choice(" -").join(words))
    return terms


@pytest.mark.perf
def test_building_the_automaton_for_5000_terms_stays_within_budget() -> None:
    terms = dictionary()
    assert_within_budget(
        measure(lambda: DomainTermDetector(terms), repeat=3),
        BUILD_BUDGET_SECONDS,
        label="automaton build, 5000 terms",
    )


@pytest.mark.perf
def test_matching_a_2000_line_slice_against_5000_terms_stays_within_budget() -> None:
    terms = dictionary()
    detector = DomainTermDetector([*terms, "festival bonus"])
    text = RawCode(secret_slice())

    def run() -> int:
        return len(detector.detect(text, path="src/app.py", language=Language.PYTHON))

    assert run() >= 500  # the slice holds "festival bonus" on every fourth group of lines
    assert_within_budget(
        measure(run, repeat=5), MATCH_BUDGET_SECONDS, label="term matching, 2000 lines"
    )
