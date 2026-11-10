"""The domain-term miner and its bundled baseline (E08-04)."""

import math
from pathlib import Path
from textwrap import dedent

import pytest

from codekavach.core.models import Language
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.models import LiteralSpan
from codekavach.parsing.subtokens import split_subtokens
from codekavach.parsing.symbols import SymbolTable
from codekavach.privacy.detect.mining import (
    MIN_TERM_LENGTH,
    Baseline,
    BaselineError,
    MinedTerm,
    bundled_baseline,
    mine_domain_terms,
    parse_baseline,
)
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from tests.support.symbols import table_of

BASELINE_PATH = (
    Path(__file__).resolve().parents[4]
    / "src"
    / "codekavach"
    / "privacy"
    / "detect"
    / "data"
    / "term_baseline.tsv"
)


def table(source: str) -> SymbolTable:
    return table_of(Language.PYTHON, dedent(source))[1]


REPOSITORY = table(
    """
    def accrual_rate(value):
        accrual = value + value
        return accrual * value

    def post_accrual(value, accrual):
        return accrual_rate(value) + accrual

    class AccrualJob:
        def run(self, value, mandate):
            self.mandate = mandate
            return post_accrual(value, self.mandate)
    """
)
BASELINE = Baseline(
    rates={"accrual": 2e-6, "value": 0.5, "mandate": 1e-5, "return": 0.3, "self": 0.2},
    floor_rate=1e-6,
    source="test",
)


def words(terms: tuple[MinedTerm, ...]) -> list[str]:
    return [t.term for t in terms]


def test_a_domain_word_outranks_a_common_word_and_the_common_word_is_not_suggested() -> None:
    mined = mine_domain_terms([REPOSITORY], [], baseline=BASELINE)
    assert words(mined)[0] == "accrual"
    assert "value" not in words(mined)
    everything = mine_domain_terms([REPOSITORY], [], baseline=BASELINE, min_score=-100)
    assert words(everything).index("accrual") < words(everything).index("value")


def test_the_score_is_the_log_ratio_of_the_repository_rate_to_the_baseline_rate() -> None:
    mined = {t.term: t for t in mine_domain_terms([REPOSITORY], [], baseline=BASELINE)}
    all_words = sum(
        1
        for symbol in REPOSITORY.symbols
        for piece in split_subtokens(symbol.name)
        if len(piece) >= 2 and piece.isalpha()
    )
    expected = math.log((mined["accrual"].occurrences / all_words) / 2e-6)
    assert mined["accrual"].score == pytest.approx(expected, abs=1e-5)


def test_a_word_missing_from_the_baseline_gets_the_floor_rate() -> None:
    mined = mine_domain_terms([REPOSITORY], [], baseline=BASELINE)
    assert "self" not in words(mined) and "run" not in words(mined)  # excluded / too short
    assert any(t.term == "mandate" for t in mine_domain_terms([REPOSITORY], [], baseline=BASELINE))
    sparse = Baseline(rates={}, floor_rate=1e-6, source="test")
    assert "accrual" in words(mine_domain_terms([REPOSITORY], [], baseline=sparse))


def test_excluded_words_are_never_suggested() -> None:
    mined = mine_domain_terms(
        [REPOSITORY], [], baseline=BASELINE, excluded=lambda word: word in {"accrual", "return"}
    )
    assert "accrual" not in words(mined)
    assert "mandate" in words(mined)


def test_keywords_builtins_and_allowlisted_names_can_be_excluded_with_the_real_sets() -> None:
    spec = REGISTRY.get(Language.PYTHON)
    allowlist = PublicAllowlist.bundled(Language.PYTHON)

    def excluded(word: str) -> bool:
        return word in spec.keywords or word in spec.builtins or allowlist.is_public(word)

    source = table(
        """
        def handler(request, response):
            print(request, response, request.args, request.headers)
            return isinstance(request, dict) and len(response) and accrual
        """
    )
    base = Baseline(rates={}, floor_rate=1e-9, source="test")
    plain = words(mine_domain_terms([source], [], baseline=base, min_occurrences=1))
    kept = words(
        mine_domain_terms([source], [], baseline=base, min_occurrences=1, excluded=excluded)
    )
    assert {"request", "print", "isinstance", "return"} & set(plain)
    assert not {"print", "isinstance", "return", "request"} & set(kept)
    assert "accrual" in kept


def test_short_words_digits_and_rare_words_are_not_suggested() -> None:
    source = table("def f(ab, abc, ab1, xyzzy_q):\n    return ab + abc + ab1 + xyzzy_q\n")
    base = Baseline(rates={}, floor_rate=1e-9, source="test")
    mined = words(mine_domain_terms([source], [], baseline=base, min_occurrences=1))
    assert all(len(w) >= MIN_TERM_LENGTH and w.isalpha() for w in mined)
    assert mined == ["xyzzy"]
    assert mine_domain_terms([source], [], baseline=base, min_occurrences=10) == ()


def test_string_literals_contribute_and_their_kind_is_reported() -> None:
    parsed = parse("a.py", Language.PYTHON, "label = 'nach mandate registered'\nother = 'nach'\n")
    literals = parsed.string_literals()
    assert literals and all(isinstance(item, LiteralSpan) for item in literals)
    base = Baseline(rates={}, floor_rate=1e-9, source="test")
    mined = {t.term: t for t in mine_domain_terms([], literals, baseline=base, min_occurrences=1)}
    assert mined["nach"].occurrences == 2
    assert mined["nach"].sample_kinds == ("literal:natural",)


def test_sample_kinds_come_from_the_symbols_and_are_bounded() -> None:
    mined = {t.term: t for t in mine_domain_terms([REPOSITORY], [], baseline=BASELINE)}
    kinds = mined["accrual"].sample_kinds
    assert 1 <= len(kinds) <= 3 and "function" in kinds


def test_the_result_is_deterministic_and_independent_of_input_order() -> None:
    other = table("def audit_trail(mandate):\n    return mandate\n")
    tables = [REPOSITORY, other, REPOSITORY]
    first = mine_domain_terms(tables, [], baseline=BASELINE)
    tables.reverse()
    assert mine_domain_terms(tables, [], baseline=BASELINE) == first
    assert mine_domain_terms(tables, [], baseline=BASELINE) == first


def test_limit_caps_the_result_and_an_empty_repository_gives_nothing() -> None:
    assert len(mine_domain_terms([REPOSITORY], [], baseline=BASELINE, min_score=-100, limit=2)) == 2
    assert mine_domain_terms([], [], baseline=BASELINE) == ()


def test_a_mined_term_is_client_data_and_is_classified_raw() -> None:
    assert MinedTerm.DATA_CLASSIFICATION.value == "raw"


# --- the bundled baseline ------------------------------------------------------------------


def lines() -> list[str]:
    return [
        line
        for line in BASELINE_PATH.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]


def test_the_bundled_baseline_is_sorted_non_empty_and_has_no_short_term() -> None:
    words_in_file = [line.split("\t")[0] for line in lines()]
    assert len(words_in_file) > 1000
    assert words_in_file == sorted(words_in_file)
    assert len(set(words_in_file)) == len(words_in_file)
    assert all(len(w) >= MIN_TERM_LENGTH and w == w.lower() for w in words_in_file)


def test_the_bundled_baseline_records_how_it_was_generated_and_its_licence() -> None:
    header = [
        line for line in BASELINE_PATH.read_text(encoding="utf-8").splitlines() if line[:1] == "#"
    ]
    text = "\n".join(header)
    for needle in ("source:", "PSF-2.0", "generator:", "licence:", "generated:", "floor_rate:"):
        assert needle in text


def test_the_bundled_baseline_loads_and_knows_common_code_words() -> None:
    baseline = bundled_baseline()
    for common in ("name", "value", "path", "data"):
        assert baseline.rate(common) > baseline.floor_rate * 10, common
    assert baseline.rate("accrual") == baseline.floor_rate


@pytest.mark.parametrize(
    "text",
    [
        "# floor_rate: 1e-6\nabc\t0.1\n",  # too short
        "# floor_rate: 1e-6\nzzzz\t0.1\naaaa\t0.1\n",  # not sorted
        "# floor_rate: 1e-6\nAAAA\t0.1\n",  # not lower case
        "# floor_rate: 1e-6\naaaa\tx\n",  # no rate
        "# floor_rate: 1e-6\naaaa 0.1\n",  # no tab
        "aaaa\t0.1\n",  # no floor
        "# floor_rate: 0\naaaa\t0.1\n",
    ],
)
def test_a_malformed_baseline_is_refused(text: str) -> None:
    with pytest.raises(BaselineError):
        parse_baseline(text)
