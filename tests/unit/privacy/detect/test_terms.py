"""The Aho-Corasick automaton and the domain-term detector."""

import ast
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.config.models.root import Settings
from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode
from codekavach.privacy.detect import terms
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_all
from codekavach.privacy.detect.terms import (
    MIN_TERM_LENGTH,
    AhoCorasick,
    DomainTermDetector,
    TermStats,
    fold,
    register_term_detector,
)
from tests.support.synthetic import SYNTHETIC_TERMS


def hits(terms: list[str], text: str) -> list[str]:
    """The slices of ``text`` that the detector reports."""
    data = text.encode()
    detector = DomainTermDetector(terms)
    spans = detector.detect(RawCode(text), path="src/app.py", language=Language.PYTHON)
    return [data[s.start_byte : s.end_byte].decode() for s in spans]


# --- the automaton --------------------------------------------------------------------------


def slow_reference(patterns: list[str], text: str) -> set[tuple[int, int, int]]:
    found = set()
    for index, pattern in enumerate(patterns):
        start = text.find(pattern)
        while start != -1:
            found.add((start, start + len(pattern), index))
            start = text.find(pattern, start + 1)
    return found


def test_the_textbook_example() -> None:
    patterns = ["he", "she", "his", "hers"]
    assert set(AhoCorasick(patterns).finditer("ushers")) == {(1, 4, 1), (2, 4, 0), (2, 6, 3)}


def test_overlapping_nested_and_repeated_occurrences_are_all_reported() -> None:
    patterns = ["aa", "aaa", "a"]
    expected = slow_reference(patterns, "aaaa")
    assert set(AhoCorasick(patterns).finditer("aaaa")) == expected
    assert len(expected) == 4 + 3 + 2


def test_an_empty_pattern_is_refused_and_no_patterns_match_nothing() -> None:
    with pytest.raises(ValueError, match="empty pattern"):
        AhoCorasick(["a", ""])
    assert list(AhoCorasick([]).finditer("anything")) == []


@given(
    st.lists(st.text(alphabet="abc", min_size=1, max_size=5), min_size=0, max_size=8, unique=True),
    st.text(alphabet="abc", max_size=40),
)
def test_property_the_automaton_equals_a_slow_reference(patterns: list[str], text: str) -> None:
    assert set(AhoCorasick(patterns).finditer(text)) == slow_reference(patterns, text)


def test_repr_shows_sizes_only() -> None:
    automaton = AhoCorasick(["festival"])
    assert "festival" not in repr(automaton)
    assert "patterns=1" in repr(automaton)


# --- the detector: the matching modes --------------------------------------------------------

TERM = "festival-bonus"


def test_the_term_is_found_in_a_camel_case_identifier_a_snake_case_one_and_a_string() -> None:
    assert hits([TERM], "x = festivalBonusRate") == ["festivalBonus"]
    assert hits([TERM], "calculate_festival_bonus(a)") == ["festival_bonus"]
    assert hits([TERM], 'label = "festival bonus"') == ["festival bonus"]


def test_hyphen_underscore_dot_and_space_are_equivalent_in_term_and_text() -> None:
    for term in ("festival-bonus", "festival_bonus", "festival.bonus", "festival bonus"):
        for text in ("festival-bonus", "festival_bonus", "festival.bonus", "festival bonus"):
            assert hits([term], f"x {text} y") == [text], (term, text)


def test_matching_is_case_insensitive() -> None:
    assert hits(["Festival Bonus"], "FESTIVAL_BONUS = 1") == ["FESTIVAL_BONUS"]
    assert hits([TERM], "Festival-BONUS") == ["Festival-BONUS"]


def test_a_single_word_term_is_a_substring_match() -> None:
    assert hits(["kisan"], 'a = "kisan credit card"; kisanCard = 1') == ["kisan", "kisan"]


def test_the_two_word_term_does_not_match_either_word_alone() -> None:
    assert hits([TERM], "festivals = []; bonus = 1; festival = 2") == []


def test_a_term_of_fewer_than_four_characters_is_ignored_entirely() -> None:
    assert MIN_TERM_LENGTH == 4
    assert hits(["abc", "a-b", "x_y_z"], "abc a-b x_y_z abcabc") == []
    assert hits(["abcd"], "abcd") == ["abcd"]
    assert hits(["a-b-c"], "a-b-c") == []  # three characters once the separators go


def test_the_span_covers_the_matched_run_and_not_the_whole_identifier() -> None:
    text = "def calculate_festival_bonus_for_staff(x): pass"
    assert hits([TERM], text) == ["festival_bonus"]
    text = "totalFestivalBonusRateWithTax"
    assert hits([TERM], text) == ["FestivalBonus"]


def test_every_hit_is_a_term_span_with_the_domain_subtype() -> None:
    text = "festivalBonus and kisan_credit and Festival Bonus"
    detector = DomainTermDetector([TERM, "kisan credit"])
    spans = detector.detect(RawCode(text), path="a.py", language=Language.PYTHON)
    assert len(spans) == 3
    for span in spans:
        assert span.kind is PlaceholderKind.TERM
        assert span.subtype == "domain"
        assert span.confidence is Confidence.HIGH
        assert span.detector == "term.domain"


def test_the_synthetic_terms_are_found() -> None:
    terms = [entry.value for entry in SYNTHETIC_TERMS]
    text = f"# {terms[0]}\nrate = kisanCredit"
    assert hits(terms, text) == [terms[0], "kisanCredit"]


def test_a_term_does_not_match_across_other_punctuation() -> None:
    assert hits([TERM], "festival, bonus") == []
    assert hits([TERM], "festival(bonus)") == []


def test_offsets_are_utf8_bytes() -> None:
    text = 'café = "日本"  # \U0001f600 festivalBonus'
    assert hits([TERM], text) == ["festivalBonus"]


def test_no_terms_and_no_match_cost_nothing() -> None:
    assert hits([], "festival bonus") == []
    assert hits([TERM], "nothing here") == []
    assert hits([""], "festival bonus") == []


def test_duplicate_terms_and_overlapping_terms_do_not_duplicate_spans() -> None:
    assert hits([TERM, "festival_bonus", "FESTIVAL BONUS"], "festival bonus") == ["festival bonus"]
    detector = DomainTermDetector(["festival bonus", "bonus rate"])
    text = "festival bonus rate"
    spans = detector.detect(RawCode(text), path="a.py", language=Language.PYTHON)
    assert [text.encode()[s.start_byte : s.end_byte].decode() for s in spans] == [
        "festival bonus",
        "bonus rate",
    ]


def test_fold_removes_separators_and_lowercases() -> None:
    assert fold("Festival-Bonus_Rate.X y") == "festivalbonusratexy"


def test_the_length_of_a_text_does_not_change_when_lowercasing_it_changes_it() -> None:
    # "İ" lower-cases to two characters; the offsets must still point into the original text.
    text = "İİ festivalBonus"
    assert hits([TERM], text) == ["festivalBonus"]


# --- no term text anywhere ------------------------------------------------------------------


def test_stats_count_distinct_terms_and_hits_without_text() -> None:
    detector = DomainTermDetector([TERM, "kisan credit", "unused term"])
    assert detector.stats() == TermStats(distinct_terms=0, hits=0)
    detector.detect(
        RawCode("festivalBonus festival_bonus kisan credit"), path="a.py", language=Language.PYTHON
    )
    assert detector.stats() == TermStats(distinct_terms=2, hits=3)
    detector.detect(RawCode("festival bonus"), path="a.py", language=Language.PYTHON)
    assert detector.stats() == TermStats(distinct_terms=2, hits=4)
    assert set(vars(detector.stats())) == {"distinct_terms", "hits"}


def test_reprs_of_the_detector_its_stats_and_its_spans_hold_no_term() -> None:
    detector = DomainTermDetector(["festival bonus"])
    (span,) = detector.detect(RawCode("festivalBonus"), path="a.py", language=Language.PYTHON)
    for text in (repr(detector), repr(detector.stats()), repr(span), str(span)):
        assert "festival" not in text.lower()
        assert "bonus" not in text.lower()


# --- settings and the registry --------------------------------------------------------------


def test_the_detector_reads_the_effective_term_list_from_the_settings() -> None:
    settings = Settings.model_validate({"privacy": {"domain_terms": ["festival bonus", "kisan"]}})
    detector = DomainTermDetector.from_settings(settings)
    assert detector.id == "term.domain"
    assert detector.kinds == frozenset({PlaceholderKind.TERM})
    spans = detect_all(
        RawCode("festivalBonus"),
        path="a.py",
        language=Language.PYTHON,
        settings=settings,
        registry=register_term_detector(DetectorRegistry(), settings),
    )
    assert [(s.kind, s.subtype) for s in spans] == [(PlaceholderKind.TERM, "domain")]


def test_the_module_calls_no_file_reading_function() -> None:
    """The terms file is merged into the settings by E03-21; this module must not open it."""
    tree = ast.parse(Path(terms.__file__ or "").read_text(encoding="utf-8"))
    called = {
        node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name | ast.Attribute)
    }
    assert not called & {"open", "read_text", "read_bytes", "Path", "getenv", "urlopen"}
