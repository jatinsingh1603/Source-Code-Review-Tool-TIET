"""Budget, elision, assembly, the parse index and the registry (E11-01)."""

from pathlib import Path
from typing import Any

import pytest

from codekavach.config import Settings
from codekavach.core.models import (
    CodeRegion,
    Language,
    RawCode,
    SegmentRole,
    SliceSegment,
    SliceStrategy,
    Stub,
    StubReason,
)
from codekavach.parsing import parse
from codekavach.privacy.slicing.assemble import (
    assemble,
    file_text,
    numbered_labels,
    ordered,
)
from codekavach.privacy.slicing.base import (
    REASONS,
    SliceRefusal,
    SlicingError,
    StrategyRegistry,
    outcome_for,
)
from codekavach.privacy.slicing.budget import SliceBudget, estimate
from codekavach.privacy.slicing.elide import elide_region, elision_marker
from codekavach.privacy.slicing.index import never_send_matcher
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from tests.support.slicing import candidate_at, make_index


def segment(path: str, start: int, end: int, text: str | None = None) -> SliceSegment:
    body = text if text is not None else "\n".join(f"line {n}" for n in range(start, end + 1))
    return SliceSegment(
        path=path,
        region=CodeRegion(start_line=start, end_line=end),
        text=RawCode(body),
        role=SegmentRole.PRIMARY,
    )


# --- budget --------------------------------------------------------------------------------


class TestBudget:
    def test_the_estimate_is_three_and_a_half_characters_per_token_rounded_up(self) -> None:
        assert estimate("") == 0
        assert estimate("a") == 1
        assert estimate("a" * 7) == 2
        assert estimate("a" * 8) == 3
        assert estimate("a" * 35) == 10
        assert estimate("a" * 36) == 11

    def test_remaining_and_fits(self) -> None:
        budget = SliceBudget(10)
        assert budget.remaining(4) == 6
        assert budget.remaining(12) == -2
        assert budget.fits(4, "a" * 21)
        assert not budget.fits(4, "a" * 22)
        assert budget.fits(10)

    def test_a_budget_is_at_least_one_token(self) -> None:
        with pytest.raises(ValueError):
            SliceBudget(0)

    def test_estimating_needs_no_network(self) -> None:
        # The suite blocks sockets (E01-08); the estimate is arithmetic and must still work.
        assert estimate("def f(): pass") > 0


# --- elision -------------------------------------------------------------------------------


class TestElision:
    def test_markers_are_comments_in_each_language(self) -> None:
        assert elision_marker(Language.PYTHON) == "# ... elided ..."
        assert elision_marker(Language.JAVASCRIPT) == "// ... elided ..."
        assert elision_marker(Language.TYPESCRIPT) == "// ... elided ..."
        with pytest.raises(ValueError):
            elision_marker(Language.UNKNOWN)

    def test_removed_stretches_become_one_marker_each(self) -> None:
        text = "\n".join(f"l{n}" for n in range(1, 11))
        result = elide_region(text, [(2, 3), (7, 7)], Language.PYTHON)
        assert result.split("\n") == [
            "# ... elided ...",
            "l2",
            "l3",
            "# ... elided ...",
            "l7",
            "# ... elided ...",
        ]

    def test_keeping_everything_adds_no_marker(self) -> None:
        text = "a\nb\nc"
        assert elide_region(text, [(1, 3)], Language.PYTHON) == text
        assert elide_region(text, [(1, 1), (2, 3)], Language.PYTHON) == text

    def test_keeping_nothing_leaves_one_marker(self) -> None:
        assert elide_region("a\nb", [], Language.JAVASCRIPT) == "// ... elided ..."

    def test_ranges_are_clamped_and_may_overlap(self) -> None:
        assert elide_region("a\nb\nc", [(0, 2), (2, 99)], Language.PYTHON) == "a\nb\nc"

    def test_an_elided_python_function_still_parses(self) -> None:
        text = "def f(x):\n    a = 1\n    b = 2\n    return eval(x)\n"
        result = elide_region(text.rstrip("\n"), [(1, 1), (4, 4)], Language.PYTHON)
        assert parse("f.py", Language.PYTHON, result).error_count == 0


# --- assembly ------------------------------------------------------------------------------


class TestAssembly:
    def test_segments_are_ordered_by_path_and_line_not_by_input_order(self) -> None:
        shuffled = [segment("b.py", 3, 3), segment("a.py", 9, 9), segment("a.py", 1, 1)]
        assert [(s.path, s.region.start_line) for s in ordered(shuffled)] == [
            ("a.py", 1),
            ("a.py", 9),
            ("b.py", 3),
        ]
        labels = numbered_labels(["a.py", "b.py"])
        forward = assemble(shuffled, (), language=Language.PYTHON, labels=labels)
        backward = assemble(shuffled[::-1], (), language=Language.PYTHON, labels=labels)
        assert forward == backward

    def test_a_gap_gets_a_marker_and_adjacent_segments_none(self) -> None:
        text = assemble(
            [segment("a.py", 1, 2), segment("a.py", 3, 3), segment("a.py", 9, 9)],
            (),
            language=Language.PYTHON,
            labels=numbered_labels(["a.py"]),
        )
        assert text == "# file_1\nline 1\nline 2\nline 3\n# ... elided ...\nline 9"

    def test_files_are_labelled_by_the_callback_and_separated_by_a_blank_line(self) -> None:
        text = assemble(
            [segment("a.py", 1, 1), segment("b.py", 1, 1)],
            (),
            language=Language.JAVASCRIPT,
            labels=lambda path: f"pseudo_{path[0]}",
        )
        assert text == "// pseudo_a\nline 1\n\n// pseudo_b\nline 1"

    def test_labels_never_come_from_the_path_itself(self) -> None:
        labels = numbered_labels(["services/api/secret_accounts.py"])
        assert labels("services/api/secret_accounts.py") == "file_1"

    def test_stubs_follow_in_a_stable_order(self) -> None:
        stubs = [
            Stub(
                symbol="zeta",
                signature=RawCode("def zeta(): ..."),
                reason=StubReason.OUT_OF_SLICE_CALLEE,
            ),
            Stub(
                symbol="alpha",
                signature=RawCode("def alpha(): ..."),
                reason=StubReason.OUT_OF_SLICE_CALLEE,
            ),
        ]
        text = assemble(
            [segment("a.py", 1, 1)],
            stubs,
            language=Language.PYTHON,
            labels=numbered_labels(["a.py"]),
        )
        assert text.endswith("\n\ndef alpha(): ...\ndef zeta(): ...")

    def test_file_text_has_no_label(self) -> None:
        assert file_text([segment("a.py", 1, 1), segment("a.py", 5, 5)], Language.PYTHON) == (
            "line 1\n# ... elided ...\nline 5"
        )


# --- the index -----------------------------------------------------------------------------

SOURCE = """import os


def alpha(x):
    return beta(x)


def beta(y):
    return os.getcwd()


class Box:
    def method(self):
        return 1
"""


class TestIndex:
    def test_accessors(self) -> None:
        index = make_index({"m.py": SOURCE})
        assert index.source_of("m.py").expose() == SOURCE
        assert {r.symbol_name for r in index.function_ranges_of("m.py")} == {
            "alpha",
            "beta",
            "method",
        }
        assert index.symbols_of("m.py").imports
        assert index.symbols_of("unknown.py").imports == ()
        with pytest.raises(KeyError):
            index.parsed_of("unknown.py")

    def test_enclosing_function_is_the_innermost(self) -> None:
        index = make_index({"m.py": SOURCE})
        where = candidate_at("m.py", 5).locations[0]
        found = index.enclosing_function(where)
        assert found is not None and found.symbol_name == "alpha"
        method = index.enclosing_function(candidate_at("m.py", 14).locations[0])
        assert method is not None and method.qualified_name == "Box.method"
        assert index.enclosing_function(candidate_at("m.py", 1).locations[0]) is None

    def test_definition_of_in_the_same_file_and_across_files(self) -> None:
        index = make_index(
            {
                "m.py": SOURCE,
                "pkg/user.py": "from m import beta\n\n\ndef go():\n    return beta(1)\n",
            }
        )
        local = index.definition_of("beta", "m.py")
        assert local is not None and local[0] == "m.py"
        across = index.definition_of("beta", "pkg/user.py")
        assert across is not None and across[0] == "m.py"
        assert index.definition_of("missing", "m.py") is None

    @pytest.mark.parametrize(
        ("kwargs", "reason"),
        [
            ({"vendored": ("m.py",)}, "vendored"),
            ({"generated": ("m.py",)}, "generated"),
            ({"minified": ("m.py",)}, "minified"),
            ({"never_send": lambda path: path == "m.py"}, "policy_never_send"),
        ],
    )
    def test_each_exclusion_source_gives_its_reason(
        self, kwargs: dict[str, Any], reason: str
    ) -> None:
        index = make_index({"m.py": SOURCE, "n.py": "x = 1\n"}, **kwargs)
        assert index.is_excluded("m.py") == (True, reason)
        assert index.is_excluded("n.py") == (False, "")

    def test_a_file_the_scan_never_saw_is_excluded(self) -> None:
        assert make_index({"m.py": SOURCE}).is_excluded("ghost.py") == (True, "unknown_file")

    def test_never_send_outranks_the_ingestion_flags(self) -> None:
        index = make_index({"m.py": SOURCE}, vendored=("m.py",), never_send=lambda _p: True)
        assert index.is_excluded("m.py") == (True, "policy_never_send")


class TestNeverSendMatcher:
    @staticmethod
    def matcher(*patterns: str, rules: tuple[str, ...] = ()) -> object:
        settings = Settings.model_validate(
            {
                "privacy": {
                    "never_send": list(patterns),
                    "paths": [{"pattern": rule, "never_send": True} for rule in rules],
                }
            }
        )
        return never_send_matcher(settings)

    def test_patterns(self) -> None:
        match = self.matcher("secrets/**", "*.pem", "config/prod.py", rules=("legacy",))
        assert callable(match)
        assert match("secrets/a/b.py")
        assert match("secrets/key.txt")
        assert match("deep/dir/server.pem")
        assert match("config/prod.py")
        assert match("legacy/old.py")  # a rule from privacy.paths with never_send
        assert match("a/legacy/old.py")  # a pattern without a slash matches at any depth
        assert not match("config/dev.py")
        assert not match("src/app.py")
        assert not match("other/config/prod.py")  # a pattern with a slash is anchored

    def test_nothing_is_never_sent_by_default(self) -> None:
        match = self.matcher()
        assert callable(match)
        assert not match("anything/at/all.py")


# --- the registry and refusals -------------------------------------------------------------


class TestRegistry:
    def test_register_get_and_duplicates(self) -> None:
        registry = StrategyRegistry()
        strategy = EnclosingFunctionStrategy()
        registry.register(strategy)
        assert registry.get(SliceStrategy.ENCLOSING_FUNCTION) is strategy
        assert registry.names() == (SliceStrategy.ENCLOSING_FUNCTION,)
        with pytest.raises(ValueError):
            registry.register(EnclosingFunctionStrategy())
        with pytest.raises(KeyError):
            registry.get(SliceStrategy.TAINT_PATH)

    def test_slicing_error_keeps_to_the_closed_vocabulary_and_quotes_nothing(self) -> None:
        for reason in REASONS:
            assert str(SlicingError(reason)) == reason
        assert SlicingError("anything else").reason == "not_coherent"

    def test_a_refusal_is_a_value_not_an_exception(self, tmp_path: Path) -> None:
        index = make_index({"v.py": "def f(x):\n    return eval(x)\n"}, vendored=("v.py",))
        outcome = outcome_for(
            EnclosingFunctionStrategy(), candidate_at("v.py", 2), index, budget=SliceBudget(2048)
        )
        assert isinstance(outcome, SliceRefusal)
        assert outcome.reason == "vendored"
        with pytest.raises(ValueError):
            SliceRefusal(candidate_id=outcome.candidate_id, reason="because")  # type: ignore[arg-type]
