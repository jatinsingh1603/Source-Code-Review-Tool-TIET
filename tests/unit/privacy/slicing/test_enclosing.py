"""The enclosing-function strategy (E11-01): behaviour, shrink order and the never-elide rules."""

from collections.abc import Callable
from itertools import pairwise
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.core.models import CodeSlice, Language, SegmentRole, SliceStrategy
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.parsing import parse
from codekavach.privacy.slicing.assemble import assemble, file_text, numbered_labels
from codekavach.privacy.slicing.base import (
    SliceRefusal,
    SlicingError,
    lookup_outcome,
    outcome_for,
)
from codekavach.privacy.slicing.budget import SliceBudget, estimate
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from tests.support.slicing import candidate_at, make_index

STRATEGY = EnclosingFunctionStrategy()
SCAN_ID = "scan_01J8ZC3W6T5X0Q9V7R4M2N1K8P"  # pragma: allowlist secret
BIG = SliceBudget(100_000)

SERVICE = """import os
from flask import route
import json


class AccountService:
    def __init__(self, db):
        self.db = db

    @route("/accrue")
    def accrue(self, account_id):
        rate = os.environ.get("RATE")
        cur = self.db.cursor()
        cur.execute("SELECT * FROM t WHERE id = '%s'" % account_id)
        return cur.fetchall()

    def close(self):
        self.db.close()
"""

LONG = "\n".join(
    [
        "import hashlib",
        "",
        "",
        "def settle(batch, ledger, audit):",
        "    total = 0",
        "    for item in batch:",
        "        total += item.amount",
        "        audit.record(item.id, item.amount)",
        "        audit.flush()",
        "    audit.record('summary', total)",
        "    if ledger.is_open():",
        "        if total > 0:",
        "            ledger.append('INSERT %s' % total)",
        "        else:",
        "            ledger.skip()",
        "    audit.record('done', hashlib.md5(b'x').hexdigest())",
        "    audit.flush()",
        "    audit.close()",
        "    return total",
        "",
    ]
)


def build(
    source: dict[str, str],
    where: tuple[str, int],
    *,
    budget: int = 100_000,
    vendored: tuple[str, ...] = (),
    generated: tuple[str, ...] = (),
    minified: tuple[str, ...] = (),
    never_send: Callable[[str], bool] | None = None,
) -> CodeSlice:
    index = make_index(
        source, vendored=vendored, generated=generated, minified=minified, never_send=never_send
    )
    return STRATEGY.build(candidate_at(*where), index, budget=SliceBudget(budget))


def text_of(slice_: CodeSlice) -> str:
    labels = numbered_labels([segment.path for segment in slice_.segments])
    return assemble(slice_.segments, (), language=slice_.language, labels=labels)


def segment_tokens(slice_: CodeSlice) -> int:
    """The estimated tokens of the segments alone: stubs fill what is left, so they do not count."""
    return estimate(text_of(slice_))


def regions(slice_: CodeSlice) -> list[tuple[str, int, int]]:
    return [(s.role.value, s.region.start_line, s.region.end_line) for s in slice_.segments]


class TestWorkedExample:
    def test_the_documented_segments(self) -> None:
        """The issue's example: class header as context, the decorated method, the used imports."""
        found = build({"svc.py": SERVICE}, ("svc.py", 14))
        assert regions(found) == [
            ("imports", 1, 2),
            ("context", 6, 6),
            ("primary", 10, 15),
        ]
        assert text_of(found) == "\n".join(
            [
                "# file_1",
                "import os",
                "from flask import route",
                "# ... elided ...",
                "class AccountService:",
                "# ... elided ...",
                '    @route("/accrue")',
                "    def accrue(self, account_id):",
                '        rate = os.environ.get("RATE")',
                "        cur = self.db.cursor()",
                "        cur.execute(\"SELECT * FROM t WHERE id = '%s'\" % account_id)",
                "        return cur.fetchall()",
            ]
        )
        assert found.strategy is SliceStrategy.ENCLOSING_FUNCTION
        assert not found.truncated
        assert found.token_estimate > 0

    def test_a_method_candidate_carries_its_class_header(self) -> None:
        found = build({"svc.py": SERVICE}, ("svc.py", 14))
        assert any(
            s.role is SegmentRole.CONTEXT and s.text.expose() == "class AccountService:"
            for s in found.segments
        )


class TestSelection:
    def test_the_function_includes_its_decorators(self) -> None:
        found = build({"svc.py": SERVICE}, ("svc.py", 12))
        primary = next(s for s in found.segments if s.role is SegmentRole.PRIMARY)
        assert primary.text.expose().startswith('    @route("/accrue")')

    def test_only_imports_used_inside_the_taken_code_are_included(self) -> None:
        found = build({"svc.py": SERVICE}, ("svc.py", 14))
        imported = "\n".join(
            s.text.expose() for s in found.segments if s.role is SegmentRole.IMPORTS
        )
        assert "import os" in imported and "from flask import route" in imported
        assert "json" not in imported

    def test_overlapping_and_adjacent_ranges_become_one_segment(self) -> None:
        index = make_index({"svc.py": SERVICE})
        both = candidate_at("svc.py", 13, ("svc.py", 15))
        found = STRATEGY.build(both, index, budget=BIG)
        function_segments = [s for s in found.segments if s.region.start_line >= 10]
        assert len(function_segments) == 1

    def test_code_outside_any_function_uses_a_window_of_whole_statements(self) -> None:
        lines = [f"VALUE_{n} = {n}" for n in range(1, 100)]
        found = build({"cfg.py": "\n".join(lines) + "\n"}, ("cfg.py", 50), budget=64)
        (only,) = found.segments
        assert only.role is SegmentRole.PRIMARY
        assert only.region.start_line < 50 < only.region.end_line
        assert only.region.line_count < 20

    def test_the_window_grows_with_the_budget(self) -> None:
        lines = "\n".join(f"VALUE_{n} = {n}" for n in range(1, 200)) + "\n"
        small = build({"cfg.py": lines}, ("cfg.py", 100), budget=64)
        large = build({"cfg.py": lines}, ("cfg.py", 100), budget=2048)
        assert large.segments[0].region.line_count > small.segments[0].region.line_count

    def test_a_second_location_in_another_file_adds_its_function(self) -> None:
        sources = {
            "a.py": "def one(x):\n    return eval(x)\n",
            "b.py": "def two(y):\n    return exec(y)\n",
        }
        index = make_index(sources)
        found = STRATEGY.build(candidate_at("a.py", 2, ("b.py", 2)), index, budget=BIG)
        assert found.files == ("a.py", "b.py")
        assert [s.role for s in found.segments] == [SegmentRole.PRIMARY, SegmentRole.CONTEXT]

    def test_a_location_in_an_excluded_file_is_left_out_but_the_primary_still_slices(self) -> None:
        sources = {
            "a.py": "def one(x):\n    return eval(x)\n",
            "v.py": "def two(y):\n    return exec(y)\n",
        }
        index = make_index(sources, vendored=("v.py",))
        found = STRATEGY.build(candidate_at("a.py", 2, ("v.py", 2)), index, budget=BIG)
        assert found.files == ("a.py",)


class TestRefusals:
    @pytest.mark.parametrize(
        ("flag", "reason"),
        [("vendored", "vendored"), ("generated", "generated"), ("minified", "minified")],
    )
    def test_flagged_files_are_refused_with_their_reason(self, flag: str, reason: str) -> None:
        source = {"x.py": "def f(x):\n    return eval(x)\n"}
        with pytest.raises(SlicingError) as caught:
            build(source, ("x.py", 2), **{flag: ("x.py",)})  # type: ignore[arg-type]
        assert caught.value.reason == reason
        assert str(caught.value) == reason

    def test_a_never_send_path_is_refused(self) -> None:
        with pytest.raises(SlicingError) as caught:
            build({"x.py": "x = 1\n"}, ("x.py", 1), never_send=lambda path: True)
        assert caught.value.reason == "policy_never_send"

    def test_an_unknown_file_is_refused(self) -> None:
        with pytest.raises(SlicingError) as caught:
            STRATEGY.build(candidate_at("ghost.py", 1), make_index({"x.py": "x = 1\n"}), budget=BIG)
        assert caught.value.reason == "unknown_file"

    def test_an_unsupported_language_is_refused(self) -> None:
        index = make_index({"main.go": "package main\n"})
        with pytest.raises(SlicingError) as caught:
            STRATEGY.build(candidate_at("main.go", 1), index, budget=BIG)
        assert caught.value.reason == "unsupported_language"

    def test_a_blank_line_has_no_enclosing_code(self) -> None:
        with pytest.raises(SlicingError) as caught:
            build({"x.py": "x = 1\n\n\ny = 2\n"}, ("x.py", 2))
        assert caught.value.reason == "no_enclosing_code"

    def test_the_error_message_never_holds_code_or_paths(self) -> None:
        source = {"secret_vendor/zq_lib.py": "def zq(x):\n    return eval(x)\n"}
        with pytest.raises(SlicingError) as caught:
            build(source, ("secret_vendor/zq_lib.py", 2), vendored=("secret_vendor/zq_lib.py",))
        text = str(caught.value) + repr(caught.value)
        assert "zq" not in text and "secret_vendor" not in text and "eval" not in text

    def test_a_refusal_is_stored_with_its_reason_and_found_apart_from_absence(self) -> None:
        index = make_index({"v.py": "def f(x):\n    return eval(x)\n"}, vendored=("v.py",))
        candidate = candidate_at("v.py", 2)
        refusal = outcome_for(STRATEGY, candidate, index, budget=BIG)
        assert isinstance(refusal, SliceRefusal)
        assert lookup_outcome(candidate.id, [], [refusal]) == refusal
        assert lookup_outcome(candidate.id, [], []) is None
        other = candidate_at("v.py", 2, id="cand_01J8ZC3W6T5X0Q9V7R4M2N1K8Q")
        assert lookup_outcome(other.id, [], [refusal]) is None


class TestShrinkOrder:
    def test_imports_go_first(self) -> None:
        full = build({"m.py": LONG}, ("m.py", 13))
        tight = build({"m.py": LONG}, ("m.py", 13), budget=segment_tokens(full) - 3)
        assert tight.truncated
        assert not any(s.role is SegmentRole.IMPORTS for s in tight.segments)
        assert "def settle" in text_of(tight) and "audit.close()" in text_of(tight)

    def test_then_the_window_around_module_level_code_shrinks(self) -> None:
        lines = "\n".join(f"VALUE_{n} = {n}" for n in range(1, 200)) + "\n"
        wide = build({"cfg.py": lines}, ("cfg.py", 100), budget=2048)
        narrow = build({"cfg.py": lines}, ("cfg.py", 100), budget=2048 // 12)
        assert (
            narrow.truncated
            or narrow.segments[0].region.line_count <= wide.segments[0].region.line_count
        )

    def test_then_the_interior_of_the_function_is_elided(self) -> None:
        tight = build({"m.py": LONG}, ("m.py", 13), budget=70)
        assert tight.truncated
        shown = text_of(tight)
        assert "# ... elided ..." in shown
        assert "audit.flush()" not in shown.split("def settle")[1].split("if ledger")[0]

    def test_the_same_input_always_shrinks_the_same_way(self) -> None:
        first = build({"m.py": LONG}, ("m.py", 13), budget=70)
        second = build({"m.py": LONG}, ("m.py", 13), budget=70)
        assert text_of(first) == text_of(second) and first.id == second.id

    def test_the_candidates_own_lines_are_never_elided(self) -> None:
        tight = build({"m.py": LONG}, ("m.py", 13), budget=70)
        assert "ledger.append('INSERT %s' % total)" in text_of(tight)

    def test_the_function_signature_is_never_elided(self) -> None:
        tight = build({"m.py": LONG}, ("m.py", 13), budget=70)
        assert "def settle(batch, ledger, audit):" in text_of(tight)

    def test_a_dominating_guard_is_never_elided(self) -> None:
        tight = build({"m.py": LONG}, ("m.py", 13), budget=70)
        shown = text_of(tight)
        assert "if ledger.is_open():" in shown and "if total > 0:" in shown

    def test_javascript_keeps_the_braces_that_close_kept_blocks(self) -> None:
        source = "\n".join(
            [
                "function settle(batch, ledger, audit) {",
                "  let total = 0;",
                "  for (const item of batch) {",
                "    total += item.amount;",
                "    audit.record(item.id, item.amount);",
                "    audit.flush();",
                "  }",
                "  audit.record('summary', total);",
                "  if (ledger.isOpen()) {",
                "    if (total > 0) {",
                "      ledger.append('INSERT ' + total);",
                "    }",
                "  }",
                "  audit.close();",
                "  return total;",
                "}",
                "",
            ]
        )
        tight = build({"s.js": source}, ("s.js", 11), budget=66)
        assert tight.truncated
        shown = file_text(list(tight.segments), Language.JAVASCRIPT)
        assert parse("s.js", Language.JAVASCRIPT, shown).error_count == 0
        assert shown.count("{") == shown.count("}")

    def test_a_slice_that_cannot_fit_is_refused_and_not_sent_over_budget(self) -> None:
        with pytest.raises(SlicingError) as caught:
            build({"m.py": LONG}, ("m.py", 13), budget=20)
        assert caught.value.reason == "over_budget"

    def test_a_cut_that_would_not_parse_is_undone(self) -> None:
        source = "\n".join(
            [
                "def load(blob, log):",
                "    log.info('a')",
                "    try:",
                "        value = pickle.loads(blob)",
                "    except Exception:",
                "        value = None",
                "    log.info('b')",
                "    return value",
                "",
            ]
        )
        found = build({"m.py": source}, ("m.py", 4), budget=45)
        shown = text_of(found)
        assert "try:" in shown and "except Exception:" in shown
        assert (
            parse(
                "m.py", Language.PYTHON, file_text(list(found.segments), Language.PYTHON)
            ).error_count
            == 0
        )


class TestCoherenceGuard:
    def test_a_cut_that_does_not_parse_is_never_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Even if the cutting rules were wrong, a slice that does not parse must not come out."""
        source = "\n".join(
            [
                "def route(kind, value, log):",
                "    log.info('start')",
                "    if kind == 'a':",
                "        log.info('a')",
                "    else:",
                "        log.info('other')",
                "        log.info(value)",
                "    log.info('end')",
                "    return None",
                "",
            ]
        )
        whole = build({"r.py": source}, ("r.py", 7))
        assert "if kind == 'a':" in text_of(whole)

        def broken(*_args: object, **_kwargs: object) -> set[int]:
            return {1, 5, 7}  # an `else:` with no `if`

        monkeypatch.setattr("codekavach.privacy.slicing.strategies.enclosing.kept_lines", broken)
        with pytest.raises(SlicingError) as caught:
            build({"r.py": source}, ("r.py", 7), budget=segment_tokens(whole) - 12)
        assert caught.value.reason == "over_budget"


class TestDeterminismAndArtefacts:
    def test_two_runs_give_the_same_bytes(self) -> None:
        one = build({"svc.py": SERVICE}, ("svc.py", 14))
        two = build({"svc.py": SERVICE}, ("svc.py", 14))
        assert one.model_dump_json() == two.model_dump_json()

    def test_the_order_of_the_candidate_locations_beyond_the_first_does_not_matter(self) -> None:
        sources = {
            "a.py": "def one(x):\n    return eval(x)\n",
            "b.py": "def two(y):\n    return exec(y)\n",
            "c.py": "def three(z):\n    return compile(z)\n",
        }
        index = make_index(sources)
        one = STRATEGY.build(candidate_at("a.py", 2, ("b.py", 2), ("c.py", 2)), index, budget=BIG)
        two = STRATEGY.build(candidate_at("a.py", 2, ("c.py", 2), ("b.py", 2)), index, budget=BIG)
        assert [s.path for s in one.segments] == [s.path for s in two.segments]
        assert text_of(one) == text_of(two)

    def test_a_slice_survives_the_artefact_store_without_loss(self, tmp_path: Path) -> None:
        refused_index = make_index({"v.py": "def f(x):\n    return eval(x)\n"}, vendored=("v.py",))
        truncated = build({"m.py": LONG}, ("m.py", 13), budget=70)
        whole = build({"svc.py": SERVICE}, ("svc.py", 14))
        refusal = outcome_for(STRATEGY, candidate_at("v.py", 2), refused_index, budget=BIG)
        assert isinstance(refusal, SliceRefusal)
        store = OnDiskArtefactStore(StateLayout(tmp_path / ".codekavach"), SCAN_ID)
        store.put("slices", [whole, truncated])
        store.put("slices.refusals", [refusal])
        loaded = store.get_list("slices", CodeSlice)
        assert loaded == [whole, truncated]
        for original, restored in zip([whole, truncated], loaded, strict=True):
            assert restored.strategy is original.strategy
            assert restored.token_estimate == original.token_estimate
            assert restored.truncated == original.truncated
            assert restored.segments == original.segments
            assert restored.stubs == original.stubs
        assert loaded[1].truncated
        assert store.get_list("slices.refusals", SliceRefusal) == [refusal]
        stored = "".join(
            path.read_text(encoding="utf-8") for path in (tmp_path / ".codekavach").rglob("*.json")
        )
        assert str(tmp_path) not in stored  # no absolute path, handle or index in the artefact


# --- properties ---------------------------------------------------------------------------


@st.composite
def programs(draw: st.DrawFn) -> tuple[str, list[int]]:
    """A Python module with one function holding nested compound statements; returns code lines."""
    lines: list[str] = ["import os", "", "", "def work(a, b):"]
    candidates: list[int] = []

    def block(depth: int, indent: str) -> None:
        for _ in range(draw(st.integers(1, 3))):
            kind = draw(st.sampled_from(["simple", "if", "for", "while", "try", "with"]))
            if kind == "simple" or depth >= 3:
                lines.append(f"{indent}x = os.getcwd() + str(a)")
                candidates.append(len(lines))
            elif kind == "if":
                lines.append(f"{indent}if a > b:")
                block(depth + 1, indent + "    ")
                if draw(st.booleans()):
                    lines.append(f"{indent}else:")
                    block(depth + 1, indent + "    ")
            elif kind in {"for", "while", "with"}:
                header = {"for": "for i in range(b):", "while": "while a:", "with": "with a:"}[kind]
                lines.append(f"{indent}{header}")
                block(depth + 1, indent + "    ")
            else:
                lines.append(f"{indent}try:")
                block(depth + 1, indent + "    ")
                lines.append(f"{indent}except Exception:")
                lines.append(f"{indent}    pass")

    block(0, "    ")
    lines.append("    return a")
    return "\n".join(lines) + "\n", candidates


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(programs(), st.integers(30, 400), st.data())
def test_generated_slices_parse_contain_the_candidate_and_do_not_overlap(
    program: tuple[str, list[int]], budget: int, data: st.DataObject
) -> None:
    source, candidates = program
    line = data.draw(st.sampled_from(candidates))
    index = make_index({"w.py": source})
    candidate = candidate_at("w.py", line)
    try:
        found = STRATEGY.build(candidate, index, budget=SliceBudget(budget))
    except SlicingError as refused:
        assert refused.reason == "over_budget"  # never "not_coherent": a cut that parses exists
        return
    shown = file_text(list(found.segments), found.language)
    assert parse("w.py", Language.PYTHON, shown).error_count == 0
    assert any(s.region.contains_line(line) for s in found.segments)
    assert found.token_estimate <= budget
    spans = [(s.region.start_line, s.region.end_line) for s in found.segments]
    assert all(a[1] < b[0] for a, b in pairwise(spans))
    again = STRATEGY.build(candidate, index, budget=SliceBudget(budget))
    assert again.model_dump_json() == found.model_dump_json()
