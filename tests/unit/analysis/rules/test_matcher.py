"""The structural matcher: compilation, binding, constraints, clauses and taint (E16-02)."""

import string
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.analysis.rules.compile import PatternSyntaxError, compile_pattern, rewrite
from codekavach.analysis.rules.dsl import RuleDef
from codekavach.analysis.rules.matcher import Matcher, TaintHit
from codekavach.core.models import Language
from codekavach.parsing import parse
from tests.support.rule_files import rule_data
from tests.support.rules import catalogue_entry, lines_of, matches_of, rule_of

PY = Language.PYTHON
JS = Language.JAVASCRIPT

FIND = """def find(owner, cur):
    cur.execute("SELECT * FROM accounts WHERE owner = '" + owner + "'")
    cur.execute("SELECT * FROM accounts WHERE owner = ?", (owner,))
"""
WORKED = rule_data()["match"]
NL = chr(10)


# --- compilation ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "anchor"),
    [
        ("$CUR.execute($Q)", "call"),
        ("$X = $Y", "assignment"),
        ("@app.route($P)\ndef $F(...): ...", "decorated_definition"),
        ("f($...ARGS)", "call"),
        ("def $F(...): ...", "function_definition"),
    ],
)
def test_a_pattern_compiles_to_its_anchor_kind(pattern: str, anchor: str) -> None:
    assert compile_pattern(pattern, PY).anchor_kind == anchor


def test_metavariable_names_are_recorded() -> None:
    assert compile_pattern("$A.f($B, $...C)", PY).names == {"A", "B", "C"}


@pytest.mark.parametrize("pattern", ["def (", "f(", "", "$X"])
def test_an_unparseable_or_bare_pattern_raises_ck_rule_011(pattern: str) -> None:
    with pytest.raises(PatternSyntaxError) as caught:
        compile_pattern(pattern, PY)
    assert caught.value.code == "CK-RULE-011"


def test_text_inside_a_string_is_not_rewritten() -> None:
    text, names = rewrite('f("$X ... $...Y", $Z)')
    assert '"$X ... $...Y"' in text
    assert names == {"Z"}


def test_compiled_patterns_are_cached() -> None:
    assert compile_pattern("f($X)", PY) is compile_pattern("f($X)", PY)


# --- the worked example --------------------------------------------------------------------


def test_the_worked_example_matches_once_on_the_concatenating_call() -> None:
    found = matches_of(FIND, WORKED)
    assert len(found) == 1
    assert lines_of(FIND, found) == [2]
    assert found[0].node_type == "call"


# --- binding and consistency ---------------------------------------------------------------


def test_a_metavariable_bound_twice_must_bind_equal_text() -> None:
    code = "a.run(a)\nb.run(c)\nb.run(  b )\n"
    found = matches_of(code, {"any": [{"pattern": "$X.run($X)"}]})
    assert lines_of(code, found) == [1, 3]  # whitespace is normalised, other text is not


def test_bindings_are_reported_as_text() -> None:
    found = matches_of("cur.execute(q)\n", {"any": [{"pattern": "$C.execute($Q)"}]})
    assert dict(found[0].bindings) == {"$C": "cur", "$Q": "q"}


def test_a_variadic_metavariable_binds_the_remaining_arguments() -> None:
    found = matches_of("f(1, 2, 3)\n", {"any": [{"pattern": "f($A, $...REST)"}]})
    assert dict(found[0].bindings) == {"$A": "1", "$...REST": "2 3"}


def test_an_underscore_matches_one_node_only() -> None:
    code = "f(1)\nf(1, 2)\nf()\n"
    assert lines_of(code, matches_of(code, {"any": [{"pattern": "f(_)"}]})) == [1]


def test_an_ellipsis_matches_any_arguments_including_none() -> None:
    code = "f()\nf(1)\nf(1, 2, 3)\ng(1)\n"
    found = matches_of(code, {"any": [{"pattern": "f(...)"}]})
    assert lines_of(code, found) == [1, 2, 3]


def test_an_ellipsis_between_arguments_keeps_the_ends_fixed() -> None:
    code = "f(a, b, c)\nf(a, c)\nf(a, b)\n"
    found = matches_of(code, {"any": [{"pattern": "f(a, ..., c)"}]})
    assert lines_of(code, found) == [1, 2]


def test_an_ellipsis_across_statements() -> None:
    code = "def a():\n    x = open(p)\n    y = 1\n    z = 2\n    x.read()\ndef b():\n    x.read()\n"
    pattern = "x = open($P)\n...\nx.read()"
    found = matches_of(code, {"any": [{"pattern": pattern}]})
    assert lines_of(code, found) == [2]


def test_a_string_ellipsis_matches_any_string_literal() -> None:
    code = 'f("a")\nf(b)\nf("c" "d")\n'
    found = matches_of(code, {"any": [{"pattern": 'f("...")'}]})
    assert lines_of(code, found) == [1]


def test_javascript_patterns_match() -> None:
    code = "db.query('a' + id);\ndb.query('a', [id]);\n"
    match = {
        "any": [
            {
                "pattern": "$D.query($Q)",
                "where": [{"metavariable": "$Q", "kind": "concatenation"}],
            }
        ]
    }
    found = matches_of(code, match, language=JS, languages=["javascript"])
    assert lines_of(code, found) == [1]


# --- constraints ---------------------------------------------------------------------------

CONSTRAINT_CODE = (
    'f("abc")\n'  # 1
    'f("a" + "b")\n'  # 2
    "f(name)\n"  # 3
    'f("a" + name)\n'  # 4
    'f(f"a{name}")\n'  # 5
    "f(12)\n"  # 6
    'f("x".upper())\n'  # 7
)


def constrained(**condition: Any) -> list[int]:
    match = {
        "any": [
            {"pattern": "f($V)", "where": [{"metavariable": "$V", **condition}]},
        ]
    }
    return lines_of(CONSTRAINT_CODE, matches_of(CONSTRAINT_CODE, match))


def test_kind_concatenation() -> None:
    assert constrained(kind="concatenation") == [2, 4]


def test_kind_interpolation() -> None:
    assert constrained(kind="interpolation") == [5]


def test_kind_call_identifier_and_literal() -> None:
    assert constrained(kind="call") == [7]
    assert constrained(kind="identifier") == [3]
    assert constrained(kind="literal") == [1, 5, 6]


def test_is_constant_over_literals_and_concatenations_of_literals() -> None:
    assert constrained(is_constant=True) == [1, 2, 6]


def test_is_constant_false_selects_everything_else() -> None:
    assert constrained(is_constant=False) == [3, 4, 5, 7]


def test_regex_and_not_regex_look_at_the_bound_text() -> None:
    assert constrained(regex="^name$") == [3]
    assert constrained(not_regex="name|abc|upper") == [2, 6]


def test_min_length_counts_the_string_content() -> None:
    code = "f('ab')" + NL + "f('abcd')" + NL + "f(name_that_is_long)" + NL
    match = {"any": [{"pattern": "f($V)", "where": [{"metavariable": "$V", "min_length": 3}]}]}
    assert lines_of(code, matches_of(code, match)) == [2, 3]


def test_equals_and_one_of_accept_the_literal_content() -> None:
    assert constrained(equals="abc") == [1]
    assert constrained(one_of=["abc", "12"]) == [1, 6]


def test_catalogue_resolution_hit_and_miss() -> None:
    code = "run(shell_cmd(a))\nrun(safe(a))\n"
    entry = catalogue_entry("python.sinks.shell-cmd", "shell_cmd(...)")
    matcher = Matcher(catalogues={entry.id: (PY, entry)})
    match = {
        "any": [
            {
                "pattern": "run($X)",
                "where": [{"metavariable": "$X", "catalogue": entry.id}],
            }
        ]
    }
    assert lines_of(code, matches_of(code, match, matcher=matcher)) == [1]
    assert matches_of(code, match) == []  # no catalogue loaded: a miss, never an error


# --- clauses -------------------------------------------------------------------------------

CLAUSE_CODE = """\
import os


class A:
    def m(self, x):
        os.system(x)
        os.popen(x)


def top(x):
    os.system(x)
    eval(x)
"""


def clause_lines(match: dict[str, Any]) -> list[int]:
    return lines_of(CLAUSE_CODE, matches_of(CLAUSE_CODE, match))


def test_any_is_a_union() -> None:
    match = {"any": [{"pattern": "os.system(...)"}, {"pattern": "eval(...)"}]}
    assert clause_lines(match) == [6, 11, 12]


def test_all_requires_every_clause_at_the_anchor() -> None:
    match = {
        "any": [{"pattern": "os.system($X)"}],
        "all": [{"pattern_inside": "class $C: ..."}],
    }
    assert clause_lines(match) == [6]


def test_none_removes_matches_at_the_same_anchor_only() -> None:
    match = {"any": [{"pattern": "os.$F($X)"}], "none": [{"pattern": "os.popen(...)"}]}
    assert clause_lines(match) == [6, 11]


def test_pattern_inside_walks_the_ancestors() -> None:
    match = {
        "any": [{"pattern": "os.system(...)"}],
        "all": [{"pattern_inside": "def top(...): ..."}],
    }
    assert clause_lines(match) == [11]


def test_pattern_not_inside_is_the_negation() -> None:
    match = {
        "any": [{"pattern": "os.system(...)"}],
        "all": [{"pattern_not_inside": "class $C: ..."}],
    }
    assert clause_lines(match) == [11]


def test_ref_expands_another_rule() -> None:
    other = rule_of({"any": [{"pattern": "eval(...)"}]}, id="python.misc.eval")
    match = {"any": [{"ref": "python.misc.eval"}, {"pattern": "os.popen(...)"}]}
    found = [m for m in matches_of(CLAUSE_CODE, match, extra=[other]) if m.rule is not other]
    assert lines_of(CLAUSE_CODE, found) == [7, 12]


def test_a_ref_cycle_does_not_loop_at_match_time() -> None:
    a = rule_of({"any": [{"ref": "python.misc.b"}]}, id="python.misc.a")
    b = rule_of({"any": [{"ref": "python.misc.a"}]}, id="python.misc.b")
    parsed = parse("a.py", PY, "x = 1\n")
    result = Matcher().match_detailed(parsed, [a, b])
    assert result.matches == []


def test_pattern_regex_matches_text_spans() -> None:
    code = "a = 1\nSECRET_TOKEN_X\n"
    found = matches_of(code, {"any": [{"pattern_regex": "SECRET_[A-Z_]+"}]})
    assert lines_of(code, found) == [2]


def test_rules_for_other_languages_are_not_applied() -> None:
    assert matches_of("f(1)\n", {"any": [{"pattern": "f(1)"}]}, languages=["javascript"]) == []


def test_matches_are_in_source_order() -> None:
    code = "f(2)\nf(1)\n"
    found = matches_of(code, {"any": [{"pattern": "f($X)"}]})
    assert [m.start_byte for m in found] == sorted(m.start_byte for m in found)


# --- failures ------------------------------------------------------------------------------


def test_a_rule_that_cannot_compile_is_reported_and_the_others_still_run() -> None:
    bad = rule_of({"any": [{"pattern": "def ("}]}, id="python.misc.bad")
    good = rule_of({"any": [{"pattern": "eval(...)"}]}, id="python.misc.eval")
    result = Matcher().match_detailed(parse("a.py", PY, "eval(x)\n"), [bad, good])
    assert [f.rule_id for f in result.failures] == ["python.misc.bad"]
    assert result.failures[0].code == "rule_error"
    assert [m.rule.id for m in result.matches] == ["python.misc.eval"]


def test_a_rule_over_its_time_budget_is_a_timeout() -> None:
    code = "f(" + ", ".join(["1"] * 400) + ")\n"
    rule = rule_of({"any": [{"pattern": "f(..., 1, ..., 1, ..., 1, ..., 2)"}]})
    result = Matcher(rule_seconds=0.0).match_detailed(parse("a.py", PY, code), [rule])
    assert [f.code for f in result.failures] == ["rule_timeout"]
    assert result.matches == []


# --- taint ---------------------------------------------------------------------------------


class FakeTaint:
    def __init__(self, hits: list[TaintHit]) -> None:
        self.hits = hits

    def find_paths(self, parsed: Any, sources: Any, sinks: Any, sanitisers: Any) -> list[TaintHit]:
        return self.hits


def taint_rule() -> RuleDef:
    return RuleDef.model_validate(
        rule_data(
            id="python.taint.exec",
            match={},
            taint={"sources": ["python.src.req"], "sinks": ["python.sink.exec"]},
        )
    )


def taint_matcher(engine: Any) -> Matcher:
    sink = catalogue_entry("python.sink.exec", "exec($X)")
    return Matcher(catalogues={sink.id: (PY, sink)}, taint_engine=engine)


def test_a_taint_engine_decides_the_matches() -> None:
    code = "exec(a)\nexec(b)\n"
    engine = FakeTaint([TaintHit(8, 15)])
    found = taint_matcher(engine).match_file(parse("a.py", PY, code), [taint_rule()])
    assert [(m.start_byte, m.taint_unavailable) for m in found] == [(8, False)]


def test_without_a_taint_engine_the_sink_patterns_match_and_are_marked() -> None:
    code = "exec(a)\nprint(b)\n"
    found = taint_matcher(None).match_file(parse("a.py", PY, code), [taint_rule()])
    assert [m.start_byte for m in found] == [0]
    assert all(m.taint_unavailable for m in found)


# --- the structural property ---------------------------------------------------------------

identifiers = st.text(alphabet=string.ascii_lowercase, min_size=3, max_size=10).filter(
    lambda name: name not in {"def", "for", "not", "and", "del", "try", "pass", "none", "true"}
)


@settings(max_examples=40, deadline=None)
@given(owner=identifiers, cursor=identifiers, function=identifiers)
def test_renaming_identifiers_does_not_change_a_structural_match(
    owner: str, cursor: str, function: str
) -> None:
    code = (
        f"def {function}({owner}, {cursor}):\n"
        f'    {cursor}.execute("SELECT 1 WHERE a = \'" + {owner} + "\'")\n'
    )
    assert lines_of(code, matches_of(code, WORKED)) == [2]
