"""Stubs for out-of-slice callees, class fields and imports (E11-02).

The worked example of the issue is a named regression test; each rule that keeps a stub from
becoming a leak (defaults replaced, no body, docstring or comment, nothing for a public or a
never-send callee) has its own test; the summary grammar is checked clause by clause; and two
properties run over generated source: no stub holds a byte of the callee's body, and the stub set
does not depend on the order of the calls.
"""

import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from tree_sitter import Node

from codekavach.config import Settings
from codekavach.core.models import CodeSlice, Language, StubReason
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.functions import FunctionRange
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import build_symbol_table
from codekavach.privacy.pseudonymise.classify import IdentifierClass, classify_all
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator, PseudonymKind
from codekavach.privacy.slicing.assemble import assemble, numbered_labels
from codekavach.privacy.slicing.base import outcome_for
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.index import ParseIndex, never_send_matcher
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from codekavach.privacy.slicing.stubs import (
    EffectSummary,
    StubStats,
    build_stubs,
    callees_of,
    effect_summary,
    function_node,
    is_valid_summary,
    make_stubs,
    parameter_names,
    signature_of,
)
from tests.support.slicing import candidate_at, make_index
from tests.unit.privacy.slicing.test_fixtures import CASES, load, run

STRATEGY = EnclosingFunctionStrategy()

SERVICE = '''from billing.bonus import compute_bonus


class AccountService:
    tier_cap: int = 5

    def accrue(self, account_id):
        rate = self._lookup_rate(account_id)
        return compute_bonus(rate, self.tier_cap)

    def _lookup_rate(self, account_id):
        """Festival rate lookup."""
        # KavachBank internal note
        return account_id
'''
BONUS = '''def compute_bonus(rate, cap):
    """Bonus for the festival season."""
    return 1.5
'''


def build(
    sources: dict[str, str],
    where: tuple[str, int],
    *,
    budget: int = 4000,
    never_send: list[str] | None = None,
    vendored: tuple[str, ...] = (),
) -> tuple[ParseIndex, CodeSlice, StubStats]:
    matcher = None
    if never_send:
        matcher = never_send_matcher(
            Settings.model_validate({"privacy": {"never_send": never_send}})
        )
    index = make_index(sources, vendored=vendored, never_send=matcher)
    found, stats = STRATEGY.build_with_stats(
        candidate_at(*where), index, budget=SliceBudget(budget)
    )
    return index, found, stats


def stub_texts(found: CodeSlice) -> list[str]:
    labels = numbered_labels([s.path for s in found.segments])
    del labels
    ordered = sorted(found.stubs, key=lambda s: (s.path or "", s.line or 0, s.symbol))
    return [stub.signature.expose() for stub in ordered]


def node_of(
    source: str, name: str, *, language: Language = Language.PYTHON, path: str = "m.py"
) -> tuple[ParsedFile, Node, FunctionRange]:
    """The function node and parsed file of ``name`` in ``source``."""
    index = make_index({path: source})
    function = next(r for r in index.function_ranges_of(path) if r.symbol_name == name)
    file = index.parsed_of(path)
    node = function_node(file, function)
    assert node is not None
    assert file.language is language
    return file, node, function


# --- the worked example -----------------------------------------------------------------------


def test_worked_example_produces_exactly_the_documented_stubs_and_summaries() -> None:
    _, found, stats = build(
        {"billing/service.py": SERVICE, "billing/bonus.py": BONUS}, ("billing/service.py", 9)
    )
    assert stub_texts(found) == [
        "# cross_file\n"
        "def compute_bonus(rate, cap): ...\n"
        "# returns value; no parameter flows to return; no sanitiser; derived: syntactic",
        "# class context\nclass AccountService:\n    tier_cap: int",
        "# out_of_slice\n"
        "def _lookup_rate(self, account_id): ...\n"
        "# returns value; param_0 flows to return; no sanitiser; derived: syntactic",
    ]
    assert stats.stubs_omitted == 0
    assert [s.reason for s in found.stubs] == [
        StubReason.OUT_OF_SLICE_CALLEE,
        StubReason.CROSS_FILE_CALLEE,
        StubReason.CLASS_CONTEXT,
    ] or {s.reason for s in found.stubs} == {
        StubReason.OUT_OF_SLICE_CALLEE,
        StubReason.CROSS_FILE_CALLEE,
        StubReason.CLASS_CONTEXT,
    }


def test_no_stub_holds_the_docstring_a_comment_or_a_body() -> None:
    _, found, _ = build(
        {"billing/service.py": SERVICE, "billing/bonus.py": BONUS}, ("billing/service.py", 9)
    )
    text = "\n".join(stub_texts(found))
    for forbidden in ("Festival", "festival", "KavachBank", "1.5"):
        assert forbidden not in text


# --- reasons and omissions --------------------------------------------------------------------


def test_a_callee_on_the_public_allowlist_gets_no_stub_and_is_counted() -> None:
    source = (
        "import json\nimport hashlib\n\n\ndef digest(p):\n    t = json.dumps(p)\n"
        "    return hashlib.sha256(t.encode()).hexdigest()\n"
    )
    _, found, stats = build({"d.py": source}, ("d.py", 7))
    assert found.stubs == ()
    assert stats.omitted_public >= 2


@pytest.mark.parametrize("flag", ["never_send", "vendored"])
def test_a_callee_in_an_excluded_file_gets_no_stub_and_is_counted(flag: str) -> None:
    sources = {
        "app/h.py": (
            "from vault.keys import load_key\n\n\ndef sign(m):\n"
            "    key = load_key()\n    return m + key\n"
        ),
        "vault/keys.py": "def load_key():\n    return 'k'\n",
    }
    options = (
        {"never_send": ["vault/**"]} if flag == "never_send" else {"vendored": ("vault/keys.py",)}
    )
    _, found, stats = build(sources, ("app/h.py", 6), **options)
    assert not [s for s in found.stubs if s.symbol == "load_key"]
    assert stats.omitted_excluded == 1


def test_a_callee_in_the_slice_gets_no_stub() -> None:
    source = (
        "def walk(n, d):\n    if n is None:\n        return d\n    return walk(n.next, d + 1)\n"
    )
    _, found, _ = build({"w.py": source}, ("w.py", 3))
    assert found.stubs == ()


def test_each_reason_is_classified() -> None:
    sources = {
        "a/main.py": (
            "from flask import unlisted_helper\nfrom a.other import far\n\n\ndef run(x):\n"
            "    near(x)\n    far(x)\n    unlisted_helper(x)\n    mystery(x)\n    return x\n\n\n"
            "def near(x):\n    return x\n"
        ),
        "a/other.py": "def far(x):\n    return x\n",
    }
    _, found, _ = build(sources, ("a/main.py", 10))
    by_symbol = {s.symbol: s.reason for s in found.stubs}
    assert by_symbol["near"] is StubReason.OUT_OF_SLICE_CALLEE
    assert by_symbol["far"] is StubReason.CROSS_FILE_CALLEE
    assert by_symbol["mystery"] is StubReason.UNRESOLVED_CALLEE


def test_a_call_on_an_arbitrary_object_is_not_a_callee() -> None:
    source = "def f(ledger):\n    ledger.is_open()\n    return 1\n"
    index = make_index({"f.py": source})
    found = STRATEGY.build(candidate_at("f.py", 3), index, budget=SliceBudget(4000))
    assert callees_of(found.segments, index) == ()


# --- defaults and literals --------------------------------------------------------------------


def test_every_default_in_a_python_signature_is_replaced() -> None:
    source = (
        'def f(a: int = 5, b="festival", *args, c: str = "x", d=(1, 2), **kw) -> "Result":\n'
        "    return a\n"
    )
    file, node, function = node_of(source, "f")
    text = signature_of(file, node, function.symbol_name)
    assert text == "def f(a: int = ..., b=..., *args, c: str = ..., d=..., **kw) -> ...: ..."
    for leaked in ("festival", "5", "(1, 2)", '"x"', "Result"):
        assert leaked not in text


def test_nested_defaults_in_destructured_javascript_parameters_are_replaced() -> None:
    source = (
        'export function build({ mode = "fast", level: lvl = 2 } = {}, [a = 1, b] = [], '
        "size = 10) {\n  return size;\n}\n"
    )
    file, node, function = node_of(source, "build", language=Language.JAVASCRIPT, path="b.js")
    text = signature_of(file, node, function.symbol_name)
    assert text == (
        "function build({ mode = undefined, level: lvl = undefined } = undefined, "
        "[a = undefined, b] = undefined, size = undefined) {}"
    )


def test_a_string_literal_in_an_annotation_is_replaced() -> None:
    source = 'def f(mode: Literal["secret-mode"]) -> None:\n    pass\n'
    file, node, function = node_of(source, "f")
    assert "secret-mode" not in signature_of(file, node, function.symbol_name)


# --- signatures per language ------------------------------------------------------------------


def test_python_signature_keeps_annotations_async_and_the_static_decorators() -> None:
    source = (
        "class C:\n"
        "    @staticmethod\n"
        "    def s(x: int) -> int:\n        return x\n\n"
        "    @app.route('/secret/path')\n"
        "    async def a(self, y: 'Model', *, z=None):\n        return y\n"
    )
    file, node, _ = node_of(source, "s")
    assert signature_of(file, node, "s") == "@staticmethod\ndef s(x: int) -> int: ..."
    file, node, _ = node_of(source, "a")
    text = signature_of(file, node, "a")
    assert text == "async def a(self, y: ..., *, z=...): ..."
    assert "secret" not in text


def test_typescript_signature_keeps_types_generics_and_async() -> None:
    source = (
        "export async function load<T>(id: string, retries: number = 3): Promise<T> {\n"
        "  return fetchIt(id);\n}\n"
    )
    file, node, _ = node_of(source, "load", language=Language.TYPESCRIPT, path="l.ts")
    assert (
        signature_of(file, node, "load")
        == "async function load<T>(id: string, retries: number = undefined): Promise<T> {}"
    )


def test_an_arrow_function_with_one_bare_parameter_has_a_parenthesised_signature() -> None:
    source = "const inc = x => x + 1;\n"
    file, node, _ = node_of(source, "inc", language=Language.JAVASCRIPT, path="i.js")
    assert signature_of(file, node, "inc") == "function inc(x) {}"


def test_parameter_names_drop_the_receiver_and_cover_destructuring() -> None:
    _, node, _ = node_of("class C:\n    def m(self, a, b=1, *c, **d):\n        pass\n", "m")
    assert parameter_names(node, drop_receiver=True) == [["a"], ["b"], ["c"], ["d"]]
    _, node, _ = node_of(
        "function f({ x, y: z }, [p, q], r) {}\n", "f", language=Language.JAVASCRIPT, path="f.js"
    )
    assert [sorted(group) for group in parameter_names(node, drop_receiver=False)] == [
        ["x", "z"],
        ["p", "q"],
        ["r"],
    ]


# --- the effect summary -----------------------------------------------------------------------


def summary_of(source: str, name: str = "f", **kwargs: object) -> str:
    language = (
        Language.PYTHON if source.startswith(("def", "async", "class")) else Language.JAVASCRIPT
    )
    _, node, _ = node_of(
        source, name, language=language, path="m.py" if language is Language.PYTHON else "m.js"
    )
    return effect_summary(node, language, **kwargs).render()  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("def f(a):\n    pass\n", "returns nothing; no sanitiser; derived: syntactic"),
        (
            "def f(a):\n    return 1\n",
            "returns value; no parameter flows to return; no sanitiser; derived: syntactic",
        ),
        (
            "def f(a, b):\n    return b\n",
            "returns value; param_1 flows to return; no sanitiser; derived: syntactic",
        ),
        (
            "def f(a):\n    x = a\n    y = x + 1\n    return y\n",
            "returns value; param_0 flows to return; no sanitiser; derived: syntactic",
        ),
        (
            "def f(a):\n    return escape(a)\n",
            "returns value; param_0 flows to return; calls allowlisted sanitiser: escape; "
            "derived: syntactic",
        ),
        (
            "def f(a):\n    subprocess.run(a)\n    cur.execute(a)\n",
            "returns nothing; no sanitiser; calls sink family: sql; calls sink family: subprocess; "
            "derived: syntactic",
        ),
        (
            "def f(a):\n    raise ValueError(a)\n",
            "returns nothing; no sanitiser; raises; derived: syntactic",
        ),
        (
            "def f(a):\n    yield a\n",
            "returns value; param_0 flows to return; no sanitiser; derived: syntactic",
        ),
        (
            "def f(a):\n    def g():\n        return a\n    pass\n",
            "returns nothing; no sanitiser; derived: syntactic",
        ),
        (
            "const f = (a) => a;\n",
            "returns value; param_0 flows to return; no sanitiser; derived: syntactic",
        ),
        (
            "function f(a) {\n  eval(a);\n  throw new Error('x');\n}\n",
            "returns nothing; no sanitiser; calls sink family: eval; raises; derived: syntactic",
        ),
    ],
)
def test_the_effect_summary_has_one_clause_per_fact(source: str, expected: str) -> None:
    assert summary_of(source) == expected


def test_every_summary_follows_the_grammar_and_asserts_no_safety() -> None:
    combos = [
        EffectSummary(known=False),
        EffectSummary(returns_value=True, flows_to_return=(0, 2), sanitiser="escape", raises=True),
        EffectSummary(sink_families=("eval", "sql"), source="taint"),
    ]
    for summary in combos:
        line = summary.render()
        assert is_valid_summary(line), line
        assert not re.search(r"\b(safe|secure|sanitised|clean|validated)\b", line)
    assert not is_valid_summary("returns value; input is safe; derived: syntactic")
    assert not is_valid_summary("returns value; no sanitiser")


def test_every_summary_line_in_every_fixture_golden_is_valid() -> None:
    seen = 0
    for folder in CASES:
        outcome, _ = run(folder)
        if not isinstance(outcome, CodeSlice):
            continue
        for stub in outcome.stubs:
            for line in stub.signature.expose().splitlines():
                body = line.removeprefix("# ").removeprefix("// ")
                if body.startswith(("returns ", "effects ")):
                    assert is_valid_summary(body), body
                    seen += 1
    assert seen >= 10


# --- class context and imports ----------------------------------------------------------------


def test_a_class_stub_lists_only_the_referenced_fields_and_no_initialiser() -> None:
    source = (
        "class Ledger:\n    region: str = 'south'\n    cap: int = 5\n    floor = 1\n\n"
        "    def __init__(self, store):\n        self.store = store\n\n"
        "    def post(self, e):\n        if e > self.cap:\n            raise ValueError\n"
        "        return self.store.append(e)\n"
    )
    _, found, _ = build({"l.py": source}, ("l.py", 12))
    (klass,) = [s for s in found.stubs if s.reason is StubReason.CLASS_CONTEXT]
    assert (
        klass.signature.expose() == "# class context\nclass Ledger:\n    cap: int\n    store: ..."
    )
    for leaked in ("south", "= 5", "floor", "region"):
        assert leaked not in klass.signature.expose()


def class_stub_text(found: CodeSlice) -> str:
    return next(s.signature.expose() for s in found.stubs if s.reason is StubReason.CLASS_CONTEXT)


def test_a_public_base_class_is_kept_and_an_internal_one_is_replaced() -> None:
    template = (
        "import unittest\n\n\nclass T({base}):\n    cap: int = 1\n\n"
        "    def m(self):\n        return self.cap\n"
    )
    _, public, _ = build({"t.py": template.format(base="flask.views.View")}, ("t.py", 8))
    _, internal, _ = build({"t.py": template.format(base="SecretBase")}, ("t.py", 8))
    assert "class T(flask.views.View):" in class_stub_text(public)
    assert "class T(Base):" in class_stub_text(internal) and "SecretBase" not in class_stub_text(
        internal
    )


def test_an_internal_import_loses_its_module_path_and_a_public_one_is_kept() -> None:
    sources = {
        "post.py": (
            "import json\nfrom billing.rates import RATE_TABLE\n\n\ndef post(entry):\n"
            "    data = json.dumps(entry)\n    return RATE_TABLE[data]\n"
        ),
        "billing/rates.py": "RATE_TABLE = {}\n",
    }
    _, found, _ = build(sources, ("post.py", 7), budget=36)
    texts = [s.signature.expose() for s in found.stubs if s.reason is StubReason.IMPORT_CONTEXT]
    assert "from _internal import RATE_TABLE" in texts
    assert not any("billing" in t for t in texts)
    _, roomy, _ = build(sources, ("post.py", 7), budget=60)
    assert not [s for s in roomy.stubs if s.reason is StubReason.IMPORT_CONTEXT]  # imports are in


# --- budget, order, duplicates ----------------------------------------------------------------

HELPERS = "".join(
    f"def {n}(value):\n    return value\n\n\n" for n in ("alpha", "beta", "gamma", "delta")
)
WORK = (
    "from app.helpers import alpha, beta, gamma, delta\n\n\ndef work(item):\n"
    "    first = alpha(item)\n    beta(item)\n    gamma(item)\n    delta(item)\n    return first\n"
)


def test_stubs_are_dropped_in_priority_order_and_counted() -> None:
    index = make_index({"app/work.py": WORK, "app/helpers.py": HELPERS})
    found = STRATEGY.build(candidate_at("app/work.py", 9), index, budget=SliceBudget(4000))
    full = build_stubs(found.segments, index, candidate_path="app/work.py", candidate_line=9)
    assert next(s.symbol for s in full.stubs) == "alpha"  # the data path first
    assert [s.symbol for s in full.stubs] == ["alpha", "beta", "delta", "gamma"]
    one = full.stubs[0].signature.expose()
    tight = build_stubs(
        found.segments,
        index,
        candidate_path="app/work.py",
        candidate_line=9,
        budget_tokens=len(one) // 3 + 3,
    )
    assert [s.symbol for s in tight.stubs] == ["alpha"]
    assert tight.stats.stubs_omitted == 3
    assert tight.stats.omitted_reasons == (("cross_file", 3),)


def test_a_slice_with_stubs_never_exceeds_its_budget() -> None:
    index = make_index({"app/work.py": WORK, "app/helpers.py": HELPERS})
    checked = 0
    for budget in range(60, 220, 7):
        outcome = outcome_for(
            STRATEGY, candidate_at("app/work.py", 9), index, budget=SliceBudget(budget)
        )
        if isinstance(outcome, CodeSlice):  # a refusal is allowed; exceeding the budget is not
            assert outcome.token_estimate <= budget
            checked += 1
    assert checked >= 10


def test_one_stub_per_definition_however_often_it_is_called() -> None:
    source = (
        "def f(x):\n    helper(x)\n    helper(x)\n    helper(x)\n    return 0\n\n\n"
        "def helper(v):\n    return v\n"
    )
    _, found, _ = build({"f.py": source}, ("f.py", 5))
    assert [s.symbol for s in found.stubs] == ["helper"]


NAMES = st.lists(st.sampled_from(["aa", "bb", "cc", "dd", "ee"]), min_size=1, max_size=8)


@settings(max_examples=40, deadline=None)
@given(order=NAMES)
def test_the_stub_set_is_deterministic_and_deduplicated_whatever_the_call_order(
    order: list[str],
) -> None:
    helpers = "".join(f"def {n}(v):\n    return v\n\n\n" for n in ("aa", "bb", "cc", "dd", "ee"))
    calls = "".join(f"    {n}(x)\n" for n in order)
    caller = f"from h import aa, bb, cc, dd, ee\n\n\ndef run(x):\n{calls}    return 0\n"
    _, found, _ = build({"run.py": caller, "h.py": helpers}, ("run.py", 5 + len(order)))
    symbols = [s.symbol for s in found.stubs]
    assert symbols == sorted(set(order))


WORDS = st.from_regex(r"zq[a-z]{6,10}", fullmatch=True)


@settings(max_examples=40, deadline=None)
@given(var=WORDS, text=WORDS, note=WORDS)
def test_no_stub_holds_any_byte_of_the_callee_body(var: str, text: str, note: str) -> None:
    callee = (
        f'def helper(a, b=1):\n    """{text} docs"""\n    # {note}\n    {var} = a\n'
        f'    other = "{text}"\n    return {var}\n'
    )
    caller = "from h import helper\n\n\ndef run(x):\n    y = helper(x)\n    return y\n"
    _, found, _ = build({"run.py": caller, "h.py": callee}, ("run.py", 6))
    assert [s.symbol for s in found.stubs] == ["helper"]
    joined = "\n".join(stub_texts(found))
    for sentinel in (var, text, note):
        assert sentinel not in joined


# --- the assembled slice ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "folder", [c for c in CASES if c.name.startswith("stub")], ids=lambda c: c.name
)
def test_the_assembled_slice_with_stubs_parses_in_its_language(folder) -> None:  # type: ignore[no-untyped-def]
    outcome, _ = run(folder)
    assert isinstance(outcome, CodeSlice)
    labels = numbered_labels([s.path for s in outcome.segments])
    text = assemble(outcome.segments, outcome.stubs, language=outcome.language, labels=labels)
    assert parse("slice", outcome.language, text).error_count == 0


def test_there_are_at_least_fifteen_stub_cases_in_three_languages() -> None:
    stub_cases = [c for c in CASES if c.name.startswith("stub")]
    assert len(stub_cases) >= 15
    extensions = {p.suffix for c in stub_cases for p in (c / "src").rglob("*") if p.is_file()}
    assert {".py", ".js", ".ts"} <= extensions
    for case in stub_cases:
        assert (case / "golden.txt").is_file()
        assert load(case)[0]["locations"]


def test_a_stubs_internal_names_are_renamed_before_the_payload_leaves() -> None:
    """The names in stub text go through the classifier and the generator like any other name.

    The renamer itself (E09-04) is not in the tree yet, so this test applies the generator to the
    identifiers the classifier calls internal and checks that none survives and that the result
    still parses.
    """
    _, found, _ = build(
        {"billing/service.py": SERVICE, "billing/bonus.py": BONUS}, ("billing/service.py", 9)
    )
    labels = numbered_labels([s.path for s in found.segments])
    text = assemble(found.segments, found.stubs, language=found.language, labels=labels)
    parsed = parse("slice.py", Language.PYTHON, text)
    table = build_symbol_table(parsed, REGISTRY.get(Language.PYTHON))
    result = classify_all(parsed, table)
    internal = sorted(
        {
            s.name
            for s, d in zip(table.symbols, result.decisions, strict=True)
            if d.classification is IdentifierClass.INTERNAL
        }
    )
    for name in ("_lookup_rate", "compute_bonus", "tier_cap", "AccountService"):
        assert name in internal
    generator = PseudonymGenerator(ScanSalt(bytes(range(32))))
    generator.prepare(PseudonymKind.FN, internal)
    renamed = text
    for name in sorted(internal, key=len, reverse=True):
        renamed = re.sub(
            rf"\b{re.escape(name)}\b", generator.token(PseudonymKind.FN, name), renamed
        )
    for name in ("_lookup_rate", "compute_bonus", "tier_cap", "AccountService"):
        assert name not in renamed
    assert parse("renamed.py", Language.PYTHON, renamed).error_count == 0


def test_make_stubs_returns_the_stubs_of_the_given_callees() -> None:
    index = make_index({"billing/service.py": SERVICE, "billing/bonus.py": BONUS})
    found = STRATEGY.build(candidate_at("billing/service.py", 9), index, budget=SliceBudget(4000))
    stubs = make_stubs(callees_of(found.segments, index), index, segments=found.segments)
    assert [s.symbol for s in stubs] == ["AccountService._lookup_rate", "compute_bonus"]
