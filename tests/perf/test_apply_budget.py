"""Performance budgets of the whole pseudonymiser (E09-05).

``Pseudonymiser.process`` for a 2 000-line slice does, in order: layout, parse of the redacted
text, symbol table and import origins, classification, rename plan, application, re-parse and
comparison, line map and survival self-check.

Two budgets. The parse, symbol table and import origins are the parsing layer's work and have
budgets of their own (``test_parsing_budgets``, ``test_symbols_budget``); with them replaced by a
cache, the pseudonymiser's own work takes under 120 ms, which is the budget of the issue. The
whole call, parsing included, takes under 600 ms, the budget of the symbol table, so a regression
in the part that was cached still shows. Both scale with the performance factor.
"""

import pytest

import codekavach.privacy.pseudonymise.engine as engine_module
from codekavach.core.models import Language, PrivacyLevel
from codekavach.parsing import parse
from codekavach.parsing.imports import attach_imports
from codekavach.parsing.symbols import build_symbol_table
from codekavach.privacy.pseudonymise.engine import Pseudonymiser
from tests.perf.test_rename_budget import _javascript_source, _python_source
from tests.support.factories import SCAN_ID
from tests.support.payload import SALT, segment, slice_of, unredacted
from tests.support.perf import assert_within_budget, measure

OWN_BUDGET_SECONDS = 0.120
TOTAL_BUDGET_SECONDS = 0.600
TARGET_LINES = 1990  # the layout adds a header and a label: 2 000 lines in the payload

CASES = pytest.mark.parametrize(
    ("language", "build", "path"),
    [
        (Language.PYTHON, _python_source, "slice.py"),
        (Language.JAVASCRIPT, _javascript_source, "slice.js"),
    ],
    ids=["python", "javascript"],
)


def _prepare(language: Language, build: object, path: str):  # type: ignore[no-untyped-def]
    text: str = build(TARGET_LINES)  # type: ignore[operator]
    slice_ = slice_of(segment(path, 1, text.rstrip("\n").split("\n")), language=language)
    engine = Pseudonymiser()
    redaction = unredacted(slice_, PrivacyLevel.L3, engine)
    assert redaction.text.count("\n") >= 1990

    def apply() -> str:
        result = engine.process(
            slice_, redaction, salt=SALT, level=PrivacyLevel.L3, scan_id=SCAN_ID
        )
        return result.payload.payload_hash

    return apply


@pytest.mark.perf
@CASES
def test_a_two_thousand_line_payload_is_built_within_the_total_budget(
    language: Language, build: object, path: str
) -> None:
    apply = _prepare(language, build, path)
    assert apply() == apply()  # warm the caches, and check the result is stable
    assert_within_budget(measure(apply, repeat=5), TOTAL_BUDGET_SECONDS, label=f"total {path}")


@pytest.mark.perf
@CASES
def test_the_pseudonymisers_own_work_is_within_budget_once_the_parse_is_cached(
    monkeypatch: pytest.MonkeyPatch, language: Language, build: object, path: str
) -> None:
    apply = _prepare(language, build, path)
    first = apply()
    # each call parses the same redacted text into a new object: key the caches on it
    parse_cache: dict[str, object] = {}
    real_parse, real_table, real_attach = parse, build_symbol_table, attach_imports

    def parse_cached(path: str, lang: Language, text: str) -> object:
        if text not in parse_cache:
            parse_cache[text] = real_parse(path, lang, text)
        return parse_cache[text]

    tables: dict[int, object] = {}

    def table_cached(parsed: object, spec: object) -> object:
        if id(parsed) not in tables:
            tables[id(parsed)] = real_table(parsed, spec)  # type: ignore[arg-type]
        return tables[id(parsed)]

    attached: dict[int, object] = {}

    def attach_cached(table: object, parsed: object, *args: object, **kwargs: object) -> object:
        if id(parsed) not in attached:
            attached[id(parsed)] = real_attach(table, parsed, *args, **kwargs)  # type: ignore[arg-type]
        return attached[id(parsed)]

    monkeypatch.setattr(engine_module, "parse", parse_cached)
    monkeypatch.setattr(engine_module, "build_symbol_table", table_cached)
    monkeypatch.setattr(engine_module, "attach_imports", attach_cached)
    assert apply() == first  # fills the caches; the result does not depend on them
    assert_within_budget(measure(apply, repeat=5), OWN_BUDGET_SECONDS, label=f"own {path}")
