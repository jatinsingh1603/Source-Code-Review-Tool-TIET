"""One test per classification rule and per hard case, in both languages (E09-02).

Each assertion here fails if the rule it names is broken: a rule that quietly turned an internal
name public, or a conservative default that quietly turned public, changes one of these decisions.
"""

import pytest

from codekavach.core.models import Language
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.imports import DefaultImportResolver, attach_imports
from codekavach.parsing.symbols import build_symbol_table
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.classify import (
    ClassificationDecision,
    ClassificationNote,
    ClassificationResult,
    IdentifierClass,
    IdentifierClassifier,
    Rule,
)
from tests.support.classification import FIXTURES, classify_text, decisions_by_name

PUBLIC = IdentifierClass.PUBLIC
INTERNAL = IdentifierClass.INTERNAL


def decision(
    result: ClassificationResult, name: str, kind: str | None = None, line: int | None = None
) -> ClassificationDecision:
    """The single decision for ``name`` (of ``kind``, on ``line``); fails unless one matches."""
    matches = [
        d
        for d in result.decisions
        if d.name == name
        and (kind is None or d.kind == kind)
        and (line is None or d.location.start_line == line)
    ]
    assert len(matches) == 1, f"expected one decision for {name!r}, found {len(matches)}"
    return matches[0]


def decisions_of(result: ClassificationResult, name: str) -> list[ClassificationDecision]:
    """Every occurrence of ``name``, in source order."""
    return [d for d in result.decisions if d.name == name]


# --- the base rules, parametrised per language -------------------------------------------------

PYTHON_RULES = [
    ("def convert(value):\n    return str(value)\n", "str", PUBLIC, Rule.KEYWORD_OR_BUILTIN),
    ("import os\n\nos.getcwd()\n", "os", PUBLIC, Rule.STDLIB_IMPORT),
    ("from flask import request\n\nrequest\n", "request", PUBLIC, Rule.ALLOWLISTED_IMPORT),
    ("from billing import ledger\n\nledger\n", "ledger", INTERNAL, Rule.UNLISTED_IMPORT),
    ("from . import rules\n\nrules\n", "rules", INTERNAL, Rule.INTERNAL_IMPORT),
    ("def __init__(self):\n    pass\n", "__init__", PUBLIC, Rule.MAGIC),
    ("class Repo:\n    def post(self):\n        pass\n", "post", PUBLIC, Rule.FRAMEWORK_CONTRACT),
    ("def order_total(order):\n    return order\n", "order_total", INTERNAL, Rule.DEFAULT_INTERNAL),
    ("def run(x):\n    return subprocess_helper(x)\n", "run", PUBLIC, Rule.WELL_KNOWN),
    (
        "import sqlite3\n\nc = sqlite3.connect('x')\n",
        "connect",
        PUBLIC,
        Rule.MEMBER_OF_PUBLIC,
    ),
]

JAVASCRIPT_RULES = [
    ("function f(v) { return JSON.stringify(v); }\n", "JSON", PUBLIC, Rule.KEYWORD_OR_BUILTIN),
    ("const fs = require('fs');\nfs;\n", "fs", PUBLIC, Rule.STDLIB_IMPORT),
    ("import express from 'express';\nexpress;\n", "express", PUBLIC, Rule.ALLOWLISTED_IMPORT),
    ("const b = require('billing-engine');\nb;\n", "b", INTERNAL, Rule.UNLISTED_IMPORT),
    ("import { r } from './rules.js';\nr();\n", "r", INTERNAL, Rule.INTERNAL_IMPORT),
    ("class A {\n  toString() { return 'a'; }\n}\n", "toString", PUBLIC, Rule.FRAMEWORK_CONTRACT),
    (
        "function orderTotal(order) { return order; }\n",
        "orderTotal",
        INTERNAL,
        Rule.DEFAULT_INTERNAL,
    ),
    ("const x = escapeHtml(1);\n", "escapeHtml", PUBLIC, Rule.WELL_KNOWN),
    (
        "const { exec } = require('child_process');\nexec('x');\n",
        "exec",
        PUBLIC,
        Rule.STDLIB_IMPORT,
    ),
    (
        "const fs = require('fs');\nconst x = fs.readFileSync('a');\n",
        "readFileSync",
        PUBLIC,
        Rule.MEMBER_OF_PUBLIC,
    ),
]


@pytest.mark.parametrize(
    ("text", "name", "expected", "rule"), PYTHON_RULES, ids=lambda v: str(v)[:24]
)
def test_each_python_rule_decides_its_case(
    text: str, name: str, expected: IdentifierClass, rule: Rule
) -> None:
    result = classify_text(Language.PYTHON, text)
    matches = [d for d in result.decisions if d.name == name]
    assert matches, name
    assert any(d.classification is expected and d.rule is rule for d in matches), [
        (d.classification, d.rule) for d in matches
    ]


@pytest.mark.parametrize(
    ("text", "name", "expected", "rule"), JAVASCRIPT_RULES, ids=lambda v: str(v)[:24]
)
def test_each_javascript_rule_decides_its_case(
    text: str, name: str, expected: IdentifierClass, rule: Rule
) -> None:
    result = classify_text(Language.JAVASCRIPT, text)
    matches = [d for d in result.decisions if d.name == name]
    assert matches, name
    assert any(d.classification is expected and d.rule is rule for d in matches), [
        (d.classification, d.rule) for d in matches
    ]


# --- the hard cases, each as its own named test -------------------------------------------------


def test_stdlib_import_is_public_and_internal_import_is_internal_and_unlisted_is_internal() -> None:
    text = "import os\nfrom . import rules\nfrom billing import ledger\nos\nrules\nledger\n"
    result = classify_text(Language.PYTHON, text)
    assert {d.classification for d in decisions_of(result, "os")} == {PUBLIC}
    assert {d.classification for d in decisions_of(result, "rules")} == {INTERNAL}
    assert {d.classification for d in decisions_of(result, "ledger")} == {INTERNAL}


def test_attribute_chain_with_resolved_public_base_is_public_per_link() -> None:
    text = "from flask import request\n\n\ndef f():\n    return request.args.get('x')\n"
    result = classify_text(Language.PYTHON, text)
    args = [d for d in result.decisions if d.name == "args"]
    get = [d for d in result.decisions if d.name == "get"]
    assert args[0].classification is PUBLIC
    assert args[0].rule is Rule.MEMBER_OF_PUBLIC
    assert get[0].classification is PUBLIC
    assert get[0].rule is Rule.MEMBER_OF_PUBLIC


def test_attribute_chain_with_unresolved_base_is_internal_and_counted() -> None:
    text = "def total(order):\n    return ledger.festival_bonus_rate(order)\n"
    result = classify_text(Language.PYTHON, text)
    attribute = decision(result, "festival_bonus_rate")
    assert attribute.classification is INTERNAL
    assert attribute.rule is Rule.DEFAULT_INTERNAL
    assert result.counts.unresolved_base == 1
    assert result.counts.unresolved_name == 1


def test_keyword_argument_is_public_on_a_public_callee() -> None:
    text = "import sqlite3\n\n\ndef find(cur, values):\n    cur.execute('q', params=values)\n"
    result = classify_text(Language.PYTHON, text)
    params = decision(result, "params", "parameter")
    assert params.classification is PUBLIC
    assert params.rule is Rule.KEYWORD_OF_PUBLIC
    # The value passed as ``params`` is an ordinary internal name.
    assert {d.classification for d in decisions_of(result, "values")} == {INTERNAL}


def test_keyword_argument_is_internal_on_an_internal_callee() -> None:
    text = (
        "from billing.engine import accrue\n\n\ndef f(a, rate):\n    return accrue(a, rate=rate)\n"
    )
    result = classify_text(Language.PYTHON, text)
    # Line 5 holds the keyword ``rate=`` and its value ``rate``; only the keyword has this rule.
    keywords = [d for d in result.decisions if d.rule is Rule.KEYWORD_OF_INTERNAL]
    assert [d.name for d in keywords] == ["rate"]
    assert keywords[0].classification is INTERNAL


def test_keyword_argument_is_public_when_listed_on_the_callee_package() -> None:
    text = "from flask import request\n\n\ndef f():\n    return request.args.get('r', type=float)\n"
    result = classify_text(Language.PYTHON, text)
    assert decision(result, "type", "parameter").classification is PUBLIC


def test_overridden_framework_method_is_public_though_defined_in_the_client_class() -> None:
    text = (
        "from django.views import View\n\n\n"
        "class Report(View):\n    def get(self, request):\n        return request\n"
    )
    result = classify_text(Language.PYTHON, text)
    method = decision(result, "get", "method")
    assert method.classification is PUBLIC
    assert method.rule is Rule.FRAMEWORK_CONTRACT


def test_dunder_name_is_public() -> None:
    result = classify_text(
        Language.PYTHON, "class L:\n    def __repr__(self):\n        return ''\n"
    )
    dunder = decision(result, "__repr__")
    assert dunder.classification is PUBLIC
    assert dunder.rule is Rule.MAGIC


def test_serialisation_fields_are_internal_and_flagged_for_renaming() -> None:
    text = (
        "from dataclasses import dataclass\n\n\n"
        "@dataclass\nclass Account:\n    festival_bonus_rate: float = 0.0\n"
    )
    result = classify_text(Language.PYTHON, text)
    field = decision(result, "festival_bonus_rate")
    assert field.classification is INTERNAL
    assert ClassificationNote.SERIALISATION_FIELD in field.notes


def test_plain_class_field_is_not_flagged_as_a_serialisation_field() -> None:
    result = classify_text(Language.PYTHON, "class Account:\n    festival_bonus_rate = 0.0\n")
    field = decision(result, "festival_bonus_rate")
    assert field.classification is INTERNAL
    assert ClassificationNote.SERIALISATION_FIELD not in field.notes


def test_getattr_with_literal_name_is_marked_when_the_rewrite_is_provable() -> None:
    text = (
        "def festival_rate():\n    return 1.1\n\n\n"
        "def read(account):\n    return getattr(account, 'festival_rate')()\n"
    )
    result = classify_text(Language.PYTHON, text)
    definition = decision(result, "festival_rate")
    assert definition.classification is INTERNAL
    assert ClassificationNote.DYNAMIC_NAME in definition.notes
    assert result.counts.dynamic_name_marked == 1
    assert result.kept_dynamic == frozenset()


def test_getattr_with_literal_name_is_kept_and_counted_when_not_provable() -> None:
    text = "def read(account):\n    return getattr(account, 'festival_bonus_rate', 0.0)\n"
    result = classify_text(Language.PYTHON, text)
    assert result.kept_dynamic == frozenset({"festival_bonus_rate"})
    assert result.counts.kept_identifier == 1
    assert "festival_bonus_rate" in result.kept_public_names()


def test_getattr_with_a_variable_name_leaves_nothing_to_rewrite() -> None:
    text = "def read(account, field_name):\n    return getattr(account, field_name)\n"
    result = classify_text(Language.PYTHON, text)
    assert result.kept_dynamic == frozenset()
    assert result.counts.kept_identifier == 0
    assert result.counts.dynamic_name_marked == 0
    assert {d.classification for d in decisions_of(result, "field_name")} == {INTERNAL}


def test_subscript_with_a_literal_key_is_marked_when_the_key_is_a_name_of_the_file() -> None:
    text = "festival_rate = 1.2\n\n\ndef apply(account):\n    return account['festival_rate']\n"
    result = classify_text(Language.PYTHON, text)
    assert result.counts.dynamic_name_marked == 1
    assert ClassificationNote.DYNAMIC_NAME in decision(result, "festival_rate").notes


def test_subscript_with_a_literal_key_outside_the_file_is_left_to_the_literal_rules() -> None:
    result = classify_text(Language.PYTHON, "def s(config):\n    return config['database_url']\n")
    assert result.kept_dynamic == frozenset()
    assert result.counts.kept_identifier == 0
    assert "database_url" not in result.kept_public_names()


def test_eval_marks_the_file_as_dynamic_code() -> None:
    result = classify_text(Language.PYTHON, "def c(expr):\n    return eval(expr)\n")
    evaluate = decision(result, "eval")
    assert ClassificationNote.DYNAMIC_CODE in evaluate.notes
    assert result.counts.dynamic_code == 1


def test_unbound_name_is_internal_and_counted() -> None:
    result = classify_text(Language.PYTHON, "def n(c):\n    return dispatch_festival_notice(c)\n")
    unbound = decision(result, "dispatch_festival_notice")
    assert unbound.classification is INTERNAL
    assert result.counts.unresolved_name == 1


def test_incomplete_table_forces_table_dependent_public_decisions_to_internal() -> None:
    text = "from flask import request\n\n\ndef handle(:\n    return request.args.get('x')\n"
    result = classify_text(Language.PYTHON, text)
    request = [d for d in result.decisions if d.name == "request"]
    assert request and all(d.classification is INTERNAL for d in request)
    assert all(d.rule is Rule.INCOMPLETE_TABLE for d in request)
    assert result.counts.incomplete_table >= 1
    # The framework contract is a name-only decision and survives the broken parse.
    assert decision(result, "handle").classification is PUBLIC


def test_a_missing_import_origin_is_internal_not_public() -> None:
    """An import binding with no ImportRef is a binding the table cannot explain: INTERNAL."""
    parsed = parse("case.py", Language.PYTHON, "import os\nos\n")
    table = build_symbol_table(parsed, REGISTRY.get(Language.PYTHON))
    classifier = IdentifierClassifier(
        table, DefaultImportResolver(Language.PYTHON), PublicAllowlist.bundled(Language.PYTHON)
    )
    classifier.attach(parsed)
    # The table was not attached with imports, so ``os`` has no origin and must not be public.
    assert all(
        d.classification is INTERNAL for d in classifier.classify_file().decisions if d.name == "os"
    )


# --- the named regression: the worked example of the issue -------------------------------------

WORKED_EXAMPLE = (
    "from flask import request\n"
    "from billing.engine import accrue_interest\n"
    "\n"
    '@app.route("/accounts/<aid>")\n'
    "def get_account(aid):\n"
    '    rate = request.args.get("rate", type=float)\n'
    "    return accrue_interest(aid, rate=rate)\n"
)

# (line, name, kind) -> expected decision, for every occurrence of the worked example.
WORKED_EXAMPLE_MAP: dict[tuple[int, str, str], IdentifierClass] = {
    (1, "flask", "module"): PUBLIC,
    (1, "request", "import"): PUBLIC,
    (2, "billing", "module"): INTERNAL,
    (2, "engine", "module"): INTERNAL,
    (2, "accrue_interest", "import"): INTERNAL,
    (4, "app", "variable"): PUBLIC,
    (4, "route", "field"): PUBLIC,
    (5, "get_account", "function"): INTERNAL,
    (5, "aid", "parameter"): INTERNAL,
    (6, "rate", "variable"): INTERNAL,
    (6, "request", "import"): PUBLIC,
    (6, "args", "field"): PUBLIC,
    (6, "get", "field"): PUBLIC,
    (6, "type", "parameter"): PUBLIC,
    (6, "float", "variable"): PUBLIC,
    (7, "accrue_interest", "import"): INTERNAL,
    (7, "aid", "parameter"): INTERNAL,
    (7, "rate", "parameter"): INTERNAL,
    (7, "rate", "variable"): INTERNAL,
}


def test_worked_example_produces_exactly_the_documented_decision_map() -> None:
    result = classify_text(Language.PYTHON, WORKED_EXAMPLE)
    actual = {(d.location.start_line, d.name, d.kind): d.classification for d in result.decisions}
    assert actual == WORKED_EXAMPLE_MAP
    assert result.kept_public_names() == (
        "app",
        "args",
        "flask",
        "float",
        "get",
        "request",
        "route",
        "type",
    )
    # The one unresolved base is ``app`` in ``@app.route``. ``route`` is public by its decorator
    # rule, but its base has no binding, so the conservative counter records it.
    assert result.counts.unresolved_base == 1
    assert result.counts.kept_identifier == 0


def test_every_occurrence_of_a_name_in_a_chain_has_a_decision() -> None:
    by_name = decisions_by_name(classify_text(Language.PYTHON, WORKED_EXAMPLE))
    assert set(by_name) >= {"flask", "request", "args", "get", "type", "float", "app", "route"}


# --- rules pinned after a mutation check: each fails if the privacy default is flipped ----------


def test_a_keyword_that_the_public_callee_does_not_list_is_internal() -> None:
    text = "from flask import request\n\n\ndef f():\n    return request.args.get('r', rate=1)\n"
    result = classify_text(Language.PYTHON, text)
    rate = decision(result, "rate", "parameter")
    assert rate.classification is INTERNAL
    assert rate.rule is Rule.KEYWORD_NOT_LISTED


def test_a_keyword_whose_callee_cannot_be_found_is_internal() -> None:
    text = "def f(handlers):\n    return handlers[0](rate=1)\n"
    result = classify_text(Language.PYTHON, text)
    rate = decision(result, "rate", "parameter")
    assert rate.classification is INTERNAL
    assert rate.rule is Rule.KEYWORD_OF_INTERNAL


def test_an_import_flagged_conservative_is_never_public_whatever_its_origin() -> None:
    parsed = parse("case.py", Language.PYTHON, "import os\n\nos.getcwd()\n")
    table = build_symbol_table(parsed, REGISTRY.get(Language.PYTHON))
    table = attach_imports(
        table, parsed, DefaultImportResolver(Language.PYTHON), project_root=FIXTURES
    )
    assert any(ref.origin == "stdlib" for ref in table.imports)
    doubtful = table.model_copy(
        update={
            "imports": tuple(ref.model_copy(update={"conservative": True}) for ref in table.imports)
        }
    )
    classifier = IdentifierClassifier(
        doubtful, DefaultImportResolver(Language.PYTHON), PublicAllowlist.bundled(Language.PYTHON)
    )
    classifier.attach(parsed)
    result = classifier.classify_file()
    os_decisions = [d for d in result.decisions if d.name == "os"]
    assert os_decisions and all(d.classification is INTERNAL for d in os_decisions)


def test_an_extra_name_is_public_even_when_an_import_would_make_it_internal() -> None:
    text = "from billing import ledger\n\nledger\n"
    plain = classify_text(Language.PYTHON, text)
    assert {d.classification for d in decisions_of(plain, "ledger")} == {INTERNAL}
    widened = classify_text(
        Language.PYTHON, text, allowlist=PublicAllowlist.bundled(Language.PYTHON, extra=["ledger"])
    )
    assert {d.classification for d in decisions_of(widened, "ledger")} == {PUBLIC}
    assert {d.rule for d in decisions_of(widened, "ledger")} == {Rule.EXTRA}
    # The extra name is the only thing that changed: other internal names stay internal.
    assert {d.classification for d in decisions_of(widened, "billing")} == {INTERNAL}


def test_a_symbol_that_is_not_in_the_table_is_internal() -> None:
    parsed = parse("case.py", Language.PYTHON, "x = 1\n")
    table = build_symbol_table(parsed, REGISTRY.get(Language.PYTHON))
    classifier = IdentifierClassifier(
        table, DefaultImportResolver(Language.PYTHON), PublicAllowlist.bundled(Language.PYTHON)
    )
    stranger = table.symbols[0].model_copy(
        update={
            "name": "request",  # a name that is public wherever the table knows it
            "location": table.symbols[0].location.model_copy(
                update={"start_line": 99, "end_line": 99}
            ),
        }
    )
    assert classifier.classify(stranger) is INTERNAL
