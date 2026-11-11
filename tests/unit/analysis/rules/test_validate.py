"""The CK-RULE-nnn validation codes and the regular-expression safety check (E16-01)."""

from pathlib import Path
from typing import Any

import pytest

from codekavach.analysis.rules.dsl import RuleDef
from codekavach.analysis.rules.loader import load_rule_file
from codekavach.analysis.rules.validate import (
    RuleCode,
    unsafe_regex_reason,
    validate_rule,
    validate_rules,
)
from tests.support.rule_files import rule_data, rule_text

CATALOGUE = {"python.flask.request-args", "python.db.execute"}


def issues_for(tmp_path: Path, text: str, **options: Any) -> set[RuleCode]:
    path = tmp_path / "rule.yaml"
    path.write_text(text, encoding="utf-8")
    return {item.code for item in validate_rule(load_rule_file(path), **options)}


def test_the_shipped_example_has_no_issue(tmp_path: Path) -> None:
    assert issues_for(tmp_path, rule_text(), catalogue_ids=CATALOGUE, licence_dir="mit") == set()


INVALID: dict[RuleCode, tuple[str, dict[str, Any]]] = {
    RuleCode.UNKNOWN_LANGUAGE: (rule_text(languages=["cobol"]), {}),
    RuleCode.BAD_ID: (rule_text(id="NotAnId"), {}),
    RuleCode.EMPTY_MATCH: (rule_text(match={}), {}),
    RuleCode.CLAUSE_KINDS: (
        rule_text(match={"any": [{"pattern": "f($X)", "pattern_regex": "a"}]}),
        {},
    ),
    RuleCode.UNBOUND_METAVARIABLE: (
        rule_text(
            match={"any": [{"pattern": "f($X)", "where": [{"metavariable": "$Y", "kind": "call"}]}]}
        ),
        {},
    ),
    RuleCode.UNKNOWN_CATALOGUE: (
        rule_text(
            match={
                "any": [
                    {
                        "pattern": "f($X)",
                        "where": [{"metavariable": "$X", "catalogue": "python.no.such"}],
                    }
                ]
            }
        ),
        {"catalogue_ids": CATALOGUE},
    ),
    RuleCode.UNSAFE_REGEX: (rule_text(match={"any": [{"pattern_regex": "(a+)+$"}]}), {}),
    RuleCode.MISSING_CWE: (rule_text(metadata={"licence": "MIT"}), {}),
    RuleCode.BAD_CWE: (rule_text(metadata={"cwe": [710], "licence": "MIT"}), {}),
    RuleCode.LICENCE_MISMATCH: (rule_text(), {"licence_dir": "lgpl-2.1"}),
}


@pytest.mark.parametrize("code", sorted(INVALID))
def test_each_code_is_produced_by_its_own_invalid_rule(code: RuleCode, tmp_path: Path) -> None:
    text, options = INVALID[code]
    assert code in issues_for(tmp_path, text, **options)


def test_a_duplicate_id_in_one_pack_is_reported() -> None:
    rule = RuleDef.model_validate(rule_data())
    found = validate_rules([rule, rule])
    assert RuleCode.DUPLICATE_ID in {item.code for item in found}


def test_a_ref_to_a_rule_outside_the_pack_is_reported() -> None:
    rule = RuleDef.model_validate(rule_data(match={"any": [{"ref": "python.other.rule"}]}))
    assert RuleCode.UNKNOWN_REF in {item.code for item in validate_rules([rule])}


def test_the_pattern_parse_code_is_declared_for_the_matcher() -> None:
    assert RuleCode.PATTERN_PARSE.value == "CK-RULE-011"
    assert len({member.value for member in RuleCode}) == len(list(RuleCode))


def test_a_constraint_with_two_conditions_or_an_unknown_kind_is_reported(tmp_path: Path) -> None:
    two = rule_text(
        match={
            "any": [
                {
                    "pattern": "f($X)",
                    "where": [{"metavariable": "$X", "kind": "call", "min_length": 1}],
                }
            ]
        }
    )
    odd = rule_text(
        match={"any": [{"pattern": "f($X)", "where": [{"metavariable": "$X", "kind": "banana"}]}]}
    )
    assert RuleCode.BAD_CONSTRAINT in issues_for(tmp_path, two)
    assert RuleCode.BAD_CONSTRAINT in issues_for(tmp_path, odd)


def test_cwe_20_alone_is_too_broad(tmp_path: Path) -> None:
    text = rule_text(metadata={"cwe": [20], "licence": "MIT"})
    assert RuleCode.BAD_CWE in issues_for(tmp_path, text)


def test_a_variadic_metavariable_bound_by_a_pattern_is_accepted(tmp_path: Path) -> None:
    text = rule_text(
        match={
            "any": [
                {"pattern": "f($...ARGS)", "where": [{"metavariable": "$...ARGS", "min_length": 1}]}
            ]
        }
    )
    assert RuleCode.UNBOUND_METAVARIABLE not in issues_for(tmp_path, text)


def test_no_issue_text_contains_pattern_source(tmp_path: Path) -> None:
    text = rule_text(match={"any": [{"pattern": "SECRET_PATTERN($X)", "pattern_regex": "(a+)+"}]})
    path = tmp_path / "r.yaml"
    path.write_text(text, encoding="utf-8")
    for item in validate_rule(load_rule_file(path)):
        assert "SECRET_PATTERN" not in item.message


@pytest.mark.parametrize("text", ["(a+)+", "(.*)*", "(a*)+$", "x(\\w+\\s*)*y", "(a{2,})+"])
def test_nested_unbounded_quantifiers_are_rejected(text: str) -> None:
    assert unsafe_regex_reason(text) == "nested unbounded quantifiers"


@pytest.mark.parametrize(
    "text", ["(ab)+", "a+b+", "(?:foo|bar)+", "[(a+)]+", "\\(a+\\)+", "(a{2}){3}"]
)
def test_similar_but_safe_expressions_are_accepted(text: str) -> None:
    assert unsafe_regex_reason(text) is None


def test_an_overlong_or_broken_expression_is_rejected() -> None:
    assert "longer" in (unsafe_regex_reason("a" * 513) or "")
    assert unsafe_regex_reason("(") == "does not compile"
