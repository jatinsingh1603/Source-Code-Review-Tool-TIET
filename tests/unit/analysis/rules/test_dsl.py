"""The rule models: field validators, the worked example and round trips (E16-01)."""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.analysis.rules.dsl import (
    Constraint,
    MatchBlock,
    PatternClause,
    RuleDef,
    RuleMeta,
    TaintSpec,
)
from codekavach.analysis.rules.loader import load_rule_file
from codekavach.analysis.rules.pack import pack_checksum
from codekavach.analysis.rules.schema import EXAMPLE
from codekavach.core.models.canonical import canonical_json
from tests.support.golden import assert_matches_golden
from tests.support.rule_files import rule_data

GOLDEN = Path(__file__).parent / "golden"


def load_example(tmp_path: Path) -> RuleDef:
    path = tmp_path / "example.yaml"
    path.write_text(EXAMPLE, encoding="utf-8")
    return load_rule_file(path)


def test_the_worked_example_loads_and_matches_its_golden(tmp_path: Path) -> None:
    rule = load_example(tmp_path)
    assert rule.metadata.cwe == (89,)
    text = json.dumps(rule.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    assert_matches_golden(text, GOLDEN / "rule_example.json")


def test_the_worked_example_round_trips_through_json_unchanged(tmp_path: Path) -> None:
    rule = load_example(tmp_path)
    again = RuleDef.model_validate_json(rule.model_dump_json())
    assert again == rule
    assert canonical_json(again) == canonical_json(rule)


@pytest.mark.parametrize("name", ["$q", "Q", "$1", "$", "$....Q", "$Q-1"])
def test_a_malformed_metavariable_name_is_refused(name: str) -> None:
    with pytest.raises(ValidationError):
        Constraint(metavariable=name, kind="call")


@pytest.mark.parametrize("name", ["$Q", "$...ARGS", "$A_1"])
def test_a_wellformed_metavariable_name_is_accepted(name: str) -> None:
    assert Constraint(metavariable=name, kind="call").metavariable == name


def test_a_constraint_reports_the_conditions_that_are_set() -> None:
    constraint = Constraint(metavariable="$Q", regex="a", min_length=2)
    assert constraint.conditions == ("regex", "min_length")


def test_a_clause_reports_its_pattern_kinds() -> None:
    assert PatternClause(pattern="f($X)").kinds == ("pattern",)
    assert PatternClause(pattern="f($X)", ref="a.b").kinds == ("pattern", "ref")
    assert PatternClause().kinds == ()


def test_a_regular_expression_over_512_characters_is_refused_by_the_model() -> None:
    with pytest.raises(ValidationError):
        PatternClause(pattern_regex="a" * 513)


@pytest.mark.parametrize("value", ["A03", "a03:2021", "A11:2021", "A03:1999"])
def test_a_malformed_owasp_entry_is_refused(value: str) -> None:
    with pytest.raises(ValidationError):
        RuleMeta(owasp=(value,))


def test_remediation_is_capped_at_2000_characters() -> None:
    assert len(RuleMeta(remediation="x" * 2000).remediation) == 2000
    with pytest.raises(ValidationError):
        RuleMeta(remediation="x" * 2001)


@pytest.mark.parametrize("value", [0, 10_000_000, "abc"])
def test_an_impossible_cwe_number_is_refused(value: Any) -> None:
    with pytest.raises(ValidationError):
        RuleMeta(cwe=(value,))


def test_cwe_accepts_the_string_form() -> None:
    assert RuleMeta(cwe=("CWE-89",)).cwe == (89,)  # type: ignore[arg-type]


def test_an_unknown_field_is_refused() -> None:
    with pytest.raises(ValidationError):
        RuleDef.model_validate(rule_data(surprise=1))


def test_severity_and_confidence_use_the_shared_enums() -> None:
    with pytest.raises(ValidationError):
        RuleDef.model_validate(rule_data(severity="urgent"))
    with pytest.raises(ValidationError):
        RuleDef.model_validate(rule_data(confidence="certain"))


def test_models_are_frozen() -> None:
    rule = RuleDef.model_validate(rule_data())
    with pytest.raises(ValidationError):
        rule.id = "other.rule"  # type: ignore[misc]


def test_a_validation_message_does_not_echo_the_input() -> None:
    with pytest.raises(ValidationError) as caught:
        RuleDef.model_validate(rule_data(severity="SECRET-VALUE"))
    assert "SECRET-VALUE" not in str(caught.value)


def test_patterns_and_regexes_are_collected_from_every_clause() -> None:
    rule = RuleDef.model_validate(
        rule_data(
            match={
                "any": [{"pattern": "f($X)", "where": [{"metavariable": "$X", "regex": "a+"}]}],
                "all": [{"pattern_inside": "class $C: ..."}],
                "none": [{"pattern_regex": "b+"}],
            },
            taint=TaintSpec(sources=("python.s.one",)).model_dump(),
        )
    )
    assert rule.patterns == ("f($X)", "class $C: ...")
    assert set(rule.regexes) == {"a+", "b+"}
    assert isinstance(rule.match, MatchBlock)


def test_compiled_regexes_are_cached_on_the_instance_not_the_module() -> None:
    first = RuleDef.model_validate(rule_data(match={"any": [{"pattern_regex": "ab+"}]}))
    second = RuleDef.model_validate(rule_data(match={"any": [{"pattern_regex": "ab+"}]}))
    assert first.compiled_regexes is first.compiled_regexes
    assert first.compiled_regexes is not second.compiled_regexes


def test_the_checksum_ignores_rule_order() -> None:
    a = RuleDef.model_validate(rule_data(id="python.a.one"))
    b = RuleDef.model_validate(rule_data(id="python.a.two"))
    assert pack_checksum([a, b]) == pack_checksum([b, a])
    assert pack_checksum([a]) != pack_checksum([b])


identifiers = st.from_regex(r"[a-z][a-z0-9]{0,7}(\.[a-z][a-z0-9-]{0,7}){1,2}", fullmatch=True)


@settings(max_examples=60, deadline=None)
@given(
    rule_id=identifiers,
    cwe=st.lists(
        st.sampled_from([22, 78, 79, 89, 94, 327, 798]), min_size=1, max_size=3, unique=True
    ),
    severity=st.sampled_from(["info", "low", "medium", "high", "critical"]),
    pattern=st.text(alphabet="abc$XYZ()., ", min_size=1, max_size=30),
)
def test_any_valid_rule_round_trips_through_yaml_and_json(
    rule_id: str, cwe: list[int], severity: str, pattern: str
) -> None:
    data = rule_data(
        id=rule_id,
        severity=severity,
        metadata={"cwe": cwe, "licence": "MIT"},
        match={"any": [{"pattern": pattern}]},
    )
    rule = RuleDef.model_validate(data)
    through_yaml = RuleDef.model_validate(yaml.safe_load(yaml.safe_dump(data)))
    through_json = RuleDef.model_validate_json(rule.model_dump_json())
    assert rule == through_yaml == through_json
    assert pack_checksum([rule]) == pack_checksum([through_yaml]) == pack_checksum([through_json])
