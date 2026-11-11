"""``CK-RULE-011`` (a pattern that does not parse) and ``CK-RULE-015`` (a ``ref`` cycle)."""

from codekavach.analysis.rules.dsl import RuleDef
from codekavach.analysis.rules.validate import RuleCode, validate_rule, validate_rules
from tests.support.rule_files import rule_data


def rule(rule_id: str, match: dict[str, object]) -> RuleDef:
    return RuleDef.model_validate(rule_data(id=rule_id, match=match))


def test_an_unparseable_pattern_is_ck_rule_011_only_when_asked() -> None:
    bad = rule("python.misc.bad", {"any": [{"pattern": "def ("}]})
    assert validate_rule(bad) == []
    (issue,) = validate_rule(bad, check_patterns=True)
    assert issue.code is RuleCode.PATTERN_PARSE and issue.code.value == "CK-RULE-011"


def test_a_parseable_pattern_has_no_issue() -> None:
    good = rule("python.misc.good", {"any": [{"pattern": "f($X, ...)"}]})
    assert validate_rule(good, check_patterns=True) == []


def test_a_ref_cycle_is_ck_rule_015_for_each_rule_in_it() -> None:
    a = rule("python.misc.a", {"any": [{"ref": "python.misc.b"}]})
    b = rule("python.misc.b", {"any": [{"ref": "python.misc.a"}]})
    c = rule("python.misc.c", {"any": [{"ref": "python.misc.a"}]})
    cyclic = {i.rule_id for i in validate_rules([a, b, c]) if i.code is RuleCode.REF_CYCLE}
    assert cyclic == {"python.misc.a", "python.misc.b"}


def test_a_rule_that_refers_to_itself_is_a_cycle() -> None:
    a = rule("python.misc.a", {"any": [{"ref": "python.misc.a"}]})
    assert [i.code for i in validate_rules([a]) if i.code is RuleCode.REF_CYCLE]


def test_a_chain_without_a_cycle_is_fine() -> None:
    a = rule("python.misc.a", {"any": [{"ref": "python.misc.b"}]})
    b = rule("python.misc.b", {"any": [{"pattern": "f()"}]})
    assert not [i for i in validate_rules([a, b]) if i.code is RuleCode.REF_CYCLE]
