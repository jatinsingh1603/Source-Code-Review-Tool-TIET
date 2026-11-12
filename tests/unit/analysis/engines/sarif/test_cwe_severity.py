"""CWE extraction, severity and confidence normalisation, and the data tables (E14-02)."""

from pathlib import Path
from typing import Any

import pytest

from codekavach.analysis.engines.sarif.cwe import extract_cwe, extract_cwe_details
from codekavach.analysis.engines.sarif.model import ReportingDescriptor, Result, Run
from codekavach.analysis.engines.sarif.severity import normalise_confidence, normalise_severity
from codekavach.analysis.engines.sarif.tables import (
    CweFallback,
    TableError,
    default_cwe_fallback,
    default_severity_table,
    parse_cwe_fallback,
    parse_severity_map,
)
from codekavach.core.models.enums import Confidence, Severity


def rule(**fields: Any) -> ReportingDescriptor:
    return ReportingDescriptor.model_validate({"id": "r1", **fields})


def res(**fields: Any) -> Result:
    return Result.model_validate({"ruleId": "r1", **fields})


# --- the four CWE strategies -------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [89, "89", "CWE-89", "cwe-089", "CWE-89: Improper Neutralization of Special Elements", [89]],
)
def test_strategy_one_rule_properties(value: object) -> None:
    found = extract_cwe_details(rule(properties={"cwe": value}), res(), "eng")
    assert (found.cwe, found.source) == ((89,), "properties")


def test_strategy_one_result_properties_and_lists() -> None:
    found = extract_cwe_details(None, res(properties={"cwe": ["CWE-79", 89, "cwe-79"]}), "eng")
    assert (found.cwe, found.source) == ((79, 89), "properties")


@pytest.mark.parametrize(
    "tag",
    ["external/cwe/cwe-089", "CWE-89", "cwe/89", "cwe:89", "external/cwe-89", "CWE-89: Injection"],
)
def test_strategy_two_tags(tag: str) -> None:
    found = extract_cwe_details(rule(properties={"tags": ["security", tag]}), res(), "eng")
    assert (found.cwe, found.source) == ((89,), "tags")


def test_strategy_three_taxonomy_by_name_and_by_index() -> None:
    run = Run.model_validate({"taxonomies": [{"name": "CWE"}]})
    by_name = rule(relationships=[{"target": {"id": "089", "toolComponent": {"name": "CWE"}}}])
    by_index = rule(relationships=[{"target": {"id": "CWE-79", "toolComponent": {"index": 0}}}])
    assert extract_cwe_details(by_name, res(), "eng", run=run).source == "taxonomy"
    assert extract_cwe(by_name, res(), "eng", run=run) == (89,)
    assert extract_cwe(by_index, res(), "eng", run=run) == (79,)
    on_result = res(taxa=[{"id": "22", "toolComponent": {"name": "CWE"}}])
    assert extract_cwe(None, on_result, "eng", run=run) == (22,)


def test_a_taxonomy_that_is_not_cwe_is_ignored() -> None:
    run = Run.model_validate({"taxonomies": [{"name": "OWASP"}]})
    other = rule(relationships=[{"target": {"id": "89", "toolComponent": {"index": 0}}}])
    assert extract_cwe(other, res(), "eng", run=run) == ()


def test_strategy_four_fallback_exact_then_longest_prefix() -> None:
    table = CweFallback({"eng": {"EX": (1,), "EX2.": (78, 77), "EX2.sub.": (94,), "ONE": (89,)}})
    assert extract_cwe_details(None, res(ruleId="ONE"), "eng", fallback=table).source == "fallback"
    assert extract_cwe(None, res(ruleId="ONE"), "eng", fallback=table) == (89,)
    assert extract_cwe(None, res(ruleId="EX2.a"), "eng", fallback=table) == (78, 77)
    assert extract_cwe(None, res(ruleId="EX2.sub.x"), "eng", fallback=table) == (94,)
    assert extract_cwe(None, res(ruleId="EX9"), "eng", fallback=table) == (1,)
    assert extract_cwe(None, res(ruleId="ZZ"), "eng", fallback=table) == ()
    assert extract_cwe(None, res(ruleId="ONE"), "other-engine", fallback=table) == ()


def test_the_first_strategy_with_a_hit_wins() -> None:
    both = rule(properties={"cwe": 89, "tags": ["CWE-79"]})
    table = CweFallback({"eng": {"r1": (22,)}})
    assert extract_cwe_details(both, res(), "eng", fallback=table).cwe == (89,)
    assert extract_cwe_details(
        rule(properties={"tags": ["CWE-79"]}), res(), "eng", fallback=table
    ).cwe == (79,)


def test_values_are_deduplicated_in_order_and_range_checked() -> None:
    found = extract_cwe(
        rule(properties={"cwe": [79, 89, 79, 99999, 0, 1426, True, "x"]}), res(), "e"
    )
    assert found == (79, 89)
    assert extract_cwe(rule(properties={"cwe": 1425}), res(), "e") == (1425,)


@pytest.mark.parametrize("pillar", [284, 664, 693, 703, 710])
def test_a_pillar_is_not_a_mapping(pillar: int) -> None:
    found = extract_cwe_details(rule(properties={"cwe": pillar}), res(), "eng")
    assert (found.cwe, found.source, found.unmapped) == ((), None, True)


def test_a_pillar_does_not_hide_a_later_real_mapping() -> None:
    table = CweFallback({"eng": {"r1": (89,)}})
    found = extract_cwe_details(rule(properties={"cwe": 284}), res(), "eng", fallback=table)
    assert (found.cwe, found.source, found.unmapped) == ((89,), "fallback", False)


def test_no_default_is_invented() -> None:
    found = extract_cwe_details(rule(), res(), "eng")
    assert (found.cwe, found.source, found.unmapped) == ((), None, False)


# --- severity ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        ("error", Severity.HIGH),
        ("warning", Severity.MEDIUM),
        ("note", Severity.LOW),
        ("none", Severity.INFO),
    ],
)
def test_the_level_decides_by_default(level: str, expected: Severity) -> None:
    assert normalise_severity(res(level=level), None, "eng") is expected


def test_an_absent_level_falls_back_to_the_rule_default_then_warning() -> None:
    with_default = rule(defaultConfiguration={"level": "error"})
    assert normalise_severity(res(), with_default, "eng") is Severity.HIGH
    assert normalise_severity(res(), None, "eng") is Severity.MEDIUM
    assert normalise_severity(res(level="bogus"), None, "eng") is Severity.MEDIUM


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        ("9.8", Severity.CRITICAL),
        (7.5, Severity.HIGH),
        ("5.0", Severity.MEDIUM),
        (0.0, Severity.INFO),
    ],
)
def test_security_severity_beats_the_level(score: object, expected: Severity) -> None:
    on_rule = rule(properties={"security-severity": score})
    assert normalise_severity(res(level="note"), on_rule, "eng") is expected
    on_result = res(level="note", properties={"security-severity": score})
    assert normalise_severity(on_result, None, "eng") is expected


@pytest.mark.parametrize("score", ["high", "11", "-1", True, None])
def test_a_bad_security_severity_is_ignored(score: object) -> None:
    on_rule = rule(properties={"security-severity": score})
    assert normalise_severity(res(level="error"), on_rule, "eng") is Severity.HIGH


@pytest.fixture
def table_path(tmp_path: Path) -> Path:
    path = tmp_path / "severity.toml"
    path.write_text(
        """
[engines.eng]
default_level_map = { error = "critical", warning = "high" }
confidence_keys = ["issue_confidence"]

[engines.eng.confidence_map]
UNDEFINED = "low"
HIGH = "high"

[engines.eng.rules]
"B1" = "low"
"B1.hard" = "info"
""",
        encoding="utf-8",
    )
    return path


def test_the_engine_table_replaces_the_level_map_and_overrides_rules(table_path: Path) -> None:
    table = parse_severity_map(table_path)
    assert normalise_severity(res(level="error"), None, "eng", table=table) is Severity.CRITICAL
    assert normalise_severity(res(level="note"), None, "eng", table=table) is Severity.LOW
    assert (
        normalise_severity(res(ruleId="B1x", level="error"), None, "eng", table=table)
        is Severity.LOW
    )
    assert (
        normalise_severity(res(ruleId="B1.hard.x", level="error"), None, "eng", table=table)
        is Severity.INFO
    )
    other = normalise_severity(res(level="error"), None, "other", table=table)
    assert other is Severity.HIGH


def test_a_rule_row_beats_security_severity(table_path: Path) -> None:
    table = parse_severity_map(table_path)
    on_result = res(ruleId="B1", properties={"security-severity": "9.9"})
    assert normalise_severity(on_result, None, "eng", table=table) is Severity.LOW


def test_confidence_from_the_engine_table_and_generic_keys(table_path: Path) -> None:
    table = parse_severity_map(table_path)
    mapped = res(properties={"issue_confidence": "UNDEFINED"})
    assert normalise_confidence(mapped, None, "eng", table=table) is Confidence.LOW
    on_rule = rule(properties={"issue_confidence": "HIGH"})
    assert normalise_confidence(res(), on_rule, "eng", table=table) is Confidence.HIGH
    assert (
        normalise_confidence(res(), rule(properties={"precision": "very-high"}), "x")
        is Confidence.HIGH
    )
    assert normalise_confidence(res(properties={"confidence": 0.5}), None, "x") is Confidence.MEDIUM
    assert normalise_confidence(res(properties={"confidence": 7}), None, "x") is None
    assert normalise_confidence(res(), None, "x") is None
    assert normalise_confidence(res(properties={"precision": "weird"}), None, "x") is None


# --- the tables --------------------------------------------------------------------------------


def test_the_shipped_tables_load() -> None:
    assert set(default_cwe_fallback().engines) == {"eslint-security", "detekt"}
    assert set(default_severity_table().engines) == {"detekt", "cppcheck", "flawfinder"}


@pytest.mark.parametrize(
    "text",
    [
        "[engines.e]\nunknown_key = 1\n",
        '[engines.e.rules]\n"x" = "catastrophic"\n',
        '[engines.e]\ndefault_level_map = { error = "nope" }\n',
        "[engines.e]\nconfidence_keys = [1]\n",
        "[engines]\ne = 3\n",
        "this is not toml [",
    ],
)
def test_a_malformed_severity_table_is_refused(text: str, tmp_path: Path) -> None:
    path = tmp_path / "t.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(TableError):
        parse_severity_map(path)


@pytest.mark.parametrize(
    "text", ['[engines.e]\n"x" = "89"\n', '[engines.e]\n"x" = []\n', '[engines.e]\n"x" = 0\n']
)
def test_a_malformed_cwe_table_is_refused(text: str, tmp_path: Path) -> None:
    path = tmp_path / "t.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(TableError):
        parse_cwe_fallback(path)


def test_a_cwe_table_loads(tmp_path: Path) -> None:
    path = tmp_path / "t.toml"
    path.write_text('[engines.e]\n"a" = 89\n"b." = [78, 77]\n', encoding="utf-8")
    assert parse_cwe_fallback(path).lookup("e", "b.c") == (78, 77)
