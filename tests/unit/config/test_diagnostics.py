import re
from pathlib import Path
from types import MappingProxyType

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.config import ConfigErrorCode, ConfigIssue, Settings
from codekavach.config.diagnostics import (
    DEPRECATED_KEYS,
    apply_deprecations,
    format_issues,
    suggest_key,
)
from codekavach.config.errors import ConfigValidationError
from codekavach.config.provenance import Layer
from tests.support.config import ConfigSandbox
from tests.support.golden import assert_matches_golden

GOLDEN = Path(__file__).resolve().parents[2] / "golden" / "config" / "diagnostics_basic.txt"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

FIXTURE = [
    ConfigIssue(
        ConfigErrorCode.CK_CFG_038,
        "warning",
        "public providers are configured below L3",
        key="privacy.provider_tier_levels.public",
        source="/home/u/.config/codekavach/config.toml",
        line=9,
    ),
    ConfigIssue(
        ConfigErrorCode.CK_CFG_002,
        "error",
        "unknown key 'privacy.levle'",
        key="privacy.levle",
        source="/repo/codekavach.toml",
        line=14,
        hint="did you mean 'privacy.level'?",
    ),
]


def make(
    code: ConfigErrorCode = ConfigErrorCode.CK_CFG_003,
    severity: str = "error",
    **fields: object,
) -> ConfigIssue:
    return ConfigIssue(code, severity, "bad value", **fields)  # type: ignore[arg-type]


# layout


def test_golden_layout() -> None:
    assert_matches_golden(format_issues(FIXTURE) + "\n", GOLDEN)


def test_colour_wraps_only_severity_words() -> None:
    coloured = format_issues(FIXTURE, colour=True)
    assert "\x1b[31merror\x1b[0m[CK-CFG-002]" in coloured
    assert "\x1b[33mwarning\x1b[0m[CK-CFG-038]" in coloured
    assert len(ANSI.findall(coloured)) == 4
    assert ANSI.sub("", coloured) == format_issues(FIXTURE)


def test_empty_list() -> None:
    assert format_issues([]) == ""


def test_no_source_and_no_line() -> None:
    assert format_issues([make()]) == (
        "error[CK-CFG-003]: bad value\n\n1 problem (1 error, 0 warnings)"
    )
    assert "  --> a.toml\n" in format_issues([make(source="a.toml")])


def test_multi_line_hint_aligned() -> None:
    text = format_issues([make(hint="first\nsecond")])
    assert "  hint: first\n        second\n" in text


def test_only_warnings() -> None:
    warnings = [make(ConfigErrorCode.CK_CFG_006, "warning")] * 2
    assert format_issues(warnings).endswith("2 problems (0 errors, 2 warnings)")


def test_only_errors_keep_order() -> None:
    text = format_issues([make(ConfigErrorCode.CK_CFG_005), make(ConfigErrorCode.CK_CFG_001)])
    assert text.index("CK-CFG-005") < text.index("CK-CFG-001")
    assert text.endswith("2 problems (2 errors, 0 warnings)")


def test_key_appended_when_not_in_message() -> None:
    assert "error[CK-CFG-003]: bad value (scan.jobs)" in format_issues([make(key="scan.jobs")])


def test_str_of_error_uses_formatter() -> None:
    error = ConfigValidationError(FIXTURE)
    assert str(error) == format_issues(error.issues)


# suggestions


@pytest.mark.parametrize(
    ("unknown", "expected"),
    [
        ("config_versoin", "config_version"),
        ("scna", "scan"),
        ("privacy.levle", "privacy.level"),
        ("privcy.level", "privacy.level"),
        ("scan.max_file_size", "scan.max_file_size_kb"),
        ("llm.providers.lab.modle", "llm.providers.lab.model"),
        ("privacy.paths[2].levl", "privacy.paths[2].level"),
    ],
)
def test_suggest_key(unknown: str, expected: str) -> None:
    assert suggest_key(unknown, Settings) == expected


@pytest.mark.parametrize("unknown", ["zzzz", "privacy.qqqqqq", "llm.providers.lab.xyzzy"])
def test_no_suggestion(unknown: str) -> None:
    assert suggest_key(unknown, Settings) is None


def test_unknown_key_from_loader(config_sandbox: ConfigSandbox) -> None:
    path = config_sandbox.write_project('[privacy]\nlevle = "L4"\n')
    with pytest.raises(ConfigValidationError) as info:
        config_sandbox.load(use_user_config=False)
    issue = info.value.issues[0]
    assert issue.code is ConfigErrorCode.CK_CFG_002
    assert (issue.key, issue.source, issue.line) == ("privacy.levle", str(path), 2)
    assert issue.hint == "did you mean 'privacy.level'?"


# deprecations

RENAME = {"scan.max_size_kb": "scan.max_file_size_kb"}


def layer(data: dict[str, object], text: str | None = None) -> Layer:
    return Layer(name="project", source="/repo/codekavach.toml", data=data, text=text)


def test_shipped_map_is_empty() -> None:
    assert DEPRECATED_KEYS == {}


def test_move() -> None:
    original = layer({"scan": {"max_size_kb": 10}}, "[scan]\nmax_size_kb = 10\n")
    moved, warnings = apply_deprecations(original, RENAME)
    assert moved.data == {"scan": {"max_file_size_kb": 10}}
    assert [(w.code, w.severity, w.key, w.line) for w in warnings] == [
        (ConfigErrorCode.CK_CFG_006, "warning", "scan.max_size_kb", 2)
    ]
    assert warnings[0].message == "'scan.max_size_kb' is deprecated; use 'scan.max_file_size_kb'"
    assert original.data == {"scan": {"max_size_kb": 10}}


def test_both_present_keeps_new() -> None:
    both = layer({"scan": {"max_size_kb": 10, "max_file_size_kb": 20}})
    moved, warnings = apply_deprecations(both, RENAME)
    assert moved.data == {"scan": {"max_file_size_kb": 20}}
    assert "ignored" in warnings[0].message
    assert both.data == {"scan": {"max_size_kb": 10, "max_file_size_kb": 20}}


def test_neither_present() -> None:
    plain = layer({"scan": {"jobs": 2}})
    assert apply_deprecations(plain, RENAME) == (plain, [])


def test_emptied_table_dropped() -> None:
    moved, _ = apply_deprecations(layer({"old": {"jobs": 3}}), {"old.jobs": "scan.jobs"})
    assert moved.data == {"scan": {"jobs": 3}}


def test_loader_migrates_with_warning(
    config_sandbox: ConfigSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    for old, new in RENAME.items():
        monkeypatch.setitem(DEPRECATED_KEYS, old, new)
    config_sandbox.write_project('[project]\nname = "demo"\n\n[scan]\nmax_size_kb = 64\n')
    loaded = config_sandbox.load(use_user_config=False)
    assert loaded.settings.scan.max_file_size_kb == 64
    assert [(w.code.value, w.line) for w in loaded.warnings] == [("CK-CFG-006", 5)]


def test_input_layer_mappings_not_mutated() -> None:
    inner = {"max_size_kb": 10}
    frozen = layer(MappingProxyType({"scan": MappingProxyType(inner)}))  # type: ignore[arg-type]
    apply_deprecations(frozen, RENAME)
    assert inner == {"max_size_kb": 10}


# properties

# Free text never contains "[", so it cannot imitate a headline.
_text = st.text(alphabet=st.characters(exclude_characters="["), max_size=40)
_issues = st.builds(
    ConfigIssue,
    code=st.sampled_from(list(ConfigErrorCode)),
    severity=st.sampled_from(["error", "warning"]),
    message=_text,
    key=st.none() | _text,
    source=st.none() | _text,
    line=st.none() | st.integers(1, 10_000),
    hint=st.none() | _text,
)


@given(st.lists(_issues, max_size=8))
def test_formatter_total_and_codes_once_per_issue(issues: list[ConfigIssue]) -> None:
    text = format_issues(issues)
    headlines = re.findall(r"^(?:error|warning)\[(CK-CFG-\d{3})\]: ", text, re.MULTILINE)
    assert sorted(headlines) == sorted(issue.code.value for issue in issues)
