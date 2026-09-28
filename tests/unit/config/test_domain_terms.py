from pathlib import Path

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from codekavach.config import ConfigError
from codekavach.config.domain_terms import MAX_TERMS, parse_terms, read_terms_file
from tests.support.config import ConfigSandbox

TERMS_KEY = "privacy.domain_terms_file"


def codes(error: ConfigError) -> list[str]:
    return [issue.code.value for issue in error.issues]


# parse_terms


def test_comments_blank_lines_and_white_space() -> None:
    text = "# products\n  GoldSaver  \n\n\t# indented comment\nkavachbank\n"
    assert parse_terms(text) == ["GoldSaver", "kavachbank"]


def test_bom_crlf_and_duplicates() -> None:
    assert parse_terms("﻿Alpha\r\nBeta\r\nAlpha\r\n") == ["Alpha", "Beta"]


def test_case_preserved() -> None:
    assert parse_terms("Kavach\nkavach\n") == ["Kavach", "kavach"]


@pytest.mark.parametrize("separator", ["\x0c", "\N{LINE SEPARATOR}"])
def test_split_lines_model_keeps_line_numbers(separator: str) -> None:
    assert parse_terms(f"ab{separator}cd\nef\n") == [f"ab{separator}cd", "ef"]
    with pytest.raises(ConfigError) as info:
        parse_terms(f"ab{separator}cd\nx\n")
    assert info.value.issues[0].line == 2


@pytest.mark.parametrize("term", ["x", "y" * 129])
def test_term_length_limits(term: str) -> None:
    with pytest.raises(ConfigError) as info:
        parse_terms(f"ok-term\n# c\n{term}\n")
    issue = info.value.issues[0]
    assert codes(info.value) == ["CK-CFG-003"]
    assert issue.line == 3
    assert issue.key == TERMS_KEY
    assert term not in str(info.value)


def test_boundary_lengths_accepted() -> None:
    assert parse_terms("ab\n" + "z" * 128) == ["ab", "z" * 128]


def test_too_many_terms() -> None:
    text = "\n".join(f"term{i}" for i in range(MAX_TERMS + 1))
    with pytest.raises(ConfigError) as info:
        parse_terms(text)
    assert codes(info.value) == ["CK-CFG-003"]
    assert info.value.issues[0].line == MAX_TERMS + 1
    assert len(parse_terms("\n".join(f"term{i}" for i in range(MAX_TERMS)))) == MAX_TERMS


# read_terms_file


def test_read_terms_file_failures_hide_content(tmp_path: Path) -> None:
    hidden_term = "GoldSaverPremium"
    big = tmp_path / "big.txt"
    big.write_text(hidden_term + "\n" + "x" * 64, encoding="utf-8")
    bad = tmp_path / "bad.txt"
    bad.write_bytes(hidden_term.encode() + b"\xff\xfe\n")
    cases = [(tmp_path / "missing.txt", None), (tmp_path, None), (big, 32), (bad, None)]
    for path, limit in cases:
        with pytest.raises(ConfigError) as info:
            if limit is None:
                read_terms_file(path, confine_to=None)
            else:
                read_terms_file(path, max_bytes=limit, confine_to=None)
        assert codes(info.value) == ["CK-CFG-005"], path
        assert hidden_term not in str(info.value)


# loader


def test_example_list_and_contributors(config_sandbox: ConfigSandbox) -> None:
    (config_sandbox.root / "config").mkdir()
    (config_sandbox.root / "config" / "terms.txt").write_text(
        "# products\nGoldSaver\n\nkavachbank\n", encoding="utf-8"
    )
    config_sandbox.write_project(
        '[privacy]\ndomain_terms = ["kavachbank"]\ndomain_terms_file = "config/terms.txt"\n'
    )
    loaded = config_sandbox.load(use_user_config=False)
    assert loaded.settings.privacy.domain_terms == ["kavachbank", "GoldSaver"]
    assert loaded.origins["privacy.domain_terms"].contributors == ("project", "project:file")
    assert loaded.settings.privacy.domain_terms_file == Path("config/terms.txt")


def test_file_only_contributor(config_sandbox: ConfigSandbox) -> None:
    (config_sandbox.root / "terms.txt").write_text("GoldSaver\n", encoding="utf-8")
    config_sandbox.write_project('[privacy]\ndomain_terms_file = "terms.txt"\n')
    loaded = config_sandbox.load(use_user_config=False)
    assert loaded.origins["privacy.domain_terms"].contributors == ("project:file",)


def _project_failure(config_sandbox: ConfigSandbox, value: str) -> ConfigError:
    project = config_sandbox.write_project(
        f'[project]\nname = "demo"\n\n[privacy]\ndomain_terms_file = "{value}"\n'
    )
    # Trusted, so that the read itself is exercised; untrusted, 040 fires first (E03-25).
    with pytest.raises(ConfigError) as info:
        config_sandbox.load(use_user_config=False, trust_project_config=True)
    issue = info.value.issues[0]
    assert issue.code.value == "CK-CFG-005"
    assert issue.key == TERMS_KEY
    assert issue.source == str(project)
    assert issue.line == 5
    return info.value


def test_missing_and_directory_stop_loading(config_sandbox: ConfigSandbox) -> None:
    _project_failure(config_sandbox, "missing.txt")
    (config_sandbox.root / "folder").mkdir()
    _project_failure(config_sandbox, "folder")


def test_oversized_and_non_utf8_stop_loading(config_sandbox: ConfigSandbox) -> None:
    (config_sandbox.root / "big.txt").write_text("ab\n" * 600_000, encoding="utf-8")
    _project_failure(config_sandbox, "big.txt")
    (config_sandbox.root / "bad.txt").write_bytes(b"GoldSaver\xff\n")
    error = _project_failure(config_sandbox, "bad.txt")
    assert "GoldSaver" not in str(error)


def test_symlink_escaping_project_refused(config_sandbox: ConfigSandbox) -> None:
    target = config_sandbox.outside / "terms.txt"
    target.write_text("GoldSaver\n", encoding="utf-8")
    link = config_sandbox.root / "terms.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are not permitted here")
    error = _project_failure(config_sandbox, "terms.txt")
    assert "GoldSaver" not in str(error)


def test_absolute_path_outside_project_refused(config_sandbox: ConfigSandbox) -> None:
    target = config_sandbox.outside / "terms.txt"
    target.write_text("GoldSaver\n", encoding="utf-8")
    _project_failure(config_sandbox, target.as_posix())


def test_invalid_term_reports_terms_file_line(config_sandbox: ConfigSandbox) -> None:
    terms = config_sandbox.root / "terms.txt"
    terms.write_text("GoldSaver\nx\n", encoding="utf-8")
    config_sandbox.write_project('[privacy]\ndomain_terms_file = "terms.txt"\n')
    with pytest.raises(ConfigError) as info:
        config_sandbox.load(use_user_config=False)
    issue = info.value.issues[0]
    assert (issue.code.value, issue.line, issue.source) == ("CK-CFG-003", 2, str(terms))


def test_user_relative_path_resolves_against_project(config_sandbox: ConfigSandbox) -> None:
    (config_sandbox.root / "user-terms.txt").write_text("UserTerm\n", encoding="utf-8")
    config_sandbox.write_user('[privacy]\ndomain_terms_file = "user-terms.txt"\n')
    loaded = config_sandbox.load()
    assert loaded.settings.privacy.domain_terms == ["UserTerm"]


def test_user_absolute_and_home_paths(
    config_sandbox: ConfigSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    absolute = config_sandbox.outside / "abs.txt"
    absolute.write_text("AbsTerm\n", encoding="utf-8")
    config_sandbox.write_user(f'[privacy]\ndomain_terms_file = "{absolute.as_posix()}"\n')
    assert config_sandbox.load().settings.privacy.domain_terms == ["AbsTerm"]
    monkeypatch.setenv("HOME", str(config_sandbox.home))
    monkeypatch.setenv("USERPROFILE", str(config_sandbox.home))
    (config_sandbox.home / "terms.txt").write_text("HomeTerm\n", encoding="utf-8")
    config_sandbox.write_user('[privacy]\ndomain_terms_file = "~/terms.txt"\n')
    assert config_sandbox.load().settings.privacy.domain_terms == ["HomeTerm"]


def test_environment_and_cli_layers_expand(config_sandbox: ConfigSandbox) -> None:
    terms = config_sandbox.outside / "env.txt"
    terms.write_text("EnvTerm\n", encoding="utf-8")
    config_sandbox.env["CODEKAVACH_PRIVACY__DOMAIN_TERMS_FILE"] = str(terms)
    loaded = config_sandbox.load(use_user_config=False)
    assert loaded.settings.privacy.domain_terms == ["EnvTerm"]
    assert loaded.origins["privacy.domain_terms"].contributors == ("env:file",)
    del config_sandbox.env["CODEKAVACH_PRIVACY__DOMAIN_TERMS_FILE"]
    loaded = config_sandbox.load(
        use_user_config=False, cli_overrides={"privacy": {"domain_terms_file": str(terms)}}
    )
    assert loaded.settings.privacy.domain_terms == ["EnvTerm"]


# properties

_term = st.text(
    alphabet=st.characters(codec="utf-8", categories=["L", "N"]), min_size=2, max_size=20
)


@given(st.lists(_term, max_size=30))
def test_round_trip_dedupes_in_first_seen_order(terms: list[str]) -> None:
    assert parse_terms("\n".join(terms)) == list(dict.fromkeys(terms))


@given(st.lists(_term.filter(lambda t: len(t) >= 4), min_size=1, max_size=10), st.data())
def test_errors_never_contain_sibling_terms(terms: list[str], data: st.DataObject) -> None:
    with pytest.raises(ConfigError) as baseline:
        parse_terms("q" * 129)
    fixed_text = str(baseline.value) + repr(baseline.value)
    # A generated word that happens to be part of the fixed message proves nothing.
    assume(not any(term in fixed_text for term in terms))
    position = data.draw(st.integers(0, len(terms)))
    lines = [*terms[:position], "q" * 129, *terms[position:]]
    with pytest.raises(ConfigError) as info:
        parse_terms("\n".join(lines))
    rendered = str(info.value) + repr(info.value)
    assert info.value.issues[0].line == position + 1
    for term in terms:
        assert term not in rendered
