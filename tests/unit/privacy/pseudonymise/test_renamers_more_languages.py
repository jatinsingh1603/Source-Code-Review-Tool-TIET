"""The Kotlin, PHP, C#, Ruby, C and C++ renamers (E09-07).

Fixtures under ``tests/fixtures/pseudonymise/rename/{kotlin,php,csharp,ruby,c,cpp}`` each cover
one hazard; their renamed output is a golden file, re-parses with the node-type sequence of the
input (the AST-isomorphism invariant), holds no internal name of four characters or more (I6), and
is the same on every run (I5).
"""

import re
from pathlib import Path

import pytest

from codekavach.core.models import Language
from codekavach.parsing import REGISTRY, parse
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.classify import IdentifierClass
from codekavach.privacy.pseudonymise.renamers.registry import default_registry
from tests.support.golden import assert_matches_golden
from tests.support.rename import FIXTURES, Renamed, node_types, rename_text

LANGUAGES = {
    "kotlin": Language.KOTLIN,
    "php": Language.PHP,
    "csharp": Language.CSHARP,
    "ruby": Language.RUBY,
    "c": Language.C,
    "cpp": Language.CPP,
}
CASES = [
    (LANGUAGES[folder], path)
    for folder in LANGUAGES
    for path in sorted((FIXTURES / folder).glob("*.*"))
    if not path.name.endswith(".golden.txt")
]


def case_id(case: tuple[Language, Path]) -> str:
    return case[1].stem


def run(case: tuple[Language, Path]) -> Renamed:
    language, path = case
    return rename_text(language, path.read_text(encoding="utf-8"), path=path.name)


def stem(name: str) -> tuple[Language, Path]:
    return next(case for case in CASES if case[1].stem == name)


def kept_words(renamed: Renamed) -> set[str]:
    decisions = renamed.classification.decisions
    allowed = {d.name for d in decisions if d.classification is IdentifierClass.PUBLIC}
    return allowed | set(renamed.classification.kept_dynamic)


def words_of(text: str) -> set[str]:
    return set(re.findall(r"\w+", text))


def test_each_language_has_at_least_five_fixtures_with_goldens() -> None:
    for language in LANGUAGES.values():
        assert len([c for c in CASES if c[0] is language]) >= 5, language
    for _, path in CASES:
        assert path.with_name(path.name + ".golden.txt").is_file(), path.name


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_the_renamed_output_matches_its_golden(case: tuple[Language, Path]) -> None:
    assert_matches_golden(run(case).text, case[1].with_name(case[1].name + ".golden.txt"))


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_the_output_reparses_with_the_same_node_type_sequence(case: tuple[Language, Path]) -> None:
    language, path = case
    renamed = run(case)
    again = parse(path.name, language, renamed.text)
    assert again.error_count == 0
    assert node_types(again.tree) == node_types(renamed.parsed.tree)


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_no_internal_name_of_four_characters_or_more_survives(case: tuple[Language, Path]) -> None:
    renamed = run(case)
    internal = {
        d.name.lstrip("@$:").rstrip("?!")
        for d in renamed.classification.decisions
        if d.classification is IdentifierClass.INTERNAL and len(d.name.lstrip("@$:")) >= 4
    }
    survivors = (internal & words_of(renamed.text)) - {w.lstrip("@$:") for w in kept_words(renamed)}
    assert not survivors, sorted(survivors)


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_the_plan_is_deterministic_for_a_fixed_salt(case: tuple[Language, Path]) -> None:
    assert run(case).text == run(case).text


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_renaming_twice_changes_nothing_further(case: tuple[Language, Path]) -> None:
    language, path = case
    once = run(case)
    twice = rename_text(language, once.text, path=path.name)
    assert node_types(parse(path.name, language, twice.text).tree) == node_types(once.parsed.tree)


# --- hazards of one language ------------------------------------------------------------------


def test_ruby_sigils_and_suffixes_are_kept_and_the_spellings_of_a_name_share_a_token() -> None:
    source = (
        "class Registry\n"
        "  attr_accessor :festival_cap\n"
        "  def initialize(festival_cap)\n"
        "    @festival_cap = festival_cap\n"
        "  end\n"
        "  def festival_cap?\n"
        "    @festival_cap > 0\n"
        "  end\n"
        "end\n"
    )
    text = rename_text(Language.RUBY, source, path="r.rb").text
    assert "festival_cap" not in text
    assert text.count("@") == 2
    assert "?" in text
    tokens = set(re.findall(r"[a-z]+_\d+", text))
    assert len(tokens) == 2  # the class and the one shared name


def test_php_variables_keep_their_dollar_and_superglobals_stay() -> None:
    text = rename_text(
        Language.PHP,
        "<?php\nfunction pay($festivalBonus) { return $_POST['amount'] + $festivalBonus; }\n",
        path="a.php",
    ).text
    assert "$_POST" in text
    assert "festivalBonus" not in text
    assert re.search(r"\$[a-z]+_\d+", text)


def test_c_library_calls_and_types_stay_in_clear() -> None:
    text = rename_text(
        Language.C,
        "#include <string.h>\nvoid copyOwner(char *dst, const char *src) { strcpy(dst, src); }\n",
        path="a.c",
    ).text
    assert "strcpy" in text
    assert "copyOwner" not in text


def test_csharp_base_class_library_names_stay_in_clear() -> None:
    text = rename_text(
        Language.CSHARP,
        "class A { void Run(string festivalName) { System.Console.WriteLine(festivalName); } }\n",
        path="A.cs",
    ).text
    assert "Console.WriteLine" in text
    assert "festivalName" not in text


def test_cpp_std_names_stay_and_a_qualified_definition_follows_its_class() -> None:
    renamed = rename_text(Language.CPP, run_source("cpp04_out_of_line_methods"), path="a.cpp")
    assert "SessionRegistry" not in renamed.text
    assert renamed.text.count("cls_") >= 3


def run_source(name: str) -> str:
    return stem(name)[1].read_text(encoding="utf-8")


def test_kotlin_jvm_library_calls_stay_in_clear() -> None:
    text = run(stem("kt02_jdbc_query")).text
    assert "createStatement" in text and "executeQuery" in text
    assert "AccountDao" not in text


# --- the allowlists and the registry ----------------------------------------------------------


@pytest.mark.parametrize(
    ("language", "keywords", "library"),
    [
        (Language.KOTLIN, ("fun", "val", "class"), ("println", "executeQuery")),
        (Language.PHP, ("function", "foreach", "echo"), ("htmlspecialchars", "mysqli_query")),
        (Language.CSHARP, ("namespace", "using", "var"), ("ExecuteReader", "WriteLine")),
        (Language.RUBY, ("def", "end", "rescue"), ("puts", "attr_accessor")),
        (Language.C, ("struct", "typedef", "sizeof"), ("strcpy", "malloc")),
        (Language.CPP, ("namespace", "template", "nullptr"), ("cout", "make_unique")),
    ],
)
def test_an_allowlist_keeps_keywords_and_library_surface(
    language: Language, keywords: tuple[str, ...], library: tuple[str, ...]
) -> None:
    allowlist = PublicAllowlist.bundled(language)
    assert all(allowlist.is_keyword_or_builtin(name) for name in keywords)
    assert all(
        allowlist.is_keyword_or_builtin(name) or allowlist.is_listed_member(name)
        for name in library
    )
    assert allowlist.version().startswith(f"{language.value}-")


def test_each_new_allowlist_has_a_source_date_and_version_header() -> None:
    from codekavach.privacy.pseudonymise import data  # noqa: PLC0415 - the data files' package

    root = Path(next(iter(data.__path__)))
    for name in LANGUAGES:
        header = (root / f"{name}.toml").read_text(encoding="utf-8").split("\nversion", 1)[0]
        for needle in ("Source:", "Generated:", "Version:"):
            assert needle in header, (name, needle)


def test_every_new_language_has_a_renamer_of_its_own_language() -> None:
    registry = default_registry()
    for language in LANGUAGES.values():
        assert registry.get(language).language is language
        assert language in REGISTRY.languages()
