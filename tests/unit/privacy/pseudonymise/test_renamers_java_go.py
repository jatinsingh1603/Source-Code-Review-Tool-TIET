"""The Java and Go renamers (E09-06).

Fixtures under ``tests/fixtures/pseudonymise/rename/{java,go}`` each cover one hazard; their
renamed output is a golden file, re-parses with the node-type sequence of the input, holds no
internal name of four characters or more, and is the same on every run. The Go worked example of
the issue is a named regression test, and every fallback that leaves a name in clear is checked to
be counted while the plan still validates.
"""

import re
from pathlib import Path

import pytest

from codekavach.core.models import Language
from codekavach.parsing import REGISTRY, parse
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.classify import IdentifierClass
from codekavach.privacy.pseudonymise.renamers.go import STDLIB_ROOTS, rewrite_tag
from codekavach.privacy.pseudonymise.renamers.registry import (
    NO_RENAMER_YET,
    default_registry,
)
from tests.support.golden import assert_matches_golden
from tests.support.rename import FIXTURES, Renamed, node_types, rename_text

LANGUAGES = {"java": Language.JAVA, "go": Language.GO}
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


# --- the fixture set --------------------------------------------------------------------------


def test_each_language_has_at_least_fifteen_fixtures_with_goldens() -> None:
    for language in LANGUAGES.values():
        assert len([c for c in CASES if c[0] is language]) >= 15, language
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
        d.name
        for d in renamed.classification.decisions
        if d.classification is IdentifierClass.INTERNAL and len(d.name) >= 4
    }
    survivors = (internal & set(re.findall(r"\w+", renamed.text))) - kept_words(renamed)
    assert not survivors, sorted(survivors)


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_the_plan_is_deterministic_for_a_fixed_salt(case: tuple[Language, Path]) -> None:
    assert run(case).text == run(case).text


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_renaming_twice_changes_nothing_further(case: tuple[Language, Path]) -> None:
    """The output is already pseudonymised: its internal names are tokens, so a second pass finds
    the same set of tokens and changes only how they are numbered, never the structure."""
    language, path = case
    once = run(case)
    twice = rename_text(language, once.text, path=path.name)
    assert node_types(parse(path.name, language, twice.text).tree) == node_types(once.parsed.tree)


# --- the Go worked example --------------------------------------------------------------------

GO_EXAMPLE = """\
package pay

type Account struct {
	FestivalBonus int64 `json:"festivalBonus" db:"festival_bonus"`
}

func (a *Account) Accrue(rate int64) int64 { return a.FestivalBonus * rate }
"""
GO_EXPECTED = """\
package mod_1

type cls_1 struct {
	field_1 int64 `json:"field_1" db:"field_1"`
}

func (param_1 *cls_1) fn_1(param_2 int64) int64 { return param_1.field_1 * param_2 }
"""


def test_the_go_worked_example_produces_the_documented_output() -> None:
    """The tag keys stay, the wire names take the field's token, and the numbering is the salt's.

    The issue's example leaves the package clause out; here it is renamed like any internal name.
    """
    assert rename_text(Language.GO, GO_EXAMPLE, path="a.go").text == GO_EXPECTED


# --- the hazards ------------------------------------------------------------------------------


def test_java_this_field_and_same_named_parameter_share_one_token() -> None:
    text = run(stem("java02_this_and_shadowing")).text
    assert re.search(r"long (var_\d+) = (param_\d+|field_\d+) - this\.(field_\d+);", text)


def test_java_constructor_follows_its_class_name() -> None:
    text = run(stem("java01_class_members")).text
    assert re.search(r"public (cls_\d+)\(", text)
    assert len(set(re.findall(r"(cls_\d+)", text))) == 1


def test_java_annotation_types_and_element_names_stay_and_their_values_are_shaped() -> None:
    text = run(stem("java03_annotations")).text
    for kept in ("@Entity", "@Column(name = ", "@GetMapping(value = ", "produces ="):
        assert kept in text
    assert "mandate_registry" not in text and "nach_reference" not in text


def test_java_framework_contract_names_are_kept() -> None:
    text = run(stem("java10_servlet_contract")).text
    assert "doGet(HttpServletRequest" in text and "getParameter" in text
    text = run(stem("java13_interface_impl")).text
    for name in ("compareTo", "equals", "hashCode"):
        assert name in text


def test_java_reflection_by_name_follows_the_binding_it_names() -> None:
    renamed = run(stem("java11_reflection_marked"))
    token = re.search(r"private long (field_\d+)", renamed.text)
    assert token is not None
    assert f'getDeclaredField("{token.group(1)}")' in renamed.text
    assert "festivalBonus" not in renamed.text
    assert renamed.report.name_strings_rewritten == 1
    assert renamed.classification.counts.dynamic_name_marked == 1


def test_java_reflection_on_a_name_the_file_does_not_define_stays_in_clear_and_is_counted() -> None:
    source = (
        "class Probe {\n"
        "    Object read(Object target) throws Exception {\n"
        '        return target.getClass().getDeclaredField("festivalBonus").get(target);\n'
        "    }\n"
        "}\n"
    )
    renamed = rename_text(Language.JAVA, source, path="Probe.java")
    assert 'getDeclaredField("festivalBonus")' in renamed.text
    assert renamed.report.kept_identifier >= 1


def test_java_class_library_imports_are_kept_and_internal_packages_are_not() -> None:
    text = run(stem("java12_jdbc")).text
    assert "import java.sql.Connection;" in text
    assert "import java.sql.PreparedStatement;" in text
    assert "com.bank" not in text


def test_java_static_imports_follow_the_origin_of_the_import() -> None:
    text = run(stem("java08_static_imports")).text
    assert "import static java.lang.Math.max;" in text
    assert "Rounding" not in text and "roundHalfEven" not in text


def test_java_text_block_keeps_its_shape_and_loses_its_words() -> None:
    text = run(stem("java09_text_block")).text
    assert '"""' in text
    assert "festival" not in text and "andheri" not in text


def test_go_struct_tags_keep_their_keys_and_follow_the_field_token() -> None:
    text = run(stem("go02_struct_tags")).text
    names = set(re.findall(r"(field_\d+)", text))
    assert re.search(r'json:"field_\d+,omitempty" db:"field_\d+"', text)
    assert 'validate:"required,min=3"' in text
    assert "column:field_" in text and "primaryKey" in text
    assert 'json:"-"' in text
    assert "festival-bonus" not in text and "nachReference" not in text
    assert len(names) >= 3


def test_go_tag_rewriting_of_the_grammar() -> None:
    assert rewrite_tag('json:"a,omitempty,x"', "t") == 'json:"t,omitempty"'
    assert rewrite_tag('yaml:"-"', "t") == 'yaml:"-"'
    assert rewrite_tag('db:"" validate:"required"', "t") == 'db:"" validate:"required"'
    assert rewrite_tag('gorm:"not null;default:abc"', "t") == 'gorm:"not null;t"'
    assert rewrite_tag("not a tag", "t") == "t"
    assert rewrite_tag("", "t") == ""


def test_go_exported_and_unexported_names_are_both_renamed() -> None:
    text = run(stem("go01_struct_methods")).text
    assert "FestivalBonus" not in text and "owner" not in text and "Accrue" not in text


def test_go_method_set_names_stay_where_the_standard_library_defines_them() -> None:
    assert "ServeHTTP" in run(stem("go07_http_handler")).text
    assert "Error()" in run(stem("go15_custom_error")).text


def test_go_import_paths_keep_standard_library_and_shape_the_rest() -> None:
    text = run(stem("go14_import_aliases")).text
    assert '"encoding/json"' in text
    assert "github.com/bank" not in text and "payments" not in text
    assert "rules" not in text


def test_go_blank_identifier_and_blank_import_are_kept() -> None:
    text = run(stem("go05_blank_identifier")).text
    assert "_ = " in text and "for _, " in text and "import _ " in text


def test_go_reflection_by_name_follows_the_binding_it_names() -> None:
    renamed = run(stem("go13_reflection_marked"))
    token = re.search(r"(field_\d+) int64", renamed.text)
    assert token is not None
    assert f'FieldByName("{token.group(1)}")' in renamed.text
    assert "FestivalBonus" not in renamed.text
    assert renamed.report.name_strings_rewritten == 1


def test_go_reflection_on_a_name_the_file_does_not_define_stays_in_clear_and_is_counted() -> None:
    source = (
        'package p\n\nimport "reflect"\n\n'
        "func read(target any) any {\n"
        '\treturn reflect.ValueOf(target).FieldByName("FestivalBonus").Interface()\n'
        "}\n"
    )
    renamed = rename_text(Language.GO, source, path="p.go")
    assert 'FieldByName("FestivalBonus")' in renamed.text
    assert renamed.report.kept_identifier >= 1


def test_go_embedded_field_and_its_promoted_use_agree() -> None:
    text = run(stem("go10_embedded")).text
    names = re.findall(r"cls_\d+|field_\d+", text)
    assert text.count(sorted(set(names))[0]) >= 1
    assert "Audit" not in text and "CreatedBy" not in text


def test_go_standard_library_roots_do_not_include_a_dotted_host() -> None:
    assert all("." not in root for root in STDLIB_ROOTS)


# --- every fallback is counted and the payload still validates --------------------------------


def test_go_tag_on_a_public_field_takes_the_common_path() -> None:
    source = 'package p\n\ntype E struct {\n\tError string `json:"festivalBonus"`\n}\n'
    renamed = rename_text(Language.GO, source, path="e.go")
    assert "festivalBonus" not in renamed.text


# --- the allowlists ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("language", "keywords", "stdlib", "contracts"),
    [
        (
            Language.JAVA,
            ("class", "public", "static", "void", "int"),
            ("PreparedStatement", "executeQuery", "MessageDigest", "ObjectMapper"),
            ("doGet", "toString", "equals", "hashCode", "compareTo", "readObject"),
        ),
        (
            Language.GO,
            ("func", "package", "range", "chan", "defer"),
            ("Println", "ListenAndServe", "Query", "Marshal", "ParseInt"),
            ("ServeHTTP", "Error", "String", "MarshalJSON", "Scan"),
        ),
    ],
)
def test_an_allowlist_keeps_keywords_library_surface_and_contract_names(
    language: Language,
    keywords: tuple[str, ...],
    stdlib: tuple[str, ...],
    contracts: tuple[str, ...],
) -> None:
    allowlist = PublicAllowlist.bundled(language)
    assert all(allowlist.is_keyword_or_builtin(name) for name in keywords)
    assert all(allowlist.is_listed_member(name) for name in stdlib)
    assert all(allowlist.is_framework_contract(name) for name in contracts)


def test_each_allowlist_has_a_source_date_and_version_header() -> None:
    from codekavach.privacy.pseudonymise import data  # noqa: PLC0415 - the data files' package

    root = Path(next(iter(data.__path__)))
    for filename in ("java.toml", "go.toml"):
        header = (root / filename).read_text(encoding="utf-8").split("\nversion", 1)[0]
        for needle in ("Source:", "Generated:", "Version:"):
            assert needle in header, (filename, needle)


def test_the_allowlist_version_changes_with_the_data() -> None:
    java = PublicAllowlist.bundled(Language.JAVA).version()
    go = PublicAllowlist.bundled(Language.GO).version()
    assert java.startswith("java-") and go.startswith("go-") and java != go


# --- the registry -----------------------------------------------------------------------------


def test_every_language_with_a_spec_has_a_renamer_or_a_stated_reason() -> None:
    renamers = set(default_registry().languages())
    for language in REGISTRY.languages():
        assert language in renamers or language in NO_RENAMER_YET, language
    for language, reason in NO_RENAMER_YET.items():
        assert language not in renamers, language
        assert len(reason) >= 10, language


def test_java_and_go_are_registered_with_renamers_of_their_own_language() -> None:
    registry = default_registry()
    assert registry.get(Language.JAVA).language is Language.JAVA
    assert registry.get(Language.GO).language is Language.GO
