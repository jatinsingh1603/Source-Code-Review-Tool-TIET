"""The Python, JavaScript and TypeScript renamers (E09-04).

Fixtures under ``tests/fixtures/pseudonymise/rename`` each cover one hazard; their renamed output is
a golden file, re-parses with the node-type sequence of the input, and holds no internal name of
four characters or more. The two worked examples of the issue are named regression tests. Rules
that need a close look (shorthand, f-strings, dynamic names, keyword pairing, placeholders,
fail-closed behaviour) have tests of their own.
"""

import re
from itertools import pairwise
from pathlib import Path

import pytest

from codekavach.core.models import Language, PrivacyLevel
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.parsing import parse
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.classify import (
    ClassificationDecision,
    ClassificationResult,
    ConservativeCounts,
    IdentifierClass,
    Rule,
)
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator
from codekavach.privacy.pseudonymise.plan import (
    EditReason,
    file_labels,
    placeholder_byte_ranges,
)
from codekavach.privacy.pseudonymise.renamers.base import (
    BaseRenamer,
    UnsupportedLanguageError,
)
from codekavach.privacy.pseudonymise.renamers.go import GoRenamer
from codekavach.privacy.pseudonymise.renamers.java import JavaRenamer
from codekavach.privacy.pseudonymise.renamers.javascript import (
    JavaScriptRenamer,
    TypeScriptRenamer,
)
from codekavach.privacy.pseudonymise.renamers.python import PythonRenamer
from codekavach.privacy.pseudonymise.renamers.registry import RenamerRegistry, default_registry
from tests.support.golden import assert_matches_golden
from tests.support.rename import (
    FIXTURES,
    SALT,
    Renamed,
    expanded_starts,
    node_types,
    rename_text,
)

LANGUAGES = {
    "python": Language.PYTHON,
    "javascript": Language.JAVASCRIPT,
    "typescript": Language.TYPESCRIPT,
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


def fixture(name: str) -> tuple[Language, Path]:
    return next(case for case in CASES if case[1].stem == name)


def kept_words(renamed: Renamed) -> set[str]:
    """Names that may appear in the output: public somewhere, kept dynamic, or a shorthand key."""
    decisions = renamed.classification.decisions
    allowed = {d.name for d in decisions if d.classification is IdentifierClass.PUBLIC}
    allowed |= set(renamed.classification.kept_dynamic)
    allowed |= {
        e.replacement.split(":", 1)[0]
        for e in renamed.plan.edits
        if e.reason is EditReason.SHORTHAND_KEY
    }
    return allowed


# --- the fixture set --------------------------------------------------------------------------


def test_there_are_thirty_python_and_thirty_javascript_or_typescript_cases() -> None:
    python = [c for c in CASES if c[0] is Language.PYTHON]
    script = [c for c in CASES if c[0] is not Language.PYTHON]
    assert len(python) >= 30
    assert len(script) >= 30
    assert {c[0] for c in script} == {Language.JAVASCRIPT, Language.TYPESCRIPT}
    for _, path in CASES:
        assert path.with_name(path.name + ".golden.txt").is_file(), path.name


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_the_renamed_output_matches_its_golden(case: tuple[Language, Path]) -> None:
    renamed = run(case)
    assert_matches_golden(renamed.text, case[1].with_name(case[1].name + ".golden.txt"))


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_the_output_reparses_with_the_same_node_type_sequence(case: tuple[Language, Path]) -> None:
    language, path = case
    renamed = run(case)
    again = parse(path.name, language, renamed.text)
    assert again.error_count == 0
    before = node_types(renamed.parsed.tree, expanded=expanded_starts(renamed))
    assert node_types(again.tree) == before


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_no_internal_name_of_four_characters_or_more_survives(case: tuple[Language, Path]) -> None:
    renamed = run(case)
    internal = {
        d.name.removeprefix("#")
        for d in renamed.classification.decisions
        if d.classification is IdentifierClass.INTERNAL and len(d.name.removeprefix("#")) >= 4
    }
    survivors = (internal & set(re.findall(r"\w+", renamed.text))) - kept_words(renamed)
    assert not survivors, sorted(survivors)


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_the_plan_is_deterministic_for_a_fixed_salt(case: tuple[Language, Path]) -> None:
    assert run(case).text == run(case).text


# --- the worked examples ----------------------------------------------------------------------

JS_EXAMPLE = (
    "const { accountId, createdAt } = req.body;      // req is public, both bindings internal\n"
    'const fee = computeFee({ accountId, tier: "premium" });\n'
)
PY_EXAMPLE = (
    "from flask import Flask, jsonify\n"
    "app = Flask(__name__)\n\n"
    '@app.route("/accounts/<aid>")\n'
    "def get_account(aid):\n"
    '    "Return the account and its festival bonus."\n'
    '    return jsonify({"balance": account_balance(aid)})\n'
)


def test_worked_example_javascript_expands_the_shorthand_in_both_directions() -> None:
    """``{ accountId }`` becomes ``{ accountId: var_N }`` in the pattern and in the literal.

    The issue shows ``var_1``, ``var_2``, ``fn_1`` and a kept ``tier`` key; the numbers depend on
    the scan salt (I5), ``computeFee`` has no definition so it is a ``var``, and ``tier`` is an
    internal key, which the classifier renames. The shape is the documented one.
    """
    renamed = rename_text(Language.JAVASCRIPT, JS_EXAMPLE, extra=("req",))
    first, second = renamed.text.split("\n")[:2]
    token = r"var_\d+"
    assert re.fullmatch(
        rf"const \{{ accountId: ({token}), createdAt: ({token}) \}} = req\.body; +", first
    )
    binding = re.match(rf"const \{{ accountId: ({token}),", first)
    assert binding is not None
    assert re.fullmatch(
        rf"const {token} = {token}\(\{{ accountId: {re.escape(binding.group(1))}, "
        r'field_\d+: "x{7}" \}\);',
        second,
    )
    assert renamed.report.shorthand_expanded == 3


def test_worked_example_python_keeps_public_names_and_blanks_the_docstring() -> None:
    """``app``, ``route`` and ``jsonify`` survive; the docstring keeps its length and its quotes.

    The issue shows a docstring of spaces; E09-03's blanker refuses a whitespace marker, so the
    body is the marker ``x``. The dictionary key survives because ``balance`` is declared public.
    """
    renamed = rename_text(Language.PYTHON, PY_EXAMPLE, extra=("balance",))
    lines = renamed.text.split("\n")
    assert lines[0] == "from flask import Flask, jsonify"
    assert re.fullmatch(r'@app\.route\("/file_\d+/file_\d+"\)', lines[3])
    assert re.fullmatch(r"def fn_1\(param_1\):", lines[4])
    assert lines[5] == '    "' + "x" * len("Return the account and its festival bonus.") + '"'
    assert re.fullmatch(r'    return jsonify\(\{"balance": var_1\(param_1\)\}\)', lines[6])
    assert len(lines) == len(PY_EXAMPLE.split("\n"))


# --- shorthand --------------------------------------------------------------------------------


def test_a_shorthand_property_and_pattern_expand_and_a_public_one_stays() -> None:
    source = (
        "// extra: req\n"
        "const { accountId } = req.body;\n"
        "const out = { accountId, req };\n"
        "function f({ accountId, req }) { return accountId + req; }\n"
    )
    renamed = rename_text(Language.JAVASCRIPT, source)
    token = re.search(r"\{ accountId: ((?:var|param)_\d+) \}", renamed.text)
    assert token is not None
    assert f"{{ accountId: {token.group(1)}, req }}" in renamed.text  # literal: req is public
    assert re.search(r"function fn_\d+\(\{ accountId: (?:var|param)_\d+, req \}\)", renamed.text)
    assert renamed.report.shorthand_expanded == 3


def test_a_shorthand_pattern_with_a_default_keeps_its_default() -> None:
    renamed = rename_text(
        Language.JAVASCRIPT, "function f({ retryLimit = 3 }) { return retryLimit; }\n"
    )
    assert re.search(r"\{ retryLimit: var_\d+ = 3 \}", renamed.text) or re.search(
        r"\{ retryLimit: param_\d+ = 3 \}", renamed.text
    )
    assert parse("o.js", Language.JAVASCRIPT, renamed.text).error_count == 0


def test_private_fields_keep_their_hash() -> None:
    renamed = run(fixture("js13_private_fields"))
    assert re.search(r"#field_\d+ = 0;", renamed.text)
    assert "this.#field_" in renamed.text
    assert "#secretTotal" not in renamed.text


# --- f-strings --------------------------------------------------------------------------------


def test_an_fstring_renames_its_interpolations_and_shapes_its_quasis_in_disjoint_ranges() -> None:
    renamed = run(fixture("py15_fstring_interpolation"))
    assert re.search(r'f"x{7} \{param_\d+\} x{5} \{param_\d+\} x{6}"', renamed.text)
    ranges = [(e.start_byte, e.end_byte, e.reason) for e in renamed.plan.edits]
    assert {r for _, _, r in ranges} >= {EditReason.IDENTIFIER, EditReason.LITERAL}
    for (_, end, _), (start, _, _) in pairwise(ranges):
        assert end <= start


def test_an_fstring_keeps_its_conversion_and_format_spec() -> None:
    renamed = run(fixture("py16_fstring_spec_conversion"))
    assert "!r:>12}" in renamed.text
    assert ":,.2f}" in renamed.text
    assert "total_due" not in renamed.text


def test_the_self_documenting_form_echoes_the_token() -> None:
    renamed = run(fixture("py17_fstring_self_documenting"))
    assert re.search(r'f"\{param_\d+=\} \{param_\d+ = \}"', renamed.text)


# --- dynamic names, keywords, strings that name a binding --------------------------------------


def test_a_dynamic_name_that_is_provable_is_rewritten_with_its_definition() -> None:
    renamed = run(fixture("py24_dynamic_marked"))
    assert "festival_bonus_rate" not in renamed.text
    assert re.search(r'getattr\(param_1, "(field_\d+)"\)', renamed.text)
    assert renamed.report.name_strings_rewritten == 1
    assert renamed.report.kept_identifier == 0


def test_a_dynamic_name_that_is_not_provable_stays_in_clear_and_is_counted() -> None:
    renamed = run(fixture("py25_dynamic_kept"))
    assert 'getattr(param_1, "loyalty_points_total")' in renamed.text
    assert renamed.report.kept_identifier == 1


def test_a_keyword_follows_the_parameter_it_binds() -> None:
    internal = run(fixture("py09_keyword_internal_callee")).text
    assert re.search(r"fn_\d+\(param_\d+=param_\d+, param_\d+=10, param_\d+=", internal)
    pair = run(fixture("py11_keyword_param_public_pair"))
    assert "def fn_1(param_1, type=None)" in pair.text
    assert "type=int" in pair.text
    assert pair.report.kept_identifier == 1


def test_a_keyword_of_a_public_callee_is_not_renamed() -> None:
    text = run(fixture("py10_keyword_public_callee")).text
    assert "timeout=" in text
    assert "verify=True" in text


def test_all_entries_and_string_annotations_follow_their_names() -> None:
    exported = run(fixture("py14_all_entries")).text
    assert '__all__ = ["fn_1", "cls_1"]' in exported
    assert "class cls_1" in exported
    annotated = run(fixture("py19_string_annotations")).text
    assert '"cls_1"' in annotated
    assert "Ledger" not in annotated


def test_relative_module_paths_are_pseudonymised() -> None:
    python = run(fixture("py28_relative_imports")).text
    assert re.fullmatch(r"from \. import mod_\d+\nfrom \.mod_\d+\.mod_\d+ import \w+\n", python)
    script = run(fixture("js14_import_export_specifiers")).text
    assert 'from "./file_' in script
    assert "report" not in script


def test_file_labels_are_tokens_that_do_not_depend_on_order() -> None:
    first = file_labels(PseudonymGenerator(SALT), ["a/b.py", "c/d.py", "e.py"])
    second = file_labels(PseudonymGenerator(SALT), ["e.py", "c/d.py", "a/b.py"])
    assert first == second
    assert all(re.fullmatch(r"file_[1-9]\d*", label) for label in first.values())
    assert not set(first) & set(first.values())


# --- placeholders and comments ----------------------------------------------------------------


@pytest.mark.parametrize("name", ["py31_placeholder_tokens", "js28_placeholder_tokens"])
def test_placeholder_tokens_survive_untouched_and_outside_every_edit(name: str) -> None:
    case = fixture(name)
    renamed = run(case)
    source = case[1].read_bytes()
    for start, end in placeholder_byte_ranges(source):
        assert not [e for e in renamed.plan.edits if e.start_byte < end and e.end_byte > start]
    for token in re.findall(r"<(?:SECRET|PII|TERM):\w+:\d+>", source.decode()):
        assert token in renamed.text


def test_comments_and_docstrings_keep_every_line_in_place() -> None:
    for name in ("py22_docstrings", "py23_comments", "js25_comments"):
        case = fixture(name)
        original = case[1].read_text(encoding="utf-8")
        renamed = run(case)
        assert renamed.text.count("\n") == original.count("\n")
        assert "KavachBank" not in renamed.text
        assert "festival" not in renamed.text


def test_multibyte_text_is_renamed_without_corruption() -> None:
    renamed = run(fixture("py30_unicode"))
    assert "grüße" not in renamed.text
    assert "naïve_name" not in renamed.text
    assert "日本語" not in renamed.text
    assert parse("o.py", Language.PYTHON, renamed.text).error_count == 0


# --- the registry -----------------------------------------------------------------------------


def test_the_registry_returns_each_renamer_by_language() -> None:
    registry = default_registry()
    assert isinstance(registry.get(Language.PYTHON), PythonRenamer)
    assert isinstance(registry.get(Language.JAVASCRIPT), JavaScriptRenamer)
    assert isinstance(registry.get(Language.TYPESCRIPT), TypeScriptRenamer)
    assert isinstance(registry.get(Language.JAVA), JavaRenamer)
    assert isinstance(registry.get(Language.GO), GoRenamer)
    assert registry.languages() == (
        Language.PYTHON,
        Language.JAVASCRIPT,
        Language.TYPESCRIPT,
        Language.JAVA,
        Language.GO,
    )


def test_a_language_without_a_renamer_is_refused_by_name() -> None:
    with pytest.raises(UnsupportedLanguageError, match="kotlin"):
        default_registry().get(Language.KOTLIN)
    assert issubclass(UnsupportedLanguageError, PseudonymError)


def test_another_language_can_be_added_without_touching_the_module() -> None:
    class GoRenamer(BaseRenamer):
        language = Language.GO

    registry = RenamerRegistry()
    registry.register(GoRenamer())
    assert isinstance(registry.get(Language.GO), GoRenamer)


# --- fail closed ------------------------------------------------------------------------------


def test_a_file_with_syntax_errors_is_not_renamed() -> None:
    with pytest.raises(PseudonymError, match="syntax"):
        rename_text(Language.PYTHON, "def broken(:\n    pass\n")


def test_a_renamer_refuses_a_file_of_another_language() -> None:
    renamed = rename_text(Language.PYTHON, "x_value = 1\n")
    with pytest.raises(PseudonymError, match="language"):
        JavaScriptRenamer().plan(
            renamed.parsed,
            renamed.classification,
            PseudonymGenerator(SALT),
            allowlist=_allowlist(Language.PYTHON),
        )


def _allowlist(language: Language) -> PublicAllowlist:
    return PublicAllowlist.bundled(language)


def test_a_token_that_equals_a_name_in_clear_is_refused() -> None:
    with pytest.raises(PseudonymError, match="stays in clear"):
        rename_text(
            Language.PYTHON,
            "def settle(batch):\n    return fn_1(batch)\n",
            extra=("fn_1",),
        )


def test_nothing_is_shaped_at_level_l0() -> None:
    renamed = rename_text(Language.PYTHON, 'label = "a festival bonus"\n')
    with pytest.raises(PseudonymError, match="L0"):
        PythonRenamer().plan(
            renamed.parsed,
            renamed.classification,
            PseudonymGenerator(SALT),
            allowlist=_allowlist(Language.PYTHON),
            level=PrivacyLevel.L0,
        )


def test_two_rules_claiming_the_same_bytes_raise_and_name_both_reasons() -> None:
    renamed = rename_text(Language.PYTHON, 'label = "festival"\n')
    where = renamed.parsed.string_literals()[0].location
    stray = ClassificationDecision(
        name="festival",
        kind="variable",
        location=where,
        classification=IdentifierClass.INTERNAL,
        rule=Rule.DEFAULT_INTERNAL,
        notes=frozenset(),
    )
    forged = ClassificationResult(
        decisions=(*renamed.classification.decisions, stray),
        counts=ConservativeCounts(),
        allowlist_version=renamed.classification.allowlist_version,
        kept_dynamic=frozenset(),
    )
    with pytest.raises(PseudonymError) as caught:
        PythonRenamer().plan(
            renamed.parsed,
            forged,
            PseudonymGenerator(SALT),
            allowlist=_allowlist(Language.PYTHON),
        )
    assert "identifier" in str(caught.value)
    assert "literal" in str(caught.value)


def test_a_decision_that_does_not_sit_on_its_name_is_refused() -> None:
    renamed = rename_text(Language.PYTHON, "alpha_value = 1\n")
    wrong = renamed.classification.decisions[0]._replace(name="omega_value")
    forged = renamed.classification._replace(decisions=(wrong,))
    with pytest.raises(PseudonymError, match="does not sit"):
        PythonRenamer().plan(
            renamed.parsed,
            forged,
            PseudonymGenerator(SALT),
            allowlist=_allowlist(Language.PYTHON),
        )


# --- tokens -----------------------------------------------------------------------------------


def test_one_name_gets_one_token_whatever_the_scope() -> None:
    renamed = run(fixture("py29_shadowing"))
    assert len(set(re.findall(r"param_\d+", renamed.text))) == 1


SMALL = "def alpha_fn(beta_arg):\n    gamma_var = beta_arg\n    return gamma_var\n"
SHAPE = r"def fn_1\(param_1\):\n    var_1 = param_1\n    return var_1\n"


def test_tokens_depend_on_the_salt_and_the_set_of_names_not_on_the_code_order() -> None:
    reordered = "gamma_var = 0\n\n\ndef alpha_fn(beta_arg):\n    return beta_arg\n"
    first = rename_text(Language.PYTHON, SMALL)
    assert re.fullmatch(SHAPE, first.text)
    other_salt = rename_text(
        Language.PYTHON, SMALL, generator=PseudonymGenerator(ScanSalt(bytes(reversed(range(32)))))
    )
    assert re.fullmatch(SHAPE, other_salt.text)  # one name of each kind: the numbers coincide
    again = rename_text(Language.PYTHON, reordered)
    assert re.search(r"var_1 = 0", again.text)
    assert re.search(r"def fn_1\(param_1\):", again.text)
