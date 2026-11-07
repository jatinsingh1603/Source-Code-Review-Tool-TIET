"""The matcher runtime: candidate shape, fingerprints, determinism and the registry (E13-01)."""

import textwrap

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.analysis.rules.base import CandidateGenerator, GeneratorRegistry
from codekavach.analysis.rules.builtin import BUILTIN_MATCHERS, default_registry
from codekavach.analysis.rules.engine import ENGINE, NodeMatcher, run_matchers
from codekavach.analysis.rules.matchers.sql_injection import SqlInjectionMatcher
from codekavach.core.models import Candidate, CandidateKind, Language, Severity
from codekavach.parsing import parse
from tests.support.rules import candidates_in

PY, JS = Language.PYTHON, Language.JAVASCRIPT
SAMPLE = textwrap.dedent(
    """
    import hashlib
    import pickle


    def hash_password(password):
        return hashlib.md5(password.encode()).hexdigest()


    def find(cur, account_id):
        cur.execute("SELECT * FROM accounts WHERE id = '%s'" % account_id)
        cur.execute("SELECT * FROM accounts WHERE id = '%s'" % account_id)


    def load(blob):
        return pickle.loads(blob)
    """
)


def fingerprints(code: str, language: Language = PY) -> list[str]:
    return [c.fingerprint for c in candidates_in(code, language)]


def test_a_candidate_carries_the_documented_fields() -> None:
    sql = next(c for c in candidates_in(SAMPLE, PY) if c.rule_id == "py.sql-injection")
    assert sql.engine == ENGINE == "codekavach.rules"
    assert sql.cwe == (89,)
    assert sql.engine_severity is Severity.HIGH
    assert sql.kind is CandidateKind.VULNERABILITY
    assert sql.language is PY
    assert sql.primary_location.path == "src/sample.py"
    assert sql.primary_location.symbol == "find"
    assert sql.fingerprint.startswith("ckfp1:")
    assert "accounts" not in sql.message  # the message states the class of weakness, not the code


def test_the_message_and_properties_never_quote_the_code() -> None:
    for candidate in candidates_in(SAMPLE, PY):
        text = candidate.message + " ".join(f"{k}={v}" for k, v in candidate.properties)
        assert not {"account_id", "blob", "hexdigest", "SELECT", "pickle"} & set(text.split())


def test_two_runs_give_the_same_fingerprints_and_order() -> None:
    assert fingerprints(SAMPLE) == fingerprints(SAMPLE)
    assert [c.primary_location.start_line for c in candidates_in(SAMPLE, PY)] == [7, 11, 12, 16]


def test_identical_statements_get_different_fingerprints() -> None:
    sql = [c for c in candidates_in(SAMPLE, PY) if c.rule_id == "py.sql-injection"]
    assert len(sql) == 2
    assert sql[0].fingerprint != sql[1].fingerprint


def test_a_whitespace_edit_of_an_unrelated_line_keeps_every_fingerprint() -> None:
    edited = SAMPLE.replace("import pickle", "import pickle  ").replace(
        "\n\n\ndef find", "\n\n\n\ndef find"
    )
    assert fingerprints(edited) == fingerprints(SAMPLE)


def test_a_line_inserted_above_moves_the_location_but_not_the_fingerprint() -> None:
    shifted = "# a new comment\n" + SAMPLE
    before, after = candidates_in(SAMPLE, PY), candidates_in(shifted, PY)
    assert [c.fingerprint for c in after] == [c.fingerprint for c in before]
    assert [c.primary_location.start_line for c in after] == [
        c.primary_location.start_line + 1 for c in before
    ]


def test_a_changed_statement_changes_its_fingerprint() -> None:
    edited = SAMPLE.replace("pickle.loads(blob)", "pickle.loads(blob, fix_imports=True)")
    changed = {c.fingerprint for c in candidates_in(edited, PY)} ^ {
        c.fingerprint for c in candidates_in(SAMPLE, PY)
    }
    assert len(changed) == 2


def test_the_same_code_in_another_file_has_another_fingerprint() -> None:
    first = candidates_in(SAMPLE, PY, path="a/one.py")
    second = candidates_in(SAMPLE, PY, path="a/two.py")
    assert not {c.fingerprint for c in first} & {c.fingerprint for c in second}


def test_candidates_validate_as_models_round_trip() -> None:
    for candidate in candidates_in(SAMPLE, PY):
        assert Candidate.model_validate(candidate.model_dump()) == candidate


def test_an_unsupported_language_or_missing_tree_yields_nothing() -> None:
    ts = parse("a.ts", Language.TYPESCRIPT, "const x = 1;")
    assert run_matchers(BUILTIN_MATCHERS, ts, None) == []


def test_a_matcher_alone_reports_only_its_own_rule() -> None:
    parsed = parse("a.py", PY, SAMPLE)
    only_sql = SqlInjectionMatcher().generate(parsed, None)
    assert {c.rule_id for c in only_sql} == {"py.sql-injection"}
    assert len(only_sql) == 2


def test_the_registry_looks_up_by_language_and_refuses_duplicates() -> None:
    registry = default_registry()
    assert len(registry) == len(BUILTIN_MATCHERS) == 9
    assert registry.languages == {PY, JS}
    assert registry.for_language(Language.GO) == ()
    assert set(registry.for_language(PY)) == set(BUILTIN_MATCHERS)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(BUILTIN_MATCHERS[0])


def test_every_builtin_matcher_satisfies_the_protocol() -> None:
    assert all(isinstance(m, CandidateGenerator) for m in BUILTIN_MATCHERS)
    assert isinstance(GeneratorRegistry(), GeneratorRegistry)


def _as_set(matchers: tuple[NodeMatcher, ...]) -> set[tuple[str, int]]:
    parsed = parse("src/sample.py", PY, SAMPLE)
    return {
        (c.rule_id, c.primary_location.start_line) for c in run_matchers(matchers, parsed, None)
    }


@settings(max_examples=40, deadline=None)
@given(st.permutations(BUILTIN_MATCHERS))
def test_the_result_does_not_depend_on_the_order_of_the_matchers(
    order: list[NodeMatcher],
) -> None:
    assert _as_set(tuple(order)) == _as_set(BUILTIN_MATCHERS)


PREDICATE_PROGRAMS = st.lists(
    st.sampled_from(
        [
            'cur.execute("SELECT 1 WHERE a = %s" % x)',
            'cur.execute("SELECT 1 WHERE a = %s", (x,))',
            "os.system('ls ' + x)",
            "subprocess.run(['ls', x])",
            "pickle.loads(x)",
            "json.loads(x)",
            "requests.get(x)",
            "requests.get('https://example.com')",
        ]
    ),
    min_size=1,
    max_size=6,
)


@settings(max_examples=60, deadline=None)
@given(PREDICATE_PROGRAMS)
def test_the_matchers_are_deterministic_over_generated_programs(statements: list[str]) -> None:
    code = "def handler(x):\n" + "\n".join(f"    {line}" for line in statements) + "\n"
    first = [(c.rule_id, c.fingerprint) for c in candidates_in(code, PY)]
    assert first == [(c.rule_id, c.fingerprint) for c in candidates_in(code, PY)]


@settings(max_examples=60, deadline=None)
@given(PREDICATE_PROGRAMS)
def test_each_statement_is_judged_on_its_own(statements: list[str]) -> None:
    together = "def handler(x):\n" + "\n".join(f"    {line}" for line in statements) + "\n"
    alone = sum(len(candidates_in(f"def handler(x):\n    {line}\n", PY)) for line in statements)
    assert len(candidates_in(together, PY)) == alone
