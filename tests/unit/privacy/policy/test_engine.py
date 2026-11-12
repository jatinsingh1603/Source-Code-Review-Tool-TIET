"""The policy engine: axes, strictest wins, never-send, path-free keys."""

import threading
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.config import Settings
from codekavach.core.models import PrivacyLevel
from codekavach.core.models.enums import TrustTier
from codekavach.privacy.policy.decision import DecisionAxis
from codekavach.privacy.policy.engine import (
    RULE_KEY_PATTERN,
    PolicyEngine,
    PolicyError,
    load_document,
)

DOC = """
policy_version = 1
[[path]]
pattern = "src/payments/**"
level = "L4"
[[path]]
pattern = "**/secrets/**"
never_send = true
[[language]]
language = "java"
level = "L3"
[[rule]]
match = "CWE-89"
level = "L4"
[[classification]]
tag = "pci"
patterns = ["**/card/**"]
level = "L4"
[provider_tiers]
public = "L3"
"""


def engine(text: str = DOC) -> PolicyEngine:
    document, digest = load_document(text)
    return PolicyEngine(Settings(), document, digest)


def test_default_is_base_level() -> None:
    decision = PolicyEngine(Settings()).resolve("a/b.py", TrustTier.PUBLIC)
    assert decision.level >= PrivacyLevel.L3
    assert not decision.never_send


def test_path_axis_tightens() -> None:
    decision = engine().resolve("src/payments/x.py", TrustTier.PRIVATE)
    assert decision.level is PrivacyLevel.L4
    assert decision.rule_key == "path_rule:0"


def test_never_send_overrides_everything() -> None:
    decision = engine().resolve("app/secrets/key.py", TrustTier.LOCAL)
    assert decision.never_send
    assert decision.rule_key.startswith("never_send:")


def test_rule_and_language_and_classification_axes() -> None:
    eng = engine()
    assert eng.resolve("a.java", TrustTier.LOCAL, language="java").level >= PrivacyLevel.L3
    assert eng.resolve("a.py", TrustTier.LOCAL, cwes=("CWE-89",)).level is PrivacyLevel.L4
    decision = eng.resolve("svc/card/pay.py", TrustTier.LOCAL)
    assert decision.classifications == ("pci",)
    assert decision.level is PrivacyLevel.L4


def test_document_cannot_loosen_settings() -> None:
    loose = 'policy_version = 1\n[provider_tiers]\npublic = "L1"\n'
    decision = engine(loose).resolve("a.py", TrustTier.PUBLIC)
    assert decision.level >= PrivacyLevel.L3


def test_hash_is_content_hash() -> None:
    assert engine().policy_hash == engine().policy_hash
    assert engine().policy_hash != engine("policy_version = 1\n").policy_hash


@pytest.mark.parametrize(
    "text",
    [
        "policy_version = 2",
        "[[path]]\npattern='x'\n",
        "[[path]]\npattern='x'\nlevel='L2'\nnever_send=true\n",
        "bogus = 1",
        "not toml ===",
    ],
)
def test_invalid_documents_fail_with_code(text: str) -> None:
    with pytest.raises(PolicyError) as info:
        load_document(text)
    assert info.value.code.startswith("CK-POL-")


@given(
    path=st.text(alphabet="abc/._-", min_size=1, max_size=30),
    tier=st.sampled_from(list(TrustTier)),
)
def test_rule_key_is_always_path_free(path: str, tier: TrustTier) -> None:
    decision = engine().resolve(path.strip("/") or "a", tier)
    assert RULE_KEY_PATTERN.match(decision.rule_key)
    assert "/" not in decision.rule_key
    assert decision.level >= PrivacyLevel.L1


def test_shipped_example_is_valid() -> None:

    example = Path(__file__).parents[4] / "docs" / "examples" / "codekavach.policy.example.toml"
    document, digest = load_document(example)
    assert document.path and len(digest) == 64
    eng = PolicyEngine(Settings(), document, digest)
    # The expectations written in the example's comments.
    assert eng.resolve("services/payments/api.py", TrustTier.LOCAL).level is PrivacyLevel.L4
    assert eng.resolve("app/secrets/token.txt", TrustTier.LOCAL).never_send
    assert eng.resolve("Main.java", TrustTier.LOCAL, language="java").level >= PrivacyLevel.L3
    assert eng.resolve("a.py", TrustTier.LOCAL, cwes=("CWE-89",)).level >= PrivacyLevel.L3
    assert eng.resolve("web/cards/pay.py", TrustTier.LOCAL).classifications == ("pci",)
    assert eng.resolve("a.py", TrustTier.PUBLIC).level.at_least(PrivacyLevel.L3)


def test_commented_example_matches_its_expectations() -> None:
    example = Path(__file__).parents[4] / "docs" / "examples" / "codekavach.policy.toml"
    document, digest = load_document(example)
    eng = PolicyEngine(strict_settings(), document, digest)
    fees = eng.resolve("src/engine/fees/calc.py", TrustTier.PRIVATE)
    assert (fees.level, fees.winner.axis) == (PrivacyLevel.L4, DecisionAxis.PATH_RULE)
    assert eng.resolve("config/keys/prod.txt", TrustTier.LOCAL).never_send
    sql = eng.resolve("db/schema.sql", TrustTier.PRIVATE, language="sql")
    assert (sql.level, sql.winner.axis) == (PrivacyLevel.L4, DecisionAxis.LANGUAGE)
    assert eng.resolve("app/views.py", TrustTier.PRIVATE, cwes=("CWE-89",)).level is (
        PrivacyLevel.L3
    )
    pay = eng.resolve("src/payments/ledger.py", TrustTier.PRIVATE)
    assert pay.level is PrivacyLevel.L4
    assert pay.classifications == ("pci", "crown-jewel")
    public = eng.resolve("app/views.py", TrustTier.PUBLIC)
    assert (public.level, public.winner.axis) == (PrivacyLevel.L4, DecisionAxis.PROVIDER_TIER)
    for axis, count in eng.manifest_entry()["rules"].items():  # type: ignore[attr-defined]
        assert count >= 1, axis


# --- E25-01 scenario table and engine contract ---------------------------------------------

WORKED = """
policy_version = 1
[[path]]
pattern = "src/engine/fees/**"
level = "L4"
[[path]]
pattern = "config/keys/**"
never_send = true
[[classification]]
tag = "pci"
patterns = ["src/payments/**"]
level = "L3"
[[classification]]
tag = "crown-jewel"
patterns = ["src/payments/**"]
level = "L4"
[[language]]
language = "sql"
level = "L4"
[[rule]]
match = "ck.python.sqli"
level = "L3"
[[path]]
pattern = "src/**/legacy/**"
level = "L3"
"""


def strict_settings() -> Settings:
    return Settings.model_validate({"privacy": {"level": "L3", "min_level": "L3"}})


def worked() -> PolicyEngine:
    document, digest = load_document(WORKED)
    return PolicyEngine(strict_settings(), document, digest)


SCENARIOS = [
    # (path, tier, language, rule id, level, winning axis)
    (
        "src/payments/ledger.py",
        TrustTier.PUBLIC,
        "python",
        "ck.python.sqli",
        "L4",
        "classification",
    ),
    ("src/engine/fees/calc.py", TrustTier.PUBLIC, "python", None, "L4", "path_rule"),
    ("db/schema.sql", TrustTier.PUBLIC, "sql", None, "L4", "language"),
    ("app/views.py", TrustTier.PUBLIC, "python", "ck.python.sqli", "L3", "base"),
    ("app/views.py", TrustTier.LOCAL, "python", None, "L3", "base"),
    ("config/keys/prod.pem", TrustTier.LOCAL, None, None, "L3", "never_send"),
    ("src/a/legacy/b.py", TrustTier.PRIVATE, "python", None, "L3", "base"),
    ("README.md", TrustTier.PUBLIC, "unknown", None, "L3", "base"),
]


@pytest.mark.parametrize(("path", "tier", "language", "rule_id", "level", "axis"), SCENARIOS)
def test_scenario_table(  # noqa: PLR0917 - one row of the table
    path: str, tier: TrustTier, language: str | None, rule_id: str | None, level: str, axis: str
) -> None:
    decision = worked().resolve(path, tier, language=language, rule_id=rule_id)
    assert decision.level.value == level
    assert decision.winner.axis.value == axis
    assert sum(1 for c in decision.contributions if c is decision.winner) == 1


def test_worked_example_contributions() -> None:
    decision = worked().resolve(
        "src/payments/ledger.py", TrustTier.PUBLIC, language="python", rule_id="ck.python.sqli"
    )
    axes = [c.axis for c in decision.contributions]
    assert DecisionAxis.RULE in axes
    assert decision.classifications == ("pci", "crown-jewel")
    assert decision.rule_key == "classification:crown-jewel"


def test_ties_break_by_axis_order() -> None:
    decision = worked().resolve("app/x.py", TrustTier.PUBLIC, rule_id="ck.python.sqli")
    # base, provider_tier and rule all say L3: the first recorded (base) wins.
    assert decision.winner.axis is DecisionAxis.BASE


def test_never_send_below_a_trailing_double_star() -> None:
    eng = worked()
    for path in ("config/keys", "config/keys/a.pem", "config/keys/x/y/z.pem"):
        assert eng.resolve(path, TrustTier.LOCAL).never_send, path
    # a.pem would hit the default privacy.never_send ("*.pem"); a sibling directory is not covered
    assert not eng.resolve("config/keys2/a.txt", TrustTier.LOCAL).never_send


def test_overlapping_path_rule_never_weaker_than_floors() -> None:
    text = (
        '[[path]]\npattern = "src/**"\nlevel = "L4"\n[[path]]\npattern = "src/a/**"\nlevel = "L3"\n'
    )
    document, digest = load_document(text)
    decision = PolicyEngine(strict_settings(), document, digest).resolve(
        "src/a/b.py", TrustTier.PUBLIC
    )
    assert decision.level is PrivacyLevel.L4
    assert decision.level.at_least(strict_settings().privacy.floor_for_tier(TrustTier.PUBLIC))


def test_unknown_language_contributes_nothing() -> None:
    text = '[[language]]\nlanguage = "unknown"\nlevel = "L4"\n'
    document, digest = load_document(text)
    decision = PolicyEngine(Settings(), document, digest).resolve(
        "x.bin", TrustTier.PUBLIC, language="unknown"
    )
    assert all(c.axis is not DecisionAxis.LANGUAGE for c in decision.contributions)


def test_resolve_many_equals_repeated_resolve() -> None:
    eng = worked()
    paths = ["src/payments/a.py", "app/b.py", "config/keys/c", "src/engine/fees/d.py"]
    assert eng.resolve_many(paths, TrustTier.PUBLIC) == tuple(
        worked().resolve(p, TrustTier.PUBLIC) for p in paths
    )


def test_resolve_candidate_folds_strictest_and_never_send() -> None:
    eng = worked()
    folded = eng.resolve_candidate(["app/b.py", "src/payments/a.py"], TrustTier.PUBLIC)
    assert folded.level is PrivacyLevel.L4
    assert folded.paths == 2
    assert eng.resolve_candidate(["app/b.py", "config/keys/k"], TrustTier.PUBLIC).never_send


def test_concurrent_resolution_matches_serial() -> None:
    paths = [f"src/{d}/f{i}.py" for d in ("payments", "engine/fees", "app") for i in range(200)]
    serial = worked().resolve_many(paths, TrustTier.PUBLIC)
    eng = worked()
    results: dict[int, object] = {}

    def work(offset: int) -> None:
        for i in range(offset, len(paths), 4):
            results[i] = eng.resolve(paths[i], TrustTier.PUBLIC)

    threads = [threading.Thread(target=work, args=(k,)) for k in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert tuple(results[i] for i in range(len(paths))) == serial


def test_policy_hash_binds_settings_and_document() -> None:
    document, digest = load_document(WORKED)
    a = PolicyEngine(strict_settings(), document, digest)
    b = PolicyEngine(Settings(), document, digest)
    assert a.document_hash == b.document_hash == digest
    assert a.policy_hash != b.policy_hash
    assert len(a.policy_hash) == 64


def test_manifest_entry_has_counts_only() -> None:
    entry = worked().manifest_entry()
    text = repr(entry)
    for fragment in ("src/", "payments", "pci", "crown", "sqli", "config/keys"):
        assert fragment not in text
    assert entry["rules"] == {
        "path": 3,
        "language": 1,
        "rule": 1,
        "classification": 2,
        "provider_tiers": 0,
    }
