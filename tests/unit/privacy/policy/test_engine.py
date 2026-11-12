"""The policy engine: axes, strictest wins, never-send, path-free keys."""

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.config import Settings
from codekavach.core.models import PrivacyLevel
from codekavach.core.models.enums import TrustTier
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
