"""Property suite of E25-01: a project policy can only tighten.

For any document the loader accepts and any path, tier, language and rule, the decided level is at
least ``privacy.min_level``, ``privacy.level`` and the provider tier floor, and adding the document
never loses a ``never_send`` match. A document stating a level weaker than ``min_level`` is refused
with ``[CK-POL-006]`` (file, line and both levels), not clamped.
"""

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.config import Settings
from codekavach.core.models.enums import PrivacyLevel, TrustTier
from codekavach.privacy.policy.engine import PolicyEngine, load_document
from codekavach.privacy.policy.errors import PolicyError
from codekavach.privacy.policy.loader import load_policy

pytestmark = pytest.mark.privacy

LEVELS = st.sampled_from([PrivacyLevel.L1, PrivacyLevel.L2, PrivacyLevel.L3, PrivacyLevel.L4])
SEGMENT = st.sampled_from(["src", "app", "payments", "secrets", "lib", "x", "card"])
PATHS = st.lists(SEGMENT, min_size=1, max_size=5).map(lambda s: "/".join(s) + ".py")
PATTERNS = st.lists(
    st.sampled_from(["src", "app", "payments", "secrets", "**", "*"]), min_size=1, max_size=4
).map("/".join)


@st.composite
def documents(draw: st.DrawFn) -> str:
    out = ["policy_version = 1"]
    for _ in range(draw(st.integers(0, 4))):
        pattern = draw(PATTERNS)
        if draw(st.booleans()):
            out.append(f'[[path]]\npattern = "{pattern}"\nnever_send = true')
        else:
            out.append(f'[[path]]\npattern = "{pattern}"\nlevel = "{draw(LEVELS).value}"')
    out.extend(
        f'[[rule]]\nmatch = "CWE-*"\nlevel = "{draw(LEVELS).value}"'
        for _ in range(draw(st.integers(0, 2)))
    )
    out.extend(
        f'[[language]]\nlanguage = "python"\nlevel = "{draw(LEVELS).value}"'
        for _ in range(draw(st.integers(0, 2)))
    )
    return "\n".join(out) + "\n"


@given(text=documents(), path=PATHS, tier=st.sampled_from(list(TrustTier)), cwe=st.booleans())
def test_decision_is_never_weaker_than_floors(
    text: str, path: str, tier: TrustTier, cwe: bool
) -> None:
    settings = Settings()
    document, digest = load_document(text)
    engine = PolicyEngine(settings, document, digest)
    decision = engine.resolve(path, tier, language="python", cwes=("CWE-89",) if cwe else ())
    assert decision.level.at_least(settings.privacy.min_level)
    assert decision.level.at_least(settings.privacy.floor_for_tier(tier))
    assert decision.level.at_least(settings.privacy.level)
    bare = PolicyEngine(settings).resolve(path, tier, language="python")
    assert decision.level.at_least(bare.level)
    assert decision.never_send or not bare.never_send


@pytest.mark.parametrize("weak", [PrivacyLevel.L1, PrivacyLevel.L2])
def test_level_below_min_level_is_refused_not_clamped(weak: PrivacyLevel, tmp_path: Path) -> None:
    (tmp_path / "codekavach.policy.toml").write_text(
        f'policy_version = 1\n\n[[path]]\npattern = "src/**"\nlevel = "{weak.value}"\n',
        encoding="utf-8",
    )
    settings = Settings.model_validate({"privacy": {"min_level": "L3"}})
    with pytest.raises(PolicyError) as caught:
        load_policy(settings, project_root=tmp_path)
    assert caught.value.code == "CK-POL-006"
    message = str(caught.value)
    assert "codekavach.policy.toml:3" in message
    assert weak.value in message
    assert "L3" in message
