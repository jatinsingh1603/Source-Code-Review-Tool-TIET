"""Hypothesis properties of the identifier classifier (E09-02).

These are the invariants the issue requires to hold for any input: the classifier is total and
deterministic, a name on no allowlist is never public, an incomplete parse never defaults to
public, and the extra setting only adds public names. Each property would fail if the rule it
guards were broken.
"""

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from codekavach.core.models import Language
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.classify import (
    NAME_ONLY_RULES,
    IdentifierClass,
    Rule,
)
from tests.support.classification import classify_text

NAME = st.from_regex(r"[a-z][a-z0-9_]{2,14}", fullmatch=True)
# Names the bundled data and the language make public: a mix of them and of random names.
PUBLIC_POOL = ["request", "args", "get", "execute", "params", "path", "join", "fs", "str", "len"]
CASE_SETTINGS = settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _module(names: list[str]) -> str:
    """A small Python module with a definition, a parameter, a member and a call, from ``names``."""
    function, parameter, local, member, extra = names[:5]
    return (
        f"def {function}({parameter}, {extra}=1):\n"
        f"    {local} = {parameter}.{member}({extra})\n"
        f"    return {local}\n"
    )


def _unlisted(allowlist: PublicAllowlist, name: str) -> bool:
    """Whether no bundled rule and no extra name makes ``name`` public."""
    return not (
        allowlist.is_keyword_or_builtin(name)
        or allowlist.is_magic(name)
        or allowlist.is_extra(name)
        or allowlist.is_framework_contract(name)
        or allowlist.decorator_package(name) is not None
        or allowlist.is_well_known(name)
        or allowlist.is_listed_member(name)
        or allowlist.is_dynamic_code_call(name)
        or allowlist.is_attribute_call(name)
    )


@CASE_SETTINGS
@given(names=st.lists(NAME, min_size=5, max_size=5, unique=True))
def test_classification_is_total_and_deterministic(names: list[str]) -> None:
    text = _module(names)
    first = classify_text(Language.PYTHON, text)
    second = classify_text(Language.PYTHON, text)
    assert first.decisions == second.decisions
    assert first.counts == second.counts
    assert all(d.classification in IdentifierClass for d in first.decisions)
    assert first.decisions, "every symbol of the file receives a decision"


@CASE_SETTINGS
@given(names=st.lists(NAME, min_size=5, max_size=5, unique=True))
def test_a_name_on_no_allowlist_is_always_internal(names: list[str]) -> None:
    allowlist = PublicAllowlist.bundled(Language.PYTHON)
    assume(all(_unlisted(allowlist, name) for name in names))
    result = classify_text(Language.PYTHON, _module(names))
    assert all(d.classification is IdentifierClass.INTERNAL for d in result.decisions)
    assert result.kept_public_names() == ()


@CASE_SETTINGS
@given(
    names=st.lists(
        st.one_of(NAME, st.sampled_from(PUBLIC_POOL)), min_size=5, max_size=5, unique=True
    )
)
def test_an_incomplete_table_never_produces_a_public_default(names: list[str]) -> None:
    broken = _module(names) + "\ndef broken(:\n"
    result = classify_text(Language.PYTHON, broken)
    assert result.decisions
    for decision in result.decisions:
        if decision.classification is IdentifierClass.PUBLIC:
            assert decision.rule in NAME_ONLY_RULES or decision.rule is Rule.KEPT_DYNAMIC, (
                decision.name,
                decision.rule,
            )


@CASE_SETTINGS
@given(
    extra=st.lists(NAME, max_size=4, unique=True),
    names=st.lists(
        st.one_of(NAME, st.sampled_from(PUBLIC_POOL)), min_size=5, max_size=5, unique=True
    ),
)
def test_extra_names_only_add_public_decisions(extra: list[str], names: list[str]) -> None:
    text = _module(names)
    bundled = classify_text(Language.PYTHON, text)
    widened = classify_text(
        Language.PYTHON, text, allowlist=PublicAllowlist.bundled(Language.PYTHON, extra=extra)
    )
    assert len(bundled.decisions) == len(widened.decisions)
    for before, after in zip(bundled.decisions, widened.decisions, strict=True):
        if before.classification is IdentifierClass.PUBLIC:
            assert after.classification is IdentifierClass.PUBLIC
        if before.name in extra:
            assert after.classification is IdentifierClass.PUBLIC
    assert set(bundled.kept_public_names()) <= set(widened.kept_public_names())
