"""Properties of restoration (E10-02), checked with hypothesis against a simple reference model.

The reference is deliberately naive: a sentence is kept when every token in it is known, and each
token of a kept sentence is replaced by its original. The engine must agree with it on random
mappings and random verdict texts, and must never leave a token in its output.
"""

from collections.abc import Iterator
from itertools import count

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.restore.engine import RestoreEngine, check_restored_text
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.store import Vault
from tests.support.factories import make_payload, make_slice, make_verdict

pytestmark = pytest.mark.privacy

KEY = SecretBytes(b"\x77" * 32)
KINDS = {"fn": PseudonymKind.FN, "var": PseudonymKind.VAR, "param": PseudonymKind.PARAM}
TOKENS = [f"{kind}_{number}" for kind in KINDS for number in range(1, 5)]
FILLER = ["the", "call", "reads", "value", "here", "then"]
ORIGINAL = st.from_regex(r"[a-z]{3,9}", fullmatch=True)
_SCAN_IDS = count()


@pytest.fixture(scope="module")
def vault(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Vault]:
    path = tmp_path_factory.mktemp("restore-properties") / "vault" / "vault.db"
    with Vault(path, KeySource.EPHEMERAL, KEY) as opened:
        yield opened


@st.composite
def mapping_and_sentences(draw: st.DrawFn) -> tuple[dict[str, str], list[list[str]]]:
    known = draw(st.dictionaries(st.sampled_from(TOKENS), ORIGINAL, max_size=len(TOKENS)))
    sentences = draw(
        st.lists(
            st.lists(
                st.one_of(st.sampled_from(FILLER), st.sampled_from(TOKENS)),
                min_size=1,
                max_size=6,
            ),
            min_size=1,
            max_size=5,
        )
    )
    return known, sentences


def reference(known: dict[str, str], sentences: list[list[str]]) -> tuple[str, int, bool]:
    """The expected restored prose, the number of unknown tokens, and whether the first dropped."""
    kept: list[str] = []
    unknown_total = 0
    first_dropped = False
    for index, words in enumerate(sentences):
        unknown = [word for word in words if word in TOKENS and word not in known]
        unknown_total += len(unknown)
        if index == 0:
            first_dropped = bool(unknown)
        if not unknown:
            kept.append(" ".join(known.get(word, word) for word in words) + ".")
    return " ".join(kept), unknown_total, first_dropped


@settings(
    max_examples=120,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(data=mapping_and_sentences())
def test_restoration_agrees_with_the_reference_model(
    vault: Vault, data: tuple[dict[str, str], list[list[str]]]
) -> None:
    known, sentences = data
    scan_id = f"scan_prop_{next(_SCAN_IDS)}"
    if known:
        vault.put(
            MappingBatch(
                scan_id,
                tuple(
                    MappingEntry(token, original, KINDS[token.split("_")[0]], "prop")
                    for token, original in known.items()
                ),
            )
        )
    text = ". ".join(" ".join(words) for words in sentences) + "."
    restored = RestoreEngine(vault, scan_id=scan_id).restore(
        make_verdict(reasoning=text, impact="", remediation="", cited_lines=()),
        make_payload(),
        make_slice(),
    )
    expected_text, unknown_total, first_dropped = reference(known, sentences)

    assert restored.verdict_dropped is first_dropped
    assert len(restored.dropped_claims) == unknown_total
    assert all(claim.reason == "unknown_pseudonym" for claim in restored.dropped_claims)
    if not first_dropped:
        assert restored.reasoning == expected_text
        check_restored_text(restored.reasoning)


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(data=mapping_and_sentences())
def test_restoration_is_deterministic_and_idempotent(
    vault: Vault, data: tuple[dict[str, str], list[list[str]]]
) -> None:
    known, sentences = data
    scan_id = f"scan_idem_{next(_SCAN_IDS)}"
    if known:
        vault.put(
            MappingBatch(
                scan_id,
                tuple(
                    MappingEntry(token, original, KINDS[token.split("_")[0]], "idem")
                    for token, original in known.items()
                ),
            )
        )
    text = ". ".join(" ".join(words) for words in sentences) + "."
    engine = RestoreEngine(vault, scan_id=scan_id)
    verdict = make_verdict(reasoning=text, impact="", remediation="", cited_lines=())
    first = engine.restore(verdict, make_payload(), make_slice())
    again = engine.restore(verdict, make_payload(), make_slice())
    assert first == again
    if not first.verdict_dropped:
        restored_again = engine.restore(
            make_verdict(reasoning=first.reasoning, impact="", remediation="", cited_lines=()),
            make_payload(),
            make_slice(),
        )
        assert restored_again.reasoning == first.reasoning
