"""The restore engine (E10-02): token variants, placeholders, line mapping, dropping and checks."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from structlog.testing import capture_logs

from codekavach.core.models.enums import (
    ContextKind,
    PlaceholderKind,
    SegmentRole,
)
from codekavach.core.models.ids import CandidateId, SliceId
from codekavach.core.models.location import CodeRegion, Location
from codekavach.core.models.payload import LineMapEntry, SanitisedPayload
from codekavach.core.models.slice import CodeSlice, SliceSegment
from codekavach.core.models.text import RawCode, SanitisedText
from codekavach.core.models.verdict import ContextRequest, LLMVerdict
from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.restore.engine import RestoreEngine, check_restored_text
from codekavach.privacy.restore.errors import RestoreError
from codekavach.privacy.restore.models import DroppedClaim, RestoredVerdict
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.store import Vault
from tests.support.factories import (
    CANDIDATE_ID,
    make_payload,
    make_slice,
    make_verdict,
)

pytestmark = pytest.mark.privacy

SCAN = "scan_restore"
KEY = SecretBytes(b"\x6a" * 32)
ORIGINALS = ("accrue_premium_interest", "account_id", "invoice_totals", "AccountLedger")
MAPPING: tuple[tuple[str, str, PseudonymKind], ...] = (
    ("fn_1", "accrue_premium_interest", PseudonymKind.FN),
    ("param_1", "account_id", PseudonymKind.PARAM),
    ("var_3", "invoice_totals", PseudonymKind.VAR),
    ("cls_2", "AccountLedger", PseudonymKind.CLS),
)


@pytest.fixture
def vault(tmp_path: Path) -> Iterator[Vault]:
    with Vault(tmp_path / "vault" / "vault.db", KeySource.EPHEMERAL, KEY) as opened:
        opened.put(
            MappingBatch(
                SCAN,
                tuple(
                    MappingEntry(pseudonym, original, kind, "accounts")
                    for pseudonym, original, kind in MAPPING
                ),
            )
        )
        yield opened


def verdict(**fields: Any) -> LLMVerdict:
    defaults: dict[str, Any] = {"reasoning": "", "impact": "", "remediation": ""}
    return make_verdict(**{**defaults, **fields})


def restore(vault: Vault, value: LLMVerdict, **kwargs: Any) -> RestoredVerdict:
    payload = kwargs.pop("payload", None) or make_payload()
    slice_ = kwargs.pop("slice_", None) or make_slice()
    return RestoreEngine(vault, scan_id=SCAN).restore(value, payload, slice_)


def sentence_with(token: str) -> str:
    return f"The check reads {token} directly."


# The worked example of the E10-02 technical notes, as a 13-line segment of accounts.py.
WORKED_PATH = "services/api/accounts.py"


def worked_pair() -> tuple[SanitisedPayload, CodeSlice]:
    text = "\n".join(f"line {number}" for number in range(1, 14))
    payload = make_payload(
        text=SanitisedText(text),
        line_map=(
            LineMapEntry(
                payload_start_line=1, payload_end_line=13, segment_index=0, file_start_line=40
            ),
        ),
    )
    segment = SliceSegment(
        path=WORKED_PATH,
        region=CodeRegion(start_line=40, end_line=52),
        text=RawCode("\n".join(f"code {number}" for number in range(13))),
        role=SegmentRole.PRIMARY,
    )
    return payload, make_slice(segments=(segment,))


def two_segment_pair() -> tuple[SanitisedPayload, CodeSlice]:
    text = "\n".join(f"line {number}" for number in range(1, 11))
    payload = make_payload(
        text=SanitisedText(text),
        line_map=(
            LineMapEntry(
                payload_start_line=1, payload_end_line=3, segment_index=0, file_start_line=10
            ),
            LineMapEntry(
                payload_start_line=5, payload_end_line=7, segment_index=1, file_start_line=100
            ),
        ),
    )
    first = SliceSegment(
        path="a.py",
        region=CodeRegion(start_line=10, end_line=12),
        text=RawCode("a\nb\nc"),
        role=SegmentRole.PRIMARY,
    )
    second = SliceSegment(
        path="b.py",
        region=CodeRegion(start_line=100, end_line=102),
        text=RawCode("d\ne\nf"),
        role=SegmentRole.CONTEXT,
    )
    return payload, make_slice(segments=(first, second))


# --- the worked example (named regression) ---------------------------------------------------


def test_the_worked_example_restores_exactly(vault: Vault) -> None:
    payload, slice_ = worked_pair()
    value = verdict(
        reasoning=(
            "The function `Fn_1` interpolates `param_1` into an SQL string on line 6, and the "
            "value of `<SECRET:aws_access_key:1>` is unrelated. See also fn_9."
        ),
        cited_lines=(6,),
    )
    restored = RestoreEngine(vault, scan_id=SCAN).restore(value, payload, slice_)
    assert restored.verdict_dropped is False
    assert restored.reasoning == (
        "The function `accrue_premium_interest` interpolates `account_id` into an SQL string on "
        "line 6, and the value of the hardcoded AWS access key is unrelated."
    )
    assert restored.cited_locations == (Location(path=WORKED_PATH, start_line=45, end_line=45),)
    assert restored.dropped_claims == (
        DroppedClaim(section="reasoning", reason="unknown_pseudonym"),
    )
    assert restored.restore_stats.unknown_pseudonyms == 1
    assert restored.restore_stats.secret_placeholders == 1
    assert restored.restore_stats.pseudonyms == 2


# --- token grammar: accepted variants ---------------------------------------------------------

VARIANTS = [
    ("fn_1", "accrue_premium_interest"),
    ("Fn_1", "accrue_premium_interest"),
    ("FN_1", "accrue_premium_interest"),
    ("`fn_1`", "`accrue_premium_interest`"),
    ('"fn_1"', '"accrue_premium_interest"'),
    ("(fn_1)", "(accrue_premium_interest)"),
    ("fn_1()", "accrue_premium_interest()"),
    ("fn_1's", "accrue_premium_interest's"),
    ("param_1s", "account_ids"),
    ("fn 1", "accrue_premium_interest"),
    ("fn-1", "accrue_premium_interest"),
    ("**fn_1**", "**accrue_premium_interest**"),
    ("*fn_1*", "*accrue_premium_interest*"),
    ("_fn_1_", "_accrue_premium_interest_"),
]


@pytest.mark.parametrize(("variant", "expected"), VARIANTS)
def test_every_accepted_variant_is_substituted(vault: Vault, variant: str, expected: str) -> None:
    restored = restore(vault, verdict(reasoning=sentence_with(variant)))
    assert restored.reasoning == f"The check reads {expected} directly."
    assert restored.dropped_claims == ()


def test_the_worked_variants_keep_their_prose(vault: Vault) -> None:
    restored = restore(vault, verdict(reasoning="Uses `param_1` and `Fn_1`."))
    assert restored.reasoning == "Uses `account_id` and `accrue_premium_interest`."


# --- the rejected near match ------------------------------------------------------------------


@pytest.mark.parametrize("near", ["fn_11", "fn_01", "fn_9"])
def test_a_different_number_is_never_fuzzy_matched(vault: Vault, near: str) -> None:
    restored = restore(vault, verdict(reasoning=sentence_with(near)))
    assert restored.verdict_dropped is True
    assert restored.reasoning == ""
    assert restored.restore_stats.unknown_pseudonyms == 1


@pytest.mark.parametrize("not_a_token", ["fn_1x", "myfn_1", "fn_1st"])
def test_text_that_only_looks_like_a_token_is_left_alone(vault: Vault, not_a_token: str) -> None:
    restored = restore(vault, verdict(reasoning=sentence_with(not_a_token)))
    assert restored.reasoning == sentence_with(not_a_token)
    assert restored.dropped_claims == ()


def test_a_near_miss_drops_its_sentence_and_keeps_the_rest(vault: Vault) -> None:
    restored = restore(
        vault, verdict(reasoning="The primary point uses param_1. The call fn_11 is unrelated.")
    )
    assert restored.verdict_dropped is False
    assert restored.reasoning == "The primary point uses account_id."
    assert restored.dropped_claims == (
        DroppedClaim(section="reasoning", reason="unknown_pseudonym"),
    )


def test_an_unknown_primary_assertion_drops_the_whole_verdict(vault: Vault) -> None:
    restored = restore(vault, verdict(reasoning=sentence_with("fn_11"), cited_lines=(3,)))
    assert restored.verdict_dropped is True
    assert restored.reasoning == ""
    assert restored.cited_locations == ()
    assert restored.is_vulnerable is None


# --- placeholders -----------------------------------------------------------------------------


def test_a_secret_placeholder_becomes_a_subtype_phrase_never_a_value(vault: Vault) -> None:
    restored = restore(vault, verdict(reasoning="The key `<SECRET:aws_access_key:1>` is stored."))
    assert restored.reasoning == "The key the hardcoded AWS access key is stored."
    assert restored.restore_stats.secret_placeholders == 1


def test_a_personal_data_placeholder_becomes_a_subtype_phrase(vault: Vault) -> None:
    restored = restore(vault, verdict(reasoning="Mail goes to <PII:email:2> every day."))
    assert restored.reasoning == "Mail goes to the email every day."
    assert restored.restore_stats.pii_placeholders == 1


def test_a_term_placeholder_is_restored_through_the_vault(
    vault: Vault, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_lookup = vault.lookup_many

    def fake(pseudonyms: Any, *, scan_id: str | None = None) -> dict[str, str]:
        found = original_lookup(pseudonyms, scan_id=scan_id)
        return {**found, "<TERM:domain:1>": "billing.internal"}

    monkeypatch.setattr(vault, "lookup_many", fake)
    restored = restore(vault, verdict(reasoning="It calls <TERM:domain:1> directly."))
    assert restored.reasoning == "It calls billing.internal directly."
    assert restored.restore_stats.term_placeholders == 1


def test_an_unknown_term_placeholder_drops_its_sentence(vault: Vault) -> None:
    restored = restore(
        vault, verdict(reasoning="A kept point uses param_1. It calls <TERM:domain:9> here.")
    )
    assert restored.reasoning == "A kept point uses account_id."
    assert restored.restore_stats.unknown_pseudonyms == 1


def test_placeholder_phrases_are_plain_prose_without_brackets(vault: Vault) -> None:
    restored = restore(vault, verdict(reasoning="Found <SECRET:generic_credential:3> here."))
    assert "<" not in restored.reasoning and ">" not in restored.reasoning
    assert PlaceholderKind.SECRET.value == "SECRET"


# --- line mapping -----------------------------------------------------------------------------


def test_a_cited_line_maps_to_the_real_file_line(vault: Vault) -> None:
    restored = restore(vault, verdict(reasoning="Fine.", cited_lines=(3,)))
    assert restored.cited_locations == (
        Location(path=make_slice().files[0], start_line=88, end_line=88),
    )
    assert restored.restore_stats.unmappable_lines == 0


def test_lines_between_and_across_segments_map_through_the_index(vault: Vault) -> None:
    payload, slice_ = two_segment_pair()
    restored = RestoreEngine(vault, scan_id=SCAN).restore(
        verdict(reasoning="Fine.", cited_lines=(2, 6)), payload, slice_
    )
    assert restored.cited_locations == (
        Location(path="a.py", start_line=11, end_line=11),
        Location(path="b.py", start_line=101, end_line=101),
    )


def test_a_gap_line_and_out_of_range_lines_are_unmappable(vault: Vault) -> None:
    payload, slice_ = two_segment_pair()
    restored = RestoreEngine(vault, scan_id=SCAN).restore(
        verdict(reasoning="Fine.", cited_lines=(4, 9, 2)), payload, slice_
    )
    assert restored.cited_locations == (Location(path="a.py", start_line=11, end_line=11),)
    assert restored.restore_stats.unmappable_lines == 2
    assert (
        restored.dropped_claims.count(DroppedClaim(section="cited_lines", reason="unmappable_line"))
        == 2
    )


def test_an_unmappable_cited_line_drops_only_itself(vault: Vault) -> None:
    restored = restore(vault, verdict(reasoning="Fine.", cited_lines=(3, 99)))
    assert len(restored.cited_locations) == 1
    assert restored.dropped_claims == (
        DroppedClaim(section="cited_lines", reason="unmappable_line"),
    )


def test_a_payload_and_slice_of_different_candidates_are_refused(vault: Vault) -> None:
    other = CandidateId("cand_01ARYZ6S410000000000000009")
    with pytest.raises(RestoreError):
        restore(vault, verdict(reasoning="Fine."), payload=make_payload(candidate_id=other))


def test_a_payload_and_slice_with_different_slice_ids_are_refused(vault: Vault) -> None:
    other = SliceId("slice_01ARYZ6S410000000000000009")
    with pytest.raises(RestoreError):
        restore(vault, verdict(reasoning="Fine."), payload=make_payload(slice_id=other))


def test_a_line_that_the_payload_maps_outside_its_segment_is_unmappable(vault: Vault) -> None:
    """The payload says file line 40; the slice's segment covers lines 1 to 3: do not report 40."""
    payload, _ = worked_pair()
    segment = SliceSegment(
        path=WORKED_PATH,
        region=CodeRegion(start_line=1, end_line=3),
        text=RawCode("a" + chr(10) + "b" + chr(10) + "c"),
        role=SegmentRole.PRIMARY,
    )
    restored = RestoreEngine(vault, scan_id=SCAN).restore(
        verdict(reasoning="Fine.", cited_lines=(1,)), payload, make_slice(segments=(segment,))
    )
    assert restored.cited_locations == ()
    assert restored.restore_stats.unmappable_lines == 1


# --- claim-level dropping ---------------------------------------------------------------------


def test_an_unknown_remediation_sentence_drops_only_that_sentence(vault: Vault) -> None:
    restored = restore(
        vault,
        verdict(
            reasoning="Fine with param_1.",
            remediation="Bind param_1 safely. Retire fn_9 next.",
        ),
    )
    assert restored.remediation == "Bind account_id safely."
    assert restored.dropped_claims == (
        DroppedClaim(section="remediation", reason="unknown_pseudonym"),
    )


def test_a_needs_context_item_with_an_unknown_symbol_is_dropped(vault: Vault) -> None:
    value = verdict(
        is_vulnerable=None,
        reasoning="Need more.",
        needs_context=(
            ContextRequest(kind=ContextKind.CALLEE_BODY, symbol="fn_1", reason="see param_1"),
            ContextRequest(kind=ContextKind.CALLER, symbol="fn_77", reason="who calls it"),
        ),
    )
    restored = restore(vault, value)
    assert [item.symbol for item in restored.needs_context] == ["accrue_premium_interest"]
    assert restored.needs_context[0].reason == "see account_id"
    assert restored.dropped_claims == (
        DroppedClaim(section="needs_context", reason="unknown_pseudonym"),
    )


def test_an_undecided_verdict_with_no_anchored_context_is_dropped(vault: Vault) -> None:
    value = verdict(
        is_vulnerable=None,
        reasoning="Need more.",
        needs_context=(ContextRequest(kind=ContextKind.CALLER, symbol="fn_77", reason="x"),),
    )
    restored = restore(vault, value)
    assert restored.verdict_dropped is True
    assert restored.needs_context == ()


def test_a_restored_verdict_keeps_its_structured_fields(vault: Vault) -> None:
    restored = restore(vault, verdict(reasoning="Uses param_1.", cited_lines=(3,)))
    assert restored.is_vulnerable is True
    assert restored.cwe == (89,)
    assert restored.candidate_id == CANDIDATE_ID
    assert restored.verdict_dropped is False


# --- restored-output validation ---------------------------------------------------------------


@pytest.mark.parametrize(
    "leftover", ["calls fn_1 now", "uses <PII:email:2>", "a `var_3` inside", "<SECRET:jwt:1>"]
)
def test_a_planted_leftover_raises(leftover: str) -> None:
    with pytest.raises(RestoreError):
        check_restored_text(leftover)


def test_clean_restored_text_passes() -> None:
    check_restored_text("The function accrue_premium_interest reads account_id.")


# --- scope, resolution and batching -----------------------------------------------------------


def test_a_lookup_is_scoped_to_the_scan(vault: Vault) -> None:
    vault.put(
        MappingBatch("scan_other", (MappingEntry("fn_1", "other_name", PseudonymKind.FN, "x"),))
    )
    value = verdict(reasoning="Calls fn_1.")
    assert restore(vault, value).reasoning == "Calls accrue_premium_interest."
    other = RestoreEngine(vault, scan_id="scan_other").restore(value, make_payload(), make_slice())
    assert other.reasoning == "Calls other_name."


def test_resolve_symbol_maps_known_tokens_only(vault: Vault) -> None:
    engine = RestoreEngine(vault, scan_id=SCAN)
    assert engine.resolve_symbol("fn_1") == "accrue_premium_interest"
    assert engine.resolve_symbol(" Fn_1 ") == "accrue_premium_interest"
    assert engine.resolve_symbol("fn_12") is None
    assert engine.resolve_symbol("fn_1x") is None
    assert engine.resolve_symbol("the definition of fn_1") is None


def test_thirty_distinct_tokens_cost_one_lookup(
    vault: Vault, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []
    original = vault.lookup_many

    def counting(pseudonyms: Any, *, scan_id: str | None = None) -> dict[str, str]:
        calls.append(len(list(pseudonyms)))
        return original(pseudonyms, scan_id=scan_id)

    monkeypatch.setattr(vault, "lookup_many", counting)
    tokens = " ".join(f"var_{number}" for number in range(1, 31))
    restore(vault, verdict(reasoning=f"Many: {tokens}."))
    assert calls == [30]


def test_restoring_already_restored_text_changes_nothing(vault: Vault) -> None:
    once = restore(vault, verdict(reasoning="Uses param_1 in accrue_premium_interest.")).reasoning
    twice = restore(vault, verdict(reasoning=once)).reasoning
    assert twice == once == "Uses account_id in accrue_premium_interest."


# --- secrecy of messages, logs and representations --------------------------------------------


def test_no_log_line_or_exception_holds_an_original(vault: Vault) -> None:
    other = CandidateId("cand_01ARYZ6S410000000000000009")
    with capture_logs() as events:
        restored = restore(
            vault, verdict(reasoning="Uses fn_1 and param_1 and fn_9.", cited_lines=(3, 99))
        )
        with pytest.raises(RestoreError) as caught:
            restore(vault, verdict(reasoning="Fine."), payload=make_payload(candidate_id=other))
    text = repr(events) + repr(restored) + repr(restored.dropped_claims) + str(caught.value)
    text += repr(caught.value) + repr(caught.value.args)
    for secret in (*ORIGINALS, "param_1", "fn_9"):
        assert secret not in text


def test_representations_show_counts_not_text(vault: Vault) -> None:
    restored = restore(vault, verdict(reasoning="Uses fn_1 and param_1."))
    shown = repr(restored) + str(restored)
    for secret in ORIGINALS:
        assert secret not in shown
    assert repr(RestoreEngine(vault, scan_id=SCAN)) == "RestoreEngine(<vault>)"
