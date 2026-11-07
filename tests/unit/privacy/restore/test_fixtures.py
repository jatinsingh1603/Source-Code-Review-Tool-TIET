"""The recorded verdict fixtures of E10-02, run through the engine with a real vault.

Every case in ``tests/fixtures/restore/cases.json`` states what the restored verdict must hold. The
security half checks that no log event and no exception message carries an original of the
fixture mapping, over the whole set.
"""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from structlog.testing import capture_logs

from codekavach.core.models.enums import ContextKind
from codekavach.core.models.ids import CandidateId
from codekavach.core.models.verdict import ContextRequest
from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.restore.engine import RestoreEngine
from codekavach.privacy.restore.errors import RestoreError
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.store import Vault
from tests.support.factories import make_payload, make_slice, make_verdict

pytestmark = pytest.mark.privacy

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "restore"
KEY = SecretBytes(b"\x3d" * 32)
CASES: list[dict[str, Any]] = json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8"))[
    "cases"
]
MAPPING: dict[str, Any] = json.loads((FIXTURES / "mapping.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def vault(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Vault]:
    path = tmp_path_factory.mktemp("restore-fixtures") / "vault" / "vault.db"
    with Vault(path, KeySource.EPHEMERAL, KEY) as opened:
        entries = tuple(
            MappingEntry(pseudonym, original, PseudonymKind(kind), "fixture")
            for pseudonym, original, kind in MAPPING["entries"]
        )
        opened.put(MappingBatch(MAPPING["scan_id"], entries))
        yield opened


def originals() -> tuple[str, ...]:
    return tuple(original for _, original, _ in MAPPING["entries"])


def verdict_of(case: dict[str, Any]) -> Any:
    needs = tuple(
        ContextRequest(kind=ContextKind(item["kind"]), symbol=item["symbol"], reason=item["reason"])
        for item in case.get("needs_context", [])
    )
    return make_verdict(
        is_vulnerable=case.get("is_vulnerable", True),
        reasoning=case["reasoning"],
        impact=case.get("impact", ""),
        remediation=case.get("remediation", ""),
        needs_context=needs,
        cited_lines=tuple(case.get("cited_lines", ())),
    )


def test_the_fixture_set_is_large_enough_and_names_every_variant() -> None:
    assert len(CASES) >= 20
    ids = {case["id"] for case in CASES}
    for required in (
        "variant_backticks",
        "variant_case",
        "variant_call_suffix",
        "variant_possessive",
        "variant_plural",
        "variant_space_and_hyphen",
        "variant_markdown_emphasis",
        "near_miss_as_primary_assertion",
        "unknown_in_second_sentence",
        "secret_placeholder_plain",
        "personal_data_placeholder",
        "unmappable_cited_line",
        "primary_unanchored_then_anchored",
    ):
        assert required in ids


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_each_recorded_verdict_restores_as_recorded(vault: Vault, case: dict[str, Any]) -> None:
    expect = case["expect"]
    restored = RestoreEngine(vault, scan_id=MAPPING["scan_id"]).restore(
        verdict_of(case), make_payload(), make_slice()
    )
    assert restored.verdict_dropped is expect["verdict_dropped"]
    assert restored.reasoning == expect["reasoning"]
    assert restored.remediation == expect.get("remediation", "")
    assert len(restored.dropped_claims) == expect["dropped"]
    assert len(restored.cited_locations) == expect["locations"]
    assert restored.restore_stats.unknown_pseudonyms == sum(
        1 for claim in restored.dropped_claims if claim.reason == "unknown_pseudonym"
    )


def test_no_log_event_or_exception_message_holds_an_original(vault: Vault) -> None:
    engine = RestoreEngine(vault, scan_id=MAPPING["scan_id"])
    texts: list[str] = []
    with capture_logs() as events:
        for case in CASES:
            restored = engine.restore(verdict_of(case), make_payload(), make_slice())
            texts.append(repr(restored) + str(restored) + repr(restored.dropped_claims))
        for case in CASES:
            try:
                engine.restore(
                    verdict_of(case),
                    make_payload(candidate_id=_other_candidate()),
                    make_slice(),
                )
            except RestoreError as error:
                texts.append(str(error) + repr(error) + repr(error.args))
    shown = repr(events) + "".join(texts)
    for original in originals():
        assert original not in shown


def _other_candidate() -> CandidateId:
    return CandidateId("cand_01ARYZ6S410000000000000009")
