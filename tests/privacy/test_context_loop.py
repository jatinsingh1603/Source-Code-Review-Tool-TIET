"""The context loop goes through the whole privacy pipeline again (E11-04, I2, I3, I4).

A model that answers ``needs_context`` names a pseudonym. The expansion is a ``CodeSlice``, so it
is redacted, pseudonymised, validated and checked by the egress guard like the first slice, and
the ledger gets an entry of its own. The pseudonym of a symbol is the same in both rounds.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from codekavach.config import Settings
from codekavach.core.models import ContextKind, ContextRequest, PrivacyLevel
from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.egress import TokenCounts
from codekavach.core.models.enums import EgressOutcome
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.pipeline.context import ConsentDecision
from codekavach.privacy.egress.guard import EgressGuard, ScannerRegistry
from codekavach.privacy.egress.ledger import EgressDraft, open_writer
from codekavach.privacy.egress.models import EgressMeta, LeakHit
from codekavach.privacy.pseudonymise.engine import Pseudonymiser
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator
from codekavach.privacy.pseudonymise.mapping import MappingBatch
from codekavach.privacy.restore.engine import RestoreEngine
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.context import AggregationBudget, ContextResolver
from codekavach.privacy.slicing.index import never_send_matcher
from codekavach.privacy.slicing.metrics import ScanDisclosure
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.store import Vault
from tests.support.factories import FIXED_NOW, SCAN_ID
from tests.support.payload import SALT, unredacted
from tests.support.slicing import candidate_at, make_index

pytestmark = pytest.mark.privacy

ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "slicing" / "context" / "project"
SCAN = SCAN_ID
GRANTED = ConsentDecision(granted=True, source="flag")
SETTINGS = Settings.model_validate(
    {
        "llm": {
            "allow_remote": True,
            "providers": {
                "hosted": {
                    "kind": "openai-compatible",
                    "model": "m",
                    "base_url": "https://api.example.test/v1",
                }
            },
        },
        "privacy": {
            "never_send": ["secrets_store"],
            "egress": {"provider_host_allowlist": ["api.example.test"]},
        },
    }
)


class Clean:
    id = "clean"

    def scan(self, body: bytes, meta: EgressMeta) -> list[LeakHit]:
        return []


def sources() -> dict[str, str]:
    return {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(ROOT.rglob("*.py"))
    }


def pseudonym_of(batch: MappingBatch, original: str) -> str:
    matches = [entry.pseudonym for entry in batch.entries if entry.original == original]
    assert len(matches) == 1, (original, len(matches))
    return matches[0]


def prepare(
    slice_: Any, engine: Pseudonymiser, generator: PseudonymGenerator
) -> tuple[SanitisedPayload, MappingBatch]:
    return engine.apply(
        slice_,
        unredacted(slice_, PrivacyLevel.L3, engine),
        salt=SALT,
        level=PrivacyLevel.L3,
        scan_id=SCAN,
        generator=generator,
    )


def test_a_two_round_expansion_runs_the_whole_pipeline_and_leaves_two_ledger_entries(
    tmp_path: Path,
) -> None:
    index = make_index(
        sources(), vendored=("vendor/lib.py",), never_send=never_send_matcher(SETTINGS)
    )
    candidate = candidate_at("app/views.py", 15)
    first = EnclosingFunctionStrategy().build(candidate, index, budget=SliceBudget(2048))
    disclosure = ScanDisclosure.for_index(index)
    disclosure.record(first, index)
    engine = Pseudonymiser()
    generator = PseudonymGenerator(SALT)  # the scan's generator, shared by every round
    payload_one, batch_one = prepare(first, engine, generator)

    guard = EgressGuard(ScannerRegistry([Clean()]))
    ledger = open_writer(tmp_path / "state", key_source="ephemeral")
    seen: list[str] = []

    def egress(payload: SanitisedPayload) -> None:
        """Guard the payload and ledger it: what the stage does for every request."""
        body = json.dumps({"payload": payload.text.expose()}).encode("utf-8")
        meta = EgressMeta(
            provider="hosted", model="m", level=PrivacyLevel.L3, payload_hash=payload.payload_hash
        )
        decision = guard.evaluate(
            body, meta, settings=SETTINGS, consent=GRANTED, payload_text=payload.text.expose()
        )
        assert decision.allowed and decision.ticket is not None
        ledger.append(
            EgressDraft(
                timestamp=FIXED_NOW,
                scan_id=SCAN,
                candidate_id=str(candidate.id),
                provider="hosted",
                model="m",
                task="triage",
                level=PrivacyLevel.L3,
                payload_hash=payload.payload_hash,
                token_counts=TokenCounts(prompt=len(payload.text.expose())),
                outcome=EgressOutcome.SENT,
            ),
            payload.text,
        )
        seen.append(payload.payload_hash)

    egress(payload_one)

    with Vault(
        tmp_path / "vault" / "vault.db", KeySource.EPHEMERAL, SecretBytes(b"\x2b" * 32)
    ) as vault:
        vault.put(batch_one)
        resolver = ContextResolver(
            candidate=candidate, index=index, disclosure=disclosure, settings=SETTINGS
        )
        token = pseudonym_of(batch_one, "helper")
        ask = ContextRequest(kind=ContextKind.CALLEE_BODY, symbol=token, reason="needs the body")
        expansion = resolver.resolve(
            ask, vault=RestoreEngine(vault, scan_id=SCAN), budget=AggregationBudget(100.0)
        )
    assert expansion is not None

    payload_two, batch_two = prepare(expansion, engine, generator)
    # The expansion is a payload of its own, different from the first, with its own hash.
    assert payload_two.payload_hash != payload_one.payload_hash
    assert token in payload_two.text.expose()  # the symbol keeps the name the model asked about
    assert pseudonym_of(batch_two, "helper") == token
    # No original name of the expansion survives into what would leave.
    for original in ("helper", "account"):
        assert original not in payload_two.text.expose(), original

    egress(payload_two)

    records = ledger.records_for_candidate(str(candidate.id))
    assert [r.payload_hash for r in records] == seen
    assert len({r.payload_hash for r in records}) == 2
    assert sha256_hex(payload_two.text.expose()) == payload_two.payload_hash
    assert ledger.verify_chain().ok
    assert resolver.rounds_used == 1
    assert disclosure.expansions == 1


def test_the_same_symbol_has_the_same_pseudonym_in_every_round() -> None:
    index = make_index(sources())
    engine = Pseudonymiser()
    generator = PseudonymGenerator(SALT)
    strategy = EnclosingFunctionStrategy()
    first = strategy.build(candidate_at("app/views.py", 7), index, budget=SliceBudget(2048))
    other = strategy.build(candidate_at("app/views.py", 15), index, budget=SliceBudget(2048))
    _, batch_one = prepare(first, engine, generator)
    _, batch_two = prepare(other, engine, generator)
    shared = {entry.original for entry in batch_one.entries} & {
        entry.original for entry in batch_two.entries
    }
    assert shared  # the two slices have names in common
    for original in sorted(shared):
        assert pseudonym_of(batch_one, original) == pseudonym_of(batch_two, original)


def test_without_a_shared_generator_a_symbol_may_change_its_token_between_slices() -> None:
    """Why the engine takes the scan's generator: a fresh one numbers only one slice's names."""
    index = make_index(sources())
    engine = Pseudonymiser()
    strategy = EnclosingFunctionStrategy()
    first = strategy.build(candidate_at("app/views.py", 7), index, budget=SliceBudget(2048))
    other = strategy.build(candidate_at("app/views.py", 15), index, budget=SliceBudget(2048))
    batches = [
        engine.apply(
            item,
            unredacted(item, PrivacyLevel.L3, engine),
            salt=SALT,
            level=PrivacyLevel.L3,
            scan_id=SCAN,
        )[1]
        for item in (first, other)
    ]
    tokens = [{e.original: e.pseudonym for e in batch.entries} for batch in batches]
    common = set(tokens[0]) & set(tokens[1])
    assert common
    assert any(tokens[0][name] != tokens[1][name] for name in common)
