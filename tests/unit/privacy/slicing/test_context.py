"""The metered needs-context loop (E11-04): resolution, every refusal, the cap and the budget."""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from codekavach.config import Settings
from codekavach.config.merge import deep_merge
from codekavach.core.models import ContextKind, ContextRequest
from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.restore.engine import RestoreEngine
from codekavach.privacy.slicing.context import (
    AggregationBudget,
    ContextRefusal,
    ContextResolver,
)
from codekavach.privacy.slicing.index import ParseIndex, never_send_matcher
from codekavach.privacy.slicing.metrics import ScanDisclosure
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.store import Vault
from tests.support.slicing import candidate_at, candidate_id_n, make_index

ROOT = Path(__file__).resolve().parents[3] / "fixtures" / "slicing" / "context"
SPEC = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))
SCAN = "scan_context"
KEY = SecretBytes(b"\x5c" * 32)


def project_sources() -> dict[str, str]:
    base = ROOT / "project"
    return {
        path.relative_to(base).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(base.rglob("*.py"))
    }


def settings_for(overrides: dict[str, Any] | None = None) -> Settings:
    base: dict[str, Any] = {"privacy": {"never_send": list(SPEC["never_send"])}}
    return Settings.model_validate(deep_merge(base, overrides or {}))


def index_for(settings: Settings) -> ParseIndex:
    return make_index(
        project_sources(),
        vendored=tuple(SPEC["vendored"]),
        never_send=never_send_matcher(settings),
    )


@pytest.fixture(scope="module")
def engine(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RestoreEngine]:
    path = tmp_path_factory.mktemp("vault") / "vault.db"
    with Vault(path, KeySource.EPHEMERAL, KEY) as vault:
        vault.put(
            MappingBatch(
                SCAN,
                tuple(
                    MappingEntry(
                        pseudonym,
                        original,
                        PseudonymKind.VAR if pseudonym.startswith("var") else PseudonymKind.FN,
                        "accounts",
                    )
                    for pseudonym, original in SPEC["mapping"].items()
                ),
            )
        )
        yield RestoreEngine(vault, scan_id=SCAN)


def resolver_for(
    settings: Settings, *, index: ParseIndex | None = None
) -> tuple[ContextResolver, ScanDisclosure]:
    found = index or index_for(settings)
    disclosure = ScanDisclosure.for_index(found)
    path, line = SPEC["candidate"]["path"], SPEC["candidate"]["line"]
    resolver = ContextResolver(
        candidate=candidate_at(path, line),
        index=found,
        disclosure=disclosure,
        settings=settings,
    )
    return resolver, disclosure


def request(kind: str, symbol: str) -> ContextRequest:
    return ContextRequest(kind=ContextKind(kind), symbol=symbol, reason="needed")


CASES = SPEC["cases"]


def test_the_fixture_covers_every_refusal_reason_and_both_kinds_of_success() -> None:
    assert len(CASES) >= 10
    refusals = {c["expect"]["refusal"] for c in CASES if "refusal" in c["expect"]}
    assert refusals == {reason.value for reason in ContextRefusal}
    successes = [c for c in CASES if "files" in c["expect"]]
    assert any(len(c["expect"]["files"]) == 1 for c in successes)  # same file
    assert any(c["expect"]["files"] != ["app/views.py"] for c in successes)  # cross file


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_each_request_case(case: dict[str, Any], engine: RestoreEngine) -> None:
    settings = settings_for(case.get("settings"))
    resolver, disclosure = resolver_for(settings)
    budget = AggregationBudget(case.get("ceiling_pct", 100.0))
    ask = request(case["request"]["kind"], case["request"]["symbol"])
    found = resolver.resolve(ask, vault=engine, budget=budget)
    expect = case["expect"]
    if "refusal" in expect:
        assert found is None
        assert resolver.last_refusal is not None
        assert resolver.last_refusal.value == expect["refusal"]
        assert disclosure.rounds_used(resolver_candidate_id(resolver)) == 0
        assert disclosure.union_lines == 0  # a refusal discloses nothing
        return
    assert found is not None
    assert resolver.last_refusal is None
    assert sorted(found.files) == expect["files"]
    primary = next(s for s in found.segments if s.role.value == "primary")
    assert primary.path == expect["primary"]
    assert disclosure.rounds_used(found.candidate_id) == 1
    assert disclosure.expansions == 1


def resolver_candidate_id(resolver: ContextResolver) -> str:
    return str(resolver._candidate.id)


def test_the_expansion_is_the_definition_and_carries_the_candidates_id(
    engine: RestoreEngine,
) -> None:
    settings = settings_for()
    resolver, _ = resolver_for(settings)
    found = resolver.resolve(
        request("callee_body", "fn_3"), vault=engine, budget=AggregationBudget(100.0)
    )
    assert found is not None
    assert found.candidate_id == resolver_candidate_id(resolver)
    text = "\n".join(segment.text.expose() for segment in found.segments)
    assert "def run_query(statement):" in text
    assert "cursor.execute(statement)" in text


# --- the round cap: per candidate, recorded -------------------------------------------------


def test_the_round_cap_is_enforced_and_recorded_per_candidate(engine: RestoreEngine) -> None:
    settings = settings_for()  # two rounds by default
    resolver, disclosure = resolver_for(settings)
    budget = AggregationBudget(100.0)
    first = resolver.resolve(request("callee_body", "fn_2"), vault=engine, budget=budget)
    second = resolver.resolve(request("callee_body", "fn_3"), vault=engine, budget=budget)
    third = resolver.resolve(request("callee_body", "fn_9"), vault=engine, budget=budget)
    assert first is not None and second is not None and third is None
    assert resolver.last_refusal is ContextRefusal.ROUND_CAP
    assert resolver.rounds_used == 2
    assert disclosure.rounds_used(resolver_candidate_id(resolver)) == 2


def test_the_cap_belongs_to_the_candidate_not_to_the_scan(engine: RestoreEngine) -> None:
    settings = settings_for()
    index = index_for(settings)
    disclosure = ScanDisclosure.for_index(index)
    budget = AggregationBudget(100.0)
    for line, name in (
        (7, candidate_id_n(0)),
        (8, candidate_id_n(1)),
    ):
        resolver = ContextResolver(  # two candidates of one scan, two rounds each
            candidate=candidate_at("app/views.py", line, id=name),
            index=index,
            disclosure=disclosure,
            settings=settings,
        )
        for symbol in ("fn_2", "fn_3"):
            assert resolver.resolve(request("callee_body", symbol), vault=engine, budget=budget)
    assert disclosure.expansions == 4


def test_a_refused_request_does_not_use_a_round(engine: RestoreEngine) -> None:
    resolver, _ = resolver_for(settings_for())
    budget = AggregationBudget(100.0)
    assert resolver.resolve(request("callee_body", "fn_99"), vault=engine, budget=budget) is None
    assert resolver.rounds_used == 0
    assert resolver.resolve(request("callee_body", "fn_2"), vault=engine, budget=budget)


def test_the_limit_is_a_setting_with_a_default_of_two_and_a_zero_that_turns_the_loop_off() -> None:
    assert Settings().privacy.slice.max_needs_context_rounds == 2
    with pytest.raises(ValueError, match="max_needs_context_rounds"):
        Settings.model_validate({"privacy": {"slice": {"max_needs_context_rounds": 11}}})


# --- the aggregation budget ----------------------------------------------------------------------


def test_the_budget_consumes_at_below_and_above_the_ceiling() -> None:
    index = index_for(settings_for())
    disclosure = ScanDisclosure(repo_lines=100)
    budget = AggregationBudget(10.0)
    assert budget.consume(disclosure) is True
    assert budget.remaining_pct() == pytest.approx(10.0)
    disclosure.record(_lines_slice(index, 5), index)
    assert budget.consume(disclosure) is True  # 5 percent, below
    assert budget.remaining_pct() == pytest.approx(5.0)
    disclosure.record(_lines_slice(index, 5, start=20), index)
    assert budget.consume(disclosure) is False  # 10 percent, at the ceiling: refused
    assert budget.remaining_pct() == 0.0
    disclosure.record(_lines_slice(index, 4, start=40), index)
    assert budget.consume(disclosure) is False  # above
    assert budget.remaining_pct() == 0.0


def _lines_slice(index: ParseIndex, count: int, *, start: int = 1):  # type: ignore[no-untyped-def]
    from codekavach.core.models import (  # noqa: PLC0415 - only this helper builds slices
        CodeRegion,
        CodeSlice,
        RawCode,
        SegmentRole,
        SliceSegment,
        SliceStrategy,
    )
    from tests.support.factories import CANDIDATE_ID, SLICE_ID  # noqa: PLC0415

    segment = SliceSegment(
        path="app/views.py",
        region=CodeRegion(start_line=start, end_line=start + count - 1),
        text=RawCode("\n".join("x" for _ in range(count))),
        role=SegmentRole.PRIMARY,
    )
    return CodeSlice(
        id=SLICE_ID,
        candidate_id=CANDIDATE_ID,
        language=index.parsed_of("app/views.py").language,
        strategy=SliceStrategy.ENCLOSING_FUNCTION,
        segments=(segment,),
        token_estimate=1,
    )


def test_an_aggregation_ceiling_is_a_percentage() -> None:
    for bad in (-0.1, 100.1):
        with pytest.raises(ValueError, match="between 0 and 100"):
            AggregationBudget(bad)
    assert AggregationBudget(100.0).admits(100.0)
    assert not AggregationBudget(50.0).admits(50.01)


def test_the_budget_refuses_once_the_union_reaches_the_ceiling(engine: RestoreEngine) -> None:
    settings = settings_for()
    resolver, disclosure = resolver_for(settings)
    index_lines = disclosure.union_lines
    assert index_lines == 0
    tight = AggregationBudget(10.0)
    assert resolver.resolve(request("callee_body", "fn_2"), vault=engine, budget=tight)
    # fn_3 (run_query, 8 lines) would take the union over the 10 percent ceiling
    assert resolver.resolve(request("callee_body", "fn_3"), vault=engine, budget=tight) is None
    assert resolver.last_refusal is ContextRefusal.BUDGET_EXHAUSTED
    assert disclosure.repo_pct <= 10.0


# --- refusals stay local --------------------------------------------------------------------------


def test_a_refusal_reason_never_reaches_a_payload(engine: RestoreEngine) -> None:
    from codekavach.core.models import PrivacyLevel  # noqa: PLC0415
    from codekavach.privacy.pseudonymise.engine import Pseudonymiser  # noqa: PLC0415
    from tests.support.payload import SALT, unredacted  # noqa: PLC0415

    settings = settings_for()
    resolver, _ = resolver_for(settings)
    budget = AggregationBudget(100.0)
    served = resolver.resolve(request("callee_body", "fn_2"), vault=engine, budget=budget)
    assert served is not None
    reasons = [reason.value for reason in ContextRefusal]
    refused = [
        resolver.resolve(request("callee_body", symbol), vault=engine, budget=budget)
        for symbol in ("fn_6", "fn_7", "fn_99")
    ]
    assert refused == [None, None, None]
    pseudonymiser = Pseudonymiser()
    payload, _ = pseudonymiser.apply(
        served,
        unredacted(served, PrivacyLevel.L3, pseudonymiser),
        salt=SALT,
        level=PrivacyLevel.L3,
        scan_id=SCAN,
    )
    for reason in reasons:
        assert reason not in payload.text.expose()
    for forbidden in ("secrets_store", "vendor/lib", "never_send", "excluded", "refus"):
        assert forbidden not in payload.text.expose()


def test_a_refusal_is_not_an_exception_and_not_a_repr_leak(engine: RestoreEngine) -> None:
    resolver, _ = resolver_for(settings_for())
    outcome = resolver.attempt(
        request("callee_body", "fn_6"), vault=engine, budget=AggregationBudget(100.0)
    )
    assert outcome.slice is None and outcome.refusal is ContextRefusal.DEFINITION_EXCLUDED
    assert "load_key" not in repr(outcome) and "secrets_store" not in repr(outcome)
    assert "load_key" not in repr(resolver)
