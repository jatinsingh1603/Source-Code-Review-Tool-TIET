"""Self-tests of the core model strategies (E02-26)."""

import hashlib
import itertools
import json
import os
import time
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis.strategies import SearchStrategy
from pydantic import BaseModel

import tests.conftest as root_conftest
from codekavach.core.models.base import KavachModel
from codekavach.core.models.candidate import Candidate
from codekavach.core.models.egress import EgressRecord
from codekavach.core.models.enums import PrivacyLevel
from codekavach.core.models.evidence import Evidence
from codekavach.core.models.finding import Finding
from codekavach.core.models.ids import CandidateId
from codekavach.core.models.location import CodeRegion, Location
from codekavach.core.models.paths import normalise_repo_path
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.scan import Project, Scan
from codekavach.core.models.slice import CodeSlice
from codekavach.core.models.summary import EgressTotals, ScanSummary
from codekavach.core.models.taint import TaintPath
from codekavach.core.models.text import SanitisedText, split_lines
from codekavach.core.models.verdict import LLMVerdict
from tests.support import strategies as s
from tests.support.perf import budget

EXAMPLES = 200
MODEL_STRATEGIES: dict[str, tuple[Callable[[], SearchStrategy[Any]], type[KavachModel]]] = {
    "regions": (s.regions, CodeRegion),
    "locations": (s.locations, Location),
    "taint_paths": (s.taint_paths, TaintPath),
    "candidates": (s.candidates, Candidate),
    "code_slices": (s.code_slices, CodeSlice),
    "sanitised_payloads": (s.sanitised_payloads, SanitisedPayload),
    "verdicts": (s.verdicts, LLMVerdict),
    "evidences": (s.evidences, Evidence),
    "findings": (s.findings, Finding),
    "egress_totals": (s.egress_totals, EgressTotals),
    "summaries": (s.summaries, ScanSummary),
    "projects": (s.projects, Project),
    "scans": (s.scans, Scan),
}


# Draws are cached per strategy object and count, so that the round-trip tests and the timing
# test share one set of 200 examples instead of drawing everything twice.
_DRAWN: dict[tuple[int, int], tuple[list[Any], float]] = {}


def collect(
    strategy: SearchStrategy[Any], count: int = EXAMPLES, *, fresh: bool = False
) -> list[Any]:
    """Draw ``count`` examples with every health check active, derandomized."""
    key = (id(strategy), count)
    if not fresh and key in _DRAWN:
        return _DRAWN[key][0]
    seen: list[Any] = []

    @settings(
        max_examples=count,
        derandomize=True,
        database=None,
        deadline=None,
        suppress_health_check=[],
    )
    @given(strategy)
    def run(value: Any) -> None:
        seen.append(value)

    started = time.perf_counter()
    run()
    _DRAWN[key] = (seen, time.perf_counter() - started)
    return seen


def _dump(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return json.loads(value.model_dump_json())
    if isinstance(value, list | tuple):
        return [_dump(item) for item in value]
    return value


def digest(values: list[Any]) -> str:
    return hashlib.sha256(json.dumps(_dump(values), sort_keys=True).encode()).hexdigest()


@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(MODEL_STRATEGIES))
def test_model_strategy_round_trips(name: str) -> None:
    factory, model = MODEL_STRATEGIES[name]
    examples = collect(factory())
    assert len(examples) >= EXAMPLES // 2
    for example in examples:
        assert isinstance(example, model)
        assert model.model_validate_json(example.model_dump_json()) == example


@pytest.mark.slow
def test_egress_chains_link_pairwise() -> None:
    for chain in collect(s.egress_chains()):
        assert 1 <= len(chain) <= 20
        previous: EgressRecord | None = None
        for record in chain:
            record.verify_link(previous)
            assert EgressRecord.model_validate_json(record.model_dump_json()) == record
            previous = record


@pytest.mark.slow
def test_status_histories_end_in_the_status() -> None:
    for status, history in collect(s.status_histories()):
        if history:
            assert history[-1].to_status is status
            for earlier, later in itertools.pairwise(history):
                assert later.from_status is earlier.to_status
                assert later.at >= earlier.at


@pytest.mark.slow
def test_findings_history_matches_status() -> None:
    for finding in collect(s.findings(), 100):
        if finding.status_history:
            assert finding.status_history[-1].to_status is finding.status


def test_repo_paths_are_fixed_points() -> None:
    for path in collect(s.repo_paths()):
        assert normalise_repo_path(path) == path
        assert 1 <= path.count("/") + 1 <= 6


def test_safe_payload_texts_always_build() -> None:
    for text in collect(s.safe_payload_texts()):
        payload = SanitisedPayload.build(
            candidate_id=CandidateId("cand_01ARYZ6S410000000000000001"),
            slice_id=None,
            text=SanitisedText(text),
            level=PrivacyLevel.L4,
        )
        assert payload.text.expose() == text


def test_raw_code_texts_cover_the_awkward_cases() -> None:
    texts = collect(s.raw_code_texts(), 500)
    assert any(s.FORM_FEED in text or s.LINE_SEPARATOR in text for text in texts)
    assert any("\r\n" in text for text in texts)
    assert any(not text.endswith("\n") for text in texts)
    assert any(len(line) >= s.LONG_LINE_LENGTH - 20 for t in texts for line in t.split("\n"))
    assert all(1 <= len(split_lines(text)) <= 120 for text in texts)


@pytest.mark.slow
@pytest.mark.parametrize("name", ["candidates", "findings", "egress_chains", "scans"])
def test_derandomized_draws_are_reproducible(name: str) -> None:
    factory = s.egress_chains if name == "egress_chains" else MODEL_STRATEGIES[name][0]
    assert digest(collect(factory(), 30, fresh=True)) == digest(collect(factory(), 30, fresh=True))


@pytest.mark.slow
def test_all_strategies_within_the_time_budget() -> None:
    strategies = [factory() for factory, _ in MODEL_STRATEGIES.values()]
    strategies += [s.egress_chains(), s.status_histories(), s.raw_code_texts()]
    strategies.append(s.safe_payload_texts())
    for strategy in strategies:
        collect(strategy)
    elapsed = sum(_DRAWN[(id(strategy), EXAMPLES)][1] for strategy in strategies)
    print(f"all strategies, {EXAMPLES} examples each: {elapsed:.1f} s")  # noqa: T201
    assert elapsed <= budget(60.0)


def test_unknown_profile_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(root_conftest.PROFILE_VARIABLE, "cii")
    with pytest.raises(pytest.UsageError, match="valid profiles: dev, ci, nightly"):
        root_conftest.pytest_configure(pytest.Config.__new__(pytest.Config))


def test_known_profiles_load(monkeypatch: pytest.MonkeyPatch) -> None:
    active = os.environ.get(root_conftest.PROFILE_VARIABLE, "dev")
    try:
        for name in root_conftest.PROFILES:
            monkeypatch.setenv(root_conftest.PROFILE_VARIABLE, name)
            root_conftest.pytest_configure(pytest.Config.__new__(pytest.Config))
            assert settings.default == settings.get_profile(name)
    finally:
        settings.load_profile(active)
