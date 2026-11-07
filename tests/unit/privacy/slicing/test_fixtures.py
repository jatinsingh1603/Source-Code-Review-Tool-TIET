"""Golden slices for the 28 fixture cases of E11-01.

Each folder of ``tests/fixtures/slicing`` holds ``src/`` (the repository), ``case.json`` (the
candidate's locations, the budget and which files are vendored, generated, minified or never sent)
and ``golden.txt``: the status, the segments and the assembled text of the slice, or the reason it
was refused. Rewrite goldens with ``CODEKAVACH_UPDATE_GOLDEN=1`` and read the diff.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from codekavach.config import Settings
from codekavach.core.models import CodeSlice, Language
from codekavach.parsing import parse
from codekavach.privacy.slicing.assemble import assemble, file_text, numbered_labels
from codekavach.privacy.slicing.base import SliceRefusal, outcome_for
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.index import never_send_matcher
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from tests.support.golden import assert_matches_golden
from tests.support.slicing import candidate_at, language_of, make_index

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "slicing"
CASES = sorted(path for path in FIXTURES.iterdir() if (path / "case.json").is_file())


def load(folder: Path) -> tuple[dict[str, Any], dict[str, str]]:
    meta = json.loads((folder / "case.json").read_text(encoding="utf-8"))
    sources = {
        path.relative_to(folder / "src").as_posix(): path.read_text(encoding="utf-8")
        for path in sorted((folder / "src").rglob("*"))
        if path.is_file()
    }
    return meta, sources


def run(folder: Path) -> tuple[CodeSlice | SliceRefusal, dict[str, str]]:
    meta, sources = load(folder)
    patterns = meta.get("never_send", [])
    never = never_send_matcher(Settings.model_validate({"privacy": {"never_send": patterns}}))
    index = make_index(
        sources,
        vendored=tuple(meta.get("vendored", ())),
        generated=tuple(meta.get("generated", ())),
        minified=tuple(meta.get("minified", ())),
        never_send=never if patterns else None,
    )
    first, *more = meta["locations"]
    candidate = candidate_at(first[0], first[1], *[(p, n) for p, n in more])
    outcome = outcome_for(
        EnclosingFunctionStrategy(), candidate, index, budget=SliceBudget(meta["budget"])
    )
    return outcome, sources


def render(outcome: CodeSlice | SliceRefusal) -> str:
    if isinstance(outcome, SliceRefusal):
        return f"refused: {outcome.reason}\n"
    labels = numbered_labels([segment.path for segment in outcome.segments])
    lines = [
        "status: slice",
        f"truncated: {outcome.truncated}",
        f"tokens: {outcome.token_estimate}",
        "segments:",
    ]
    for segment in outcome.segments:
        region = segment.region
        lines.append(
            f"  {segment.role.value} {labels(segment.path)} {region.start_line}-{region.end_line}"
        )
    lines.append("---")
    lines.append(
        assemble(outcome.segments, outcome.stubs, language=outcome.language, labels=labels)
    )
    return "\n".join(lines) + "\n"


def test_there_are_at_least_twenty_cases() -> None:
    assert len(CASES) >= 20
    languages = {language_of(next(iter(load(folder)[1]))) for folder in CASES}
    assert {Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT} <= languages


@pytest.mark.parametrize("folder", CASES, ids=lambda folder: folder.name)
def test_the_slice_matches_its_golden(folder: Path) -> None:
    outcome, _ = run(folder)
    assert_matches_golden(render(outcome), folder / "golden.txt")


@pytest.mark.parametrize("folder", CASES, ids=lambda folder: folder.name)
def test_every_slice_parses_in_its_language(folder: Path) -> None:
    outcome, sources = run(folder)
    if isinstance(outcome, SliceRefusal):
        pytest.skip("refused")
    for path in outcome.files:
        text = file_text([s for s in outcome.segments if s.path == path], outcome.language)
        assert parse(path, language_of(path), text).error_count == 0, path
        assert sources[path]  # the slice came from a real file


@pytest.mark.parametrize("folder", CASES, ids=lambda folder: folder.name)
def test_the_slice_is_byte_identical_on_a_second_run(folder: Path) -> None:
    first, _ = run(folder)
    second, _ = run(folder)
    assert render(first) == render(second)
    if isinstance(first, CodeSlice) and isinstance(second, CodeSlice):
        assert first.model_dump_json() == second.model_dump_json()
