"""The replay cassettes reproduce the mock run, and go stale loudly (E13-03)."""

import json
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from codekavach.cli.demo_runner import CASSETTES, run_demo
from tests.support.cassettes import stale
from tests.support.kavachbank import FIXTURE_ROOT

# Each test runs the whole KavachBank demo (one to two minutes on a loaded CI runner).
pytestmark = [pytest.mark.slow, pytest.mark.timeout(420)]

COMMITTED = FIXTURE_ROOT / CASSETTES


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("a socket was opened")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    yield


def test_the_committed_cassettes_are_current() -> None:
    assert stale(FIXTURE_ROOT, COMMITTED) == [], "run: uv run python tools/gen_cassettes.py"


def test_a_stale_cassette_set_is_reported(tmp_path: Path) -> None:
    copy = tmp_path / "cassettes"
    copy.mkdir()
    files = sorted(COMMITTED.glob("*.json"))
    for path in files[1:]:
        (copy / path.name).write_bytes(path.read_bytes())
    document = json.loads(files[1].read_text("utf-8"))
    document["body"]["content"]["confidence"] = (
        "low" if document["body"]["content"]["confidence"] != "low" else "high"
    )
    (copy / files[1].name).write_text(json.dumps(document), encoding="utf-8")
    (copy / ("0" * 64 + ".json")).write_text("{}", encoding="utf-8")
    problems = stale(FIXTURE_ROOT, copy)
    assert f"missing {files[0].name}" in problems
    assert f"changed {files[1].name}" in problems
    assert f"unused {'0' * 64}.json" in problems


def test_replay_reproduces_the_mock_run(tmp_path: Path) -> None:
    mock = run_demo(str(FIXTURE_ROOT), tmp_path / "mock", provider="mock", send=True)
    replay = run_demo(str(FIXTURE_ROOT), tmp_path / "replay", provider="replay", send=True)
    assert (mock.provider == "mock" and replay.provider == "rec") or replay.provider == "replay"
    assert (replay.findings, replay.reviewed, replay.payloads) == (
        mock.findings,
        mock.reviewed,
        mock.payloads,
    )
    assert replay.reviewed > 0
    assert replay.zero_leak_passed and mock.zero_leak_passed


def test_a_missing_cassette_fails_the_review_instead_of_falling_back(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    report = run_demo(
        str(FIXTURE_ROOT), tmp_path / "out", provider="replay", send=True, cassette_dir=empty
    )
    assert report.reviewed == 0 and report.findings > 0  # deterministic findings remain
