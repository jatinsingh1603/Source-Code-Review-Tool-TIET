"""Record and check the replay cassettes of the KavachBank fixture (E13-03).

A cassette is the mock provider's answer to one payload and task, keyed by the payload hash
(``<hash>.json`` for triage, ``<hash>.<task>.json`` for explain and remediate). The demo scans
under a fixed salt (``demo_runner.DEMO_SALT_HEX``), so the payloads, and their hashes, are the same
on every run; the recorder captures the payloads of one demo scan and writes the mock's answer for
each. ``stale`` compares what a fresh recording would write with what is committed, which is the
drift check: a change to the redactor, the pseudonymiser or the slicer changes a hash, and the
committed cassettes no longer answer the scan.

This module belongs to the test support tree and is not part of the shipped package.
"""

import json
import tempfile
from pathlib import Path

import pytest

from codekavach.cli.demo_runner import run_demo
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.pipeline import keys
from codekavach.llm.providers.mock import MockProvider
from codekavach.llm.providers.replay import RECORD_VARIABLE, ReplayProvider
from codekavach.llm.tasks import build_task
from codekavach.privacy.stages import PrivacyPrepareStage

RECORDED_TASKS = ("triage", "explain", "remediate")


def _payloads(fixture: Path) -> list[SanitisedPayload]:
    """The payloads of one demo scan; they are transient, so a spy on the stage keeps them."""
    captured: list[SanitisedPayload] = []
    original = PrivacyPrepareStage.run

    def spy(self: PrivacyPrepareStage, ctx: object) -> None:
        original(self, ctx)  # type: ignore[arg-type]
        found = ctx.artefacts.get_object(keys.PAYLOADS_SANITISED)  # type: ignore[attr-defined]
        assert isinstance(found, list)
        captured.extend(found)

    with pytest.MonkeyPatch.context() as patch, tempfile.TemporaryDirectory() as out:
        patch.setattr(PrivacyPrepareStage, "run", spy)
        run_demo(str(fixture), Path(out), send=False)
    return captured


def record_cassettes(fixture: Path, into: Path) -> list[Path]:
    """Write one cassette per payload of the demo scan into ``into``; the files written."""
    mock, replay = MockProvider(), ReplayProvider(cassette_dir=into)
    tasks = [build_task(name) for name in RECORDED_TASKS]
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(RECORD_VARIABLE, "1")
        patch.delenv("CI", raising=False)
        return [
            replay.record(
                payload.payload_hash, mock.respond(mock.prepare(task, payload)), task.name
            )
            for payload in _payloads(fixture)
            for task in tasks
        ]


def stale(fixture: Path, committed: Path) -> list[str]:
    """What differs between a fresh recording and ``committed``, one line per file."""
    with tempfile.TemporaryDirectory() as scratch:
        fresh = Path(scratch)
        record_cassettes(fixture, fresh)
        want = {path.name: json.loads(path.read_text("utf-8")) for path in fresh.glob("*.json")}
    have = {path.name: json.loads(path.read_text("utf-8")) for path in committed.glob("*.json")}
    problems = [f"missing {name}" for name in sorted(want.keys() - have.keys())]
    problems += [f"unused {name}" for name in sorted(have.keys() - want.keys())]
    problems += [
        f"changed {name}" for name in sorted(want.keys() & have.keys()) if want[name] != have[name]
    ]
    return problems
