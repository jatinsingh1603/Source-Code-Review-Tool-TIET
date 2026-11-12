"""Cassette conformance: responses recorded from real endpoints parse again (E22-04).

Cassettes are written by ``tools/record_conformance.py`` for the bundled synthetic payload only.
Each one is parsed by an adapter of the wire format it was recorded from, and served by the
replay adapter from its directory.
"""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from codekavach.config.models.llm import ProviderSettings
from codekavach.core.models.verdict import LLMVerdict
from codekavach.llm.providers.base import RawResponse, usage_of
from codekavach.llm.providers.registry import REGISTRY
from codekavach.llm.providers.replay import ReplayProvider
from codekavach.llm.tasks.triage import TriageTask
from codekavach.privacy.egress.probe import probe_payload
from tests.conformance.support import (
    SYNTHETIC_KEY,
    allowed_payload_hashes,
    cassettes,
    provider_settings,
)

pytestmark = pytest.mark.conformance

ROOT = Path(__file__).resolve().parents[2]
CASSETTES = cassettes()
REQUIRED_WIRE_FORMATS = {"openai-responses"}


def _tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "record_conformance", ROOT / "tools" / "record_conformance.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("record_conformance", module)
    spec.loader.exec_module(module)
    return module


def _load(path: Path) -> dict[str, object]:
    document: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
    return document


def test_the_required_wire_formats_have_a_cassette() -> None:
    recorded = {_load(path)["conformance"]["wire_format"] for path in CASSETTES}  # type: ignore[index]
    assert recorded >= REQUIRED_WIRE_FORMATS


@pytest.mark.parametrize("path", CASSETTES, ids=lambda path: path.parent.name)
def test_a_cassette_is_for_the_synthetic_payload_and_holds_no_credential(path: Path) -> None:
    cassette = _load(path)
    assert cassette["payload_hash"] == probe_payload().payload_hash
    assert cassette["payload_hash"] in allowed_payload_hashes()
    assert path.stem == cassette["payload_hash"]
    text = path.read_text(encoding="utf-8").lower()
    for forbidden in ("authorization", "bearer ", "x-api-key", "sk-", '"user": "u'):
        assert forbidden not in text
    meta = cassette["conformance"]
    assert isinstance(meta, dict) and meta["model"] and meta["recorded_at"]


@pytest.mark.parametrize("path", CASSETTES, ids=lambda path: path.parent.name)
def test_the_recording_adapter_parses_the_cassette(path: Path) -> None:
    cassette = _load(path)
    meta = cassette["conformance"]
    assert isinstance(meta, dict)
    kind = str(meta["kind"])
    settings = provider_settings(kind)
    if meta["wire_format"] == "openai-responses":
        settings = settings.model_copy(update={"options": {"wire_api": "responses"}})
    adapter = REGISTRY[kind].build("conformance", settings, SYNTHETIC_KEY)
    body = json.dumps(cassette["body"]).encode()
    verdict = adapter.parse(RawResponse(int(str(cassette["status"])), body))
    assert isinstance(verdict, LLMVerdict)
    assert verdict.reasoning
    assert usage_of(body).input_tokens > 0


@pytest.mark.parametrize("path", CASSETTES, ids=lambda path: path.parent.name)
def test_the_replay_adapter_serves_the_cassette_directory(path: Path) -> None:
    replay = ReplayProvider(
        "replay", ProviderSettings.model_validate({"kind": "replay"}), cassette_dir=path.parent
    )
    request = replay.prepare(TriageTask(), probe_payload())
    assert isinstance(replay.parse(replay.respond(request)), LLMVerdict)


def test_the_recorder_refuses_a_payload_not_on_the_allow_list() -> None:
    tool = _tool()
    with pytest.raises(tool.RecordError, match="not in"):
        tool.check_allowed("0" * 64, allowed_payload_hashes())
    tool.check_allowed(probe_payload().payload_hash, allowed_payload_hashes())


def test_the_recorder_scrubs_account_identifiers_and_refuses_credentials() -> None:
    tool = _tool()
    body = {
        "id": "resp_123",
        "user": "someone",
        "safety_identifier": "acct",
        "output": [{"type": "message", "content": [{"type": "output_text", "text": "{}"}]}],
    }
    document = tool.cassette_document(
        payload_hash="h",
        status=200,
        body=json.dumps(body).encode(),
        kind="openai",
        wire_format="openai-responses",
        model="m",
        host="example.org",
        prompt_version="v",
        recorded_at="2026-01-01",
    )
    assert document["body"]["id"] == "redacted" and document["body"]["user"] == "redacted"
    assert "headers" not in document
    leaked = {"echo": "Authorization: Bearer x"}
    with pytest.raises(tool.RecordError):
        tool.cassette_document(
            payload_hash="h",
            status=200,
            body=json.dumps(leaked).encode(),
            kind="openai",
            wire_format="openai-responses",
            model="m",
            host=None,
            prompt_version="v",
            recorded_at="2026-01-01",
        )


def test_the_recorder_is_refused_in_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    tool = _tool()
    monkeypatch.setenv("CI", "true")
    with pytest.raises(tool.RecordError, match="CI"):
        tool.record("agentrouter", "x", model=None, timeout=1.0)
