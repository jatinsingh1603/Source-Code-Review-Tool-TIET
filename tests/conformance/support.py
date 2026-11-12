"""Shared data of the provider conformance suite (E22-04).

The suite has three modes:

* **offline** (``test_offline.py``): every registered adapter kind builds a request for the
  bundled synthetic payload and parses a canned envelope of its wire format. No key, no network.
* **cassette** (``test_cassette.py``): responses recorded from real endpoints by
  ``tools/record_conformance.py`` against the bundled synthetic payload only are parsed again by
  the adapter that recorded them and by the replay adapter.
* **live** (``test_live.py``): runs only when ``CODEKAVACH_CONFORMANCE_LIVE=1`` and the provider's
  key reference resolves; skipped otherwise, never failed.
"""

import json
from pathlib import Path
from typing import Any, Final

from pydantic import SecretStr

from codekavach.config.models.llm import ProviderKind, ProviderSettings
from codekavach.core.models.verdict import LLMVerdict
from codekavach.llm.providers.registry import REGISTRY, load_provider_metadata

HERE: Final = Path(__file__).resolve().parent
CASSETTE_DIR: Final = HERE / "cassettes"
ALLOW_LIST: Final = HERE / "allowed_payloads.txt"
LIVE_VARIABLE: Final = "CODEKAVACH_CONFORMANCE_LIVE"
SYNTHETIC_KEY: Final = SecretStr("sk-conformance-SYNTHETIC0000")  # pragma: allowlist secret
AWS_ENV: Final = {
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # pragma: allowlist secret
}

# Extra settings a kind needs to be built; every other field comes from the defaults.
_EXTRA: Final[dict[str, dict[str, Any]]] = {
    "openai-compatible": {"base_url": "https://llm.example.org/v1"},
    "litellm": {"base_url": "https://llm.example.org"},
    "azure-openai": {"base_url": "https://synthetic.openai.azure.com"},
    "bedrock": {"region": "eu-west-1"},
    "vertex": {"options": {"project": "synthetic-project", "location": "europe-west4"}},
    "replay": {"cassette_dir": str(CASSETTE_DIR / "openai-responses")},
}


def registered_kinds() -> list[str]:
    """Every adapter kind of this build, sorted."""
    return sorted(REGISTRY)


def provider_settings(kind: str) -> ProviderSettings:
    """Settings that build the adapter of ``kind`` with no real endpoint or key."""
    data: dict[str, Any] = {"kind": kind, "model": "conformance-model", **_EXTRA.get(kind, {})}
    return ProviderSettings.model_validate(data)


def wire_format(kind: str) -> str:
    """The wire format of ``kind`` from the metadata table."""
    return load_provider_metadata()[kind].wire_format


def offline_kinds() -> frozenset[str]:
    """Kinds whose adapter answers in-process (no transport)."""
    return frozenset({ProviderKind.MOCK.value, ProviderKind.REPLAY.value})


def verdict_json(verdict: LLMVerdict) -> str:
    """The verdict as a model would write it."""
    return json.dumps(verdict.model_dump(mode="json", exclude={"schema_version"}))


def envelope(fmt: str, text: str) -> dict[str, Any]:
    """A successful vendor response of wire format ``fmt`` whose answer is ``text``."""
    document = json.loads(text)
    envelopes: dict[str, dict[str, Any]] = {
        "openai-responses": {
            "output": [
                {"type": "reasoning", "summary": []},
                {"type": "message", "content": [{"type": "output_text", "text": text}]},
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        },
        "openai-chat": {
            "choices": [{"message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        },
        "anthropic-messages": {
            "content": [{"type": "tool_use", "name": "verdict", "input": document}],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 10, "output_tokens": 5},
        },
        "gemini-generate-content": {
            "candidates": [{"content": {"parts": [{"text": text}]}}],
            "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5},
        },
        "bedrock-converse": {
            "output": {"message": {"content": [{"toolUse": {"input": document}}]}},
            "usage": {"inputTokens": 10, "outputTokens": 5},
        },
        "ollama-chat": {"message": {"role": "assistant", "content": text}},
    }
    return envelopes[fmt]


REFUSALS: Final[dict[str, dict[str, Any]]] = {
    "openai-responses": {
        "output": [{"type": "message", "content": [{"type": "refusal", "refusal": "no"}]}]
    },
    "openai-chat": {"choices": [{"message": {"refusal": "I can't help with that."}}]},
    "anthropic-messages": {"stop_reason": "refusal", "content": []},
    "gemini-generate-content": {"promptFeedback": {"blockReason": "SAFETY"}},
    "bedrock-converse": {
        "stopReason": "content_filtered",
        "output": {"message": {"content": []}},
    },
}


def allowed_payload_hashes() -> frozenset[str]:
    """The payload hashes a cassette may be recorded for (one per line, ``#`` comments)."""
    lines = ALLOW_LIST.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip() for line in lines if line.strip() and not line.startswith("#"))


def cassettes() -> list[Path]:
    """The recorded conformance cassettes, sorted.

    One directory per recording (``cassettes/<name>/``) holding ``<payload_hash>.json`` in the
    replay provider's format, so that the replay adapter can serve the directory as it is.
    """
    return sorted(CASSETTE_DIR.glob("*/*.json"))
