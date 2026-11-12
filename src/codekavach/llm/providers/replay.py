r"""The replay provider: recorded responses keyed by payload hash, for continuous integration.

Owning epic: E13. MVP; extended by E22.

A cassette is a JSON file ``<payload_hash>.json`` in the cassette directory (by default
``fixtures/kavachbank/cassettes/``) holding ``{"payload_hash", "status", "body"}``, where ``body``
is the response in any envelope ``extract_content`` understands. ``respond`` returns it, and raises
``CassetteMissingError`` naming the payload hash when there is none.

**A miss never falls back.** A silent fallback to the mock would make a demo look as if it worked
with the wrong data, and would hide a continuous-integration failure. A miss after a change to the
pseudonymiser is the expected signal that payloads changed, and it is useful because it is loud.

**Recording** is for a maintainer who has a real response to keep. It needs
``CODEKAVACH_REPLAY_RECORD=1`` and is refused when ``CI`` is set, so a pipeline cannot rewrite the
cassettes it replays. The prepared request is built exactly as the mock builds it, so the guard
scans the same bytes in replay as in a live run.
"""

import json
import os
import re
from pathlib import Path
from typing import Final

from codekavach.config.models.llm import ProviderSettings
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.verdict import LLMVerdict
from codekavach.llm.providers.base import (
    PreparedRequest,
    ProviderCapabilities,
    ProviderError,
    RawResponse,
    StructuredMode,
    chat_body,
    parse_response,
)
from codekavach.llm.tasks.base import CandidateFacts, ReviewTask

URL: Final = "replay://local/v1/chat"
DEFAULT_CASSETTE_DIR: Final = Path("fixtures") / "kavachbank" / "cassettes"
RECORD_VARIABLE: Final = "CODEKAVACH_REPLAY_RECORD"
_HASH: Final = re.compile(r"^[0-9a-f]{64}$")
_TRUE: Final = frozenset({"1", "true", "yes", "on"})


class CassetteMissingError(ProviderError):
    """No recorded response exists for a payload hash; the message names the hash."""

    def __init__(self, payload_hash: str) -> None:
        super().__init__(f"cassette_missing {payload_hash}")
        self.payload_hash = payload_hash


class RecordRefusedError(ProviderError):
    """Recording was requested where it is not allowed."""


def _enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUE


class ReplayProvider:
    """A provider that answers from recorded cassettes only."""

    capabilities = ProviderCapabilities(
        structured_output=True,
        context_window=1_000_000,
        local=True,
        structured_modes=(StructuredMode.JSON_SCHEMA,),
    )

    def __init__(
        self,
        provider_id: str = "replay",
        settings: ProviderSettings | None = None,
        *,
        cassette_dir: Path | None = None,
    ) -> None:
        self.id = provider_id
        configured = settings.cassette_dir if settings is not None else None
        self._dir = cassette_dir or (Path(configured) if configured else DEFAULT_CASSETTE_DIR)
        self._model = (settings.model if settings and settings.model else None) or "replay-1"

    def prepare(self, task: ReviewTask, payload: SanitisedPayload) -> PreparedRequest:
        """The request for ``payload``, built as the mock builds it."""
        facts = CandidateFacts.from_payload(payload)
        body = chat_body(
            model=self._model,
            prompt=task.render(payload, facts),
            schema=task.output_schema(),
            temperature=0.0,
            max_tokens=1024,
        )
        return PreparedRequest(
            provider=self.id,
            model=self._model,
            method="POST",
            url=URL,
            headers={"content-type": "application/json"},
            body=body,
            payload_hash=payload.payload_hash,
            task=task.name,
            prompt_version=task.prompt_version,
            prompt_hash=task.prompt_hash,
            candidate_id=str(payload.candidate_id),
        )

    def _path(self, payload_hash: str, task: str = "triage") -> Path:
        """``<hash>.json`` for triage (the original cassettes), ``<hash>.<task>.json`` otherwise."""
        if not _HASH.fullmatch(payload_hash) or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", task):
            raise ProviderError("payload_hash_malformed")
        suffix = "" if task == "triage" else f".{task}"
        return self._dir / f"{payload_hash}{suffix}.json"

    def respond(self, request: PreparedRequest) -> RawResponse:
        """The recorded response for the request's payload hash.

        Raises:
            CassetteMissingError: there is no cassette for the hash; there is no fallback.
        """
        path = self._path(request.payload_hash, request.task)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            return RawResponse(
                status=int(document["status"]), body=json.dumps(document["body"]).encode("utf-8")
            )
        except FileNotFoundError:
            raise CassetteMissingError(request.payload_hash) from None
        except (KeyError, TypeError, ValueError):
            raise ProviderError("cassette_malformed") from None

    def record(self, payload_hash: str, raw: RawResponse, task: str = "triage") -> Path:
        """Write ``raw`` as the cassette for ``payload_hash``.

        Raises:
            RecordRefusedError: ``CODEKAVACH_REPLAY_RECORD`` is not set, or ``CI`` is.
        """
        if _enabled("CI"):
            raise RecordRefusedError("record_refused_in_ci")
        if not _enabled(RECORD_VARIABLE):
            raise RecordRefusedError("record_mode_not_enabled")
        path = self._path(payload_hash, task)
        path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "payload_hash": payload_hash,
            "status": raw.status,
            "body": json.loads(raw.body),
        }
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def parse(self, raw: RawResponse) -> LLMVerdict:
        """The verdict in ``raw``."""
        return parse_response(raw)
