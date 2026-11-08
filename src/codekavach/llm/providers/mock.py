"""The mock provider: a deterministic, schema-valid verdict with no network.

Owning epic: E13. MVP; extended by E22.

For tests and for the first demo pass. ``prepare`` builds a real request body, so the egress guard
scans exactly the bytes a hosted provider would send; ``respond`` computes the answer locally. The
answer is a pure function of the payload hash and the candidate's CWE, so a test can predict it:

* ``digest`` is the first 8 hex digits of the payload hash read as an integer;
* ``is_vulnerable`` is true unless ``digest % 4 == 0`` (three payloads in four);
* ``confidence`` is ``low``, ``medium`` or ``high`` for ``digest % 3`` equal to 0, 1 or 2;
* ``cwe`` is the candidate's CWE list from the payload's facts (empty if it has none);
* ``reasoning`` is one fixed sentence naming the first 12 digits of the payload hash;
* ``needs_context`` is empty, and ``impact`` and ``remediation`` are fixed sentences.

The request carries a ``metadata`` object with the CWE list, and ``respond`` reads the payload hash
from the request itself. The hash is not put into the body: a 64-digit hexadecimal string is what
the secret scanners look for, and the guard would rightly block a request that carried one.
"""

import json
from typing import Final

from codekavach.config.models.llm import ProviderSettings
from codekavach.core.models.enums import Confidence
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.verdict import LLMVerdict
from codekavach.llm.providers.base import (
    PreparedRequest,
    ProviderCapabilities,
    ProviderError,
    RawResponse,
    chat_body,
    parse_response,
)
from codekavach.llm.tasks.base import CandidateFacts, ReviewTask

URL: Final = "mock://local/v1/chat"
_CONFIDENCE: Final = (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)


def verdict_for(payload_hash: str, cwe: tuple[int, ...]) -> LLMVerdict:
    """The mock's answer for ``payload_hash`` and ``cwe`` (the documented mapping)."""
    digest = int(payload_hash[:8], 16)
    return LLMVerdict(
        is_vulnerable=digest % 4 != 0,
        confidence=_CONFIDENCE[digest % 3],
        cwe=cwe,
        reasoning=f"Mock analysis of payload {payload_hash[:12]}: the data flow was not executed.",
        impact="Mock impact statement.",
        remediation="Mock remediation: validate the input before it reaches the sink.",
    )


class MockProvider:
    """A provider that never leaves the process."""

    capabilities = ProviderCapabilities(
        structured_output=True, context_window=1_000_000, local=True
    )

    def __init__(self, provider_id: str = "mock", settings: ProviderSettings | None = None) -> None:
        self.id = provider_id
        self._model = (settings.model if settings and settings.model else None) or "mock-1"

    def prepare(self, task: ReviewTask, payload: SanitisedPayload) -> PreparedRequest:
        """The request for ``payload``; the body is what the guard scans."""
        facts = CandidateFacts.from_payload(payload)
        prompt = task.render(payload, facts)
        body = chat_body(
            model=self._model,
            prompt=prompt,
            schema=task.output_schema(),
            temperature=0.0,
            max_tokens=1024,
            extra={"metadata": {"cwe": list(facts.cwe)}},
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

    def respond(self, request: PreparedRequest) -> RawResponse:
        """The mock's answer to ``request``, computed from the metadata it carries."""
        try:
            metadata = json.loads(request.body)["metadata"]
            verdict = verdict_for(request.payload_hash, tuple(int(c) for c in metadata["cwe"]))
        except (KeyError, TypeError, ValueError):
            raise ProviderError("mock_request_malformed") from None
        body = json.dumps({"content": verdict.model_dump(mode="json", exclude={"schema_version"})})
        return RawResponse(status=200, body=body.encode("utf-8"))

    def parse(self, raw: RawResponse) -> LLMVerdict:
        """The verdict in ``raw``."""
        return parse_response(raw)
