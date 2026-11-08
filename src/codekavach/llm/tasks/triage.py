"""The triage review task: is this reported finding a true positive?

Owning epic: E13. MVP; extended by E23, which adds the prompt library, the other tasks and
consensus.

**One finding per call.** A task renders exactly one payload. Batching several candidates into one
prompt would be cheaper and is rejected on purpose: with one candidate per call a poisoned file can
influence only its own verdict, so the blast radius of any injected text is one finding
(``docs/research/INSIGHTS.md`` insight 6). Do not add a batch method.

The prompt is the fixed rubric of ``prompts/triage/v1.md`` followed by the client material after a
random delimiter. The delimiter is generated per request (``render`` takes an optional one for
tests), is long enough that code cannot guess it, and must not occur in the material; if it does
the render fails closed rather than producing an ambiguous prompt.
"""

import json
import re
import secrets
from typing import Final

from codekavach.core.models.payload import SanitisedPayload
from codekavach.llm.prompts.loader import PromptTemplate, load_prompt
from codekavach.llm.schema.triage import triage_schema
from codekavach.llm.tasks.base import CandidateFacts

TASK_NAME: Final = "triage"
PROMPT_VERSION: Final = "v1"
DELIMITER_BYTES: Final = 12
_COMMENT: Final = re.compile(r"<!--.*?-->\s*", re.DOTALL)


class PromptBoundaryError(ValueError):
    """The delimiter occurs in the material it is meant to fence."""


def _facts_header(facts: CandidateFacts) -> str:
    """The four closed-vocabulary lines of the facts: rule, CWE, sink family and strategy."""
    return "\n".join(
        [
            f"rule: {facts.rule_id}",
            f"cwe: {', '.join(f'CWE-{number}' for number in facts.cwe) or 'none given'}",
            f"sink family: {facts.sink_family or 'none given'}",
            f"slice strategy: {facts.strategy}",
        ]
    )


def _facts_block(facts: CandidateFacts) -> str:
    lines = [_facts_header(facts)]
    if facts.stub_summaries:
        lines.append("callee summaries:")
        lines.extend(f"- {summary}" for summary in facts.stub_summaries)
    return "\n".join(lines)


class TriageTask:
    """Renders the triage prompt and states the shape of the answer."""

    name = TASK_NAME
    prompt_version = PROMPT_VERSION

    def __init__(self) -> None:
        self._template: PromptTemplate = load_prompt(TASK_NAME, PROMPT_VERSION)

    @property
    def prompt_hash(self) -> str:
        """SHA-256 of the template file."""
        return self._template.sha256

    def render(
        self,
        payload: SanitisedPayload,
        candidate_facts: CandidateFacts,
        *,
        delimiter: str | None = None,
    ) -> str:
        """The prompt for ``payload``; ``delimiter`` is random per call unless given.

        Raises:
            PromptBoundaryError: the delimiter occurs in the facts or the payload.
        """
        boundary = delimiter or f"=====CK-{secrets.token_hex(DELIMITER_BYTES)}====="
        facts = _facts_block(candidate_facts)
        text = payload.text.expose()
        if boundary in facts or boundary in text:
            raise PromptBoundaryError("the prompt delimiter occurs in the material")
        template = _COMMENT.sub("", self._template.text, count=1)
        # The payload is substituted last, in one pass, so its own braces are never re-read.
        parts = re.split(r"(\{\{BOUNDARY\}\}|\{\{FACTS\}\}|\{\{PAYLOAD\}\})", template)
        values = {"{{BOUNDARY}}": boundary, "{{FACTS}}": facts, "{{PAYLOAD}}": text}
        return "".join(values.get(part, part) for part in parts)

    def output_schema(self) -> dict[str, object]:
        """The triage answer schema (the analysis field first)."""
        return triage_schema()

    def static_text(self, payload: SanitisedPayload) -> tuple[str, ...]:
        """The text this task writes itself: the rubric pieces, the answer schema, the facts header.

        None of it derives from the client's code, so the egress guard need not scan it for client
        identifiers (see ``EgressGuard.evaluate``). The header is the rule, CWE, sink family and
        strategy lines, whose values ``PayloadFacts`` restricts to a closed vocabulary; the callee
        summaries are not included, so they are scanned like the code.
        """
        template = _COMMENT.sub("", self._template.text, count=1)
        pieces = re.split(r"\{\{BOUNDARY\}\}|\{\{FACTS\}\}|\{\{PAYLOAD\}\}", template)
        schema = json.dumps(triage_schema(), sort_keys=True, separators=(",", ":"))
        header = _facts_header(CandidateFacts.from_payload(payload))
        return (*(piece for piece in pieces if piece.strip()), schema, header)
