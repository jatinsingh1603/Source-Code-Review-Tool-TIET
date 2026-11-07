"""The review-task protocol and the facts a prompt may state about a candidate.

Owning epic: E13. MVP; extended by E23, which adds the remaining tasks and the prompt library.

``CandidateFacts`` is the **only** candidate-derived material that may enter a prompt: the rule
identifier, the CWE numbers, the sink family, the slice strategy and the stub summary clauses. It
is built from ``SanitisedPayload.facts``, which the privacy layer fills, so this package never sees
a ``Candidate``. What it deliberately lacks is as important as what it has: no engine severity (it
would anchor the model, ``docs/research/INSIGHTS.md`` section 2.2 item 4), no verdict from an
earlier run, no file path (a disclosure), and no author, commit message or pull-request metadata (an
injection vector). A test renders prompts and asserts each of those is absent.
"""

from dataclasses import dataclass
from typing import Protocol

from codekavach.core.models.payload import SanitisedPayload


@dataclass(frozen=True, slots=True)
class CandidateFacts:
    """Facts about a candidate that are safe to state in a prompt."""

    rule_id: str
    cwe: tuple[int, ...]
    sink_family: str | None
    strategy: str
    stub_summaries: tuple[str, ...]

    @classmethod
    def from_payload(cls, payload: SanitisedPayload) -> "CandidateFacts":
        """The facts the payload carries, or an empty set for a payload that carries none."""
        facts = payload.facts
        if facts is None:
            return cls("unknown", (), None, "unknown", ())
        return cls(
            rule_id=facts.rule,
            cwe=tuple(facts.cwe),
            sink_family=facts.sink_family,
            strategy=facts.strategy,
            stub_summaries=tuple(facts.stub_summaries),
        )


class ReviewTask(Protocol):
    """One kind of question put to the model about one payload."""

    name: str
    prompt_version: str

    def render(self, payload: SanitisedPayload, candidate_facts: CandidateFacts) -> str:
        """The user-visible prompt: the fixed rubric, then the delimited client material."""
        ...

    def output_schema(self) -> dict[str, object]:
        """The JSON Schema of the answer, with the free-text analysis field first."""
        ...

    @property
    def prompt_hash(self) -> str:
        """SHA-256 of the template text, recorded in provenance with ``prompt_version``."""
        ...
