"""The triage review task: is this reported finding a true positive?

Owning epic: E13. MVP; extended by E23, which adds the prompt library, the other tasks and
consensus.

**One finding per call.** A task renders exactly one payload. Batching several candidates into one
prompt would be cheaper and is rejected on purpose: with one candidate per call a poisoned file can
influence only its own verdict, so the blast radius of any injected text is one finding
(``docs/research/INSIGHTS.md`` insight 6). Do not add a batch method.

The prompt is the fixed rubric of ``prompts/triage/v2.md`` (preceded by the shared primer of
``prompts/common``) followed by the client material after a random delimiter. The delimiter is
generated per request (``render`` takes an optional one for tests), is long enough that code cannot
guess it, and must not occur in the material; if it does the render fails closed rather than
producing an ambiguous prompt. The rendering machinery lives in ``templated``.
"""

from typing import Final

from codekavach.llm.schema.triage import triage_schema
from codekavach.llm.tasks.templated import PromptBoundaryError, TemplatedTask, facts_block

TASK_NAME: Final = "triage"
PROMPT_VERSION: Final = "v2"
_facts_block = facts_block

__all__ = ["PROMPT_VERSION", "TASK_NAME", "PromptBoundaryError", "TriageTask"]


class TriageTask(TemplatedTask):
    """Renders the triage prompt and states the shape of the answer."""

    def __init__(self, version: str = PROMPT_VERSION) -> None:
        super().__init__(TASK_NAME, version)

    def output_schema(self) -> dict[str, object]:
        """The triage answer schema (the analysis field first)."""
        return triage_schema()
