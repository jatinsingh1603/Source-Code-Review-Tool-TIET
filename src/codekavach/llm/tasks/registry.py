"""The review tasks by name (E23-02)."""

from collections.abc import Callable
from typing import Final

from pydantic import BaseModel

from codekavach.llm.schema.tasks import (
    ClassifyAnswer,
    DiscoverAnswer,
    ExplainAnswer,
    RemediateAnswer,
    ReviewAnswer,
    SummariseAnswer,
)
from codekavach.llm.tasks.templated import TemplatedTask
from codekavach.llm.tasks.triage import TriageTask


def _simple(
    name: str, model: type[BaseModel], *, facts_only: bool = False
) -> Callable[[], TemplatedTask]:
    def build() -> TemplatedTask:
        task = TemplatedTask(name, "v1")
        task.answer_model = model
        task.material_is_facts = facts_only
        return task

    return build


TASKS: Final[dict[str, Callable[[], TemplatedTask]]] = {
    "triage": TriageTask,
    "explain": _simple("explain", ExplainAnswer),
    "remediate": _simple("remediate", RemediateAnswer),
    # The combined review (triage + explain + remediate in one request per candidate).
    "review": _simple("review", ReviewAnswer),
    "classify": _simple("classify", ClassifyAnswer),
    "discover": _simple("discover", DiscoverAnswer),
    "summarise": _simple("summarise", SummariseAnswer, facts_only=True),
}


def build_task(name: str) -> TemplatedTask:
    """A fresh task object for ``name``.

    Raises:
        KeyError: no such task.
    """
    return TASKS[name]()
