"""Review tasks: triage, discover, explain, remediate, classify and summarise.

Owning epic: E23. Normative layout: docs/ARCHITECTURE.md section 3.
"""

from codekavach.llm.tasks.registry import TASKS, build_task

__all__ = ["TASKS", "build_task"]
