"""Exceptions of the pipeline package.

Owning epic: E04.
"""


class PipelineError(Exception):
    """Base class of pipeline errors."""


class StageDeclarationError(PipelineError):
    """A stage's declaration violates the Stage protocol or its no-weakening rules."""

    def __init__(self, stage: str, problem: str) -> None:
        self.stage = stage
        self.problem = problem
        super().__init__(f"stage {stage!r}: {problem}")
