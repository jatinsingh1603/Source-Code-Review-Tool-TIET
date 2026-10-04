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


class PersistenceError(PipelineError):
    """The local database could not record a scan; artefacts and manifest are on disk."""

    def __init__(self, step: str, error_type: str) -> None:
        self.step = step
        self.error_type = error_type
        super().__init__(f"could not record the scan in the local database ({step}: {error_type})")


class GraphError(PipelineError):
    """The stages of a plan cannot be ordered."""


class DuplicateStageError(GraphError):
    """Two stages share a name."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"stage {name!r} appears more than once")


class DuplicateProviderError(GraphError):
    """A single-provider artefact key has more than one provider."""

    def __init__(self, key: str, stages: tuple[str, ...]) -> None:
        self.key = key
        self.stages = stages
        super().__init__(
            f"artefact {key!r} is provided by more than one stage: {', '.join(stages)}"
        )


class UnsatisfiedRequirementError(GraphError):
    """A stage requires a key that nothing provides."""

    def __init__(self, stage: str, key: str) -> None:
        self.stage = stage
        self.key = key
        super().__init__(f"stage {stage!r} requires {key!r}, which no stage in the plan provides")


class StageCycleError(GraphError):
    """Stages depend on each other in a cycle; ``cycle`` lists them in dependency order."""

    def __init__(self, cycle: tuple[str, ...], detail: str = "") -> None:
        self.cycle = cycle
        message = f"dependency cycle: {' -> '.join(cycle)}"
        super().__init__(f"{message} ({detail})" if detail else message)
