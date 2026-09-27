"""Taint paths: ordered steps from a source to a sink.

Owning epic: E02. Steps carry real paths, symbols and engine notes that often quote client
code, so both models are raw data under invariant I2 and are never sent to an LLM. Order is
execution order; adapters for engines that report sink-first traces reverse them. Repeated
locations (loops) are kept as reported.
"""

from collections.abc import Sequence
from typing import ClassVar, Self

from pydantic import Field, model_validator

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.enums import TaintRole
from codekavach.core.models.location import Location

MAX_NOTE_LENGTH = 500


class TaintStep(KavachModel):
    """One step of a taint path."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    location: Location
    role: TaintRole
    note: str | None = Field(default=None, max_length=MAX_NOTE_LENGTH)


class TaintPath(KavachModel):
    """Steps from a source to a sink; a sanitiser step does not make the path invalid."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    steps: tuple[TaintStep, ...] = Field(min_length=2)

    @model_validator(mode="after")
    def _check_structure(self) -> Self:
        roles = [step.role for step in self.steps]
        if roles[0] is not TaintRole.SOURCE:
            raise ValueError("a taint path must start with a source step")
        if roles[-1] is not TaintRole.SINK:
            raise ValueError("a taint path must end with a sink step")
        if TaintRole.SOURCE in roles[1:]:
            raise ValueError("only the first step of a taint path may be a source")
        if TaintRole.SINK in roles[:-1]:
            raise ValueError("only the last step of a taint path may be a sink")
        return self

    @property
    def source(self) -> TaintStep:
        """The first step."""
        return self.steps[0]

    @property
    def sink(self) -> TaintStep:
        """The last step."""
        return self.steps[-1]

    @property
    def is_sanitised(self) -> bool:
        """True when any step is a sanitiser; a hint for the reviewer, not a verdict."""
        return any(step.role is TaintRole.SANITISER for step in self.steps)

    @property
    def files(self) -> tuple[str, ...]:
        """Distinct paths in first-seen order."""
        return tuple(dict.fromkeys(step.location.path for step in self.steps))

    @property
    def is_interprocedural(self) -> bool:
        """True when the steps name more than one distinct symbol."""
        symbols = {step.location.symbol for step in self.steps} - {None}
        return len(symbols) > 1

    @property
    def is_cross_file(self) -> bool:
        """True when the steps touch more than one file."""
        return len(self.files) > 1

    def __len__(self) -> int:
        return len(self.steps)

    @classmethod
    def from_locations(cls, source: Location, sink: Location, via: Sequence[Location] = ()) -> Self:
        """Build a path whose intermediate locations are propagators."""
        steps = (
            TaintStep(location=source, role=TaintRole.SOURCE),
            *(TaintStep(location=loc, role=TaintRole.PROPAGATOR) for loc in via),
            TaintStep(location=sink, role=TaintRole.SINK),
        )
        return cls(steps=steps)
