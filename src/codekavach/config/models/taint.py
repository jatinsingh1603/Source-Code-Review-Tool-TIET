"""The ``[taint]`` section: limits of the taint engine's lowering (E17-01).

Owning epic: E17 (section conventions: E03); consumed by ``codekavach.analysis.taint``.

Every limit bounds one pathological-input risk of the intermediate representation: an access path
that grows without end, a generated function with hundreds of thousands of statements, a control
flow graph too large for the dataflow pass, and a lowering that does not return.
"""

from typing import Annotated

from pydantic import Field

from codekavach.config.models.base import (
    SectionModel,
    bounds,
    float_in_range,
    in_range,
    volatile,
)

MIN_TIMEOUT_SECONDS = 0.1
MAX_TIMEOUT_SECONDS = 300.0


class TaintSettings(SectionModel):
    """Resource limits and diagnostics of the taint engine."""

    max_access_path: Annotated[int, in_range(1, 16, "taint.max_access_path")] = Field(
        default=3,
        description="Longest attribute or index path tracked as one place; longer paths are cut.",
        json_schema_extra=bounds(1, 16),
    )
    max_function_nodes: Annotated[int, in_range(100, 5_000_000, "taint.max_function_nodes")] = (
        Field(
            default=20_000,
            description="Most intermediate nodes in one function; larger functions are skipped.",
            json_schema_extra=bounds(100, 5_000_000),
        )
    )
    max_blocks: Annotated[int, in_range(10, 1_000_000, "taint.max_blocks")] = Field(
        default=5_000,
        description="Largest number of basic blocks in one function; larger ones are skipped.",
        json_schema_extra=bounds(10, 1_000_000),
    )
    timeout_seconds: Annotated[
        float, float_in_range(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS, "taint.timeout_seconds")
    ] = Field(
        default=10.0,
        description="Time limit for lowering one file, in seconds.",
        json_schema_extra={
            **volatile(),
            **bounds(int(MIN_TIMEOUT_SECONDS), int(MAX_TIMEOUT_SECONDS)),
        },
    )
    max_path_steps: Annotated[int, in_range(4, 1_000, "taint.max_path_steps")] = Field(
        default=64,
        description="Most steps in one reported taint path; longer paths are trimmed.",
        json_schema_extra=bounds(4, 1_000),
    )
    max_paths_per_sink: Annotated[int, in_range(1, 1_000, "taint.max_paths_per_sink")] = Field(
        default=10,
        description="Most paths reported for one sink; the shortest are kept.",
        json_schema_extra=bounds(1, 1_000),
    )
    loop_iterations: Annotated[int, in_range(1, 20, "taint.loop_iterations")] = Field(
        default=3,
        description="Extra passes over a function with a loop before taint propagation stops.",
        json_schema_extra=bounds(1, 20),
    )
    explain: bool = Field(
        default=False,
        description="Record why each taint step was taken, for debugging a missed finding.",
    )
