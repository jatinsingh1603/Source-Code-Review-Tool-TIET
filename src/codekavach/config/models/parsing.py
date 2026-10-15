"""The ``[parsing]`` section: tree-sitter resource guards (E07-01).

Owning epic: E03 (section conventions); consumed by E07.

Every guard here bounds one pathological-input risk in ``codekavach.parsing``: a parse that
never returns, a source so large it dominates memory, and a tree so deep or wide that walking it
dominates CPU. The guards are precautionary, not a fix for a published vulnerability (see
``docs/research/INSIGHTS.md`` section 7).
"""

from typing import Annotated

from pydantic import Field

from codekavach.config.models.base import SectionModel, bounds, float_in_range, in_range

MIN_TIMEOUT_SECONDS = 0.1
MAX_TIMEOUT_SECONDS = 300.0


class ParsingSettings(SectionModel):
    """Resource guards applied to every file the parsing layer parses."""

    timeout_seconds: Annotated[
        float, float_in_range(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS, "parsing.timeout_seconds")
    ] = Field(
        default=5.0,
        description="Per-file tree-sitter parse timeout, in seconds.",
        json_schema_extra=bounds(int(MIN_TIMEOUT_SECONDS), int(MAX_TIMEOUT_SECONDS)),
    )
    max_source_bytes: Annotated[int, in_range(1, 100_000_000, "parsing.max_source_bytes")] = Field(
        default=2_000_000,
        description="Largest source file, in bytes, that is parsed.",
        json_schema_extra=bounds(1, 100_000_000),
    )
    max_node_count: Annotated[int, in_range(1, 50_000_000, "parsing.max_node_count")] = Field(
        default=2_000_000,
        description="Largest number of AST nodes a parsed file may have.",
        json_schema_extra=bounds(1, 50_000_000),
    )
