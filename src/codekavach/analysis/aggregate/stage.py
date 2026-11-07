"""``AggregateStage``: from ``candidates.raw`` to ``candidates`` (E13-01, ruling O-6).

Owning epic: E13. MVP; extended by E21, which adds engine correlation, baselines and suppressions on
top of this contract.

The minimal aggregate the pipeline needs so that the ``candidates.raw`` to ``candidates`` transition
resolves: exact-fingerprint deduplication and a stable order, nothing else. Parts are read in
part-name order and the first candidate with a fingerprint wins, so the result does not depend on
which analyser finished first. The order is ``(path, start_line, rule_id)``; the payload order, the
ledger sequence and the report's finding order all inherit it, which is what makes a second run of
the same scan comparable with the first. Category ``AGGREGATE`` aborts the scan on failure, because
nothing downstream can run without ``candidates``.
"""

from collections.abc import Iterable

from codekavach.core.models import Candidate
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.stage import StageCategory


def aggregate(candidates: Iterable[Candidate]) -> list[Candidate]:
    """``candidates`` without repeated fingerprints, ordered by path, start line and rule id."""
    unique: dict[str, Candidate] = {}
    for candidate in candidates:
        unique.setdefault(candidate.fingerprint, candidate)
    return sorted(
        unique.values(),
        key=lambda c: (c.primary_location.path, c.primary_location.start_line, c.rule_id),
    )


class AggregateStage:
    """Deduplicates and orders the raw candidates of every analyser."""

    name = "aggregate"
    version = "1"
    requires = frozenset({keys.CANDIDATES_RAW})
    provides = frozenset({keys.CANDIDATES})
    category = StageCategory.AGGREGATE

    def run(self, ctx: RunContext) -> None:
        """Publish ``candidates``."""
        parts = ctx.artefacts.get_parts(keys.CANDIDATES_RAW, Candidate)
        merged = aggregate(candidate for name in sorted(parts) for candidate in parts[name])
        ctx.artefacts.put(keys.CANDIDATES, merged)
