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

import contextlib
import json
import os
from collections.abc import Iterable
from pathlib import Path

from codekavach.analysis.aggregate import baseline as baseline_file
from codekavach.analysis.aggregate import suppress
from codekavach.analysis.aggregate.correlate import correlate
from codekavach.analysis.aggregate.delta import compute_delta
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
        """Publish ``candidates``.

        Beyond deduplication: engines that agree are correlated into one candidate, suppressions
        (inline and ``.codekavach/suppressions.yaml``, both needing a justification) are applied,
        candidates already in the baseline (``.codekavach/baseline.json`` or
        ``CODEKAVACH_BASELINE``) are dropped as known, and what was dropped is written with its
        justification to ``aggregate-<scan id>.json`` in the scan's state directory. Set
        ``CODEKAVACH_BASELINE_UPDATE=1`` to record the current candidates as the new baseline.
        """
        parts = ctx.artefacts.get_parts(keys.CANDIDATES_RAW, Candidate)
        merged = aggregate(candidate for name in sorted(parts) for candidate in parts[name])
        raw_count = len(merged)
        merged = sorted(
            correlate(merged),
            key=lambda c: (c.primary_location.path, c.primary_location.start_line, c.rule_id),
        )
        correlated = raw_count - len(merged)
        config_dir = Path(ctx.project_root) / ".codekavach"
        rules = suppress.load_file_rules(config_dir / "suppressions.yaml")
        merged, applied, unjustified = suppress.apply_suppressions(merged, ctx.source_root, rules)
        baseline_path = Path(os.environ.get("CODEKAVACH_BASELINE") or config_dir / "baseline.json")
        known = baseline_file.load_baseline(baseline_path)
        delta = compute_delta(known, (c.fingerprint for c in merged)) if known else None
        if os.environ.get("CODEKAVACH_BASELINE_UPDATE") == "1":
            baseline_file.write_baseline(baseline_path, merged)
        elif known:
            merged = [c for c in merged if c.fingerprint not in known]
        ctx.artefacts.put(keys.CANDIDATES, merged)
        if ctx.state_dir is not None:
            report = {
                "correlated": correlated,
                "suppressed": [s.__dict__ for s in applied],
                "unjustified_markers": [{"path": p, "line": n} for p, n in unjustified],
                "baseline": str(baseline_path) if known else None,
                "delta": delta.as_dict() if delta else None,
                "fixed": list(delta.fixed) if delta else [],
            }
            with contextlib.suppress(OSError):
                (Path(ctx.state_dir) / f"aggregate-{ctx.scan_id}.json").write_text(
                    json.dumps(report, indent=2), encoding="utf-8"
                )
