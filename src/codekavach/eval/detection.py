"""Detection experiment runner (#279).

Arms:

``engines-only``
    deterministic analysis, the LLM switched off (the baseline every other arm is compared with);
``L1`` .. ``L4``
    the full pipeline with the LLM review at that privacy level, on the chosen provider;
``llm-raw``
    *not run*: sending raw code to a model is allowed only on synthetic fixtures and bypasses the
    privacy layer by definition, which this harness does not do. It is listed as skipped so a
    results file says so instead of silently omitting the arm.

A finding the LLM reviewed and judged not vulnerable is dropped from the reported set of an LLM
arm, the way the report treats it.
"""

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codekavach.eval.datasets import Dataset, resolve_dataset
from codekavach.eval.export import write_detection_outputs
from codekavach.eval.matcher import match
from codekavach.eval.metrics import breakdowns, score_result, to_reported
from codekavach.eval.scanrun import ScanArtifacts, scan_dataset

ENGINES_ONLY = "engines-only"
LLM_RAW = "llm-raw"
DEFAULT_LEVELS = ("L1", "L2", "L3", "L4")
SCHEMA_VERSION = 1


@dataclass
class ArmResult:
    """Metrics of one arm."""

    arm: str
    level: str | None
    provider: str
    findings: int
    in_scope_findings: int
    out_of_scope: int
    duplicates: int
    on_controls: int
    overall: dict[str, Any]
    by_cwe: dict[str, Any] = field(default_factory=dict)
    by_family: dict[str, Any] = field(default_factory=dict)
    by_language: dict[str, Any] = field(default_factory=dict)
    missed: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    skipped_reason: str | None = None


def _kept(artifacts: ScanArtifacts) -> list[Any]:
    kept = []
    for finding in artifacts.findings:
        reviews = finding.provenance.llm_reviews
        if reviews and all(r.is_vulnerable is False for r in reviews):
            continue
        kept.append(finding)
    return kept


def evaluate_arm(
    dataset: Dataset, artifacts: ScanArtifacts, *, arm: str, window: int = 3
) -> ArmResult:
    """Match one scan's findings against the dataset's labels and score them."""
    reported = to_reported(_kept(artifacts))
    result = match(dataset.truth, reported, window=window)
    groups = breakdowns(result)
    return ArmResult(
        arm=arm,
        level=None if arm == ENGINES_ONLY else artifacts.level,
        provider=artifacts.provider if artifacts.llm_enabled else "none",
        findings=len(reported),
        in_scope_findings=len(result.matched) + len(result.false_positives) + result.duplicates,
        out_of_scope=result.out_of_scope,
        duplicates=result.duplicates,
        on_controls=len(result.on_controls),
        overall=score_result(result).to_dict(),
        by_cwe={k: v.to_dict() for k, v in groups["by_cwe"].items()},
        by_family={k: v.to_dict() for k, v in groups["by_family"].items()},
        by_language={k: v.to_dict() for k, v in groups["by_language"].items()},
        missed=[t.id for t in result.missed],
        duration_s=round(artifacts.duration_s, 2),
    )


def run_detection(
    dataset: str,
    levels: Sequence[str] = (),
    providers: Sequence[str] = (),
    out: str | None = None,
    limit: int | None = None,
    *,
    progress: Callable[[str], None] | None = None,
    engines_only: bool = True,
) -> dict[str, Any]:
    """Run the detection experiment and write the results directory.

    Returns a small summary (the same numbers as ``results.json``) for the CLI to print.
    """
    ds = resolve_dataset(dataset).limited(limit)
    chosen_levels = list(levels) or list(DEFAULT_LEVELS)
    chosen_providers = list(providers) or ["mock"]
    say = progress or (lambda _m: None)
    arms: list[ArmResult] = []
    if engines_only:
        say("arm engines-only")
        arms.append(
            evaluate_arm(
                ds,
                scan_dataset(ds, level="L4", llm=False, keep_payloads=False),
                arm=ENGINES_ONLY,
            )
        )
    for provider in chosen_providers:
        for level in chosen_levels:
            say(f"arm {provider} {level}")
            art = scan_dataset(ds, level=level, provider=provider, keep_payloads=False)
            arms.append(evaluate_arm(ds, art, arm=f"{provider}@{level}"))
    arms.append(
        ArmResult(
            LLM_RAW,
            None,
            "-",
            0,
            0,
            0,
            0,
            0,
            {},
            skipped_reason=(
                "raw code is never sent by this harness; run it by hand on synthetic fixtures only"
            ),
        )
    )
    results: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "detection",
        "dataset": {
            "name": ds.name,
            "layout": ds.layout,
            "synthetic": ds.synthetic,
            "vulnerabilities": len(ds.vulnerabilities),
            "controls": len(ds.controls),
        },
        "method": {
            "matcher": "same file, line window 3, same CWE family",
            "precision": "in-scope findings only; out-of-scope findings are counted separately",
            "bootstrap": "1000 resamples of tp/fp/fn units, seed 20260101, 95 percent",
        },
        "arms": [a.__dict__ for a in arms],
    }
    if out:
        directory = Path(out).expanduser()
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "results.json").write_text(
            json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        results["files"] = write_detection_outputs(results, directory)
    return results


def summarise(results: dict[str, Any], out: str | None) -> dict[str, Any]:
    """The compact view the CLI prints; the full numbers are in ``results.json``."""
    rows = []
    for arm in results["arms"]:
        o = arm.get("overall") or {}
        rows.append(
            {
                "arm": arm["arm"],
                "findings": arm["findings"],
                "tp": o.get("tp"),
                "fp": o.get("fp"),
                "fn": o.get("fn"),
                "precision": o.get("precision"),
                "recall": o.get("recall"),
                "f1": o.get("f1"),
                "note": arm.get("skipped_reason"),
            }
        )
    return {
        "dataset": results["dataset"]["name"],
        "arms": rows,
        "out": str(Path(out).expanduser()) if out else None,
        "files": results.get("files", []),
    }


def run_detection_eval(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Entry point of ``codekavach eval detection``: run, write, return the compact summary."""
    out = kwargs.get("out") if "out" in kwargs else (args[3] if len(args) > 3 else None)
    return summarise(run_detection(*args, **kwargs), out)
