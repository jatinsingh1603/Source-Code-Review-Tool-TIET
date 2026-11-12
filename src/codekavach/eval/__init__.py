"""Evaluation: detection harness, leakage harness, datasets, metrics and attacker models.

Owning epic: E36, E37. Normative layout: docs/ARCHITECTURE.md section 3.

``run_detection_eval`` and ``run_leakage_eval`` are the entry points of ``codekavach eval``.
They are imported lazily so that importing this package stays cheap.
"""

# ruff: noqa: PLC0415
from typing import Any


def run_detection_eval(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """See ``codekavach.eval.detection.run_detection_eval``."""
    from codekavach.eval.detection import run_detection_eval as run

    return run(*args, **kwargs)


def run_leakage_eval(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """See ``codekavach.eval.leakage.run_leakage_eval``."""
    from codekavach.eval.leakage import run_leakage_eval as run

    return run(*args, **kwargs)


__all__ = ["run_detection_eval", "run_leakage_eval"]
