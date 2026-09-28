"""What the orchestrator does after a stage fails, and which later stages may still start.

Owning epic: E04.

After a failure the stage's outputs are discarded first; then its ``failure_policy`` decides:
``ABORT_SCAN`` ends the run as failed; ``DEGRADE`` continues with every stage whose hard
requirements are still met; ``FAIL_CLOSED`` does the same and locks egress for the rest of the run,
so no privacy, LLM or uncategorised stage starts (I4, PLAN principle 7). Locking out privacy stages
too is deliberate: once a privacy stage has failed, nothing will be sent, so preparing more payloads
would only create material that is never used. Deterministic stages keep running, so the audit
still reports findings from deterministic evidence.
"""

import threading
from dataclasses import dataclass, field

from codekavach.core.pipeline.plan import RunPlan
from codekavach.core.pipeline.result import StageRun
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory, StageInfo
from codekavach.core.store.base import ArtefactStore

LOCKED_CATEGORIES: frozenset[StageCategory | None] = frozenset(
    {StageCategory.PRIVACY, StageCategory.LLM, None}
)


@dataclass
class RunState:
    """Failure bookkeeping of one ``Orchestrator.run`` call."""

    failed: dict[str, StageRun] = field(default_factory=dict)
    skipped: dict[str, StageRun] = field(default_factory=dict)
    egress_locked: bool = False
    lock_cause: str | None = None
    aborted: bool = False
    abort_cause: str | None = None
    abandoned: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


def decide_after_failure(info: StageInfo, state: RunState) -> None:
    """Apply the failed stage's policy to ``state`` (outputs are already discarded)."""
    with state.lock:
        if info.failure_policy is FailurePolicy.ABORT_SCAN and not state.aborted:
            state.aborted = True
            state.abort_cause = info.name
        elif info.failure_policy is FailurePolicy.FAIL_CLOSED and not state.egress_locked:
            state.egress_locked = True
            state.lock_cause = info.name


def _providers(plan: RunPlan, key: str, before: str) -> list[str]:
    names: list[str] = []
    for name in plan.order:
        if name == before:
            break
        if key in plan.infos[name].provides:
            names.append(name)
    return names


def skip_reason_for(
    info: StageInfo, store: ArtefactStore, state: RunState, plan: RunPlan
) -> tuple[str, str | None] | None:
    """Why ``info`` must not start, as ``(reason_code, blocked_by)``, or ``None``.

    Precedence: aborted, then egress locked, then a missing hard requirement.
    """
    with state.lock:
        if state.aborted:
            return "scan_aborted", state.abort_cause
        if state.egress_locked and info.category in LOCKED_CATEGORIES:
            return "egress_locked", state.lock_cause
        unavailable = {**state.failed, **state.skipped}
    for key in sorted(info.requires):
        if store.has(key):
            continue
        broken = [name for name in _providers(plan, key, info.name) if name in unavailable]
        if broken:
            return "dependency_failed", broken[-1]
        return "dependency_missing", None
    return None


def partial_inputs(info: StageInfo, state: RunState, plan: RunPlan) -> list[str]:
    """Hard requirements of ``info`` that are present although one of their providers failed."""
    with state.lock:
        failed = set(state.failed)
    return [
        key
        for key in sorted(info.requires)
        if any(name in failed for name in _providers(plan, key, info.name))
    ]
