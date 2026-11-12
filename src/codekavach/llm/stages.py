"""``LlmReviewStage``: from sanitised payloads to raw verdicts (E13-02).

Owning epic: E13. MVP; extended by E22 (hosted providers, budgets, caching) and E25 (context
rounds, consensus).

One candidate, one request. For each payload the stage renders the triage task, lets the provider
prepare the request, and hands it to the ``EgressSession``, which runs the guard, writes the ledger
and sends. The stage reads ``payloads.sanitised`` only (invariant I2): it never receives a slice,
a candidate or a vault, and the session is the one object that sees payload text.

**Fail closed (I4).** A request the guard blocks, a transport failure and an answer that is not a
schema-valid verdict each fail that candidate (``fail_item``) and publish no verdict for it; the
other candidates go on. ``llm.enabled = false`` publishes an empty list and opens nothing. With
``no_send`` every check runs and a ``not_sent_dry_run`` entry is written, and no verdict exists.
"""

import importlib
import os
import queue
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager
from typing import Final, cast

from pydantic import BaseModel

from codekavach.config.models.llm import ProviderSettings
from codekavach.core.log import get_logger
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.verdict import CandidateVerdict
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.items import (
    EGRESS_BLOCKED,
    ITEM_EXCEPTION,
    LLM_OUTPUT_INVALID,
    guard_item,
)
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.store.base import ArtefactTypeError
from codekavach.llm.cache import CACHE_DIR, ResponseCache
from codekavach.llm.lifecycle import ManagedSession
from codekavach.llm.providers.base import OfflineProvider
from codekavach.llm.providers.factory import build_provider
from codekavach.llm.review import Outcome, ReviewCounts, Reviewer
from codekavach.llm.tasks import build_task
from codekavach.privacy.egress.session import EgressSession

_log = get_logger("codekavach.llm.stages")
SESSION_FACTORY = ("codekavach.privacy.stages", "open_egress_session")


def _open_session(ctx: RunContext) -> AbstractContextManager[EgressSession]:
    """The egress session of this scan, built by the privacy package that owns the vault.

    Named and imported at run time, not at import time: the LLM layer may not import the vault,
    even through another module (I3), and the session it receives cannot read a mapping record.
    """
    module, attribute = SESSION_FACTORY
    factory: Callable[..., AbstractContextManager[EgressSession]] = getattr(
        importlib.import_module(module), attribute
    )
    if ctx.state_dir is None:
        raise RuntimeError("llm-review needs the state directory of the ledger")
    return factory(
        settings=ctx.config,
        state_dir=ctx.state_dir,
        scan_id=ctx.scan_id,
        consent=ctx.consent,
        dry_run=ctx.no_send,
    )


LLM_REQUEST_FAILED = "llm_request_failed"
LLM_REFUSED = "llm_refused"  # the model declined; recorded, never retried (E22-03)


_FAILURE_CODES: Final = {
    "blocked": EGRESS_BLOCKED,
    "failed": LLM_REQUEST_FAILED,
    "refused": LLM_REFUSED,
    "invalid": LLM_OUTPUT_INVALID,
}


def _read[Model: BaseModel](ctx: RunContext, key: str, model: type[Model]) -> list[Model]:
    """The models under ``key``, whether stored or held transiently."""
    try:
        return ctx.artefacts.get_list(key, model)
    except ArtefactTypeError:
        value = ctx.artefacts.get_object(key)
        if isinstance(value, (list, tuple)) and all(isinstance(item, model) for item in value):
            return list(value)
        raise


CONCURRENCY_VARIABLE = "CODEKAVACH_LLM_CONCURRENCY"
MAX_CONCURRENCY = 16


def concurrency(provider: ProviderSettings, *, offline: bool) -> int:
    """How many candidates are reviewed at once (E22-03).

    ``CODEKAVACH_LLM_CONCURRENCY`` wins, then the provider's ``options.concurrency``; the default
    is one. Offline providers always use one worker, so a mock or replay run stays sequential.
    """
    if offline:
        return 1
    raw = os.environ.get(CONCURRENCY_VARIABLE) or provider.options.get("concurrency", 1)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = 1
    return max(1, min(MAX_CONCURRENCY, value))


class LlmReviewStage:
    """Asks the selected provider for a triage verdict on every payload."""

    name = "llm-review"
    version = "1"
    requires = frozenset({keys.PAYLOADS_SANITISED})
    provides = frozenset({keys.VERDICTS_RAW})
    category = StageCategory.LLM

    def run(self, ctx: RunContext) -> None:
        """Publish one raw verdict per candidate that was sent, answered and parsed."""
        payloads = _read(ctx, keys.PAYLOADS_SANITISED, SanitisedPayload)
        if not ctx.config.llm.enabled or not payloads:
            ctx.artefacts.put(keys.VERDICTS_RAW, [])
            return
        if ctx.state_dir is None:
            raise RuntimeError("llm-review needs the state directory of the ledger")
        provider_id, provider_settings = ctx.config.llm.selected_provider()
        provider = build_provider(provider_id, provider_settings, model=ctx.config.llm.model)
        verdicts: list[CandidateVerdict] = []
        with _open_session(ctx) as egress:
            # E22-03: the response cache, the scan budget and retries wrap the egress session
            llm = ctx.config.llm
            managed = ManagedSession.for_settings(
                egress,
                provider_settings,
                limits=llm.budget,
                cache=ResponseCache(ctx.state_dir / CACHE_DIR)
                if llm.cache and not ctx.no_send
                else None,
                max_retries=llm.max_retries,
            )
            session = cast("EgressSession", managed)

            def make_reviewer() -> Reviewer:
                return Reviewer(
                    provider,
                    session,
                    tasks=frozenset(task.value for task in llm.tasks) | {"triage"},
                    consensus=llm.consensus,
                    wait_seconds=float(llm.timeout_seconds),
                    build_task=build_task,
                    repair_attempts=llm.max_repair_attempts,
                )

            # One reviewer per worker: a reviewer's tasks keep per-call state (the injection
            # report of the last render), so reviewers are never shared between threads.
            workers = concurrency(provider_settings, offline=isinstance(provider, OfflineProvider))
            reviewers: queue.SimpleQueue[Reviewer] = queue.SimpleQueue()
            pool = [make_reviewer() for _ in range(workers)]
            for each in pool:
                reviewers.put(each)

            def review(payload: SanitisedPayload) -> Outcome:
                ctx.check_cancelled()
                reviewer = reviewers.get()
                try:
                    return reviewer.review(payload)
                finally:
                    reviewers.put(reviewer)

            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="llm-review") as pool_:
                futures = [pool_.submit(review, payload) for payload in payloads]
                try:
                    for done, (payload, future) in enumerate(
                        zip(payloads, futures, strict=True), start=1
                    ):
                        item = str(payload.candidate_id)
                        with guard_item(ctx, item, ITEM_EXCEPTION):
                            outcome = future.result()
                            if outcome.verdict is not None:
                                verdicts.append(
                                    CandidateVerdict(
                                        candidate_id=payload.candidate_id, verdict=outcome.verdict
                                    )
                                )
                            elif (code := _FAILURE_CODES.get(outcome.failure or "")) is not None:
                                ctx.fail_item(item, code)
                        ctx.emit_progress(done, len(payloads), "candidates")
                finally:
                    for future in futures:
                        future.cancel()
            counts = ReviewCounts()
            for each in pool:
                for name, value in each.counts.as_dict().items():
                    setattr(counts, name, getattr(counts, name) + value)
            prompts = {name: value for each in pool for name, value in each.prompts.items()}
        ctx.emit_progress(len(payloads), len(payloads), "candidates")
        _log.info(
            "llm_review_done",
            provider=provider.id,
            prompts={name: f"{ver}:{digest[:12]}" for name, (ver, digest) in prompts.items()},
            workers=workers,
            **counts.as_dict(),
            usage=managed.budget.summary(),
            retries=managed.retries,
        )
        ctx.artefacts.put(keys.VERDICTS_RAW, verdicts)
