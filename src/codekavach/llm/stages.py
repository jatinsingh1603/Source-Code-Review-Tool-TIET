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
from collections.abc import Callable
from contextlib import AbstractContextManager

from pydantic import BaseModel

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
from codekavach.llm.providers.factory import build_provider
from codekavach.llm.review import Reviewer
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


def _read[Model: BaseModel](ctx: RunContext, key: str, model: type[Model]) -> list[Model]:
    """The models under ``key``, whether stored or held transiently."""
    try:
        return ctx.artefacts.get_list(key, model)
    except ArtefactTypeError:
        value = ctx.artefacts.get_object(key)
        if isinstance(value, (list, tuple)) and all(isinstance(item, model) for item in value):
            return list(value)
        raise


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
        provider = build_provider(provider_id, provider_settings)
        verdicts: list[CandidateVerdict] = []
        with _open_session(ctx) as session:
            reviewer = Reviewer(
                provider,
                session,
                tasks=frozenset(task.value for task in ctx.config.llm.tasks) | {"triage"},
                consensus=ctx.config.llm.consensus,
                wait_seconds=float(ctx.config.llm.timeout_seconds),
                build_task=build_task,
            )
            for done, payload in enumerate(payloads, start=1):
                ctx.check_cancelled()
                with guard_item(ctx, str(payload.candidate_id), ITEM_EXCEPTION):
                    item = str(payload.candidate_id)
                    outcome = reviewer.review(payload)
                    if outcome.verdict is not None:
                        verdicts.append(
                            CandidateVerdict(
                                candidate_id=payload.candidate_id, verdict=outcome.verdict
                            )
                        )
                    elif outcome.failure == "blocked":
                        ctx.fail_item(item, EGRESS_BLOCKED)
                    elif outcome.failure == "failed":
                        ctx.fail_item(item, LLM_REQUEST_FAILED)
                    elif outcome.failure == "invalid":
                        ctx.fail_item(item, LLM_OUTPUT_INVALID)
                if done % 25 == 0:
                    ctx.emit_progress(done, len(payloads), "candidates")
        ctx.emit_progress(len(payloads), len(payloads), "candidates")
        _log.info(
            "llm_review_done",
            provider=provider.id,
            prompts={
                name: f"{ver}:{digest[:12]}" for name, (ver, digest) in reviewer.prompts.items()
            },
            **reviewer.counts.as_dict(),
        )
        ctx.artefacts.put(keys.VERDICTS_RAW, verdicts)
