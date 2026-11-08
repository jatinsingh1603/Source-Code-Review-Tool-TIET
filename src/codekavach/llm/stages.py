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
from codekavach.llm.providers.base import OfflineProvider, ProviderParseError, RawResponse
from codekavach.llm.providers.factory import build_provider
from codekavach.llm.tasks.triage import TriageTask
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
        task = TriageTask()
        verdicts: list[CandidateVerdict] = []
        counts = {"answered": 0, "blocked": 0, "dry_run": 0, "failed": 0}
        with _open_session(ctx) as session:
            for done, payload in enumerate(payloads, start=1):
                ctx.check_cancelled()
                with guard_item(ctx, str(payload.candidate_id), ITEM_EXCEPTION):
                    request = provider.prepare(task, payload)
                    respond = (
                        (lambda r=request: provider.respond(r))
                        if isinstance(provider, OfflineProvider)
                        else None
                    )
                    result = session.dispatch(
                        request,
                        provider=provider.id,
                        model=request.model,
                        task=task.name,
                        payload=payload,
                        respond=respond,
                        static_text=task.static_text(payload),
                    )
                    counts[result.kind] += 1
                    item = str(payload.candidate_id)
                    if result.kind == "blocked":
                        ctx.fail_item(item, EGRESS_BLOCKED)
                    elif result.kind == "failed":
                        ctx.fail_item(item, LLM_REQUEST_FAILED)
                    elif result.kind == "answered":
                        try:
                            verdict = provider.parse(
                                RawResponse(result.status or 0, result.body, result.headers)
                            )
                        except ProviderParseError:
                            ctx.fail_item(item, LLM_OUTPUT_INVALID)
                        else:
                            verdicts.append(
                                CandidateVerdict(candidate_id=payload.candidate_id, verdict=verdict)
                            )
                if done % 25 == 0:
                    ctx.emit_progress(done, len(payloads), "candidates")
        ctx.emit_progress(len(payloads), len(payloads), "candidates")
        _log.info("llm_review_done", provider=provider.id, **counts)
        ctx.artefacts.put(keys.VERDICTS_RAW, verdicts)
