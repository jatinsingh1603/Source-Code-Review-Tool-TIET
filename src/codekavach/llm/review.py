"""The per-candidate review flow of the llm-review stage (E23-02, E23-03, E24).

For one payload: triage (one sample, or several with different perspectives when
``llm.consensus > 1``), then, when the candidate looks vulnerable, an optional context round and the
``explain`` and ``remediate`` tasks. The answers are merged into one ``LLMVerdict`` in pseudonym
space, so the restore stage can translate it back to real names unchanged.

Every request goes through ``EgressSession.dispatch``; this module never opens a connection and
never sees anything but the ``SanitisedPayload`` (I1, I2). Every answer is validated as untrusted
(``defence.output``); a rejected triage answer fails that candidate and leaves its deterministic
finding untouched. A failed or rejected explain or remediate answer only leaves the verdict
without that enrichment.

Context loop: when a verdict has ``needs_context`` and the privacy layer exposes a context
resolver (``CONTEXT_FACTORY``), up to ``MAX_CONTEXT_ROUNDS`` extra slices are fetched through it,
already sanitised, and triage is asked again with them inside the same delimited, guard-scanned
request. Without a resolver the loop does nothing and the undecided verdict is kept as it is.
"""

import importlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Final

from pydantic import BaseModel

from codekavach.core.log import get_logger
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.verdict import LLMVerdict
from codekavach.llm.consensus import ConsensusResult, calibrate, vote
from codekavach.llm.defence.injection import new_canary
from codekavach.llm.defence.output import (
    OutputRejected,
    OutputReport,
    check_text,
    prompt_shingles,
    validate_verdict,
)
from codekavach.llm.providers.base import (
    LLMProvider,
    OfflineProvider,
    PreparedRequest,
    ProviderError,
    ProviderParseError,
    RawResponse,
    extract_content,
)
from codekavach.llm.schema.tasks import ExplainAnswer, RemediateAnswer
from codekavach.llm.tasks.base import CandidateFacts
from codekavach.llm.tasks.templated import PERSPECTIVES, TemplatedTask
from codekavach.privacy.egress.session import Dispatch, EgressSession

_log = get_logger("codekavach.llm.review")
CONTEXT_FACTORY: Final = ("codekavach.privacy.stages", "resolve_context")
MAX_CONTEXT_ROUNDS: Final = 2
MAX_IMPACT: Final = 2000
MAX_REMEDIATION: Final = 4000


class _Bound:
    """A task with fixed render options, so a provider's ``prepare(task, payload)`` sees them."""

    def __init__(self, task: TemplatedTask, **options: str) -> None:
        self._task = task
        self._options = options
        self.name = task.name
        self.prompt_version = task.prompt_version

    @property
    def prompt_hash(self) -> str:
        return self._task.prompt_hash

    def render(self, payload: SanitisedPayload, facts: CandidateFacts) -> str:
        return self._task.render(payload, facts, **self._options)

    def render_parts(self, payload: SanitisedPayload, facts: CandidateFacts) -> tuple[str, str]:
        return self._task.render_parts(payload, facts, **self._options)

    def output_schema(self) -> dict[str, object]:
        return self._task.output_schema()

    def static_text(self, payload: SanitisedPayload) -> tuple[str, ...]:
        return self._task.static_text(payload)


@dataclass(slots=True)
class ReviewCounts:
    """Counters the stage logs at the end."""

    answered: int = 0
    blocked: int = 0
    dry_run: int = 0
    failed: int = 0
    rejected: int = 0
    enriched: int = 0
    context_rounds: int = 0
    injection_suspected: int = 0
    calls: int = 0

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__slots__}


@dataclass(slots=True)
class Outcome:
    """The result of reviewing one candidate: a verdict, or the failure code."""

    verdict: LLMVerdict | None = None
    failure: str | None = None
    consensus: ConsensusResult | None = None
    notes: list[str] = field(default_factory=list)


def _resolver() -> Callable[..., str | None] | None:
    module, attribute = CONTEXT_FACTORY
    try:
        found = getattr(importlib.import_module(module), attribute, None)
    except ImportError:
        return None
    return found if callable(found) else None


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, BaseModel):
        yield from _strings(value.model_dump())
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def answer_text(provider: LLMProvider, raw: RawResponse) -> str:
    """The model's text in ``raw``: the provider's own extractor when it has one."""
    extractor = getattr(provider, "extract_text", None)
    if callable(extractor):
        return str(extractor(raw))
    if not 200 <= raw.status < 300:
        raise ProviderParseError(f"http_status_{raw.status}")
    return extract_content(raw.body)


class Reviewer:
    """Reviews payloads with one provider through one egress session."""

    def __init__(
        self,
        provider: LLMProvider,
        session: EgressSession,
        *,
        tasks: frozenset[str],
        consensus: int,
        wait_seconds: float,
        build_task: Callable[[str], TemplatedTask],
        canary: str | None = None,
    ) -> None:
        self._canary = canary or new_canary()
        self._provider = provider
        self._session = session
        self._enabled = tasks
        self._samples = max(1, consensus)
        self._wait = wait_seconds
        self._build = build_task
        self.counts = ReviewCounts()
        self.prompts: dict[str, tuple[str, str]] = {}
        self._tasks: dict[str, TemplatedTask] = {}
        self._shingles: dict[str, frozenset[tuple[str, ...]]] = {}

    # -- plumbing --------------------------------------------------------------------------

    def _task(self, name: str) -> TemplatedTask:
        if name not in self._tasks:
            task = self._build(name)
            self._tasks[name] = task
            self.prompts[name] = (task.prompt_version, task.prompt_hash)
            self._shingles[name] = prompt_shingles(task.rubric_text())
        return self._tasks[name]

    def _dispatch(self, bound: _Bound, payload: SanitisedPayload) -> Dispatch:
        provider = self._provider
        request: PreparedRequest = provider.prepare(bound, payload)
        respond = (
            (lambda r=request: provider.respond(r))
            if isinstance(provider, OfflineProvider)
            else None
        )
        self.counts.calls += 1
        return self._session.dispatch(
            request,
            provider=provider.id,
            model=request.model,
            task=bound.name,
            payload=payload,
            respond=respond,
            static_text=bound.static_text(payload),
            wait_seconds=self._wait,
        )

    def _triage_once(
        self, payload: SanitisedPayload, facts: CandidateFacts, perspective: str, context: str
    ) -> tuple[LLMVerdict | None, str | None]:
        """One triage call: ``(verdict, failure_code)``; both None for a dry run."""
        task = self._task("triage")
        bound = _Bound(task, perspective=perspective, context=context, canary=self._canary)
        result = self._dispatch(bound, payload)
        if result.kind == "blocked":
            self.counts.blocked += 1
            return None, "blocked"
        if result.kind == "failed":
            self.counts.failed += 1
            return None, "failed"
        if result.kind == "dry_run":
            self.counts.dry_run += 1
            return None, None
        self.counts.answered += 1
        try:
            verdict = self._provider.parse(
                RawResponse(result.status or 0, result.body, result.headers)
            )
            if task.last_suspected:
                self.counts.injection_suspected += 1
            cleaned, _report = validate_verdict(
                verdict,
                trusted_cwes=facts.cwe,
                canaries=(self._canary,),
                shingles=self._shingles["triage"],
            )
        except ProviderParseError:
            return None, "invalid"
        except OutputRejected as rejected:
            self.counts.rejected += 1
            _log.warning("llm_output_rejected", reason=rejected.reason)
            return None, "invalid"
        return cleaned, None

    def _enrich_call[A: BaseModel](
        self,
        name: str,
        model: type[A],
        payload: SanitisedPayload,
        facts: CandidateFacts,
        prior: str,
    ) -> A | None:
        """One explain or remediate call; None on any problem (the verdict stays as it is)."""
        task = self._task(name)
        result = self._dispatch(_Bound(task, prior=prior, canary=self._canary), payload)
        if result.kind != "answered":
            return None
        try:
            text = answer_text(self._provider, RawResponse(result.status or 0, result.body))
            answer = task.parse_text(text)
            for piece in _strings(answer):
                check_text(piece, canaries=(self._canary,), shingles=self._shingles[name])
        except (ProviderError, ValueError, OutputRejected):
            return None
        return answer if isinstance(answer, model) else None

    # -- the flow --------------------------------------------------------------------------

    def review(self, payload: SanitisedPayload) -> Outcome:
        """Review one payload."""
        facts = CandidateFacts.from_payload(payload)
        verdicts: list[LLMVerdict] = []
        context = ""
        for index in range(self._samples):
            perspective = PERSPECTIVES[index % len(PERSPECTIVES)]
            verdict, failure = self._triage_once(payload, facts, perspective, context)
            if verdict is None:
                if index == 0 or failure == "blocked":
                    return Outcome(failure=failure or "dry_run")
                continue
            verdicts.append(verdict)
            if index == 0 and verdict.needs_context:
                extra = self._context_rounds(payload, facts, verdict, perspective)
                if extra is not None:
                    verdicts[-1] = extra[0]
                    context = extra[1]
        combined = vote(verdicts)
        merged = combined.verdict
        task = self._task("triage")
        suspected = bool(task.last_suspected)
        confidence = calibrate(
            merged.confidence,
            agreement=combined.agreement,
            samples=combined.samples,
            injection_suspected=suspected,
        )
        merged = merged.model_copy(update={"confidence": confidence})
        if merged.is_vulnerable:
            merged = self._enrich(payload, facts, merged)
        return Outcome(verdict=merged, consensus=combined)

    def _context_rounds(
        self,
        payload: SanitisedPayload,
        facts: CandidateFacts,
        verdict: LLMVerdict,
        perspective: str,
    ) -> tuple[LLMVerdict, str] | None:
        resolve = _resolver()
        if resolve is None:
            return None
        gathered = ""
        current = verdict
        for _ in range(MAX_CONTEXT_ROUNDS):
            if not current.needs_context:
                break
            extra = resolve(payload, tuple(current.needs_context))
            if not extra:
                break
            gathered += ("\n" if gathered else "") + extra
            self.counts.context_rounds += 1
            again, _failure = self._triage_once(payload, facts, perspective, gathered)
            if again is None:
                break
            current = again
        return (current, gathered) if gathered else None

    def _enrich(
        self, payload: SanitisedPayload, facts: CandidateFacts, verdict: LLMVerdict
    ) -> LLMVerdict:
        prior = (
            f"is_vulnerable: {verdict.is_vulnerable}\nconfidence: {verdict.confidence.value}\n"
            f"reasoning: {verdict.reasoning}"
        )
        impact, remediation = verdict.impact, verdict.remediation
        done = False
        if "explain" in self._enabled:
            explained = self._enrich_call("explain", ExplainAnswer, payload, facts, prior)
            if explained is not None:
                impact = _impact_text(explained)
                done = True
        if "remediate" in self._enabled:
            fixed = self._enrich_call("remediate", RemediateAnswer, payload, facts, prior)
            if fixed is not None:
                remediation = _remediation_text(fixed)
                done = True
        if done:
            self.counts.enriched += 1
        return verdict.model_copy(
            update={"impact": impact[:MAX_IMPACT], "remediation": remediation[:MAX_REMEDIATION]}
        )


def _impact_text(answer: ExplainAnswer) -> str:
    parts = [answer.impact.strip()]
    if answer.attack_scenario.strip():
        parts.append(f"Attack scenario: {answer.attack_scenario.strip()}")
    if answer.affected_assets:
        parts.append("Affected: " + "; ".join(answer.affected_assets))
    if answer.exploit_preconditions.strip():
        parts.append(f"Preconditions: {answer.exploit_preconditions.strip()}")
    return "\n\n".join(part for part in parts if part)


def _remediation_text(answer: RemediateAnswer) -> str:
    parts = [answer.guidance.strip()]
    if answer.secure_example.strip():
        language = "".join(ch for ch in answer.secure_example_language.lower() if ch.isalnum())
        body = answer.secure_example.strip().replace("```", "'''")
        fence = f"```{language}\n{body}\n```"
        parts.append(f"Secure example:\n{fence}")
    if answer.defence_in_depth:
        parts.append(
            "Defence in depth:\n" + "\n".join(f"- {item}" for item in answer.defence_in_depth)
        )
    return "\n\n".join(part for part in parts if part)


__all__ = ["Outcome", "OutputReport", "Reviewer", "answer_text"]
