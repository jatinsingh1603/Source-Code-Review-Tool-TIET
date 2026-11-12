"""The request lifecycle around the egress session: cache, budget and retries (E22-03).

Owning epic: E22.

``ManagedSession`` has the ``dispatch`` signature of ``EgressSession`` and wraps one, so the review
flow is unchanged while every request gains:

1. **a cache lookup** (``llm.cache``): an answer stored for the same provider kind, host, model,
   task, prompt version and hash, payload hash and sample index is returned without egress and
   without a ledger entry. The sample index is the number of earlier requests for the same task
   and payload in this scan, so consensus samples and context rounds are cached apart;
2. **a budget check** (``llm.budget``): once a limit is reached, no request is sent and the
   dispatch fails with ``error_kind = "budget_exhausted"``; deterministic findings are untouched;
3. **retries with backoff** for a transient answer (408, 429, 5xx) or a connection failure, up to
   ``llm.max_retries``, honouring ``Retry-After`` (capped). Every attempt is a fresh dispatch, so
   the guard evaluates the body again and issues a new ticket, and the ledger records each
   attempt. A 4xx other than 408 and 429 is not retried, and a refusal is not retried either
   (the caller sees it in the answer and records it).

Only answers that are 2xx and carry content are cached. Offline providers are not cached: they
already answer locally.
"""

import random
import threading
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final
from urllib.parse import urlsplit

from codekavach.config.models.llm import ProviderSettings
from codekavach.core.log import get_logger
from codekavach.core.models.payload import SanitisedPayload
from codekavach.llm.budget import ScanBudget, prices_for
from codekavach.llm.cache import CacheKey, ResponseCache
from codekavach.llm.providers.base import (
    PreparedRequest,
    ProviderParseError,
    extract_content,
    usage_of,
)
from codekavach.privacy.egress.session import Dispatch, EgressSession

_log = get_logger("codekavach.llm.lifecycle")

TRANSIENT_STATUSES: Final = frozenset({408, 429, 500, 502, 503, 504})
TRANSIENT_ERRORS: Final = frozenset({"connect", "timeout", "protocol"})
BUDGET_EXHAUSTED: Final = "budget_exhausted"
MAX_RETRY_AFTER_SECONDS: Final = 60.0
_BACKOFF_BASE: Final = 1.0
_BACKOFF_CAP: Final = 20.0


def retry_after(headers: Mapping[str, str]) -> float | None:
    """The ``Retry-After`` delay in seconds (the delta-seconds form), capped; else ``None``."""
    value = {name.lower(): text for name, text in headers.items()}.get("retry-after")
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    return min(max(seconds, 0.0), MAX_RETRY_AFTER_SECONDS)


class ManagedSession:
    """An ``EgressSession`` with a response cache, a scan budget and retries."""

    def __init__(
        self,
        session: EgressSession,
        *,
        provider_settings: ProviderSettings,
        budget: ScanBudget,
        cache: ResponseCache | None,
        max_retries: int,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self._session = session
        self._kind = provider_settings.kind.value
        self._budget = budget
        self._cache = cache
        self._max_retries = max(0, max_retries)
        self._sleep = sleep
        self._rng = rng if rng is not None else random.Random()  # noqa: S311 - jitter only
        self._lock = threading.Lock()  # dispatch may run on several threads at once
        self._samples: Counter[tuple[str, str]] = Counter()
        self.retries = 0

    @classmethod
    def for_settings(
        cls,
        session: EgressSession,
        provider_settings: ProviderSettings,
        *,
        limits: Any,
        cache: ResponseCache | None,
        max_retries: int,
    ) -> "ManagedSession":
        """A managed session with a fresh budget over ``limits`` (``llm.budget``)."""
        budget = ScanBudget(limits, prices_for(provider_settings))
        return cls(
            session,
            provider_settings=provider_settings,
            budget=budget,
            cache=cache,
            max_retries=max_retries,
        )

    @property
    def budget(self) -> ScanBudget:
        """What this scan has spent."""
        return self._budget

    def _key(self, request: PreparedRequest, task: str, payload: SanitisedPayload) -> CacheKey:
        sample_key = (task, payload.payload_hash)
        with self._lock:
            sample = self._samples[sample_key]
            self._samples[sample_key] += 1
        return CacheKey(
            kind=self._kind,
            host=urlsplit(request.url).hostname or "",
            model=request.model,
            task=task,
            prompt_version=request.prompt_version,
            prompt_hash=request.prompt_hash,
            payload_hash=payload.payload_hash,
            sample=sample,
        )

    def _backoff(self, attempt: int, result: Dispatch) -> float:
        hinted = retry_after(result.headers)
        if hinted is not None:
            return hinted
        base = min(_BACKOFF_CAP, _BACKOFF_BASE * (2**attempt))
        return float(base * self._rng.uniform(0.5, 1.5))

    @staticmethod
    def _transient(result: Dispatch) -> bool:
        if result.kind == "failed":
            return result.error_kind in TRANSIENT_ERRORS
        return result.kind == "answered" and (result.status or 0) in TRANSIENT_STATUSES

    def dispatch(
        self,
        request: Any,
        *,
        provider: str,
        model: str,
        task: str,
        payload: SanitisedPayload,
        respond: Callable[[], Any] | None = None,
        static_text: Sequence[str] = (),
        wait_seconds: float = 0.0,
    ) -> Dispatch:
        """Answer from the cache, or check the budget and dispatch with retries."""
        offline = respond is not None
        key = None
        if self._cache is not None and not offline and isinstance(request, PreparedRequest):
            key = self._key(request, task, payload)
            hit = self._cache.get(key)
            if hit is not None:
                self._budget.cache_hits += 1
                return Dispatch("answered", status=hit.status, body=hit.body)
        attempt = 0
        while True:
            if not offline and (limit := self._budget.exhausted()) is not None:
                _log.warning("llm_budget_exhausted", limit=limit)
                return Dispatch("failed", error_kind=BUDGET_EXHAUSTED)
            result = self._session.dispatch(
                request,
                provider=provider,
                model=model,
                task=task,
                payload=payload,
                respond=respond,
                static_text=static_text,
                wait_seconds=wait_seconds,
            )
            if result.kind in {"answered", "failed"} and not offline:
                with self._lock:
                    self._budget.record(usage_of(result.body), request_bytes=len(request.body))
            if attempt >= self._max_retries or not self._transient(result):
                break
            delay = self._backoff(attempt, result)
            _log.info(
                "llm_retry",
                attempt=attempt + 1,
                status=result.status,
                error_kind=result.error_kind,
                delay_s=round(delay, 2),
            )
            self.retries += 1
            self._sleep(delay)
            attempt += 1
        if key is not None and self._cacheable(result) and self._cache is not None:
            self._cache.put(key, result.status or 200, result.body)
        return result

    @staticmethod
    def _cacheable(result: Dispatch) -> bool:
        if result.kind != "answered" or not 200 <= (result.status or 0) < 300:
            return False
        try:
            extract_content(result.body)
        except ProviderParseError:
            return False
        return True
