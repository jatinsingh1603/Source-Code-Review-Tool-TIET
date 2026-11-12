"""``probe_provider``: ask a provider one constant question through the real egress path (E22).

Owning epic: E22 (used by ``codekavach providers test`` and ``doctor --probe-providers``, E05).

The probe is a scan in miniature: the constant synthetic payload of
``codekavach.privacy.egress.probe`` is rendered by the triage task, prepared by the adapter, run
through the egress guard, written to a ledger and sent by the transport (I1). Consent is the
caller's to obtain; without it the guard blocks a remote provider. The ledger of probes lives in
``<user config dir>/probes`` so that a diagnostic call is in an audit trail too.

The outcome carries reason codes, timings and token counts only: never a response body, a header
or an error text, which some providers fill with parts of the request or the key.
"""

import os
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from codekavach.config import Settings
from codekavach.config.paths import ensure_state_dir, user_config_dir
from codekavach.core.pipeline.context import ConsentDecision
from codekavach.llm.providers.base import (
    OfflineProvider,
    ProviderError,
    ProviderParseError,
    ProviderRefused,
    ProviderUnavailable,
    RawResponse,
    usage_of,
)
from codekavach.llm.providers.factory import build_provider
from codekavach.llm.tasks.triage import TriageTask
from codekavach.privacy.egress.ledger import LedgerError
from codekavach.privacy.egress.probe import probe_payload, probe_scan_id
from codekavach.privacy.egress.session import Dispatch, EgressSession

PROBE_DIR: Final = "probes"
PROBE_TASK: Final = "probe"  # the task label of a probe's ledger entries
_STATUS_REASONS: Final = {401: "unauthorised", 403: "unauthorised", 404: "model_not_found"}
_TRANSPORT_REASONS: Final = {
    "connect": "unreachable",
    "timeout": "timeout",
    "tls": "tls_error",
    "redirect": "bad_response",
}


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """What a probe found; safe to print."""

    ok: bool
    provider_id: str
    kind: str
    model: str | None
    latency_ms: int | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    structured_output: str = "not-tested"
    ledger_seq: int | None = None
    reason_code: str | None = None


class _NoOriginals:
    """The probe has no vault: its payload is synthetic, so there is no original to look for."""

    def iter_originals(self, *, min_len: int = 4) -> Iterator[str]:
        return iter(())


def probe_state_dir(env: dict[str, str] | None = None) -> Path:
    """Where the probe ledger is kept."""
    return ensure_state_dir(user_config_dir(dict(os.environ) if env is None else env) / PROBE_DIR)


@contextmanager
def _session(
    settings: Settings, consent: ConsentDecision | None, state_dir: Path
) -> Iterator[EgressSession]:
    with EgressSession(
        settings=settings,
        state_dir=state_dir,
        vault=_NoOriginals(),
        scan_id=probe_scan_id(),
        consent=consent,
    ) as session:
        yield session


def _with_timeout(settings: Settings, timeout: float) -> Settings:
    llm = settings.llm.model_copy(update={"timeout_seconds": max(1, int(timeout))})
    return settings.model_copy(update={"llm": llm})


def _in_clear(settings: Settings) -> Settings:
    """The settings with the ledger stored in clear (the probe's own fallback ledger).

    The probe payload is the synthetic snippet of ``privacy.egress.probe``, so encrypting that
    ledger protects nothing and would make ``providers test`` depend on the vault key source.
    """
    egress = settings.privacy.egress.model_copy(update={"encrypt_at_rest": False})
    privacy = settings.privacy.model_copy(update={"egress": egress})
    return settings.model_copy(update={"privacy": privacy})


def _dispatch(
    settings: Settings,
    consent: ConsentDecision | None,
    state_dir: Path | None,
    send: Callable[[EgressSession], Dispatch],
) -> Dispatch:
    """Run ``send`` in a session on the project's ledger, or on the probe ledger.

    The project ledger is used when the caller names its state directory and its key opens; a
    ledger whose key is not available here falls back to ``<user config dir>/probes``.
    """
    if state_dir is not None:
        try:
            with _session(settings, consent, state_dir) as session:
                return send(session)
        except LedgerError:
            pass
    with _session(_in_clear(settings), consent, probe_state_dir()) as session:
        return send(session)


def probe_provider(
    provider_id: str,
    settings: Settings,
    *,
    model: str | None = None,
    structured: bool = False,
    timeout: float = 30.0,
    consent: ConsentDecision | None = None,
    state_dir: Path | None = None,
) -> ProbeOutcome:
    """Send the constant probe to ``provider_id`` and report what happened."""
    configured = settings.llm.providers.get(provider_id)
    if configured is None:
        return ProbeOutcome(False, provider_id, "unknown", model, reason_code="bad_response")
    kind = configured.kind.value
    chosen = model or settings.llm.model or configured.model
    try:
        provider = build_provider(provider_id, configured, model=chosen)
    except ProviderError as error:
        reason = "unauthorised" if error.reason == "api_key_not_available" else "bad_response"
        return ProbeOutcome(False, provider_id, kind, chosen, reason_code=reason)
    task = TriageTask()
    payload = probe_payload()
    request = provider.prepare(task, payload)
    static = (*task.static_text(payload), *getattr(provider, "static_text", tuple)())
    effective = _with_timeout(settings, timeout)
    started = time.monotonic()
    respond = (lambda: provider.respond(request)) if isinstance(provider, OfflineProvider) else None

    def send(session: EgressSession) -> Dispatch:
        return session.dispatch(
            request,
            provider=provider_id,
            model=request.model,
            task=PROBE_TASK,
            payload=payload,
            respond=respond,
            static_text=static,
        )

    result = _dispatch(effective, consent, state_dir, send)
    latency = round((time.monotonic() - started) * 1000)
    seq = result.ledger_seq
    if result.kind == "blocked":
        return ProbeOutcome(
            False, provider_id, kind, request.model, ledger_seq=seq, reason_code="bad_response"
        )
    if result.kind == "failed":
        reason = _TRANSPORT_REASONS.get(result.error_kind or "", "unreachable")
        return ProbeOutcome(
            False, provider_id, kind, request.model, latency, ledger_seq=seq, reason_code=reason
        )
    if result.kind == "dry_run":
        return ProbeOutcome(True, provider_id, kind, request.model, latency)
    status = result.status or 0
    usage = usage_of(result.body)
    tokens_in = usage.input_tokens or None
    tokens_out = usage.output_tokens or None
    failure: str | None = None
    if status == 429:
        failure = "rate_limited"
    elif not 200 <= status < 300:
        failure = _STATUS_REASONS.get(status, "bad_response")
    state = "passed" if structured else "not-tested"
    if failure is None:
        try:
            provider.parse(RawResponse(status, result.body, result.headers))
        except (ProviderRefused, ProviderUnavailable, ProviderParseError):
            failure = "bad_response"
            state = "failed" if structured else "not-tested"
    return ProbeOutcome(
        ok=failure is None,
        provider_id=provider_id,
        kind=kind,
        model=request.model,
        latency_ms=latency,
        prompt_tokens=tokens_in,
        completion_tokens=tokens_out,
        structured_output=state if failure in {None, "bad_response"} else "not-tested",
        ledger_seq=seq,
        reason_code=failure,
    )
