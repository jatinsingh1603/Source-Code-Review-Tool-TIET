"""``EgressSession``: one scan's way from a prepared request to a ledger entry (E13-02).

Owning epic: E12 (used by the llm-review stage of E13). The LLM layer may not import the vault or
the guard's internals (I2, I3), and this module does not either: the vault arrives as a
``VaultOriginals`` that the caller opened and will close. The stage hands each request to this
session and gets back only what it needs: a block code, or the bytes of an answer.

For every request the session does, in this order:

1. ``EgressGuard.evaluate`` on the serialised body with the vault's originals bound to the
   scanners; a refusal is a ``blocked`` ledger entry (the payload is stored with it, so the
   operator sees what was stopped) and the request is not sent;
2. an allowed request in dry-run mode is redeemed, ledgered as ``not_sent_dry_run`` and not sent;
3. an allowed request is ledgered as ``sent`` before anything leaves, then handed to the
   transport (a network provider) or answered locally by the caller's ``respond`` (the mock and
   the replay provider, which have no endpoint); the answer is ledgered as ``completed`` and a
   failure as ``failed``, both pointing back at the ``sent`` entry.

Only ``codekavach.privacy.egress.transport`` opens a connection (I1); this module never imports a
network library. Any exception here is the caller's to turn into a failed candidate (I4), and no
exception message carries payload text.
"""

import contextlib
import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import TracebackType
from typing import Any, Final, Literal, Protocol, Self

from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.core.models.egress import TokenCounts
from codekavach.core.models.enums import EgressOutcome
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.timeutil import utc_now
from codekavach.core.pipeline.context import ConsentDecision
from codekavach.privacy.egress.guard import EgressGuard, ScannerRegistry, VaultOriginals
from codekavach.privacy.egress.ledger import EgressDraft, LedgerWriter, open_writer
from codekavach.privacy.egress.models import EgressBlocked, EgressMeta, EgressTicket
from codekavach.privacy.egress.scanners import register_default_scanners, release, warm
from codekavach.privacy.egress.transport import (
    DryRunTransport,
    OutboundRequest,
    Transport,
    TransportError,
)
from codekavach.privacy.slicing.metrics import ScanDisclosure

_log = get_logger("codekavach.privacy.egress.session")
_BYTES_PER_TOKEN: Final = 4

Kind = Literal["answered", "blocked", "dry_run", "failed"]


class Reply(Protocol):
    """What an offline provider's ``respond`` returns."""

    @property
    def status(self) -> int:
        """The response status."""
        ...

    @property
    def body(self) -> bytes:
        """The response body."""
        ...


@dataclass(frozen=True, slots=True, repr=False)
class Dispatch:
    """What the stage learns about one request. It holds no payload text."""

    kind: Kind
    block_code: str | None = None
    status: int | None = None
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)
    error_kind: str | None = None

    def __repr__(self) -> str:
        return f"Dispatch({self.kind}, block={self.block_code}, status={self.status})"

    __str__ = __repr__


def _tokens(size: int) -> int:
    return max(1, size // _BYTES_PER_TOKEN)


class EgressSession:
    """The vault, the guard, the ledger and the transport of one scan."""

    def __init__(
        self,
        *,
        settings: Settings,
        state_dir: Path,
        vault: VaultOriginals,
        scan_id: str,
        consent: ConsentDecision | None,
        dry_run: bool = False,
        http_transport: Any = None,  # an httpx.BaseTransport; tests inject a mock one
    ) -> None:
        self._settings = settings
        self._state = state_dir
        self._vault = vault
        self._scan_id = scan_id
        self._consent = consent
        self._dry_run = dry_run
        self._http_transport = http_transport
        self._stack = contextlib.ExitStack()
        self._guard: EgressGuard | None = None
        self._ledger: LedgerWriter | None = None
        self._transport: Transport | DryRunTransport | None = None
        self._registry: ScannerRegistry | None = None

    def __enter__(self) -> Self:
        state = self._state
        privacy = self._settings.privacy
        try:
            self._ledger = open_writer(
                state,
                encrypt_at_rest=privacy.egress.encrypt_at_rest,
                key_source=privacy.vault.key_source,
                settings=self._settings,
            )
            registry = register_default_scanners(ScannerRegistry(), ScanDisclosure(repo_lines=1))
            self._registry = registry
            self._guard = EgressGuard(registry)
            warm(registry, self._vault, self._settings)
            if self._dry_run:
                self._transport = DryRunTransport(self._guard, self._settings)
            else:
                transport = Transport(
                    self._guard, self._settings, http_transport=self._http_transport
                )
                self._stack.callback(transport.close)
                self._transport = transport
        except BaseException:
            self._stack.close()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._registry is not None:
            release(self._registry)
        self._stack.close()

    def dispatch(
        self,
        request: OutboundRequest,
        *,
        provider: str,
        model: str,
        task: str,
        payload: SanitisedPayload,
        respond: Callable[[], Reply] | None = None,
        static_text: Sequence[str] = (),
    ) -> Dispatch:
        """Guard, ledger and send ``request``; ``respond`` answers an offline provider locally."""
        guard, ledger, transport = self._guard, self._ledger, self._transport
        if guard is None or ledger is None or transport is None:
            raise RuntimeError("the egress session is not open")
        meta = EgressMeta(
            provider=provider,
            model=model,
            level=payload.level,
            payload_hash=payload.payload_hash,
            candidate_id=payload.candidate_id,
            task=task,
        )
        text = payload.text
        decision = guard.evaluate(
            request.body,
            meta,
            settings=self._settings,
            consent=self._consent,
            vault=self._vault,
            payload_text=text.expose(),
            static_text=static_text,
        )

        def draft(
            outcome: EgressOutcome, *, block_code: str | None = None, ref_seq: int | None = None
        ) -> EgressDraft:
            return EgressDraft(
                timestamp=utc_now(),
                scan_id=self._scan_id,
                candidate_id=str(payload.candidate_id),
                provider=provider,
                model=model,
                task=task,
                level=payload.level,
                payload_hash=payload.payload_hash,
                token_counts=TokenCounts(prompt=_tokens(len(request.body))),
                outcome=outcome,
                request_hash=hashlib.sha256(request.body).hexdigest(),
                block_code=block_code,
                ref_seq=ref_seq,
            )

        if not decision.allowed or decision.ticket is None:
            code = decision.block_code or "scanner_error"
            ledger.append(draft(EgressOutcome.BLOCKED, block_code=code), text)
            return Dispatch("blocked", block_code=code)
        ticket = decision.ticket
        if self._dry_run:
            return self._dry(transport, guard, request, ticket, respond, ledger, draft, payload)
        sent = ledger.append(draft(EgressOutcome.SENT), text)
        try:
            if respond is None:
                if not isinstance(transport, Transport):
                    raise RuntimeError("the transport is not open")
                response = transport.send(request, ticket, payload_text=text.expose())
                status, body, headers = response.status, response.body, response.headers
            else:
                guard.redeem(
                    ticket, payload_hash=meta.payload_hash, provider=provider, level=meta.level
                )
                answer = respond()
                status, body, headers = answer.status, answer.body, {}
        except EgressBlocked as blocked:
            self._follow_up(ledger, draft, EgressOutcome.FAILED, sent.seq, 0)
            return Dispatch("failed", block_code=blocked.block_code, error_kind="refused")
        except TransportError as error:
            self._follow_up(ledger, draft, EgressOutcome.FAILED, sent.seq, 0)
            return Dispatch("failed", error_kind=error.kind)
        except Exception:  # noqa: BLE001 - an offline provider may raise anything; text is dropped
            self._follow_up(ledger, draft, EgressOutcome.FAILED, sent.seq, 0)
            return Dispatch("failed", error_kind="provider_error")
        self._follow_up(ledger, draft, EgressOutcome.COMPLETED, sent.seq, len(body))
        return Dispatch("answered", status=status, body=body, headers=dict(headers))

    @staticmethod
    def _follow_up(
        ledger: LedgerWriter,
        draft: Callable[..., EgressDraft],
        outcome: EgressOutcome,
        ref_seq: int,
        size: int,
    ) -> None:
        base = draft(outcome, ref_seq=ref_seq)
        counts = TokenCounts(
            prompt=base.token_counts.prompt, completion=_tokens(size) if size else 0
        )
        ledger.append(replace(base, token_counts=counts))

    def _dry(  # noqa: PLR0917 - the request's context, passed explicitly
        self,
        transport: Transport | DryRunTransport,
        guard: EgressGuard,
        request: OutboundRequest,
        ticket: EgressTicket,
        respond: Callable[[], Reply] | None,
        ledger: LedgerWriter,
        draft: Callable[..., EgressDraft],
        payload: SanitisedPayload,
    ) -> Dispatch:
        try:
            if respond is None:
                transport.send(request, ticket, payload_text=payload.text.expose())
            else:
                guard.redeem(
                    ticket,
                    payload_hash=payload.payload_hash,
                    provider=ticket.provider,
                    level=payload.level,
                )
        except EgressBlocked as blocked:
            ledger.append(draft(EgressOutcome.BLOCKED, block_code=blocked.block_code), payload.text)
            return Dispatch("blocked", block_code=blocked.block_code)
        ledger.append(draft(EgressOutcome.NOT_SENT_DRY_RUN), payload.text)
        return Dispatch("dry_run")
