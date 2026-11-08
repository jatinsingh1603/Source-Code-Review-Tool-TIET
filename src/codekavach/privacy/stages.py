"""``PrivacyPrepareStage``: from candidates to sanitised payloads (E13-02).

Owning epic: E13. MVP; extended by E25, which adds the context rounds and the L4 abstract facts.

For every candidate the stage runs, in this order:

1. the policy: a path covered by ``never_send`` (or a level of L0) produces no payload at all;
2. the slice (``EnclosingFunctionStrategy``) under ``privacy.slice.max_tokens``;
3. detection and redaction of secrets, personal data and domain terms;
4. pseudonymisation and the structural checks of the engine, with one generator for the whole scan
   so that a name keeps its token in every payload;
5. the mapping batch goes to the vault, then the payload carries its prompt facts.

**Fail closed (invariant I4).** Any failure in steps 2 to 5 is recorded with ``fail_item`` against
that candidate and no payload is published for it; the others go on. A payload is appended to the
output only after every step succeeded, so a fault can never leave a half-redacted text in
``payloads.sanitised``. Error codes name the step and nothing else: exception text is dropped
because it may quote the code that is being protected.

The original slices are published under ``slices`` (raw code, never readable by an LLM stage) so
that the restore stage and ``privacy inspect`` can show them beside the payloads.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.core.models import Candidate, RawCode
from codekavach.core.models.enums import PrivacyLevel
from codekavach.core.models.payload import (
    MAX_STUB_SUMMARIES,
    MAX_SUMMARY_LENGTH,
    PayloadFacts,
    SanitisedPayload,
)
from codekavach.core.models.slice import CodeSlice
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import ConsentDecision, RunContext
from codekavach.core.pipeline.items import (
    ITEM_EXCEPTION,
    PRIVACY_PSEUDONYMISE_FAILED,
    PRIVACY_REDACTION_FAILED,
    PRIVACY_VALIDATION_FAILED,
    guard_item,
)
from codekavach.core.pipeline.stage import StageCategory
from codekavach.ingest.models import SourceFile
from codekavach.parsing.callgraph import CallGraph
from codekavach.parsing.symbols import SymbolsArtefact
from codekavach.privacy.detect.pii.builtin import pii_detectors
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_all
from codekavach.privacy.detect.secrets.builtin import register_secret_detectors
from codekavach.privacy.detect.terms import register_term_detector
from codekavach.privacy.egress.session import EgressSession
from codekavach.privacy.errors import PseudonymError, RedactionError
from codekavach.privacy.policy.resolve import PolicyResolver
from codekavach.privacy.pseudonymise.engine import Pseudonymiser
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator
from codekavach.privacy.redact.numbering import PlaceholderNumbering
from codekavach.privacy.redact.redactor import Redactor
from codekavach.privacy.slicing.base import SlicingError
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.metrics import ScanDisclosure
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from codekavach.privacy.slicing.stubs import is_valid_summary
from codekavach.privacy.vault.errors import VaultError
from codekavach.privacy.vault.keys import KeySource
from codekavach.privacy.vault.salt import vault_path
from codekavach.privacy.vault.store import Vault

_log = get_logger("codekavach.privacy.stages")

SLICE_FAILED: Final = "privacy_slice_failed"
VAULT_FAILED: Final = "privacy_vault_failed"
_RULE_UNSAFE: Final = frozenset(
    chr(code) for code in range(128) if not (chr(code).isalnum() or chr(code) in "_.:/-")
)
_COMMENT_MARKS: Final = ("#", "//", "--")
_SINK_CLAUSE: Final = "calls sink family: "


class _FailedError(Exception):
    """One candidate failed at a step; ``code`` is the item error code and the only message."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class _Outcome:
    payload: SanitisedPayload
    slice_: CodeSlice


def _safe_rule(rule_id: str) -> str:
    """``rule_id`` restricted to the characters a prompt fact may hold."""
    cleaned = "".join("_" if char in _RULE_UNSAFE or ord(char) > 127 else char for char in rule_id)
    cleaned = cleaned.lstrip("_.:/-")[:128]
    return cleaned or "unknown"


def _summaries(slice_: CodeSlice) -> tuple[str, ...]:
    """The effect-summary lines the slicer wrote into the stubs, in the fixed grammar only."""
    found: list[str] = []
    for stub in slice_.stubs:
        for line in stub.signature.expose().splitlines():
            text = line.strip()
            for mark in _COMMENT_MARKS:
                if text.startswith(mark):
                    text = text[len(mark) :].strip()
                    break
            else:
                continue
            if len(text) <= MAX_SUMMARY_LENGTH and is_valid_summary(text) and text not in found:
                found.append(text)
    return tuple(found[:MAX_STUB_SUMMARIES])


def _sink_family(summaries: tuple[str, ...]) -> str | None:
    for line in summaries:
        for clause in line.split("; "):
            if clause.startswith(_SINK_CLAUSE):
                return clause[len(_SINK_CLAUSE) :]
    return None


def facts_of(candidate: Candidate, slice_: CodeSlice) -> PayloadFacts:
    """The prompt facts of ``candidate``: rule, CWE, sink family, strategy, stub summaries."""
    summaries = _summaries(slice_)
    return PayloadFacts(
        rule=_safe_rule(candidate.rule_id),
        cwe=tuple(candidate.cwe),
        sink_family=_sink_family(summaries),
        strategy=slice_.strategy.value,
        stub_summaries=summaries,
    )


def detector_registry(settings: Settings) -> DetectorRegistry:
    """The secret, personal-data and domain-term detectors that ``settings`` enable."""
    registry = register_secret_detectors(DetectorRegistry())
    for detector in pii_detectors(tuple(sorted(settings.privacy.pii_locales))):
        registry.register(detector)
    return register_term_detector(registry, settings)


# What each scan's prepare stage has disclosed, handed to the egress session of the same scan. Both
# stages run in one process; a review that finds no entry (a resumed scan) starts from an empty
# record, which the aggregation budget treats as no disclosure.
_DISCLOSURES: dict[str, ScanDisclosure] = {}


@contextmanager
def open_egress_session(
    *,
    settings: Settings,
    state_dir: Path,
    scan_id: str,
    consent: ConsentDecision | None,
    dry_run: bool = False,
) -> Iterator[EgressSession]:
    """An ``EgressSession`` over the scan's vault, closed together with the vault.

    This is the composition point of the egress path. It sits here, in the package that already
    owns the vault for the prepare stage, because the LLM layer may not import the vault even
    indirectly (invariant I3, the record-locality contract); ``llm-review`` reaches it by name at
    run time and receives only the session, which has no way to read a mapping record.
    """
    with (
        Vault(
            vault_path(state_dir),
            KeySource(settings.privacy.vault.key_source),
            settings=settings,
            create=False,
        ) as vault,
        EgressSession(
            settings=settings,
            state_dir=state_dir,
            vault=vault,
            scan_id=scan_id,
            consent=consent,
            dry_run=dry_run,
            disclosure=_DISCLOSURES.pop(scan_id, None),
        ) as session,
    ):
        yield session


class PrivacyPrepareStage:
    """Slices, redacts and pseudonymises every candidate that policy allows to leave."""

    name = "privacy-prepare"
    version = "1"
    requires = frozenset({keys.CANDIDATES, keys.FILES, keys.SYMBOLS, keys.AST})
    optional_requires = frozenset({keys.CALL_GRAPH})
    provides = frozenset({keys.PAYLOADS_SANITISED, keys.SLICES})
    # Sanitised text and raw code are never reloaded from disk, so the store holds them in memory.
    transient_provides = provides
    category = StageCategory.PRIVACY

    def run(self, ctx: RunContext) -> None:
        """Publish one payload and one slice per candidate that succeeded, and fail the rest."""
        candidates = ctx.artefacts.get_list(keys.CANDIDATES, Candidate)
        files = {file.path: file for file in ctx.artefacts.get_list(keys.FILES, SourceFile)}
        symbols = ctx.artefacts.get(keys.SYMBOLS, SymbolsArtefact)
        ast = ctx.artefacts.get_object(keys.AST)
        callgraph = (
            ctx.artefacts.get(keys.CALL_GRAPH, CallGraph)
            if ctx.artefacts.has(keys.CALL_GRAPH)
            else None
        )
        policy = PolicyResolver(ctx.config)
        _, provider = ctx.config.llm.selected_provider()
        tier = provider.effective_trust_tier
        index = ParseIndex(
            files=files,
            ast=ast,  # type: ignore[arg-type]
            symbols=symbols.tables,
            callgraph=callgraph,
            never_send=policy.is_never_send,
        )
        disclosure = ScanDisclosure.for_index(index)
        registry = detector_registry(ctx.config)
        numbering = PlaceholderNumbering(ctx.scan_salt)
        generator = PseudonymGenerator(ctx.scan_salt)
        engine = Pseudonymiser(project_root=ctx.project_root)
        budget = SliceBudget(ctx.config.privacy.slice.max_tokens)
        payloads: list[SanitisedPayload] = []
        slices: list[CodeSlice] = []
        withheld = 0
        if ctx.state_dir is None:
            raise RuntimeError("privacy-prepare needs the state directory of the vault")
        with Vault(
            vault_path(ctx.state_dir),
            KeySource(ctx.config.privacy.vault.key_source),
            settings=ctx.config,
            create=True,
        ) as vault:
            for done, candidate in enumerate(candidates, start=1):
                ctx.check_cancelled()
                path = candidate.locations[0].path
                level = policy.effective_level(path, tier)
                if policy.is_never_send(path) or level is PrivacyLevel.L0:
                    withheld += 1
                    continue
                with guard_item(ctx, str(candidate.id), ITEM_EXCEPTION):
                    try:
                        outcome = self._one(
                            ctx,
                            candidate,
                            level,
                            index=index,
                            budget=budget,
                            registry=registry,
                            numbering=numbering,
                            generator=generator,
                            engine=engine,
                            vault=vault,
                        )
                    except _FailedError as failure:
                        ctx.fail_item(str(candidate.id), failure.code)
                        continue
                    disclosure.record(outcome.slice_, index)
                    payloads.append(outcome.payload)
                    slices.append(outcome.slice_)
                if done % 25 == 0:
                    ctx.emit_progress(done, len(candidates), "candidates")
        ctx.emit_progress(len(candidates), len(candidates), "candidates")
        _log.info(
            "payloads_prepared",
            prepared=len(payloads),
            withheld=withheld,
            candidates=len(candidates),
        )
        _DISCLOSURES[ctx.scan_id] = disclosure
        ctx.artefacts.put(keys.SLICES, slices, persist=False)
        ctx.artefacts.put(keys.PAYLOADS_SANITISED, payloads, persist=False)

    @staticmethod
    def _one(
        ctx: RunContext,
        candidate: Candidate,
        level: PrivacyLevel,
        *,
        index: ParseIndex,
        budget: SliceBudget,
        registry: DetectorRegistry,
        numbering: PlaceholderNumbering,
        generator: PseudonymGenerator,
        engine: Pseudonymiser,
        vault: Vault,
    ) -> _Outcome:
        try:
            slice_ = EnclosingFunctionStrategy().build(candidate, index, budget=budget)
        except (SlicingError, KeyError):
            raise _FailedError(SLICE_FAILED) from None
        try:
            layout = engine.layout(slice_, level)
            spans = detect_all(
                RawCode(layout.text),
                path=candidate.locations[0].path,
                language=slice_.language,
                settings=ctx.config,
                registry=registry,
            )
            redaction = Redactor().redact(layout.text, spans, numbering=numbering)
        except RedactionError:
            raise _FailedError(PRIVACY_REDACTION_FAILED) from None
        try:
            result = engine.process(
                slice_,
                redaction,
                salt=ctx.scan_salt,
                level=level,
                scan_id=ctx.scan_id,
                generator=generator,
            )
        except (PseudonymError, NotImplementedError):
            raise _FailedError(PRIVACY_PSEUDONYMISE_FAILED) from None
        try:
            vault.put(result.batch)
        except VaultError:
            raise _FailedError(VAULT_FAILED) from None
        try:
            payload = result.payload.model_copy(update={"facts": facts_of(candidate, slice_)})
        except ValueError:
            raise _FailedError(PRIVACY_VALIDATION_FAILED) from None
        return _Outcome(payload, slice_)
