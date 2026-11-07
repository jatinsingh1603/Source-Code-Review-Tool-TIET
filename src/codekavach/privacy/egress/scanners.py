"""The six leak scanners the egress guard runs over the final request body (invariant I6).

Owning epic: E12 (issue E12-02). They satisfy ``LeakScanner`` from ``guard`` and report hits as a
count and an offset, never as text.

======================  ===================  ==================================================
scanner id              block code           what it checks
======================  ===================  ==================================================
``residual_secret``     ``residual_secret``  the E08 secret detectors, run again on the body
``residual_pii``        ``residual_pii``     the E08 personal-data detectors, run again
``vault_original``      ``vault_identifier`` every original of 4+ characters the vault holds
``domain_term``         ``domain_term``      ``privacy.domain_terms``, matched as E08-03 matches
``budget``              ``size_budget``,     body size, and a token bucket per provider
                        ``rate_budget``
``aggregation``         ``aggregation_budget``  the union share of the repository disclosed
======================  ===================  ==================================================

**Why detect again.** Redaction ran on the slice; the body holds more than the slice. A template
variable, a schema description or a bug in payload assembly can add a value that never passed the
redactor, and a check is only meaningful if it is independent of the step it checks. The detectors
use the same confidence floor as redaction (``privacy.detect.min_confidence``), so a value that
redaction would have replaced and did not is a hit; a false positive here blocks a request, which is
why the floor is the one knob and why a block never quotes the value.

**The vault automaton.** One ``AhoCorasick`` (the class of E08-03, not a second one) is built per
scan from ``vault.iter_originals(min_len=4)``, minus names on the public allowlist, minus tokens
of the pseudonym grammar, minus the words of the placeholder vocabulary. It is the most sensitive
structure in the process after the vault: the scanner keeps nothing else (no list of originals),
nothing serialises it (``__ck_never_persist__``), it has no accessor that returns a pattern, and
``release`` drops it when the scan ends. Matching is a case-insensitive substring match over the
normalised views of ``textview`` (JSON-unescaped, zero-width characters removed, lookalike
letters folded), which also finds the case-sensitive form. It is a verbatim check with
normalisation, not a semantic one.

**Cost.** A vault original that is an ordinary word (``value``, ``result``) blocks a body that
contains that word anywhere, including in the instruction text around the payload. That is the
price of a substring check that does not trust where in the body a name sits; a stage that builds
the instruction text should avoid vocabulary that its own scan renamed.

**Rebuilds.** The automaton is built by ``warm`` before the first request. When the vault holds a
different number of originals at a later request (a context round added mappings), it is rebuilt,
because a stale automaton would pass a new original.
"""

import re
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from typing import Final

from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.core.models import Language, PlaceholderKind, RawCode
from codekavach.privacy.detect.pii.builtin import pii_detectors
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_with_report
from codekavach.privacy.detect.secrets.builtin import register_secret_detectors
from codekavach.privacy.detect.terms import MIN_TERM_LENGTH, AhoCorasick, DomainTermDetector, fold
from codekavach.privacy.detect.vocabulary import VOCABULARY
from codekavach.privacy.egress.guard import (
    BoundScanner,
    LeakScanner,
    ScannerRegistry,
    VaultOriginals,
)
from codekavach.privacy.egress.models import EgressMeta, LeakHit
from codekavach.privacy.egress.textview import forget, normalise, view_of
from codekavach.privacy.pseudonymise.allowlist import NoAllowlistError, PublicAllowlist
from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.slicing.metrics import ScanDisclosure

_log = get_logger("codekavach.privacy.egress")
MIN_ORIGINAL_LENGTH: Final = 4  # invariant I6's own threshold
SCANNER_IDS: Final = (
    "aggregation",
    "budget",
    "domain_term",
    "residual_pii",
    "residual_secret",
    "vault_original",
)
_PATH: Final = "request-body"
_WORD: Final = re.compile(r"[\w$]+")
_TOKEN: Final = re.compile(
    "(?:" + "|".join(kind.value for kind in PseudonymKind) + r")_[0-9]+(?:_[a-z]+)?"
)
_PLACEHOLDER_WORDS: Final = frozenset(
    {kind.value.casefold() for kind in PlaceholderKind}
    | {word.casefold() for words in VOCABULARY.values() for word in words}
)


def _hit(scanner_id: str, code: str, count: int, first: int) -> tuple[LeakHit, ...]:
    return (LeakHit(scanner_id=scanner_id, block_code=code, count=count, first_offset=first),)


# --- residual secrets and personal data -----------------------------------------------------


class _DetectorScanner:
    """Runs a detector registry again over the body and reports spans of one kind."""

    id: str
    __ck_never_persist__ = True

    def __init__(self, scanner_id: str, block_code: str, kind: PlaceholderKind) -> None:
        self.id = scanner_id
        self._code = block_code
        self._kind = kind
        self._settings: Settings | None = None
        self._registry: DetectorRegistry | None = None
        self._registry_key: object = None

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def _registry_for(self, settings: Settings) -> tuple[DetectorRegistry, object]:
        raise NotImplementedError

    def bind(self, vault: VaultOriginals | None, settings: Settings) -> None:
        """Receive the settings; the registry is rebuilt only when they change what it holds."""
        registry, key = self._registry_for(settings)
        if self._registry is None or key != self._registry_key:
            self._registry, self._registry_key = registry, key
        self._settings = settings

    def scan(self, body: bytes, meta: EgressMeta) -> Sequence[LeakHit]:
        """Hits as a count and the byte offset of the first, in the unescaped view of the body."""
        if self._settings is None or self._registry is None:
            raise RuntimeError("scanner used before it was bound")
        spans, _ = detect_with_report(
            RawCode(view_of(body).strings),
            path=_PATH,
            language=Language.UNKNOWN,
            settings=self._settings,
            registry=self._registry,
        )
        found = [span for span in spans if span.kind is self._kind]
        if not found:
            return ()
        return _hit(self.id, self._code, len(found), min(span.start_byte for span in found))


class ResidualSecretScanner(_DetectorScanner):
    """The E08-02 pattern, assignment and entropy detectors, run again on the body."""

    def __init__(self) -> None:
        super().__init__("residual_secret", "residual_secret", PlaceholderKind.SECRET)
        self._built: DetectorRegistry | None = None

    def _registry_for(self, settings: Settings) -> tuple[DetectorRegistry, object]:
        if self._built is None:
            self._built = register_secret_detectors(DetectorRegistry())
        return self._built, "secrets"


class ResidualPiiScanner(_DetectorScanner):
    """The E08-03 personal-data detectors for ``privacy.pii_locales``, run again on the body.

    The checksum-validated formats (card numbers, Aadhaar, PAN, IBAN) are exact; the others
    (phone numbers, dates of birth) can match innocent text. The confidence floor
    ``privacy.detect.min_confidence`` decides which are reported, the same floor redaction uses.
    """

    def __init__(self) -> None:
        super().__init__("residual_pii", "residual_pii", PlaceholderKind.PII)

    def _registry_for(self, settings: Settings) -> tuple[DetectorRegistry, object]:
        locales = tuple(sorted(settings.privacy.pii_locales))
        registry = DetectorRegistry()
        for detector in pii_detectors(locales):
            registry.register(detector)
        return registry, locales


# --- the vault automaton ----------------------------------------------------------------------


class OriginalMatcher:
    """A case-insensitive substring matcher over normalised patterns; it answers counts only.

    Patterns made of word characters only can sit inside one run of word characters, so they are
    matched against the distinct runs of the text and the result is multiplied by how often each
    run occurs. A pattern with spaces or punctuation is matched against the whole text. There is
    no method that returns a pattern, and the object never persists.
    """

    __slots__ = ("_other", "_words")
    __ck_never_persist__ = True

    def __init__(self, patterns: Iterable[str]) -> None:
        words: list[str] = []
        other: list[str] = []
        for pattern in dict.fromkeys(patterns):
            (words if _WORD.fullmatch(pattern) else other).append(pattern)
        self._words = AhoCorasick(words) if words else None
        self._other = AhoCorasick(other) if other else None

    def __repr__(self) -> str:
        return "OriginalMatcher(<patterns>)"

    def __len__(self) -> int:
        return sum(len(part) for part in (self._words, self._other) if part is not None)

    def scan(self, text: str) -> tuple[int, int]:
        """``(count, first_offset)`` over ``text``; ``(0, -1)`` when nothing matches."""
        count, first = 0, -1
        if self._words is not None:
            runs: dict[str, list[int]] = {}
            for match in _WORD.finditer(text):
                seen = runs.get(match.group())
                if seen is None:
                    runs[match.group()] = [1, match.start()]
                else:
                    seen[0] += 1
            for run, (times, position) in runs.items():
                for start, _end, _index in self._words.finditer(run):
                    count += times
                    if first < 0 or position + start < first:
                        first = position + start
        if self._other is not None:
            for start, _end, _index in self._other.finditer(text):
                count += 1
                if first < 0 or start < first:
                    first = start
        return count, first


def _public_names(settings: Settings) -> tuple[list[PublicAllowlist], frozenset[str]]:
    """The allowlists of every language that has one, and the names they list as members."""
    lists: list[PublicAllowlist] = []
    members: set[str] = set()
    for language in Language:
        try:
            allowlist = PublicAllowlist.from_settings(language, settings)
        except NoAllowlistError:
            continue
        lists.append(allowlist)
        for package in allowlist.package_names():
            members.update(allowlist.members_of(package))
    return lists, frozenset(members)


def _kept(original: str, lists: list[PublicAllowlist], members: frozenset[str]) -> bool:
    """Whether ``original`` is checked: not public, not a pseudonym, not a placeholder word."""
    if len(original) < MIN_ORIGINAL_LENGTH or original in members:
        return False
    if _TOKEN.fullmatch(original.casefold()) or original.casefold() in _PLACEHOLDER_WORDS:
        return False
    return not any(allowlist.is_public(original) for allowlist in lists)


class VaultOriginalScanner:
    """Blocks a body that contains an original identifier, literal or secret the vault holds."""

    id = "vault_original"
    __ck_never_persist__ = True

    def __init__(self) -> None:
        self._matcher: OriginalMatcher | None = None
        self._signature: int | None = None
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "VaultOriginalScanner()"

    def warm(self, vault: VaultOriginals, settings: Settings) -> None:
        """Build the automaton now, so the first request does not pay for it."""
        self._ensure(vault, settings)

    def release(self) -> None:
        """Drop the automaton (the scan is over)."""
        with self._lock:
            self._matcher = None
            self._signature = None

    def bind(self, vault: VaultOriginals | None, settings: Settings) -> None:
        """Receive the vault; rebuilds the automaton if the vault changed since it was built."""
        if vault is None:
            raise RuntimeError("the vault scanner needs the vault")
        self._ensure(vault, settings)

    @staticmethod
    def _signature_of(vault: VaultOriginals) -> int | None:
        count = getattr(vault, "original_count", None)
        return int(count(MIN_ORIGINAL_LENGTH)) if callable(count) else None

    def _ensure(self, vault: VaultOriginals, settings: Settings) -> None:
        signature = self._signature_of(vault)
        with self._lock:
            if self._matcher is not None and (signature is None or signature == self._signature):
                return
            started = time.perf_counter()
            lists, members = _public_names(settings)
            patterns: dict[str, None] = {}
            for original in vault.iter_originals(min_len=MIN_ORIGINAL_LENGTH):
                if _kept(original, lists, members):
                    folded = normalise(original)
                    if len(folded) >= MIN_ORIGINAL_LENGTH:
                        patterns[folded] = None
            self._matcher = OriginalMatcher(patterns)
            self._signature = signature
            patterns.clear()
            _log.info(
                "egress_vault_automaton_built",
                patterns=len(self._matcher),
                elapsed_ms=round((time.perf_counter() - started) * 1000),
            )

    def scan(self, body: bytes, meta: EgressMeta) -> Sequence[LeakHit]:
        """Hits as a count and the first offset in the view that matched; never the text."""
        matcher = self._matcher
        if matcher is None:
            raise RuntimeError("the vault automaton has not been built")
        count, first = _best(matcher.scan(text) for text in view_of(body).matching_texts())
        return _hit(self.id, "vault_identifier", count, first) if count else ()


def _best(results: Iterable[tuple[int, int]]) -> tuple[int, int]:
    """The largest count over the views and the earliest offset among the views that matched."""
    count, first = 0, -1
    for found, at in results:
        count = max(count, found)
        if found and (first < 0 or at < first):
            first = at
    return count, first


# --- domain terms -----------------------------------------------------------------------------


class DomainTermScanner:
    """Blocks a body that contains a configured domain term, matched as E08-03 matches it."""

    id = "domain_term"
    __ck_never_persist__ = True
    _PREFILTER_LIMIT = 128

    def __init__(self) -> None:
        self._detector: DomainTermDetector | None = None
        self._terms: tuple[str, ...] = ()
        self._folded: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return "DomainTermScanner()"

    def bind(self, vault: VaultOriginals | None, settings: Settings) -> None:
        """Receive the settings; the detector is rebuilt only when the term list changed."""
        terms = tuple(settings.privacy.domain_terms)
        if self._detector is None or terms != self._terms:
            self._detector = DomainTermDetector(terms)
            self._terms = terms
            self._folded = tuple(
                form
                for form in dict.fromkeys(fold(term) for term in terms)
                if len(form) >= MIN_TERM_LENGTH
            )

    def _present(self, text: str) -> bool:
        """A cheap necessary condition, so the automaton runs only when a term can be there."""
        if len(self._folded) > self._PREFILTER_LIMIT:
            return True
        compact = fold(text)
        return any(form in compact for form in self._folded)

    def scan(self, body: bytes, meta: EgressMeta) -> Sequence[LeakHit]:
        """Hits as a count and the byte offset of the first, in the normalised view."""
        detector = self._detector
        if detector is None:
            raise RuntimeError("scanner used before it was bound")
        if not self._folded:
            return ()
        results: list[tuple[int, int]] = []
        for text in view_of(body).matching_texts():
            if not self._present(text):
                results.append((0, -1))
                continue
            spans = detector.detect(RawCode(text), path=_PATH, language=Language.UNKNOWN)
            results.append((len(spans), min((s.start_byte for s in spans), default=-1)))
        count, first = _best(results)
        return _hit(self.id, "domain_term", count, first) if count else ()


# --- size and rate ----------------------------------------------------------------------------


class _Bucket:
    """A token bucket: ``capacity`` tokens, refilled at ``capacity`` per 60 seconds."""

    __slots__ = ("capacity", "stamp", "tokens")

    def __init__(self, capacity: int, now: float) -> None:
        self.capacity = capacity
        self.tokens = float(capacity)
        self.stamp = now

    def take(self, capacity: int, now: float) -> bool:
        if capacity != self.capacity:  # the limit was changed in settings
            self.tokens = min(self.tokens, float(capacity))
            self.capacity = capacity
        self.tokens = min(float(capacity), self.tokens + (now - self.stamp) * capacity / 60.0)
        self.stamp = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class BudgetScanner:
    """Blocks a body over ``max_payload_bytes`` and a request over ``rate_per_minute``.

    The bucket is held per provider and lives as long as the scanner, which the stage creates per
    scan. A request the guard blocks for another reason still takes a token: a runaway loop is a
    runaway disclosure whatever stops it.
    """

    id = "budget"
    __ck_never_persist__ = True

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._settings: Settings | None = None
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "BudgetScanner()"

    def bind(self, vault: VaultOriginals | None, settings: Settings) -> None:
        """Receive the settings whose limits apply."""
        self._settings = settings

    def scan(self, body: bytes, meta: EgressMeta) -> Sequence[LeakHit]:
        """``size_budget`` and ``rate_budget`` hits; the offset is the limit that was passed."""
        if self._settings is None:
            raise RuntimeError("scanner used before it was bound")
        egress = self._settings.privacy.egress
        hits: list[LeakHit] = []
        if len(body) > egress.max_payload_bytes:
            hits.extend(_hit(self.id, "size_budget", 1, egress.max_payload_bytes))
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(meta.provider)
            if bucket is None:
                bucket = self._buckets[meta.provider] = _Bucket(egress.rate_per_minute, now)
            allowed = bucket.take(egress.rate_per_minute, now)
        if not allowed:
            hits.extend(_hit(self.id, "rate_budget", 1, egress.rate_per_minute))
        return tuple(hits)


# --- aggregation ------------------------------------------------------------------------------


class AggregationScanner:
    """Blocks a request once the union share of the repository disclosed passes the ceiling.

    ``disclosure_for(provider)`` returns the scan's ``ScanDisclosure`` for that provider (the
    stage may keep one per provider; by default one record serves all). The slice of this request
    is already in the record, because slices are recorded when they are prepared, so the check is
    the record's share against ``privacy.egress.aggregation_budget_pct``. At the default of 100
    percent it never blocks: the control is off until it is configured, and nothing here presents
    it as protection.
    """

    id = "aggregation"
    __ck_never_persist__ = True

    def __init__(
        self,
        disclosure: ScanDisclosure,
        *,
        disclosure_for: Callable[[str], ScanDisclosure] | None = None,
    ) -> None:
        self._disclosure_for = disclosure_for or (lambda _provider: disclosure)
        self._settings: Settings | None = None

    def __repr__(self) -> str:
        return "AggregationScanner()"

    def bind(self, vault: VaultOriginals | None, settings: Settings) -> None:
        """Receive the settings whose ceiling applies."""
        self._settings = settings

    def scan(self, body: bytes, meta: EgressMeta) -> Sequence[LeakHit]:
        """One ``aggregation_budget`` hit when the share is over the ceiling."""
        if self._settings is None:
            raise RuntimeError("scanner used before it was bound")
        ceiling = self._settings.privacy.egress.aggregation_budget_pct
        share = self._disclosure_for(meta.provider).repo_pct
        if share <= ceiling:
            return ()
        return _hit(self.id, "aggregation_budget", 1, round(share))


# --- registration -------------------------------------------------------------------------------


def default_scanners(
    disclosure: ScanDisclosure,
    *,
    disclosure_for: Callable[[str], ScanDisclosure] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[LeakScanner, ...]:
    """A fresh set of the six scanners, for one scan."""
    return (
        ResidualSecretScanner(),
        VaultOriginalScanner(),
        DomainTermScanner(),
        ResidualPiiScanner(),
        BudgetScanner(clock),
        AggregationScanner(disclosure, disclosure_for=disclosure_for),
    )


def register_default_scanners(
    registry: ScannerRegistry,
    disclosure: ScanDisclosure,
    *,
    disclosure_for: Callable[[str], ScanDisclosure] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> ScannerRegistry:
    """Add the six scanners to ``registry`` and return it."""
    for scanner in default_scanners(disclosure, disclosure_for=disclosure_for, clock=clock):
        registry.register(scanner)
    return registry


def warm(registry: ScannerRegistry, vault: VaultOriginals, settings: Settings) -> None:
    """Build what the scanners build lazily (the vault automaton), off the first request's path."""
    for scanner in registry:
        if isinstance(scanner, VaultOriginalScanner):
            scanner.warm(vault, settings)
        elif isinstance(scanner, BoundScanner):
            scanner.bind(vault, settings)


def release(registry: ScannerRegistry) -> None:
    """Drop the automaton and the cached body: the scan is over."""
    for scanner in registry:
        if isinstance(scanner, VaultOriginalScanner):
            scanner.release()
    forget()


__all__ = [
    "SCANNER_IDS",
    "AggregationScanner",
    "BudgetScanner",
    "DomainTermScanner",
    "OriginalMatcher",
    "ResidualPiiScanner",
    "ResidualSecretScanner",
    "VaultOriginalScanner",
    "default_scanners",
    "register_default_scanners",
    "release",
    "warm",
]
