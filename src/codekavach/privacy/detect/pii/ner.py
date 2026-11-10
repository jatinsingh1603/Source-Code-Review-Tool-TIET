"""``NerDetector``: person, organisation and location names from an offline language model.

Owning epic: E08.

An optional layer on top of the native format detectors (E08-03), which find values that have a
shape (a card number, an Aadhaar number). A name has no shape, so this detector asks a
named-entity recogniser. It is **not imported by the package** and **never registered by the
native set**: a caller registers it with :func:`register_ner_detector`, which does nothing unless
``privacy.pii_locales`` is non-empty.

The recogniser is spaCy with a model package such as ``en_core_web_sm``, both installed by the
client into the same environment. The model must already be on disk: nothing is downloaded at run
time, so an air-gapped host cannot fail silently. When the library or the model is missing,
:meth:`NerDetector.detect` returns no spans and the process logs a single warning that names the
extra; ``codekavach doctor`` reports the same condition at setup (check
``privacy:ner-model``).

The detector reads the text it is given. The privacy layer passes slices, never a whole
repository, which is what keeps a statistical pipeline affordable. It emits ``MEDIUM``
confidence: a model is evidence, not a format. The ``nric_or_national_id`` subtype is part of the
vocabulary for models that recognise it; the default English pipeline does not, so it is not
produced by it.
"""

import importlib
from collections.abc import Callable, Collection, Iterator, Sequence
from typing import Any, Final, Protocol

from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode, RepoPath
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.offsets import ByteOffsets
from codekavach.privacy.detect.optional import NER_EXTRA, module_present, warn_unavailable
from codekavach.privacy.detect.registry import DetectorRegistry

DEFAULT_MODEL: Final = "en_core_web_sm"
MIN_ENTITY_CHARS: Final = 3
CHUNK_CHARS: Final = 50_000
LABELS: Final = {
    "PERSON": "person_name",
    "ORG": "organisation",
    "GPE": "location",
    "LOC": "location",
    "FAC": "location",
    "NRIC": "nric_or_national_id",
    "NATIONAL_ID": "nric_or_national_id",
}


class Pipeline(Protocol):
    """The part of a spaCy ``Language`` the detector calls."""

    def __call__(self, text: str) -> Any:
        """Process ``text``; the result has an ``ents`` sequence of entity spans."""
        ...


def ner_status(model: str = DEFAULT_MODEL) -> str:
    """``"ready"``, ``"library missing"`` or ``"model missing"``, without loading anything."""
    if not module_present("spacy"):
        return "library missing"
    if not module_present(model):
        return "model missing"
    return "ready"


def _load(model: str) -> Pipeline:
    spacy = importlib.import_module("spacy")
    loaded: Pipeline = spacy.load(model)
    return loaded


def _chunks(text: str) -> Iterator[tuple[int, str]]:
    """``(character offset, piece)`` of ``text``, cut at line ends so no name is split."""
    start = 0
    while start < len(text):
        end = min(len(text), start + CHUNK_CHARS)
        if end < len(text):
            cut = text.rfind("\n", start, end)
            end = cut + 1 if cut > start else end
        yield start, text[start:end]
        start = end


class NerDetector:
    """Names of people, organisations and places, found by a locally installed model."""

    id = "pii.ner"
    kinds = frozenset({PlaceholderKind.PII})

    def __init__(
        self, model: str = DEFAULT_MODEL, *, loader: Callable[[str], Pipeline] = _load
    ) -> None:
        self._model = model
        self._loader = loader
        self._pipeline: Pipeline | None = None
        self._failed = False

    def available(self) -> bool:
        """Whether the library and the model are installed."""
        return ner_status(self._model) == "ready"

    def _get(self) -> Pipeline | None:
        if self._pipeline is not None or self._failed:
            return self._pipeline
        status = ner_status(self._model)
        if status != "ready":
            self._failed = True
            warn_unavailable("pii.ner", NER_EXTRA, reason=status)
            return None
        try:
            self._pipeline = self._loader(self._model)
        except Exception:  # noqa: BLE001 - the library may raise anything, and the message may name paths
            self._failed = True
            warn_unavailable("pii.ner", NER_EXTRA, reason="model could not be loaded")
        return self._pipeline

    def detect(self, text: RawCode, *, path: RepoPath, language: Language) -> Sequence[TypedSpan]:
        """Entity spans of ``text``; none, with one warning, when the model is not installed."""
        del path, language
        pipeline = self._get()
        if pipeline is None:
            return ()
        raw = text.expose()
        offsets = ByteOffsets(raw)
        spans: list[TypedSpan] = []
        for base, piece in _chunks(raw):
            for entity in pipeline(piece).ents:
                subtype = LABELS.get(entity.label_)
                if subtype is None or entity.end_char - entity.start_char < MIN_ENTITY_CHARS:
                    continue
                spans.append(
                    TypedSpan(
                        kind=PlaceholderKind.PII,
                        subtype=subtype,
                        start_byte=offsets.at(base + entity.start_char),
                        end_byte=offsets.at(base + entity.end_char),
                        confidence=Confidence.MEDIUM,
                        detector=self.id,
                    )
                )
        return spans


def ner_detectors(
    locales: Collection[str], *, model: str = DEFAULT_MODEL
) -> tuple[NerDetector, ...]:
    """The NER detector when ``privacy.pii_locales`` names at least one locale, else none."""
    return (NerDetector(model),) if locales else ()


def register_ner_detector(
    registry: DetectorRegistry, locales: Collection[str], *, model: str = DEFAULT_MODEL
) -> DetectorRegistry:
    """Add the NER detector to ``registry`` when ``locales`` is non-empty; return ``registry``."""
    for detector in ner_detectors(locales, model=model):
        registry.register(detector)
    return registry
