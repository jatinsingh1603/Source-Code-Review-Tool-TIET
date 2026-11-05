"""The real PII and domain-term detectors, set up the way the corpus tests use them (E08-03).

The corpus cases named ``pii_*`` and ``terms_*`` have labels written from these detectors, and a
test checks that they still reproduce them, so the labels cannot drift from the code. The terms
are the synthetic business vocabulary of ``tests/support/synthetic.py``.
"""

from typing import Final

from codekavach.config.models.root import Settings
from codekavach.core.models import Language, RawCode
from codekavach.privacy.detect.base import Detector, TypedSpan
from codekavach.privacy.detect.overlap import resolve_overlaps
from codekavach.privacy.detect.pii.builtin import pii_detectors
from codekavach.privacy.detect.terms import DomainTermDetector
from tests.support.synthetic import SYNTHETIC_TERMS

CORPUS_PATH: Final = "data/records.txt"
CORPUS_LOCALES: Final = ("intl", "in", "passport")
CORPUS_PREFIXES: Final = ("pii_", "terms_")


def corpus_settings() -> Settings:
    """Settings whose ``privacy.domain_terms`` are the synthetic terms."""
    return Settings.model_validate(
        {
            "privacy": {
                "pii_locales": list(CORPUS_LOCALES),
                "domain_terms": [entry.value for entry in SYNTHETIC_TERMS],
            }
        }
    )


def real_detected(text: str) -> tuple[TypedSpan, ...]:
    """Everything the PII and term detectors report in ``text``, overlaps included."""
    settings = corpus_settings()
    detectors: tuple[Detector, ...] = (
        *pii_detectors(settings.privacy.pii_locales),
        DomainTermDetector.from_settings(settings),
    )
    spans: list[TypedSpan] = []
    for detector in detectors:
        spans.extend(detector.detect(RawCode(text), path=CORPUS_PATH, language=Language.UNKNOWN))
    return tuple(sorted(spans, key=lambda s: (s.start_byte, s.end_byte, s.subtype)))


def real_resolved(text: str) -> tuple[TypedSpan, ...]:
    """What :func:`real_detected` leaves after overlap resolution."""
    return tuple(resolve_overlaps(real_detected(text)))
