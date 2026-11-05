"""Register the personal-data detectors that ``privacy.pii_locales`` enables.

Owning epic: E08.
"""

from collections.abc import Collection

from codekavach.privacy.detect.pii.formats import PiiDetector, formats_for
from codekavach.privacy.detect.registry import DetectorRegistry


def pii_detectors(locales: Collection[str]) -> tuple[PiiDetector, ...]:
    """One detector per format that ``locales`` enable.

    Raises:
        UnknownLocale: ``locales`` holds an entry that is not a known locale.
    """
    return tuple(PiiDetector(item) for item in formats_for(locales))


def register_pii_detectors(
    registry: DetectorRegistry, locales: Collection[str]
) -> DetectorRegistry:
    """Add the detectors of ``locales`` to ``registry`` and return it."""
    for detector in pii_detectors(locales):
        registry.register(detector)
    return registry
