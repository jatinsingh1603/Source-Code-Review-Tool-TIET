"""Register ``secret.pattern``, ``secret.assignment`` and ``secret.entropy``.

Owning epic: E08.
"""

from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.secrets.assignment import AssignmentDetector
from codekavach.privacy.detect.secrets.entropy import EntropyDetector
from codekavach.privacy.detect.secrets.patterns import PatternDetector
from codekavach.privacy.detect.secrets.stats import ScanSecretStats


def secret_detectors(
    stats: ScanSecretStats | None = None,
) -> tuple[PatternDetector, AssignmentDetector, EntropyDetector]:
    """The built-in secret detectors; ``stats`` feeds the entropy detector's repetition filter."""
    return PatternDetector(), AssignmentDetector(), EntropyDetector(stats)


def register_secret_detectors(
    registry: DetectorRegistry, stats: ScanSecretStats | None = None
) -> DetectorRegistry:
    """Add the built-in secret detectors to ``registry`` and return it."""
    for detector in secret_detectors(stats):
        registry.register(detector)
    return registry
