"""``DetectorRegistry``: the detectors a scan runs.

Owning epic: E08.

Built-in detectors are registered by the epic's own modules (E08-02 to E08-04); a third party
adds one through the ``codekavach.detectors`` entry-point group, which
:meth:`DetectorRegistry.from_plugins` reads through the plugin registry (E04-04). A plugin that
does not satisfy the :class:`~codekavach.privacy.detect.base.Detector` protocol is skipped with a
warning, never half-registered. There is no setting that turns a detector off (ADR decision D8:
no off switches for redaction); the confidence floor is the one knob.
"""

from collections.abc import Iterable
from typing import Any, Self, cast

from codekavach.core.log import get_logger
from codekavach.core.models import PlaceholderKind
from codekavach.core.plugins.registry import PluginRegistry
from codekavach.privacy.detect.base import DETECTOR_ID_PATTERN, Detector

_log = get_logger("codekavach.privacy.detect")


def _check(detector: Detector) -> Detector:
    """Validate a detector at run time: plugins are not type-checked by us."""
    candidate: Any = detector
    if not isinstance(candidate, Detector):
        raise TypeError("a detector needs id, kinds and detect")
    identifier: Any = candidate.id
    if not isinstance(identifier, str) or not DETECTOR_ID_PATTERN.match(identifier):
        raise ValueError("the detector id must match [a-z][a-z0-9_.]{0,63}")
    kinds: Any = candidate.kinds
    if not isinstance(kinds, frozenset) or not kinds:
        raise ValueError("a detector declares a non-empty frozenset of kinds")
    if not all(isinstance(kind, PlaceholderKind) for kind in kinds):
        raise ValueError("a detector's kinds are PlaceholderKind members")
    return detector


class DetectorRegistry:
    """Detectors by id; iteration order is the sorted id, so results do not depend on it."""

    def __init__(self, detectors: Iterable[Detector] = ()) -> None:
        self._detectors: dict[str, Detector] = {}
        for detector in detectors:
            self.register(detector)

    def register(self, detector: Detector) -> None:
        """Add ``detector``.

        Raises:
            TypeError: ``detector`` does not satisfy the protocol.
            ValueError: its id or kinds are invalid, or the id is already registered.
        """
        checked = _check(detector)
        if checked.id in self._detectors:
            raise ValueError("a detector with this id is already registered")
        self._detectors[checked.id] = checked

    def all(self) -> tuple[Detector, ...]:
        """Every detector, sorted by id."""
        return tuple(self._detectors[key] for key in sorted(self._detectors))

    def for_kind(self, kind: PlaceholderKind) -> tuple[Detector, ...]:
        """Every detector that may emit ``kind``, sorted by id."""
        return tuple(d for d in self.all() if kind in d.kinds)

    @classmethod
    def from_plugins(cls, plugins: PluginRegistry, builtins: Iterable[Detector] = ()) -> Self:
        """The ``builtins`` plus every valid plugin of the ``codekavach.detectors`` group."""
        registry = cls(builtins)
        for name, instance in sorted(plugins.detectors().items()):
            try:
                registry.register(cast("Detector", instance))  # validated inside
            except (TypeError, ValueError) as error:
                _log.warning(
                    "detector_plugin_skipped", plugin=name, error_type=type(error).__name__
                )
        return registry
