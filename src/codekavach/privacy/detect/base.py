"""``TypedSpan`` and the ``Detector`` protocol.

Owning epic: E08.

A detector reads one text and returns spans: a kind, a subtype from the closed vocabulary, a
byte range, a confidence and its own id. A span carries **no matched text**, so a ``TypedSpan``
can be logged, compared and stored without exposing the value it points at; the value is read
from the text again, by the redactor, at the moment it is replaced.

``downgraded`` marks a span whose confidence a detector lowered on purpose, for instance a value
that occurs so often in a scan that it is probably boilerplate. ``Confidence`` has no level below
``LOW``, so the flag is how the lowering stays visible: the span is kept (recall first), it is
counted in ``DetectionReport.downgraded``, and a raised floor drops it with the other ``LOW`` spans.

Offsets are **byte offsets into the UTF-8 encoding** of the text, which is how tree-sitter and
the regular-expression engines over bytes report them. The redactor checks that every boundary
falls on a character boundary and fails closed otherwise.
"""

import re
from collections.abc import Sequence
from typing import ClassVar, Protocol, Self, runtime_checkable

from pydantic import Field, model_validator

from codekavach.core.models import (
    Confidence,
    DataClassification,
    KavachModel,
    Language,
    PlaceholderKind,
    RawCode,
    RepoPath,
)
from codekavach.privacy.detect.vocabulary import validate_subtype

SUBTYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
DETECTOR_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")


class TypedSpan(KavachModel):
    """One detected value: where it is and what type of thing it is, never what it says."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    kind: PlaceholderKind
    subtype: str
    start_byte: int = Field(ge=0)
    end_byte: int
    confidence: Confidence
    detector: str
    downgraded: bool = False

    @model_validator(mode="after")
    def _check(self) -> Self:
        if not self.start_byte < self.end_byte:
            raise ValueError("a span needs 0 <= start_byte < end_byte")
        if not SUBTYPE_PATTERN.match(self.subtype):
            raise ValueError("the subtype must match [a-z][a-z0-9_]{0,47}")
        validate_subtype(self.kind, self.subtype)
        if not DETECTOR_ID_PATTERN.match(self.detector):
            raise ValueError("the detector id must match [a-z][a-z0-9_.]{0,63}")
        return self

    @property
    def length(self) -> int:
        """The length of the span in bytes."""
        return self.end_byte - self.start_byte


@runtime_checkable
class Detector(Protocol):
    """Finds values of one or more kinds in a text.

    ``id`` is unique and stable (``secret.pattern``); ``kinds`` lists every kind the detector may
    emit. ``detect`` returns spans in any order and may return overlapping ones: resolution is
    the framework's job (``resolve_overlaps``), so a detector reports everything it matched.
    """

    id: str
    kinds: frozenset[PlaceholderKind]

    def detect(self, text: RawCode, *, path: RepoPath, language: Language) -> Sequence[TypedSpan]:
        """Return the spans found in ``text``."""
        ...
