"""The secret-detector corpus (E08-02): templates, a ground-truth manifest and a loader.

``tests/fixtures/detect/secrets/manifest.json`` lists every case: the template file under
``positive/`` or ``negative/``, the logical path and language the detectors are given, and for a
positive case each planted value with the subtype and confidence the detectors must report.
Templates hold markers such as ``{{secret:aws_access_key}}``; ``expand`` (the E08-01 corpus
loader) fills them from ``tests/support/synthetic.py``, so no secret-shaped string is committed
as a literal. The manifest is the ground-truth list of planted values that E13-01 formalises.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from codekavach.core.models import Confidence, Language
from tests.support.corpus import byte_range, expand

SECRETS_ROOT: Final = Path(__file__).resolve().parents[1] / "fixtures" / "detect" / "secrets"


@dataclass(frozen=True)
class Planted:
    """One planted value: where it is (UTF-8 bytes) and what a detector must call it."""

    subtype: str
    confidence: Confidence
    start_byte: int
    end_byte: int


@dataclass(frozen=True)
class SecretCase:
    """One expanded case."""

    file: str
    path: str
    language: Language
    text: str
    planted: tuple[Planted, ...]

    @property
    def positive(self) -> bool:
        """True for a case that plants at least one value."""
        return bool(self.planted)


def secret_cases() -> list[SecretCase]:
    """Every case of the manifest, expanded."""
    manifest = json.loads((SECRETS_ROOT / "manifest.json").read_text(encoding="utf-8"))
    cases: list[SecretCase] = []
    for entry in manifest["cases"]:
        text = expand((SECRETS_ROOT / entry["file"]).read_text(encoding="utf-8"))
        planted = []
        for item in entry["expect"]:
            value = expand(item["value"])
            start, end = byte_range(text, value)
            planted.append(Planted(item["subtype"], Confidence(item["confidence"]), start, end))
        cases.append(
            SecretCase(
                entry["file"], entry["path"], Language(entry["language"]), text, tuple(planted)
            )
        )
    return cases
