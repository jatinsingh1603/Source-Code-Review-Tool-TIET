"""The optional name recogniser and the rule that absent extras change nothing (E08-04)."""

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from structlog.testing import capture_logs

from codekavach.config.models.root import Settings
from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode
from codekavach.privacy.detect import optional
from codekavach.privacy.detect.pii import ner
from codekavach.privacy.detect.pii.builtin import register_pii_detectors
from codekavach.privacy.detect.pii.ner import (
    NerDetector,
    ner_detectors,
    ner_status,
    register_ner_detector,
)
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_all
from codekavach.privacy.detect.secrets.builtin import register_secret_detectors
from codekavach.privacy.detect.vocabulary import NER_SUBTYPES, PII_SUBTYPES, VOCABULARY
from tests.support.synthetic import synthetic_value

REPO = Path(__file__).resolve().parents[5]


@dataclass
class Ent:
    label_: str
    start_char: int
    end_char: int


@dataclass
class Doc:
    ents: list[Ent]


class FakePipeline:
    """Returns entities for the first occurrence of each configured name in the piece."""

    def __init__(self, names: dict[str, str]) -> None:
        self.names = names
        self.pieces: list[str] = []

    def __call__(self, text: str) -> Doc:
        self.pieces.append(text)
        ents = []
        for name, label in self.names.items():
            index = text.find(name)
            if index >= 0:
                ents.append(Ent(label, index, index + len(name)))
        return Doc(ents)


@pytest.fixture(autouse=True)
def fresh_warnings() -> None:
    optional.reset_warnings()


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ner, "ner_status", lambda model=ner.DEFAULT_MODEL: "ready")


def detect(detector: NerDetector, text: str) -> tuple[Any, ...]:
    return tuple(detector.detect(RawCode(text), path="a.py", language=Language.PYTHON))


def test_the_vocabulary_has_the_name_subtypes_without_touching_the_format_set() -> None:
    assert {"person_name", "organisation", "location", "nric_or_national_id"} == NER_SUBTYPES
    assert not NER_SUBTYPES & PII_SUBTYPES
    assert VOCABULARY[PlaceholderKind.PII] >= NER_SUBTYPES


def test_entities_become_pii_spans_over_exactly_the_name(installed: None) -> None:
    text = "# owner: Ramesh Kulkarni of Acme Payments in Pune\n"
    pipeline = FakePipeline(
        {"Ramesh Kulkarni": "PERSON", "Acme Payments": "ORG", "Pune": "GPE", "owner": "MISC"}
    )
    found = detect(NerDetector(loader=lambda model: pipeline), text)
    seen = {(s.subtype, text.encode()[s.start_byte : s.end_byte].decode()) for s in found}
    assert seen == {
        ("person_name", "Ramesh Kulkarni"),
        ("organisation", "Acme Payments"),
        ("location", "Pune"),
    }
    assert {(s.kind, s.confidence, s.detector) for s in found} == {
        (PlaceholderKind.PII, Confidence.MEDIUM, "pii.ner")
    }


def test_spans_are_utf8_byte_offsets(installed: None) -> None:
    text = "नमस्ते Ramesh Kulkarni\n"
    found = detect(
        NerDetector(loader=lambda model: FakePipeline({"Ramesh Kulkarni": "PERSON"})), text
    )
    (span,) = found
    assert text.encode()[span.start_byte : span.end_byte] == b"Ramesh Kulkarni"


def test_a_very_short_entity_is_not_reported(installed: None) -> None:
    found = detect(NerDetector(loader=lambda model: FakePipeline({"Al": "PERSON"})), "Al wrote")
    assert found == ()


def test_a_long_text_is_cut_at_line_ends_and_offsets_stay_absolute(
    installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ner, "CHUNK_CHARS", 40)
    lines = [f"line {i} padding padding\n" for i in range(6)]
    text = "".join(lines) + "contact Ramesh Kulkarni now\n"
    pipeline = FakePipeline({"Ramesh Kulkarni": "PERSON"})
    (span,) = detect(NerDetector(loader=lambda model: pipeline), text)
    assert len(pipeline.pieces) > 1 and all(piece.endswith("\n") for piece in pipeline.pieces)
    assert text.encode()[span.start_byte : span.end_byte] == b"Ramesh Kulkarni"


def test_without_the_library_or_model_nothing_is_found_and_one_warning_is_logged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ner, "module_present", lambda name: False)
    detector = NerDetector()
    with capture_logs() as events:
        for _ in range(3):
            assert detect(detector, "Ramesh Kulkarni lives in Pune") == ()
        assert detect(NerDetector(), "again") == ()
    warnings = [e for e in events if e["event"] == "optional_extra_unavailable"]
    assert len(warnings) == 1
    assert warnings[0]["extra"] == "codekavach[pii]"
    assert detector.available() is False


@pytest.mark.parametrize(
    ("present", "expected"),
    [(set(), "library missing"), ({"spacy"}, "model missing"), ({"spacy", "m"}, "ready")],
)
def test_the_status_distinguishes_a_missing_library_from_a_missing_model(
    monkeypatch: pytest.MonkeyPatch, present: set[str], expected: str
) -> None:
    monkeypatch.setattr(ner, "module_present", lambda name: name in present)
    assert ner_status("m") == expected


def test_a_model_that_fails_to_load_is_treated_as_absent(installed: None) -> None:
    def boom(model: str) -> Any:
        raise OSError("cannot open /home/alice/models/x")

    with capture_logs() as events:
        assert detect(NerDetector(loader=boom), "Ramesh Kulkarni") == ()
    assert "alice" not in repr(events)
    assert [e["reason"] for e in events] == ["model could not be loaded"]


def test_the_detector_is_only_registered_when_locales_are_enabled() -> None:
    assert ner_detectors([]) == ()
    assert len(ner_detectors(["intl"])) == 1
    registry = DetectorRegistry()
    assert register_ner_detector(registry, []).all() == ()
    assert [d.id for d in register_ner_detector(registry, ["in"]).all()] == ["pii.ner"]


# --- detection is unchanged when the extras are absent -------------------------------------


def settings() -> Settings:
    return Settings.model_validate({})


def native_registry() -> DetectorRegistry:
    registry = register_secret_detectors(DetectorRegistry())
    return register_pii_detectors(registry, ["intl", "in"])


def run(registry: DetectorRegistry, text: str) -> tuple[Any, ...]:
    return tuple(
        (s.kind, s.subtype, s.start_byte, s.end_byte)
        for s in detect_all(
            RawCode(text),
            path="a.py",
            language=Language.PYTHON,
            settings=settings(),
            registry=registry,
        )
    )


def test_detect_all_is_unchanged_with_the_extras_absent_and_warns_once_per_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ner, "module_present", lambda name: False)
    key = synthetic_value("secret", "aws_access_key")
    mail = synthetic_value("pii", "email")
    text = f'key = "{key}"\nmail = "{mail}"\n'
    baseline = run(native_registry(), text)
    assert len(baseline) >= 2
    with_ner = register_ner_detector(native_registry(), ["intl"])
    with capture_logs() as events:
        for _ in range(3):
            assert run(with_ner, text) == baseline
    warnings = [e for e in events if e["event"] == "optional_extra_unavailable"]
    assert len(warnings) == 1


def test_importing_the_detect_package_does_not_import_the_optional_modules() -> None:
    code = (
        "import sys, codekavach.privacy.detect, codekavach.privacy.detect.registry, "
        "codekavach.privacy.detect.runner, codekavach.privacy.detect.secrets.builtin, "
        "codekavach.privacy.detect.pii.builtin\n"
        "bad = [m for m in sys.modules if m in {'spacy', 'codekavach.privacy.detect.pii.ner', "
        "'codekavach.privacy.detect.secrets.adapters', 'codekavach.privacy.detect.mining'}]\n"
        "print(','.join(bad))"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO,
        env={"PYTHONPATH": str(REPO / "src"), "SYSTEMROOT": "C:\\Windows", "PATH": ""},
    )
    assert done.stdout.strip() == ""
