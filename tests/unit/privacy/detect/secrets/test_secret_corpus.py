"""The labelled corpus through ``detect_all`` and through each detector (E08-02).

Positive files plant values with a known subtype and confidence; negative files are near misses
and false-positive shapes that no detector may report. The test run prints the precision each
detector achieved over the corpus (``pytest -rP`` or ``-s``) and asserts the pattern detector's
recall is 1.0 on its positive files.
"""

import sys

import pytest

from codekavach.config.models.root import Settings
from codekavach.core.models import RawCode
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_all
from codekavach.privacy.detect.secrets.builtin import register_secret_detectors, secret_detectors
from tests.support.secret_corpus import SecretCase, secret_cases

CASES = secret_cases()
POSITIVE = [case for case in CASES if case.positive]
NEGATIVE = [case for case in CASES if not case.positive]
PATTERN_SUBTYPES_ONLY = {"generic_credential", "high_entropy_string"}


def resolved(case: SecretCase) -> list[tuple[str, str, int, int]]:
    registry = register_secret_detectors(DetectorRegistry())
    spans = detect_all(
        RawCode(case.text),
        path=case.path,
        language=case.language,
        settings=Settings(),
        registry=registry,
    )
    return [(s.subtype, s.confidence.value, s.start_byte, s.end_byte) for s in spans]


def test_the_corpus_meets_the_size_the_issue_asks_for() -> None:
    assert len(POSITIVE) >= 40
    assert len(NEGATIVE) >= 25
    assert len({case.file for case in CASES}) == len(CASES)


@pytest.mark.parametrize("case", POSITIVE, ids=lambda case: case.file)
def test_every_planted_value_is_one_span_with_its_subtype_and_confidence(case: SecretCase) -> None:
    expected = sorted(
        (p.subtype, p.confidence.value, p.start_byte, p.end_byte) for p in case.planted
    )
    assert sorted(resolved(case)) == expected


@pytest.mark.parametrize("case", NEGATIVE, ids=lambda case: case.file)
def test_a_near_miss_or_filtered_value_is_not_reported(case: SecretCase) -> None:
    assert resolved(case) == []


def test_pattern_recall_is_one_and_precision_per_detector_is_printed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    detectors = secret_detectors()
    hits = {detector.id: [0, 0] for detector in detectors}  # [true positives, false positives]
    missed: list[str] = []
    for case in CASES:
        planted = {(p.start_byte, p.end_byte) for p in case.planted}
        for detector in detectors:
            for span in detector.detect(RawCode(case.text), path=case.path, language=case.language):
                inside = any(
                    span.start_byte < end and start < span.end_byte for start, end in planted
                )
                hits[detector.id][0 if inside else 1] += 1
        pattern_found = {
            (s.start_byte, s.end_byte, s.subtype)
            for s in detectors[0].detect(RawCode(case.text), path=case.path, language=case.language)
        }
        missed.extend(
            f"{case.file}:{p.subtype}"
            for p in case.planted
            if p.subtype not in PATTERN_SUBTYPES_ONLY
            and (p.start_byte, p.end_byte, p.subtype) not in pattern_found
        )
    with capsys.disabled():
        for detector_id, (true_positive, false_positive) in sorted(hits.items()):
            total = true_positive + false_positive
            precision = true_positive / total if total else 1.0
            sys.stdout.write(
                f"\n[precision] {detector_id}: {precision:.2f} "
                f"({true_positive} on planted values, {false_positive} elsewhere)"
            )
        sys.stdout.write("\n")
    assert missed == []
    assert hits["secret.pattern"][1] == 0
