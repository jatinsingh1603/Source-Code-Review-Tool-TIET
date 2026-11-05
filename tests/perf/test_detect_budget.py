"""Performance budget: detection over a 2 000-line slice (E08-01).

The issue's budget is 50 ms for ``detect_all`` on a 2 000-line slice, because it runs per
candidate and again in the guard. The detectors that will fill the registry arrive in E08-02 to
E08-04, so this measures the framework with three regular-expression detectors of the kind those
issues add (compiled once through ``safe_compile``): running each, flooring, masking, clipping
and resolving several hundred overlapping spans. The budget is scaled by the performance factor.
"""

import pytest

from codekavach.config.models.root import Settings
from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_all
from codekavach.privacy.detect.secrets.builtin import register_secret_detectors
from tests.support.fake_detectors import RegexDetector
from tests.support.perf import assert_within_budget, measure
from tests.support.synthetic import synthetic_value

LINES = 2_000
BUDGET_SECONDS = 0.050

LINE = (
    'config_{i} = {{"host": "db{i}.internal", "owner": "user{i}@example.test", '
    '"key": "AKIA{i:016d}", "note": "festival bonus {i}"}}\n'
)


def build_slice() -> str:
    return "".join(LINE.format(i=i) for i in range(LINES // 4)) + "".join(
        f"def handler_{i}(request):\n    return request.value + {i}\n\n" for i in range(LINES // 4)
    )


def registry() -> DetectorRegistry:
    return DetectorRegistry(
        [
            RegexDetector(
                "perf.key",
                PlaceholderKind.SECRET,
                "aws_access_key",
                r"AKIA[0-9A-Z]{16}",
                Confidence.HIGH,
            ),
            RegexDetector(
                "perf.email",
                PlaceholderKind.PII,
                "email",
                r"[A-Za-z0-9_.+-]{1,64}@[A-Za-z0-9.-]{1,64}",
                Confidence.MEDIUM,
            ),
            RegexDetector(
                "perf.term", PlaceholderKind.TERM, "domain", r"festival bonus", Confidence.MEDIUM
            ),
            RegexDetector(
                "perf.entropy",
                PlaceholderKind.SECRET,
                "high_entropy_string",
                r'"[A-Za-z0-9]{16,}"',
                Confidence.LOW,
            ),
        ]
    )


@pytest.mark.perf
def test_detect_all_on_a_2000_line_slice_stays_within_budget() -> None:
    text = RawCode(build_slice())
    assert text.line_count >= LINES
    detectors = registry()
    settings = Settings()

    def run() -> int:
        return len(
            detect_all(
                text,
                path="src/app.py",
                language=Language.PYTHON,
                settings=settings,
                registry=detectors,
            )
        )

    assert run() >= 1_000  # a realistic number of spans to resolve
    assert_within_budget(measure(run, repeat=5), BUDGET_SECONDS, label="detect_all, 2000 lines")


SECRET_LINES = 2_000
HUNTER = "hunter2hunter2"  # pragma: allowlist secret


def secret_slice() -> str:
    """About 2 000 lines: hosts, credential assignments and key-like literals."""
    key = synthetic_value("secret", "aws_access_key")
    blob = synthetic_value("secret", "high_entropy_string", 3)
    parts: list[str] = []
    for i in range(SECRET_LINES // 4):
        parts.append(f'config_{i} = {{"host": "db{i}.internal", "note": "festival bonus {i}"}}\n')
        parts.append(f"def handler_{i}(request, limit=10):\n    password = {HUNTER!r}\n")
        parts.append(f"    return request.value + {i}  # {key} {blob}\n")
    return "".join(parts)


@pytest.mark.perf
def test_the_secret_detectors_on_a_2000_line_slice_stay_within_budget() -> None:
    """The issue's budget: the pattern pack, assignment and entropy passes in 50 ms."""
    text = RawCode(secret_slice())
    assert text.line_count >= SECRET_LINES
    detectors = register_secret_detectors(DetectorRegistry())
    settings = Settings()

    def run() -> int:
        return len(
            detect_all(
                text,
                path="src/app.py",
                language=Language.PYTHON,
                settings=settings,
                registry=detectors,
            )
        )

    assert run() >= 500
    assert_within_budget(
        measure(run, repeat=5), BUDGET_SECONDS, label="secret detectors, 2000 lines"
    )
