"""The three secret detectors together: containment, determinism and registration order (E08-02)."""

import itertools

from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.config.models.root import Settings
from codekavach.core.models import Language, RawCode
from codekavach.privacy.detect.base import Detector
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_all
from codekavach.privacy.detect.secrets.builtin import register_secret_detectors, secret_detectors
from tests.support.synthetic import EXAMPLE_CONNECTION_STRING, synthetic_value


def spans(
    text: str, registry: DetectorRegistry, path: str = "src/app.py"
) -> list[tuple[str, int, int]]:
    found = detect_all(
        RawCode(text),
        path=path,
        language=Language.PYTHON,
        settings=Settings(),
        registry=registry,
    )
    return [(s.subtype, s.start_byte, s.end_byte) for s in found]


def test_the_three_detectors_have_the_documented_ids() -> None:
    registry = register_secret_detectors(DetectorRegistry())
    assert [d.id for d in registry.all()] == [
        "secret.assignment",
        "secret.entropy",
        "secret.pattern",
    ]


def test_an_aws_key_inside_a_connection_string_is_one_span_over_the_whole_url() -> None:
    text = f'DATABASE_URL = "{EXAMPLE_CONNECTION_STRING}"\n'
    start = text.index("postgres")
    assert spans(text, register_secret_detectors(DetectorRegistry())) == [
        ("connection_string", start, start + len(EXAMPLE_CONNECTION_STRING))
    ]


def test_a_specific_subtype_wins_over_the_generic_one_on_the_same_value() -> None:
    value = synthetic_value("secret", "npm_token")
    text = f"NPM_TOKEN={value}\n"
    found = spans(text, register_secret_detectors(DetectorRegistry()), ".env")
    assert found == [("npm_token", 10, 10 + len(value))]


TEXT = (
    f'AWS_KEY = "{synthetic_value("secret", "aws_access_key")}"\n'
    f'DATABASE_URL = "{EXAMPLE_CONNECTION_STRING}"\n'
    f'password = "{synthetic_value("secret", "generic_credential")}"\n'
    f'blob = "{synthetic_value("secret", "high_entropy_string", 3)}"\n'
    f'token = "{synthetic_value("secret", "github_token")}"\n'
)


def test_the_result_does_not_depend_on_the_order_the_detectors_were_registered() -> None:
    expected = spans(TEXT, register_secret_detectors(DetectorRegistry()))
    assert len(expected) == 5
    detectors: list[Detector] = list(secret_detectors())
    for order in itertools.permutations(detectors):
        assert spans(TEXT, DetectorRegistry(order)) == expected


def test_detection_is_deterministic_across_repeated_runs() -> None:
    results = {tuple(spans(TEXT, register_secret_detectors(DetectorRegistry()))) for _ in range(5)}
    assert len(results) == 1


@settings(max_examples=60, deadline=None)
@given(st.permutations(range(3)), st.text(alphabet="abc=\"' \n_xyz0123456789", max_size=200))
def test_property_registration_order_never_changes_the_spans(order: list[int], filler: str) -> None:
    text = f"{filler}\n{TEXT}{filler}"
    detectors = secret_detectors()
    shuffled = DetectorRegistry([detectors[i] for i in order])
    assert spans(text, shuffled) == spans(text, register_secret_detectors(DetectorRegistry()))
