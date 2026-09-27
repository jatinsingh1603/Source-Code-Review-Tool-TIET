import keyword

from hypothesis import find, given, settings
from hypothesis import strategies as st

from tests.support.strategies import fake_secrets, identifiers, nested_json
from tests.support.synthetic import SECRET_SHAPES


@given(identifiers())
def test_identifiers_are_valid(name: str) -> None:
    assert name.isidentifier()
    assert name not in keyword.kwlist


@given(identifiers(min_size=3, max_size=5))
def test_identifiers_respect_size(name: str) -> None:
    assert 3 <= len(name) <= 5


def test_identifiers_include_non_ascii() -> None:
    example = find(identifiers(), lambda name: not name.isascii())
    assert not example.isascii()


@given(fake_secrets())
def test_fake_secrets_match_their_pattern(pair: tuple[str, str]) -> None:
    kind, value = pair
    assert kind in SECRET_SHAPES
    assert SECRET_SHAPES[kind].pattern.fullmatch(value)


def test_fake_secrets_are_reproducible_when_derandomised() -> None:
    def draw_sequence() -> list[tuple[str, str]]:
        seen: list[tuple[str, str]] = []

        @settings(derandomize=True, max_examples=25, database=None)
        @given(fake_secrets())
        def collect(pair: tuple[str, str]) -> None:
            seen.append(pair)

        collect()
        return seen

    first = draw_sequence()
    assert first
    assert first == draw_sequence()


def _depth(value: object) -> int:
    if isinstance(value, dict):
        return 1 + max(_depth(v) for v in value.values())
    if isinstance(value, list | tuple):
        return 1 + max(_depth(v) for v in value)
    return 0


def _leaf_count(value: object) -> int:
    if isinstance(value, dict):
        return sum(_leaf_count(v) for v in value.values())
    if isinstance(value, list | tuple):
        return sum(_leaf_count(v) for v in value)
    return 1


@given(nested_json(st.integers()))
def test_nested_json_bounds(value: object) -> None:
    assert isinstance(value, dict | list | tuple)
    assert 1 <= _depth(value) <= 4
    assert _leaf_count(value) >= 1
