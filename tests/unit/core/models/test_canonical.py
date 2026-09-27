import json
import random

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.models import KavachModel, ModelError, canonical_json, sha256_hex


class Pair(KavachModel):
    b: int
    a: str


def test_example_from_specification() -> None:
    assert canonical_json({"b": 1, "a": ["x", None]}) == b'{"a":["x",null],"b":1}'


def test_key_order_does_not_matter() -> None:
    assert canonical_json({"x": 1, "y": {"b": 2, "a": 3}}) == canonical_json(
        {"y": {"a": 3, "b": 2}, "x": 1}
    )


def test_model_input_and_exclude() -> None:
    assert canonical_json(Pair(b=1, a="é")) == '{"a":"é","b":1}'.encode()
    assert canonical_json(Pair(b=1, a="x"), exclude=frozenset({"a"})) == b'{"b":1}'


@pytest.mark.parametrize("value", [1.5, {"a": [1, 2.0]}, ("x", 0.0)])
def test_floats_rejected(value: object) -> None:
    with pytest.raises(ModelError):
        canonical_json(value)


def test_no_trailing_newline_and_no_normalisation() -> None:
    composed = "é"
    decomposed = "é"
    assert canonical_json(composed) != canonical_json(decomposed)
    assert not canonical_json({"a": 1}).endswith(b"\n")


def test_sha256_of_empty_string() -> None:
    # pragma: allowlist nextline secret
    assert sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_hex(b"") == sha256_hex("")


def test_sha256_rejects_lone_surrogate_without_echoing_it() -> None:
    with pytest.raises(ModelError) as info:
        sha256_hex("abc\ud800")
    assert "abc" not in str(info.value)


_scalars = st.none() | st.booleans() | st.integers() | st.text()
_json = st.recursive(
    _scalars,
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=6), children, max_size=4)
    ),
    max_leaves=20,
)


def _shuffled(value: object, rng: random.Random) -> object:
    if isinstance(value, dict):
        keys = list(value)
        rng.shuffle(keys)
        return {k: _shuffled(value[k], rng) for k in keys}
    if isinstance(value, list):
        return [_shuffled(v, rng) for v in value]
    return value


@given(st.dictionaries(st.text(max_size=6), _json, max_size=6), st.randoms())
def test_canonical_json_is_order_invariant_and_round_trips(
    data: dict[str, object], rng: random.Random
) -> None:
    encoded = canonical_json(data)
    assert encoded == canonical_json(_shuffled(data, rng))
    assert json.loads(encoded) == data
