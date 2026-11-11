"""The intermediate representation: places, expressions and the settings that bound them."""

import pytest
from pydantic import ValidationError

from codekavach.analysis.taint.ir import (
    ANY_INDEX,
    Assign,
    Const,
    IRBlock,
    IRFunction,
    IRModule,
    Op,
    Place,
    Return,
    Unknown,
)
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import DataClassification, Location

LOCATION = Location(path="a.py", start_line=1, end_line=1)


def test_a_place_extends_until_the_limit_and_is_then_truncated() -> None:
    place = Place(base="a")
    for step in (".b", ".c", ".d"):
        place = place.extend(step, 3)
    assert place.text == "a.b.c.d"
    assert not place.truncated
    cut = place.extend(".e", 3)
    assert cut.truncated
    assert cut.text == "a.b.c.d..."
    assert cut.extend(".f", 3) == cut


def test_related_paths_are_prefixes_of_one_another() -> None:
    a = Place(base="a")
    ab = Place(base="a", steps=(".b",))
    abc = Place(base="a", steps=(".b", ".c"))
    ac = Place(base="a", steps=(".c",))
    assert a.related(ab) and ab.related(a) and ab.related(abc)
    assert not ab.related(ac)
    assert not a.related(Place(base="b"))


def test_a_write_through_an_unknown_index_or_a_cut_path_is_weak() -> None:
    assert Place(base="a", steps=(".b",)).strong()
    assert not Place(base="a", steps=(ANY_INDEX,)).strong()
    assert not Place(base="a", truncated=True).strong()


def test_nodes_are_frozen_raw_and_forbid_unknown_fields() -> None:
    place = Place(base="a")
    assert Place.DATA_CLASSIFICATION is DataClassification.RAW
    with pytest.raises(ValidationError):
        place.base = "b"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Place(base="a", surprise=1)  # type: ignore[call-arg]


def test_a_module_survives_a_json_round_trip() -> None:
    value = Op(
        operator="+",
        style="concat",
        operands=(
            Const(kind="str", shape="x"),
            Place(base="q"),
            Unknown(mentions=(Place(base="z"),)),
        ),
    )
    function = IRFunction(
        name="f",
        qualname="f",
        params=("q",),
        location=LOCATION,
        blocks=(
            IRBlock(
                id=0,
                stmts=(
                    Assign(target=Place(base="s"), value=value, location=LOCATION),
                    Return(value=Place(base="s")),
                ),
            ),
        ),
    )
    module = IRModule(path="a.py", language="python", lowering_version="1", functions=(function,))
    assert IRModule.model_validate_json(module.model_dump_json()) == module


def test_the_shape_of_a_string_is_bounded() -> None:
    with pytest.raises(ValidationError):
        Const(kind="str", shape="x" * 1000)


def test_taint_settings_defaults_and_bounds() -> None:
    settings = TaintSettings()
    assert (settings.max_access_path, settings.max_function_nodes, settings.max_blocks) == (
        3,
        20_000,
        5_000,
    )
    assert settings.timeout_seconds == 10.0
    assert settings.explain is False
    with pytest.raises(ValidationError):
        TaintSettings(max_access_path=0)
    with pytest.raises(ValidationError):
        TaintSettings(timeout_seconds=0.0)
