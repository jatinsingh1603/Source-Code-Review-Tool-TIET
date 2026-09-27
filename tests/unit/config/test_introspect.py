from typing import Annotated

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel, Field

from codekavach.config import Settings
from codekavach.config.introspect import (
    flatten_leaves,
    has_marker,
    iter_fields,
    key_to_path,
    keys_with_marker,
    loc_to_key,
    resolve_field,
)


class Leaf(BaseModel):
    level: str = "L3"
    secret: str | None = Field(default=None, json_schema_extra={"x-ck-sensitive": True})


class Nested(BaseModel):
    depth: int = 1


class Tree(BaseModel):
    plain: int = 0
    nested: Nested = Field(default_factory=Nested)
    optional: Nested | None = None
    mapping: dict[str, Leaf] = Field(
        default_factory=dict, json_schema_extra={"x-ck-restricted": True}
    )
    items: list[Leaf] = Field(default_factory=list, json_schema_extra={"x-ck-merge": "union"})
    options: dict[str, int] = Field(default_factory=dict)
    annotated: Annotated[Nested | None, "doc"] = None
    sibling: int = Field(default=0, json_schema_extra={"x-ck-volatile": True})


def test_iter_fields_on_all_shapes() -> None:
    assert [ref.key for ref in iter_fields(Tree)] == [
        "plain",
        "nested.depth",
        "optional.depth",
        "mapping.*.level",
        "mapping.*.secret",
        "items[].level",
        "items[].secret",
        "options",
        "annotated.depth",
        "sibling",
    ]
    assert [ref.key for ref in iter_fields(Tree, prefix="root")][:2] == [
        "root.plain",
        "root.nested.depth",
    ]


def test_mapping_entry_flag() -> None:
    flags = {ref.key: ref.is_mapping_entry for ref in iter_fields(Tree)}
    assert flags["mapping.*.level"] is True
    assert flags["items[].level"] is False
    assert flags["plain"] is False


def test_real_settings_examples() -> None:
    assert [ref.key for ref in iter_fields(Settings)][:4] == [
        "config_version",
        "profile",
        "project.name",
        "project.client",
    ]
    jobs = resolve_field(Settings, "scan.jobs")
    assert jobs is not None
    assert jobs.markers == frozenset({"volatile"})
    assert resolve_field(Settings, "scan.nope") is None


@pytest.mark.parametrize(
    ("key", "template"),
    [
        ("plain", "plain"),
        ("nested.depth", "nested.depth"),
        ("mapping.lab.level", "mapping.*.level"),
        ("items[2].level", "items[].level"),
        ("items[].level", "items[].level"),
        ("options.seed", "options.*"),
        ("nested", "nested"),
    ],
)
def test_resolve_field(key: str, template: str) -> None:
    ref = resolve_field(Tree, key)
    assert ref is not None
    assert ref.key == template


@pytest.mark.parametrize(
    "key",
    ["", ".", "a..b", "a[x]", "nope", "plain.more", "items.level", "mapping[0].level", "*", "[0]"],
)
def test_resolve_field_unknown_or_malformed(key: str) -> None:
    assert resolve_field(Tree, key) is None


def test_marker_inheritance() -> None:
    assert has_marker(Tree, "mapping.lab.level", "restricted")
    assert not has_marker(Tree, "plain", "restricted")
    assert has_marker(Tree, "mapping.lab.secret", "sensitive")
    assert not has_marker(Tree, "mapping.lab.level", "sensitive")
    assert has_marker(Tree, "items[0].secret", "union")
    assert not has_marker(Tree, "nope", "restricted")


def test_keys_with_marker() -> None:
    assert keys_with_marker(Tree, "restricted") == {"mapping.*.level", "mapping.*.secret"}
    assert keys_with_marker(Tree, "volatile") == {"sibling"}
    assert keys_with_marker(Tree, "sensitive") == {"mapping.*.secret", "items[].secret"}
    assert "reporting.template_dir" in keys_with_marker(Settings, "restricted")


@pytest.mark.parametrize(
    ("loc", "key"),
    [
        (("privacy", "paths", 2, "level"), "privacy.paths[2].level"),
        (("llm", "providers", "lab", "base_url"), "llm.providers.lab.base_url"),
        (("scan",), "scan"),
        (("a", 0, 1, "b"), "a[0][1].b"),
    ],
)
def test_loc_and_key(loc: tuple[str | int, ...], key: str) -> None:
    assert loc_to_key(loc) == key
    assert key_to_path(key) == loc


@pytest.mark.parametrize("key", ["", "a..b", "a[x]", "a.*", "a[]"])
def test_key_to_path_rejects_malformed(key: str) -> None:
    with pytest.raises(ValueError, match="malformed"):
        key_to_path(key)


def test_flatten_leaves() -> None:
    data = {"a": {"b": 1, "c": {"d": [1, 2]}}, "e": {}, "f": None, "g": [{"h": 1}]}
    assert flatten_leaves(data) == {
        "a.b": 1,
        "a.c.d": [1, 2],
        "e": {},
        "f": None,
        "g": [{"h": 1}],
    }
    assert flatten_leaves({}) == {}


@given(st.text())
def test_property_resolve_never_raises(key: str) -> None:
    resolve_field(Settings, key)
    resolve_field(Tree, key)


identifier = st.from_regex(r"[a-z_][a-z0-9_]{0,10}", fullmatch=True)


@given(
    st.tuples(identifier).flatmap(
        lambda head: st.lists(identifier | st.integers(0, 10_000), max_size=6).map(
            lambda tail: (*head, *tail)
        )
    )
)
def test_property_loc_round_trip(loc: tuple[str | int, ...]) -> None:
    assert key_to_path(loc_to_key(loc)) == loc
