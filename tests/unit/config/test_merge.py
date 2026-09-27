import copy
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from codekavach.config.merge import deep_merge, is_union_key

UNION = frozenset({"privacy.never_send", "llm.providers.*.tags"})


def test_tables_merge_and_leaves_replace() -> None:
    base = {"scan": {"jobs": 4, "exclude": ["a"]}, "x": 1}
    overlay = {"scan": {"jobs": 2}, "y": 2}
    assert deep_merge(base, overlay) == {"scan": {"jobs": 2, "exclude": ["a"]}, "x": 1, "y": 2}


def test_arrays_and_arrays_of_tables_replace() -> None:
    base = {"privacy": {"paths": [{"pattern": "a"}], "never_send": ["x"]}, "list": [1, 2]}
    overlay = {"privacy": {"paths": [{"pattern": "b"}]}, "list": [3]}
    merged = deep_merge(base, overlay)
    assert merged["privacy"]["paths"] == [{"pattern": "b"}]
    assert merged["list"] == [3]


def test_union_keys_concatenate_without_duplicates() -> None:
    base = {"privacy": {"never_send": ["a", "b"]}}
    overlay = {"privacy": {"never_send": ["b", "c", "a", "d"]}}
    merged = deep_merge(base, overlay, union_keys=UNION)
    assert merged["privacy"]["never_send"] == ["a", "b", "c", "d"]


def test_union_template_with_mapping_wildcard() -> None:
    assert is_union_key("llm.providers.lab.tags", UNION)
    assert not is_union_key("llm.providers.lab.model", UNION)
    base = {"llm": {"providers": {"lab": {"tags": ["x"]}}}}
    overlay = {"llm": {"providers": {"lab": {"tags": ["y"]}}}}
    merged = deep_merge(base, overlay, union_keys=UNION)
    assert merged["llm"]["providers"]["lab"]["tags"] == ["x", "y"]


def test_type_mismatch_replaces() -> None:
    assert deep_merge({"a": {"b": 1}}, {"a": 5}) == {"a": 5}
    assert deep_merge({"a": 5}, {"a": {"b": 1}}) == {"a": {"b": 1}}
    assert deep_merge(
        {"privacy": {"never_send": "x"}}, {"privacy": {"never_send": ["y"]}}, union_keys=UNION
    ) == {"privacy": {"never_send": ["y"]}}


def test_result_shares_no_mutable_state() -> None:
    base: dict[str, Any] = {"a": {"b": [1]}}
    overlay: dict[str, Any] = {"c": {"d": [2]}}
    merged = deep_merge(base, overlay)
    merged["a"]["b"].append(9)
    merged["c"]["d"].append(9)
    assert base == {"a": {"b": [1]}}
    assert overlay == {"c": {"d": [2]}}


# Associativity holds when a key is a table in every layer or a leaf in every layer; a key that
# changes between table and leaf is rejected by validation anyway.
leaf_names = st.sampled_from(["a", "b", "never_send"])
table_names = st.sampled_from(["t", "u"])
leaves = st.integers() | st.text(max_size=3) | st.lists(st.integers(), max_size=3)
tables = st.recursive(
    st.dictionaries(leaf_names, leaves, max_size=3),
    lambda children: st.builds(
        lambda flat, nested: {**flat, **nested},
        st.dictionaries(leaf_names, leaves, max_size=3),
        st.dictionaries(table_names, children, max_size=2),
    ),
    max_leaves=10,
)


@given(tables, tables, tables)
def test_property_associative(a: dict[str, Any], b: dict[str, Any], c: dict[str, Any]) -> None:
    assert deep_merge(deep_merge(a, b), c) == deep_merge(a, deep_merge(b, c))


@given(tables, tables)
def test_property_identity_no_mutation_right_bias(a: dict[str, Any], b: dict[str, Any]) -> None:
    before_a, before_b = copy.deepcopy(a), copy.deepcopy(b)
    assert deep_merge(a, {}) == a
    assert deep_merge({}, a) == a
    merged = deep_merge(a, b)
    assert (a, b) == (before_a, before_b)
    for key, value in b.items():
        if not isinstance(value, dict) or not isinstance(a.get(key), dict):
            assert merged[key] == value


@given(st.lists(st.integers(0, 20)), st.lists(st.integers(0, 20)))
def test_property_union_elements(base: list[int], overlay: list[int]) -> None:
    merged = deep_merge(
        {"privacy": {"never_send": base}},
        {"privacy": {"never_send": overlay}},
        union_keys=UNION,
    )["privacy"]["never_send"]
    expected: list[int] = []
    for item in (*base, *overlay):
        if item not in expected:
            expected.append(item)
    assert merged == expected
