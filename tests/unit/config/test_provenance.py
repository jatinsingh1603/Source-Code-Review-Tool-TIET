from codekavach.config.provenance import Layer, Origin, compute_origins

USER_TEXT = 'scan.jobs = 4\n[privacy]\nnever_send = ["a"]\n'
PROJECT_TEXT = '[llm.providers.lab]\nmodel = "m"\n\n[privacy]\nnever_send = ["b"]\n'


def layers() -> list[Layer]:
    return [
        Layer(
            name="user",
            source="/home/u/config.toml",
            data={"scan": {"jobs": 4}, "privacy": {"never_send": ["a"]}, "t": {"x": 1, "y": 2}},
            text=USER_TEXT,
        ),
        Layer(
            name="project",
            source="/repo/codekavach.toml",
            data={
                "llm": {"providers": {"lab": {"model": "m"}}},
                "privacy": {"never_send": ["b"]},
                "t": [1],
            },
            text=PROJECT_TEXT,
        ),
        Layer(
            name="cli",
            source="command line",
            data={"reporting": {"formats": ["pdf"]}},
            key_sources={"reporting.formats": "--format"},
        ),
    ]


FINAL = {
    "scan": {"jobs": 4, "exclude": [".git/**"]},
    "privacy": {"never_send": ["x", "a", "b"]},
    "llm": {"providers": {"lab": {"model": "m", "kind": "mock"}}},
    "reporting": {"formats": ["pdf"]},
    "t": [1],
}


def test_an_empty_table_does_not_claim_the_keys_below_it() -> None:
    """The starter file has ``[logging]`` with every key commented out (issue 302)."""
    text = '[logging]\n# level = "info"\n'
    layer = Layer(name="project", source="/repo/codekavach.toml", data={"logging": {}}, text=text)
    final = {"logging": {"level": "info", "format": "console"}}
    origins = compute_origins([layer], final)
    assert origins["logging.level"] == Origin("default")
    assert origins["logging.format"] == Origin("default")


def test_a_written_key_keeps_its_origin_beside_an_unwritten_one() -> None:
    text = '[logging]\nlevel = "debug"\n'
    layer = Layer(
        name="project",
        source="/repo/codekavach.toml",
        data={"logging": {"level": "debug"}},
        text=text,
    )
    final = {"logging": {"level": "debug", "format": "console"}}
    origins = compute_origins([layer], final)
    assert origins["logging.level"] == Origin("project", "/repo/codekavach.toml", 2)
    assert origins["logging.format"] == Origin("default")


def test_an_empty_table_that_is_the_key_itself_is_a_written_value() -> None:
    layer = Layer(name="project", source="/repo/codekavach.toml", data={"llm": {"providers": {}}})
    origins = compute_origins([layer], {"llm": {"providers": {}}})
    assert origins["llm.providers"].layer == "project"


def test_a_nested_empty_table_under_a_written_table_claims_nothing() -> None:
    layer = Layer(name="user", source="/home/u/config.toml", data={"a": {"b": {}, "x": 1}})
    origins = compute_origins([layer], {"a": {"b": {"c": 1}, "x": 1}})
    assert origins["a.b.c"] == Origin("default")
    assert origins["a.x"].layer == "user"


def test_a_higher_layer_that_is_empty_does_not_hide_a_lower_one() -> None:
    lower = Layer(name="user", source="/home/u/config.toml", data={"logging": {"level": "warning"}})
    higher = Layer(name="project", source="/repo/codekavach.toml", data={"logging": {}})
    origins = compute_origins([lower, higher], {"logging": {"level": "warning"}})
    assert origins["logging.level"].layer == "user"


def test_origins() -> None:
    origins = compute_origins(
        layers(),
        FINAL,
        union_keys=frozenset({"privacy.never_send"}),
        defaults={"privacy": {"never_send": ["x"]}},
    )
    assert origins["scan.jobs"] == Origin("user", "/home/u/config.toml", 1)
    assert origins["scan.exclude"] == Origin("default")
    assert origins["llm.providers.lab.model"] == Origin("project", "/repo/codekavach.toml", 2)
    assert origins["llm.providers.lab.kind"] == Origin("default")  # filled in by the model
    assert origins["reporting.formats"] == Origin("cli", "--format", None)
    assert origins["t"].layer == "project"  # a table replaced by a list in a higher layer
    union = origins["privacy.never_send"]
    assert union.layer == "project"
    assert union.line == 5
    assert union.contributors == ("default", "user", "project")


def test_no_layers_means_default() -> None:
    origins = compute_origins([], {"a": {"b": 1}, "c": []})
    assert set(origins.values()) == {Origin("default")}
