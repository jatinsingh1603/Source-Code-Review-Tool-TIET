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
