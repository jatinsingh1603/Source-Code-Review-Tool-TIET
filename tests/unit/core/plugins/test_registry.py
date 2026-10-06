import dataclasses
import json
import sys
import threading
from pathlib import Path

import pytest

from codekavach.core.plugins import registry as registry_module
from codekavach.core.plugins.discovery import PluginSpec, discover, kind_of
from codekavach.core.plugins.registry import (
    PluginRegistry,
    register_group_validator,
    registry_from_environment,
)
from tests.support.golden import assert_matches_golden
from tests.support.pipeline import write_fake_distribution

GOLDEN = Path(__file__).parent / "golden" / "plugin_rows.json"
STAGES = "codekavach.stages"

MODULE = """
created = []


class SampleStage:
    name = "sample"
    requires = frozenset({"files"})
    provides = frozenset({"sample.out"})
    category = None

    def __init__(self):
        created.append(self)

    def run(self, ctx):
        ctx.artefacts.put("sample.out", {"ok": True})


class Misnamed(SampleStage):
    name = "other"


class Invalid:
    name = "invalid"
    requires = frozenset()
    provides = frozenset()

    def run(self, ctx):
        pass


class Explodes:
    def __init__(self):
        raise RuntimeError("/home/client/secret/path")


NOT_CALLABLE = 42


class Renderer:
    pass
"""


def spec(name: str, target: str, dist: str = "ck-fake", group: str = STAGES) -> PluginSpec:
    return PluginSpec(group, name, target, dist, "1.0")


@pytest.fixture
def module(fake_site: Path) -> Path:
    (fake_site / "ck_fake.py").write_text(MODULE, encoding="utf-8")
    return fake_site


def failure_map(registry: PluginRegistry) -> dict[str, tuple[str, str]]:
    return {f.spec.name: (f.stage, f.error_type) for f in registry.failures()}


def test_valid_and_broken_plugins(module: Path) -> None:
    registry = PluginRegistry(
        [spec("sample", "ck_fake:SampleStage"), spec("broken", "ck_missing:Nope")]
    )
    assert "ck_fake" not in sys.modules
    assert list(registry.stages()) == ["sample"]
    assert failure_map(registry) == {"broken": ("import", "ModuleNotFoundError")}
    info = registry.stage_infos()["sample"]
    assert info.origin == "ck-fake==1.0"
    with pytest.raises(KeyError):
        registry.get(STAGES, "broken")
    with pytest.raises(KeyError):
        registry.get(STAGES, "nothing")


def test_create_and_validate_failures(module: Path) -> None:
    registry = PluginRegistry(
        [
            spec("other", "ck_fake:SampleStage"),
            spec("misnamed", "ck_fake:Misnamed"),
            spec("invalid", "ck_fake:Invalid"),
            spec("explodes", "ck_fake:Explodes"),
            spec("number", "ck_fake:NOT_CALLABLE"),
        ]
    )
    assert registry.stages() == {}
    assert failure_map(registry) == {
        "explodes": ("create", "RuntimeError"),
        "invalid": ("validate", "StageDeclarationError"),
        "misnamed": ("validate", "ValueError"),
        "number": ("create", "TypeError"),
        "other": ("validate", "ValueError"),
    }
    listing = json.dumps([dataclasses.asdict(row) for row in registry.rows()])
    assert "/home/client" not in listing


def test_lazy_single_instantiation(module: Path) -> None:
    registry = PluginRegistry([spec("sample", "ck_fake:SampleStage")])
    results: list[object] = []

    def fetch() -> None:
        results.append(registry.get(STAGES, "sample"))

    threads = [threading.Thread(target=fetch) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len({id(result) for result in results}) == 1
    assert len(sys.modules["ck_fake"].created) == 1


def test_collisions() -> None:
    specs = [
        spec("rate", "b:Rate", "zzz-plugin"),
        spec("rate", "a:Rate", "bbb-plugin"),
        spec("parse", "x:Parse", "aaa-plugin"),
        spec("parse", "codekavach.parsing:Parse", "codekavach"),
    ]
    forward = PluginRegistry(specs)
    backward = PluginRegistry(list(reversed(specs)))
    assert forward.shadowed() == backward.shadowed()
    assert [(s.name, s.dist_name) for s in forward.shadowed()] == [
        ("parse", "aaa-plugin"),
        ("rate", "zzz-plugin"),
    ]


def test_group_validator(module: Path) -> None:
    calls: list[object] = []

    def reject(plugin: object) -> None:
        calls.append(plugin)
        raise TypeError("not a renderer")

    group = "codekavach.renderers"
    registry = PluginRegistry(
        [spec("pdf", "ck_fake:Renderer", group=group)], validators={group: reject}
    )
    assert registry.renderers() == {}
    assert failure_map(registry) == {"pdf": ("validate", "TypeError")}
    assert len(calls) == 1
    accepting = PluginRegistry([spec("pdf", "ck_fake:Renderer", group=group)], validators={})
    assert list(accepting.renderers()) == ["pdf"]


def test_register_group_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry_module, "_GROUP_VALIDATORS", {})
    register_group_validator("codekavach.engines", lambda plugin: None)
    assert "codekavach.engines" in registry_module._GROUP_VALIDATORS


def test_other_group_conveniences(module: Path) -> None:
    groups = {
        "codekavach.languages": "languages",
        "codekavach.engines": "engines",
        "codekavach.detectors": "detectors",
        "codekavach.providers": "providers",
    }
    registry = PluginRegistry(
        [spec("x", "ck_fake:Renderer", group=group) for group in groups], validators={}
    )
    for method in groups.values():
        assert list(getattr(registry, method)()) == ["x"]
    assert [kind_of(group) for group in groups] == ["language", "engine", "detector", "provider"]


def test_rows_golden(module: Path) -> None:
    registry = PluginRegistry(
        [
            spec("sample", "ck_fake:SampleStage"),
            spec("sample", "ck_other:SampleStage", "zz-plugin"),
            spec("broken", "ck_missing:Nope"),
            spec("pdf", "ck_fake:Renderer", group="codekavach.renderers"),
        ],
        validators={},
    )
    rows = [dataclasses.asdict(row) for row in registry.rows()]
    assert rows == sorted(rows, key=lambda row: (row["group"], row["name"], row["dist"]))
    assert_matches_golden(json.dumps(rows, indent=2) + "\n", GOLDEN)


def test_real_environment(fake_site: Path) -> None:
    write_fake_distribution(
        fake_site,
        "ck-sample-plugin",
        "0.1.0",
        entry_points={STAGES: {"sample": "ck_sample:SampleStage", "broken": "ck_nope:X"}},
        modules={"ck_sample.py": MODULE.replace("class SampleStage", "class SampleStage")},
    )
    registry = PluginRegistry(
        [s for s in discover() if s.dist_name == "ck-sample-plugin"], validators={}
    )
    assert "ck_sample" not in sys.modules
    assert list(registry.stages()) == ["sample"]
    assert [f.error_type for f in registry.failures()] == ["ModuleNotFoundError"]
    assert isinstance(registry_from_environment(), PluginRegistry)
