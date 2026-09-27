import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codekavach.core.plugins.discovery import GROUPS, PluginSpec, discover
from tests.support.pipeline import write_fake_distribution


@dataclass
class Dist:
    name: str
    version: str


@dataclass
class FakeEntryPoint:
    name: str
    value: str
    dist: Dist | None


def fake_entry_points(table: dict[str, list[FakeEntryPoint]]) -> Any:
    def entry_points(*, group: str) -> list[FakeEntryPoint]:
        return table.get(group, [])

    return entry_points


def test_discover_with_injected_function() -> None:
    table = {
        "codekavach.stages": [
            FakeEntryPoint("rate", "pkg.rate:Rate", Dist("b-plugin", "2.0")),
            FakeEntryPoint("ingest", "pkg.ingest:Ingest", Dist("a-plugin", "1.0")),
        ],
        "codekavach.renderers": [FakeEntryPoint("pdf", "pkg.pdf:Pdf", None)],
    }
    specs = discover(entry_points_fn=fake_entry_points(table))
    assert specs == [
        PluginSpec("codekavach.renderers", "pdf", "pkg.pdf:Pdf", "unknown", ""),
        PluginSpec("codekavach.stages", "ingest", "pkg.ingest:Ingest", "a-plugin", "1.0"),
        PluginSpec("codekavach.stages", "rate", "pkg.rate:Rate", "b-plugin", "2.0"),
    ]


def test_all_six_groups_are_queried() -> None:
    asked: list[str] = []

    def entry_points(*, group: str) -> list[FakeEntryPoint]:
        asked.append(group)
        return []

    assert discover(entry_points_fn=entry_points) == []
    assert tuple(asked) == GROUPS
    assert len(GROUPS) == 6


def test_real_discovery_does_not_import(fake_site: Path) -> None:
    write_fake_distribution(
        fake_site,
        "ck-sample-plugin",
        "0.1.0",
        entry_points={"codekavach.stages": {"sample": "ck_sample:SampleStage"}},
        modules={"ck_sample.py": "raise RuntimeError('imported')\n"},
    )
    specs = [spec for spec in discover() if spec.dist_name == "ck-sample-plugin"]
    assert specs == [
        PluginSpec(
            "codekavach.stages", "sample", "ck_sample:SampleStage", "ck-sample-plugin", "0.1.0"
        )
    ]
    assert "ck_sample" not in sys.modules
