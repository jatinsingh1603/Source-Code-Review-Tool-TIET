"""Helpers for tests that run the real built-in stages through ``run_scan``."""

import shutil
from pathlib import Path

from codekavach.core.plugins.discovery import PluginSpec, discover
from codekavach.core.plugins.registry import PluginRegistry

SALT_HEX = "6c" * 32  # pragma: allowlist secret
PROJECTS_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "parsing" / "projects"


def stages_registry(*names: str) -> PluginRegistry:
    """A registry holding only the named stages that the ``codekavach`` distribution ships."""
    specs: list[PluginSpec] = [
        spec
        for spec in discover()
        if spec.group == "codekavach.stages"
        and spec.name in names
        and spec.dist_name == "codekavach"
    ]
    assert sorted(spec.name for spec in specs) == sorted(names), (
        "a codekavach.stages entry point is not installed"
    )
    return PluginRegistry(specs)


def ingest_registry() -> PluginRegistry:
    """A registry holding only the ``ingest`` stage."""
    return stages_registry("ingest")


def materialise_project(name: str, into: Path) -> Path:
    """Copy the sample project ``name`` into ``into``, stripping the ``.txt`` suffix of each file.

    Fixtures are stored as ``.txt`` so that linters, type checkers and the JSON hook leave them
    alone; scanning needs the real names.
    """
    source = PROJECTS_ROOT / name
    for path in sorted(source.rglob("*")):
        if path.is_file():
            target = into / path.relative_to(source).with_suffix("")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    return into
