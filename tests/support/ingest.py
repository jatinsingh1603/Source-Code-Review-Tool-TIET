"""Helpers for tests that run the real ``IngestStage`` through ``run_scan``."""

from codekavach.core.plugins.discovery import PluginSpec, discover
from codekavach.core.plugins.registry import PluginRegistry

SALT_HEX = "6c" * 32  # pragma: allowlist secret


def ingest_registry() -> PluginRegistry:
    """A registry holding only the ``ingest`` stage that the ``codekavach`` distribution ships."""
    specs: list[PluginSpec] = [
        spec
        for spec in discover()
        if spec.group == "codekavach.stages"
        and spec.name == "ingest"
        and spec.dist_name == "codekavach"
    ]
    assert len(specs) == 1, "the codekavach.stages entry point for ingest is not installed"
    return PluginRegistry(specs)
