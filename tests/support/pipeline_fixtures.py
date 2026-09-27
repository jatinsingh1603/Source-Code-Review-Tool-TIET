"""Pytest fixtures of the pipeline test kit, registered in ``tests/conftest.py``."""

import importlib
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def fake_site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A temporary site directory at the front of ``sys.path``; fake modules are unloaded after."""
    site = tmp_path / "site-packages"
    site.mkdir()
    before = set(sys.modules)
    monkeypatch.syspath_prepend(str(site))
    importlib.invalidate_caches()
    yield site
    for name in set(sys.modules) - before:
        module = sys.modules.get(name)
        location = getattr(module, "__file__", None) or ""
        if location and Path(location).resolve().is_relative_to(site.resolve()):
            del sys.modules[name]
    importlib.invalidate_caches()
