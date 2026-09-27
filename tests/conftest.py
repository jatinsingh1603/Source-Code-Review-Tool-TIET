"""Suite-wide pytest configuration: automatic tier markers and shared fixtures."""

from pathlib import Path

import pytest

from tests.support.tiers import tier_of


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Mark every test with the tier of the directory it lives in."""
    root = config.rootpath / "tests"
    for item in items:
        tier = tier_of(item.path, root)
        if tier is not None:
            item.add_marker(getattr(pytest.mark, tier))


@pytest.fixture
def repo_root(pytestconfig: pytest.Config) -> Path:
    """Return the repository root."""
    return pytestconfig.rootpath
