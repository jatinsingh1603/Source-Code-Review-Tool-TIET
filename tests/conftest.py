"""Suite-wide pytest configuration: hypothesis profiles, tier markers and shared fixtures."""

import io
import os
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from hypothesis import settings

from codekavach.core.log import configure_logging
from tests.support.tiers import tier_of

pytest_plugins = ["tests.support.cli_fixtures", "tests.support.pipeline_fixtures"]

PROFILE_VARIABLE = "HYPOTHESIS_PROFILE"
PROFILES = ("dev", "ci", "nightly")

# E02 extends this registration; never register a profile name twice.
settings.register_profile("dev", max_examples=50, deadline=timedelta(milliseconds=500))
settings.register_profile("ci", max_examples=200, deadline=None, derandomize=True, print_blob=True)
settings.register_profile("nightly", max_examples=2000, deadline=None)


def pytest_configure(config: pytest.Config) -> None:
    """Load the hypothesis profile named by HYPOTHESIS_PROFILE (default dev)."""
    name = os.environ.get(PROFILE_VARIABLE, "dev")
    if name not in PROFILES:
        raise pytest.UsageError(
            f"unknown {PROFILE_VARIABLE} {name!r}; valid profiles: {', '.join(PROFILES)}"
        )
    settings.load_profile(name)


NETWORK_VARIABLE = "CODEKAVACH_TEST_NETWORK"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Mark every test with its tier; gate ``network`` tests behind CODEKAVACH_TEST_NETWORK=1.

    A ``-m`` expression on the command line replaces the ``-m "not network"`` of ``addopts``, so
    deselection alone is not reliable: without the variable a ``network`` test is skipped, and
    with it the test (and only that test) may open sockets.
    """
    root = config.rootpath / "tests"
    network_allowed = os.environ.get(NETWORK_VARIABLE) == "1"
    for item in items:
        tier = tier_of(item.path, root)
        if tier is not None:
            item.add_marker(getattr(pytest.mark, tier))
        if item.get_closest_marker("network") is not None:
            if network_allowed:
                item.add_marker(pytest.mark.enable_socket)
            else:
                item.add_marker(
                    pytest.mark.skip(reason=f"external network test; set {NETWORK_VARIABLE}=1")
                )


@pytest.fixture
def repo_root(pytestconfig: pytest.Config) -> Path:
    """Return the repository root."""
    return pytestconfig.rootpath


@pytest.fixture
def log_output() -> Iterator[io.StringIO]:
    """Configure JSON logging into a buffer; restore the default configuration afterwards."""
    buffer = io.StringIO()
    configure_logging(fmt="json", level="DEBUG", stream=buffer, force=True)
    yield buffer
    configure_logging(force=True)
