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

pytest_plugins = [
    "tests.support.cli_fixtures",
    "tests.support.pipeline_fixtures",
    "tests.support.config",
    "tests.support.no_network",
]

# No test may reach the operating system's keyring: on macOS a real Keychain can block a headless
# runner waiting for an unlock prompt, and a developer's own secrets must never be read. The
# refusing backend makes every platform behave like the Linux runners (the vault fails closed);
# tests that need a keyring use the in-memory one. Set before keyring is first imported and
# inherited by the subprocesses the CLI tests start.
os.environ["PYTHON_KEYRING_BACKEND"] = "keyring.backends.fail.Keyring"

PROFILE_VARIABLE = "HYPOTHESIS_PROFILE"
PROFILES = ("dev", "ci", "nightly")

# E02 extends this registration; never register a profile name twice. Unnamed settings are
# inherited from hypothesis' own defaults, and with CI=true in the environment (a CI runner, some
# dev containers) those defaults are already derandomised, so every profile states it.
settings.register_profile(
    "dev", max_examples=50, deadline=timedelta(milliseconds=500), derandomize=False
)
settings.register_profile("ci", max_examples=200, deadline=None, derandomize=True, print_blob=True)
settings.register_profile("nightly", max_examples=2000, deadline=None, derandomize=False)


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register ``--engines-live``: re-record the engine conformance cases (E14-02)."""
    parser.addoption(
        "--engines-live",
        action="store_true",
        default=False,
        help="re-record the recorded engine cases with the installed engines (never in CI)",
    )


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


@pytest.fixture(scope="session", autouse=True)
def project_logging() -> None:
    """Start every worker with the product's logging configuration.

    Without it structlog keeps its development defaults until a test configures it: debug events
    print, and an event with ``exc_info`` is rendered as a rich traceback with every frame's
    locals. A failing stage logs one (``stage_failed_detail``), and rendering the run context's
    settings that way took longer than the 120 s test timeout on a CI runner.
    """
    configure_logging(force=True)


@pytest.fixture
def log_output() -> Iterator[io.StringIO]:
    """Configure JSON logging into a buffer; restore the default configuration afterwards."""
    buffer = io.StringIO()
    configure_logging(fmt="json", level="DEBUG", stream=buffer, force=True)
    yield buffer
    configure_logging(force=True)
