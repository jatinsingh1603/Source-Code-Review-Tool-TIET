"""No telemetry or analytics distribution is locked or installed.

CodeKavach has no telemetry, update check or crash reporting. A dependency that brings such a
package would change that without a line of our code changing, so both the lock file and the
installed environment are audited.
"""

import importlib.metadata
import re
import tomllib
from collections.abc import Iterable
from pathlib import Path

import pytest

pytestmark = pytest.mark.privacy

LOCK_FILE = Path(__file__).resolve().parents[2] / "uv.lock"

# Distribution names as PyPI spells them. To request an exception (for example an exporter that
# an operator has to switch on explicitly), write an ADR that names the package, what it sends
# and to whom, and how it stays off by default; remove the name here in the commit that adds
# the ADR.
TELEMETRY_DISTRIBUTIONS = (
    "sentry-sdk",
    "posthog",
    "analytics-python",
    "mixpanel",
    "opentelemetry-exporter-otlp",
)


def normalised(name: str) -> str:
    """The comparison form of a distribution name (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def telemetry_among(names: Iterable[str]) -> list[str]:
    """The telemetry distributions found in ``names``."""
    banned = {normalised(name) for name in TELEMETRY_DISTRIBUTIONS}
    return sorted({normalised(name) for name in names} & banned)


def locked_names() -> list[str]:
    lock = tomllib.loads(LOCK_FILE.read_text(encoding="utf-8"))
    return [package["name"] for package in lock["package"]]


def installed_names() -> list[str]:
    return [
        name
        for distribution in importlib.metadata.distributions()
        if (name := distribution.metadata["Name"])
    ]


def test_lock_file_has_no_telemetry_distribution() -> None:
    names = locked_names()
    assert "typer" in names  # the lock file was really read
    assert telemetry_among(names) == []


def test_environment_has_no_telemetry_distribution() -> None:
    names = installed_names()
    assert "typer" in {normalised(name) for name in names}
    assert telemetry_among(names) == []


def test_audit_fails_when_a_telemetry_distribution_is_present() -> None:
    assert telemetry_among([*installed_names(), "sentry-sdk"]) == ["sentry-sdk"]
    assert telemetry_among(["Sentry_SDK", "PostHog", "typer"]) == ["posthog", "sentry-sdk"]
    assert telemetry_among(["opentelemetry.exporter.otlp", "analytics_python", "mixpanel"]) == [
        "analytics-python",
        "mixpanel",
        "opentelemetry-exporter-otlp",
    ]
    assert telemetry_among(["sentry", "opentelemetry-api", "requests"]) == []
