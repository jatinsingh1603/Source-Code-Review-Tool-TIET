"""I1 at the command layer, static half: ``codekavach.cli`` imports no network client.

The dynamic test (``test_cli_no_network.py``) sees only code that runs in tests. This scan also
covers an error handler or a rarely used branch: every ``import`` statement of every file under
``src/codekavach/cli/``, at any nesting depth.
"""

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.privacy

CLI_SOURCE = Path(__file__).resolve().parents[2] / "src" / "codekavach" / "cli"

NETWORK_MODULES = (
    "socket",
    "ssl",
    "http.client",
    "urllib.request",
    "urllib3",
    "httpx",
    "requests",
    "aiohttp",
    "websockets",
    "smtplib",
    "ftplib",
)
PROVIDER_SDKS = ("anthropic", "openai", "google.generativeai", "boto3", "litellm")
ANALYTICS = ("sentry_sdk", "posthog", "segment", "mixpanel")
FORBIDDEN = NETWORK_MODULES + PROVIDER_SDKS + ANALYTICS


def imported_modules(source: str) -> set[str]:
    """Every module an ``import`` or ``from ... import`` statement in ``source`` can load."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def forbidden_imports(source: str) -> list[str]:
    """The forbidden modules that ``source`` imports, by the name it imports them under."""
    return sorted(
        name
        for name in imported_modules(source)
        if any(name == banned or name.startswith(f"{banned}.") for banned in FORBIDDEN)
    )


def test_no_cli_module_imports_a_network_client() -> None:
    files = sorted(CLI_SOURCE.rglob("*.py"))
    assert len(files) >= 20
    found = {
        str(file.relative_to(CLI_SOURCE)): hits
        for file in files
        if (hits := forbidden_imports(file.read_text(encoding="utf-8")))
    }
    assert not found, found


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import httpx\n", ["httpx"]),
        ("import socket, ssl\n", ["socket", "ssl"]),
        ("from urllib import request\n", ["urllib.request"]),
        ("import urllib.request as web\n", ["urllib.request"]),
        ("from http.client import HTTPSConnection\n",
         ["http.client", "http.client.HTTPSConnection"]),
        ("from requests.adapters import HTTPAdapter\n",
         ["requests.adapters", "requests.adapters.HTTPAdapter"]),
        ("def late():\n    import anthropic\n", ["anthropic"]),
        ("try:\n    import sentry_sdk\nexcept ImportError:\n    pass\n", ["sentry_sdk"]),
        ("from google import generativeai\n", ["google.generativeai"]),
        ("if True:\n    from litellm import completion\n", ["litellm", "litellm.completion"]),
        ("import boto3.session\n", ["boto3.session"]),
        ("import posthog\nimport mixpanel\nimport segment.analytics\n",
         ["mixpanel", "posthog", "segment.analytics"]),
        ("import smtplib\nimport ftplib\nimport websockets\nimport aiohttp\nimport urllib3\n",
         ["aiohttp", "ftplib", "smtplib", "urllib3", "websockets"]),
    ],
)  # fmt: skip
def test_scanner_reports_forbidden_imports(source: str, expected: list[str]) -> None:
    assert forbidden_imports(source) == expected


@pytest.mark.parametrize(
    "source",
    [
        "import urllib.parse\n",
        "from urllib.parse import urlsplit\n",
        "import http\n",
        "import socketserver_helpers\n",
        "import requests_like\n",
        "from . import request\n",
        "from .socket import helper\n",
        "text = 'import httpx'\n",
        "import typer\nimport rich.console\n",
    ],
)
def test_scanner_accepts_harmless_imports(source: str) -> None:
    assert forbidden_imports(source) == []
