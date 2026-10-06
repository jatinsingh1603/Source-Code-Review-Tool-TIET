"""The configuration package contains no endpoint it could call (E03-44).

Two static scans over ``src/codekavach/config``: every URL in a string constant is on a short,
reasoned allow-list, and no module imports a network client or a credential store at module
level. Both complement the runtime check in ``tests/integration/config/test_offline.py``: that
one proves a load makes no connection, these catch a connection that a test never exercises.
"""

import ast
import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest

PACKAGE = Path(__file__).resolve().parents[3] / "src" / "codekavach" / "config"
URL = re.compile(r"https?://[^\s'\"`)>\]]+")

# Every URL host in a string constant, with the module that may hold it and why. None is called.
ALLOWED_HOSTS: dict[str, dict[str, str]] = {
    "constants.py": {"raw.githubusercontent.com": "base of the schema $id; an identifier"},
    "masking.py": {"host": "the documented shape of a masked URL (docstring)"},
    "models/integrations.py": {"api.github.com": "default API base URL; used by the sync stage"},
    "models/llm.py": {"127.0.0.1": "the default URL of a local Ollama; loopback"},
    "schema.py": {"json-schema.org": "the JSON Schema dialect identifier; never fetched"},
    "starter.py": {"127.0.0.1": "a commented example in the starter file; loopback"},
}
NETWORK_AND_CREDENTIAL_MODULES = (
    "socket", "ssl", "http", "urllib.request", "urllib3", "httpx", "requests", "aiohttp",
    "smtplib", "ftplib", "xmlrpc", "keyring", "cryptography", "litellm", "anthropic", "openai",
)  # fmt: skip


def modules() -> list[Path]:
    return sorted(path for path in PACKAGE.rglob("*.py") if "__pycache__" not in path.parts)


def relative(path: Path) -> str:
    return path.relative_to(PACKAGE).as_posix()


def url_hosts(source: str) -> set[str]:
    """The host of every URL inside a string constant (docstrings and f-string parts too)."""
    hosts: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for match in URL.findall(node.value):
                hosts.add(urlsplit(match).hostname or match)
    return hosts


def module_level_imports(source: str) -> set[str]:
    """Dotted names imported by the top-level statements of a module (not inside functions)."""
    names: set[str] = set()
    for node in ast.parse(source).body:
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def is_forbidden(name: str) -> bool:
    return any(
        name == banned or name.startswith(f"{banned}.") for banned in NETWORK_AND_CREDENTIAL_MODULES
    )


def test_the_scan_sees_the_package() -> None:
    assert len(modules()) > 30


def test_every_url_in_the_package_is_allow_listed() -> None:
    unexpected: list[str] = []
    for path in modules():
        allowed = ALLOWED_HOSTS.get(relative(path), {})
        found = url_hosts(path.read_text(encoding="utf-8"))
        unexpected.extend(f"{relative(path)}: {host}" for host in sorted(found - set(allowed)))
    assert unexpected == [], (
        "a URL appeared in the configuration package; if it is needed, add it to ALLOWED_HOSTS "
        "with the reason and an approving issue"
    )


def test_the_allow_list_has_no_stale_entries() -> None:
    for name, hosts in ALLOWED_HOSTS.items():
        found = url_hosts((PACKAGE / name).read_text(encoding="utf-8"))
        assert set(hosts) <= found, f"{name}: {sorted(set(hosts) - found)} no longer appears"
        assert all(reason.strip() for reason in hosts.values())


def test_no_module_imports_a_network_client_or_credential_store_at_module_level() -> None:
    offenders = [
        f"{relative(path)}: {name}"
        for path in modules()
        for name in sorted(module_level_imports(path.read_text(encoding="utf-8")))
        if is_forbidden(name)
    ]
    assert offenders == []


# --- the scanners are live ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "hosts"),
    [
        ('X = "https://telemetry.example.invalid/collect"', {"telemetry.example.invalid"}),
        ('"""Docs: see http://evil.example.invalid/x."""', {"evil.example.invalid"}),
        ('X = f"https://{a}.example.invalid/{b}"', set()),  # the host is dynamic; no constant URL
        ('X = ("https://a.example.invalid/" "b")', {"a.example.invalid"}),
        ("X = 1  # https://in-a-comment.example.invalid", set()),  # comments are not constants
    ],
    ids=["constant", "docstring", "fstring-host", "concatenated", "comment"],
)
def test_url_scanner(source: str, hosts: set[str]) -> None:
    assert url_hosts(source) == hosts


@pytest.mark.parametrize(
    ("source", "found"),
    [
        ("import httpx", {"httpx"}),
        ("from urllib.request import urlopen", {"urllib.request"}),
        ("import keyring", {"keyring"}),
        ("def f():\n    import keyring\n", set()),  # a lazy import inside a function is allowed
        ("if True:\n    import socket\n", set()),  # only top-level statements are considered
        ("from . import sibling", set()),
    ],
    ids=["httpx", "urllib", "keyring", "lazy", "nested", "relative"],
)
def test_import_scanner(source: str, found: set[str]) -> None:
    assert module_level_imports(source) == found


def test_forbidden_matching_is_by_dotted_prefix() -> None:
    assert is_forbidden("http.client")
    assert is_forbidden("urllib.request")
    assert not is_forbidden("urllib.parse")
    assert not is_forbidden("httpx_sse_like")
    assert not is_forbidden("httpserver")
