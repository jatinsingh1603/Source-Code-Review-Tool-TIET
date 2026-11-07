"""I1: only ``codekavach.privacy.egress.transport`` opens connections to model endpoints (E12-04).

Four statements, each of which fails if the claim is weakened:

* the import contract names every network client individually, covers every network-capable
  distribution in the lock file, and breaks when another module imports one;
* a request without a valid ticket opens no socket, and a refused request opens none either;
* a request that passes every check is the one thing that does reach for a socket;
* the header allow-list stops a provider adapter from smuggling metadata past the guard.

The app-wide scan with sockets blocked needs the pipeline wiring of E13-02; until then the socket
statements are made at the transport itself.
"""

import configparser
import re
import tomllib
from collections.abc import Sequence
from pathlib import Path

import pytest

from codekavach.config import Settings
from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.enums import PrivacyLevel
from codekavach.core.pipeline.context import ConsentDecision
from codekavach.privacy.egress.guard import EgressGuard, ScannerRegistry
from codekavach.privacy.egress.models import EgressBlocked, EgressMeta, EgressTicket, LeakHit
from codekavach.privacy.egress.transport import (
    ALLOWED_HEADERS,
    Refusal,
    SimpleRequest,
    Transport,
    TransportRefused,
)
from tests.support.fake_tree import build_fake_tree
from tests.support.lint_imports import run_lint_imports
from tests.support.no_network import NetworkAttempts

pytestmark = pytest.mark.privacy

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / ".importlinter"
LOCK_FILE = REPO / "uv.lock"

# Every distribution in the lock file that can open a network connection, with the name its
# import goes by. Each must be forbidden outside the transport by the contract. Adding a
# dependency fails ``test_every_locked_distribution_is_classified`` until it is placed here or in
# REVIEWED_OFFLINE, which is the point: a new dependency cannot quietly open a second door.
NETWORK_DISTRIBUTIONS = {
    "httpx": "httpx",
    "httpcore": "httpcore",
    "h11": "h11",
    "anyio": "anyio",
    "requests": "requests",
    "urllib3": "urllib3",
}
# Reviewed and found not to open connections of their own in this product: they either run only
# in development or never touch a remote host (``jeepney`` and ``secretstorage`` speak D-Bus on a
# local socket for the keyring; ``certifi`` is a certificate bundle, not a client).
REVIEWED_OFFLINE = frozenset(
    (
        "alembic",
        "annotated-doc",
        "annotated-types",
        "ast-serialize",
        "attrs",
        "certifi",
        "cffi",
        "cfgv",
        "charset-normalizer",
        "click",
        "codekavach",
        "colorama",
        "coverage",
        "cryptography",
        "detect-secrets",
        "distlib",
        "execnet",
        "filelock",
        "grimp",
        "hypothesis",
        "identify",
        "idna",
        "import-linter",
        "iniconfig",
        "jaraco-classes",
        "jaraco-context",
        "jaraco-functools",
        "jeepney",
        "jinja2",
        "jsonschema",
        "jsonschema-specifications",
        "keyring",
        "librt",
        "mako",
        "markdown-it-py",
        "markupsafe",
        "mdurl",
        "more-itertools",
        "mypy",
        "mypy-extensions",
        "nodeenv",
        "packaging",
        "pathspec",
        "platformdirs",
        "pluggy",
        "pre-commit",
        "pycparser",
        "pydantic",
        "pydantic-core",
        "pydantic-settings",
        "pygments",
        "pytest",
        "pytest-cov",
        "pytest-randomly",
        "pytest-socket",
        "pytest-timeout",
        "pytest-xdist",
        "python-discovery",
        "python-dotenv",
        "pywin32-ctypes",
        "pyyaml",
        "referencing",
        "rich",
        "rpds-py",
        "ruff",
        "secretstorage",
        "shellingham",
        "sortedcontainers",
        "sqlalchemy",
        "structlog",
        "tomli-w",
        "towncrier",
        "tree-sitter",
        "tree-sitter-c-sharp",
        "tree-sitter-embedded-template",
        "tree-sitter-language-pack",
        "tree-sitter-yaml",
        "typer",
        "types-jsonschema",
        "types-pyyaml",
        "typing-extensions",
        "typing-inspection",
        "virtualenv",
    )
)
VENDOR_SDKS = (
    "anthropic",
    "openai",
    "boto3",
    "botocore",
    "azure",
    "litellm",
    "ollama",
    "aiohttp",
    "websockets",
)


def _forbidden() -> set[str]:
    parser = configparser.ConfigParser()
    parser.read(CONFIG, encoding="utf-8")
    return set(parser.get("importlinter:contract:i1-single-egress", "forbidden_modules").split())


def _locked() -> set[str]:
    lock = tomllib.loads(LOCK_FILE.read_text(encoding="utf-8"))
    return {re.sub(r"[-_.]+", "-", package["name"]).lower() for package in lock["package"]}


# --- the contract ---------------------------------------------------------------------------


def test_the_contract_names_each_client_and_vendor_sdk_individually() -> None:
    forbidden = _forbidden()
    assert "httpx" in forbidden
    for name in (*NETWORK_DISTRIBUTIONS.values(), *VENDOR_SDKS):
        assert name in forbidden, name
    assert not any("*" in entry for entry in forbidden)


def test_the_forbidden_list_covers_every_network_distribution_in_the_lock_file() -> None:
    locked = _locked()
    present = {dist: module for dist, module in NETWORK_DISTRIBUTIONS.items() if dist in locked}
    assert "httpx" in present  # the lock file was really read
    assert set(present.values()) <= _forbidden()


def test_every_locked_distribution_is_classified() -> None:
    unclassified = _locked() - set(NETWORK_DISTRIBUTIONS) - REVIEWED_OFFLINE
    assert unclassified == set(), (
        f"new locked distribution(s) {sorted(unclassified)}: decide whether each can open a "
        "network connection; if so add it to NETWORK_DISTRIBUTIONS and to the i1-single-egress "
        "contract in .importlinter, otherwise to REVIEWED_OFFLINE"
    )


@pytest.mark.parametrize("module", ["httpx", "h11", "anyio", "requests", "openai", "azure"])
def test_a_planted_import_outside_the_transport_breaks_the_build(
    tmp_path: Path, module: str
) -> None:
    tree = build_fake_tree(
        tmp_path, CONFIG, {"codekavach/report/render/bad.py": f"import {module}\n"}
    )
    completed = run_lint_imports(tree, CONFIG)
    assert completed.returncode == 1, completed.stdout
    assert "I1 only privacy.egress.transport" in completed.stdout


def test_the_transport_itself_may_import_the_client(tmp_path: Path) -> None:
    files = {"codekavach/privacy/egress/transport.py": "import httpx\n"}
    tree = build_fake_tree(tmp_path, CONFIG, files)
    assert run_lint_imports(tree, CONFIG).returncode == 0


# --- sockets --------------------------------------------------------------------------------

PAYLOAD = "def fn_1(var_1):\n    return var_1\n"
DIGEST = sha256_hex(PAYLOAD)
BODY = ('{"payload": "' + PAYLOAD.replace("\n", "\\n") + '", "h": "' + DIGEST + '"}').encode()
URL = "https://api.example.test/v1/messages"
SETTINGS = Settings.model_validate(
    {
        "llm": {
            "allow_remote": True,
            "providers": {
                "hosted": {"kind": "openai-compatible", "model": "m", "base_url": URL},
            },
        },
        "privacy": {"egress": {"provider_host_allowlist": ["api.example.test"]}},
    }
)


class Clean:
    id = "clean"

    def scan(self, body: bytes, meta: EgressMeta) -> Sequence[LeakHit]:
        return ()


def _ticket(guard: EgressGuard) -> EgressTicket:
    meta = EgressMeta(provider="hosted", model="m", level=PrivacyLevel.L3, payload_hash=DIGEST)
    decision = guard.evaluate(
        BODY,
        meta,
        settings=SETTINGS,
        consent=ConsentDecision(granted=True, source="flag"),
        payload_text=PAYLOAD,
    )
    assert decision.ticket is not None
    return decision.ticket


def _transport(guard: EgressGuard) -> Transport:
    return Transport(guard, SETTINGS, resolver=lambda _host: ["93.184.216.34"])


def _request(**overrides: object) -> SimpleRequest:
    fields: dict[str, object] = {
        "method": "POST",
        "url": URL,
        "headers": {"content-type": "application/json"},
        "body": BODY,
    }
    return SimpleRequest(**(fields | overrides))  # type: ignore[arg-type]


def test_a_ticket_from_another_guard_opens_no_socket(no_network: NetworkAttempts) -> None:
    ours, theirs = EgressGuard(ScannerRegistry([Clean()])), EgressGuard(ScannerRegistry([Clean()]))
    foreign = _ticket(theirs)
    with pytest.raises(EgressBlocked):
        _transport(ours).send(_request(), foreign)
    assert no_network.count == 0


def test_a_consumed_ticket_opens_no_socket_the_second_time(no_network: NetworkAttempts) -> None:
    guard = EgressGuard(ScannerRegistry([Clean()]))
    ticket = _ticket(guard)
    transport = _transport(guard)
    with pytest.raises(AssertionError, match="network access attempted"):
        transport.send(_request(), ticket)  # the redemption happens, then the connection is tried
    first = no_network.count
    assert first >= 1
    with pytest.raises(EgressBlocked):
        transport.send(_request(), ticket)
    assert no_network.count == first


@pytest.mark.parametrize(
    "case",
    [
        {"url": "http://api.example.test/v1/messages"},
        {"url": "https://elsewhere.example.test/v1"},
        {"url": "https://203.0.113.9/v1"},
        {"headers": {"x-repository": "kavachbank"}},
        {"body": b"not the payload"},
    ],
)
def test_a_refused_request_opens_no_socket(
    case: dict[str, object], no_network: NetworkAttempts
) -> None:
    guard = EgressGuard(ScannerRegistry([Clean()]))
    with pytest.raises(TransportRefused):
        _transport(guard).send(_request(**case), _ticket(guard))
    assert no_network.count == 0


def test_the_one_request_that_passes_every_check_is_the_one_that_reaches_for_a_socket(
    no_network: NetworkAttempts,
) -> None:
    guard = EgressGuard(ScannerRegistry([Clean()]))
    with pytest.raises(AssertionError, match="network access attempted"):
        _transport(guard).send(_request(), _ticket(guard))
    assert no_network.count >= 1
    assert all(
        "api.example.test" in attempt or "socket" in attempt for attempt in no_network.attempts
    )


# --- headers --------------------------------------------------------------------------------


def test_the_header_allow_list_is_closed_and_an_extra_header_is_refused() -> None:
    assert {
        "authorization",
        "x-api-key",
        "api-key",
        "content-type",
        "accept",
        "user-agent",
    } == ALLOWED_HEADERS
    guard = EgressGuard(ScannerRegistry([Clean()]))
    for name in ("x-repository", "x-machine-id", "x-forwarded-for", "cookie", "x-trace"):
        with pytest.raises(TransportRefused) as caught:
            _transport(guard).send(_request(headers={name: "v"}), _ticket(guard))
        assert caught.value.reason == Refusal.HEADER
