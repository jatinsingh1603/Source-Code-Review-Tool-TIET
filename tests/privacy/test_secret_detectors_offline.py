"""No secret detector performs a network operation (E08-02, I1).

Two halves: a static check that nothing in ``codekavach.privacy.detect`` imports a network or
process module, and a run of every detector over the whole corpus with every socket, DNS lookup
and TLS wrap refused and recorded (the E01-08 block, plus a record that survives a swallowed
exception). Validation in this package is structural only; none of it contacts a provider.
"""

import ast
from pathlib import Path

import pytest

import codekavach.privacy.detect as detect_package
from codekavach.config.models.root import Settings
from codekavach.core.models import RawCode
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_all
from codekavach.privacy.detect.secrets.builtin import register_secret_detectors
from tests.support.no_network import NetworkAttempts
from tests.support.secret_corpus import secret_cases

FORBIDDEN = frozenset(
    {"socket", "ssl", "http", "urllib.request", "urllib3", "requests", "httpx", "httpcore"}
    | {"aiohttp", "ftplib", "smtplib", "telnetlib", "xmlrpc", "asyncio", "subprocess", "webbrowser"}
)


def imported_modules(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def test_no_detector_module_imports_a_network_or_process_module() -> None:
    root = Path(next(iter(detect_package.__path__)))
    offenders = {
        f"{path.relative_to(root)}: {module}"
        for path in root.rglob("*.py")
        for module in imported_modules(path)
        if module in FORBIDDEN or module.split(".")[0] in FORBIDDEN - {"urllib.request"}
    }
    assert offenders == set()


@pytest.mark.privacy
def test_every_detector_runs_over_the_whole_corpus_without_touching_the_network(
    no_network: NetworkAttempts,
) -> None:
    registry = register_secret_detectors(DetectorRegistry())
    total = 0
    for case in secret_cases():
        total += len(
            detect_all(
                RawCode(case.text),
                path=case.path,
                language=case.language,
                settings=Settings(),
                registry=registry,
            )
        )
    assert total > 40
    assert no_network.count == 0
