"""No secret, personal-data or term detector performs a network operation (E08-02, E08-03, I1).

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
from tests.support.corpus import case_names, load_case
from tests.support.no_network import NetworkAttempts
from tests.support.real_detectors import CORPUS_PREFIXES, real_detected
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


# The one module that starts a process: the optional external-engine adapters (E08-04). They run
# the engine without network, with a timeout and without repository configuration; tests of
# that module assert the argument vector. Every other module, and every network module even in
# this one, stays forbidden.
PROCESS_MODULES = {"secrets/adapters.py": {"subprocess"}}


def test_no_detector_module_imports_a_network_or_process_module() -> None:
    root = Path(next(iter(detect_package.__path__)))
    offenders = {
        f"{path.relative_to(root)}: {module}"
        for path in root.rglob("*.py")
        for module in imported_modules(path)
        if (module in FORBIDDEN or module.split(".")[0] in FORBIDDEN - {"urllib.request"})
        and module not in PROCESS_MODULES.get(path.relative_to(root).as_posix(), set())
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


@pytest.mark.privacy
def test_the_pii_and_term_detectors_run_over_their_corpus_without_touching_the_network(
    no_network: NetworkAttempts,
) -> None:
    total = 0
    for name in case_names():
        if name.startswith(CORPUS_PREFIXES):
            total += len(real_detected(load_case(name).text))
    assert total > 30
    assert no_network.count == 0
