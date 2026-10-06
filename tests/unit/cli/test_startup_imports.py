"""Informational invocations import no back end (E05-31).

``--version``, ``--help``, ``scan --help`` and a completion request run in a fresh interpreter,
because the pytest process has already imported everything; the test then inspects
``sys.modules`` for the deny list.
"""

import json
import os
import subprocess
import sys

import pytest

# Top-level packages, and CodeKavach packages, that informational invocations must not import.
# Pygments is not listed: structlog imports rich.traceback, which imports pygments, as soon as
# structlog itself is imported (structlog.dev), and structlog is part of every invocation.
DENY = (
    "pydantic", "pydantic_core", "sqlalchemy", "alembic", "tree_sitter",
    "tree_sitter_language_pack", "keyring", "cryptography", "httpx", "requests", "litellm",
    "anthropic", "openai", "google", "boto3", "weasyprint", "docxtpl", "jinja2", "xlsxwriter",
    "codekavach.core.pipeline", "codekavach.core.plugins", "codekavach.privacy",
    "codekavach.llm", "codekavach.analysis", "codekavach.report", "codekavach.integrations",
)  # fmt: skip

PROGRAM = """
import contextlib, io, json, sys
from codekavach.cli.app import main
with contextlib.redirect_stdout(io.StringIO()):
    try:
        main({argv!r})
    except SystemExit:
        pass
print(json.dumps(sorted(sys.modules)))
"""


def imported(argv: list[str], env: dict[str, str] | None = None) -> list[str]:
    """The modules a fresh interpreter has loaded after ``main(argv)``."""
    environment = {**os.environ, **(env or {})}
    completed = subprocess.run(
        [sys.executable, "-c", PROGRAM.format(argv=argv)],
        capture_output=True,
        text=True,
        check=True,
        env=environment,
    )
    last = completed.stdout.strip().splitlines()[-1]
    modules: list[str] = json.loads(last)
    return modules


def denied(modules: list[str]) -> list[str]:
    """Deny-listed packages present in ``modules`` (prefix match on dotted names)."""
    return sorted(
        {
            name
            for name in DENY
            for module in modules
            if module == name or module.startswith(f"{name}.")
        }
    )


@pytest.mark.parametrize(
    "argv", [["--version"], ["--help"], ["scan", "--help"]], ids=["version", "help", "scan-help"]
)
def test_informational_invocations_import_no_back_end(argv: list[str]) -> None:
    assert denied(imported(argv)) == []


def test_completion_request_imports_no_back_end() -> None:
    env = {
        "_CODEKAVACH_COMPLETE": "bash_complete",
        "COMP_WORDS": "codekavach sc",
        "COMP_CWORD": "1",
    }
    assert denied(imported([], env)) == []


def test_matcher_uses_prefixes() -> None:
    assert denied(["sqlalchemy.orm", "httpx_sse", "pydantic_core"]) == [
        "pydantic_core",
        "sqlalchemy",
    ]
    assert denied(["codekavach.privacy.vault", "codekavach.privacy_notes"]) == [
        "codekavach.privacy"
    ]
