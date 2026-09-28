"""The import contracts (I1, I2, I3) are kept by the real tree and broken by planted violations.

A control that has never been seen to fail is not known to work. Each case plants one violation in a
miniature ``codekavach`` package and runs the real ``.importlinter`` against it. Missing tooling,
an empty derived module list or analysing the wrong tree all fail the test.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.support.fake_tree import build_fake_tree, contract_modules, contract_names
from tests.support.lint_imports import (
    analysed_package,
    lint_imports_executable,
    run_lint_imports,
    tree_environment,
)

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / ".importlinter"
NAMES = contract_names(CONFIG)

VIOLATIONS = {
    "i2-providers-import-parsing": (
        {"codekavach/llm/providers/bad.py": "import codekavach.parsing\n"},
        "i2-llm-no-raw-code",
    ),
    "i2-tasks-import-slicing": (
        {
            "codekavach/llm/tasks/bad.py": "from codekavach.privacy.slicing import x\n",
            "codekavach/privacy/slicing/__init__.py": "x = 1\n",
        },
        "i2-llm-no-raw-code",
    ),
    "i2-type-checking-import": (
        {
            "codekavach/llm/bad.py": (
                "from typing import TYPE_CHECKING\n\nif TYPE_CHECKING:\n"
                "    import codekavach.ingest\n"
            )
        },
        "i2-llm-no-raw-code",
    ),
    "i1-report-httpx": ({"codekavach/report/render/bad.py": "import httpx\n"}, "i1-single-egress"),
    "i1-sca-requests": (
        {"codekavach/analysis/sca/bad.py": "import requests\n"},
        "i1-single-egress",
    ),
    "i1-provider-openai": (
        {"codekavach/llm/providers/bad.py": "import openai\n"},
        "i1-single-egress",
    ),
    "i3-github-vault": (
        {"codekavach/integrations/github/bad.py": "import codekavach.privacy.vault\n"},
        "i3-vault-locality",
    ),
    "config-imports-privacy": (
        {"codekavach/config/bad.py": "import codekavach.privacy\n"},
        "config-is-a-leaf",
    ),
    "models-import-config": (
        {"codekavach/core/models/bad.py": "import codekavach.config\n"},
        "core-models-independent",
    ),
}

ALLOWED = {
    "transport-imports-httpx": {"codekavach/privacy/egress/transport.py": "import httpx\n"},
    "indirect-vault-chain": {
        "codekavach/llm/ok.py": "import codekavach.privacy.egress.guard\n",
        "codekavach/privacy/egress/guard.py": "import codekavach.privacy.vault\n",
    },
}


@pytest.fixture
def fake(tmp_path: Path) -> Path:
    return tmp_path / "tree"


def test_every_contract_has_a_planted_violation() -> None:
    assert {contract for _, contract in VIOLATIONS.values()} == set(NAMES)


def test_tooling_is_installed() -> None:
    assert lint_imports_executable().is_file()
    assert contract_modules(CONFIG)
    assert len(NAMES) >= 4


def test_real_tree_keeps_every_contract() -> None:
    completed = subprocess.run(
        [str(lint_imports_executable()), "--config", str(CONFIG), "--no-cache"],
        cwd=REPO,
        env=tree_environment(None),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == 0, completed.stdout


def test_clean_fake_tree_passes(fake: Path) -> None:
    tree = build_fake_tree(fake, CONFIG, {})
    completed = run_lint_imports(tree, CONFIG)
    assert completed.returncode == 0, completed.stdout


@pytest.mark.parametrize("case", sorted(VIOLATIONS))
def test_planted_violation_breaks_its_contract(fake: Path, case: str) -> None:
    files, contract = VIOLATIONS[case]
    tree = build_fake_tree(fake, CONFIG, files)
    completed = run_lint_imports(tree, CONFIG)
    assert completed.returncode == 1, completed.stdout
    assert NAMES[contract] in completed.stdout
    broken = [line for line in completed.stdout.splitlines() if "BROKEN" in line]
    assert any(NAMES[contract] in line for line in broken), broken


@pytest.mark.parametrize("case", sorted(ALLOWED))
def test_allowed_imports_pass(fake: Path, case: str) -> None:
    tree = build_fake_tree(fake, CONFIG, ALLOWED[case])
    completed = run_lint_imports(tree, CONFIG)
    assert completed.returncode == 0, completed.stdout


def test_external_packages_need_not_be_installed(fake: Path) -> None:
    missing = "ck_package_that_does_not_exist"
    tree = build_fake_tree(fake, CONFIG, {"codekavach/report/render/bad.py": "import httpx\n"})
    assert shutil.which(missing) is None
    assert run_lint_imports(tree, CONFIG).returncode == 1


def test_guard_detects_the_wrong_tree(fake: Path) -> None:
    tree = build_fake_tree(fake, CONFIG, {})
    assert analysed_package(tree, tree).is_relative_to(tree.resolve())
    # From outside the tree and without PYTHONPATH the real package is found: the guard catches it.
    assert not analysed_package(None, tree.parent).is_relative_to(tree.resolve())


def ruff_reports(path: str, source: str) -> list[str]:
    completed = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--select", "TID251", "--output-format", "json",
         "--stdin-filename", path, "-"],
        cwd=REPO,
        input=source,
        capture_output=True,
        text=True,
        check=False,
    )  # fmt: skip
    return [item["code"] for item in json.loads(completed.stdout or "[]")]


@pytest.mark.parametrize(
    "source",
    [
        "import urllib.request\n",
        "import http.client\n",
        "import socket\n",
        "from google import genai\n",
    ],
)
def test_ruff_bans_network_modules_outside_the_transport(source: str) -> None:
    assert ruff_reports("src/codekavach/llm/x.py", source) == ["TID251"]
    assert ruff_reports("src/codekavach/privacy/egress/transport.py", source) == []
