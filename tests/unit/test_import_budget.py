"""Import-time budget of the package and the CLI start-up path (E01-32).

The hard gate is deterministic: a fresh interpreter imports the target and the test inspects
``sys.modules`` for the ``HEAVY`` list. The soft gate times ``python -m codekavach --version``.
When a later epic has a real reason to import one of these on the start-up path, it changes
this list in the same commit and justifies it in the commit body: the list is the budget.
"""

import importlib.util
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest

from tests.support.perf import budget

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE = REPO_ROOT / "tests" / "unit" / "tools" / "data" / "importtime_sample.txt"

# Pygments is left out on purpose: Rich, and through it structlog and Typer's help formatter,
# may import it.
HEAVY = ("tree_sitter", "tree_sitter_language_pack", "sqlalchemy", "alembic", "fastapi", "uvicorn",
         "starlette", "weasyprint", "docxtpl", "xlsxwriter", "jinja2", "httpx", "litellm",
         "anthropic", "openai", "boto3", "presidio_analyzer", "spacy", "torch", "transformers",
         "numpy", "pandas", "cryptography", "keyring")  # fmt: skip
FRAMEWORKS = ("pydantic", "typer", "rich", "structlog")


def _load_report() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "importtime_report", REPO_ROOT / "tools" / "dev" / "importtime_report.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["importtime_report"] = module
    spec.loader.exec_module(module)
    return module


report = _load_report()


def loaded_after(target: str) -> list[str]:
    """The modules a fresh interpreter has loaded after ``import target``."""
    program = f"import json, sys, {target}; print(json.dumps(sorted(sys.modules)))"
    completed = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, check=True
    )
    modules: list[str] = json.loads(completed.stdout.strip().splitlines()[-1])
    return modules


def matching(modules: list[str], names: tuple[str, ...]) -> list[str]:
    """Names from ``names`` present in ``modules``, matched as dotted prefixes."""
    return sorted(
        {
            name
            for name in names
            for module in modules
            if module == name or module.startswith(f"{name}.")
        }
    )


def test_package_import_is_bare() -> None:
    modules = loaded_after("codekavach")
    assert matching(modules, HEAVY) == []
    assert matching(modules, FRAMEWORKS) == []  # the top-level package only reads its version


def test_cli_import_loads_no_heavy_module() -> None:
    assert matching(loaded_after("codekavach.cli.app"), HEAVY) == []


def test_prefix_matcher() -> None:
    assert matching(["sqlalchemy.orm"], HEAVY) == ["sqlalchemy"]
    assert matching(["httpx_sse", "torchvision_extra"], HEAVY) == []
    assert matching(["numpy"], HEAVY) == ["numpy"]


def test_importtime_parser_on_a_captured_sample() -> None:
    rows = report.parse(SAMPLE.read_text(encoding="utf-8") + "not an import line\n")
    assert len(rows) == 11  # the header and the stray line are skipped
    slowest = report.slowest(rows, 3)
    assert [row.module for row in slowest] == ["encodings", "encodings.aliases", "zipimport"]
    assert slowest[0].cumulative_us == 3307
    assert slowest[0].self_us == 1875
    assert [row.depth for row in rows[:3]] == [0, 1, 1]
    table = report.render(slowest)
    assert table.splitlines()[0].split() == ["cumulative", "ms", "self", "ms", "module"]
    assert "3.3" in table.splitlines()[1]


def test_report_prints_twenty_rows() -> None:
    lines = report.report(top=20).splitlines()
    assert len(lines) == 21  # header and twenty rows
    cumulative = [float(line.split()[0]) for line in lines[1:]]
    assert cumulative == sorted(cumulative, reverse=True)


@pytest.mark.perf
def test_start_up_within_budget() -> None:
    times = []
    for _ in range(6):
        started = time.perf_counter()
        subprocess.run(
            [sys.executable, "-m", "codekavach", "--version"], capture_output=True, check=True
        )
        times.append(time.perf_counter() - started)
    median = statistics.median(times[1:])  # the first run warms the file cache
    limit = budget(0.5)
    if median > limit:
        print(report.report(top=20))  # noqa: T201 - shows the slow imports in the CI log
    assert median <= limit, f"median start-up {median:.3f} s exceeds {limit:.3f} s"
