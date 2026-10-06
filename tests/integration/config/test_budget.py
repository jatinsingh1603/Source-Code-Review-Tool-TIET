"""Time budgets of configuration loading and of importing the configuration package (E03-44).

``load_settings`` is about 6 ms on Windows and 4 ms on Linux against a 50 ms budget. The import of
``codekavach.config`` is about 350 ms on Windows and 250 ms on Linux (cumulative) against a 400 ms
budget, which leaves little room on a slow machine: CI sets ``CODEKAVACH_PERF_FACTOR=3.0`` and a
local run on a busy laptop may need a factor too. Both are scaled through ``budget()``. Skipped
with ``CODEKAVACH_SKIP_PERF=1``.
"""

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tests.support.config import ConfigSandbox
from tests.support.perf import assert_within_budget, budget, measure

pytestmark = [
    pytest.mark.perf,
    pytest.mark.skipif(
        os.environ.get("CODEKAVACH_SKIP_PERF") == "1", reason="CODEKAVACH_SKIP_PERF"
    ),
]
REPO_ROOT = Path(__file__).resolve().parents[3]
LOAD_SECONDS = 0.05
IMPORT_SECONDS = 0.4
IMPORT_RUNS = 3
TARGET = "codekavach.config"
TEN_VARIABLES = {
    "CODEKAVACH_SCAN__JOBS": "2",
    "CODEKAVACH_SCAN__TIMEOUT_SECONDS": "600",
    "CODEKAVACH_SCAN__MAX_FILES": "1000",
    "CODEKAVACH_SCAN__CACHE": "false",
    "CODEKAVACH_SCAN__FAIL_ON": "medium",
    "CODEKAVACH_PRIVACY__LEVEL": "L4",
    "CODEKAVACH_REPORTING__FORMATS": '["json"]',
    "CODEKAVACH_REPORTING__MIN_SEVERITY": "low",
    "CODEKAVACH_LOGGING__LEVEL": "warning",
    "CODEKAVACH_LOGGING__FORMAT": "json",
}


def _load_report() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "importtime_report_config", REPO_ROOT / "tools" / "dev" / "importtime_report.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["importtime_report_config"] = module
    spec.loader.exec_module(module)
    return module


report = _load_report()


def test_loading_a_realistic_project_is_within_budget(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user('[privacy]\nlevel = "L3"\n')
    config_sandbox.write_project('[project]\nname = "demo"\n[scan]\njobs = 2\n')
    config_sandbox.env["CODEKAVACH_PROFILE"] = "ci"
    config_sandbox.env.update(TEN_VARIABLES)
    config_sandbox.load()  # warm-up: imports and first-use caches are not what is measured
    measured = measure(config_sandbox.load, repeat=20)
    print(f"load_settings: best of 20 {measured * 1000:.1f} ms")  # noqa: T201
    assert_within_budget(measured, LOAD_SECONDS, label="load_settings")


def import_seconds() -> float:
    """The cumulative import time of the package in one fresh interpreter."""
    rows = report.parse(report.measure(TARGET))
    top_level = [row for row in rows if row.module == TARGET]
    assert len(top_level) == 1, "the package was not imported"
    return float(top_level[0].cumulative_us) / 1_000_000


def test_importing_the_package_is_within_budget() -> None:
    # Best of three fresh interpreters: a single cold import is noisy on a busy runner.
    seconds = min(import_seconds() for _ in range(IMPORT_RUNS))
    print(f"import {TARGET}: best of {IMPORT_RUNS} {seconds * 1000:.0f} ms cumulative")  # noqa: T201
    assert_within_budget(seconds, IMPORT_SECONDS, label=f"import {TARGET}")


def test_the_budget_check_is_live() -> None:
    # A budget of zero must fail, and the message shows the measurement, budget and factor.
    with pytest.raises(AssertionError, match=r"load_settings: measured .* budget 0\.000 s"):
        assert_within_budget(0.001, 0, factor=1.0, label="load_settings")
    assert budget(LOAD_SECONDS) == pytest.approx(LOAD_SECONDS * budget(1.0))
