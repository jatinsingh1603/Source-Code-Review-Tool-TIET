"""mypy runs in strict mode with the Pydantic plugin loaded from pyproject.toml."""

import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _mypy(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "mypy", "--no-incremental", *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )


def _config() -> dict[str, Any]:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


@pytest.mark.slow
def test_untyped_function_is_rejected(tmp_path: Path) -> None:
    # mypy 2 rejects `-c` when `files` is set in the configuration, so the program is
    # checked as a file with the project configuration instead.
    probe = tmp_path / "probe_untyped.py"
    probe.write_text("def f(x): return x\n", encoding="utf-8")
    result = _mypy("--config-file", str(REPO_ROOT / "pyproject.toml"), str(probe))
    assert result.returncode != 0
    assert "no-untyped-def" in result.stdout


@pytest.mark.slow
def test_pydantic_plugin_forbids_extra_init_arguments(tmp_path: Path) -> None:
    probe = tmp_path / "probe_model.py"
    probe.write_text(
        "from pydantic import BaseModel\n\n\nclass M(BaseModel):\n    a: int\n\n\nM(a=1, b=2)\n",
        encoding="utf-8",
    )
    result = _mypy("--config-file", str(REPO_ROOT / "pyproject.toml"), str(probe))
    assert result.returncode != 0
    assert "call-arg" in result.stdout


def test_strict_mode_and_plugin_configured() -> None:
    mypy = _config()["tool"]["mypy"]
    assert mypy["strict"] is True
    assert "pydantic.mypy" in mypy["plugins"]
    for override in mypy.get("overrides", []):
        assert not override.get("ignore_errors", False), override
