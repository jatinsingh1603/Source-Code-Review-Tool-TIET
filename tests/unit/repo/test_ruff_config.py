"""The ruff configuration catches the mistake classes that matter in a security tool."""

import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _ruff_codes(source: str, filename: str) -> set[str]:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--no-cache",
            "--output-format",
            "json",
            "--stdin-filename",
            filename,
            "-",
        ],
        input=source,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert result.returncode in {0, 1}, result.stderr
    return {item["code"] for item in json.loads(result.stdout)}


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ('print("x")\n', "T201"),
        ("import datetime\n\nnow = datetime.datetime.now()\n", "DTZ005"),
        ("try:\n    pass\nexcept Exception:\n    pass\n", "BLE001"),
        ("import logging\n\nlogger = logging.getLogger()\nx = 1\nlogger.info(f'{x}')\n", "G004"),
        ("import subprocess\n\ncmd = 'ls'\nsubprocess.run(cmd, shell=True)\n", "S602"),
    ],
)
def test_rule_is_reported_in_src(source: str, code: str) -> None:
    assert code in _ruff_codes(source, "src/codekavach/demo.py")


def test_assert_reported_in_src_but_not_in_tests() -> None:
    source = "x = 1\nassert x\n"
    assert "S101" in _ruff_codes(source, "src/codekavach/demo.py")
    assert "S101" not in _ruff_codes(source, "tests/unit/test_demo.py")


def test_fixtures_are_excluded() -> None:
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "fixtures" in config["tool"]["ruff"]["extend-exclude"]
