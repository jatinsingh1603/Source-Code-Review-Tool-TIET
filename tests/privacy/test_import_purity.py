"""Importing any CodeKavach module has no side effects: no socket, no file, no output, no thread.

Plugin discovery (E04) imports modules the user never asked for, and a dependency that phones home
at import time must be caught. The module list is discovered, never hard-coded, and the test fails
closed: an empty module list or a child interpreter that does not start fails the test.
"""

import importlib
import json
import os
import pkgutil
import subprocess
import sys
from pathlib import Path

import pytest

import codekavach

OPTIONAL_EXTRA_HINT = "codekavach["

CHILD_SCRIPT = r"""
import contextlib, io, json, os, pkgutil, socket, sys, threading
from pathlib import Path


class Refused(socket.socket):
    def __init__(self, *args, **kwargs):
        raise RuntimeError("socket opened at import time")


def files():
    return sorted(str(path) for path in Path.cwd().rglob("*"))


socket.socket = Refused
import codekavach

violations = []
for info in pkgutil.walk_packages(codekavach.__path__, "codekavach."):
    env, before = dict(os.environ), files()
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            __import__(info.name)
    except ImportError as error:
        if "codekavach[" not in str(error):
            violations.append([info.name, type(error).__name__])
    except BaseException as error:
        violations.append([info.name, type(error).__name__])
    if captured.getvalue():
        violations.append([info.name, "output"])
    if files() != before:
        violations.append([info.name, "file_written"])
    if dict(os.environ) != env:
        violations.append([info.name, "environment_changed"])
report = {"threads": threading.active_count(), "violations": violations}
sys.stdout.write(json.dumps(report))
"""


def discover_modules() -> list[str]:
    """Every module and package below ``codekavach``."""
    return sorted(info.name for info in pkgutil.walk_packages(codekavach.__path__, "codekavach."))


def test_discovery_finds_the_egress_and_provider_modules() -> None:
    modules = discover_modules()
    assert "codekavach.privacy.egress.transport" in modules
    assert "codekavach.llm.providers" in modules
    assert len(modules) > 50


def test_in_process_import_with_sockets_disabled() -> None:
    modules = discover_modules()
    assert modules, "module discovery returned nothing"
    for name in modules:
        try:
            importlib.import_module(name)
        except ImportError as error:
            if OPTIONAL_EXTRA_HINT not in str(error):
                pytest.fail(f"importing {name} failed: {type(error).__name__}")
        except Exception as error:  # noqa: BLE001 - name the module that misbehaved
            pytest.fail(f"importing {name} failed: {type(error).__name__}")


def test_child_import_report(tmp_path: Path) -> None:
    source_root = Path(codekavach.__file__).resolve().parents[1]
    environment = {"PYTHONPATH": str(source_root), "PYTHONDONTWRITEBYTECODE": "1"}
    for name in ("SYSTEMROOT", "PATH", "TEMP", "TMP"):  # Windows needs these to start Python
        if name in os.environ:
            environment[name] = os.environ[name]
    completed = subprocess.run(
        [sys.executable, "-c", CHILD_SCRIPT],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    report = json.loads(completed.stdout)
    assert report["violations"] == [], f"modules with import side effects: {report['violations']}"
    assert report["threads"] == 1
