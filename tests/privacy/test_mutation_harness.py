"""The mutation harness: each named privacy defect makes its named tests fail (E28-03).

For every ``PrivacyDefect`` the harness runs the tests that ``DEFECT_EXPECTATIONS`` names, in one
subprocess with the defect installed by the ``tests.support.mutate`` plugin, and asserts that
every named test fails. The four ``SMOKE`` defects run by default; the full set runs when
``CODEKAVACH_MUTATION_FULL=1`` (the nightly job). The completeness checks need no subprocess: each
registered leak scanner must have a "scanner removed" defect, and every defect must have an
expectation and an implementation.
"""

import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codekavach.privacy.egress.scanners import default_scanners
from codekavach.privacy.slicing.metrics import ScanDisclosure
from tests.support.mutate import (
    DEFECT_EXPECTATIONS,
    DEFECT_VARIABLE,
    SCANNER_DEFECTS,
    SMOKE,
    PrivacyDefect,
    apply_defect,
)

pytestmark = [pytest.mark.privacy, pytest.mark.slow]

REPO_ROOT = Path(__file__).resolve().parents[2]
FULL = os.environ.get("CODEKAVACH_MUTATION_FULL") == "1"
SELECTED = tuple(PrivacyDefect) if FULL else SMOKE


def run_with_defect(defect: PrivacyDefect, node_ids: frozenset[str]) -> tuple[set[str], str]:
    """The node ids that failed with ``defect`` installed, and the tail of the output."""
    env = {**os.environ, DEFECT_VARIABLE: defect.value}
    env.pop("PYTEST_ADDOPTS", None)
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-rf",
        "--no-header",
        "-p",
        "no:randomly",
        "-p",
        "no:cacheprovider",
        "-p",
        "tests.support.mutate",
        *sorted(node_ids),
    ]
    result = subprocess.run(
        command, cwd=REPO_ROOT, env=env, capture_output=True, text=True, check=False, timeout=600
    )
    failed = set(re.findall(r"^FAILED (\S+?)(?: - .*)?$", result.stdout, re.MULTILINE))
    return {f.split("[", 1)[0] for f in failed}, result.stdout[-2000:]


@pytest.mark.parametrize("defect", SELECTED, ids=lambda d: d.value)
def test_each_defect_breaks_its_named_tests(defect: PrivacyDefect) -> None:
    expected = DEFECT_EXPECTATIONS[defect]
    started = time.monotonic()
    failed, tail = run_with_defect(defect, expected)
    assert failed, f"{defect.value}: no named test failed\n{tail}"
    assert expected <= failed, (
        f"{defect.value}: expected {sorted(expected - failed)} to fail\n{tail}"
    )
    assert time.monotonic() - started < 180


def test_the_named_tests_pass_without_a_defect() -> None:
    """The expectations are about the defect: on the real code every named test passes."""
    names = frozenset().union(*(DEFECT_EXPECTATIONS[d] for d in SMOKE))
    env = {k: v for k, v in os.environ.items() if k != DEFECT_VARIABLE}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
            *sorted(names),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    assert result.returncode == 0, result.stdout[-2000:]


def test_every_defect_has_an_expectation_and_an_implementation() -> None:
    assert set(DEFECT_EXPECTATIONS) == set(PrivacyDefect)
    assert all(DEFECT_EXPECTATIONS.values())
    for defect in PrivacyDefect:
        patch = pytest.MonkeyPatch()
        try:
            apply_defect(patch, defect)
        finally:
            patch.undo()


def test_every_leak_scanner_has_a_defect() -> None:
    """A scanner registered without a covering defect fails here."""
    registered = {scanner.id for scanner in default_scanners(ScanDisclosure(repo_lines=1))}
    covered = {defect.value.split(":", 1)[1] for defect in SCANNER_DEFECTS}
    assert registered == covered


def test_the_smoke_subset_covers_redaction_the_guard_the_ledger_and_the_policy() -> None:
    assert set(SMOKE) <= set(PrivacyDefect)
    assert len(SMOKE) == 4
