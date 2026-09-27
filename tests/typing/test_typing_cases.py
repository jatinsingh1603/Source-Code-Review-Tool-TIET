"""Negative typing tests.

Typing tests: each file in this directory named ``fail_*.py`` must fail ``mypy --strict`` with
exactly the errors declared by trailing ``# E: <code>`` comments (several codes on one line are
separated by commas; the code is the one mypy prints in square brackets). Each ``ok_*.py`` file
must type-check without any error. The comparison is on the set of (line, code) pairs, so a
missing expected error and an unexpected extra error both fail; messages are not compared.
All case files are checked in a single mypy run per session. To add a case, drop a file here;
pytest does not collect the case files themselves, so do not rename them to ``test_*.py``.
"""

from pathlib import Path

import pytest
from tests.support.typing_harness import (
    Expectations,
    MypyRunError,
    case_files,
    compare,
    parse_expectations,
    run_mypy,
)

CASE_DIR = Path(__file__).parent
CASES = case_files(CASE_DIR)


@pytest.fixture(scope="session")
def mypy_results(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[Path, Expectations] | MypyRunError:
    try:
        return run_mypy(CASES, cache_dir=tmp_path_factory.mktemp("mypy-typing-cases"))
    except MypyRunError as exc:
        return exc


@pytest.mark.slow
@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_typing_case(case: Path, mypy_results: dict[Path, Expectations] | MypyRunError) -> None:
    if isinstance(mypy_results, MypyRunError):
        pytest.fail(str(mypy_results))
    expected = parse_expectations(case)
    if case.name.startswith("fail_"):
        assert expected, f"{case.name} declares no '# E:' expectation"
    else:
        assert not expected, f"{case.name} is an ok_ case and must not declare errors"
    problems = compare(expected, mypy_results[case.resolve()], path=case)
    assert not problems, "\n".join(problems)
