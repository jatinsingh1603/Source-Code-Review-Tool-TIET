from pathlib import Path

import pytest

from tests.support import typing_harness
from tests.support.typing_harness import (
    MypyRunError,
    compare,
    parse_expectations,
    parse_mypy_output,
    run_mypy,
)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_parse_expectations(tmp_path: Path) -> None:
    case = _write(
        tmp_path,
        "fail_x.py",
        'a: int = "x"  # E: assignment\n'
        "b = 1  # E: arg-type, operator\n"
        "c = 2\n"
        's = "# E: call-arg"\n'
        "# a comment without expectation\n",
    )
    assert parse_expectations(case) == {(1, "assignment"), (2, "arg-type"), (2, "operator")}


def test_compare_reports_missing_and_unexpected_distinctly() -> None:
    problems = compare({(1, "assignment")}, {(2, "arg-type")}, path=Path("fail_x.py"))
    assert problems == [
        "fail_x.py:1: expected error [assignment] was not reported",
        "fail_x.py:2: unexpected error [arg-type]",
    ]
    assert compare({(1, "a")}, {(1, "a")}) == []


def test_parse_output_with_and_without_column(tmp_path: Path) -> None:
    posix = tmp_path / "fail_a.py"
    windows = tmp_path / "fail_b.py"
    stdout = (
        f"{posix}:3: error: Incompatible types in assignment  [assignment]\n"
        f"{windows}:7:5: error: Argument 1 has incompatible type  [arg-type]\n"
        f"{windows}:8: note: See documentation\n"
    )
    result = parse_mypy_output(stdout)
    assert result[posix.resolve()] == {(3, "assignment")}
    assert result[windows.resolve()] == {(7, "arg-type")}


def test_parse_output_windows_style_path() -> None:
    stdout = r"tests\typing\fail_x.py:2:1: error: Bad  [operator]"
    result = parse_mypy_output(stdout)
    key = (typing_harness.REPO_ROOT / "tests" / "typing" / "fail_x.py").resolve()
    assert result == {key: {(2, "operator")}}


def test_crashed_mypy_fails_loudly(tmp_path: Path) -> None:
    case = _write(tmp_path, "ok_x.py", "x = 1\n")

    def crashed(args: list[str]) -> tuple[str, str, int]:
        return "", "mypy: error: invalid configuration", 2

    with pytest.raises(MypyRunError, match="invalid configuration"):
        run_mypy([case], runner=crashed)


def test_mypy_is_called_once_for_all_cases(tmp_path: Path) -> None:
    cases = [_write(tmp_path, f"ok_{i}.py", "x = 1\n") for i in range(3)]
    calls: list[list[str]] = []

    def counting(args: list[str]) -> tuple[str, str, int]:
        calls.append(args)
        return f"{cases[1]}:1: error: boom  [misc]\n", "", 1

    result = run_mypy(cases, runner=counting)
    assert len(calls) == 1
    assert result[cases[0].resolve()] == set()
    assert result[cases[1].resolve()] == {(1, "misc")}


def test_real_run_detects_missing_expectation(tmp_path: Path) -> None:
    fail_case = _write(tmp_path, "fail_y.py", 'count: int = "three"\n')
    ok_case = _write(tmp_path, "ok_y.py", "count: int = 3  # E: arg-type\n")
    results = run_mypy([fail_case, ok_case], cache_dir=tmp_path / "cache")
    fail_problems = compare(
        parse_expectations(fail_case), results[fail_case.resolve()], path=fail_case
    )
    ok_problems = compare(parse_expectations(ok_case), results[ok_case.resolve()], path=ok_case)
    assert fail_problems == [f"{fail_case}:1: unexpected error [assignment]"]
    assert ok_problems == [f"{ok_case}:1: expected error [arg-type] was not reported"]
