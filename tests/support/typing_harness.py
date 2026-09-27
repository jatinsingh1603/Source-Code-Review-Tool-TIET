"""Negative typing tests: case files that must fail mypy with specific errors on specific lines.

A case file marks each expected error with a trailing comment ``# E: <code>`` (several codes are
separated by commas). ``fail_*.py`` files carry at least one such comment; ``ok_*.py`` files carry
none and must type-check cleanly. All case files are checked in one mypy run.
"""

import io
import re
import tokenize
from collections.abc import Callable, Sequence
from pathlib import Path

from mypy import api

REPO_ROOT = Path(__file__).resolve().parents[2]

Expectations = set[tuple[int, str]]
Runner = Callable[[list[str]], tuple[str, str, int]]

_EXPECT = re.compile(r"#\s*E:\s*(?P<codes>[a-z0-9-]+(?:\s*,\s*[a-z0-9-]+)*)\s*$")
_ERROR_LINE = re.compile(
    r"^(?P<path>.+?):(?P<line>\d+)(?::\d+)?: error: .*\[(?P<code>[a-z0-9-]+)\]$"
)


class MypyRunError(RuntimeError):
    """mypy crashed or was misconfigured; no case result can be trusted."""


def parse_expectations(path: Path) -> Expectations:
    """Return the ``(line, code)`` pairs declared by ``# E:`` comments in ``path``."""
    source = path.read_text(encoding="utf-8")
    expected: Expectations = set()
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type != tokenize.COMMENT:
            continue
        match = _EXPECT.search(token.string)
        if match:
            for code in match.group("codes").split(","):
                expected.add((token.start[0], code.strip()))
    return expected


def parse_mypy_output(stdout: str) -> dict[Path, Expectations]:
    """Parse mypy's error lines into ``(line, code)`` sets keyed by resolved path."""
    results: dict[Path, Expectations] = {}
    for raw in stdout.splitlines():
        match = _ERROR_LINE.match(raw.strip())
        if not match:
            continue
        # mypy on Windows prints backslash separators; normalise them on every platform.
        path = Path(match.group("path").replace("\\", "/"))
        if not path.is_absolute():
            path = REPO_ROOT / path
        results.setdefault(path.resolve(), set()).add(
            (int(match.group("line")), match.group("code"))
        )
    return results


def run_mypy(
    files: Sequence[Path], *, cache_dir: Path | None = None, runner: Runner | None = None
) -> dict[Path, Expectations]:
    """Type-check ``files`` in one mypy run and return the errors found per file.

    Every file in ``files`` appears in the result, with an empty set when it has no errors.
    Raises MypyRunError when mypy writes to stderr or exits with status 2.
    """
    run = runner if runner is not None else api.run
    cache = cache_dir if cache_dir is not None else REPO_ROOT / ".mypy_cache" / "typing-cases"
    args = [
        "--config-file",
        str(REPO_ROOT / "pyproject.toml"),
        "--strict",
        "--show-error-codes",
        "--no-error-summary",
        "--no-color-output",
        "--hide-error-context",
        "--no-pretty",
        "--cache-dir",
        str(cache),
        *(str(f) for f in files),
    ]
    stdout, stderr, status = run(args)
    if stderr.strip() or status == 2:
        raise MypyRunError(f"mypy did not run cleanly (status {status}):\n{stderr}{stdout}")
    found = parse_mypy_output(stdout)
    return {f.resolve(): found.get(f.resolve(), set()) for f in files}


def compare(expected: Expectations, actual: Expectations, *, path: Path | None = None) -> list[str]:
    """Return one human-readable line per difference; empty when the sets are equal."""
    where = f"{path}:" if path is not None else "line "
    problems = [
        f"{where}{line}: expected error [{code}] was not reported"
        for line, code in sorted(expected - actual)
    ]
    problems += [
        f"{where}{line}: unexpected error [{code}]" for line, code in sorted(actual - expected)
    ]
    return problems


def case_files(case_dir: Path) -> list[Path]:
    """Return the ``fail_*.py`` and ``ok_*.py`` files in ``case_dir``, sorted by name."""
    return sorted([*case_dir.glob("fail_*.py"), *case_dir.glob("ok_*.py")])
