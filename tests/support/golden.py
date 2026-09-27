"""Byte-exact comparison against golden files."""

import difflib
import os
from pathlib import Path

import pytest

UPDATE_VARIABLE = "CODEKAVACH_UPDATE_GOLDEN"


def assert_matches_golden(actual: str | bytes, path: Path) -> None:
    """Assert that ``actual`` equals the golden file at ``path``, byte for byte.

    A str is encoded as UTF-8 without newline translation. With CODEKAVACH_UPDATE_GOLDEN=1
    the file is (re)written and the assertion passes, unless CI is also set, in which case
    the update is refused so that a pipeline can never rewrite its own expectations.
    """
    data = actual.encode("utf-8") if isinstance(actual, str) else actual
    if os.environ.get(UPDATE_VARIABLE) == "1":
        if os.environ.get("CI"):
            raise RuntimeError(f"{UPDATE_VARIABLE}=1 is refused when CI is set")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        print(f"golden file updated: {path}")  # noqa: T201 - report the rewrite to the developer
        return
    if not path.exists():
        pytest.fail(f"golden file {path} does not exist; run with {UPDATE_VARIABLE}=1 to create it")
    expected = path.read_bytes()
    if data == expected:
        return
    if isinstance(actual, str):
        diff = difflib.unified_diff(
            expected.decode("utf-8", errors="replace").splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=str(path),
            tofile="actual",
        )
        pytest.fail("output differs from golden file:\n" + "".join(diff))
    offset = next(
        (i for i, (a, b) in enumerate(zip(data, expected, strict=False)) if a != b),
        min(len(data), len(expected)),
    )
    pytest.fail(
        f"binary output differs from golden file {path} at byte offset {offset} "
        f"(actual {len(data)} bytes, expected {len(expected)} bytes)"
    )
