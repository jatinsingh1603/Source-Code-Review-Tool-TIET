"""Golden files for the HTML report and the inspection page of a fixed demo scan (E13-03).

The demo scans under a fixed salt, so the content is stable; what changes between runs is the
identifiers the scan generates, the time of day and the ledger head, which the comparison
normalises. A change to the pages shows up as a diff against ``tests/integration/golden/``.
Regenerate with ``CODEKAVACH_UPDATE_SNAPSHOTS=1`` and this file as the pytest target, then read
the diff before committing it.
"""

import difflib
import os
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from codekavach.cli.demo_runner import run_demo
from tests.support.kavachbank import FIXTURE_ROOT

GOLDEN = Path(__file__).parent / "golden"
IDENTIFIER = re.compile(r"\b(scan|cand|find|slc|pay)_[0-9A-HJKMNP-TV-Z]{26}\b")
TIME = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC")
HASH = re.compile(r"(Ledger head hash</th>\s*<td>)[0-9a-f]{64}")
UPDATE = bool(os.environ.get("CODEKAVACH_UPDATE_SNAPSHOTS"))


def normalise(page: str) -> str:
    """``page`` with generated identifiers numbered by first use, and the time and head masked."""
    seen: dict[str, str] = {}

    def number(match: re.Match[str]) -> str:
        token = match.group(0)
        seen.setdefault(token, f"<{match.group(1)}-{len(seen) + 1}>")
        return seen[token]

    page = IDENTIFIER.sub(number, page)
    page = TIME.sub("<time>", page)
    return HASH.sub(r"\1<ledger-head>", page).replace("\r\n", "\n")


@pytest.fixture(scope="module")
def pages(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    out = tmp_path_factory.mktemp("golden") / "out"
    run_demo(str(FIXTURE_ROOT), out)
    yield out


@pytest.mark.parametrize("name", ["report.html", "inspect.html"])
def test_the_page_matches_its_golden_file(pages: Path, name: str) -> None:
    actual = normalise((pages / name).read_text(encoding="utf-8"))
    golden = GOLDEN / name
    if UPDATE:
        GOLDEN.mkdir(exist_ok=True)
        golden.write_text(actual, encoding="utf-8", newline="\n")
    expected = golden.read_text(encoding="utf-8")
    diff = "".join(
        list(
            difflib.unified_diff(
                expected.splitlines(True), actual.splitlines(True), "golden", "actual", n=1
            )
        )[:60]
    )
    assert actual == expected, f"{name} differs from its golden file:\n{diff}"
