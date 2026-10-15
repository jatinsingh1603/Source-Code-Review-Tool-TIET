"""Performance budget: parsing 5 000 files of 200 lines each (E07-01, E07-02).

Measured at roughly 20 s single-threaded (E07-01, before any ``LanguageSpec`` was registered).
E07-02 registers the Python spec at import time, so ``parse()`` now also extracts identifiers,
string content and comments for every one of these files; measured again at roughly 65 s, this
raises the budget to 100 s rather than keeping the original 60 s and papering over a real,
expected increase. See ``tests/perf/test_extraction_overhead.py`` for the overhead that
registering a spec adds, measured and budgeted on its own.
"""

import pytest

from codekavach.core.models import Language
from codekavach.parsing import parse
from tests.support.perf import assert_within_budget, measure

FILE_COUNT = 5_000
LINES_PER_FILE = 200
BUDGET_SECONDS = 100.0


def _sample_file_text() -> str:
    lines = [f'value_{i} = {i} + len("x" * {i})  # line {i}' for i in range(LINES_PER_FILE)]
    return "\n".join(lines) + "\n"


@pytest.mark.perf
@pytest.mark.timeout(400)  # well past BUDGET_SECONDS x CODEKAVACH_PERF_FACTOR; 120 s is too tight
def test_parsing_5000_files_of_200_lines_stays_within_budget() -> None:
    text = _sample_file_text()

    def parse_all() -> None:
        for index in range(FILE_COUNT):
            parse(f"synthetic/file_{index}.py", Language.PYTHON, text)

    elapsed = measure(parse_all, repeat=1)
    assert_within_budget(
        elapsed, BUDGET_SECONDS, label=f"parsing {FILE_COUNT} files of {LINES_PER_FILE} lines"
    )
