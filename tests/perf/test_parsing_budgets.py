"""Performance budget: parsing 5 000 files of 200 lines each (E07-01).

Measured at roughly 20 s single-threaded on a development machine; the 60 s budget in the issue
is kept as the committed number, with headroom for a slower CI runner.
"""

import pytest

from codekavach.core.models import Language
from codekavach.parsing import parse
from tests.support.perf import assert_within_budget, measure

FILE_COUNT = 5_000
LINES_PER_FILE = 200
BUDGET_SECONDS = 60.0


def _sample_file_text() -> str:
    lines = [f'value_{i} = {i} + len("x" * {i})  # line {i}' for i in range(LINES_PER_FILE)]
    return "\n".join(lines) + "\n"


@pytest.mark.perf
def test_parsing_5000_files_of_200_lines_stays_within_budget() -> None:
    text = _sample_file_text()

    def parse_all() -> None:
        for index in range(FILE_COUNT):
            parse(f"synthetic/file_{index}.py", Language.PYTHON, text)

    elapsed = measure(parse_all, repeat=1)
    assert_within_budget(
        elapsed, BUDGET_SECONDS, label=f"parsing {FILE_COUNT} files of {LINES_PER_FILE} lines"
    )
