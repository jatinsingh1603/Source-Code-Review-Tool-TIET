"""Performance budget: the parse stage over 5 000 files of about 200 lines, cold and warm (E07-04).

The issue's budgets are 150 s cold and 15 s warm for 5 000 files of 200 lines. Cold means an empty
memo; warm means every file is served from it, which must not parse anything. Both are scaled by
the performance factor, the same as the other budgets. The synthetic repository mixes Python,
JavaScript and TypeScript files, each with imports of every origin and many calls, spread over a
directory tree.
"""

import time
from pathlib import Path

import pytest

from codekavach.config import load_settings
from codekavach.core.models import ScanStatus
from codekavach.core.pipeline.runner import ScanOutcome, run_scan
from codekavach.core.pipeline.salt import ScanSalt
from tests.support.ingest import SALT_HEX, stages_registry
from tests.support.perf import assert_within_budget

FILES = 5_000
LINES_PER_FILE = 200
COLD_BUDGET_SECONDS = 150.0
WARM_BUDGET_SECONDS = 15.0

PYTHON_HEADER = """\"\"\"Module {i}.\"\"\"

import hashlib
import numpy as np
from flask import request

from . import sibling

"""

PYTHON_BLOCK = """

def handler_{i}_{j}(value, limit=10):
    total = 0
    for item in value:
        if item > limit:
            total += item
    digest = hashlib.sha256()
    return helper_{i}_{j}(total) + sibling.go(np.zeros(1), digest, request)


def helper_{i}_{j}(total):
    return total * 2
"""

JAVASCRIPT_HEADER = """import {{ readFileSync }} from "node:fs";
import {{ helper }} from "./util";
const lodash = require("lodash");
"""

JAVASCRIPT_BLOCK = """
export function handler{i}x{j}(value, limit) {{
  let total = 0;
  for (const item of value) {{
    if (item > limit) {{ total += item; }}
  }}
  readFileSync("x");
  return helper(total) + lodash.sum([total]) + local{i}x{j}(total);
}}

function local{i}x{j}(total) {{ return total * 2; }}
"""

TYPESCRIPT_HEADER = """import {{ Component }} from "@angular/core";
import {{ helper }} from "./util";
"""

TYPESCRIPT_BLOCK = """
export class Widget{i}x{j} {{
  run(value: number[]): number {{
    return helper(value.length) + this.inner(value);
  }}

  private inner(value: number[]): number {{
    Component({{}});
    return value.length;
  }}
}}
"""

KINDS = (
    ("py", PYTHON_HEADER, PYTHON_BLOCK),
    ("js", JAVASCRIPT_HEADER, JAVASCRIPT_BLOCK),
    ("ts", TYPESCRIPT_HEADER, TYPESCRIPT_BLOCK),
)


def render(index: int) -> tuple[str, str]:
    """The extension and the text of synthetic file ``index``, about ``LINES_PER_FILE`` lines."""
    extension, header, block = KINDS[index % len(KINDS)]
    text = header.format(i=index)
    j = 0
    while text.count("\n") < LINES_PER_FILE:
        text += block.format(i=index, j=j)
        j += 1
    return extension, text


def build_repository(root: Path) -> None:
    for index in range(FILES):
        extension, text = render(index)
        directory = root / f"pkg{index % 50}" / f"sub{index % 7}"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"module_{index}.{extension}").write_text(text, encoding="utf-8")


def scan(repo: Path) -> tuple[ScanOutcome, float]:
    loaded = load_settings(target=repo, env={"CODEKAVACH_HOME": str(repo.parent / "home")})
    started = time.perf_counter()
    outcome = run_scan(
        loaded,
        str(repo),
        salt=ScanSalt.from_hex(SALT_HEX),
        registry=stages_registry("ingest", "parse"),
    )
    return outcome, time.perf_counter() - started


@pytest.mark.perf
@pytest.mark.timeout(1800)  # past (cold + warm budget) x factor; the global 120 s is too tight
def test_five_thousand_files_parse_within_the_cold_and_warm_budgets(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    build_repository(repo)
    assert all(render(i)[1].count("\n") >= LINES_PER_FILE for i in range(3))

    cold, cold_seconds = scan(repo)
    assert cold.scan.status is ScanStatus.COMPLETED
    assert cold.result.memo_hits == 0
    assert cold.result.memo_misses == FILES
    assert_within_budget(cold_seconds, COLD_BUDGET_SECONDS, label="cold parse of 5000 files")

    warm, warm_seconds = scan(repo)
    assert warm.scan.status is ScanStatus.COMPLETED
    assert (warm.result.memo_hits, warm.result.memo_misses) == (FILES, 0)
    assert_within_budget(warm_seconds, WARM_BUDGET_SECONDS, label="warm parse of 5000 files")
    # The warm run must be much cheaper than the cold one, not merely under its ceiling.
    assert warm_seconds < cold_seconds
