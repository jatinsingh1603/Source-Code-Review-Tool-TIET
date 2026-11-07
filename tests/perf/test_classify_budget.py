"""Performance budget of identifier classification (E09-02).

Classifying a 2 000-line file must take under 20 ms once the allowlist and the parsed file exist,
because the pseudonymiser runs it for every candidate. The allowlist is built once per scan, as
the design requires, so it is built outside the timed region; the budget scales with the
performance factor.
"""

from pathlib import Path

import pytest

from codekavach.core.models import Language
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.imports import DefaultImportResolver, attach_imports
from codekavach.parsing.symbols import build_symbol_table
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.classify import classify_all
from tests.support.perf import assert_within_budget, measure

BUDGET_SECONDS = 0.020
TARGET_LINES = 2000


def _source(target_lines: int) -> str:
    lines = [
        "from flask import request",
        "import os",
        "from billing.engine import accrue_interest",
        "",
        "",
    ]
    number = 0
    while len(lines) < target_lines:
        lines.extend(
            [
                f"def handler_{number}(account_id, rate):",
                "    value = request.args.get('rate', type=float)",
                "    cur = account_id",
                "    if cur:",
                f"        return accrue_interest(cur, rate=value, days={number})",
                "    return os.environ.get('RATE')",
                "",
                "",
            ]
        )
        number += 1
    return "\n".join(lines) + "\n"


@pytest.mark.perf
def test_a_two_thousand_line_file_is_classified_within_budget() -> None:
    text = _source(TARGET_LINES)
    assert len(text.splitlines()) >= TARGET_LINES
    parsed = parse("slice.py", Language.PYTHON, text)
    table = attach_imports(
        build_symbol_table(parsed, REGISTRY.get(Language.PYTHON)),
        parsed,
        DefaultImportResolver(Language.PYTHON),
        project_root=Path(),
    )
    allowlist = PublicAllowlist.bundled(Language.PYTHON)
    classify_all(parsed, table, allowlist=allowlist)  # warm the bundle and the parse caches

    def classify() -> None:
        classify_all(parsed, table, allowlist=allowlist)

    assert_within_budget(measure(classify, repeat=5), BUDGET_SECONDS, label="classification")
