"""Performance budget of renaming (E09-04).

Building the plan and applying it to a 2 000-line slice takes under 40 ms once the file is parsed
and classified, because the pseudonymiser renames every slice. Parsing and classification have
budgets of their own. The budget scales with the performance factor.
"""

from pathlib import Path

import pytest

from codekavach.core.models import Language, RawCode
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.imports import DefaultImportResolver, attach_imports
from codekavach.parsing.symbols import build_symbol_table
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.classify import classify_all
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator
from codekavach.privacy.pseudonymise.renamers.registry import default_registry
from tests.support.perf import assert_within_budget, measure

BUDGET_SECONDS = 0.040
TARGET_LINES = 2000


def _python_source(target_lines: int) -> str:
    lines = ["from flask import request", "from billing.engine import accrue_interest", "", ""]
    number = 0
    while len(lines) < target_lines:
        lines.extend(
            [
                f"def handler_{number}(account_id, rate):",
                '    """Festival handler."""',
                "    value = request.args.get('rate', type=float)  # note",
                "    label = f'account {account_id} at {rate}'",
                f"    return accrue_interest(account_id, rate=value, label=label, days={number})",
                "",
                "",
            ]
        )
        number += 1
    return "\n".join(lines) + "\n"


def _javascript_source(target_lines: int) -> str:
    lines = ["import { accrueInterest } from './engine';", ""]
    number = 0
    while len(lines) < target_lines:
        lines.extend(
            [
                f"function handler{number}({{ accountId, rate }}, options) {{",
                "  const value = options.rate; // note",
                "  const label = `account ${accountId} at ${rate}`;",
                "  return accrueInterest({ accountId, value, label, tier: 'premium' });",
                "}",
                "",
            ]
        )
        number += 1
    return "\n".join(lines) + "\n"


@pytest.mark.perf
@pytest.mark.parametrize(
    ("language", "build", "path"),
    [
        (Language.PYTHON, _python_source, "slice.py"),
        (Language.JAVASCRIPT, _javascript_source, "slice.js"),
    ],
    ids=["python", "javascript"],
)
def test_a_two_thousand_line_slice_is_renamed_within_budget(
    language: Language, build: object, path: str
) -> None:
    text = build(TARGET_LINES)  # type: ignore[operator]
    assert len(text.splitlines()) >= TARGET_LINES
    parsed = parse(path, language, text)
    table = attach_imports(
        build_symbol_table(parsed, REGISTRY.get(language)),
        parsed,
        DefaultImportResolver(language),
        project_root=Path(),
    )
    allowlist = PublicAllowlist.bundled(language)
    classification = classify_all(parsed, table, allowlist=allowlist)
    renamer = default_registry().get(language)
    source = RawCode(text)

    def rename() -> str:
        generator = PseudonymGenerator(ScanSalt(bytes(range(32))))
        plan = renamer.plan(parsed, classification, generator, allowlist=allowlist)
        return renamer.rename(source, plan)

    renamed = rename()  # warm the caches, and check the result is a real rename
    assert renamed != text
    assert_within_budget(measure(rename, repeat=5), BUDGET_SECONDS, label=f"rename {path}")
