"""Performance budgets of the E15-01 adapters.

Building an invocation and parsing a report must stay cheap: the engine itself is the cost, not the
adapter. A 5,000-result Bandit report must convert in under 2 seconds.
"""

import json
from pathlib import Path

import pytest

from codekavach.analysis.engines.adapters.bandit import BanditAdapter
from codekavach.analysis.engines.adapters.eslint_security import EslintSecurityAdapter
from codekavach.analysis.engines.adapters.opengrep import OpengrepAdapter
from codekavach.analysis.engines.base import EngineRun
from codekavach.config import Settings
from codekavach.core.models import Language
from tests.support.engines import source_file
from tests.support.perf import budget, measure
from tests.support.sarif import numbered_source, write_tree

pytestmark = pytest.mark.perf

RESULTS = 5_000


def test_building_the_three_invocations_takes_under_200_ms(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    settings = Settings.model_validate(
        {
            "engines": {
                "rule_paths": [str(rules)],
                "options": {"eslint-security": {"options": {"tools_dir": str(tmp_path / "t")}}},
            }
        }
    )
    files = [source_file("a.py"), source_file("b.js", Language.JAVASCRIPT)]

    def build() -> None:
        for adapter in (OpengrepAdapter(), BanditAdapter(), EslintSecurityAdapter()):
            assert adapter.build_invocation(tmp_path, files, settings) is not None

    assert measure(build) < budget(0.2)


def test_a_5000_result_bandit_report_converts_in_under_two_seconds(tmp_path: Path) -> None:
    root = write_tree(
        tmp_path / "view", {f"src/f{n}.py": numbered_source(200, 60) for n in range(40)}
    )
    report = {
        "results": [
            {
                "test_id": f"B{100 + n % 30}",
                "test_name": "t",
                "filename": f"./src/f{n % 40}.py",
                "line_number": 1 + n % 190,
                "line_range": [1 + n % 190],
                "issue_severity": ("HIGH", "MEDIUM", "LOW")[n % 3],
                "issue_confidence": "MEDIUM",
                "issue_text": f"finding {n}",
                "issue_cwe": {"id": 78 + n % 5},
            }
            for n in range(RESULTS)
        ]
    }
    out = tmp_path / "bandit.json"
    out.write_text(json.dumps(report), encoding="utf-8")
    run = EngineRun("bandit", "1.9.4", 0, 0.0, "ok", output_path=out)

    def convert() -> None:
        assert len(BanditAdapter().parse(run, root)) == RESULTS

    assert measure(convert, repeat=1) < budget(2.0)
