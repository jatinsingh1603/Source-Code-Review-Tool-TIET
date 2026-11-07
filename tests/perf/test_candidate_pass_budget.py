"""Performance budget of the candidate pass (E13-01).

A full candidate pass over the KavachBank fixture completes in under 5 seconds, because the demo
job runs on every push. The pass is every file parsed once and all matchers run over one traversal.
The budget is scaled by the performance factor.
"""

import pytest

from codekavach.analysis.aggregate.stage import aggregate
from codekavach.analysis.rules.builtin import BUILTIN_MATCHERS
from codekavach.analysis.rules.engine import run_matchers
from codekavach.core.models import Candidate, Language
from codekavach.parsing import parse
from tests.support.kavachbank import FIXTURE_ROOT
from tests.support.perf import assert_within_budget, measure

BUDGET_SECONDS = 5.0
LANGUAGES = {".py": Language.PYTHON, ".js": Language.JAVASCRIPT}


def candidate_pass() -> list[Candidate]:
    found: list[Candidate] = []
    for path in sorted(FIXTURE_ROOT.rglob("*")):
        language = LANGUAGES.get(path.suffix)
        if language is None or not path.is_file():
            continue
        name = path.relative_to(FIXTURE_ROOT).as_posix()
        parsed = parse(name, language, path.read_text(encoding="utf-8"))
        found.extend(run_matchers(BUILTIN_MATCHERS, parsed, None))
    return aggregate(found)


@pytest.mark.perf
def test_the_candidate_pass_over_the_fixture_stays_within_budget() -> None:
    assert len(candidate_pass()) == 10  # also warms the grammar and query caches
    assert_within_budget(measure(candidate_pass, repeat=3), BUDGET_SECONDS, label="candidate pass")
