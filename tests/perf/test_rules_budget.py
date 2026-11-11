"""Performance budget of the rule loader (E16-01).

Loading 1,000 rules and 20 catalogues must take under 400 ms on the reference machine.
"""

from pathlib import Path

import pytest

from codekavach.analysis.rules.dsl import RuleDef
from codekavach.analysis.rules.loader import load_pack
from codekavach.analysis.rules.matcher import Matcher
from codekavach.core.models import Language
from codekavach.parsing import parse
from tests.support.perf import budget, measure
from tests.support.rule_files import rule_data, rule_text, write_pack

pytestmark = pytest.mark.perf


def catalogue(n: int) -> str:
    entries = "".join(
        f"  - {{id: python.cat{n}.e{k}, kind: sink, pattern: 'call{k}($X)'}}\n" for k in range(10)
    )
    return f"language: python\nframework: fw{n}\nentries:\n{entries}"


def test_1000_rules_and_20_catalogues_load_in_under_400_ms(tmp_path: Path) -> None:
    rules = {
        f"c{n % 20}/r{n}.yaml": rule_text(id=f"python.cls{n % 20}.rule{n}") for n in range(1000)
    }
    pack = write_pack(
        tmp_path, rules=rules, catalogues={f"python/fw{n}.yaml": catalogue(n) for n in range(20)}
    )
    assert measure(lambda: load_pack(pack), repeat=3) < budget(0.4)


# --- the matcher (E16-02) ---------------------------------------------------------------------

LINES = 1000
RULE_COUNT = 20


def source_of(lines: int) -> str:
    body = []
    for n in range(lines // 4):
        body.append(f"def f{n}(a, cur):")
        body.append(f'    cur.execute("SELECT {n} WHERE x = " + a)')
        body.append(f"    value{n} = helper(a, {n})")
        body.append("    return value" + str(n))
    return chr(10).join(body) + chr(10)


def rules_of(count: int) -> list[RuleDef]:
    found = [
        RuleDef.model_validate(
            rule_data(
                id=f"python.perf.rule{n}",
                match={
                    "any": [{"pattern": f"$C.execute{n}($Q)"}, {"pattern": f"helper{n}($A, $B)"}]
                },
            )
        )
        for n in range(count - 1)
    ]
    found.append(RuleDef.model_validate(rule_data()))
    return found


def test_the_matcher_stays_under_2_ms_per_rule_per_1000_lines() -> None:
    parsed = parse("a.py", Language.PYTHON, source_of(LINES))
    rules = rules_of(RULE_COUNT)
    matcher = Matcher()
    matcher.match_file(parsed, rules)  # compile the patterns once, as a real scan does per run
    elapsed = measure(lambda: matcher.match_file(parsed, rules), repeat=3)
    assert elapsed < budget(0.002 * RULE_COUNT)


# --- the default pack (E16-03) -----------------------------------------------------------------


def test_the_default_pack_matches_1000_lines_within_its_per_rule_budget() -> None:
    from codekavach.analysis.rules.coverage import DEFAULT_PACK  # noqa: PLC0415

    pack = load_pack(DEFAULT_PACK)
    matcher, rules = Matcher.for_packs([pack])
    python_rules = [rule for rule in rules if "python" in rule.languages]
    parsed = parse("a.py", Language.PYTHON, source_of(LINES))
    matcher.match_file(parsed, python_rules)  # compile the patterns once, as a real scan does
    elapsed = measure(lambda: matcher.match_file(parsed, python_rules), repeat=3)
    # The synthetic file is a call on every other line, about four times denser than real code,
    # and the shipped rules use catalogue lookups and sequences, so the allowance is 8 ms a rule.
    assert elapsed < budget(0.008 * len(python_rules))
