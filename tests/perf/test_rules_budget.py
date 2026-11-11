"""Performance budget of the rule loader (E16-01).

Loading 1,000 rules and 20 catalogues must take under 400 ms on the reference machine.
"""

from pathlib import Path

import pytest

from codekavach.analysis.rules.loader import load_pack
from tests.support.perf import budget, measure
from tests.support.rule_files import rule_text, write_pack

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
