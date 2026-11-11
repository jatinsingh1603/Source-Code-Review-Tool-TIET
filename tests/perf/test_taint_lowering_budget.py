"""Performance budgets of the taint lowering, the def-use pass and the propagation (E17-01, E17-02).

Lowering one 1,000-line Python file takes under 150 ms and one 1,000-line TypeScript file under
200 ms on the reference machine; the def-use pass over every function of the Python file takes
under 150 ms.
"""

import pytest

from codekavach.analysis.taint.catalogue import Binding
from codekavach.analysis.taint.defuse import analyse
from codekavach.analysis.taint.propagate import Budget, propagate_bound
from codekavach.core.models import Language
from tests.support.perf import budget, measure
from tests.support.taint import lower_source, shipped_catalogues

pytestmark = pytest.mark.perf

PY_BLOCK = (
    "def handler_{n}(request, db):\n"
    "    name = request.args.get('name')\n"
    "    rows = []\n"
    "    for item in db.fetch(name):\n"
    "        if item.active:\n"
    "            rows.append(item.value + '-' + name)\n"
    "        else:\n"
    "            audit(item)\n"
    "    try:\n"
    "        db.execute(f'select {{name}} from t')\n"
    "    except Exception as error:\n"
    "        log(error)\n"
    "    return rows\n\n"
)
TS_BLOCK = (
    "function handler_{n}(req: Request, db: Db): string[] {{\n"
    "  const name = req.query.name;\n"
    "  const rows: string[] = [];\n"
    "  for (const item of db.fetch(name)) {{\n"
    "    if (item.active) {{ rows.push(item.value + '-' + name); }} else {{ audit(item); }}\n"
    "  }}\n"
    "  try {{ db.execute(`select ${{name}} from t`); }} catch (error) {{ log(error); }}\n"
    "  return rows;\n"
    "}}\n\n"
)


def source(block: str, lines: int) -> str:
    per = block.count("\n")
    return "".join(block.format(n=n) for n in range(lines // per))


def test_lowering_1000_python_lines_is_within_150_ms() -> None:
    code = source(PY_BLOCK, 1000)
    elapsed = measure(lambda: lower_source(code))
    assert elapsed < budget(0.150), f"{elapsed * 1000:.0f} ms"


def test_lowering_1000_typescript_lines_is_within_200_ms() -> None:
    code = source(TS_BLOCK, 1000)
    elapsed = measure(lambda: lower_source(code, Language.TYPESCRIPT))
    assert elapsed < budget(0.200), f"{elapsed * 1000:.0f} ms"


def test_the_def_use_pass_over_1000_python_lines_is_within_150_ms() -> None:
    module = lower_source(source(PY_BLOCK, 1000))
    elapsed = measure(lambda: [analyse(function) for function in module.functions])
    assert elapsed < budget(0.150), f"{elapsed * 1000:.0f} ms"


def test_propagation_over_1000_python_lines_is_within_100_ms() -> None:
    """Propagation on top of the lowering: 100 ms per 1,000-line file (E17-02)."""
    code = "from flask import request\n" + source(PY_BLOCK, 1000)
    module = lower_source(code)
    binding = Binding(shipped_catalogues(), module.aliases, "python")

    def run() -> int:
        return sum(
            len(propagate_bound(function, binding, budget=Budget.of(30)))
            for function in module.functions
        )

    assert run() > 0, "the synthetic file must contain flows, or the budget measures nothing"
    elapsed = measure(run)
    assert elapsed < budget(0.100), f"{elapsed * 1000:.0f} ms"
