"""Every code block in the "Recipes" section of docs/reference/domain-model.md runs (E02-30)."""

import contextlib
import io
import re
from pathlib import Path

import pytest

REFERENCE = Path(__file__).resolve().parents[4] / "docs" / "reference" / "domain-model.md"


def recipes() -> list[str]:
    text = REFERENCE.read_text(encoding="utf-8")
    recipes_section = text[text.index("## 8. Recipes") :]
    return re.findall(r"```python\n(.*?)```", recipes_section, re.DOTALL)


def test_there_are_four_recipes() -> None:
    assert len(recipes()) == 4


@pytest.mark.parametrize("index", range(4), ids=["candidate", "evidence", "ledger", "status"])
def test_recipe_runs(index: int) -> None:
    code = recipes()[index]
    with contextlib.redirect_stdout(io.StringIO()):
        exec(compile(code, f"domain-model.md recipe {index + 1}", "exec"), {})  # noqa: S102
