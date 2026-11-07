"""Golden decision maps of the 50 classification fixtures (E09-02).

Each ``.py`` or ``.js`` file under ``tests/fixtures/pseudonymise/classification`` is one case: the
source, and a ``.golden.txt`` beside it holding the decision of every identifier occurrence, the
rule that made it, the conservative counters, the kept names and the allowlist version. Rewrite a
golden with ``CODEKAVACH_UPDATE_GOLDEN=1`` and read the diff before committing it.
"""

from pathlib import Path

import pytest

from codekavach.core.models import Language
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from tests.support.classification import FIXTURES, classify_text, render
from tests.support.golden import assert_matches_golden

SOURCES = sorted(path for path in FIXTURES.iterdir() if path.suffix in {".py", ".js"})


def _language(path: Path) -> Language:
    return Language.JAVASCRIPT if path.suffix == ".js" else Language.PYTHON


def test_there_are_twenty_five_cases_per_language() -> None:
    python = [path for path in SOURCES if path.suffix == ".py"]
    javascript = [path for path in SOURCES if path.suffix == ".js"]
    assert len(python) == 25
    assert len(javascript) == 25


@pytest.mark.parametrize("path", SOURCES, ids=lambda path: path.name)
def test_decision_map_matches_golden(path: Path) -> None:
    language = _language(path)
    result = classify_text(language, path.read_text(encoding="utf-8"))
    actual = render(
        result,
        name=path.name,
        allowlist_version=PublicAllowlist.bundled(language).version(),
    )
    assert_matches_golden(actual, path.with_suffix(".golden.txt"))


@pytest.mark.parametrize("path", SOURCES, ids=lambda path: path.name)
def test_every_case_has_a_golden_and_a_decision_per_symbol(path: Path) -> None:
    assert path.with_suffix(".golden.txt").is_file()
    result = classify_text(_language(path), path.read_text(encoding="utf-8"))
    assert result.decisions
