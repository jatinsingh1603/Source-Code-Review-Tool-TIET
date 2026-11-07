"""Golden shaped output for the literal fixtures (E09-03), parsed by the real parser.

Each fixture is a small synthetic Python or JavaScript source. Its string literals are found by
``codekavach.parsing.parse``, shaped with a fixed salt, and spliced back into the source; the result
is compared byte for byte with ``<name>.golden.txt``. Run with ``CODEKAVACH_UPDATE_GOLDEN=1`` to
regenerate, and review the diff: a golden change is a change in what leaves the machine.
"""

from pathlib import Path

import pytest

from codekavach.core.models import Language, PrivacyLevel
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.parsing import parse
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator
from codekavach.privacy.pseudonymise.literals import shape
from tests.support.golden import assert_matches_golden

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "pseudonymise" / "literals"
FIXED_SALT = ScanSalt(bytes(range(32)))
LANGUAGES = {".py": Language.PYTHON, ".js": Language.JAVASCRIPT}


class _NoAllowlist:
    def is_public(self, word: str) -> bool:
        return False


def _sources() -> list[Path]:
    return sorted(path for path in FIXTURES.iterdir() if path.suffix in LANGUAGES)


def shape_source(path: Path) -> tuple[str, list[str]]:
    """The fixture with every string literal shaped, and the kinds of those literals in order."""
    text = path.read_text(encoding="utf-8")
    parsed = parse(path.name, LANGUAGES[path.suffix], text)
    generator = PseudonymGenerator(FIXED_SALT)
    out: list[str] = []
    cursor = 0
    kinds: list[str] = []
    for span in parsed.string_literals():
        position = text.index(span.raw_text, cursor)
        out.append(text[cursor:position])
        out.append(
            shape(
                span,
                generator=generator,
                allowlist=_NoAllowlist(),
                level=PrivacyLevel.L3,
            )
        )
        cursor = position + len(span.raw_text)
        kinds.append(str(span.kind))
    out.append(text[cursor:])
    return "".join(out), kinds


@pytest.mark.parametrize("source", _sources(), ids=lambda path: path.name)
def test_shaped_fixture_matches_golden(source: Path) -> None:
    shaped, _ = shape_source(source)
    assert_matches_golden(shaped, source.with_name(source.name + ".golden.txt"))


def test_fixtures_cover_all_six_kinds_and_forty_literals() -> None:
    kinds: list[str] = []
    for source in _sources():
        _, found = shape_source(source)
        kinds.extend(found)
    assert len(kinds) >= 40
    assert set(kinds) == {"sql", "url", "path", "format", "regex", "natural"}
