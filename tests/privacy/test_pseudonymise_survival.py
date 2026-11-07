"""Local I6 suite for identifiers (E09-05): no original name survives in a payload.

For generated programs with known internal names, the whole path (layout, classification, rename,
validation, line map, self-check) runs, and the payload text is searched for every name. The
names are lower-case words of four to nine letters that no allowlist rule keeps. A name may stay
only as a JavaScript shorthand key written beside its own token, which the renamer counts; the
public names of the program must stay.

The same programs also give the other properties of the payload: the line map inverts, the hash
is a function of the input and the salt, and a payload never equals its input.
"""

import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.core.models import Language, PrivacyLevel
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.pseudonymise.engine import Pseudonymiser
from tests.support.factories import SCAN_ID
from tests.support.payload import SALT, segment, slice_of, unredacted
from tests.unit.privacy.pseudonymise.test_rename_properties import (
    JAVASCRIPT_ALLOWLIST,
    PYTHON_ALLOWLIST,
    javascript_program,
    python_program,
)
from tests.unit.privacy.pseudonymise.test_rename_properties import (
    internal_names as _internal_names,
)

pytestmark = pytest.mark.privacy

ENGINE = Pseudonymiser()
WORD = re.compile(r"[\w$]+")


def payload_of(program: str, language: Language, salt: ScanSalt = SALT):  # type: ignore[no-untyped-def]
    path = "program.py" if language is Language.PYTHON else "program.js"
    slice_ = slice_of(segment(path, 1, program.rstrip("\n").split("\n")), language=language)
    result = ENGINE.process(
        slice_, unredacted(slice_), salt=salt, level=PrivacyLevel.L3, scan_id=SCAN_ID
    )
    return slice_, result


def check_line_map(slice_, payload) -> None:  # type: ignore[no-untyped-def]
    first = slice_.segments[0].region.start_line
    last = slice_.segments[0].region.end_line
    for number in range(1, payload.text.line_count + 1):
        mapped = payload.map_line(number)
        assert mapped is None or (mapped[0] == 0 and first <= mapped[1] <= last)
    mapped_lines = [payload.map_line(n) for n in range(1, payload.text.line_count + 1)]
    assert [m for m in mapped_lines if m is not None] == [
        (0, line) for line in range(first, last + 1)
    ]


@settings(max_examples=40, deadline=None)
@given(
    names=_internal_names(PYTHON_ALLOWLIST, 7), word=st.from_regex(r"[a-z]{5,9}", fullmatch=True)
)
def test_python_no_internal_name_survives_in_the_payload(names: list[str], word: str) -> None:
    program = python_program(names)
    program += f'# {word} is only mentioned here\nnote = "{word} failed"\n'
    if PYTHON_ALLOWLIST.is_public(word) or word in names:
        return
    slice_, result = payload_of(program, Language.PYTHON)
    text = result.payload.text.expose()
    words = set(WORD.findall(text))
    assert not (set(names) | {word}) & words
    assert {"print", "range"} <= words
    assert text != program
    check_line_map(slice_, result.payload)


@settings(max_examples=40, deadline=None)
@given(names=_internal_names(JAVASCRIPT_ALLOWLIST, 9))
def test_javascript_a_name_survives_only_as_a_key_beside_its_token(names: list[str]) -> None:
    program = javascript_program(names)
    slice_, result = payload_of(program, Language.JAVASCRIPT)
    text = result.payload.text.expose()
    keys = set(names[3:5])  # the two names written as shorthand
    for name in names:
        for found in re.finditer(rf"(?<![\w$]){name}(?![\w$])", text):
            assert name in keys, name
            assert re.match(r"\s*:\s*(?:var|param)_\d+", text[found.end() :]), name
    assert "console.log" in text
    check_line_map(slice_, result.payload)


@settings(max_examples=25, deadline=None)
@given(names=_internal_names(PYTHON_ALLOWLIST, 7), seed=st.binary(min_size=32, max_size=32))
def test_the_hash_is_a_function_of_the_input_and_the_salt(names: list[str], seed: bytes) -> None:
    program = python_program(names)
    salt = ScanSalt(seed)
    first = payload_of(program, Language.PYTHON, salt)[1]
    second = payload_of(program, Language.PYTHON, salt)[1]
    assert first.payload.payload_hash == second.payload.payload_hash
    assert [(e.pseudonym, e.original) for e in first.batch.entries] == [
        (e.pseudonym, e.original) for e in second.batch.entries
    ]
    # every original of the batch is one the program holds, and none of them is in the payload
    originals = {e.original for e in first.batch.entries}
    assert set(names) <= originals
