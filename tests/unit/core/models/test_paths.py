import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from codekavach.core.models.paths import normalise_repo_path

COMBINING_ACUTE = chr(0x301)
E_ACUTE = chr(0xE9)

ACCEPTED = [
    ("src/app/db.py", "src/app/db.py"),
    ("./src/app/db.py", "src/app/db.py"),
    (r"src\app\db.py", "src/app/db.py"),
    ("src//app/./db.py", "src/app/db.py"),
    (f"docs/cafe{COMBINING_ACUTE}.md", f"docs/caf{E_ACUTE}.md"),
    ("Src/App/DB.py", "Src/App/DB.py"),
]

REJECTED = [
    "/etc/passwd",
    "C:/x/y.py",
    r"C:\x\y.py",
    r"\\server\share\f",
    "C:notes.py",
    "d:src/a.py",
    "../secrets.py",
    "src/../x.py",
    "",
    ".",
    "src/",
    "src/a\x00.py",
    "src/a\x07.py",
    "src/a\n.py",
    "src/a\x7f.py",
]


@pytest.mark.parametrize(("value", "expected"), ACCEPTED, ids=[a for a, _ in ACCEPTED])
def test_accepted(value: str, expected: str) -> None:
    assert normalise_repo_path(value) == expected
    assert normalise_repo_path(expected) == expected


@pytest.mark.parametrize("value", REJECTED, ids=[repr(v) for v in REJECTED])
def test_rejected_without_echoing_path(value: str) -> None:
    with pytest.raises(ValueError) as info:
        normalise_repo_path(value)
    if value:
        assert value not in str(info.value)


def test_length_limit() -> None:
    assert len(normalise_repo_path("a" * 1024)) == 1024
    with pytest.raises(ValueError, match="1024"):
        normalise_repo_path("a" * 1025)


_segment = st.text(
    alphabet=st.characters(blacklist_categories=("Cc", "Cs"), blacklist_characters="/\\"),
    min_size=1,
    max_size=8,
)
_parts = st.lists(st.one_of(_segment, st.sampled_from([".", "", ".."])), min_size=1, max_size=6)


@given(_parts, st.booleans())
def test_normalisation_is_idempotent_and_clean(parts: list[str], backslash: bool) -> None:
    raw = ("\\" if backslash else "/").join(parts)
    try:
        result = normalise_repo_path(raw)
    except ValueError:
        return
    assume(result)
    assert normalise_repo_path(result) == result
    assert "\\" not in result
    assert "//" not in result
    assert not result.startswith("/")
    assert all(segment not in (".", "..") for segment in result.split("/"))
