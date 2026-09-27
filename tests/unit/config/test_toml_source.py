import codecs
import hashlib
import os
import sys
import tomllib
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.config import toml_source
from codekavach.config.errors import ConfigError, ConfigErrorCode, ConfigSyntaxError
from codekavach.config.toml_source import locate_key, read_toml
from codekavach.core.models.text import split_lines

EXAMPLE = """# line 1
[scan]
jobs = 4                      # line 3
[[privacy.paths]]             # line 4
pattern = "a/**"
[[privacy.paths]]             # line 6
pattern = "b/**"
level = "L4"                  # line 8
"""

MARKER = "PLANTEDCONTENT"


def write(tmp_path: Path, content: bytes, name: str = "codekavach.toml") -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def refused(call: object) -> ConfigError:
    with pytest.raises(ConfigError) as error:
        call()  # type: ignore[operator]
    assert error.value.code is ConfigErrorCode.CK_CFG_005
    assert MARKER not in str(error.value)
    return error.value


def test_reads_valid_file(tmp_path: Path) -> None:
    raw = b"[scan]\njobs = 4\n"
    document = read_toml(write(tmp_path, raw))
    assert document.data == {"scan": {"jobs": 4}}
    assert document.text == raw.decode()
    assert document.sha256 == hashlib.sha256(raw).hexdigest()


def test_too_large(tmp_path: Path) -> None:
    path = write(tmp_path, f'x = "{MARKER}"\n'.encode().ljust(101, b"#"))
    refused(lambda: read_toml(path, max_bytes=100))
    assert read_toml(path, max_bytes=101).data == {"x": MARKER}


def test_latin1(tmp_path: Path) -> None:
    path = write(tmp_path, f'x = "{MARKER} caf\xe9"\n'.encode("latin-1"))
    refused(lambda: read_toml(path))


def test_directory_and_missing(tmp_path: Path) -> None:
    refused(lambda: read_toml(tmp_path))
    refused(lambda: read_toml(tmp_path / "missing.toml"))


needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@needs_symlinks
def test_symlink_escaping_confinement(tmp_path: Path) -> None:
    outside = write(tmp_path, f'x = "{MARKER}"\n'.encode(), "outside.toml")
    project = tmp_path / "project"
    project.mkdir()
    link = project / "codekavach.toml"
    link.symlink_to(outside)
    error = refused(lambda: read_toml(link, confine_to=project))
    assert "outside" in str(error)
    assert read_toml(link).data == {"x": MARKER}


@needs_symlinks
def test_symlink_inside_confinement(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    target = write(project, b"x = 1\n", "real.toml")
    link = project / "codekavach.toml"
    link.symlink_to(target)
    assert read_toml(link, confine_to=project).data == {"x": 1}


def test_confinement_of_regular_files(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    inside = write(project, b"x = 1\n")
    assert read_toml(inside, confine_to=project).data == {"x": 1}
    outside = write(tmp_path, b"x = 1\n", "other.toml")
    refused(lambda: read_toml(outside, confine_to=project))
    refused(lambda: read_toml(project / ".." / "other.toml", confine_to=project))
    refused(lambda: read_toml(project / "missing.toml", confine_to=project))


def test_syntax_error_line(tmp_path: Path) -> None:
    lines = [f"a{index} = 1" for index in range(6)] + [f'b = "{MARKER}" oops', "c = 2"]
    path = write(tmp_path, "\n".join(lines).encode())
    with pytest.raises(ConfigSyntaxError) as error:
        read_toml(path)
    assert error.value.code is ConfigErrorCode.CK_CFG_001
    assert error.value.issues[0].line == 7
    assert MARKER not in str(error.value)
    assert "invalid TOML" in str(error.value)


def test_byte_order_mark(tmp_path: Path) -> None:
    raw = codecs.BOM_UTF8 + b"x = 1\n"
    document = read_toml(write(tmp_path, raw))
    assert document.data == {"x": 1}
    assert not document.text.startswith("﻿")
    assert document.sha256 == hashlib.sha256(raw).hexdigest()


def test_hash_is_stable(tmp_path: Path) -> None:
    path = write(tmp_path, b"x = 1\n")
    assert read_toml(path).sha256 == read_toml(path).sha256


def test_single_open_and_bounded_reads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write(tmp_path, b"x = 1\n")
    opens: list[object] = []
    sizes: list[int] = []
    real_open, real_read = os.open, os.read

    def counting_open(target: object, flags: int, *args: int) -> int:
        opens.append(target)
        return real_open(target, flags, *args)  # type: ignore[arg-type]

    def counting_read(fd: int, size: int) -> bytes:
        sizes.append(size)
        return real_read(fd, size)

    monkeypatch.setattr(os, "open", counting_open)
    monkeypatch.setattr(os, "read", counting_read)
    read_toml(path, max_bytes=10)
    assert opens == [path]
    assert sum(sizes) <= 11 + 11


def test_locate_key_examples() -> None:
    assert locate_key(EXAMPLE, "scan.jobs") == 3
    assert locate_key(EXAMPLE, "privacy.paths[1].level") == 8
    assert locate_key(EXAMPLE, "privacy.paths[0].level") == 4
    assert locate_key(EXAMPLE, "llm.enabled") is None


FIXTURE = '''# jobs = 99 is a comment that looks like a key
title = """
[scan]
jobs = 1
"""
literal = \'\'\'
exclude = []
\'\'\'
[scan]
"jobs" = 4
languages = [
  "python",
  "java",
]
fail_on.level = "high"
inline = { a = 1, b = 2 }

[llm.providers."lab"]
kind = "mock"

[[privacy.paths]]
pattern = "a/**"
[[privacy.paths]]
pattern = "b/**"
level = "L4"
'''


@pytest.mark.parametrize(
    ("key", "line"),
    [
        ("title", 2),
        ("literal", 6),
        ("scan", 9),
        ("scan.jobs", 10),
        ("scan.languages", 11),
        ("scan.fail_on.level", 15),
        ("scan.fail_on", 15),
        ("scan.inline.b", 16),
        ("llm.providers.lab.kind", 19),
        ("llm.providers.lab", 18),
        ("privacy.paths[0].pattern", 22),
        ("privacy.paths[1].level", 25),
        ("privacy.paths[2].level", 21),  # falls back to the first [[privacy.paths]] header
        ("exclude", None),
    ],
)
def test_locate_key_fixture(key: str, line: int | None) -> None:
    assert locate_key(FIXTURE, key) == line


LEGAL_IN_STRINGS = {chr(0x2028), chr(0x85)}  # the others are illegal in TOML strings


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("odd", [chr(12), chr(0x2028), chr(13), chr(0x85), chr(11)])
def test_odd_characters_do_not_shift_lines(newline: str, odd: str) -> None:
    text = newline.join([f'a = "x{odd}y"', "[scan]", "jobs = 4", "bad = = 1", ""])
    assert locate_key(text, "scan.jobs") == 3
    if odd in LEGAL_IN_STRINGS:
        with pytest.raises(tomllib.TOMLDecodeError, match="at line 4"):
            tomllib.loads(text)


def test_config_package_never_uses_splitlines() -> None:
    root = Path(toml_source.__file__).parent
    for source in root.rglob("*.py"):
        assert ".splitlines(" not in source.read_text(encoding="utf-8"), source


@given(st.text(), st.text())
def test_property_locate_key_never_raises(text: str, key: str) -> None:
    line = locate_key(text, key)
    assert line is None or 1 <= line <= len(split_lines(text))


keys = st.from_regex(r"[a-z][a-z0-9_]{0,8}", fullmatch=True)


@given(st.dictionaries(keys, st.integers(), min_size=1, max_size=10), st.booleans())
def test_property_flat_table_lines(table: dict[str, int], crlf: bool) -> None:
    newline = "\r\n" if crlf else "\n"
    lines = ["# header", "[section]", *(f"{key} = {value}" for key, value in table.items())]
    text = newline.join(lines) + newline
    for offset, key in enumerate(table, start=3):
        assert locate_key(text, f"section.{key}") == offset
