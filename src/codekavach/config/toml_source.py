r"""Bounded, confined reading of TOML configuration files, and key-to-line lookup.

Owning epic: E03.

A project file may come from a hostile repository, so ``read_toml`` reads each file once through a
single descriptor, checks the size and file type on that descriptor (CWE-367), bounds the read
(CWE-400), refuses a path that resolves outside ``confine_to`` (CWE-59) and never puts file
content into a message (CWE-532).

``locate_key`` is a best-effort lookup of the line on which a dotted key is written. Lines are
split with ``split_lines`` (only ``\n`` and ``\r\n`` end a line, as in TOML); ``str.splitlines``
is never used because it also breaks on form feed and U+2028 and would shift line numbers.
"""

import codecs
import hashlib
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codekavach.config.constants import MAX_CONFIG_BYTES
from codekavach.config.errors import ConfigError, ConfigErrorCode, ConfigSyntaxError
from codekavach.core.models.text import split_lines

_POSITION = re.compile(r"at line (\d+), column (\d+)")
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
_BARE = re.compile(r"[A-Za-z0-9_-]+")
_INDEXED = re.compile(r"^(.*?)((?:\[\d+\])*)$")
_INDEX = re.compile(r"\[(\d+)\]")
_CHUNK = 65_536

Token = str | int


@dataclass(frozen=True, slots=True)
class TomlDocument:
    """One parsed configuration file; ``text`` and ``data`` describe the bytes ``sha256`` hashes."""

    path: Path
    data: dict[str, Any]
    text: str
    sha256: str


def _refuse(path: Path, reason: str) -> ConfigError:
    return ConfigError.single(ConfigErrorCode.CK_CFG_005, reason, source=str(path))


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        chunk = os.read(descriptor, min(remaining, _CHUNK))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_bytes(path: Path, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise _refuse(path, "file does not exist") from None
    except OSError:
        raise _refuse(path, "file cannot be opened or is not a regular file") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise _refuse(path, "not a regular file")
        if info.st_size > max_bytes:
            raise _refuse(path, f"file is larger than {max_bytes} bytes")
        raw = _read_bounded(descriptor, max_bytes + 1)
    except OSError:
        raise _refuse(path, "file cannot be read") from None
    finally:
        os.close(descriptor)
    if len(raw) > max_bytes:
        raise _refuse(path, f"file is larger than {max_bytes} bytes")
    return raw


def _check_confined(path: Path, confine_to: Path) -> None:
    try:
        resolved = path.resolve(strict=True)
        root = confine_to.resolve()
    except (OSError, RuntimeError):
        raise _refuse(path, "file does not exist or its links cannot be resolved") from None
    if not resolved.is_relative_to(root):
        raise _refuse(path, "file resolves to a location outside the permitted directory")


def _syntax_error(path: Path, error: tomllib.TOMLDecodeError) -> ConfigSyntaxError:
    description = str(error.args[0]) if error.args else str(error)
    match = _POSITION.search(str(error))
    line = int(match.group(1)) if match else None
    description = _POSITION.sub("", description).replace("()", "").strip(" ()")
    description = _QUOTED.sub("<...>", description)
    return ConfigSyntaxError.single(
        ConfigErrorCode.CK_CFG_001,
        f"invalid TOML: {description}" if description else "invalid TOML",
        source=str(path),
        line=line,
    )


def read_bounded_text(
    path: Path, *, max_bytes: int = MAX_CONFIG_BYTES, confine_to: Path | None = None
) -> tuple[str, bytes]:
    """Read one UTF-8 file once, bounded and optionally confined; a byte-order mark is dropped.

    Returns the decoded text and the raw bytes.

    Raises:
        ConfigError: code CK-CFG-005 when the file is missing, not a regular file, larger than
            ``max_bytes``, not UTF-8, or resolves outside ``confine_to``.
    """
    if confine_to is not None:
        _check_confined(path, confine_to)
    raw = _read_bytes(path, max_bytes)
    try:
        text = raw.removeprefix(codecs.BOM_UTF8).decode("utf-8")
    except UnicodeDecodeError:
        raise _refuse(path, "file is not valid UTF-8") from None
    return text, raw


def read_bounded_bytes(path: Path, *, max_bytes: int = MAX_CONFIG_BYTES) -> bytes:
    """Read one file once, bounded; for callers that must verify the exact bytes they parse.

    Raises:
        ConfigError: code CK-CFG-005 when the file is missing, not a regular file or larger
            than ``max_bytes``.
    """
    return _read_bytes(path, max_bytes)


def parse_toml_bytes(raw: bytes, path: Path) -> TomlDocument:
    """Parse bytes already read from ``path`` (used to verify and parse one single read).

    Raises:
        ConfigError: code CK-CFG-005 when the bytes are not UTF-8.
        ConfigSyntaxError: code CK-CFG-001 when they are not valid TOML.
    """
    try:
        text = raw.removeprefix(codecs.BOM_UTF8).decode("utf-8")
    except UnicodeDecodeError:
        raise _refuse(path, "file is not valid UTF-8") from None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise _syntax_error(path, error) from None
    return TomlDocument(path=path, data=data, text=text, sha256=hashlib.sha256(raw).hexdigest())


def read_toml(
    path: Path, *, max_bytes: int = MAX_CONFIG_BYTES, confine_to: Path | None = None
) -> TomlDocument:
    """Read and parse one TOML file.

    Raises:
        ConfigError: code CK-CFG-005 when the file is missing, not a regular file, larger than
            ``max_bytes``, not UTF-8, or resolves outside ``confine_to``.
        ConfigSyntaxError: code CK-CFG-001 when the file is not valid TOML.
    """
    if confine_to is not None:
        _check_confined(path, confine_to)
    return parse_toml_bytes(_read_bytes(path, max_bytes), path)


def _parse_key(text: str, position: int) -> tuple[list[str], int] | None:
    """Parse a bare, quoted or dotted TOML key starting at ``position``."""
    parts: list[str] = []
    while True:
        while position < len(text) and text[position] in " \t":
            position += 1
        if position >= len(text):
            return None
        quote = text[position]
        if quote in "\"'":
            end = position + 1
            while end < len(text) and text[end] != quote:
                end += 2 if quote == '"' and text[end] == "\\" else 1
            if end >= len(text):
                return None
            part = text[position + 1 : end]
            if quote == '"':
                part = part.encode("utf-8", "surrogatepass").decode("unicode_escape", "ignore")
            parts.append(part)
            position = end + 1
        else:
            match = _BARE.match(text, position)
            if match is None:
                return None
            parts.append(match.group(0))
            position = match.end()
        while position < len(text) and text[position] in " \t":
            position += 1
        if position < len(text) and text[position] == ".":
            position += 1
            continue
        return parts, position


@dataclass(slots=True)
class _Scan:
    """Lexical state carried from one line to the next."""

    multiline: str | None = None  # the open triple-quote delimiter
    depth: int = 0  # open [ and { of a value


def _advance(line: str, state: _Scan) -> None:
    """Update ``state`` past ``line``: strings, comments and bracket depth."""
    index = 0
    while index < len(line):
        if state.multiline is not None:
            end = line.find(state.multiline, index)
            if end < 0:
                return
            index = end + 3
            while line.startswith(state.multiline[0], index):
                index += 1  # up to two extra quotes may close the string
            state.multiline = None
            continue
        char = line[index]
        if char == "#":
            return
        if line.startswith('"""', index) or line.startswith("'''", index):
            state.multiline = line[index : index + 3]
            index += 3
            continue
        if char in "\"'":
            index += 1
            while index < len(line) and line[index] != char:
                index += 2 if char == '"' and line[index] == "\\" else 1
            index += 1
            continue
        if char in "[{":
            state.depth += 1
        elif char in "]}":
            state.depth = max(0, state.depth - 1)
        index += 1


class _Locator:
    """Records the first line of every table header and key path in a TOML text."""

    def __init__(self) -> None:
        self.lines: dict[tuple[Token, ...], int] = {}
        self.table: tuple[Token, ...] = ()
        self.arrays: dict[tuple[Token, ...], int] = {}

    def _record(self, path: tuple[Token, ...], number: int) -> None:
        self.lines.setdefault(path, number)

    def _resolve(self, parts: list[str]) -> list[Token]:
        tokens: list[Token] = []
        for part in parts:
            tokens.append(part)
            if tuple(tokens) in self.arrays:
                tokens.append(self.arrays[tuple(tokens)])
        return tokens

    def header(self, stripped: str, number: int) -> bool:
        array = stripped.startswith("[[")
        parsed = _parse_key(stripped, 2 if array else 1)
        if parsed is None:
            return False
        parts, end = parsed
        closing = "]]" if array else "]"
        if not stripped.startswith(closing, end):
            return False
        rest = stripped[end + len(closing) :].strip()
        if rest and not rest.startswith("#"):
            return False
        tokens = self._resolve(parts[:-1])
        tokens.append(parts[-1])
        if array:
            key = tuple(tokens)
            index = self.arrays.get(key, -1) + 1
            self.arrays[key] = index
            self._record(key, number)
            tokens.append(index)
        self.table = tuple(tokens)
        self._record(self.table, number)
        return True

    def key(self, stripped: str, number: int) -> None:
        parsed = _parse_key(stripped, 0)
        if parsed is None:
            return
        parts, end = parsed
        if not stripped.startswith("=", end):
            return
        path: tuple[Token, ...] = self.table
        for part in parts:
            path = (*path, part)
            self._record(path, number)

    def feed(self, text: str) -> None:
        state = _Scan()
        for number, line in enumerate(split_lines(text), start=1):
            if state.multiline is None and state.depth == 0:
                stripped = line.strip()
                if stripped.startswith("["):
                    self.header(stripped, number)
                elif stripped and not stripped.startswith("#"):
                    self.key(stripped, number)
            _advance(line, state)


def _target(dotted_key: str) -> tuple[Token, ...] | None:
    tokens: list[Token] = []
    for segment in dotted_key.split("."):
        match = _INDEXED.match(segment)
        if match is None or not match.group(1):
            return None
        tokens.append(match.group(1))
        tokens.extend(int(index) for index in _INDEX.findall(match.group(2)))
    return tuple(tokens)


def locate_key(text: str, dotted_key: str) -> int | None:
    """The 1-based line of ``dotted_key``, else of its longest written prefix, else ``None``.

    Best effort: never raises.
    """
    try:
        target = _target(dotted_key)
        if not target:
            return None
        locator = _Locator()
        locator.feed(text)
        for length in range(len(target), 0, -1):
            line = locator.lines.get(target[:length])
            if line is not None:
                return line
    except Exception:  # noqa: BLE001 - diagnostics must never fail the caller
        return None
    return None
