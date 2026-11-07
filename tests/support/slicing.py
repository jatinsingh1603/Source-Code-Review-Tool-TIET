"""Helpers for the slicing tests (E11-01): a real ``ParseIndex`` built from source strings."""

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from codekavach.core.models import Candidate, Language, sha256_hex
from codekavach.core.models.text import split_lines
from codekavach.ingest.models import SourceFile
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.imports import DefaultImportResolver, attach_imports
from codekavach.parsing.symbols import build_symbol_table
from codekavach.privacy.slicing.index import ParseIndex
from tests.support.factories import make_candidate, make_location

EXTENSIONS = {".py": Language.PYTHON, ".js": Language.JAVASCRIPT, ".ts": Language.TYPESCRIPT}


def language_of(path: str) -> Language:
    for suffix, language in EXTENSIONS.items():
        if path.endswith(suffix):
            return language
    return Language.UNKNOWN


def make_index(
    sources: Mapping[str, str],
    *,
    vendored: tuple[str, ...] = (),
    generated: tuple[str, ...] = (),
    minified: tuple[str, ...] = (),
    never_send: Callable[[str], bool] | None = None,
) -> ParseIndex:
    """A ``ParseIndex`` over ``sources`` (path to text), parsed with the real parser."""
    internal = {path.split("/")[0].rsplit(".", 1)[0] for path in sources}
    files: dict[str, SourceFile] = {}
    ast = {}
    symbols = {}
    for path, text in sources.items():
        language = language_of(path)
        files[path] = SourceFile(
            path=path,
            sha256=sha256_hex(text),
            size_bytes=len(text.encode()),
            language=language,
            line_count=len(split_lines(text)),
            encoding="utf-8",
            is_vendored=path in vendored,
            is_generated=path in generated,
            is_minified=path in minified,
        )
        if language is Language.UNKNOWN:
            continue  # in the inventory, but never parsed: no grammar
        parsed = parse(path, language, text)
        ast[path] = parsed
        table = build_symbol_table(parsed, REGISTRY.get(language))
        symbols[path] = attach_imports(
            table,
            parsed,
            DefaultImportResolver(language, internal_names=internal),
            project_root=Path(),
        )
    return ParseIndex(files=files, ast=ast, symbols=symbols, never_send=never_send)


def candidate_at(path: str, line: int, *more: tuple[str, int], **overrides: Any) -> Candidate:
    """A candidate whose locations are the given ``(path, line)`` pairs (the first is primary)."""
    locations = tuple(
        make_location(
            path=where, start_line=at, end_line=at, start_col=None, end_col=None, symbol=None
        )
        for where, at in ((path, line), *more)
    )
    return make_candidate(
        locations=locations, language=language_of(path), taint_path=None, **overrides
    )


def candidate_id_n(number: int) -> str:
    """A valid candidate id that differs by ``number`` (0 to 9), built so it is no literal."""
    return "cand_0" + "0" * 24 + "ABCDEFGHJK"[number]
