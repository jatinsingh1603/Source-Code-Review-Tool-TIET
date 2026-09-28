"""Verbatim search for listed sensitive terms in stored ledger payloads (``--check-terms``).

Owning epic: E05.

This is the operator-facing check of invariant I6: no listed term of four or more characters may
occur verbatim in anything recorded for sending. The checker must not disclose what it protects:
terms are held in memory only, never printed, logged or shown by ``repr``; hits are identified by
terms-file line and ledger sequence numbers. A pass means only that no listed term occurs
verbatim, not that nothing can be inferred; structural leakage is measured by the leakage
evaluation.

Matching is a plain substring search, case-sensitive and without Unicode normalisation;
``ignore_case`` adds a ``casefold`` pass. Lines are split with ``split_lines`` so that reported
line numbers match an editor.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from codekavach.cli.errors import UsageError
from codekavach.core.models.text import split_lines

MIN_TERM_LENGTH = 4


@dataclass(frozen=True)
class Term:
    """One listed term; its text never appears in ``repr``."""

    terms_file: str
    line: int
    text: str = field(repr=False)

    def __repr__(self) -> str:
        return f"Term(line={self.line})"


@dataclass(frozen=True)
class TermHit:
    """One listed term found in one payload."""

    terms_file: str
    line: int
    payload_hash: str

    def __repr__(self) -> str:
        return f"TermHit(line={self.line}, payload={self.payload_hash[:12]})"


@dataclass(frozen=True)
class LoadedTerms:
    """The searchable terms of one file and the lines skipped as too short."""

    terms: tuple[Term, ...]
    short_lines: tuple[int, ...]


def load_terms(path: Path) -> LoadedTerms:
    """Parse a terms file: one term per line, ``#`` comments, a leading backslash for a literal #.

    Raises:
        UsageError: ``terms_file_unreadable`` naming the path and, for bad UTF-8, the byte offset.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        raise UsageError(
            f"terms file cannot be read: {path}", code="terms_file_unreadable"
        ) from None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise UsageError(
            f"terms file is not UTF-8: {path} (byte offset {error.start})",
            code="terms_file_unreadable",
        ) from None
    terms: list[Term] = []
    short: list[int] = []
    seen: set[str] = set()
    for number, line in enumerate(split_lines(text.removeprefix("﻿")), start=1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if value.startswith("\\#"):
            value = value[1:]
        if len(value) < MIN_TERM_LENGTH:
            short.append(number)
            continue
        if value in seen:
            continue
        seen.add(value)
        terms.append(Term(terms_file=str(path), line=number, text=value))
    return LoadedTerms(terms=tuple(terms), short_lines=tuple(short))


def _index(texts: Sequence[str]) -> dict[str, list[tuple[int, str]]]:
    """Terms grouped by their first four characters (every term has at least four)."""
    index: dict[str, list[tuple[int, str]]] = {}
    for position, text in enumerate(texts):
        index.setdefault(text[:MIN_TERM_LENGTH], []).append((position, text))
    return index


def _found(index: dict[str, list[tuple[int, str]]], text: str) -> set[int]:
    """Positions (in the term list) of the terms occurring in ``text``: one pass over ``text``."""
    found: set[int] = set()
    for start in range(len(text) - MIN_TERM_LENGTH + 1):
        bucket = index.get(text[start : start + MIN_TERM_LENGTH])
        if bucket is None:
            continue
        for position, term in bucket:
            if position not in found and text.startswith(term, start):
                found.add(position)
    return found


def search_payloads(
    terms: Sequence[Term], payloads: Iterable[tuple[str, str]], *, ignore_case: bool
) -> list[TermHit]:
    """Every (term, payload) pair where the term occurs verbatim in the payload text.

    Plain substring matching; terms are indexed by their first four characters so that each
    payload is scanned once, whatever the number of terms.
    """
    exact = _index([term.text for term in terms])
    folded = _index([term.text.casefold() for term in terms]) if ignore_case else {}
    hits: list[TermHit] = []
    for payload_hash, text in payloads:
        found = _found(exact, text)
        if ignore_case:
            found |= _found(folded, text.casefold())
        hits.extend(
            TermHit(terms[position].terms_file, terms[position].line, payload_hash)
            for position in found
        )
    return sorted(hits, key=lambda hit: (hit.terms_file, hit.line, hit.payload_hash))
