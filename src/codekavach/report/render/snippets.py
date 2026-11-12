"""The shared snippet renderer: Pygments tokens with line numbers, for every format.

Owning epic: E31 (E31-01).

Input is an ``EvidenceView`` whose text is already masked. ``html_rows`` returns escaped HTML per
line (token spans with inline-free CSS classes), ``token_rows`` returns coloured runs for DOCX and
XLSX. Lexing is per snippet, so a multi-line string keeps its colour across lines. If Pygments is
missing the text is returned unhighlighted, never dropped.
"""

import importlib
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Final

from markupsafe import Markup, escape

from codekavach.report.model.finding_view import EvidenceView

_LEXERS: Final = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "kotlin": "kotlin",
    "c": "c",
    "cpp": "cpp",
    "php": "php",
    "go": "go",
    "csharp": "csharp",
    "ruby": "ruby",
    "dockerfile": "docker",
    "terraform": "terraform",
    "yaml": "yaml",
    "json": "json",
    "toml": "toml",
    "xml": "xml",
    "shell": "bash",
    "sql": "sql",
    "html": "html",
}
# Token class -> (css class, colour, bold, italic); a light palette that prints well.
_STYLE: Final[dict[str, tuple[str, str, bool, bool]]] = {
    "Keyword": ("k", "#7c3aed", True, False),
    "Name.Builtin": ("nb", "#0e7490", False, False),
    "Name.Function": ("nf", "#1d4ed8", False, False),
    "Name.Class": ("nc", "#1d4ed8", True, False),
    "Name.Decorator": ("nd", "#a16207", False, False),
    "Literal.String": ("s", "#15803d", False, False),
    "Literal.Number": ("m", "#b45309", False, False),
    "Comment": ("c", "#6b7280", False, True),
    "Operator": ("o", "#be123c", False, False),
}


@dataclass(frozen=True)
class Run:
    """One coloured run of text."""

    text: str
    colour: str | None = None
    bold: bool = False
    italic: bool = False
    css: str | None = None


@dataclass(frozen=True)
class SnippetRow:
    """One numbered line of a snippet."""

    number: int
    marked: bool
    runs: tuple[Run, ...]

    @property
    def html(self) -> Markup:
        """The escaped line with token spans."""
        parts = []
        for run in self.runs:
            if run.css:
                parts.append(Markup('<span class="t{}">{}</span>').format(run.css, run.text))
            else:
                parts.append(escape(run.text))
        return Markup("").join(parts)

    @property
    def text(self) -> str:
        """The plain line."""
        return "".join(run.text for run in self.runs)


def _style(token_type: Any) -> tuple[str, str, bool, bool] | None:
    current = token_type
    while current is not None and len(current):
        key = ".".join(current)
        if key in _STYLE:
            return _STYLE[key]
        current = current.parent
    return None


@lru_cache(maxsize=32)
def _lexer(language: str) -> Any:
    try:
        lexers = importlib.import_module("pygments.lexers")
        util = importlib.import_module("pygments.util")
    except ImportError:
        return None
    try:
        return lexers.get_lexer_by_name(
            _LEXERS.get(language, language), stripnl=False, ensurenl=False
        )
    except util.ClassNotFound:
        return None


def token_rows(evidence: EvidenceView) -> tuple[SnippetRow, ...]:
    """The snippet as rows of coloured runs."""
    lines = [line.text for line in evidence.lines]
    lexer = _lexer(evidence.language)
    per_line: list[list[Run]] = [[] for _ in lines]
    if lexer is None:
        per_line = [[Run(text)] if text else [] for text in lines]
    else:
        index = 0
        for token_type, value in lexer.get_tokens("\n".join(lines)):
            style = _style(token_type)
            pieces = value.split("\n")
            for offset, piece in enumerate(pieces):
                if offset:
                    index += 1
                if piece and index < len(per_line):
                    if style:
                        css, colour, bold, italic = style
                        per_line[index].append(Run(piece, colour, bold, italic, css))
                    else:
                        per_line[index].append(Run(piece))
    return tuple(
        SnippetRow(number=line.number, marked=line.marked, runs=tuple(runs))
        for line, runs in zip(evidence.lines, per_line, strict=True)
    )


def css_rules() -> str:
    """The CSS of the token classes."""
    rules = []
    for css, colour, bold, italic in _STYLE.values():
        extra = (";font-weight:600" if bold else "") + (";font-style:italic" if italic else "")
        rules.append(f".t{css}{{color:{colour}{extra}}}")
    return "".join(rules)
