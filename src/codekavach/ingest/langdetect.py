"""Language detection from a path and the head of a file (E06-02).

Owning epic: E06.

``detect_language`` is a pure function of ``(path, head)``: it opens nothing, never raises and
gives the same answer for the same input. It resolves in a fixed order and stops at the first step
that decides:

1. exact file name (``Dockerfile``, ``Gemfile``, ``.gitlab-ci.yml``), then the ``Dockerfile.``
   prefix rule (``Dockerfile.prod``);
2. extension, with the ambiguous ones (``.h``, ``.ts``) settled by :func:`disambiguate`;
3. interpreter named by a ``#!`` line;
4. editor modeline (``-*- mode: python -*-``, ``# vim: set ft=ruby``);
5. content heuristic, limited to a ``<?php`` prefix and an XML declaration or DOCTYPE;
6. ``Language.UNKNOWN``.

The extension therefore wins over a shebang (a ``.py`` file with a bash shebang is Python), and a
file with no extension is classified by its shebang. Prefer ``UNKNOWN`` to a guess: an unknown
file is never parsed, sliced or sent, and shows up honestly in the coverage table, whereas a wrong
guess sends a file to the wrong grammar.

The tables are transcribed by hand from the extension-to-language convention of GitHub Linguist
(``lib/linguist/languages.yml`` at release v9.7.0, recorded in RESOURCE.md; every entry was
checked against that file), keeping only entries CodeKavach can act on. Linguist is not a
dependency: its data file is MIT-licensed, its Ruby runtime is irrelevant here, and a vendored
table is auditable, offline and unaffected by a grammar-version bump.
A name Linguist knows but ``Language`` has no member for (Markdown, Perl, Objective-C, MATLAB,
Makefile, plain text) resolves to ``UNKNOWN`` and is listed in ``UNANALYSED_EXTENSIONS`` or mapped
to ``UNKNOWN`` in ``FILENAME_MAP``, so the coverage appendix can say "recognised, not analysed".
"""

import codecs
import re
from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import Final

from codekavach.core.models import Language, RepoPath

# Only the start of a file is looked at; ``discover`` passes the same bytes it used to detect
# binary content, so no file is opened twice.
HEAD_LIMIT: Final = 8192
_BOM: Final = b"\xef\xbb\xbf"

C = Language.C
CPP = Language.CPP
JS = Language.JAVASCRIPT
TS = Language.TYPESCRIPT


def _table(entries: Mapping[str, Language]) -> Mapping[str, Language]:
    return MappingProxyType(dict(entries))


EXTENSION_MAP: Final[Mapping[str, Language]] = _table(
    {
        ".py": Language.PYTHON,
        ".pyi": Language.PYTHON,  # type stub
        ".pyw": Language.PYTHON,
        ".js": JS,  # includes Flow-annotated files (``// @flow``): Flow is JavaScript
        ".jsx": JS,
        ".mjs": JS,
        ".cjs": JS,
        ".ts": TS,  # see disambiguate: an MPEG transport stream also uses .ts
        ".tsx": TS,
        ".mts": TS,
        ".cts": TS,
        ".java": Language.JAVA,
        ".kt": Language.KOTLIN,
        ".kts": Language.KOTLIN,
        ".c": C,
        ".h": C,  # see disambiguate: C or C++
        ".cc": CPP,
        ".cpp": CPP,
        ".cxx": CPP,
        ".c++": CPP,
        ".hpp": CPP,
        ".hh": CPP,
        ".hxx": CPP,
        ".h++": CPP,
        ".php": Language.PHP,
        ".phtml": Language.PHP,
        ".php5": Language.PHP,
        ".go": Language.GO,
        ".cs": Language.CSHARP,
        ".rb": Language.RUBY,
        ".rake": Language.RUBY,
        ".gemspec": Language.RUBY,
        ".ru": Language.RUBY,
        ".sh": Language.SHELL,
        ".bash": Language.SHELL,
        ".zsh": Language.SHELL,
        ".ksh": Language.SHELL,
        ".dockerfile": Language.DOCKERFILE,
        ".tf": Language.TERRAFORM,
        ".tfvars": Language.TERRAFORM,
        ".yml": Language.YAML,
        ".yaml": Language.YAML,
        ".json": Language.JSON,
        ".jsonc": Language.JSON,
        ".toml": Language.TOML,
        ".xml": Language.XML,
        ".xsd": Language.XML,
        ".xsl": Language.XML,
        ".svg": Language.XML,
        ".csproj": Language.XML,
        ".sql": Language.SQL,  # every dialect is one language for scanning purposes
        ".html": Language.HTML,
        ".htm": Language.HTML,
    }
)

# Names Linguist knows for which ``Language`` has no member. Resolving them to ``UNKNOWN`` at the
# extension step keeps the content heuristics from guessing at a README or a MATLAB script.
UNANALYSED_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".md",
        ".markdown",
        ".mdx",
        ".rst",
        ".txt",
        ".pl",  # Perl or Prolog; neither is a target language
        ".pm",
        ".m",  # Objective-C or MATLAB; neither is a target language, so never guessed
        ".mm",
        ".mk",
        ".csv",
        ".ini",
        ".cfg",
    }
)

FILENAME_MAP: Final[Mapping[str, Language]] = _table(
    {
        "Dockerfile": Language.DOCKERFILE,
        "Containerfile": Language.DOCKERFILE,
        "Gemfile": Language.RUBY,
        "Rakefile": Language.RUBY,
        "Vagrantfile": Language.RUBY,
        "Podfile": Language.RUBY,
        "Brewfile": Language.RUBY,
        "Pipfile": Language.TOML,
        ".gitlab-ci.yml": Language.YAML,
        ".bashrc": Language.SHELL,
        ".bash_profile": Language.SHELL,
        ".zshrc": Language.SHELL,
        ".profile": Language.SHELL,
        # Recognised, but there is no Language member for make: ``UNKNOWN`` stops the resolution
        # so the file is not handed to a content heuristic.
        "Makefile": Language.UNKNOWN,
        "makefile": Language.UNKNOWN,
        "GNUmakefile": Language.UNKNOWN,
    }
)
DOCKERFILE_PREFIX: Final = "Dockerfile."

# Interpreter name (version suffix removed) from a ``#!`` line.
SHEBANG_MAP: Final[Mapping[str, Language]] = _table(
    {
        "python": Language.PYTHON,
        "pypy": Language.PYTHON,
        "node": JS,
        "nodejs": JS,
        "ts-node": TS,
        "tsx": TS,
        "bash": Language.SHELL,
        "sh": Language.SHELL,
        "dash": Language.SHELL,
        "zsh": Language.SHELL,
        "ksh": Language.SHELL,
        "ash": Language.SHELL,
        "ruby": Language.RUBY,
        "php": Language.PHP,
    }
)

# Names used in ``-*- mode: NAME -*-`` and ``vim: ft=NAME``, lower-cased.
MODELINE_MAP: Final[Mapping[str, Language]] = _table(
    {
        "python": Language.PYTHON,
        "javascript": JS,
        "js": JS,
        "typescript": TS,
        "ts": TS,
        "java": Language.JAVA,
        "kotlin": Language.KOTLIN,
        "c": C,
        "c++": CPP,
        "cpp": CPP,
        "php": Language.PHP,
        "go": Language.GO,
        "csharp": Language.CSHARP,
        "ruby": Language.RUBY,
        "sh": Language.SHELL,
        "bash": Language.SHELL,
        "shell": Language.SHELL,
        "zsh": Language.SHELL,
        "dockerfile": Language.DOCKERFILE,
        "terraform": Language.TERRAFORM,
        "yaml": Language.YAML,
        "json": Language.JSON,
        "toml": Language.TOML,
        "xml": Language.XML,
        "sql": Language.SQL,
        "html": Language.HTML,
    }
)

# Extensions two languages share, with the candidates :func:`disambiguate` may choose between.
AMBIGUOUS_EXTENSIONS: Final[Mapping[str, tuple[Language, ...]]] = MappingProxyType(
    {".h": (C, CPP), ".ts": (TS, Language.XML)}
)

_SHEBANG = re.compile(rb"#![ \t]*(\S+)(?:[ \t]+(.*))?")
_VERSION_SUFFIX = re.compile(r"[0-9][0-9.]*$")
_ENV_FLAG = re.compile(r"^(-\S*|\w+=\S*)$")
_EMACS_MODE = re.compile(r"-\*-.*?\bmode:\s*([A-Za-z0-9_+#.-]+)", re.IGNORECASE)
_EMACS_BARE = re.compile(r"-\*-\s*([A-Za-z0-9_+#.-]+)\s*-\*-")
_VIM_FILETYPE = re.compile(r"\b(?:vim?|ex):.*?\b(?:ft|filetype)=([A-Za-z0-9_+#.-]+)", re.IGNORECASE)
_CPP_MARKERS = re.compile(r"\b(?:class|namespace|template)\b|\bstd::")
_C_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
_MODELINE_LINES = 5


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _extension(name: str) -> str:
    dot = name.rfind(".")
    return name[dot:].lower() if dot > 0 else ""


def _text(head: bytes) -> str:
    return head.decode("utf-8", errors="replace")


def _is_text(head: bytes) -> bool:
    """True when ``head`` is NUL-free text that decodes as UTF-8 (a cut final character is fine)."""
    if b"\x00" in head:
        return False
    try:
        codecs.getincrementaldecoder("utf-8")().decode(head, final=False)
    except UnicodeDecodeError:
        return False
    return True


def disambiguate(path: RepoPath, head: bytes, candidates: Sequence[Language]) -> Language:
    """Choose among ``candidates`` for a path whose extension is ambiguous.

    * ``.h`` is C++ when the code (comments removed) contains ``class``, ``namespace``,
      ``template`` or ``std::``, otherwise C.
    * ``.ts`` is TypeScript when the head is text. An MPEG transport stream has the same extension
      and is binary, so it is ``UNKNOWN``; a Qt translation file is text that opens with an XML
      declaration or DOCTYPE, so it is XML.
    * Any other extension, or a choice that is not among ``candidates``, is ``UNKNOWN``.
    """
    head = head[:HEAD_LIMIT]
    extension = _extension(_basename(path))
    chosen = Language.UNKNOWN
    if extension == ".h":
        code = _C_COMMENT.sub(" ", _text(head))
        chosen = CPP if _CPP_MARKERS.search(code) else C
    elif extension == ".ts" and _is_text(head):
        chosen = Language.XML if _by_content(head) is Language.XML else TS
    return chosen if chosen in candidates else Language.UNKNOWN


def _by_filename(name: str) -> Language | None:
    if name in FILENAME_MAP:
        return FILENAME_MAP[name]
    if name.startswith(DOCKERFILE_PREFIX) and len(name) > len(DOCKERFILE_PREFIX):
        return Language.DOCKERFILE
    return None


def _by_extension(path: str, name: str, head: bytes) -> Language | None:
    extension = _extension(name)
    if extension in UNANALYSED_EXTENSIONS:
        return Language.UNKNOWN
    language = EXTENSION_MAP.get(extension)
    if language is None:
        return None
    if extension in AMBIGUOUS_EXTENSIONS:
        return disambiguate(path, head, AMBIGUOUS_EXTENSIONS[extension])
    return language


def _interpreter(line: bytes) -> str | None:
    match = _SHEBANG.match(line)
    if match is None:
        return None
    program = match.group(1).decode("utf-8", errors="replace").rsplit("/", 1)[-1]
    if program == "env":
        arguments = (match.group(2) or b"").decode("utf-8", errors="replace").split()
        words = [word for word in arguments if not _ENV_FLAG.match(word)]
        if not words:
            return None
        program = words[0].rsplit("/", 1)[-1]
    name = _VERSION_SUFFIX.sub("", program).rstrip("-_.")
    return name or None


def _by_shebang(head: bytes) -> Language | None:
    first = head.split(b"\n", 1)[0].rstrip(b"\r")
    if not first.startswith(b"#!"):
        return None
    interpreter = _interpreter(first)
    return SHEBANG_MAP.get(interpreter) if interpreter is not None else None


def _by_modeline(head: bytes) -> Language | None:
    lines = _text(head).splitlines()
    for line in lines[:_MODELINE_LINES]:
        for pattern in (_EMACS_MODE, _EMACS_BARE, _VIM_FILETYPE):
            match = pattern.search(line)
            if match is not None:
                language = MODELINE_MAP.get(match.group(1).lower())
                if language is not None:
                    return language
    return None


def _by_content(head: bytes) -> Language | None:
    start = head.lstrip()[:64].lower()
    if start.startswith(b"<?php"):
        return Language.PHP
    if start.startswith(b"<?xml"):
        return Language.XML
    if start.startswith(b"<!doctype"):
        return Language.HTML if start[9:].lstrip().startswith(b"html") else Language.XML
    return None


def detect_language(path: RepoPath, head: bytes) -> Language:
    """Classify a file from its path and the first bytes of its content.

    A pure function of its arguments that never raises; see the module docstring for the order.
    """
    try:
        head = head[:HEAD_LIMIT]
        if head.startswith(_BOM):
            head = head[len(_BOM) :]
        name = _basename(path)
        steps: tuple[Callable[[], Language | None], ...] = (
            lambda: _by_filename(name),
            lambda: _by_extension(path, name, head),
            lambda: _by_shebang(head),
            lambda: _by_modeline(head),
            lambda: _by_content(head),
        )
        for step in steps:
            resolved = step()
            if resolved is not None:
                return resolved
    except Exception:  # noqa: BLE001 - a pure classifier degrades to UNKNOWN, it never aborts a scan
        return Language.UNKNOWN
    return Language.UNKNOWN
