"""Gitignore-semantics exclusion for repository discovery (E06-01).

Owning epic: E06.

Implements the ordered-rule model git itself uses: later patterns win, ``!`` re-includes, a
pattern with no ``/`` matches at any depth, a leading ``/`` anchors to the directory holding the
``.gitignore``, a trailing ``/`` matches directories only, and ``**`` matches zero or more path
segments. A nested ``.gitignore`` applies only to paths under its own directory; a root-level
rule still applies everywhere below the root. ``.codekavachignore`` uses the identical grammar,
is read once from the repository root regardless of ``ingest.respect_gitignore``, and is applied
after the gitignore rules so a client can exclude a tracked path from review.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from codekavach.config.models.ingest import IngestSettings

CODEKAVACH_IGNORE_FILE = ".codekavachignore"
GITIGNORE_FILE = ".gitignore"


@dataclass(frozen=True, slots=True)
class _Rule:
    """One parsed gitignore-grammar line, scoped to the directory that declared it."""

    source_dir: str  # "" for the root; otherwise a POSIX path relative to the root
    pattern: re.Pattern[str]
    negated: bool
    dir_only: bool
    anchored: bool


def _translate(glob: str) -> str:
    """Translate one gitignore glob segment-sequence into a regex body (no anchors)."""
    out: list[str] = []
    i = 0
    length = len(glob)
    while i < length:
        char = glob[i]
        if char == "*":
            if glob[i : i + 2] == "**":
                # "**/" or "/**" or a bare "**": zero or more path segments.
                if glob[i : i + 3] == "**/":
                    out.append("(?:.*/)?")
                    i += 3
                    continue
                if glob[i - 1 : i] == "/" and glob[i : i + 2] == "**" and i + 2 == length:
                    out.append(".*")
                    i += 2
                    continue
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
        elif char == "?":
            out.append("[^/]")
            i += 1
        elif char == "[":
            end = glob.find("]", i + 1)
            if end == -1:
                out.append(re.escape(char))
                i += 1
            else:
                out.append(glob[i : end + 1])
                i = end + 1
        else:
            out.append(re.escape(char))
            i += 1
    return "".join(out)


def _compile_pattern(pattern: str, *, anchored: bool) -> re.Pattern[str]:
    body = _translate(pattern)
    if anchored:
        return re.compile(f"^{body}$")
    # Unanchored: the pattern may match starting at any path segment boundary.
    return re.compile(f"(^|.*/){body}$")


def _parse_line(source_dir: str, line: str) -> _Rule | None:
    raw = line.rstrip("\n")
    if not raw or raw.startswith("#"):
        return None
    negated = raw.startswith("!")
    if negated:
        raw = raw[1:]
    # An unescaped trailing space is trimmed by git; a literal trailing space is "\ " (not
    # handled here, an accepted simplification for this issue's scope).
    raw = raw.rstrip()
    if not raw:
        return None
    dir_only = raw.endswith("/") and not raw.endswith("\\/")
    if dir_only:
        raw = raw[:-1]
    anchored = raw.startswith("/")
    if anchored:
        raw = raw[1:]
    elif "/" in raw:
        # A pattern containing a "/" (other than a single leading one) is anchored to its
        # gitignore's directory in git's own semantics.
        anchored = True
    pattern = _compile_pattern(raw, anchored=anchored)
    return _Rule(
        source_dir=source_dir,
        pattern=pattern,
        negated=negated,
        dir_only=dir_only,
        anchored=anchored,
    )


def _read_ignore_file(path: Path, source_dir: str) -> list[_Rule]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rules = []
    for line in text.split("\n"):
        rule = _parse_line(source_dir, line)
        if rule is not None:
            rules.append(rule)
    return rules


class IgnoreSet:
    """Every exclusion rule collected for one discovery run, ready to match candidate paths."""

    def __init__(self, rules: list[_Rule], excludes: tuple[re.Pattern[str], ...]) -> None:
        self._rules = rules
        self._excludes = excludes

    @classmethod
    def from_root(cls, root: Path, settings: IngestSettings) -> "IgnoreSet":
        """Collect gitignore rules (if enabled), ``.codekavachignore`` and ``ingest.excludes``."""
        rules: list[_Rule] = []
        if settings.respect_gitignore:
            for directory in sorted(
                {p.parent for p in root.rglob(GITIGNORE_FILE)} | {root}, key=lambda p: len(p.parts)
            ):
                candidate = directory / GITIGNORE_FILE
                if candidate.is_file():
                    source_dir = directory.relative_to(root).as_posix()
                    rules.extend(
                        _read_ignore_file(candidate, "" if source_dir == "." else source_dir)
                    )
        codekavach_ignore = root / CODEKAVACH_IGNORE_FILE
        if codekavach_ignore.is_file():
            rules.extend(_read_ignore_file(codekavach_ignore, ""))
        excludes = tuple(
            _compile_pattern(pattern, anchored="/" in pattern) for pattern in settings.excludes
        )
        return cls(rules, excludes)

    def matches(self, rel_path: str, *, is_dir: bool) -> bool:
        """True when ``rel_path`` (POSIX, relative to the root) is excluded."""
        for pattern in self._excludes:
            if pattern.match(rel_path):
                return True
        ignored = False
        for rule in self._rules:
            if rule.dir_only and not is_dir:
                continue
            scoped = rel_path
            if rule.source_dir:
                prefix = rule.source_dir + "/"
                if not rel_path.startswith(prefix):
                    continue
                scoped = rel_path[len(prefix) :]
            if rule.pattern.match(scoped):
                ignored = not rule.negated
        return ignored
