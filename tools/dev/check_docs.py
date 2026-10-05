"""Check the tracked Markdown files offline: links, anchors, banned phrases, emoji (E01-23).

Usage::

    python tools/dev/check_docs.py [--format text|json] [PATH ...]
    python tools/dev/check_docs.py --claims PATH [PATH ...]

Without paths every file of ``git ls-files "*.md"`` is checked, minus the ``exclude`` patterns of
``[tool.codekavach.docs]`` in ``pyproject.toml``. Nothing is fetched: targets with a URL scheme
are skipped.

==========  ====================================================================================
``DOC001``  A relative link target does not exist.
``DOC002``  The anchor of a link matches no heading of the target file.
``DOC003``  An entry of the ``pending`` list exists on disk: remove it from the list.
``DOC004``  A banned attribution phrase occurs (the patterns of ``check_commit_msg.py``).
``DOC005``  An emoji code point occurs.
``DOC006``  A link uses an absolute path of a local machine or the ``file:`` scheme.
``DOC000``  Informational: a link to a document on the ``pending`` list, which is not written yet.
==========  ====================================================================================

``--claims`` is a reading aid for the pre-push review of ``AGENTS.md`` section 9: it prints the
lines outside code blocks that contain one of the listed words and always exits 0.
"""

import argparse
import fnmatch
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tomllib
import unicodedata
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final
from urllib.parse import unquote

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
INFORMATIONAL: Final = "DOC000"
CLAIM_WORDS: Final = ("never", "guarantee", "ensures", "impossible", "100%", "best")

FENCE: Final = re.compile(r"^ {0,3}(`{3,}|~{3,})")
INLINE_CODE: Final = re.compile(r"(`+)(.+?)\1")
# The destination is either in angle brackets (it may then contain parentheses) or bare.
INLINE_LINK: Final = re.compile(r"\[[^\]]*\]\((?:<([^>]*)>|([^)\s]+))(?:\s+\"[^\"]*\")?\)")
REFERENCE_DEFINITION: Final = re.compile(r"^\[[^\]]+\]:\s*<?([^\s>]+)>?")
HEADING: Final = re.compile(r"^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
SCHEME: Final = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
LOCAL_ABSOLUTE: Final = re.compile(r"^(/Users/|/home/|[A-Za-z]:[\\/]|file:)", re.IGNORECASE)
CLAIM: Final = re.compile(
    r"(?<!\w)(" + "|".join(re.escape(word) for word in CLAIM_WORDS) + r")(?!\w)", re.IGNORECASE
)


def _commit_patterns() -> Any:
    """The attribution and emoji patterns of ``check_commit_msg.py``, loaded from its file."""
    name = "check_commit_msg"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(f"{name}.py"))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True, order=True)
class Problem:
    """One finding: where it is, its code and what is wrong."""

    path: str
    line: int
    code: str
    message: str

    @property
    def is_failure(self) -> bool:
        """Whether the finding fails the check (everything but the informational code)."""
        return self.code != INFORMATIONAL

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.code} {self.message}"


def mask_code(text: str) -> list[str]:
    """The lines of ``text`` with fenced blocks emptied and inline code spans blanked."""
    lines = []
    fence: str | None = None
    for line in text.splitlines():
        opened = FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            lines.append("")
        elif opened:
            fence = opened.group(1)
            lines.append("")
        else:
            lines.append(INLINE_CODE.sub(lambda match: " " * len(match.group(0)), line))
    return lines


def slugify(heading: str) -> str:
    """The anchor GitHub gives a heading text, before duplicates are numbered."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = text.replace("`", "").strip().lower()
    # Letters, combining marks (vowel signs of Indic scripts) and digits stay; punctuation goes.
    kept = "".join(char for char in text if unicodedata.category(char)[0] in "LMN" or char in " -_")
    return kept.replace(" ", "-")


def heading_slugs(text: str) -> set[str]:
    """The anchors of every heading of a Markdown text, duplicates numbered ``-1``, ``-2``."""
    slugs: set[str] = set()
    seen: dict[str, int] = {}
    fence: str | None = None
    for line in text.splitlines():
        opened = FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            continue
        if opened:
            fence = opened.group(1)
            continue
        heading = HEADING.match(line)
        if heading is None:
            continue
        slug = slugify(heading.group(2))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        slugs.add(slug if count == 0 else f"{slug}-{count}")
    return slugs


def _relative(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _link_problem(
    target: str, source: Path, repo_root: Path, pending: frozenset[str]
) -> tuple[str, str] | None:
    """``(code, message)`` for one link target, or ``None`` when it is fine or not checked."""
    if LOCAL_ABSOLUTE.match(target):
        return "DOC006", f"link to a local absolute path or file: URL: {target}"
    path_part, _, anchor = target.partition("#")
    destination = None if SCHEME.match(target) else _destination(path_part, source, repo_root)
    if destination is None:
        return None
    relative = destination.relative_to(repo_root.resolve()).as_posix()
    found: tuple[str, str] | None = None
    if not destination.exists():
        if relative in pending:
            found = INFORMATIONAL, f"link to a document that is not written yet: {relative}"
        else:
            found = "DOC001", f"link target does not exist: {target}"
    elif anchor and destination.is_file() and destination.suffix.lower() == ".md":
        slugs = heading_slugs(destination.read_text(encoding="utf-8"))
        if unquote(anchor) not in slugs:
            found = "DOC002", f"no heading with the anchor '#{anchor}' in {relative}"
    return found


def _destination(path_part: str, source: Path, repo_root: Path) -> Path | None:
    """The file a link path points to; ``None`` when it leaves the repository.

    GitHub web-relative links such as ``../../issues`` leave the root and are not checked.
    """
    path_part = unquote(path_part)
    if not path_part:
        destination = source
    elif path_part.startswith("/"):
        destination = repo_root / path_part.lstrip("/")
    else:
        destination = source.parent / path_part
    destination = destination.resolve()
    root = repo_root.resolve()
    return destination if destination == root or root in destination.parents else None


def check_file(path: Path, repo_root: Path, pending: frozenset[str]) -> list[Problem]:
    """The problems of one Markdown file."""
    patterns = _commit_patterns()
    name = _relative(path, repo_root)
    text = path.read_text(encoding="utf-8")
    problems = []
    for number, line in enumerate(text.splitlines(), start=1):
        if (
            patterns.CO_AUTHOR.match(line)
            or patterns.TOOL_CREDIT.match(line)
            or patterns.ROBOT in line
        ):
            problems.append(Problem(name, number, "DOC004", "attribution to a tool or co-author"))
        emoji = patterns.EMOJI.search(line)
        if emoji:
            problems.append(
                Problem(name, number, "DOC005", f"emoji code point U+{ord(emoji.group(0)):04X}")
            )
    for number, line in enumerate(mask_code(text), start=1):
        targets = [bracketed or bare for bracketed, bare in INLINE_LINK.findall(line)]
        definition = REFERENCE_DEFINITION.match(line)
        if definition:
            targets.append(definition.group(1))
        for target in targets:
            found = _link_problem(target, path, repo_root, pending)
            if found is not None:
                problems.append(Problem(name, number, found[0], found[1]))
    return problems


def stale_pending(repo_root: Path, pending: frozenset[str]) -> list[Problem]:
    """``DOC003`` for every pending entry that exists by now."""
    return [
        Problem("pyproject.toml", 0, "DOC003", f"pending entry exists on disk, remove it: {entry}")
        for entry in sorted(pending)
        if (repo_root / entry).exists()
    ]


def load_config(repo_root: Path) -> tuple[frozenset[str], tuple[str, ...]]:
    """``(pending, exclude)`` from ``[tool.codekavach.docs]``; empty when the table is absent."""
    try:
        config = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return frozenset(), ()
    table = config.get("tool", {}).get("codekavach", {}).get("docs", {})
    return frozenset(table.get("pending", [])), tuple(table.get("exclude", []))


def tracked_markdown(repo_root: Path) -> list[Path]:
    """The Markdown files Git tracks; every ``*.md`` below the root when this is no work tree."""
    git = shutil.which("git")
    if git is not None:
        listed = subprocess.run(
            [git, "ls-files", "*.md"],
            cwd=repo_root, capture_output=True, text=True, encoding="utf-8", check=False,
        )  # fmt: skip
        if listed.returncode == 0:
            return [repo_root / line for line in listed.stdout.splitlines() if line]
    return sorted(repo_root.rglob("*.md"))


def claim_lines(path: Path, repo_root: Path) -> list[str]:
    """``path:line: CLAIM <text>`` for each line outside code that has a claim word."""
    name = _relative(path, repo_root)
    original = path.read_text(encoding="utf-8").splitlines()
    return [
        f"{name}:{number}: CLAIM {original[number - 1].strip()}"
        for number, line in enumerate(mask_code("\n".join(original)), start=1)
        if CLAIM.search(line)
    ]


def main(argv: Sequence[str] | None = None, *, repo_root: Path = REPO_ROOT) -> int:
    """Run the checker; 0 clean (or ``--claims``), 1 when a problem fails the check."""
    parser = argparse.ArgumentParser(
        prog="check_docs.py", description="Check Markdown files offline: links, anchors, style."
    )
    parser.add_argument("paths", nargs="*", type=Path, help="files to check (default: all tracked)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--claims", action="store_true", help="list lines with claim words; exit 0")
    arguments = parser.parse_args(argv)
    pending, exclude = load_config(repo_root)
    files = [path.resolve() for path in arguments.paths] or tracked_markdown(repo_root)
    files = [
        path
        for path in files
        if path.suffix.lower() == ".md"
        and path.is_file()
        and not any(fnmatch.fnmatch(_relative(path, repo_root), pattern) for pattern in exclude)
    ]
    if arguments.claims:
        for path in files:
            for line in claim_lines(path, repo_root):
                print(line)
        return 0
    problems = stale_pending(repo_root, pending)
    for path in files:
        problems.extend(check_file(path, repo_root, pending))
    problems.sort()
    if arguments.format == "json":
        print(json.dumps([asdict(problem) for problem in problems], indent=2))
    else:
        for problem in problems:
            print(problem)
    return 1 if any(problem.is_failure for problem in problems) else 0


if __name__ == "__main__":
    raise SystemExit(main())
