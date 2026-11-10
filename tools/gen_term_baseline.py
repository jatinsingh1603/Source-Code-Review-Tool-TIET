"""Generate ``src/codekavach/privacy/detect/data/term_baseline.tsv`` (E08-04).

Usage: ``uv run python tools/gen_term_baseline.py [--source DIR] [--out PATH] [--min-count N]``.

The table gives, for each sub-word of an identifier, its share of all sub-words in general code.
The domain-term miner compares a repository's rate with it (``mine_domain_terms``). The default
source is the standard library of the Python that runs this script (CPython, PSF-2.0, a
permissive licence); only identifiers are read (names, attributes, arguments, imports), never
comments or strings, and no source text is copied into the table, only counts of lower-case
words of at least four letters that occur at least ``--min-count`` times.

Limits worth knowing: the source is Python only, so a word that is common in Java or Go code but
not in Python's standard library scores higher than it deserves. The miner's output is a
suggestion that a person reviews, which is why this is acceptable. A broader corpus is a follow-up.

The output is deterministic apart from the ``generated`` date, which can be fixed with
``--date``. This is development tooling and is not shipped in the package.
"""

import argparse
import ast
import sys
import sysconfig
from collections import Counter
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from codekavach.parsing.subtokens import split_subtokens  # noqa: E402 - src must be importable

DEFAULT_OUT = ROOT / "src" / "codekavach" / "privacy" / "detect" / "data" / "term_baseline.tsv"
SKIPPED_DIRS = frozenset({"test", "tests", "idlelib", "lib2to3", "site-packages", "__pycache__"})
MIN_TERM_LENGTH = 4
MIN_WORD_LENGTH = 2


def identifiers(tree: ast.AST) -> Iterator[str]:
    """Every name a module defines or uses, once per occurrence."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.Attribute):
            yield node.attr
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            yield node.name
        elif isinstance(node, ast.arg | ast.keyword):
            if node.arg:
                yield node.arg
        elif isinstance(node, ast.alias):
            yield node.asname or node.name.split(".")[-1]
        elif isinstance(node, ast.Global | ast.Nonlocal):
            yield from node.names


def source_files(root: Path) -> Iterator[Path]:
    """The ``.py`` files under ``root``, in sorted order, skipping tests and vendored trees."""
    for path in sorted(root.rglob("*.py")):
        if not SKIPPED_DIRS & set(path.relative_to(root).parts):
            yield path


def count_words(root: Path) -> tuple[Counter[str], int, int]:
    """``(counts of eligible words, total alphabetic words, files read)``."""
    counts: Counter[str] = Counter()
    total = files = 0
    for path in source_files(root):
        try:
            tree = ast.parse(path.read_bytes())
        except (SyntaxError, ValueError, OSError):
            continue
        files += 1
        for name in identifiers(tree):
            for piece in split_subtokens(name):
                word = piece.lower()
                if len(word) >= MIN_WORD_LENGTH and word.isalpha() and word.isascii():
                    total += 1
                    if len(word) >= MIN_TERM_LENGTH:
                        counts[word] += 1
    return counts, total, files


def render(counts: Counter[str], total: int, files: int, *, min_count: int, date: str) -> str:
    """The table text: a header of ``# key: value`` lines, then sorted ``word<TAB>rate`` lines."""
    kept = {word: n for word, n in counts.items() if n >= min_count}
    version = ".".join(str(part) for part in sys.version_info[:3])
    header = [
        "# Sub-word rates in general code: the baseline of the domain-term miner (E08-04).",
        "# source: CPython standard library, version " + version + " (PSF-2.0), identifiers only",
        f"# files: {files}",
        f"# total_words: {total}",
        f"# min_count: {min_count}",
        f"# floor_rate: {1 / (2 * total):.3e}",
        f"# generated: {date}",
        "# generator: tools/gen_term_baseline.py; a rate is occurrences divided by total_words.",
        "# licence: the table holds counts of words, not source text; the source licence is above.",
    ]
    rows = [f"{word}\t{kept[word] / total:.4e}" for word in sorted(kept)]
    return "\n".join([*header, *rows]) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """Read the source tree and write the table."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--source", type=Path, default=Path(sysconfig.get_paths()["stdlib"]))
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--min-count", type=int, default=5)
    parser.add_argument("--date", default=datetime.now(UTC).date().isoformat())
    args = parser.parse_args(argv)
    counts, total, files = count_words(args.source)
    if not total:
        print(f"no Python source found under {args.source}", file=sys.stderr)
        return 2
    text = render(counts, total, files, min_count=args.min_count, date=args.date)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(text.encode("utf-8"))
    print(f"{len(text.splitlines())} lines from {files} files, {total} words")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
