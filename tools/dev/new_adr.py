"""Create the next architecture decision record and check the ADR index.

Usage:
    python tools/dev/new_adr.py "Title of decision"
    python tools/dev/new_adr.py --check

Standard library only. See docs/adr/README.md for the lifecycle and numbering rules.
"""

import argparse
import re
import sys
import unicodedata
from dataclasses import dataclass
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ADR_DIR = REPO_ROOT / "docs" / "adr"
TEMPLATE_NAME = "0000-template.md"
INDEX_NAME = "README.md"
MAX_SLUG_LENGTH = 60

_RECORD_FILE = re.compile(r"^(\d{4})-[a-z0-9-]+\.md$")
_ROW = re.compile(r"^\|\s*(?:\[(\d{4})\]\([^)]*\)|(\d{4}))\s*\|(.*)\|\s*$")
_TITLE_LINE = re.compile(r"^# ADR-(\d{4}): (.+)$")
_STATUS_LINE = re.compile(r"^\|\s*Status\s*\|\s*(.*?)\s*\|\s*$")


class AdrError(Exception):
    """Raised when a record cannot be created."""


@dataclass
class IndexRow:
    """One row of the ADR index table."""

    number: int
    title: str
    status: str
    line_no: int


def slugify(title: str) -> str:
    """Return the file-name slug for a title: ASCII, lower-case, hyphenated, at most 60 chars."""
    ascii_title = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode("ascii")
    words = re.findall(r"[a-z0-9]+", ascii_title.lower())
    slug = ""
    for word in words:
        candidate = f"{slug}-{word}" if slug else word
        if len(candidate) > MAX_SLUG_LENGTH:
            if not slug:
                slug = word[:MAX_SLUG_LENGTH]
            break
        slug = candidate
    return slug


def parse_index(index_path: Path) -> list[IndexRow]:
    """Return the rows of the index table in file order."""
    rows: list[IndexRow] = []
    for line_no, line in enumerate(index_path.read_text(encoding="utf-8").splitlines()):
        match = _ROW.match(line)
        if not match:
            continue
        number = int(match.group(1) or match.group(2))
        cells = [cell.strip() for cell in match.group(3).split("|")]
        title = re.sub(r"^\[(.*)\]\([^)]*\)$", r"\1", cells[0])
        status = cells[1] if len(cells) > 1 else ""
        rows.append(IndexRow(number, title, status, line_no))
    return rows


def record_files(adr_dir: Path) -> dict[int, list[Path]]:
    """Return record files by number, excluding the template."""
    files: dict[int, list[Path]] = {}
    for path in sorted(adr_dir.glob("*.md")):
        match = _RECORD_FILE.match(path.name)
        if match and path.name != TEMPLATE_NAME:
            files.setdefault(int(match.group(1)), []).append(path)
    return files


def next_number(adr_dir: Path) -> int:
    """Return the next free number, counting existing files and every index row."""
    used = set(record_files(adr_dir))
    index_path = adr_dir / INDEX_NAME
    if index_path.exists():
        used.update(row.number for row in parse_index(index_path))
    return max(used, default=0) + 1


def _read_record(path: Path) -> tuple[str | None, str | None]:
    title = status = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if title is None and (m := _TITLE_LINE.match(line)):
            title = m.group(2).strip()
        elif status is None and (m := _STATUS_LINE.match(line)):
            status = m.group(1)
    return title, status


def create_adr(title: str, adr_dir: Path, today: date) -> Path:
    """Create the next record from the template, register it in the index and return its path.

    A title matching a Reserved row (case-insensitive) takes that row's number, and the row
    changes to Proposed. Raises AdrError if the target file already exists.
    """
    title = " ".join(title.split())
    slug = slugify(title)
    if not slug:
        raise AdrError(f"title {title!r} has no ASCII letters or digits to build a file name")
    index_path = adr_dir / INDEX_NAME
    lines = index_path.read_text(encoding="utf-8").splitlines()
    rows = parse_index(index_path)
    reserved = next(
        (r for r in rows if r.status == "Reserved" and r.title.casefold() == title.casefold()),
        None,
    )
    for existing in (p for paths in record_files(adr_dir).values() for p in paths):
        if existing.name[5:] == f"{slug}.md":
            raise AdrError(f"{existing.name} already exists; refusing to overwrite it")
    number = reserved.number if reserved else next_number(adr_dir)
    path = adr_dir / f"{number:04d}-{slug}.md"
    if path.exists() or number in record_files(adr_dir):
        raise AdrError(f"{path.name} already exists; refusing to overwrite it")

    body = (adr_dir / TEMPLATE_NAME).read_text(encoding="utf-8")
    body = body.replace("ADR-NNNN: <short noun phrase>", f"ADR-{number:04d}: {title}", 1)
    body = re.sub(r"^\| Status \|.*$", "| Status | Proposed |", body, count=1, flags=re.M)
    body = body.replace("YYYY-MM-DD", today.isoformat(), 1)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(body)

    link = f"[{number:04d}]({path.name})"
    if reserved:
        cells = lines[reserved.line_no].strip().strip("|").split("|")
        issue = cells[5].strip() if len(cells) > 5 else ""
        lines[reserved.line_no] = (
            f"| {link} | {title} | Proposed | {today.isoformat()} | | {issue} |"
        )
    else:
        last_row = max((r.line_no for r in rows), default=len(lines) - 1)
        lines.insert(last_row + 1, f"| {link} | {title} | Proposed | {today.isoformat()} | | |")
    index_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return path


def check_index(adr_dir: Path) -> list[str]:
    """Return one message per inconsistency between the index and the record files."""
    problems: list[str] = []
    rows = parse_index(adr_dir / INDEX_NAME)
    files = record_files(adr_dir)
    by_number: dict[int, list[IndexRow]] = {}
    for row in rows:
        by_number.setdefault(row.number, []).append(row)

    for number, same in sorted(by_number.items()):
        if len(same) > 1:
            problems.append(f"ADR-{number:04d}: number appears in {len(same)} index rows")
    for number, paths in sorted(files.items()):
        if len(paths) > 1:
            names = ", ".join(p.name for p in paths)
            problems.append(f"ADR-{number:04d}: several files share the number: {names}")
        path = paths[0]
        if number not in by_number:
            problems.append(f"{path.name}: no index row")
            continue
        row = by_number[number][0]
        title, status = _read_record(path)
        if title != row.title:
            problems.append(f"{path.name}: title {title!r} differs from index title {row.title!r}")
        if status != row.status:
            problems.append(
                f"{path.name}: status {status!r} differs from index status {row.status!r}"
            )
    for number, same in sorted(by_number.items()):
        row = same[0]
        if row.status != "Reserved" and number not in files:
            problems.append(f"ADR-{number:04d} ({row.title}): index row has no file")
    return problems


def main(argv: list[str] | None = None) -> int:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("title", nargs="?", help="title of the new decision")
    parser.add_argument("--check", action="store_true", help="check the index and exit")
    parser.add_argument("--adr-dir", type=Path, default=DEFAULT_ADR_DIR, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.check:
        problems = check_index(args.adr_dir)
        for problem in problems:
            print(problem)
        return 1 if problems else 0
    if not args.title:
        parser.error("a title is required unless --check is given")
    try:
        path = create_adr(args.title, args.adr_dir, date.today())  # noqa: DTZ011 - local calendar date of the author
    except AdrError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
