"""Check commit messages against the convention of AGENTS.md section 5 (E01-19).

Usage::

    python tools/dev/check_commit_msg.py PATH            # commit-msg hook: the message file
    python tools/dev/check_commit_msg.py --range A..B    # every commit of a revision range
    python tools/dev/check_commit_msg.py --ci            # the range of the CI event (environment)

The convention: ``<area>: <imperative summary>``, a blank line, an optional body, and issue
references on lines of their own (``Refs #12`` or ``Closes #12, #13``). Attribution to a tool or a
co-author and emoji are rejected. The script reads commit messages only and uses the standard
library and ``git``; it opens no connection.

The attribution patterns are assembled from fragments, because the project's backlog tooling
refuses text that contains those phrases literally.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

AREAS: Final = (
    "core", "cli", "ingest", "parsing", "privacy", "llm", "engines", "rules", "taint", "risk",
    "report", "api", "ui", "github", "eval", "docs", "infra",
)  # fmt: skip
MAX_SUBJECT: Final = 72
EXEMPT_PREFIXES: Final = ("Merge ", 'Revert "', "fixup! ", "squash! ")
SCISSORS: Final = "# ------------------------ >8 ------------------------"
ZERO_SHA: Final = "0" * 40

SUBJECT: Final = re.compile(rf"^({'|'.join(AREAS)}): \S.*$")
PREFIX: Final = re.compile(r"^([A-Za-z][\w/-]*):(.*)$")
REFERENCE: Final = re.compile(r"^(Refs|Closes) #\d+(, #\d+)*$")
REFERENCE_ATTEMPT: Final = re.compile(r"^\s*(refs|closes)\b\s*:?\s*#", re.IGNORECASE)
CO_AUTHOR: Final = re.compile(r"^\s*" + "co-" + "authored" + "-by" + r"\s*:", re.IGNORECASE)
TOOL_CREDIT: Final = re.compile(r"^\W*" + "generated" + r"\s+(with|by)\b", re.IGNORECASE)
ROBOT: Final = chr(0x1F916)
EMOJI: Final = re.compile("[\U0001f300-\U0001faff☀-➿️]")

GUIDE: Final = f"""\
Commit message convention (AGENTS.md section 5):

  <area>: <imperative summary>    at most {MAX_SUBJECT} characters, lower-case start, no full stop
                                  (blank line)
  Optional body.
                                  (blank line)
  Refs #<issue>   or   Closes #<issue>, #<issue>

Areas: {", ".join(AREAS)}

Valid examples:

  privacy: reject payloads that contain vault identifiers

  cli: add the --strict option to scan

  Exits 1 when a stage was degraded.

  Refs #169

No attribution to a tool or a co-author, and no emoji.
"""


def strip_comments(message: str) -> str:
    """The message as Git will store it after the hook: no comment lines, nothing below scissors."""
    kept = []
    for line in message.splitlines():
        if line.rstrip() == SCISSORS:
            break
        if not line.startswith("#"):
            kept.append(line)
    return "\n".join(kept)


def _subject_problems(subject: str) -> list[str]:
    problems = []
    if not SUBJECT.match(subject):
        prefix = PREFIX.match(subject)
        if prefix is None:
            problems.append("the subject has no '<area>: ' prefix")
        elif prefix.group(1) not in AREAS:
            problems.append(f"unknown area '{prefix.group(1)}'")
        else:
            problems.append("the area is followed by ': ' and a summary, with exactly one space")
        return problems
    summary = subject.split(": ", 1)[1]
    if len(subject) > MAX_SUBJECT:
        problems.append(f"the subject has {len(subject)} characters; the limit is {MAX_SUBJECT}")
    if subject.endswith("."):
        problems.append("the subject ends with a full stop")
    if not (summary[0].islower() or summary[0] == "`"):
        problems.append("the summary starts with a lower-case letter or a back-quoted identifier")
    return problems


def validate(message: str) -> list[str]:
    """Problems of a commit message in plain words; an empty list means the message is valid."""
    lines = message.strip("\n").splitlines()
    if not lines or not lines[0].strip():
        return ["the message is empty"]
    subject = lines[0]
    if subject.startswith(EXEMPT_PREFIXES):
        return []
    problems = _subject_problems(subject)
    if len(lines) > 1 and lines[1].strip():
        problems.append("the second line is not empty: separate subject and body by a blank line")
    for line in lines[1:]:
        if REFERENCE_ATTEMPT.match(line) and not REFERENCE.match(line):
            problems.append(
                f"malformed issue reference '{line.strip()}': write 'Refs #12' or "
                "'Closes #12, #13' on a line of its own"
            )
        if CO_AUTHOR.match(line):
            problems.append("a co-author trailer is not allowed")
        if TOOL_CREDIT.match(line) or ROBOT in line:
            problems.append("a line that credits a tool is not allowed")
    if EMOJI.search(message):
        problems.append("emoji are not allowed")
    return problems


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [shutil.which("git") or "git", *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def commits_of(log_arguments: Sequence[str]) -> list[tuple[str, str]]:
    """``(hash, message)`` of the commits that ``git log <log_arguments>`` lists.

    Raises:
        RuntimeError: git failed.
    """
    completed = _git("log", "--format=%H%x00%B%x01", *log_arguments)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "git log failed")
    commits = []
    for record in completed.stdout.split("\x01"):
        if "\x00" in record:
            sha, message = record.strip("\n").split("\x00", 1)
            commits.append((sha, message))
    return commits


def ci_log_arguments(env: dict[str, str]) -> list[str]:
    """The ``git log`` arguments for the event of a CI run, read from the environment.

    A push checks ``before..sha``; when ``before`` is all zeros (a new branch) or unknown here
    (a force push), only ``HEAD`` is checked. A pull request checks ``origin/<base>..HEAD``.
    """
    event = env.get("COMMIT_CHECK_EVENT", "")
    if event == "pull_request" and env.get("COMMIT_CHECK_BASE_REF"):
        return [f"origin/{env['COMMIT_CHECK_BASE_REF']}..HEAD"]
    before, sha = env.get("COMMIT_CHECK_BEFORE", ""), env.get("COMMIT_CHECK_SHA", "")
    known = (
        event == "push"
        and re.fullmatch(r"[0-9a-f]{40}", before) is not None
        and before != ZERO_SHA
        and re.fullmatch(r"[0-9a-f]{40}", sha) is not None
        and _git("cat-file", "-e", f"{before}^{{commit}}").returncode == 0
    )
    return [f"{before}..{sha}"] if known else ["-1", "HEAD"]


def check_commits(log_arguments: Sequence[str]) -> int:
    """Validate the listed commits; print ``<short hash>: <problem>`` lines; 1 if any is invalid."""
    try:
        commits = commits_of(log_arguments)
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    failed = 0
    for sha, message in commits:
        problems = validate(message)
        if problems:
            failed += 1
            subject = message.strip("\n").splitlines()[0] if message.strip() else ""
            print(f"{sha[:7]}: {subject}", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
    if failed:
        print(f"\n{GUIDE}", file=sys.stderr)
        return 1
    print(f"{len(commits)} commit message(s) follow the convention")
    return 0


def check_file(path: Path) -> int:
    """Validate the message file of the ``commit-msg`` hook; 1 with an explanation if invalid."""
    try:
        message = strip_comments(path.read_text(encoding="utf-8"))
    except OSError as error:
        print(f"error: cannot read {path}: {type(error).__name__}", file=sys.stderr)
        return 2
    problems = validate(message)
    if not problems:
        return 0
    print("commit message rejected:", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    print(f"\n{GUIDE}", file=sys.stderr)
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Run the checker; 0 valid, 1 invalid, 2 when it could not run."""
    parser = argparse.ArgumentParser(
        prog="check_commit_msg.py",
        description="Check commit messages against the convention of AGENTS.md section 5.",
        epilog=GUIDE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("path", nargs="?", type=Path, help="message file (commit-msg hook)")
    mode.add_argument("--range", metavar="REV_RANGE", help="check the commits of A..B")
    mode.add_argument(
        "--ci", action="store_true", help="check the commits of the CI event (COMMIT_CHECK_*)"
    )
    arguments = parser.parse_args(argv)
    if arguments.range is not None:
        return check_commits([arguments.range])
    if arguments.ci:
        return check_commits(ci_log_arguments(dict(os.environ)))
    return check_file(arguments.path)


if __name__ == "__main__":
    raise SystemExit(main())
