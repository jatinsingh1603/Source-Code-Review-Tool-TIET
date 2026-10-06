"""Telemetry-free guard for dependencies (E01-31, ADR-0005).

Usage::

    python tools/dev/check_no_telemetry.py [--lock uv.lock] [--pyproject pyproject.toml]

Reports every package in ``uv.lock`` whose PEP 503 normalised name matches a pattern of
``[tool.codekavach.telemetry] deny`` in ``pyproject.toml`` and has no complete exception. The
lockfile covers the whole resolution (every extra and group, every platform). OpenTelemetry API
and SDK packages are not denied, because libraries depend on them without sending anything; the
exporters are what ship data off the machine.

An exception needs a ``reason`` (why the package is present and how it is kept silent), a
``verified_by`` (the test that proves it) and an ``approved_in`` (issue or ADR). The check fails
closed: an unparseable lockfile or a malformed policy exits non-zero.
"""

import argparse
import fnmatch
import re
import sys
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
REQUIRED_EXCEPTION_KEYS = ("reason", "verified_by", "approved_in")


class PolicyError(ValueError):
    """The telemetry policy table is missing or malformed."""


@dataclass(frozen=True)
class Policy:
    """The ``[tool.codekavach.telemetry]`` table."""

    deny: tuple[str, ...]
    exceptions: dict[str, dict[str, str]] = field(default_factory=dict)

    @classmethod
    def from_table(cls, table: Any) -> "Policy":
        if not isinstance(table, dict) or not isinstance(table.get("deny"), list):
            raise PolicyError("[tool.codekavach.telemetry] needs a 'deny' list")
        exceptions = table.get("exceptions", {})
        if not isinstance(exceptions, dict):
            raise PolicyError("[tool.codekavach.telemetry.exceptions] must be a table")
        return cls(
            deny=tuple(normalise_name(str(pattern)) for pattern in table["deny"]),
            exceptions={normalise_name(name): entry for name, entry in exceptions.items()},
        )

    @classmethod
    def from_pyproject(cls, path: Path) -> "Policy":
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return cls.from_table(data.get("tool", {}).get("codekavach", {}).get("telemetry"))


@dataclass(frozen=True)
class Hit:
    """A locked package that matches the deny list."""

    package: str
    version: str
    pattern: str
    excepted: bool
    problem: str = ""


def normalise_name(name: str) -> str:
    """PEP 503 normalised name (wildcards are kept)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _exception_problem(entry: Any) -> str:
    if not isinstance(entry, dict):
        return "exception entry is not a table"
    missing = [key for key in REQUIRED_EXCEPTION_KEYS if not str(entry.get(key, "")).strip()]
    return f"exception lacks {', '.join(missing)}" if missing else ""


def telemetry_packages(lock_text: str, policy: Policy) -> list[Hit]:
    """Every locked package that matches the deny list, with its exception status."""
    lock = tomllib.loads(lock_text)
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ValueError("uv.lock has no [[package]] entries")
    hits: list[Hit] = []
    for package in packages:
        name = normalise_name(str(package.get("name", "")))
        pattern = next((p for p in policy.deny if fnmatch.fnmatchcase(name, p)), None)
        if pattern is None:
            continue
        entry = policy.exceptions.get(name)
        problem = "" if entry is None else _exception_problem(entry)
        excepted = entry is not None and not problem
        hits.append(Hit(name, str(package.get("version", "")), pattern, excepted, problem))
    return sorted(hits, key=lambda hit: hit.package)


def stale_exceptions(lock_text: str, policy: Policy) -> list[str]:
    """Exceptions for packages that are no longer in the lockfile."""
    locked = {
        normalise_name(str(package.get("name", "")))
        for package in tomllib.loads(lock_text).get("package", [])
    }
    return sorted(name for name in policy.exceptions if name not in locked)


def main(argv: Sequence[str] | None = None) -> int:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description="Check uv.lock for telemetry packages.")
    parser.add_argument("--lock", type=Path, default=REPO_ROOT / "uv.lock")
    parser.add_argument("--pyproject", type=Path, default=REPO_ROOT / "pyproject.toml")
    args = parser.parse_args(argv)
    try:
        policy = Policy.from_pyproject(args.pyproject)
        lock_text = args.lock.read_text(encoding="utf-8")
        hits = telemetry_packages(lock_text, policy)
        stale = stale_exceptions(lock_text, policy)
    except (OSError, ValueError) as error:  # tomllib.TOMLDecodeError is a ValueError
        sys.stderr.write(f"telemetry check: cannot check ({type(error).__name__}: {error})\n")
        return 2
    failed = False
    for hit in hits:
        if hit.excepted:
            sys.stdout.write(f"exception: {hit.package} {hit.version} (matches {hit.pattern})\n")
        else:
            failed = True
            detail = f"; {hit.problem}" if hit.problem else ""
            sys.stderr.write(
                f"telemetry package: {hit.package} {hit.version} matches {hit.pattern}{detail}\n"
            )
    for name in stale:
        sys.stderr.write(f"warning: stale exception: {name} is not in uv.lock\n")
    if not failed:
        sys.stdout.write("no telemetry packages in uv.lock\n" if not hits else "")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
