"""Dependency licence gate (E01-30).

Usage::

    python tools/dev/check_licences.py [--format table|json] [--include-dev]

Classifies the licence of every installed distribution against the policy table
``[tool.codekavach.licences]`` in ``pyproject.toml``. The runtime closure (everything a user
installs with any extra, from ``uv export --no-dev --all-extras``) is strict: anything that is
not ``allowed`` or a recorded ``exception`` fails. Development-only tools are listed with
``--include-dev`` and fail only when ``denied``, because they are not redistributed.

Licences are read from installed metadata only (``importlib.metadata``): the script performs no
network access and works in the air-gapped bundle. Resolution order per distribution: the PEP 639
``License-Expression`` field, then a short ``License`` field, then Trove classifiers.

This gate is an engineering control, not legal advice. A ``review`` result needs a person's
decision, recorded under ``[tool.codekavach.licences.exceptions]`` with a reason and the issue or
ADR that approved it.
"""

import argparse
import fnmatch
import importlib.metadata
import json
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Classification = Literal["allowed", "review", "denied", "unknown", "exception"]
Scope = Literal["runtime", "dev"]

REPO_ROOT = Path(__file__).resolve().parents[2]
UNKNOWN = "unknown"
MAX_SHORT_LICENCE = 100
PLACEHOLDERS = frozenset({"unknown", "none", "n/a", "other", "see license", "see license file"})
EXPORT_COMMAND = (
    "uv", "export", "--frozen", "--no-dev", "--all-extras", "--no-hashes", "--no-emit-project",
    "--format", "requirements-txt",
)  # fmt: skip

# Trove classifiers to SPDX identifiers.
CLASSIFIERS: dict[str, str] = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: MIT No Attribution License (MIT-0)": "MIT-0",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: zlib/libpng License": "Zlib",
    "License :: OSI Approved :: Historical Permission Notice and Disclaimer (HPND)": "HPND",
    "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication": "CC0-1.0",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": (
        "GPL-2.0-or-later"
    ),
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": (
        "GPL-3.0-or-later"
    ),
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": (
        "LGPL-2.0-or-later"
    ),
    "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)": "LGPL-*",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
}
# Common free-form ``License`` values to SPDX identifiers. ``BSD`` stays ambiguous (see below).
FREE_FORM: dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "mit-cmu": "HPND",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0",
    "bsd": "BSD",
    "bsd license": "BSD",
    "new bsd": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "3-clause bsd": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd 3-clause license": "BSD-3-Clause",
    "bsd-3-clause license": "BSD-3-Clause",
    "2-clause bsd": "BSD-2-Clause",
    "bsd 2-clause license": "BSD-2-Clause",
    "bsd-2-clause license": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "psf": "PSF-2.0",
    "psf license": "PSF-2.0",
    "psfl": "PSF-2.0",
    "python software foundation license": "PSF-2.0",
    "isc": "ISC",
    "isc license": "ISC",
    "mpl 2.0": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "unlicense": "Unlicense",
    "public domain": "Unlicense",
    "zlib": "Zlib",
}


@dataclass(frozen=True)
class Policy:
    """The policy table of ``pyproject.toml``."""

    allowed: tuple[str, ...] = ()
    review: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()
    exceptions: dict[str, dict[str, str]] = field(default_factory=dict)

    @classmethod
    def from_pyproject(cls, path: Path = REPO_ROOT / "pyproject.toml") -> "Policy":
        table = tomllib.loads(path.read_text(encoding="utf-8"))["tool"]["codekavach"]["licences"]
        return cls(
            allowed=tuple(table.get("allowed", ())),
            review=tuple(table.get("review", ())),
            denied=tuple(table.get("denied", ())),
            exceptions={normalise_name(k): v for k, v in table.get("exceptions", {}).items()},
        )


@dataclass(frozen=True)
class Row:
    """One checked distribution."""

    package: str
    version: str
    licence: str
    classification: str
    scope: Scope


def normalise_name(name: str) -> str:
    """PEP 503 normalised distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def runtime_closure(lock_export: str) -> set[str]:
    """Normalised names of the requirements in an exported requirements text."""
    names: set[str] = set()
    for raw in lock_export.splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", raw).split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if match:
            names.add(normalise_name(match.group(1)))
    return names


def _short_licence(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if not text or len(text) > MAX_SHORT_LICENCE or "\n" in text:
        return None
    if text.lower() in PLACEHOLDERS:
        return None  # not a licence: fall back to the classifiers
    return FREE_FORM.get(text.lower(), text)


def licence_of(dist: Any) -> str:
    """The licence of ``dist`` as an SPDX identifier or expression, or ``unknown``."""
    metadata = dist.metadata
    expression = metadata.get("License-Expression")
    if expression and expression.strip():
        return str(expression).strip()
    from_classifiers = [
        CLASSIFIERS[value]
        for value in (metadata.get_all("Classifier") or [])
        if value in CLASSIFIERS
    ]
    short = _short_licence(metadata.get("License"))
    if short == "BSD":
        # A bare "BSD" maps to BSD-3-Clause only when a classifier agrees.
        return "BSD-3-Clause" if "BSD" in from_classifiers else UNKNOWN
    if short:
        return short
    if from_classifiers:
        first = from_classifiers[0]
        if first == "BSD":
            return UNKNOWN  # the classifier alone does not say which BSD
        return " OR ".join(dict.fromkeys(from_classifiers)) if len(from_classifiers) > 1 else first
    return UNKNOWN


# --- SPDX expressions ----------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+*:-]+)")


def _tokens(expression: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    while position < len(expression):
        match = _TOKEN.match(expression, position)
        if not match:
            if expression[position:].strip():
                raise ValueError("malformed expression")
            break
        tokens.append(match.group(1))
        position = match.end()
    return tokens


def _matches(licence: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(licence, pattern) for pattern in patterns)


def _single(licence: str, policy: Policy) -> Classification:
    if licence in {UNKNOWN, "BSD"}:
        return "unknown"
    if _matches(licence, policy.denied):
        return "denied"
    if _matches(licence, policy.allowed):
        return "allowed"
    if _matches(licence, policy.review):
        return "review"
    return "unknown"


_RANK: dict[str, int] = {"allowed": 0, "review": 1, "unknown": 2, "denied": 3}


class _Parser:
    """Recursive descent over ``or_expr := and_expr (OR and_expr)*``, AND binding tighter."""

    def __init__(self, tokens: list[str], policy: Policy) -> None:
        self.tokens = tokens
        self.position = 0
        self.policy = policy

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _next(self) -> str:
        token = self._peek()
        if token is None:
            raise ValueError("unexpected end")
        self.position += 1
        return token

    def parse(self) -> Classification:
        result = self._or()
        if self._peek() is not None:
            raise ValueError("trailing tokens")
        return result

    def _or(self) -> Classification:
        options = [self._and()]
        while self._peek() == "OR":
            self._next()
            options.append(self._and())
        return min(options, key=_RANK.__getitem__)  # we choose the best side

    def _and(self) -> Classification:
        parts = [self._with()]
        while self._peek() == "AND":
            self._next()
            parts.append(self._with())
        return max(parts, key=_RANK.__getitem__)  # every side must be acceptable

    def _with(self) -> Classification:
        result = self._atom()
        if self._peek() == "WITH":
            self._next()
            self._next()  # the exception identifier
            return "denied" if result == "denied" else "review"
        return result

    def _atom(self) -> Classification:
        item = self._next()
        if item == "(":
            result = self._or()
            if self._next() != ")":
                raise ValueError("unbalanced parentheses")
            return result
        if item in {")", "AND", "OR", "WITH"}:
            raise ValueError("operator where a licence was expected")
        return _single(item, self.policy)


def classify(name: str, licence: str, policy: Policy) -> Classification:
    """Classify ``licence`` (an SPDX expression) for distribution ``name`` under ``policy``."""
    if normalise_name(name) in policy.exceptions:
        return "exception"
    try:
        return _Parser(_tokens(licence), policy).parse()
    except ValueError:
        return "unknown"


def fails(classification: str, scope: Scope) -> bool:
    """Runtime accepts only allowed and exception; dev fails only on denied."""
    if scope == "dev":
        return classification == "denied"
    return classification not in {"allowed", "exception"}


# --- the check -----------------------------------------------------------------------------


def check(
    distributions: Iterable[Any],
    runtime: set[str],
    policy: Policy,
    *,
    include_dev: bool,
) -> tuple[list[Row], list[str]]:
    """Rows for the distributions in scope, and warnings (stale exceptions, missing packages)."""
    dists = list(distributions)
    rows: dict[str, Row] = {}
    for dist in dists:
        name = normalise_name(dist.metadata["Name"] or "")
        if not name or name in rows:
            continue
        scope: Scope = "runtime" if name in runtime else "dev"
        if scope == "dev" and not include_dev:
            continue
        licence = policy.exceptions.get(name, {}).get("licence") or licence_of(dist)
        rows[name] = Row(name, dist.version, licence, classify(name, licence, policy), scope)
    installed = {normalise_name(d.metadata["Name"] or "") for d in dists}
    warnings = [
        f"stale exception: {name} is not installed"
        for name in sorted(policy.exceptions)
        if name not in installed
    ]
    warnings += [
        f"not installed on this platform (runtime, environment marker): {name}"
        for name in sorted(runtime - installed)
    ]
    return sorted(rows.values(), key=lambda row: (row.scope, row.package)), warnings


def _render_table(rows: Sequence[Row]) -> str:
    headers = ("package", "version", "licence", "classification", "scope")
    table = [headers, *((r.package, r.version, r.licence, r.classification, r.scope) for r in rows)]
    widths = [max(len(str(line[i])) for line in table) for i in range(len(headers))]
    return "\n".join(
        "  ".join(str(cell).ljust(width) for cell, width in zip(line, widths, strict=True)).rstrip()
        for line in table
    )


def main(argv: Sequence[str] | None = None, distributions: Iterable[Any] | None = None) -> int:
    """Command line entry point; ``distributions`` and the export can be injected for tests."""
    parser = argparse.ArgumentParser(description="Check dependency licences against the policy.")
    parser.add_argument("--format", choices=("table", "json"), default="table")
    parser.add_argument("--include-dev", action="store_true", help="also list dev-only tools")
    parser.add_argument("--export", type=Path, help="read the uv export from a file")
    parser.add_argument("--pyproject", type=Path, default=REPO_ROOT / "pyproject.toml")
    args = parser.parse_args(argv)
    if args.export is not None:
        export = args.export.read_text(encoding="utf-8")
    else:
        export = subprocess.run(
            EXPORT_COMMAND, cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout
    rows, warnings = check(
        importlib.metadata.distributions() if distributions is None else distributions,
        runtime_closure(export),
        Policy.from_pyproject(args.pyproject),
        include_dev=args.include_dev,
    )
    if args.format == "json":
        sys.stdout.write(json.dumps([asdict(row) for row in rows], indent=2) + "\n")
    else:
        sys.stdout.write(_render_table(rows) + "\n")
    for warning in warnings:
        sys.stderr.write(f"warning: {warning}\n")
    failing = [row for row in rows if fails(row.classification, row.scope)]
    for row in failing:
        sys.stderr.write(
            f"licence gate: {row.package} {row.version} is {row.licence} ({row.classification}, "
            f"{row.scope})\n"
        )
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
