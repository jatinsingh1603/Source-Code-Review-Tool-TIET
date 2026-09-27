"""Reject staged paths that are CodeKavach runtime artefacts or local secrets.

Usage:
    python tools/dev/forbid_runtime_artefacts.py PATH [PATH ...]

Exits 1 and lists every offending path on stderr. `.gitignore` already lists these patterns, but
`git add -f` bypasses `.gitignore`; this pre-commit hook does not. Vaults and ledgers contain
client data (invariant I3) and must never enter the Git history.
"""

import re
import sys
from collections.abc import Sequence

_FORBIDDEN = [
    re.compile(r"(^|/)\.codekavach/", re.IGNORECASE),
    re.compile(r"\.vault$", re.IGNORECASE),
    re.compile(r"\.ledger\.jsonl$", re.IGNORECASE),
    re.compile(r"^scan-output/", re.IGNORECASE),
    re.compile(r"^reports-out/", re.IGNORECASE),
    re.compile(r"(^|/)codekavach\.local\.toml$", re.IGNORECASE),
]
_ENV = re.compile(r"(^|/)\.env($|\.)", re.IGNORECASE)
_ENV_EXAMPLE = re.compile(r"(^|/)\.env\.example$")
_KEY_FILE = re.compile(r"\.(pem|key|p12|pfx)$", re.IGNORECASE)
_FAKE_KEY_DIRS = re.compile(r"^(tests/fixtures/|fixtures/)")


def _is_offending(path: str) -> bool:
    normalised = path.replace("\\", "/")
    while normalised.startswith("./"):
        normalised = normalised[2:]
    if any(pattern.search(normalised) for pattern in _FORBIDDEN):
        return True
    if _ENV.search(normalised) and not _ENV_EXAMPLE.search(normalised):
        return True
    return bool(_KEY_FILE.search(normalised) and not _FAKE_KEY_DIRS.match(normalised))


def offending(paths: Sequence[str]) -> list[str]:
    """Return the paths that must not be committed, in input order."""
    return [path for path in paths if _is_offending(path)]


def main(argv: Sequence[str] | None = None) -> int:
    """Command line entry point."""
    paths = list(sys.argv[1:] if argv is None else argv)
    bad = offending(paths)
    for path in bad:
        print(f"runtime artefact or local secret must not be committed: {path}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
