"""Record the replay cassettes of the KavachBank fixture, or check that they are current (E13-03).

Usage: ``uv run python tools/gen_cassettes.py [--check]``.

The demo scans under a fixed salt, so its payload hashes are stable; the replay provider answers
from ``fixtures/kavachbank/cassettes/<payload_hash>.json``. After a change to the redactor, the
pseudonymiser or the slicer the hashes change and the cassettes go stale. Without ``--check`` this
rewrites the directory from a fresh scan; with ``--check`` it writes nothing and exits 1 listing
every cassette that is missing, unused or different. The recorder uses the mock provider, never a
network, and is refused when ``CI`` is set.

This is development tooling and is not shipped in the package.
"""

import argparse
import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")

from tests.support.cassettes import record_cassettes, stale  # noqa: E402 - needs the root on path

FIXTURE = ROOT / "fixtures" / "kavachbank"
CASSETTES = FIXTURE / "cassettes"


def main(argv: Sequence[str] | None = None) -> int:
    """Run the tool; returns the exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--check", action="store_true", help="Compare and exit 1 on drift.")
    args = parser.parse_args(argv)
    if args.check:
        problems = stale(FIXTURE, CASSETTES) if CASSETTES.is_dir() else ["no cassette directory"]
        for line in problems:
            print(line)
        if problems:
            print("run: uv run python tools/gen_cassettes.py", file=sys.stderr)
        return 1 if problems else 0
    if os.environ.get("CI"):
        print("refusing to rewrite the cassettes in CI", file=sys.stderr)
        return 2
    if CASSETTES.is_dir():
        shutil.rmtree(CASSETTES)
    written = record_cassettes(FIXTURE, CASSETTES)
    print(f"wrote {len(written)} cassettes to {CASSETTES.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
