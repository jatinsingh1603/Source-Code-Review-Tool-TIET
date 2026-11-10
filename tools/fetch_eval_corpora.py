"""Fetch an external evaluation corpus at a pinned commit, verified by checksum (E08-04).

Usage: ``uv run python tools/fetch_eval_corpora.py NAME [--dest DIR]``.

Reads ``tools/eval_corpora.toml``. A corpus is downloaded with the ``gh`` command as the source
archive of one commit of a public GitHub repository, its SHA-256 is compared with the pinned
value **before** anything is written, and only then is it extracted (with the ``data`` extraction
filter, so no member can leave the destination). An entry with an empty repository, commit or
checksum is refused: the pins are filled in by a person after reading the dataset's licence.
Nothing is committed to this repository; the destination defaults to
``build/eval-corpora/NAME``.

The archive is raw data. Turning it into the ``cases.jsonl`` format that ``tools/detector_eval.py``
reads is specific to each dataset and is done by a converter kept beside the pins.

This is development tooling and is not shipped in the package.
"""

import argparse
import hashlib
import io
import re
import subprocess
import sys
import tarfile
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Final

ROOT = Path(__file__).resolve().parents[1]
PINS: Final = ROOT / "tools" / "eval_corpora.toml"
DEFAULT_DEST: Final = ROOT / "build" / "eval-corpora"
COMMIT: Final = re.compile(r"[0-9a-f]{40}")
SHA256: Final = re.compile(r"[0-9a-f]{64}")
REPOSITORY: Final = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
MAX_BYTES: Final = 512 * 1024 * 1024
TIMEOUT_SECONDS: Final = 120


class PinError(ValueError):
    """A pin is missing or malformed, or the download does not match it."""


def archive_endpoint(repository: str, commit: str) -> str:
    """The GitHub API endpoint of the source archive of one commit."""
    return f"repos/{repository}/tarball/{commit}"


def read_pin(name: str, text: str) -> tuple[str, str, str]:
    """``(repository, commit, sha256)`` of ``name``, validated.

    Raises:
        PinError: the corpus is unknown or one of the three values is empty or malformed.
    """
    entry = tomllib.loads(text).get("corpus", {}).get(name)
    if entry is None:
        raise PinError(f"no corpus named {name!r} in {PINS.name}")
    repository, commit, digest = (
        str(entry.get(key, "")) for key in ("repository", "commit", "sha256")
    )
    valid = (
        REPOSITORY.fullmatch(repository) and COMMIT.fullmatch(commit) and SHA256.fullmatch(digest)
    )
    if not valid:
        raise PinError(f"{name}: repository, a 40-character commit and a sha256 must all be pinned")
    return repository, commit, digest


def download(endpoint: str) -> bytes:
    """The body of a GitHub API ``endpoint``, fetched with the ``gh`` command and bounded in size.

    The ``gh`` command is used so that this tool imports no network library: network access
    from the project's own code is confined by ADR-0003, and this tool is not an exception.
    """
    try:
        done = subprocess.run(
            ["gh", "api", endpoint],  # noqa: S607 - gh is the developer's installed client
            capture_output=True,
            check=True,
            timeout=TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PinError(f"could not download {endpoint}: {type(error).__name__}") from None
    if len(done.stdout) > MAX_BYTES:
        raise PinError("the archive is larger than the 512 MiB limit")
    return done.stdout


def fetch(
    name: str,
    dest: Path,
    *,
    pins: str | None = None,
    opener: Callable[[str], bytes] = download,
) -> Path:
    """Download, verify and extract ``name`` under ``dest``; return the extraction directory.

    Raises:
        PinError: a pin is missing or the archive's checksum differs. Nothing is written.
    """
    text = pins if pins is not None else PINS.read_text(encoding="utf-8")
    repository, commit, digest = read_pin(name, text)
    body = opener(archive_endpoint(repository, commit))
    actual = hashlib.sha256(body).hexdigest()
    if actual != digest:
        raise PinError(f"{name}: checksum mismatch (expected {digest}, got {actual})")
    target = dest / name
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
        archive.extractall(target, filter="data")
    return target


def main(argv: Sequence[str] | None = None) -> int:
    """Fetch one corpus."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("name")
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    args = parser.parse_args(argv)
    try:
        target = fetch(args.name, args.dest)
    except PinError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(f"extracted to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
