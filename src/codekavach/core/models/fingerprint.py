r"""Stable, line-shift-tolerant finding fingerprints (algorithm ``ckfp1``) and correlation keys.

Owning epic: E02. Placement in core.models follows the E02-01 ADR, decision D4.

The fingerprint is the identity of a weakness across scans: baselines, suppressions, the GitHub
issue sync and SARIF ``partialFingerprints`` key on it. It survives inserted lines above the
statement, re-indentation, trailing whitespace, CRLF versus LF, blank lines inside the region and
path spelling (backslashes, leading ``./``). It changes when the engine, rule, path, enclosing
symbol or the flagged statement changes.

Algorithm ``ckfp1`` (normative):

1. For each line of the primary location: remove every ``\r``, collapse Unicode whitespace
   (``str.split()`` joined by one space), drop the line if empty; keep the first 50 lines and
   join them with ``\n``.
2. ``snippet_hash`` is the SHA-256 hex digest of that text.
3. ``engine`` is stripped and lower-cased, ``rule_id`` stripped, ``path`` normalised,
   ``symbol`` becomes ``""`` when absent.
4. ``material`` joins ``ckfp1``, engine, rule_id, path, symbol, snippet_hash and the occurrence
   index with U+001F.
5. The fingerprint is ``ckfp1:`` plus the first 32 hex characters of SHA-256 of ``material``.

Known limitations:

- Whitespace inside string literals is collapsed too; the algorithm has no language knowledge.
- Two identical statements under the same rule are told apart only by their occurrence index in
  line order. If the first is fixed, the second becomes occurrence 0 and inherits its identity.
- A renamed file or enclosing function gives a new fingerprint (E21 may detect moves).

Privacy: a fingerprint is an unsalted hash of low-entropy client data (path, symbol, code).
Anyone who can guess the inputs can confirm the guess, so fingerprints and snippet hashes are
client-side data. They may appear in reports, SARIF and issues in the client's own organisation,
but never in a SanitisedPayload, a prompt or any request to an LLM provider. They cannot be
salted with the scan salt because they must be stable across scans.

The functions are pure: no I/O and no clock. Callers split file text with ``split_lines`` from
``codekavach.core.models.text``.
"""

import hashlib
import re
from collections.abc import Sequence
from typing import ClassVar

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.errors import FingerprintInputError
from codekavach.core.models.paths import RepoPath, normalise_repo_path

FINGERPRINT_VERSION = "ckfp1"
CORRELATION_VERSION = "ckck1"
FINGERPRINT_PATTERN = r"^ckfp1:[0-9a-f]{32}$"
CORRELATION_PATTERN = r"^ckck1:[0-9a-f]{32}$"
SARIF_PARTIAL_FINGERPRINT_KEY = "codekavachFingerprint/v1"
MAX_SNIPPET_LINES = 50

_SEPARATOR = "\x1f"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class FingerprintParts(KavachModel):
    """Inputs of one fingerprint. ``start_line`` orders occurrences and is never hashed.

    Only the path is validated on construction; the other inputs are checked by
    ``compute_fingerprint``, which raises FingerprintInputError.
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    engine: str
    rule_id: str
    path: RepoPath
    symbol: str | None = None
    snippet_hash: str
    start_line: int = 1

    def group_key(self) -> tuple[str, str, str, str, str]:
        """The key under which identical occurrences are numbered."""
        return (
            self.engine.strip().lower(),
            self.rule_id.strip(),
            self.path,
            self.symbol or "",
            self.snippet_hash,
        )


def normalise_snippet(lines: Sequence[str]) -> str:
    """Return the normalised snippet text that ``snippet_hash`` hashes."""
    kept: list[str] = []
    for line in lines:
        collapsed = " ".join(line.replace("\r", "").split())
        if collapsed:
            kept.append(collapsed)
            if len(kept) == MAX_SNIPPET_LINES:
                break
    return "\n".join(kept)


def snippet_hash(lines: Sequence[str]) -> str:
    """Return the SHA-256 hex digest of the normalised snippet."""
    return hashlib.sha256(normalise_snippet(lines).encode("utf-8")).hexdigest()


def _digest(version: str, fields: Sequence[str]) -> str:
    material = _SEPARATOR.join([version, *fields])
    return f"{version}:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _check_text(name: str, value: str) -> None:
    if _SEPARATOR in value:
        raise FingerprintInputError(f"{name} must not contain U+001F")


def _check_hash(value: str) -> None:
    if not _HEX64.match(value):
        raise FingerprintInputError("snippet_hash must be 64 lower-case hex characters")


def _normalise_path(path: str) -> str:
    _check_text("path", path)
    try:
        return normalise_repo_path(path)
    except ValueError:
        raise FingerprintInputError("path is not a valid repository path") from None


def compute_fingerprint(parts: FingerprintParts, occurrence: int = 0) -> str:
    """Return the ``ckfp1`` fingerprint of ``parts`` at the given occurrence index."""
    for name in ("engine", "rule_id", "path"):
        _check_text(name, getattr(parts, name))
    _check_text("symbol", parts.symbol or "")
    engine = parts.engine.strip().lower()
    rule_id = parts.rule_id.strip()
    if not engine or not rule_id:
        raise FingerprintInputError("engine and rule_id must not be empty")
    if occurrence < 0:
        raise FingerprintInputError("occurrence must not be negative")
    _check_hash(parts.snippet_hash)
    path = _normalise_path(parts.path)
    fields = [engine, rule_id, path, parts.symbol or "", parts.snippet_hash, str(occurrence)]
    return _digest(FINGERPRINT_VERSION, fields)


def fingerprint_batch(items: Sequence[FingerprintParts]) -> list[str]:
    """Return fingerprints in input order, numbering identical occurrences by line order."""
    groups: dict[tuple[str, str, str, str, str], list[int]] = {}
    for index, item in enumerate(items):
        groups.setdefault(item.group_key(), []).append(index)
    occurrences = [0] * len(items)
    for indices in groups.values():
        ordered = sorted(indices, key=lambda i: (items[i].start_line, i))
        for number, index in enumerate(ordered):
            occurrences[index] = number
    return [compute_fingerprint(item, occurrences[i]) for i, item in enumerate(items)]


def compute_correlation_key(
    cwe: int | None, path: str, symbol: str | None, snippet_hash: str
) -> str:
    """Return the engine-independent ``ckck1`` key used to merge results across engines."""
    _check_text("symbol", symbol or "")
    _check_hash(snippet_hash)
    return _digest(
        CORRELATION_VERSION, [str(cwe or 0), _normalise_path(path), symbol or "", snippet_hash]
    )
