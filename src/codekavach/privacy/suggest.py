"""``suggest_terms``: the backend of ``codekavach privacy terms suggest`` (E08-04).

Owning epic: E08.

Mines the domain vocabulary of one stored scan (``mine_domain_terms``) and writes the candidates to
a **suggestion file in the state directory**, in the format of a terms file, one term per line with
a comment above it that holds the score and where the word was seen. The file is a proposal for a
person to review: this module changes no setting, and nothing is redacted from a suggested term
until the person copies it into ``privacy.domain_terms`` (or points ``privacy.domain_terms_file``
at the reviewed file). The file lives in the state directory, which is private to the user, and
not in the project, because a list mined from the repository is a summary of the client's
vocabulary and must not be created somewhere that may be committed.

The returned :class:`Suggestion` carries a short ``sample`` for the operator's terminal. The
command prints it in human mode only; it is never put into a JSON envelope or a log.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from codekavach.config import Settings
from codekavach.core.models import Language
from codekavach.core.pipeline import keys
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout, atomic_write_bytes
from codekavach.ingest.models import SourceFile
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.models import LiteralSpan
from codekavach.parsing.symbols import SymbolsArtefact
from codekavach.privacy.detect.mining import (
    DEFAULT_LIMIT,
    MinedTerm,
    bundled_baseline,
    eligible_words,
    mine_domain_terms,
)
from codekavach.privacy.pseudonymise.allowlist import NoAllowlistError, PublicAllowlist

SUGGESTION_DIR: Final = "suggestions"
SAMPLE_SIZE: Final = 10
MAX_LITERAL_FILES: Final = 5_000
HEADER: Final = (
    "# Domain-term suggestions mined from scan {scan}.\n"
    "# Review every line. Nothing is redacted from these words until you copy the ones you\n"
    "# want into privacy.domain_terms, or point privacy.domain_terms_file at this file after\n"
    "# editing it. This file describes your code's vocabulary: do not commit it.\n"
)


@dataclass(frozen=True)
class Suggestion:
    """What was written and a short sample for the terminal."""

    scan_id: str
    path: Path
    count: int
    files_examined: int
    sample: tuple[MinedTerm, ...]


def _excluded_words(languages: set[Language], settings: Settings) -> frozenset[str]:
    """Words already configured, as lower-case sub-words."""
    configured: set[str] = set()
    for term in settings.privacy.domain_terms:
        configured.update(eligible_words(term))
    return frozenset(configured)


def _exclusion_test(
    languages: set[Language], settings: Settings, configured: frozenset[str]
) -> Callable[[str], bool]:
    """Words never suggested: configured, keywords and builtins, and the public allowlist."""
    allowlists: list[PublicAllowlist] = []
    keywords: set[str] = set()
    for language in sorted(languages, key=lambda item: item.value):
        spec = REGISTRY.get(language)
        keywords.update(spec.keywords)
        keywords.update(spec.builtins)
        try:
            allowlists.append(PublicAllowlist.from_settings(language, settings))
        except NoAllowlistError:
            continue

    def excluded(word: str) -> bool:
        return (
            word in configured
            or word in keywords
            or any(allowlist.is_public(word) for allowlist in allowlists)
        )

    return excluded


def _literals(
    files: list[SourceFile], tables: set[str], root: Path, max_bytes: int
) -> list[LiteralSpan]:
    found: list[LiteralSpan] = []
    for file in sorted(files, key=lambda item: item.path)[:MAX_LITERAL_FILES]:
        if str(file.path) not in tables:
            continue
        target = root / str(file.path)
        try:
            if target.is_symlink() or target.stat().st_size > max_bytes:
                continue
            text = target.read_text(encoding="utf-8", errors="replace")
            found.extend(parse(str(file.path), file.language, text).string_literals())
        except (OSError, LookupError, ValueError):
            continue
    return found


def render(scan_id: str, terms: tuple[MinedTerm, ...]) -> str:
    """The suggestion file text."""
    lines = [HEADER.format(scan=scan_id)]
    for item in terms:
        kinds = ", ".join(item.sample_kinds)
        lines.append(
            f"# score {item.score:.2f}, seen {item.occurrences}, in {kinds}\n{item.term}\n"
        )
    return "\n".join(lines)


def suggest_terms(
    layout: StateLayout,
    scan_id: str,
    *,
    settings: Settings,
    project_root: Path,
    limit: int = DEFAULT_LIMIT,
) -> Suggestion:
    """Mine the vocabulary of ``scan_id`` and write the suggestion file under ``layout``.

    Raises:
        LookupError: the scan has no ``symbols`` artefact (the parse stage did not run).
    """
    store = OnDiskArtefactStore.open_existing(layout, scan_id)
    symbols = store.get(keys.SYMBOLS, SymbolsArtefact)
    files = store.get_list(keys.FILES, SourceFile)
    languages = {file.language for file in files if str(file.path) in symbols.tables}
    languages.discard(Language.UNKNOWN)
    literals = _literals(
        files, set(symbols.tables), project_root, settings.parsing.max_source_bytes
    )
    mined = mine_domain_terms(
        symbols.tables.values(),
        literals,
        baseline=bundled_baseline(),
        excluded=_exclusion_test(languages, settings, _excluded_words(languages, settings)),
        limit=limit,
    )
    target = layout.contain(layout.root / SUGGESTION_DIR / f"domain-terms-{scan_id}.txt")
    atomic_write_bytes(target, render(scan_id, mined).encode("utf-8"))
    return Suggestion(
        scan_id=scan_id,
        path=target,
        count=len(mined),
        files_examined=len(symbols.tables),
        sample=mined[:SAMPLE_SIZE],
    )
