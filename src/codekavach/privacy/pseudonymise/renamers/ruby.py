"""The Ruby renamer (E09-07).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

Ruby writes the kind of a name into its spelling: ``@conn`` is an instance variable, ``@@n`` a
class variable, ``$g`` a global, ``:conn`` a symbol and ``valid?`` a predicate. The sigil and the
suffix are syntax and stay as written; the name between them is renamed, and ``@conn``, ``:conn``
and ``conn`` share one token, because ``attr_accessor :conn`` ties the three together. A name
that starts with a capital (a class, a module, a constant) gets a capitalised token, since a
lowercase one would not parse as a constant.
"""

from codekavach.core.models import Language
from codekavach.privacy.pseudonymise.plan import EditReason, RenameEdit
from codekavach.privacy.pseudonymise.renamers.base import BaseRenamer, SourceFacts

_SIGILS = "@$:"
_SUFFIXES = "?!"


def _split(name: str) -> tuple[str, str, str]:
    body = name.lstrip(_SIGILS)
    prefix = name[: len(name) - len(body)]
    core = body.rstrip(_SUFFIXES)
    return prefix, core, body[len(core) :]


class RubyRenamer(BaseRenamer):
    """Renames the internal identifiers of a Ruby file."""

    language = Language.RUBY

    @staticmethod
    def canonical_name(name: str) -> str:
        """``@conn``, ``:conn`` and ``conn?`` are spellings of ``conn``."""
        return _split(name)[1] or name

    def identifier_edits(
        self, name: str, token: str, start: int, end: int, facts: SourceFacts
    ) -> list[RenameEdit]:
        """Keep the sigil and the ``?``/``!`` suffix; replace the name between them."""
        prefix, core, suffix = _split(name)
        if not core:
            return [RenameEdit(start, end, token, EditReason.IDENTIFIER)]
        if core[0].isupper() and not prefix:
            token = token[:1].upper() + token[1:]  # a constant or class must stay a constant
        return [RenameEdit(start, end, f"{prefix}{token}{suffix}", EditReason.IDENTIFIER)]
