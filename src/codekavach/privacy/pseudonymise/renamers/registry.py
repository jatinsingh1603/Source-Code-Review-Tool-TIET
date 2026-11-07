"""The renamers by language (E09-04).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

``RenamerRegistry.get(language)`` returns the renamer of a language or raises
``UnsupportedLanguageError``. Another language is added by registering its renamer, without
touching this module (E09-06).
"""

from collections.abc import Iterable

from codekavach.core.models import Language
from codekavach.privacy.pseudonymise.renamers.base import BaseRenamer, UnsupportedLanguageError
from codekavach.privacy.pseudonymise.renamers.javascript import JavaScriptRenamer, TypeScriptRenamer
from codekavach.privacy.pseudonymise.renamers.python import PythonRenamer


class RenamerRegistry:
    """A renamer per language."""

    def __init__(self, renamers: Iterable[BaseRenamer] = ()) -> None:
        self._by_language: dict[Language, BaseRenamer] = {}
        for renamer in renamers:
            self.register(renamer)

    def register(self, renamer: BaseRenamer) -> None:
        """Add ``renamer`` for its language, replacing any renamer already registered for it."""
        self._by_language[renamer.language] = renamer

    def get(self, language: Language) -> BaseRenamer:
        """The renamer of ``language``.

        Raises:
            UnsupportedLanguageError: no renamer is registered for it.
        """
        try:
            return self._by_language[language]
        except KeyError:
            raise UnsupportedLanguageError(f"no renamer for {language.value}") from None

    def languages(self) -> tuple[Language, ...]:
        """The languages that have a renamer, in enum order."""
        return tuple(language for language in Language if language in self._by_language)


def default_registry() -> RenamerRegistry:
    """A registry holding the Python, JavaScript and TypeScript renamers."""
    return RenamerRegistry((PythonRenamer(), JavaScriptRenamer(), TypeScriptRenamer()))
