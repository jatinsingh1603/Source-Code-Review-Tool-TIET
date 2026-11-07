"""The candidate-generator protocol and its registry (M1 interface contract, ruling O-7).

Owning epic: E13. MVP; extended by E16, whose rule language and pack loader register further
generators behind the same protocol and replace the built-in code matchers.

A generator looks at one parsed file and its symbol table and returns candidates: possible
weaknesses with the rule that fired, the CWE, the locations and a stable fingerprint. A candidate
holds raw client data and never reaches the LLM layer (invariant I2); the privacy layer reads it.
"""

from collections.abc import Iterable, Sequence
from typing import Protocol, runtime_checkable

from codekavach.core.models import Candidate, Language
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import SymbolTable


@runtime_checkable
class CandidateGenerator(Protocol):
    """Something that turns one parsed file into candidates."""

    languages: frozenset[Language]

    def generate(self, parsed: ParsedFile, symbols: SymbolTable | None) -> Sequence[Candidate]:
        """The candidates for ``parsed``; ``symbols`` may be ``None`` when parsing skipped it."""


class GeneratorRegistry:
    """An ordered set of generators, looked up by language."""

    def __init__(self, generators: Iterable[CandidateGenerator] = ()) -> None:
        self._generators: list[CandidateGenerator] = []
        for generator in generators:
            self.register(generator)

    def register(self, generator: CandidateGenerator) -> None:
        """Add ``generator``; registering the same object twice is an error."""
        if any(existing is generator for existing in self._generators):
            raise ValueError("generator is already registered")
        self._generators.append(generator)

    def for_language(self, language: Language) -> tuple[CandidateGenerator, ...]:
        """The generators that handle ``language``, in registration order."""
        return tuple(item for item in self._generators if language in item.languages)

    @property
    def languages(self) -> frozenset[Language]:
        """Every language at least one generator handles."""
        return frozenset(language for item in self._generators for language in item.languages)

    def __len__(self) -> int:
        return len(self._generators)
