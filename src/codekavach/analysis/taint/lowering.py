"""The lowering interface and the registry of languages that have one (E17-01).

Owning epic: E17. A ``Lowering`` turns a parsed file and its symbol table into an ``IRModule``.
The registry is keyed by language. A language with no lowering costs taint *coverage*, never an
exception inside a stage: ``get_lowering`` raises ``LoweringUnavailable`` for it, and the caller
records a coverage note naming the language (``coverage_note``), which the report's scope and
limitations section prints. Java, Go, PHP and C# have stubs that raise the same error until their
lowerings are written, so the registry has its final shape now and each language is a small,
separate change later.
"""

from collections.abc import Callable
from typing import ClassVar, Protocol, runtime_checkable

from codekavach.analysis.taint.ir import IRModule
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Language
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import SymbolTable


class LoweringUnavailable(Exception):  # noqa: N818 - named for what is missing
    """No lowering exists for ``language`` yet."""

    def __init__(self, language: Language) -> None:
        super().__init__(f"no taint lowering for {language.value}")
        self.language = language


@runtime_checkable
class Lowering(Protocol):
    """Lowers one parsed file of one language."""

    language: ClassVar[Language]
    grammar_version: str
    version: str

    def lower(self, parsed: ParsedFile, symbols: SymbolTable) -> IRModule:
        """The intermediate representation of ``parsed``; never raises on malformed code."""
        ...


Factory = Callable[[TaintSettings], Lowering]
_REGISTRY: dict[Language, Factory] = {}
_LOADED = False


def register_lowering(language: Language, factory: Factory) -> None:
    """Register ``factory`` (called with the ``[taint]`` settings) as ``language``'s lowering."""
    _REGISTRY[language] = factory


def _load_defaults() -> None:
    global _LOADED  # noqa: PLW0603 - lazy registration avoids importing every language eagerly
    if _LOADED:
        return
    _LOADED = True
    from codekavach.analysis.taint.lower import registry  # noqa: PLC0415

    registry.register_all()


def get_lowering(language: Language, settings: TaintSettings | None = None) -> Lowering:
    """The lowering of ``language`` configured by ``settings``.

    Raises ``LoweringUnavailable`` when there is none; the stage catches it and records a coverage
    note instead of failing.
    """
    _load_defaults()
    factory = _REGISTRY.get(language)
    if factory is None:
        raise LoweringUnavailable(language)
    return factory(settings or TaintSettings())


def lowering_languages() -> tuple[Language, ...]:
    """The languages with a registered lowering (stubs included), in value order."""
    _load_defaults()
    return tuple(sorted(_REGISTRY, key=lambda language: language.value))


def coverage_note(language: Language) -> str:
    """The sentence the report prints for a language that cannot be taint-analysed."""
    return (
        f"Taint analysis does not cover {language.value} yet: "
        "findings in these files come from pattern rules and the reasoning step only."
    )
