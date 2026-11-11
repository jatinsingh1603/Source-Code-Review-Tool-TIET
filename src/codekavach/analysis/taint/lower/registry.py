"""The registry of taint lowerings (E17-01).

Owning epic: E17. ``register_all`` registers Python and JavaScript/TypeScript, and a stub for each
language whose lowering is not written yet; a stub raises ``LoweringUnavailable`` so the caller
records a coverage note instead of failing (``codekavach.analysis.taint.lowering``).
"""

from codekavach.analysis.taint.lowering import (
    Lowering,
    LoweringUnavailable,
    register_lowering,
)
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Language

PENDING = (Language.JAVA, Language.GO, Language.PHP, Language.CSHARP)


def _stub(language: Language) -> "type[object]":
    def factory(settings: TaintSettings) -> Lowering:
        raise LoweringUnavailable(language)

    return factory  # type: ignore[return-value]


def register_all() -> None:
    """Register every lowering and stub; idempotent."""
    from codekavach.analysis.taint.lower.javascript import JavaScriptLowering  # noqa: PLC0415
    from codekavach.analysis.taint.lower.python import PythonLowering  # noqa: PLC0415

    register_lowering(Language.PYTHON, PythonLowering)
    register_lowering(Language.JAVASCRIPT, lambda s: JavaScriptLowering(s, Language.JAVASCRIPT))
    register_lowering(Language.TYPESCRIPT, lambda s: JavaScriptLowering(s, Language.TYPESCRIPT))
    for language in PENDING:
        register_lowering(language, _stub(language))  # type: ignore[arg-type]
