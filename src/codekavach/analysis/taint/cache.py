"""Memoised lowering: the intermediate representation of an unchanged file is reused (E17-01).

Owning epic: E17. The key covers everything the result depends on, per the rules in
``codekavach.core.pipeline.memo``: the content hash, the path (it is inside every ``Location``),
the language, the grammar version, the lowering version, the three settings that change the shape
of the result (``max_access_path``, ``max_function_nodes``, ``max_blocks``) and the timeout,
because a function skipped by the timeout depends on how slow the machine was. ``explain`` does
not change the intermediate representation and is not in the key.
"""

from typing import Final

from codekavach.analysis.taint.ir import IRModule
from codekavach.analysis.taint.lowering import Lowering
from codekavach.config.models.taint import TaintSettings
from codekavach.core.pipeline.memo import ItemMemo, memo_key
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import SymbolTable

NAMESPACE: Final = "taint.ir.v1"


def cache_key(sha256: str, parsed: ParsedFile, lowering: Lowering, settings: TaintSettings) -> str:
    """The memo key of one file's lowering."""
    return memo_key(
        sha256,
        parsed.path,
        parsed.language.value,
        lowering.grammar_version,
        lowering.version,
        str(settings.max_access_path),
        str(settings.max_function_nodes),
        str(settings.max_blocks),
        repr(settings.timeout_seconds),
    )


def lower_cached(  # noqa: PLR0917 - a flat call reads better than a bundle type
    memo: ItemMemo,
    sha256: str,
    parsed: ParsedFile,
    symbols: SymbolTable,
    lowering: Lowering,
    settings: TaintSettings,
) -> IRModule:
    """The lowering of ``parsed``, from the per-item memo when the same input was lowered before."""
    return memo.get_or_compute(
        NAMESPACE,
        cache_key(sha256, parsed, lowering, settings),
        lambda: lowering.lower(parsed, symbols),
        IRModule,
    )
