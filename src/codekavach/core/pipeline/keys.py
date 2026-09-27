"""Artefact keys: the shared vocabulary through which stages are wired together.

Owning epic: E04.

The orchestrator derives execution order from ``requires`` and ``provides`` only, so every epic
imports the well-known keys from here instead of inventing its own spelling.

=====================  ======================  ==========================  =====================
Key                    Constant                Produced by                 Notes
=====================  ======================  ==========================  =====================
``scan.target``        ``TARGET``              runner (E04-16)             ``{"target": ...}``
``files``              ``FILES``               ingest (E06)                raw code
``languages``          ``LANGUAGES``           ingest (E06)
``ast``                ``AST``                 parse (E07)                 transient, raw code
``symbols``            ``SYMBOLS``             parse (E07)                 raw code
``callgraph``          ``CALL_GRAPH``          parse (E07)                 raw code
``candidates.raw``     ``CANDIDATES_RAW``      analyse-* (E14 to E20)      multi-provider
``candidates``         ``CANDIDATES``          aggregate (E21)             raw code
``payloads.sanitised`` ``PAYLOADS_SANITISED``  privacy-prepare (E25)       sanitised
``verdicts.raw``       ``VERDICTS_RAW``        llm-review (E23)            pseudonym space
``verdicts.restored``  ``VERDICTS_RESTORED``   restore (E10)
``findings``           ``FINDINGS``            rate (E29)
``scan.summary``       ``SCAN_SUMMARY``        rate (E29)
``report.outputs``     ``REPORT_OUTPUTS``      report (E30, E31)
``sync.result``        ``SYNC_RESULT``         sync (E34)
``scan.manifest``      ``MANIFEST``            orchestrator (E04)
``scan.record``        ``SCAN_RECORD``         runner (E04-16)             final ``Scan``
=====================  ======================  ==========================  =====================

The vocabulary is open: a plugin may use any key matching ``KEY_PATTERN`` (at most 64
characters). For a key that is not multi-provider, at most one stage in a plan may provide it; a
multi-provider key collects one part per provider, read in part-name order.
"""

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from codekavach.core.pipeline.stage import MAX_KEY_LENGTH, StageCategory, StageInfo

TARGET: Final = "scan.target"
FILES: Final = "files"
LANGUAGES: Final = "languages"
AST: Final = "ast"
SYMBOLS: Final = "symbols"
CALL_GRAPH: Final = "callgraph"
CANDIDATES_RAW: Final = "candidates.raw"
CANDIDATES: Final = "candidates"
PAYLOADS_SANITISED: Final = "payloads.sanitised"
VERDICTS_RAW: Final = "verdicts.raw"
VERDICTS_RESTORED: Final = "verdicts.restored"
FINDINGS: Final = "findings"
SCAN_SUMMARY: Final = "scan.summary"
REPORT_OUTPUTS: Final = "report.outputs"
SYNC_RESULT: Final = "sync.result"
MANIFEST: Final = "scan.manifest"
SCAN_RECORD: Final = "scan.record"

# Artefacts that contain or point at client code in the clear, and those produced by the privacy
# layer; E04-13 checks that an LLM stage reads only the latter (pipeline-level support for I2).
RAW_CODE_KEYS: Final = frozenset({FILES, AST, SYMBOLS, CALL_GRAPH, CANDIDATES_RAW, CANDIDATES})
SANITISED_KEYS: Final = frozenset({PAYLOADS_SANITISED, VERDICTS_RAW})

DEFAULT_STAGE_ORDER: Final[tuple[str, ...]] = (
    "ingest",
    "parse",
    "analyse",
    "aggregate",
    "privacy-prepare",
    "llm-review",
    "restore",
    "rate",
    "report",
    "sync",
)
CATEGORY_BY_DEFAULT_NAME: Final[Mapping[str, StageCategory]] = MappingProxyType(
    {name: StageCategory(name) for name in DEFAULT_STAGE_ORDER}
)

KEY_PATTERN: Final = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"
MULTI_PROVIDER_KEYS: Final = frozenset({CANDIDATES_RAW})
PARTS_SUFFIX: Final = ".parts"

_KEY = re.compile(KEY_PATTERN)


def is_valid_key(key: str) -> bool:
    """True for a dotted lower-case key of at most 64 characters (no separators, no ``..``)."""
    return len(key) <= MAX_KEY_LENGTH and _KEY.fullmatch(key) is not None


def is_multi_provider(key: str) -> bool:
    """True when several stages may each provide a part of ``key``."""
    return key in MULTI_PROVIDER_KEYS or key.endswith(PARTS_SUFFIX)


def default_rank(info: StageInfo) -> int:
    """Position of the stage's category in the default order; uncategorised stages go last."""
    if info.category is None:
        return len(DEFAULT_STAGE_ORDER)
    return DEFAULT_STAGE_ORDER.index(info.category.value)


def matches_stage_selector(info: StageInfo, selector: str) -> bool:
    """True when ``selector`` is the stage's name or the default name of its category."""
    if selector == info.name:
        return True
    return (
        selector in CATEGORY_BY_DEFAULT_NAME
        and info.category is not None
        and info.category.value == selector
    )
