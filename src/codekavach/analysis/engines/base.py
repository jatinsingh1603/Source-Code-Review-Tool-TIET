"""The engine adapter contract and its models (E14-01).

Owning epic: E14.

An adapter wraps one external engine that runs as a separate process (ADR-0002). It never imports
the engine. The adapter says whether the engine is installed (``probe``), whether it applies to a
scan (``applies_to``), what to run (``build_invocation``) and how to turn the engine's output into
candidates (``parse``). Everything that makes the run safe (no shell, scrubbed environment, limits,
read-only source view) is done by the sandbox and the runner, not by the adapter.

**Path tokens.** An adapter writes ``ROOT_TOKEN`` where the scan root belongs and
``OUTPUT_TOKEN`` where the engine's private output directory belongs, in ``argv``, ``workdir`` and
the values of ``env``. The sandbox substitutes the real paths (``/src`` and ``/out`` inside a
container). Tokens keep the invocation, and so the cache key, independent of the temporary
directories of one run.
"""

import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Protocol, runtime_checkable

from codekavach.config import Settings
from codekavach.core.models import Candidate, CandidateKind, Language
from codekavach.ingest.models import SourceFile

ROOT_TOKEN: Final = "{root}"  # noqa: S105 - a path token, not a credential
OUTPUT_TOKEN: Final = "{output_dir}"  # noqa: S105 - a path token, not a credential
ENGINE_ID_PATTERN: Final = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
SLUG_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_LICENCE: Final = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.+-]*( (AND|OR|WITH) [A-Za-z0-9][A-Za-z0-9.+-]*)*$"
)
MAX_WEIGHT: Final = 16

OutputFormat = Literal["sarif", "json", "xml", "text"]
CodeFlowOrder = Literal["source_first", "sink_first"]
RunStatus = Literal["ok", "unavailable", "timeout", "error", "skipped"]


class BuildTier(StrEnum):
    """Whether an engine needs the project to build first."""

    NO_BUILD = "no_build"
    BUILD = "build"


class DistributionMode(StrEnum):
    """How an engine reaches the user."""

    BUNDLED = "bundled"
    CLIENT_INSTALLED = "client_installed"
    EVALUATION_ONLY = "evaluation_only"


@dataclass(frozen=True, slots=True)
class EngineSpec:
    """What an engine is, statically. ``id`` is addressable from configuration."""

    id: str
    name: str
    languages: frozenset[Language]
    tier: BuildTier
    output_format: OutputFormat
    spdx_licence: str
    distribution: DistributionMode
    hosted_allowed: bool
    scans_proprietary_code: bool
    default_enabled: bool = True
    homepage: str = ""
    config_filenames: tuple[str, ...] = ()
    expect_exit_codes: frozenset[int] = frozenset({0})
    code_flow_order: CodeFlowOrder = "source_first"
    default_kind: CandidateKind = CandidateKind.VULNERABILITY
    weight: int = 1

    def __post_init__(self) -> None:
        if not ENGINE_ID_PATTERN.match(self.id) or not SLUG_PATTERN.match(self.id):
            raise ValueError("engine id must match ^[a-z][a-z0-9-]{0,31}$")
        if not self.name.strip():
            raise ValueError("engine name must not be empty")
        if not self.languages:
            raise ValueError("an engine must name at least one language")
        for language in self.languages:
            member: object = language
            if not isinstance(member, Language) or member is Language.UNKNOWN:
                raise ValueError("engine languages must be known Language members")
        if not self.spdx_licence or not _LICENCE.match(self.spdx_licence):
            raise ValueError("an engine needs an SPDX licence expression")
        if not 1 <= self.weight <= MAX_WEIGHT:
            raise ValueError(f"engine weight must be between 1 and {MAX_WEIGHT}")
        for filename in self.config_filenames:
            if not filename or "/" in filename or "\\" in filename or "\x00" in filename:
                raise ValueError("config_filenames are bare file names or patterns")
        if not self.expect_exit_codes:
            raise ValueError("expect_exit_codes must not be empty")


@dataclass(frozen=True, slots=True)
class EngineProbe:
    """Whether an engine is installed and usable."""

    engine_id: str
    available: bool
    version: str | None = None
    path: str | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class EngineInvocation:
    """One process to run: an argument vector (never a shell line) and its environment."""

    argv: tuple[str, ...]
    workdir: str = ROOT_TOKEN
    env: Mapping[str, str] = field(default_factory=dict)
    output_file: str | None = None
    stdout_is_output: bool = False
    expect_exit_codes: frozenset[int] = frozenset({0})

    def __post_init__(self) -> None:
        parts: tuple[object, ...] = self.argv
        if not parts or not all(isinstance(part, str) and part for part in parts):
            raise ValueError("argv must be a non-empty tuple of non-empty strings")
        if any("\x00" in part for part in self.argv):
            raise ValueError("argv must not contain NUL")
        if self.output_file is not None and self.stdout_is_output:
            raise ValueError("output_file and stdout_is_output are alternatives")


@dataclass(frozen=True, slots=True)
class EngineRun:
    """What happened when one engine ran (or was answered from the cache)."""

    engine: str
    version: str
    exit_code: int | None
    duration_seconds: float
    status: RunStatus
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    output_path: Path | None = None
    truncated: bool = False
    cached: bool = False
    error_code: str | None = None
    candidates: tuple[Candidate, ...] = ()


@runtime_checkable
class EngineAdapter(Protocol):
    """The contract of every engine adapter (E15, E19, E20)."""

    spec: EngineSpec

    def probe(self, settings: Settings) -> EngineProbe:
        """Whether the engine is installed here, and which version."""

    def applies_to(self, languages: Collection[Language], files: Sequence[SourceFile]) -> bool:
        """Whether the engine has anything to do for these languages and files."""

    def build_invocation(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> EngineInvocation | None:
        """The process to run, or ``None`` when nothing applies."""

    def parse(self, run: EngineRun, root: Path) -> Sequence[Candidate]:
        """Candidates from the captured output of ``run``."""

    def install_hint(self) -> str:
        """One line telling the user how to install the engine; no network access."""
