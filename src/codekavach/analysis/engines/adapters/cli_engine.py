"""A base class for engines that are one command line writing one report (E15-02, E15-03, E15-01b).

Owning epic: E15. The engines that follow the opengrep/bandit shape need the same five methods:
probe the executable, say which languages apply, build one argument vector with the output
directory token, and turn the report into candidates. ``CliAdapter`` writes those once; a concrete
adapter sets the class attributes and implements ``options`` (and ``to_sarif`` when the engine does
not write SARIF itself).

Nothing here imports an engine; the engine is a separate process (ADR-0002).
"""

from collections.abc import Collection, Sequence
from pathlib import Path
from typing import ClassVar

from codekavach.analysis.engines.adapters.common import (
    executable_for,
    extra_args,
    files_in,
    probe_version,
    telemetry_args,
)
from codekavach.analysis.engines.base import (
    EngineInvocation,
    EngineProbe,
    EngineRun,
    EngineSpec,
)
from codekavach.analysis.engines.sarif.errors import SarifFormatError
from codekavach.analysis.engines.sarif.ingest import IngestOptions, ingest_sarif
from codekavach.config import Settings
from codekavach.core.models import Candidate, Language
from codekavach.ingest.models import SourceFile

MAX_REPORT_BYTES = 64 * 1024 * 1024


class CliAdapter:
    """Shared behaviour of the one-command engines."""

    spec: EngineSpec
    executable: ClassVar[str]
    hint: ClassVar[str]
    output_file: ClassVar[str]
    version_args: ClassVar[tuple[str, ...]] = ("--version",)
    stdout_is_output: ClassVar[bool] = False

    def options(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> tuple[list[str], list[str]] | None:
        """``(options, targets)`` of the command line, or ``None`` when there is nothing to run.

        ``options`` may use ``OUTPUT_TOKEN``; ``targets`` are the paths the engine scans.
        """
        raise NotImplementedError

    def to_sarif(self, raw: bytes) -> bytes:
        """The report as SARIF 2.1.0; the default is that the engine already wrote SARIF."""
        return raw

    def probe(self, settings: Settings) -> EngineProbe:
        """Whether the engine is installed, and its version."""
        return probe_version(
            self.spec.id, executable_for(settings, self.spec.id, self.executable), self.version_args
        )

    def applies_to(self, languages: Collection[Language], files: Sequence[SourceFile]) -> bool:
        """True when the scan has files in a language the engine handles."""
        return bool(self.spec.languages & set(languages))

    def build_invocation(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> EngineInvocation | None:
        """The engine's process for this scan, or ``None`` when there is nothing to run."""
        if not files_in(files, self.spec.languages):
            return None
        planned = self.options(root, files, settings)
        if planned is None:
            return None
        options, targets = planned
        argv = (
            executable_for(settings, self.spec.id, self.executable),
            *options,
            *telemetry_args(self.spec.id),
            *extra_args(settings, self.spec.id),
            *targets,
        )
        return EngineInvocation(
            argv=argv,
            output_file=None if self.stdout_is_output else self.output_file,
            stdout_is_output=self.stdout_is_output,
            expect_exit_codes=self.spec.expect_exit_codes,
            read_only_paths=self.read_only_paths(settings),
        )

    def read_only_paths(self, settings: Settings) -> tuple[str, ...]:
        """Host paths the argument vector names that a container run must mount read-only."""
        del settings
        return ()

    def parse(self, run: EngineRun, root: Path) -> Sequence[Candidate]:
        """Candidates from the engine's recorded output."""
        if run.output_path is None:
            raise SarifFormatError(["the engine wrote no output file"])
        if run.output_path.stat().st_size > MAX_REPORT_BYTES:
            raise SarifFormatError([f"the {self.spec.name} report is too large"])
        return ingest_sarif(
            self.to_sarif(run.output_path.read_bytes()),
            engine_id=self.spec.id,
            root=root,
            engine_version=run.version or None,
            options=IngestOptions(
                code_flow_order=self.spec.code_flow_order, default_kind=self.spec.default_kind
            ),
        )

    def install_hint(self) -> str:
        """How to install the engine."""
        return self.hint
