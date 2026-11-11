"""The Opengrep adapter: the default cross-language pattern and taint engine (E15-01).

Owning epic: E15. Opengrep (LGPL-2.1) runs as a separate process and is never imported. It writes
SARIF, which ``ingest_engine_run`` converts.

Rules. The adapter passes only directories the operator listed in ``engines.rule_paths`` (and, once
E16-03 ships it, CodeKavach's own MIT rule pack). It never passes a registry shorthand, never
``auto`` and never a URL, so no rule is fetched. The Semgrep-maintained registry (Semgrep Rules
License v1.0) and the archived ``opengrep-rules`` fork (LGPL-2.1 plus Commons Clause) must not be
bundled or served; ``docs/research/INSIGHTS.md`` section 6.1 explains why. Without a rule directory
there is nothing to run and the engine is skipped.

Telemetry. The Opengrep command line has no metrics option (checked in ``Scan_CLI.ml`` at v1.33.1),
so there is no opt-out to pass and the manifest row says so. Passing ``--metrics`` would be an
unknown-option error. ``--disable-version-check`` is likewise listed there as an unsupported flag
and is not passed.
"""

from collections.abc import Collection, Sequence
from pathlib import Path
from typing import Final

from codekavach.analysis.engines.adapters.common import (
    executable_for,
    extra_args,
    option_int,
    probe_version,
    resolve_path,
    telemetry_args,
)
from codekavach.analysis.engines.base import (
    OUTPUT_TOKEN,
    BuildTier,
    DistributionMode,
    EngineInvocation,
    EngineProbe,
    EngineRun,
    EngineSpec,
)
from codekavach.analysis.engines.sarif.ingest import ingest_engine_run
from codekavach.config import Settings
from codekavach.core.models import Candidate, Language
from codekavach.ingest.models import SourceFile

ENGINE_ID: Final = "opengrep"
OUTPUT_FILE: Final = "opengrep.sarif"
DEFAULT_RULE_TIMEOUT_SECONDS: Final = 5
DEFAULT_MAX_TARGET_BYTES: Final = 1_000_000
INSTALL_HINT: Final = (
    "download the release binary for your platform from "
    "https://github.com/opengrep/opengrep/releases and put it on PATH"
)

SPEC: Final = EngineSpec(
    id=ENGINE_ID,
    name="Opengrep",
    languages=frozenset(
        {
            Language.PYTHON,
            Language.JAVASCRIPT,
            Language.TYPESCRIPT,
            Language.JAVA,
            Language.GO,
            Language.PHP,
            Language.CSHARP,
            Language.RUBY,
            Language.C,
            Language.CPP,
        }
    ),
    tier=BuildTier.NO_BUILD,
    output_format="sarif",
    spdx_licence="LGPL-2.1",
    distribution=DistributionMode.CLIENT_INSTALLED,
    hosted_allowed=True,
    scans_proprietary_code=True,
    default_enabled=True,
    homepage="https://github.com/opengrep/opengrep",
    config_filenames=(".semgrepignore", ".opengrepignore", ".semgrep.yml", ".semgrep.yaml"),
    expect_exit_codes=frozenset({0, 1}),
    weight=2,
)


def rule_directories(settings: Settings) -> list[Path]:
    """The rule directories to pass: the operator's ``engines.rule_paths`` that exist."""
    found = [resolve_path(str(path)) for path in settings.engines.rule_paths]
    return [path for path in found if path.is_dir()]


class OpengrepAdapter:
    """Adapter for Opengrep."""

    spec = SPEC

    def probe(self, settings: Settings) -> EngineProbe:
        """Whether the engine is installed, and its version."""
        return probe_version(ENGINE_ID, executable_for(settings, ENGINE_ID, "opengrep"))

    def applies_to(self, languages: Collection[Language], files: Sequence[SourceFile]) -> bool:
        """True when the scan has files in a language the engine handles."""
        return bool(SPEC.languages & set(languages))

    def build_invocation(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> EngineInvocation | None:
        """The engine's process for this scan, or ``None`` when there is nothing to run."""
        rules = rule_directories(settings)
        if not rules:
            return None
        timeout = option_int(
            settings, ENGINE_ID, "rule_timeout_seconds", DEFAULT_RULE_TIMEOUT_SECONDS
        )
        max_bytes = option_int(settings, ENGINE_ID, "max_target_bytes", DEFAULT_MAX_TARGET_BYTES)
        argv = [
            executable_for(settings, ENGINE_ID, "opengrep"),
            "scan",
            f"--sarif-output={OUTPUT_TOKEN}/{OUTPUT_FILE}",
            "--quiet",
            "--taint-intrafile",
            "--no-rewrite-rule-ids",
            f"--timeout={timeout}",
            f"--max-target-bytes={max_bytes}",
        ]
        for directory in rules:
            argv.extend(["--config", str(directory)])
        argv.extend(telemetry_args(ENGINE_ID))
        argv.extend(extra_args(settings, ENGINE_ID))
        argv.append(".")
        return EngineInvocation(
            argv=tuple(argv), output_file=OUTPUT_FILE, expect_exit_codes=SPEC.expect_exit_codes
        )

    def parse(self, run: EngineRun, root: Path) -> Sequence[Candidate]:
        """Candidates from the engine's recorded output."""
        return ingest_engine_run(SPEC, run, root)

    def install_hint(self) -> str:
        """How to install the engine."""
        return INSTALL_HINT
