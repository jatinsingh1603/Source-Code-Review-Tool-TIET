"""The Semgrep Community Edition adapter (E15-03).

Owning epic: E15. Semgrep CE (LGPL-2.1) runs as a separate process and writes SARIF. Only rule
files named in ``engines.rule_paths`` are used: no registry rule is fetched, metrics are off, and
version checks are disabled, so the run needs no network. With no rule path configured the engine
is not planned.
"""

from collections.abc import Sequence
from pathlib import Path
from typing import Final

from codekavach.analysis.engines.adapters.cli_engine import CliAdapter
from codekavach.analysis.engines.adapters.common import resolve_path
from codekavach.analysis.engines.base import (
    OUTPUT_TOKEN,
    BuildTier,
    DistributionMode,
    EngineSpec,
)
from codekavach.config import Settings
from codekavach.core.models import Language
from codekavach.ingest.models import SourceFile

ENGINE_ID: Final = "semgrep-ce"
OUTPUT_FILE: Final = "semgrep.sarif"

SPEC: Final = EngineSpec(
    id=ENGINE_ID,
    name="Semgrep CE",
    languages=frozenset(
        {
            Language.PYTHON,
            Language.JAVASCRIPT,
            Language.TYPESCRIPT,
            Language.JAVA,
            Language.GO,
            Language.RUBY,
            Language.PHP,
            Language.KOTLIN,
            Language.CSHARP,
            Language.C,
            Language.CPP,
        }
    ),
    tier=BuildTier.NO_BUILD,
    output_format="sarif",
    spdx_licence="LGPL-2.1-only",
    distribution=DistributionMode.CLIENT_INSTALLED,
    hosted_allowed=True,
    scans_proprietary_code=True,
    default_enabled=False,
    homepage="https://semgrep.dev/",
    config_filenames=(".semgrep.yml", ".semgrepignore", ".semgrep"),
    expect_exit_codes=frozenset({0, 1}),
    weight=3,
    min_memory_mb=16384,
)


class SemgrepCeAdapter(CliAdapter):
    """Adapter for Semgrep CE with operator-supplied rules."""

    spec = SPEC
    executable = "semgrep"
    hint = "pipx install semgrep  and set engines.rule_paths to your rule files"
    output_file = OUTPUT_FILE

    def options(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> tuple[list[str], list[str]] | None:
        """Rules only from ``engines.rule_paths``; offline, metrics off."""
        rule_paths = [str(resolve_path(str(p))) for p in settings.engines.rule_paths]
        if not rule_paths:
            return None
        options = ["scan", "--sarif", f"--output={OUTPUT_TOKEN}/{OUTPUT_FILE}"]
        for rule in rule_paths:
            options += ["--config", rule]
        options += [
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            "--no-git-ignore",
            "--timeout=30",
        ]
        return options, ["."]
