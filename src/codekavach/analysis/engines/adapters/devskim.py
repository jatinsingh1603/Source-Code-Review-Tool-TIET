"""The DevSkim adapter: Microsoft's pattern analyser with SARIF output (E15-03).

Owning epic: E15. DevSkim (MIT) runs as a separate process (the ``devskim`` .NET tool).
"""

from collections.abc import Sequence
from pathlib import Path
from typing import Final

from codekavach.analysis.engines.adapters.cli_engine import CliAdapter
from codekavach.analysis.engines.base import (
    OUTPUT_TOKEN,
    BuildTier,
    DistributionMode,
    EngineSpec,
)
from codekavach.config import Settings
from codekavach.core.models import Language
from codekavach.ingest.models import SourceFile

ENGINE_ID: Final = "devskim"
OUTPUT_FILE: Final = "devskim.sarif"

SPEC: Final = EngineSpec(
    id=ENGINE_ID,
    name="DevSkim",
    languages=frozenset(
        {
            Language.CSHARP,
            Language.C,
            Language.CPP,
            Language.JAVA,
            Language.JAVASCRIPT,
            Language.TYPESCRIPT,
            Language.PYTHON,
            Language.GO,
            Language.PHP,
            Language.RUBY,
            Language.KOTLIN,
        }
    ),
    tier=BuildTier.NO_BUILD,
    output_format="sarif",
    spdx_licence="MIT",
    distribution=DistributionMode.CLIENT_INSTALLED,
    hosted_allowed=True,
    scans_proprietary_code=True,
    default_enabled=False,
    homepage="https://github.com/microsoft/DevSkim",
    config_filenames=("devskim.json", ".devskim.json"),
    expect_exit_codes=frozenset({0}),
    weight=1,
)


class DevskimAdapter(CliAdapter):
    """Adapter for DevSkim."""

    spec = SPEC
    executable = "devskim"
    hint = "dotnet tool install --global Microsoft.CST.DevSkim.CLI"
    output_file = OUTPUT_FILE

    def options(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> tuple[list[str], list[str]] | None:
        """SARIF to the output directory."""
        return (
            [
                "analyze",
                "-f",
                "sarif",
                "-O",
                f"{OUTPUT_TOKEN}/{OUTPUT_FILE}",
                "--ignore-default-rules=false",
                "-E",
            ],
            ["."],
        )
