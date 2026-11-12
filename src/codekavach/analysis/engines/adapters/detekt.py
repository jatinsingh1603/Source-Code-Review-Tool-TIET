"""The detekt adapter: the Kotlin static analyser (E15-02).

Owning epic: E15. detekt (Apache-2.0) runs as a separate process through its command-line
distribution and writes SARIF. Its configuration is CodeKavach's own (``data/detekt/``), passed
with ``--config``; the repository's ``detekt.yml`` and baseline are hidden from it.

detekt is a style and bug-pattern analyser with few security rules, so its security value is
limited: every candidate it raises defaults to low confidence, which the severity table of the
engine states (``data/severity_map.toml``), and it is a cross-check beside the pattern engines.
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

ENGINE_ID: Final = "detekt"
OUTPUT_FILE: Final = "detekt.sarif"
CONFIG_FILE: Final = Path(__file__).resolve().parents[1] / "data" / "detekt" / "codekavach.yml"

SPEC: Final = EngineSpec(
    id=ENGINE_ID,
    name="detekt",
    languages=frozenset({Language.KOTLIN}),
    tier=BuildTier.NO_BUILD,
    output_format="sarif",
    spdx_licence="Apache-2.0",
    distribution=DistributionMode.CLIENT_INSTALLED,
    hosted_allowed=True,
    scans_proprietary_code=True,
    default_enabled=True,
    homepage="https://detekt.dev/",
    config_filenames=("detekt.yml", "detekt-baseline.xml", "detekt-config.yml"),
    expect_exit_codes=frozenset({0, 2}),
    weight=1,
)


class DetektAdapter(CliAdapter):
    """Adapter for detekt."""

    spec = SPEC
    executable = "detekt-cli"
    hint = (
        "download detekt-cli from https://github.com/detekt/detekt/releases "
        "and put detekt-cli on PATH (needs a JRE)"
    )
    output_file = OUTPUT_FILE

    def options(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> tuple[list[str], list[str]] | None:
        """CodeKavach's configuration on top of the defaults, SARIF to the output directory."""
        return (
            [
                "--config",
                str(CONFIG_FILE),
                "--build-upon-default-config",
                "--report",
                f"sarif:{OUTPUT_TOKEN}/{OUTPUT_FILE}",
                "--parallel",
            ],
            ["--input", "."],
        )
