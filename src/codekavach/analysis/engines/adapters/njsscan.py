"""The njsscan adapter: Node.js security patterns with SARIF output (E15-02).

Owning epic: E15. njsscan (LGPL-3.0) runs as a separate process and writes SARIF.
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

ENGINE_ID: Final = "njsscan"
OUTPUT_FILE: Final = "njsscan.sarif"

SPEC: Final = EngineSpec(
    id=ENGINE_ID,
    name="njsscan",
    languages=frozenset({Language.JAVASCRIPT, Language.TYPESCRIPT}),
    tier=BuildTier.NO_BUILD,
    output_format="sarif",
    spdx_licence="LGPL-3.0-or-later",
    distribution=DistributionMode.CLIENT_INSTALLED,
    hosted_allowed=True,
    scans_proprietary_code=True,
    default_enabled=False,
    homepage="https://github.com/ajinabraham/njsscan",
    config_filenames=(".njsscan", ".semgrepignore"),
    expect_exit_codes=frozenset({0, 1}),
    weight=2,
)


class NjsscanAdapter(CliAdapter):
    """Adapter for njsscan."""

    spec = SPEC
    executable = "njsscan"
    hint = "pip install njsscan"
    output_file = OUTPUT_FILE

    def options(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> tuple[list[str], list[str]] | None:
        """SARIF to the output directory."""
        return (["--sarif", "-o", f"{OUTPUT_TOKEN}/{OUTPUT_FILE}"], ["."])
