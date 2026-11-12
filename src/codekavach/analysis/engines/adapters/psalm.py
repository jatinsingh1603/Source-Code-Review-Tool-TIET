"""The Psalm taint adapter: PHP taint analysis with SARIF output (E15-03).

Owning epic: E15. Psalm (MIT) runs as a separate process with ``--taint-analysis`` and writes
SARIF; its data-flow steps arrive as SARIF code flows and become the candidate's taint path
through the common code-flow conversion.

Psalm needs a project configuration (``psalm.xml`` or ``psalm.xml.dist``) and the Composer
autoload directory (``vendor/autoload.php``) so that it can resolve the classes the code uses. The
adapter plans no run without both and the scheduler records the reason; it never runs ``composer``
or reaches a network. The repository's configuration is the one Psalm needs, so unlike the
pattern engines it is not hidden.
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

ENGINE_ID: Final = "psalm-taint"
OUTPUT_FILE: Final = "psalm.sarif"
CONFIG_NAMES: Final = ("psalm.xml", "psalm.xml.dist")
AUTOLOAD: Final = "vendor/autoload.php"

SPEC: Final = EngineSpec(
    id=ENGINE_ID,
    name="Psalm (taint analysis)",
    languages=frozenset({Language.PHP}),
    tier=BuildTier.NO_BUILD,
    output_format="sarif",
    spdx_licence="MIT",
    distribution=DistributionMode.CLIENT_INSTALLED,
    hosted_allowed=True,
    scans_proprietary_code=True,
    default_enabled=True,
    homepage="https://psalm.dev/",
    expect_exit_codes=frozenset({0, 1, 2}),
    weight=3,
)


def prerequisite(root: Path) -> str | None:
    """Why Psalm cannot run at ``root``, or ``None`` when the configuration and autoload exist."""
    if not any((root / name).is_file() for name in CONFIG_NAMES):
        return "no psalm.xml: run `psalm --init` in the project"
    if not (root / AUTOLOAD).is_file():
        return "no vendor/autoload.php: run `composer install` before the scan"
    return None


class PsalmAdapter(CliAdapter):
    """Adapter for Psalm taint analysis."""

    spec = SPEC
    executable = "psalm"
    hint = "composer require --dev vimeo/psalm  (the project needs psalm.xml and vendor/)"
    output_file = OUTPUT_FILE

    def options(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> tuple[list[str], list[str]] | None:
        """Taint analysis only, SARIF to the output directory, no cache and no network."""
        if prerequisite(root) is not None:
            return None
        return (
            [
                "--taint-analysis",
                f"--report={OUTPUT_TOKEN}/{OUTPUT_FILE}",
                "--no-progress",
                "--no-cache",
                "--threads=1",
                "--no-suggestions",
            ],
            [],
        )
