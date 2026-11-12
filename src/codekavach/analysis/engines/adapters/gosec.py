"""The gosec adapter: the Go security checker (E15-02).

Owning epic: E15. gosec (Apache-2.0) runs as a separate process and writes SARIF; it is never
imported. It reads the Go module at the scan root (``./...``), skips generated files and, with
``-no-fail``, exits zero whenever the run completed, so the exit code means completion.

Degraded mode (not implemented, recorded here so the report can say so): when package loading
fails because modules are not vendored and the sandbox has no network, gosec still reports from
the syntax tree alone and a build-aware retry is not attempted. The Go files the engine could not
type-check are named in its own stderr, which the run keeps.
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

ENGINE_ID: Final = "gosec"
OUTPUT_FILE: Final = "gosec.sarif"

SPEC: Final = EngineSpec(
    id=ENGINE_ID,
    name="gosec",
    languages=frozenset({Language.GO}),
    tier=BuildTier.NO_BUILD,
    output_format="sarif",
    spdx_licence="Apache-2.0",
    distribution=DistributionMode.CLIENT_INSTALLED,
    hosted_allowed=True,
    scans_proprietary_code=True,
    default_enabled=True,
    homepage="https://github.com/securego/gosec",
    config_filenames=(".gosec.json", "gosec.json"),
    expect_exit_codes=frozenset({0}),
    weight=2,
)


class GosecAdapter(CliAdapter):
    """Adapter for gosec."""

    spec = SPEC
    executable = "gosec"
    hint = "go install github.com/securego/gosec/v2/cmd/gosec@latest  (or: brew install gosec)"
    output_file = OUTPUT_FILE
    version_args = ("-version",)

    def options(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> tuple[list[str], list[str]] | None:
        """Scan the module at the root; SARIF to the output directory; never fail the run."""
        return (
            [
                "-fmt=sarif",
                f"-out={OUTPUT_TOKEN}/{OUTPUT_FILE}",
                "-no-fail",
                "-quiet",
                "-exclude-generated",
            ],
            ["./..."],
        )
