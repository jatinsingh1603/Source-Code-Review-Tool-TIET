"""The Brakeman adapter: the Rails security scanner (E15-02).

Owning epic: E15. Brakeman runs as a separate process and writes SARIF; it is never imported.
It analyses a Rails application, so it is planned only when the scan root holds one
(``config/application.rb``). Its licence is the Brakeman Public Use License, which is free for the
analysis of code but is not an open-source licence and restricts using it as part of a product, so
CodeKavach never bundles it: it is client-installed, off by default and gated by a licence
attestation (``scans_proprietary_code`` is false until the operator attests).
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

ENGINE_ID: Final = "brakeman"
OUTPUT_FILE: Final = "brakeman.sarif"

SPEC: Final = EngineSpec(
    id=ENGINE_ID,
    name="Brakeman",
    languages=frozenset({Language.RUBY}),
    tier=BuildTier.NO_BUILD,
    output_format="sarif",
    spdx_licence="LicenseRef-Brakeman-Public-Use",
    distribution=DistributionMode.CLIENT_INSTALLED,
    hosted_allowed=False,
    scans_proprietary_code=False,
    default_enabled=False,
    homepage="https://brakemanscanner.org/",
    config_filenames=("brakeman.ignore", "brakeman.yml"),
    expect_exit_codes=frozenset({0}),
    weight=2,
)


def is_rails_app(root: Path) -> bool:
    """Whether ``root`` holds a Rails application."""
    return (root / "config" / "application.rb").is_file()


class BrakemanAdapter(CliAdapter):
    """Adapter for Brakeman."""

    spec = SPEC
    executable = "brakeman"
    hint = "gem install brakeman  (client-installed; see the Brakeman Public Use License)"
    output_file = OUTPUT_FILE

    def options(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> tuple[list[str], list[str]] | None:
        """Quiet SARIF output; the exit status reports completion, never findings."""
        if not is_rails_app(root):
            return None
        return (
            [
                "--quiet",
                "--no-pager",
                "--no-progress",
                "--format",
                "sarif",
                "--output",
                f"{OUTPUT_TOKEN}/{OUTPUT_FILE}",
                "--no-exit-on-warn",
                "--no-exit-on-error",
                "--force-scan",
            ],
            ["."],
        )
