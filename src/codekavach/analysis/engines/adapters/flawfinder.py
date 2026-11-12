"""The flawfinder adapter: a lexical C and C++ scanner (E15-03).

Owning epic: E15. flawfinder (GPL-2.0) runs as a separate process and is never imported or
linked, which keeps the GPL out of CodeKavach. It prints SARIF on standard output.

It is deliberately kept as a high-recall, high-noise engine: it matches dangerous function names
(``strcpy``, ``system``, ``sprintf``) without understanding the code, so a candidate it raises is
a lead and never a finding. Its risk level (0 to 5) maps to a severity capped at medium, and every
candidate carries confidence ``low``. It is the triage stress case the reasoning layer is measured
against. ``--neverignore`` disables the ``// flawfinder: ignore`` comments of the code under audit.
"""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from codekavach.analysis.engines.adapters.cli_engine import CliAdapter
from codekavach.analysis.engines.base import BuildTier, DistributionMode, EngineSpec
from codekavach.analysis.engines.sarif.errors import SarifFormatError
from codekavach.config import Settings
from codekavach.core.models import Language
from codekavach.ingest.models import SourceFile

ENGINE_ID: Final = "flawfinder"
OUTPUT_FILE: Final = "flawfinder.sarif"

SPEC: Final = EngineSpec(
    id=ENGINE_ID,
    name="flawfinder",
    languages=frozenset({Language.C, Language.CPP}),
    tier=BuildTier.NO_BUILD,
    output_format="sarif",
    spdx_licence="GPL-2.0-or-later",
    distribution=DistributionMode.CLIENT_INSTALLED,
    hosted_allowed=True,
    scans_proprietary_code=True,
    default_enabled=False,
    homepage="https://dwheeler.com/flawfinder/",
    expect_exit_codes=frozenset({0, 1}),
    weight=1,
)


def fix_confidence(raw: bytes) -> bytes:
    """Stamp ``confidence: low`` on every result: the analysis is lexical."""
    try:
        log = json.loads(raw)
    except ValueError:
        raise SarifFormatError(["the flawfinder report is not valid JSON"]) from None
    if not isinstance(log, dict):
        raise SarifFormatError(["the flawfinder report is not a JSON object"])
    runs: Any = log.get("runs")
    for run in runs if isinstance(runs, list) else []:
        results = run.get("results") if isinstance(run, dict) else None
        for result in results if isinstance(results, list) else []:
            if isinstance(result, dict):
                properties = result.setdefault("properties", {})
                if isinstance(properties, dict):
                    properties["confidence"] = "low"
    return json.dumps(log).encode("utf-8")


class FlawfinderAdapter(CliAdapter):
    """Adapter for flawfinder."""

    spec = SPEC
    executable = "flawfinder"
    hint = "pipx install flawfinder  (or: pip install flawfinder)"
    output_file = OUTPUT_FILE
    stdout_is_output = True

    def options(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> tuple[list[str], list[str]] | None:
        """SARIF on standard output, the annotations of the audited code ignored, no context."""
        return (["--sarif", "--quiet", "--dataonly", "--neverignore", "--minlevel=1"], ["."])

    def to_sarif(self, raw: bytes) -> bytes:
        """The engine's SARIF with the fixed low confidence stamped on."""
        return fix_confidence(raw)
