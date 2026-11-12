"""The cppcheck adapter: C and C++ checks from the version 2 XML report (E15-03).

Owning epic: E15. cppcheck (GPL-3.0) runs as a separate process and is never imported or linked.
It writes its XML report (``--xml``, version 2) to a file; ``report_to_sarif`` maps
``error/@id``, ``@severity``, ``@cwe``, ``@msg`` and the ``location`` elements to SARIF, and the
common ingestion does the rest. The warning, style, performance and portability checks are enabled;
the repository's own suppressions and project file are hidden by the sandbox's configuration
filter, and CodeKavach passes a suppression for missing system includes only.

The XML comes from the code under audit's build of cppcheck, so it is untrusted: a document type
declaration is refused before parsing and a report over the size limit is refused.
"""

import json
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from codekavach.analysis.engines.adapters.cli_engine import CliAdapter
from codekavach.analysis.engines.base import (
    OUTPUT_TOKEN,
    BuildTier,
    DistributionMode,
    EngineSpec,
)
from codekavach.analysis.engines.sarif.errors import SarifFormatError
from codekavach.config import Settings
from codekavach.core.models import Language
from codekavach.ingest.models import SourceFile

ENGINE_ID: Final = "cppcheck"
OUTPUT_FILE: Final = "cppcheck.xml"
_LEVELS: Final = {
    "error": "error",
    "warning": "warning",
    "style": "note",
    "performance": "note",
    "portability": "note",
    "information": "note",
}

SPEC: Final = EngineSpec(
    id=ENGINE_ID,
    name="cppcheck",
    languages=frozenset({Language.C, Language.CPP}),
    tier=BuildTier.NO_BUILD,
    output_format="xml",
    spdx_licence="GPL-3.0-or-later",
    distribution=DistributionMode.CLIENT_INSTALLED,
    hosted_allowed=True,
    scans_proprietary_code=True,
    default_enabled=True,
    homepage="https://cppcheck.sourceforge.io/",
    config_filenames=("cppcheck.cfg", ".cppcheck", "*.cppcheck", "suppressions.txt"),
    expect_exit_codes=frozenset({0}),
    weight=2,
)


def report_to_sarif(raw: bytes) -> bytes:
    """A cppcheck version 2 XML report as a SARIF 2.1.0 log."""
    head = raw[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in raw.lower():
        raise SarifFormatError(["the cppcheck report declares a document type"])
    try:
        root = ET.fromstring(raw)  # noqa: S314 - DTD refused above
    except ET.ParseError:
        raise SarifFormatError(["the cppcheck report is not valid XML"]) from None
    errors = root.find("errors")
    if root.tag != "results" or errors is None:
        raise SarifFormatError(["the cppcheck report has no errors element"])
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in errors.findall("error"):
        rule_id = item.get("id")
        locations = [loc for loc in item.findall("location") if loc.get("file")]
        if not rule_id or not locations:
            continue
        severity = item.get("severity", "warning")
        properties: dict[str, Any] = {"cppcheck.severity": severity}
        cwe = item.get("cwe")
        if cwe and cwe.isdigit():
            properties["cwe"] = int(cwe)
        if item.get("inconclusive") == "true":
            properties["confidence"] = "low"
        rules.setdefault(rule_id, {"id": rule_id, "name": rule_id})
        sarif_locations = []
        for loc in locations:
            written = loc.get("line") or "1"
            line = max(int(written), 1) if written.isdigit() else 1
            column = loc.get("column", "")
            region: dict[str, int] = {"startLine": line}
            if column.isdigit() and int(column) > 0:
                region["startColumn"] = int(column)
            sarif_locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(loc.get("file"))},
                        "region": region,
                    }
                }
            )
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVELS.get(severity, "warning"),
                "message": {"text": item.get("msg", rule_id)},
                "locations": sarif_locations[:1],
                "relatedLocations": sarif_locations[1:],
                "properties": properties,
            }
        )
    log = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "cppcheck", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    return json.dumps(log).encode("utf-8")


class CppcheckAdapter(CliAdapter):
    """Adapter for cppcheck."""

    spec = SPEC
    executable = "cppcheck"
    hint = "apt install cppcheck  (or: brew install cppcheck)"
    output_file = OUTPUT_FILE

    def options(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> tuple[list[str], list[str]] | None:
        """XML version 2 to the output directory, the warning and style families enabled."""
        return (
            [
                "--xml",
                "--xml-version=2",
                f"--output-file={OUTPUT_TOKEN}/{OUTPUT_FILE}",
                "--enable=warning,style,performance,portability",
                "--inconclusive",
                "--suppress=missingIncludeSystem",
                "--suppress=missingInclude",
                "--quiet",
            ],
            ["."],
        )

    def to_sarif(self, raw: bytes) -> bytes:
        """The XML report as SARIF."""
        return report_to_sarif(raw)
