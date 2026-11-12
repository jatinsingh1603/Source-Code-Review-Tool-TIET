"""The ESLint security adapter: ESLint with the security rule set (E15-01).

Owning epic: E15. ESLint (MIT) runs as a separate Node process and is never imported.

* The configuration is CodeKavach's own flat config (``data/eslint/codekavach.flat.config.mjs``),
  copied into the tools directory so it can resolve the plugins installed there. The scanned
  repository's configuration is not loaded: ``--no-config-lookup`` and ``--no-inline-config`` are
  passed, and the repository's ESLint configuration files are hidden from the view. The two controls
  are deliberately redundant, because a repository-supplied configuration can run arbitrary code.
* ESLint and the plugins live in a CodeKavach-owned directory (``tools_dir``), not in the client's
  ``node_modules``. ``tools_dir`` is a restricted setting, so an untrusted project cannot point it
  at a directory of its own.
* Only JavaScript files are linted. TypeScript needs a parser plugin this rule set does not include.
* ``eslint-plugin-no-unsanitized`` is MPL-2.0, a file-level copyleft; it is installed unmodified
  from npm and none of its files is copied here.
* ESLint documents no telemetry; ``DO_NOT_TRACK`` is passed from the manifest as defence in depth.

ESLint's JSON report is converted to SARIF in memory for ``ingest_sarif``. Severity 2 maps to a
medium finding and 1 to a low one, because the rules are heuristics, and every ``security/`` rule
gets low confidence. Parse errors (no rule id) are counted and left out; the report's ``source``
field, which holds the client's code, is not read.
"""

import json
import shutil
from collections.abc import Collection, Sequence
from pathlib import Path
from typing import Any, Final

import platformdirs

from codekavach.analysis.engines.adapters.common import (
    executable_for,
    extra_args,
    files_in,
    option_int,
    option_text,
    resolve_path,
    telemetry_args,
    unavailable,
    version_in,
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
from codekavach.analysis.engines.sarif.errors import SarifFormatError
from codekavach.analysis.engines.sarif.ingest import IngestOptions, ingest_sarif
from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.core.models import Candidate, Language
from codekavach.ingest.models import SourceFile

ENGINE_ID: Final = "eslint-security"
OUTPUT_FILE: Final = "eslint.json"
CONFIG_NAME: Final = "codekavach.flat.config.mjs"
CONFIG_SOURCE: Final = Path(__file__).resolve().parents[1] / "data" / "eslint" / CONFIG_NAME
DEFAULT_MAX_FILES: Final = 5000
MAX_REPORT_BYTES: Final = 64 * 1024 * 1024
PLUGINS: Final = ("eslint", "eslint-plugin-security", "eslint-plugin-no-unsanitized")
INSTALL_HINT: Final = (
    "install Node.js, then in the CodeKavach tools directory run: "
    "npm install eslint eslint-plugin-security eslint-plugin-no-unsanitized "
    "(the directory is shown by `codekavach doctor`)"
)
_LEVELS: Final = {2: "warning", 1: "note"}

SPEC: Final = EngineSpec(
    id=ENGINE_ID,
    name="ESLint with the security rule set",
    languages=frozenset({Language.JAVASCRIPT, Language.TYPESCRIPT}),
    tier=BuildTier.NO_BUILD,
    output_format="json",
    spdx_licence="MIT",
    distribution=DistributionMode.CLIENT_INSTALLED,
    hosted_allowed=True,
    scans_proprietary_code=True,
    default_enabled=True,
    homepage="https://eslint.org/",
    config_filenames=(
        "eslint.config.js",
        "eslint.config.mjs",
        "eslint.config.cjs",
        "eslint.config.ts",
        "eslint.config.mts",
        "eslint.config.cts",
        ".eslintrc",
        ".eslintrc.js",
        ".eslintrc.cjs",
        ".eslintrc.json",
        ".eslintrc.yml",
        ".eslintrc.yaml",
        ".eslintignore",
    ),
    expect_exit_codes=frozenset({0, 1}),
    weight=4,
)
_log = get_logger(__name__)


def tools_dir(settings: Settings) -> Path:
    """The CodeKavach-owned directory that holds ESLint and its plugins."""
    chosen = option_text(settings, ENGINE_ID, "tools_dir")
    if chosen:
        return resolve_path(chosen)
    return platformdirs.user_data_path("codekavach", appauthor=False) / "tools" / "eslint"


def _package_version(directory: Path, package: str) -> str | None:
    try:
        data = json.loads((directory / "node_modules" / package / "package.json").read_bytes())
    except (OSError, ValueError):
        return None
    version = data.get("version") if isinstance(data, dict) else None
    return version_in(version) if isinstance(version, str) else None


def install_config(directory: Path) -> Path:
    """Copy the flat config next to the plugins (only when it differs) and return its path."""
    target = directory / CONFIG_NAME
    wanted = CONFIG_SOURCE.read_bytes()
    if not target.is_file() or target.read_bytes() != wanted:
        directory.mkdir(parents=True, exist_ok=True)
        target.write_bytes(wanted)
    return target


def report_to_sarif(report: object) -> tuple[bytes, int]:
    """ESLint's JSON report as a SARIF log, and the number of parse errors left out."""
    if not isinstance(report, list):
        raise SarifFormatError(["the ESLint report is not a list of files"])
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    fatal = 0
    for entry in report:
        if not isinstance(entry, dict) or not isinstance(entry.get("messages"), list):
            raise SarifFormatError(["an ESLint report entry has no messages list"])
        for message in entry["messages"]:
            rule_id = message.get("ruleId") if isinstance(message, dict) else None
            if not rule_id:
                fatal += 1
                continue
            rules.setdefault(rule_id, {"id": rule_id})
            region = {
                key: message[source]
                for key, source in (
                    ("startLine", "line"),
                    ("startColumn", "column"),
                    ("endLine", "endLine"),
                    ("endColumn", "endColumn"),
                )
                if isinstance(message.get(source), int)
            }
            properties: dict[str, Any] = {}
            if rule_id.startswith("security/"):
                properties["confidence"] = "low"
            results.append(
                {
                    "ruleId": rule_id,
                    "level": _LEVELS.get(message.get("severity"), "warning"),
                    "message": {"text": str(message.get("message", ""))},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": str(entry.get("filePath", ""))},
                                "region": region,
                            }
                        }
                    ],
                    "properties": properties,
                }
            )
    run = {
        "tool": {"driver": {"name": "eslint", "rules": list(rules.values())}},
        "columnKind": "utf16CodeUnits",
        "results": results,
    }
    return json.dumps({"version": "2.1.0", "runs": [run]}).encode("utf-8"), fatal


class EslintSecurityAdapter:
    """Adapter for ESLint with the security rule set."""

    spec = SPEC

    def probe(self, settings: Settings) -> EngineProbe:
        """Whether the engine is installed, and its version."""
        node = shutil.which(executable_for(settings, ENGINE_ID, "node"))
        if node is None:
            return unavailable(ENGINE_ID, "Node.js is not installed")
        directory = tools_dir(settings)
        for package in PLUGINS:
            if _package_version(directory, package) is None:
                return unavailable(ENGINE_ID, f"{package} is not installed in the tools directory")
        return EngineProbe(
            ENGINE_ID,
            available=True,
            version=_package_version(directory, "eslint"),
            path=node,
            reason=None,
        )

    def applies_to(self, languages: Collection[Language], files: Sequence[SourceFile]) -> bool:
        """True when the scan has files in a language the engine handles."""
        return bool(SPEC.languages & set(languages))

    def build_invocation(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> EngineInvocation | None:
        """The engine's process for this scan, or ``None`` when there is nothing to run."""
        scripts = files_in(files, SPEC.languages)
        if not scripts:
            return None
        directory = tools_dir(settings)
        config = install_config(directory)
        limit = option_int(settings, ENGINE_ID, "max_files", DEFAULT_MAX_FILES)
        targets = ["."]
        if len(scripts) > limit:
            targets = sorted(item.path for item in scripts)[:limit]
            _log.warning("eslint_files_truncated", found=len(scripts), linted=limit)
        argv = [
            executable_for(settings, ENGINE_ID, "node"),
            str(directory / "node_modules" / "eslint" / "bin" / "eslint.js"),
            "--no-config-lookup",
            "-c",
            str(config),
            "--no-inline-config",
            "--no-warn-ignored",
            "-f",
            "json",
            "-o",
            f"{OUTPUT_TOKEN}/{OUTPUT_FILE}",
            *telemetry_args(ENGINE_ID),
            *extra_args(settings, ENGINE_ID),
            *targets,
        ]
        return EngineInvocation(
            argv=tuple(argv), output_file=OUTPUT_FILE, expect_exit_codes=SPEC.expect_exit_codes
        )

    def parse(self, run: EngineRun, root: Path) -> Sequence[Candidate]:
        """Candidates from the engine's recorded output."""
        if run.output_path is None:
            raise SarifFormatError(["the engine wrote no output file"])
        if run.output_path.stat().st_size > MAX_REPORT_BYTES:
            raise SarifFormatError(["the ESLint report is too large"])
        try:
            report = json.loads(run.output_path.read_bytes())
        except ValueError:
            raise SarifFormatError(["the ESLint report is not valid JSON"]) from None
        data, fatal = report_to_sarif(report)
        if fatal:
            _log.warning("eslint_parse_errors", files=fatal)
        return ingest_sarif(
            data,
            engine_id=ENGINE_ID,
            root=root,
            engine_version=run.version or None,
            options=IngestOptions(default_kind=SPEC.default_kind),
        )

    def install_hint(self) -> str:
        """How to install the engine."""
        return INSTALL_HINT
