"""``AnalyseIacStage``: native configuration review as candidates (E20, issue 239).

Dispatches each file by name and content to a checker (Dockerfile, docker-compose, Kubernetes,
Terraform, GitHub Actions, application config) and publishes one ``misconfiguration`` candidate per
issue as this stage's part of ``candidates.raw``. Messages are fixed text: they never quote the
file's values. ``engines.native.iac = false`` disables the stage.
"""

import re
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import Final

from codekavach.analysis.iac.actions import check_workflow
from codekavach.analysis.iac.appconfig import check_appconfig, is_config_path
from codekavach.analysis.iac.common import Issue
from codekavach.analysis.iac.docker import check_compose, check_dockerfile, compose_like
from codekavach.analysis.iac.k8s import check_k8s, is_manifest
from codekavach.analysis.iac.terraform import check_terraform
from codekavach.core.log import get_logger
from codekavach.core.models import Candidate, Language, Location
from codekavach.core.models.enums import CandidateKind
from codekavach.core.models.fingerprint import FingerprintParts, fingerprint_batch, snippet_hash
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.stage import StageCategory
from codekavach.ingest.models import SourceFile

IAC_ENGINE: Final = "codekavach-iac"
MAX_FILE_BYTES: Final = 1_000_000
_log = get_logger("codekavach.analysis.iac")
_COMPOSE_NAME: Final = re.compile(r"(^|/)(docker-)?compose[\w.-]*\.ya?ml$", re.I)
_WORKFLOW: Final = re.compile(r"(^|/)\.github/(workflows|actions)/[^/]+\.ya?ml$", re.I)
_YAML: Final = re.compile(r"\.ya?ml$", re.I)

Checker = Callable[[str], list[Issue]]


def checkers_for(path: str, text: str) -> list[Checker]:
    """The checkers that apply to ``path``; content decides only for ambiguous YAML."""
    name = PurePosixPath(path).name.lower()
    found: list[Checker] = []
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        found.append(check_dockerfile)
    elif name.endswith(".tf"):
        found.append(check_terraform)
    elif _WORKFLOW.search(path):
        found.append(check_workflow)
    elif _YAML.search(name):
        if _COMPOSE_NAME.search(path) or compose_like(text):
            found.append(check_compose)
        elif is_manifest(text):
            found.append(check_k8s)
    if is_config_path(path) and not name.startswith("dockerfile") and not name.endswith(".tf"):
        found.append(check_appconfig)
    return found


def candidates_for(
    path: str, language: Language, text: str, issues: list[Issue]
) -> list[Candidate]:
    """Candidates for ``issues`` found in ``text``, deduplicated by rule and line."""
    lines = text.splitlines()
    unique = {(i.rule, i.line): i for i in issues}
    ordered = sorted(unique.values(), key=lambda i: (i.line, i.rule))
    parts = [
        FingerprintParts(
            engine=IAC_ENGINE,
            rule_id=issue.rule,
            path=path,
            snippet_hash=snippet_hash(lines[issue.line - 1 : issue.line] or [""]),
            start_line=issue.line,
        )
        for issue in ordered
    ]
    found: list[Candidate] = []
    for issue, fingerprint in zip(ordered, fingerprint_batch(parts), strict=True):
        last = max(1, len(lines))
        start = min(max(1, issue.line), last)
        found.append(
            Candidate.create(
                rule_id=issue.rule,
                engine=IAC_ENGINE,
                engine_version="1",
                cwe=(issue.cwe,),
                locations=(Location(path=path, start_line=start, end_line=start),),
                engine_severity=issue.severity,
                engine_confidence=issue.confidence,
                fingerprint=fingerprint,
                kind=CandidateKind.MISCONFIGURATION,
                language=language,
                message=issue.message,
            )
        )
    return found


class AnalyseIacStage:
    """Reviews Dockerfiles, compose files, manifests, Terraform, workflows and app config."""

    name = "analyse-iac"
    version = "1"
    requires = frozenset({keys.FILES})
    provides = frozenset({keys.CANDIDATES_RAW})
    category = StageCategory.ANALYSE

    def run(self, ctx: RunContext) -> None:
        """Publish this stage's part of ``candidates.raw``."""
        if not ctx.config.engines.native.iac:
            ctx.artefacts.put_part(keys.CANDIDATES_RAW, self.name, [])
            return
        files = sorted(ctx.artefacts.get_list(keys.FILES, SourceFile), key=lambda f: f.path)
        found: list[Candidate] = []
        for file in files:
            ctx.check_cancelled()
            if file.is_vendored or file.is_minified or file.size_bytes > MAX_FILE_BYTES:
                continue
            try:
                text = (
                    (ctx.source_root / file.path)
                    .read_bytes()
                    .decode(file.encoding or "utf-8", errors="replace")
                )
            except (OSError, LookupError):
                ctx.fail_item(f"file:{file.sha256[:16]}", "unreadable")
                continue
            for checker in checkers_for(file.path, text):
                try:
                    issues = checker(text)
                except Exception:  # noqa: BLE001 - a malformed file must not lose the others
                    _log.warning("iac_check_failed", file=file.sha256[:16])
                    ctx.fail_item(f"file:{file.sha256[:16]}", "check_failed")
                    continue
                found.extend(candidates_for(file.path, file.language, text, issues))
        ctx.artefacts.put_part(keys.CANDIDATES_RAW, self.name, found)
