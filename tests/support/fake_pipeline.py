"""A fake default pipeline, registered through real entry points (E04-31).

One fake stage per default stage name plus three analysis stages. The stages are deterministic
and data-driven: what they write depends only on the files of the target, on the artefacts they
read and, for ``privacy-prepare``, on the fingerprint of the scan salt. Artefacts are JSON-shaped
(or a small local model for the parts of ``candidates.raw``), so nothing here depends on the E02
models. Later epics (CLI tests, the thin-slice bring-up, the server) reuse this pipeline until
real stages exist.

Usage::

    def test_scan(fake_site: Path, tmp_path: Path) -> None:
        install_fake_pipeline(fake_site)  # or variant="privacy-raises"
        repo = write_fake_repo(tmp_path / "repo")
        loaded = load_settings(target=repo, env={"CODEKAVACH_HOME": str(tmp_path / "home")})
        outcome = run_scan(loaded, str(repo), salt=ScanSalt.generate(), registry=fake_registry())
        store = OnDiskArtefactStore.open_existing(StateLayout(outcome.state_dir), outcome.scan.id)
        digests = snapshot_digests(store)

Variants replace or add one stage: ``privacy-raises``, ``privacy-item-failures``,
``engine-times-out``, ``llm-reads-files`` (the plan must be rejected) and
``uncategorised-stage-fails``. Call ``reset_fake_pipeline()`` before a test that reads ``CALLS``.
"""

import hashlib
import time
from collections import Counter
from pathlib import Path
from typing import ClassVar, Final

from pydantic import BaseModel, JsonValue

from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.manifest import ScanManifest
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.plugins.discovery import discover
from codekavach.core.plugins.registry import PluginRegistry
from codekavach.core.store.base import ArtefactStore
from tests.support.pipeline import write_fake_distribution

DIST_NAME: Final = "ck-fake-pipeline"
MODULE: Final = "tests.support.fake_pipeline"
STAGES_GROUP: Final = "codekavach.stages"
ITEM_ERROR_CODE: Final = "redaction_failed"
SLOW_SECONDS: Final = 5.0
SLEEP_SLICE_SECONDS: Final = 0.01

FAKE_REPO_FILES: Final[dict[str, str]] = {
    "app/main.py": (
        "from app.db import find_owner\n\n\ndef handler(owner):\n    return find_owner(owner)\n"
    ),
    "app/db.py": (
        'def find_owner(owner):\n    return "SELECT * FROM accounts WHERE owner = " + owner\n'
    ),
    "app/settings.py": 'SERVICE_NAME = "kavach-demo"\nTIMEOUT_SECONDS = 30\n',
}

CALLS: Counter[str] = Counter()
SEEN_PAYLOADS: list[int] = []
PARTIAL_MANIFESTS: list[ScanManifest] = []
DELAYS: dict[str, float] = {}


def reset_fake_pipeline() -> None:
    """Forget the calls, payload counts, manifests and delays recorded so far."""
    CALLS.clear()
    SEEN_PAYLOADS.clear()
    PARTIAL_MANIFESTS.clear()
    DELAYS.clear()


class FakeCandidate(BaseModel):
    """One candidate of a fake analysis stage."""

    id: str
    rule: str
    path: str
    file_sha256: str


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rows(value: JsonValue) -> list[dict[str, JsonValue]]:
    """The JSON objects of a list artefact."""
    items = value if isinstance(value, list) else []
    return [item for item in items if isinstance(item, dict)]


class FakeStageBase:
    """Counts its calls, honours ``DELAYS`` and cancellation, then does its work."""

    name: ClassVar[str]
    requires: ClassVar[frozenset[str]]
    provides: ClassVar[frozenset[str]]
    optional_requires: ClassVar[frozenset[str]] = frozenset()
    category: ClassVar[StageCategory | None]
    version: ClassVar[str] = "1"
    sleep_seconds: ClassVar[float] = 0.0

    def run(self, ctx: RunContext) -> None:
        """Run the stage."""
        CALLS[self.name] += 1
        deadline = time.monotonic() + self.sleep_seconds + DELAYS.get(self.name, 0.0)
        while (left := deadline - time.monotonic()) > 0:
            time.sleep(min(SLEEP_SLICE_SECONDS, left))
            ctx.check_cancelled()
        self.work(ctx)

    def work(self, ctx: RunContext) -> None:
        """Read the inputs and write the outputs."""
        raise NotImplementedError


class Ingest(FakeStageBase):
    """Hashes the Python files of the target directory into ``files``."""

    name = "ingest"
    requires = frozenset({keys.TARGET})
    provides = frozenset({keys.FILES, keys.LANGUAGES})
    category = StageCategory.INGEST

    def work(self, ctx: RunContext) -> None:
        target = ctx.artefacts.get_json(keys.TARGET)
        root = Path(str(target["target"])) if isinstance(target, dict) else Path()
        files: list[JsonValue] = []
        for path in sorted(root.rglob("*.py")):
            relative = path.relative_to(root)
            if any(part.startswith(".") for part in relative.parts):
                continue
            data = path.read_bytes()
            files.append(
                {
                    "path": relative.as_posix(),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
            )
        ctx.artefacts.put(keys.FILES, files)
        ctx.artefacts.put(keys.LANGUAGES, ["python"])


class Parse(FakeStageBase):
    """Provides a transient ``ast`` and persisted ``symbols`` and ``callgraph``."""

    name = "parse"
    requires = frozenset({keys.FILES, keys.LANGUAGES})
    provides = frozenset({keys.AST, keys.SYMBOLS, keys.CALL_GRAPH})
    transient_provides = frozenset({keys.AST})
    category = StageCategory.PARSE

    def work(self, ctx: RunContext) -> None:
        files = _rows(ctx.artefacts.get_json(keys.FILES))
        ctx.artefacts.put(keys.AST, {str(file["path"]): object() for file in files}, persist=False)
        symbols: list[JsonValue] = [
            {"path": file["path"], "symbol": f"sym_{str(file['sha256'])[:8]}"} for file in files
        ]
        ctx.artefacts.put(keys.SYMBOLS, symbols)
        ctx.artefacts.put(keys.CALL_GRAPH, [str(file["path"]) for file in files])


class _Analyse(FakeStageBase):
    """Emits one candidate per file, derived from the file hash, as its part of the raw list."""

    requires = frozenset({keys.FILES, keys.SYMBOLS})
    provides = frozenset({keys.CANDIDATES_RAW})
    category = StageCategory.ANALYSE
    rule: ClassVar[str]

    def work(self, ctx: RunContext) -> None:
        candidates = [
            FakeCandidate(
                id=f"cand_{self.rule}_{str(file['sha256'])[:12]}",
                rule=self.rule,
                path=str(file["path"]),
                file_sha256=str(file["sha256"]),
            )
            for file in _rows(ctx.artefacts.get_json(keys.FILES))
        ]
        ctx.artefacts.put_part(keys.CANDIDATES_RAW, self.name, candidates)


class AnalyseRules(_Analyse):
    name = "analyse-rules"
    rule = "rules"


class AnalyseTaint(_Analyse):
    name = "analyse-taint"
    rule = "taint"


class AnalyseSecrets(_Analyse):
    name = "analyse-secrets"
    rule = "secrets"


class AnalyseTaintSlow(AnalyseTaint):
    """Variant ``engine-times-out``: sleeps longer than the test's stage timeout."""

    sleep_seconds = SLOW_SECONDS


class Aggregate(FakeStageBase):
    """Concatenates the parts in the order ``get_parts`` returns them (part-name order)."""

    name = "aggregate"
    requires = frozenset({keys.CANDIDATES_RAW})
    provides = frozenset({keys.CANDIDATES})
    category = StageCategory.AGGREGATE

    def work(self, ctx: RunContext) -> None:
        parts = ctx.artefacts.get_parts(keys.CANDIDATES_RAW, FakeCandidate)
        candidates: list[JsonValue] = [
            candidate.model_dump() for part in parts.values() for candidate in part
        ]
        ctx.artefacts.put(keys.CANDIDATES, candidates)


class PrivacyPrepare(FakeStageBase):
    """Derives a payload text per candidate from its id and the fingerprint of the scan salt."""

    name = "privacy-prepare"
    requires = frozenset({keys.CANDIDATES, keys.FILES})
    optional_requires = frozenset({keys.AST, keys.SYMBOLS, keys.CALL_GRAPH})
    provides = frozenset({keys.PAYLOADS_SANITISED})
    category = StageCategory.PRIVACY
    fail_first_item: ClassVar[bool] = False

    def work(self, ctx: RunContext) -> None:
        fingerprint = ctx.scan_salt.fingerprint()
        payloads: list[JsonValue] = []
        for index, candidate in enumerate(_rows(ctx.artefacts.get_json(keys.CANDIDATES))):
            candidate_id = str(candidate["id"])
            if self.fail_first_item and index == 0:
                ctx.fail_item(candidate_id, ITEM_ERROR_CODE)
                continue
            text = _sha(f"{fingerprint}:{candidate_id}")
            payloads.append({"id": f"pay_{text[:16]}", "candidate": candidate_id, "text": text})
        ctx.artefacts.put(keys.PAYLOADS_SANITISED, payloads)


class PrivacyPrepareRaises(PrivacyPrepare):
    """Variant ``privacy-raises``: the whole stage fails."""

    def work(self, ctx: RunContext) -> None:
        raise RuntimeError("fake privacy failure")


class PrivacyPrepareItemFailures(PrivacyPrepare):
    """Variant ``privacy-item-failures``: the first candidate fails and gets no payload."""

    fail_first_item = True


class LlmReview(FakeStageBase):
    """Echoes one verdict per payload and records how many payloads it saw."""

    name = "llm-review"
    requires = frozenset({keys.PAYLOADS_SANITISED})
    provides = frozenset({keys.VERDICTS_RAW})
    category = StageCategory.LLM

    def work(self, ctx: RunContext) -> None:
        payloads = _rows(ctx.artefacts.get_json(keys.PAYLOADS_SANITISED))
        SEEN_PAYLOADS.append(len(payloads))
        verdicts: list[JsonValue] = [
            {
                "payload": payload["id"],
                "candidate": payload["candidate"],
                "vulnerable": int(str(payload["text"])[:2], 16) % 2 == 0,
            }
            for payload in payloads
        ]
        ctx.artefacts.put(keys.VERDICTS_RAW, verdicts)


class LlmReviewReadsFiles(LlmReview):
    """Variant ``llm-reads-files``: requires a raw-code artefact, which no plan may allow."""

    requires = frozenset({keys.PAYLOADS_SANITISED, keys.FILES})


class Restore(FakeStageBase):
    """Maps the verdicts back to candidates."""

    name = "restore"
    requires = frozenset({keys.VERDICTS_RAW})
    provides = frozenset({keys.VERDICTS_RESTORED})
    category = StageCategory.RESTORE

    def work(self, ctx: RunContext) -> None:
        restored: list[JsonValue] = [
            {"candidate": verdict["candidate"], "vulnerable": verdict["vulnerable"]}
            for verdict in _rows(ctx.artefacts.get_json(keys.VERDICTS_RAW))
        ]
        ctx.artefacts.put(keys.VERDICTS_RESTORED, restored)


class Rate(FakeStageBase):
    """Builds JSON findings from the candidates and, when present, the restored verdicts."""

    name = "rate"
    requires = frozenset({keys.CANDIDATES})
    optional_requires = frozenset({keys.VERDICTS_RESTORED})
    provides = frozenset({keys.FINDINGS, keys.SCAN_SUMMARY})
    category = StageCategory.RATE

    def work(self, ctx: RunContext) -> None:
        verdicts: dict[str, JsonValue] = {}
        if ctx.artefacts.has(keys.VERDICTS_RESTORED):
            for verdict in _rows(ctx.artefacts.get_json(keys.VERDICTS_RESTORED)):
                verdicts[str(verdict["candidate"])] = verdict["vulnerable"]
        severity = {True: "high", False: "info", None: "medium"}
        findings: list[JsonValue] = []
        for candidate in _rows(ctx.artefacts.get_json(keys.CANDIDATES)):
            candidate_id = str(candidate["id"])
            verdict_value = verdicts.get(candidate_id)
            reviewed = verdict_value if isinstance(verdict_value, bool) else None
            findings.append(
                {
                    "id": f"fnd_{candidate_id.removeprefix('cand_')}",
                    "candidate": candidate_id,
                    "path": candidate["path"],
                    "rule": candidate["rule"],
                    "severity": severity[reviewed],
                    "reviewed_by_llm": reviewed is not None,
                }
            )
        ctx.artefacts.put(keys.FINDINGS, findings)
        ctx.artefacts.put(keys.SCAN_SUMMARY, {"findings_total": len(findings)})


class Report(FakeStageBase):
    """Counts findings and item failures and keeps the partial manifest it was given."""

    name = "report"
    requires = frozenset({keys.FINDINGS})
    optional_requires = frozenset({keys.SCAN_SUMMARY, keys.ITEM_FAILURES})
    provides = frozenset({keys.REPORT_OUTPUTS})
    category = StageCategory.REPORT

    def work(self, ctx: RunContext) -> None:
        PARTIAL_MANIFESTS.append(ctx.partial_manifest())
        failures: JsonValue = []
        if ctx.artefacts.has(keys.ITEM_FAILURES):
            failures = ctx.artefacts.get_json(keys.ITEM_FAILURES)
        ctx.artefacts.put(
            keys.REPORT_OUTPUTS,
            {
                "findings": len(_rows(ctx.artefacts.get_json(keys.FINDINGS))),
                "item_failures": len(failures) if isinstance(failures, list) else 0,
            },
        )


class Sync(FakeStageBase):
    """Records how many findings it would have synchronised."""

    name = "sync"
    requires = frozenset({keys.FINDINGS})
    provides = frozenset({keys.SYNC_RESULT})
    category = StageCategory.SYNC

    def work(self, ctx: RunContext) -> None:
        findings = _rows(ctx.artefacts.get_json(keys.FINDINGS))
        ctx.artefacts.put(keys.SYNC_RESULT, {"synced": len(findings)})


class EnrichFails(FakeStageBase):
    """Variant ``uncategorised-stage-fails``: a stage without a category that raises."""

    name = "enrich"
    requires = frozenset({keys.FILES})
    provides = frozenset({"enrich.notes"})
    category = None

    def work(self, ctx: RunContext) -> None:
        raise RuntimeError("fake enrichment failure")


DEFAULT_STAGES: Final[dict[str, type[FakeStageBase]]] = {
    stage.name: stage
    for stage in (
        Ingest,
        Parse,
        AnalyseRules,
        AnalyseTaint,
        AnalyseSecrets,
        Aggregate,
        PrivacyPrepare,
        LlmReview,
        Restore,
        Rate,
        Report,
        Sync,
    )
}
VARIANTS: Final[dict[str, dict[str, type[FakeStageBase]]]] = {
    "default": {},
    "privacy-raises": {"privacy-prepare": PrivacyPrepareRaises},
    "privacy-item-failures": {"privacy-prepare": PrivacyPrepareItemFailures},
    "engine-times-out": {"analyse-taint": AnalyseTaintSlow},
    "llm-reads-files": {"llm-review": LlmReviewReadsFiles},
    "uncategorised-stage-fails": {"enrich": EnrichFails},
}


def fake_stages(variant: str = "default") -> dict[str, type[FakeStageBase]]:
    """Entry-point name to stage class for ``variant``."""
    return {**DEFAULT_STAGES, **VARIANTS[variant]}


def install_fake_pipeline(site_dir: Path, *, variant: str = "default") -> None:
    """Write the distribution ``ck-fake-pipeline`` with the stages of ``variant`` to ``site_dir``.

    ``site_dir`` must be on ``sys.path`` (the ``fake_site`` fixture provides one). The entry
    points name the stage classes of this module, so discovery, loading and plan building run as
    they do for an installed plugin.
    """
    targets = {name: f"{MODULE}:{stage.__name__}" for name, stage in fake_stages(variant).items()}
    write_fake_distribution(
        site_dir, DIST_NAME, "1.0", entry_points={STAGES_GROUP: targets}, modules={}
    )


def fake_registry() -> PluginRegistry:
    """A registry of the installed fake pipeline only."""
    return PluginRegistry([spec for spec in discover() if spec.dist_name == DIST_NAME])


def write_fake_repo(root: Path) -> Path:
    """Create ``root`` as a project with ``FAKE_REPO_FILES`` and return it."""
    (root / ".git").mkdir(parents=True, exist_ok=True)
    for relative, source in FAKE_REPO_FILES.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source.encode("utf-8"))
    return root


def snapshot_digests(store: ArtefactStore) -> dict[str, str]:
    """Key to content digest for every persisted key; parts appear as ``part=digest`` lines."""
    digests: dict[str, str] = {}
    for key in store.keys():  # noqa: SIM118 - a store is not a mapping
        ref = store.ref(key)
        if ref is None:
            continue
        if ref.parts:
            digests[key] = "\n".join(f"{part}={digest}" for part, digest in ref.parts)
        elif ref.digest is not None:
            digests[key] = ref.digest
    return digests
