# ruff: noqa: D102
"""Run one scan of a dataset at one privacy level and collect what the evaluations need (#278).

The scan is the real pipeline (``run_scan``), on a copy of the dataset without its answer key, in
a throw-away state directory with a random vault passphrase. For the leakage harness the payload
texts are read back from the egress ledger, the only place that holds them (I3).
"""

import os
import secrets
import shutil
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from codekavach.config import load_settings
from codekavach.core.models.finding import Finding
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.runner import run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.eval.datasets import Dataset
from codekavach.privacy.inspect_source import open_payload_source

LOCAL_PROVIDERS: Final = frozenset({"mock", "replay"})
EVAL_SALT_HEX: Final = "5e" * 32  # pragma: allowlist secret
PASSPHRASE_VARIABLE: Final = "CODEKAVACH_EVAL_PASSPHRASE"  # noqa: S105 - a variable name


class ScanFailedError(RuntimeError):
    """The pipeline reported a failed scan."""


@dataclass(frozen=True)
class PayloadView:
    """One prepared payload as an adversary would see it, plus what it was cut from."""

    candidate_id: str
    text: str
    outcome: str
    placeholder_tokens: tuple[str, ...]
    segments: tuple[tuple[str, int, int], ...]

    @property
    def sent(self) -> bool:
        return self.outcome == "sent"


@dataclass
class ScanArtifacts:
    """Findings and payloads of one scan."""

    level: str
    provider: str
    scan_id: str
    findings: list[Finding] = field(default_factory=list)
    payloads: list[PayloadView] = field(default_factory=list)
    llm_enabled: bool = True
    duration_s: float = 0.0
    settings: object | None = None


def _overrides(
    level: str, provider: str, llm: bool, extra: Mapping[str, Any] | None
) -> dict[str, Any]:
    out: dict[str, Any] = {"privacy": {"level": level}, "llm": {"enabled": llm}}
    if llm and provider not in ("mock", "auto"):
        out["llm"]["default_provider"] = provider
        if provider == "replay":
            out["llm"]["providers"] = {"replay": {"kind": "replay"}}
        else:
            out["llm"]["allow_remote"] = True
    if extra:
        for section, values in extra.items():
            out.setdefault(section, {}).update(values)
    return out


def scan_dataset(
    dataset: Dataset,
    *,
    level: str,
    provider: str = "mock",
    llm: bool = True,
    extra: Mapping[str, Any] | None = None,
    keep_payloads: bool = True,
    work_dir: Path | None = None,
    inject: Mapping[str, str] | None = None,
) -> ScanArtifacts:
    """Scan ``dataset`` once. ``inject`` adds files (relative path to text) to the scanned copy."""
    own = work_dir is None
    work = work_dir or Path(tempfile.mkdtemp(prefix="kavach-eval-"))
    try:
        root = work / "project"
        if root.exists():
            shutil.rmtree(root)
        shutil.copytree(
            dataset.root, root, ignore=shutil.ignore_patterns("ground-truth", ".git", "cassettes")
        )
        (root / ".git").mkdir(exist_ok=True)
        (work / "home").mkdir(exist_ok=True)
        for rel, text in (inject or {}).items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        passphrase = secrets.token_hex(24)
        previous = os.environ.get(PASSPHRASE_VARIABLE)
        os.environ[PASSPHRASE_VARIABLE] = passphrase
        try:
            env = {
                "CODEKAVACH_HOME": str(work / "home"),
                "CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE": "passphrase",
                "CODEKAVACH_PRIVACY__VAULT__PASSPHRASE": f"env:{PASSPHRASE_VARIABLE}",
            }
            if dataset.canaries:
                terms = work / "terms.txt"
                terms.write_text(
                    "\n".join(c.value for c in dataset.canaries if c.category in {"term", "secret"})
                    + "\n",
                    encoding="utf-8",
                )
                env["CODEKAVACH_PRIVACY__DOMAIN_TERMS_FILE"] = str(terms)
            loaded = load_settings(
                target=root, env=env, cli_overrides=_overrides(level, provider, llm, extra)
            )
            started = time.monotonic()
            outcome = run_scan(
                loaded,
                str(root),
                salt=ScanSalt.from_hex(EVAL_SALT_HEX),
                persist=False,
                no_send=not llm,
            )
            elapsed = time.monotonic() - started
            if outcome.result.status.value == "failed":
                failed = ", ".join(outcome.result.failed_stages()) or "unknown"
                raise ScanFailedError(f"scan failed in stage {failed}")
            layout = StateLayout(outcome.state_dir)
            scan_id = str(outcome.scan.id)
            store = OnDiskArtefactStore.open_existing(layout, scan_id)
            findings = store.get_list(keys.FINDINGS, Finding) if store.has(keys.FINDINGS) else []
            payloads: list[PayloadView] = []
            if keep_payloads and llm:
                source = open_payload_source(layout, scan_id, settings=loaded.settings)
                for payload in source.payloads(scan_id):
                    slice_ = source.slice_for(str(payload.candidate_id))
                    segments = (
                        tuple(
                            (s.path, s.region.start_line, s.region.end_line)
                            for s in slice_.segments
                        )
                        if slice_
                        else ()
                    )
                    payloads.append(
                        PayloadView(
                            str(payload.candidate_id),
                            payload.text.expose(),
                            source.ledger_outcome(payload.payload_hash) or "unknown",
                            tuple(p.token for p in payload.placeholders),
                            segments,
                        )
                    )
            return ScanArtifacts(
                level, provider, scan_id, findings, payloads, llm, elapsed, loaded.settings
            )
        finally:
            if previous is None:
                os.environ.pop(PASSPHRASE_VARIABLE, None)
            else:
                os.environ[PASSPHRASE_VARIABLE] = previous
    finally:
        if own:
            shutil.rmtree(work, ignore_errors=True)
