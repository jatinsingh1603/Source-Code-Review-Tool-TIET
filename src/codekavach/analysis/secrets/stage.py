"""``AnalyseSecretsStage``: hard-coded credentials as masked CWE-798 candidates (E19, issue 236).

The privacy layer's secret detectors (provider patterns, credential assignments, entropy) find the
values; this stage turns each hit into a ``Candidate`` that says *what* was found and *where*,
never *what it was*. The value is read once to derive a masked preview and its entropy and is then
dropped: it is not stored in the candidate, its properties, its message or its fingerprint (the
fingerprint hashes the line with the value replaced by its type, so a rotated credential keeps its
identity for baselines).

Verification-free: nothing here contacts a provider to test whether a credential is live.

``CODEKAVACH_SECRETS_HISTORY=1`` also scans the added lines of the repository's history
(``history.py``). Candidates carry ``engine="codekavach-secrets"`` and ``rule_id="secret.<type>"``.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from codekavach.config.models.root import Settings
from codekavach.core.log import get_logger
from codekavach.core.models import Candidate, Confidence, Language, Location, RawCode, Severity
from codekavach.core.models.enums import CandidateKind
from codekavach.core.models.fingerprint import FingerprintParts, fingerprint_batch, snippet_hash
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.stage import StageCategory
from codekavach.ingest.models import SourceFile
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_all
from codekavach.privacy.detect.secrets.builtin import register_secret_detectors
from codekavach.privacy.detect.secrets.entropy import shannon_entropy

SECRETS_ENGINE: Final = "codekavach-secrets"
MAX_FILE_BYTES: Final = 1_000_000
HISTORY_ENV: Final = "CODEKAVACH_SECRETS_HISTORY"
_log = get_logger("codekavach.analysis.secrets")

_HIGH_SUBTYPES: Final = frozenset(
    {
        "aws_access_key",
        "aws_secret_key",
        "private_key_block",
        "connection_string",
        "razorpay_key_secret",
        "github_token",
        "slack_token",
        "stripe_key",
        "google_api_key",
        "jwt",
    }
)


def mask_preview(value: str) -> str:
    """A preview that cannot reconstruct ``value``: two leading characters and the length."""
    if len(value) < 12:
        return f"{'*' * 4} ({len(value)} chars)"
    return f"{value[:2]}{'*' * 6} ({len(value)} chars)"


def severity_for(subtype: str, confidence: Confidence) -> Severity:
    """High for provider-specific credentials, medium for generic or entropy-only hits."""
    if subtype in _HIGH_SUBTYPES and confidence >= Confidence.MEDIUM:
        return Severity.HIGH
    return Severity.MEDIUM if confidence >= Confidence.MEDIUM else Severity.LOW


def cwes_for(subtype: str) -> tuple[int, ...]:
    """CWE-798 for every secret; private keys also CWE-321."""
    return (798, 321) if subtype == "private_key_block" else (798,)


@dataclass
class SecretHit:
    """One masked hit; built from derived facts only, so it holds no value."""

    subtype: str
    confidence: Confidence
    detector: str
    line: int
    end_line: int
    column: int
    preview: str
    entropy: float
    length: int
    masked_line: str


def hits_in(
    text: str, path: str, language: Language, settings: Settings, registry: DetectorRegistry
) -> list[SecretHit]:
    """The masked hits of ``text``; the values exist only inside this function."""
    spans = detect_all(
        RawCode(text), path=path, language=language, settings=settings, registry=registry
    )
    data = text.encode("utf-8", errors="surrogatepass")
    hits: list[SecretHit] = []
    for span in spans:
        if span.kind.value != "SECRET":
            continue
        value = data[span.start_byte : span.end_byte].decode("utf-8", errors="replace")
        line = data.count(b"\n", 0, span.start_byte) + 1
        line_start = data.rfind(b"\n", 0, span.start_byte) + 1
        line_end = data.find(b"\n", span.end_byte)
        line_end = len(data) if line_end < 0 else line_end
        before = data[line_start : span.start_byte].decode("utf-8", errors="replace")
        after = data[span.end_byte : line_end].decode("utf-8", errors="replace")
        hits.append(
            SecretHit(
                subtype=span.subtype,
                confidence=span.confidence,
                detector=span.detector,
                line=line,
                end_line=line + value.count("\n"),
                column=len(before) + 1,
                preview=mask_preview(value),
                entropy=round(shannon_entropy(value), 2),
                length=len(value),
                masked_line=f"{before}<SECRET:{span.subtype}>{after}",
            )
        )
    return hits


def candidates_for(
    path: str,
    language: Language,
    hits: list[SecretHit],
    *,
    extra: tuple[tuple[str, str], ...] = (),
    rule_suffix: str = "",
) -> list[Candidate]:
    """Candidates for one file's (or commit's) hits."""
    parts = [
        FingerprintParts(
            engine=SECRETS_ENGINE,
            rule_id=f"secret.{hit.subtype}{rule_suffix}",
            path=path,
            snippet_hash=snippet_hash([hit.masked_line]),
            start_line=hit.line,
        )
        for hit in hits
    ]
    found: list[Candidate] = []
    for hit, fingerprint in zip(hits, fingerprint_batch(parts), strict=True):
        if hit.end_line == hit.line:
            location = Location(
                path=path,
                start_line=hit.line,
                end_line=hit.line,
                start_col=hit.column,
                end_col=hit.column + 1,
            )
        else:
            location = Location(path=path, start_line=hit.line, end_line=hit.end_line)
        found.append(
            Candidate.create(
                rule_id=f"secret.{hit.subtype}{rule_suffix}",
                engine=SECRETS_ENGINE,
                engine_version="1",
                cwe=cwes_for(hit.subtype),
                locations=(location,),
                engine_severity=severity_for(hit.subtype, hit.confidence),
                engine_confidence=hit.confidence,
                fingerprint=fingerprint,
                kind=CandidateKind.SECRET,
                language=language,
                message=(
                    f"Hard-coded credential of type {hit.subtype} "
                    f"(masked preview {hit.preview}, entropy {hit.entropy} bits/char)."
                ),
                properties=(
                    ("secret.type", hit.subtype),
                    ("secret.preview", hit.preview),
                    ("secret.entropy", str(hit.entropy)),
                    ("secret.length", str(hit.length)),
                    ("secret.detector", hit.detector),
                    *extra,
                ),
            )
        )
    return found


def secret_registry() -> DetectorRegistry:
    """A registry of the built-in secret detectors only (no PII, no domain terms)."""
    return register_secret_detectors(DetectorRegistry())


class AnalyseSecretsStage:
    """Reports every detected hard-coded credential as a masked candidate."""

    name = "analyse-secrets"
    version = "1"
    requires = frozenset({keys.FILES})
    provides = frozenset({keys.CANDIDATES_RAW})
    category = StageCategory.ANALYSE

    def run(self, ctx: RunContext) -> None:
        """Publish this stage's part of ``candidates.raw``."""
        if not ctx.config.engines.native.secrets:
            ctx.artefacts.put_part(keys.CANDIDATES_RAW, self.name, [])
            return
        registry = secret_registry()
        files = sorted(ctx.artefacts.get_list(keys.FILES, SourceFile), key=lambda f: f.path)
        found: list[Candidate] = []
        for done, file in enumerate(files, start=1):
            ctx.check_cancelled()
            if file.is_vendored or file.is_minified or file.size_bytes > MAX_FILE_BYTES:
                continue
            try:
                raw = (ctx.source_root / file.path).read_bytes()
            except OSError:
                ctx.fail_item(f"file:{file.sha256[:16]}", "unreadable")
                continue
            if b"\x00" in raw[:4096]:
                continue
            text = raw.decode(file.encoding or "utf-8", errors="replace")
            try:
                hits = hits_in(text, file.path, file.language, ctx.config, registry)
            except Exception:  # noqa: BLE001 - one file must not lose the others
                _log.warning("secrets_file_failed", file=file.sha256[:16])
                ctx.fail_item(f"file:{file.sha256[:16]}", "detector_failed")
                continue
            found.extend(candidates_for(file.path, file.language, hits))
            if done % 100 == 0:
                ctx.emit_progress(done, len(files), "files")
        if ctx.config.secrets.history or os.environ.get(HISTORY_ENV) == "1":
            from codekavach.analysis.secrets.history import scan_history  # noqa: PLC0415

            found.extend(
                scan_history(
                    Path(ctx.source_root),
                    ctx.config,
                    registry,
                    max_commits=ctx.config.secrets.history_max_commits,
                )
            )
        ctx.emit_progress(len(files), len(files), "files")
        ctx.artefacts.put_part(keys.CANDIDATES_RAW, self.name, found)
