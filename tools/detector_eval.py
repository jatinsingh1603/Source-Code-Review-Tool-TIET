"""Measure the redaction detectors against labelled corpora (E08-04).

Usage: ``uv run python tools/detector_eval.py [--out-dir DIR] [--check] [--external NAME=DIR ...]``.

For every detector and every subtype the report gives true positives, false positives, false
negatives, precision, recall, F1 and the mean span-level Jaccard overlap between predicted and
labelled byte ranges. Precision and recall are always separate figures; there is no blended score.
It measures detector accuracy on labelled text, which predicts but is not the end-to-end leakage
metric (M1 in ``docs/research/INSIGHTS.md`` section 4.3).

**Matching.** Within one corpus case, a predicted span matches a labelled span when both have the
same subtype and the Jaccard overlap of their byte ranges is at least ``MATCH_THRESHOLD`` (0.5).
Candidate pairs are taken in descending order of overlap, each span used once. An unmatched
prediction is a false positive and an unmatched label a false negative. Confidence is not part of
the match; it is used by the gate.

**Rows.** ``union`` is the resolved output of all detectors (``resolve_overlaps``), which is what
redaction uses; its rows are the per-subtype figures. Each other row is one detector on its own
(the raw spans it reported), scored against the labels of the subtypes it reported, so a detector
that covers part of a subtype shows a low recall for it. That is the point of reporting both.

**Corpora.** ``labelled`` is the in-repository corpus: the PII and term cases of
``tests/fixtures/detect/corpus`` and the secret cases of ``tests/fixtures/detect/secrets``, all
synthetic. Any directory given with ``--external NAME=DIR`` and holding ``cases.jsonl`` is added
as another corpus (one JSON object per line: ``path``, ``language``, ``text`` and ``labels``, a
list of ``kind``, ``subtype``, ``confidence``, ``start_byte`` and ``end_byte``). External
datasets are fetched by ``tools/fetch_eval_corpora.py`` at a pinned commit and checksum and are
never vendored. Each corpus is reported with its size and de-duplication, because leakage between
benchmark splits inflates secret-detection accuracy (``docs/research/INSIGHTS.md`` section 5.3).

**Gate.** ``--check`` exits 1 when the union recall of any subtype for labels of ``high``
confidence on the in-repository corpus is below 1.0.

No matched text is written to the report: it holds counts and ratios only. The output is
deterministic apart from the ``generated`` date, which ``--date`` fixes. This is development
tooling and is not shipped in the package.
"""

import argparse
import json
import sys
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from tests.support.corpus import case_names, load_case  # noqa: E402
from tests.support.real_detectors import (  # noqa: E402
    CORPUS_PATH,
    CORPUS_PREFIXES,
    corpus_settings,
)
from tests.support.secret_corpus import secret_cases  # noqa: E402

from codekavach.core.models import Confidence, Language, RawCode  # noqa: E402
from codekavach.privacy.detect.base import Detector, TypedSpan  # noqa: E402
from codekavach.privacy.detect.overlap import resolve_overlaps  # noqa: E402
from codekavach.privacy.detect.pii.builtin import pii_detectors  # noqa: E402
from codekavach.privacy.detect.secrets.builtin import secret_detectors  # noqa: E402
from codekavach.privacy.detect.terms import DomainTermDetector  # noqa: E402

MATCH_THRESHOLD: Final = 0.5
UNION: Final = "union"
IN_REPOSITORY: Final = "labelled"
DEFAULT_OUT: Final = ROOT / "build" / "detector-eval"


@dataclass(frozen=True)
class Label:
    """One labelled span."""

    subtype: str
    confidence: str
    start: int
    end: int


@dataclass(frozen=True)
class Case:
    """One text with its labels and the logical path and language the detectors are given."""

    corpus: str
    name: str
    text: str
    path: str
    language: Language
    labels: tuple[Label, ...]


@dataclass
class Counts:
    """True positives, false positives, false negatives and the summed overlap of the matches."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    jaccard_sum: float = 0.0
    high_labels: int = 0
    high_found: int = 0

    def precision(self) -> float | None:
        """TP / (TP + FP), or None when nothing was predicted."""
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    def recall(self) -> float | None:
        """TP / (TP + FN), or None when nothing was labelled."""
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    def f1(self) -> float | None:
        """The harmonic mean of precision and recall, or None when either is undefined."""
        precision, recall = self.precision(), self.recall()
        if precision is None or recall is None or precision + recall == 0:
            return None
        return 2 * precision * recall / (precision + recall)

    def jaccard(self) -> float | None:
        """The mean overlap of the matched pairs, or None when there are none."""
        return self.jaccard_sum / self.tp if self.tp else None


def jaccard(a: tuple[int, int], b: tuple[int, int]) -> float:
    """Intersection over union of two half-open byte ranges."""
    inter = max(0, min(a[1], b[1]) - max(a[0], b[0]))
    union = (a[1] - a[0]) + (b[1] - b[0]) - inter
    return inter / union if union else 0.0


def match(
    predicted: Sequence[tuple[int, int]], labelled: Sequence[tuple[int, int]]
) -> list[tuple[int, int, float]]:
    """Greedy one-to-one matching: ``(predicted index, label index, jaccard)`` per match."""
    pairs = sorted(
        (
            (-score, p, label)
            for p, span in enumerate(predicted)
            for label, other in enumerate(labelled)
            if (score := jaccard(span, other)) >= MATCH_THRESHOLD
        )
    )
    used_p: set[int] = set()
    used_l: set[int] = set()
    matches: list[tuple[int, int, float]] = []
    for negative, p, label in pairs:
        if p in used_p or label in used_l:
            continue
        used_p.add(p)
        used_l.add(label)
        matches.append((p, label, -negative))
    return matches


def score_case(
    counts: dict[str, Counts],
    predicted: Iterable[TypedSpan],
    labels: Iterable[Label],
    *,
    subtypes: Iterable[str] | None = None,
) -> None:
    """Add one case to ``counts`` (keyed by subtype).

    With ``subtypes`` given, only labels and predictions of those subtypes are scored; a detector
    is scored on the subtypes it reported.
    """
    wanted = None if subtypes is None else set(subtypes)
    by_predicted: dict[str, list[TypedSpan]] = defaultdict(list)
    by_label: dict[str, list[Label]] = defaultdict(list)
    for span in predicted:
        if wanted is None or span.subtype in wanted:
            by_predicted[span.subtype].append(span)
    for label in labels:
        if wanted is None or label.subtype in wanted:
            by_label[label.subtype].append(label)
    for subtype in sorted(by_predicted.keys() | by_label.keys()):
        spans = by_predicted.get(subtype, [])
        marked = by_label.get(subtype, [])
        found = match(
            [(s.start_byte, s.end_byte) for s in spans], [(m.start, m.end) for m in marked]
        )
        row = counts.setdefault(subtype, Counts())
        row.tp += len(found)
        row.fp += len(spans) - len(found)
        row.fn += len(marked) - len(found)
        row.jaccard_sum += sum(score for _, _, score in found)
        matched_labels = {label for _, label, _ in found}
        for index, mark in enumerate(marked):
            if mark.confidence == Confidence.HIGH.value:
                row.high_labels += 1
                row.high_found += index in matched_labels


def in_repository_cases() -> list[Case]:
    """The synthetic corpus that ships in the repository."""
    cases: list[Case] = []
    for name in case_names():
        if not name.startswith(CORPUS_PREFIXES):
            continue
        case = load_case(name)
        labels = tuple(
            Label(s.subtype, s.confidence.value, s.start_byte, s.end_byte) for s in case.expected
        )
        cases.append(Case(IN_REPOSITORY, name, case.text, CORPUS_PATH, Language.UNKNOWN, labels))
    for secret in secret_cases():
        labels = tuple(
            Label(p.subtype, p.confidence.value, p.start_byte, p.end_byte) for p in secret.planted
        )
        cases.append(
            Case(IN_REPOSITORY, secret.file, secret.text, secret.path, secret.language, labels)
        )
    return cases


def external_cases(name: str, directory: Path) -> list[Case]:
    """The cases of a fetched dataset: ``cases.jsonl`` under ``directory``."""
    cases: list[Case] = []
    source = directory / "cases.jsonl"
    for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        item: dict[str, Any] = json.loads(line)
        labels = tuple(
            Label(x["subtype"], x["confidence"], x["start_byte"], x["end_byte"])
            for x in item["labels"]
        )
        cases.append(
            Case(
                name,
                f"{name}:{number}",
                item["text"],
                item["path"],
                Language(item.get("language", "unknown")),
                labels,
            )
        )
    return cases


def detectors() -> tuple[Detector, ...]:
    """The native detectors, set up as the corpus tests set them up."""
    settings = corpus_settings()
    return (
        *secret_detectors(),
        *pii_detectors(settings.privacy.pii_locales),
        DomainTermDetector.from_settings(settings),
    )


@dataclass
class Report:
    """The scores of one corpus."""

    corpus: str
    cases: int
    unique_texts: int
    labels: int
    rows: dict[str, dict[str, Counts]] = field(default_factory=dict)


def evaluate(cases: Sequence[Case], active: Sequence[Detector]) -> list[Report]:
    """Score ``active`` and their union on every corpus in ``cases``."""
    reports: dict[str, Report] = {}
    for case in cases:
        report = reports.setdefault(case.corpus, Report(case.corpus, 0, 0, 0))
        report.cases += 1
        report.labels += len(case.labels)
        spans: dict[str, list[TypedSpan]] = {}
        everything: list[TypedSpan] = []
        for detector in active:
            found = list(
                detector.detect(RawCode(case.text), path=case.path, language=case.language)
            )
            spans[detector.id] = found
            everything.extend(found)
        score_case(report.rows.setdefault(UNION, {}), resolve_overlaps(everything), case.labels)
        for detector_id, found in spans.items():
            if found:
                score_case(
                    report.rows.setdefault(detector_id, {}),
                    found,
                    case.labels,
                    subtypes={s.subtype for s in found},
                )
    texts: dict[str, set[str]] = defaultdict(set)
    for case in cases:
        texts[case.corpus].add(case.text)
    for name, report in reports.items():
        report.unique_texts = len(texts[name])
    return [reports[name] for name in sorted(reports)]


def failing_subtypes(report: Report) -> list[str]:
    """Subtypes with a ``high``-confidence label that the union did not find."""
    return sorted(
        subtype
        for subtype, row in report.rows.get(UNION, {}).items()
        if row.high_labels and row.high_found < row.high_labels
    )


def _ratio(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def render_markdown(reports: Sequence[Report], date: str) -> str:
    """The report as Markdown: one table per corpus, precision and recall side by side."""
    lines = [
        "# Detector evaluation",
        "",
        f"Generated {date}. Precision and recall are reported separately; there is no blended",
        f"score. A match needs the same subtype and a byte-range Jaccard of at least"
        f" {MATCH_THRESHOLD}.",
    ]
    for report in reports:
        lines += [
            "",
            f"## Corpus `{report.corpus}`",
            "",
            f"{report.cases} cases, {report.unique_texts} distinct texts"
            f" ({'de-duplicated' if report.unique_texts == report.cases else 'contains repeats'}),"
            f" {report.labels} labelled spans.",
            "",
            "| detector | subtype | TP | FP | FN | precision | recall | F1 | Jaccard |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for detector_id in sorted(report.rows, key=lambda item: (item != UNION, item)):
            for subtype, row in sorted(report.rows[detector_id].items()):
                lines.append(
                    f"| {detector_id} | {subtype} | {row.tp} | {row.fp} | {row.fn} |"
                    f" {_ratio(row.precision())} | {_ratio(row.recall())} | {_ratio(row.f1())} |"
                    f" {_ratio(row.jaccard())} |"
                )
    return "\n".join(lines) + "\n"


def render_json(reports: Sequence[Report], date: str) -> str:
    """The report as JSON: counts and ratios, never text."""
    document = {
        "generated": date,
        "match_threshold": MATCH_THRESHOLD,
        "corpora": [
            {
                "corpus": report.corpus,
                "cases": report.cases,
                "unique_texts": report.unique_texts,
                "labels": report.labels,
                "rows": [
                    {
                        "detector": detector_id,
                        "subtype": subtype,
                        "tp": row.tp,
                        "fp": row.fp,
                        "fn": row.fn,
                        "precision": row.precision(),
                        "recall": row.recall(),
                        "f1": row.f1(),
                        "jaccard": row.jaccard(),
                        "high_confidence_labels": row.high_labels,
                        "high_confidence_found": row.high_found,
                    }
                    for detector_id in sorted(report.rows, key=lambda item: (item != UNION, item))
                    for subtype, row in sorted(report.rows[detector_id].items())
                ],
            }
            for report in reports
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """Run the evaluation and write ``report.md`` and ``report.json``."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true", help="exit 1 if a HIGH subtype misses")
    parser.add_argument("--external", action="append", default=[], metavar="NAME=DIR")
    parser.add_argument("--date", default=datetime.now(UTC).date().isoformat())
    args = parser.parse_args(argv)

    cases = in_repository_cases()
    for item in args.external:
        name, _, directory = item.partition("=")
        if not name or not directory or name == IN_REPOSITORY:
            print(f"--external wants NAME=DIR with a new name, got {item!r}", file=sys.stderr)
            return 2
        cases += external_cases(name, Path(directory))
    reports = evaluate(cases, detectors())
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "report.md").write_bytes(render_markdown(reports, args.date).encode("utf-8"))
    (args.out_dir / "report.json").write_bytes(render_json(reports, args.date).encode("utf-8"))
    own = next(report for report in reports if report.corpus == IN_REPOSITORY)
    missed = failing_subtypes(own)
    print(f"{own.cases} cases, {own.labels} labels; report in {args.out_dir}")
    if missed:
        print(f"HIGH-confidence recall below 1.0 for: {', '.join(missed)}", file=sys.stderr)
    return 1 if args.check and missed else 0


if __name__ == "__main__":
    raise SystemExit(main())
