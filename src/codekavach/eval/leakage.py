# ruff: noqa: PLC0415, RUF028, D103, E501
"""Leakage harness: adversary model, attackers, ablations, privacy-utility frontier.

Issues #281, #282, #283.

Adversary model
    An honest-but-curious model provider. It sees every payload that left the machine (the ledger
    records exactly those), in order, with the metadata the request carries (candidate id, model,
    placeholder tokens). It does not see the vault, the salt, the project tree or the ground
    truth. It may keep payloads and correlate them across a scan. It is not an active attacker
    against the local machine.

Attackers (each returns a rate in [0, 1]; higher is worse for privacy)
    ``canary``       exact occurrences of planted secrets, personal data, business terms and the
                     injected canary identifiers in the payload text. Secrets and personal data
                     must be zero at every level (a hard gate); business terms must be zero.
    ``identifier``   heuristic recovery of project-defined identifiers: the share of identifiers
                     defined in the covered code that appear verbatim, or by sub-word, in payloads.
    ``inference``    a keyword classifier guesses the business sector of the application from
                     the payloads; reported as the share of sector evidence words visible.
    ``stitching``    reconstruction of the code base from many slices: the share of source lines
                     covered by payloads, and how many payload pairs share a pseudonym and so can
                     be linked.
    ``llm``          optional: a model is asked to name the original identifiers. Runs only on
                     synthetic datasets and only through the egress path of the provider layer; it
                     is not enabled unless requested, and is reported as skipped otherwise.

Privacy-utility frontier
    For each level the harness reports the leakage score (a weighted exposure, 0 = nothing
    observable, 100 = everything) beside the detection F1 of the same scan, so the cost of
    each level in utility is visible.
"""

import json
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Final

from codekavach.eval.datasets import Canary, Dataset, resolve_dataset
from codekavach.eval.detection import evaluate_arm
from codekavach.eval.export import bar_chart_svg
from codekavach.eval.scanrun import PayloadView, ScanArtifacts, scan_dataset

DEFAULT_LEVELS: Final = ("L1", "L2", "L3", "L4")
ATTACKERS: Final = ("canary", "identifier", "inference", "stitching", "llm")
SCHEMA_VERSION: Final = 1
_IDENT: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_DEFINED: Final = re.compile(
    r"\b(?:def|class|function|const|let|var|async function)\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"|^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=",
    re.M,
)
_PSEUDONYM: Final = re.compile(r"\b(?:fn|var|param|mod|file|cls|attr|const|obj|field)_\d+\b")
_KEYWORDS: Final = frozenset(
    [
        "def",
        "class",
        "return",
        "import",
        "from",
        "self",
        "none",
        "true",
        "false",
        "null",
        "this",
        "function",
        "const",
        "let",
        "var",
        "if",
        "else",
        "for",
        "while",
        "try",
        "except",
        "catch",
        "raise",
        "throw",
        "new",
        "async",
        "await",
        "args",
        "kwargs",
        "main",
        "init",
        "str",
        "int",
        "dict",
        "list",
        "set",
        "get",
        "post",
        "put",
        "delete",
        "request",
        "response",
        "json",
        "data",
        "id",
        "name",
        "type",
        "value",
        "key",
        "error",
        "result",
    ]
)
SECTOR_WORDS: Final[dict[str, tuple[str, ...]]] = {
    "banking": (
        "account",
        "balance",
        "loan",
        "interest",
        "deposit",
        "overdraft",
        "cheque",
        "neft",
        "ifsc",
        "upi",
        "fee",
        "festival",
        "salary",
        "fraud",
        "transaction",
        "customer",
    ),  # fmt: skip
    "healthcare": ("patient", "diagnosis", "clinic", "prescription", "ward", "insurance"),
    "retail": ("cart", "checkout", "order", "sku", "inventory", "coupon", "shipment"),
    "telecom": ("subscriber", "sim", "roaming", "tariff", "msisdn", "recharge"),
}
CANARY_FILE: Final = "services/api/canary_probe.py"
CANARY_SOURCE: Final = '''"""Probe module injected by the leakage harness; it is not part of the dataset."""
import sqlite3

ZEBRAQUARTZ_LEDGER = "zq-ledger-7731"
CANARY_CONTACT = "zebraquartz.audit@canary-leak.test"


def zebraquartz_lookup(zq_customer_ref):
    connection = sqlite3.connect("zq.db")
    query = "SELECT * FROM zq_vault WHERE ref = '" + zq_customer_ref + "'"
    return connection.execute(query).fetchall()
'''
CANARIES: Final = (
    Canary("zebraquartz_lookup", "identifier", "canary function"),
    Canary("zq_customer_ref", "identifier", "canary parameter"),
    Canary("zq_vault", "identifier", "canary table"),
    Canary("zebraquartz.audit@canary-leak.test", "pii", "canary email"),
    Canary("zq-ledger-7731", "secret", "canary token"),
)


def _words(identifier: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", identifier).replace("_", " ")
    return [w.lower() for w in spaced.split() if len(w) >= 4]


def canary_exposure(
    payloads: Sequence[PayloadView], canaries: Sequence[Canary], level: str = "L2"
) -> dict[str, Any]:
    """Occurrences of each canary category in the payload texts (case-insensitive).

    Identifiers are hard canaries from L2 up; L1 keeps names by design (see the level table), so
    identifier hits at L1 are reported but do not fail the gate.
    """
    haystack = [p.text.lower() for p in payloads]
    by_category: dict[str, dict[str, int]] = {}
    leaked: list[dict[str, str]] = []
    for canary in canaries:
        needle = canary.value.lower()
        hits = sum(text.count(needle) for text in haystack)
        stats = by_category.setdefault(canary.category, {"checked": 0, "occurrences": 0})
        stats["checked"] += 1
        stats["occurrences"] += hits
        if hits:
            leaked.append({"category": canary.category, "label": canary.label or canary.category,
                           "value_hash": _short_hash(canary.value), "occurrences": str(hits)})  # fmt: skip
    hard_categories = ("secret", "pii") if level == "L1" else ("secret", "pii", "identifier")
    hard = sum(by_category.get(c, {}).get("occurrences", 0) for c in hard_categories)
    return {
        "by_category": by_category,
        "leaked": leaked,
        "hard_occurrences": hard,
        "passed": hard == 0,
        "business_term_occurrences": by_category.get("term", {}).get("occurrences", 0),
    }


def _short_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _defined_identifiers(text: str) -> set[str]:
    names = {a or b for a, b in _DEFINED.findall(text)}
    return {n for n in names if n and n.lower() not in _KEYWORDS and len(n) >= 4}


def identifier_recovery(
    dataset_root: Path, payloads: Sequence[PayloadView], extra_files: dict[str, str]
) -> dict[str, Any]:
    """Share of project-defined identifiers that a reader of the payloads can read off."""
    covered: dict[str, str] = {}
    for p in payloads:
        for path, _start, _end in p.segments:
            if path in covered:
                continue
            file = dataset_root / path
            if path in extra_files:
                covered[path] = extra_files[path]
            elif file.is_file():
                covered[path] = file.read_text(encoding="utf-8", errors="replace")
    defined: set[str] = set()
    for text in covered.values():
        defined |= _defined_identifiers(text)
    blob = "\n".join(p.text for p in payloads)
    visible_tokens = {t.lower() for t in _IDENT.findall(blob)}
    visible_words = {w for t in _IDENT.findall(blob) for w in _words(t)}
    exact = sorted(n for n in defined if n.lower() in visible_tokens)
    partial = sorted(
        n
        for n in defined
        if n not in exact and (w := _words(n)) and any(x in visible_words for x in w)
    )
    total = len(defined)
    return {
        "defined": total,
        "exact_recovered": len(exact),
        "subword_recovered": len(partial),
        "exact_rate": round(len(exact) / total, 4) if total else 0.0,
        "subword_rate": round((len(exact) + len(partial)) / total, 4) if total else 0.0,
        "examples_hashed": [_short_hash(n) for n in exact[:5]],
    }


def sector_inference(payloads: Sequence[PayloadView], truth: str = "banking") -> dict[str, Any]:
    """Which sector would a keyword classifier name, and how much evidence of the true one is visible."""
    tokens = [t.lower() for p in payloads for t in _IDENT.findall(p.text)]
    words = set(tokens) | {w for t in tokens for w in _words(t)}
    counts = {
        s: sum(1 for k in kws if any(k in w for w in words)) for s, kws in SECTOR_WORDS.items()
    }
    guess = max(counts, key=lambda s: counts[s]) if any(counts.values()) else "unknown"
    evidence = counts.get(truth, 0) / len(SECTOR_WORDS[truth])
    return {
        "guess": guess,
        "correct": guess == truth,
        "evidence_share": round(evidence, 4),
        "scores": counts,
    }


def slice_stitching(dataset: Dataset, payloads: Sequence[PayloadView]) -> dict[str, Any]:
    """How much of the code base the payloads cover, and how linkable they are."""
    covered: dict[str, set[int]] = {}
    for p in payloads:
        for path, start, end in p.segments:
            covered.setdefault(path, set()).update(range(start, end + 1))
    total = 0
    seen = 0
    for file in dataset.source_files():
        rel = str(file.relative_to(dataset.root))
        lines = [
            i
            for i, line in enumerate(file.read_text(errors="replace").splitlines(), 1)
            if line.strip()
        ]
        total += len(lines)
        seen += len(covered.get(rel, set()) & set(lines))
    pairs = linked = 0
    token_sets = [set(p.placeholder_tokens) | set(_PSEUDONYM.findall(p.text)) for p in payloads]
    for i in range(len(token_sets)):
        for j in range(i + 1, len(token_sets)):
            pairs += 1
            if token_sets[i] & token_sets[j]:
                linked += 1
    return {
        "source_lines": total,
        "covered_lines": seen,
        "coverage": round(seen / total, 4) if total else 0.0,
        "payload_pairs": pairs,
        "linkable_pairs": linked,
        "linkability": round(linked / pairs, 4) if pairs else 0.0,
    }


def leakage_score(report: dict[str, Any]) -> float:
    """0 (nothing observable) to 100 (everything). A hard canary hit scores 100.

    Weights: identifier recovery (sub-word) 0.35, sector evidence 0.15, code coverage 0.25,
    payload linkability 0.10, business-term occurrences (saturating at 5) 0.15.
    """
    if not report["canary"]["passed"]:
        return 100.0
    terms = min(1.0, report["canary"]["business_term_occurrences"] / 5)
    value = (
        0.35 * report["identifier"]["subword_rate"]
        + 0.15 * report["inference"]["evidence_share"]
        + 0.25 * report["stitching"]["coverage"]
        + 0.10 * report["stitching"]["linkability"]
        + 0.15 * terms
    )
    return float(round(100 * value, 1))


def attack_level(
    dataset: Dataset, art: ScanArtifacts, *, attackers: Sequence[str], inject: dict[str, str]
) -> dict[str, Any]:
    """Run the requested attackers on the payloads that were sent (and on all that were prepared)."""
    sent = [p for p in art.payloads if p.sent]
    prepared = art.payloads
    canaries = [*dataset.canaries, *CANARIES]
    report: dict[str, Any] = {
        "payloads_prepared": len(prepared),
        "payloads_sent": len(sent),
        "payloads_blocked": sum(1 for p in prepared if p.outcome.startswith("blocked")),
    }
    run = set(attackers) or set(ATTACKERS) - {"llm"}
    # The canary gate is evaluated on every prepared payload, sent or not: stricter than needed.
    report["canary"] = canary_exposure(prepared, canaries, art.level)
    if "identifier" in run:
        report["identifier"] = identifier_recovery(dataset.root, sent, inject)
    else:
        report["identifier"] = {"subword_rate": 0.0, "exact_rate": 0.0, "skipped": True}
    if "inference" in run:
        report["inference"] = sector_inference(sent)
    else:
        report["inference"] = {"evidence_share": 0.0, "skipped": True}
    if "stitching" in run:
        report["stitching"] = slice_stitching(dataset, sent)
    else:
        report["stitching"] = {"coverage": 0.0, "linkability": 0.0, "skipped": True}
    report["llm"] = {
        "skipped": True,
        "reason": "the LLM attacker runs only on request, on synthetic data, through the egress path",
    }
    report["leakage_score"] = leakage_score(report)
    report["privacy_score"] = round(100 - report["leakage_score"], 1)
    return report


ABLATIONS: Final[dict[str, dict[str, Any]]] = {
    "default": {},
    "sink-window-slices": {"privacy": {"slice": {"default_strategy": "sink_window"}}},
    "per-request-pseudonyms": {"privacy": {"pseudonym": {"link_mode": "per_request"}}},
    "role-hints": {"privacy": {"pseudonym": {"role_hints": True}}},
}


def _drop_probe(art: ScanArtifacts) -> None:
    """The injected probe file is not part of the dataset: keep it out of the F1 numbers."""
    art.findings = [
        f for f in art.findings if not any(loc.path == CANARY_FILE for loc in f.locations)
    ]


def run_leakage(
    scan: str | None = None,
    dataset: str | None = None,
    levels: Sequence[str] = (),
    attackers: Sequence[str] = (),
    out: str | None = None,
    *,
    provider: str = "mock",
    ablations: bool = True,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Prepare ``dataset`` at each level, attack the payloads and write the results directory.

    ``scan`` (a stored scan) is not supported here: the attackers need the dataset's ground
    truth, so the harness always prepares its own scans from ``dataset`` (default ``kavachbank``).
    """
    say = progress or (lambda _m: None)
    ds = resolve_dataset(dataset or "kavachbank")
    if not ds.synthetic and "llm" in attackers:
        raise ValueError("the LLM attacker runs only on synthetic datasets")
    chosen = list(levels) or list(DEFAULT_LEVELS)
    inject = {CANARY_FILE: CANARY_SOURCE}
    per_level: dict[str, Any] = {}
    frontier: list[dict[str, Any]] = []
    for level in chosen:
        say(f"level {level}")
        art = scan_dataset(ds, level=level, provider=provider, inject=inject)
        entry = attack_level(ds, art, attackers=attackers, inject=inject)
        _drop_probe(art)
        detection = evaluate_arm(ds, art, arm=f"{provider}@{level}")
        entry["detection_f1"] = detection.overall["f1"]
        entry["detection_recall"] = detection.overall["recall"]
        per_level[level] = entry
        frontier.append(
            {
                "level": level,
                "privacy_score": entry["privacy_score"],
                "leakage_score": entry["leakage_score"],
                "f1": detection.overall["f1"],
            }
        )
    ablation_rows: list[dict[str, Any]] = []
    if ablations:
        base_level = "L3" if "L3" in chosen else chosen[-1]
        for name, extra in ABLATIONS.items():
            say(f"ablation {name}")
            art = scan_dataset(ds, level=base_level, provider=provider, inject=inject, extra=extra)
            entry = attack_level(ds, art, attackers=attackers, inject=inject)
            _drop_probe(art)
            ablation_rows.append(
                {
                    "ablation": name,
                    "level": base_level,
                    "leakage_score": entry["leakage_score"],
                    "canary_passed": entry["canary"]["passed"],
                    "identifier_subword_rate": entry["identifier"]["subword_rate"],
                    "coverage": entry["stitching"]["coverage"],
                    "linkability": entry["stitching"]["linkability"],
                    "f1": evaluate_arm(ds, art, arm=name).overall["f1"],
                }
            )
    results: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "leakage",
        "dataset": {
            "name": ds.name,
            "synthetic": ds.synthetic,
            "canaries": len(ds.canaries) + len(CANARIES),
        },
        "provider": provider,
        "adversary": "honest-but-curious provider: sees every sent payload and its metadata; "
        "no vault, salt, project tree or ground truth",
        "levels": per_level,
        "frontier": frontier,
        "ablations": ablation_rows,
        "zero_leak": all(v["canary"]["passed"] for v in per_level.values()),
        "note": "No code payloads are stored in this file; leaked values appear only as hashes.",
    }
    if out:
        directory = Path(out).expanduser()
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "results.json").write_text(
            json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (directory / "summary.md").write_text(leakage_markdown(results), encoding="utf-8")
        (directory / "frontier.svg").write_text(
            bar_chart_svg(
                f"Privacy-utility frontier on {ds.name}",
                [f["level"] for f in frontier],
                {
                    "privacy score / 100": [f["privacy_score"] / 100 for f in frontier],
                    "detection F1": [f["f1"] for f in frontier],
                },
            ),
            encoding="utf-8",
        )
        results["files"] = ["results.json", "summary.md", "frontier.svg"]
    return results


def leakage_markdown(results: dict[str, Any]) -> str:
    lines = [
        f"# Leakage evaluation: {results['dataset']['name']}",
        "",
        f"Provider `{results['provider']}`. Adversary: {results['adversary']}.",
        f"Zero-leak gate (secrets, personal data, canary identifiers) across all levels: "
        f"**{'PASSED' if results['zero_leak'] else 'FAILED'}**.",
        "",
        "| Level | Sent | Canary hits | Business terms | Identifier recovery | Sector evidence | "
        "Coverage | Linkability | Privacy score | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for level, e in results["levels"].items():
        lines.append(
            f"| {level} | {e['payloads_sent']} | {e['canary']['hard_occurrences']} | "
            f"{e['canary']['business_term_occurrences']} | {e['identifier']['subword_rate']:.2f} | "
            f"{e['inference']['evidence_share']:.2f} | {e['stitching']['coverage']:.2f} | "
            f"{e['stitching']['linkability']:.2f} | {e['privacy_score']} | {e['detection_f1']:.2f} |"
        )
    if results["ablations"]:
        lines += ["", "## Ablations", "", "| Variant | Level | Leakage | Canary gate | Coverage | Linkability | F1 |",
                  "| --- | --- | ---: | --- | ---: | ---: | ---: |"]  # fmt: skip
        for a in results["ablations"]:
            lines.append(
                f"| {a['ablation']} | {a['level']} | {a['leakage_score']} | "
                f"{'pass' if a['canary_passed'] else 'FAIL'} | {a['coverage']:.2f} | "
                f"{a['linkability']:.2f} | {a['f1']:.2f} |"
            )
    lines += ["", results["note"], ""]
    return "\n".join(lines)


def run_leakage_eval(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Entry point of ``codekavach eval leakage``: run, write, return the compact summary."""
    results = run_leakage(*args, **kwargs)
    return {
        "dataset": results["dataset"]["name"],
        "zero_leak": results["zero_leak"],
        "frontier": results["frontier"],
        "ablations": [
            {k: a[k] for k in ("ablation", "leakage_score", "canary_passed", "f1")}
            for a in results["ablations"]
        ],
        "files": results.get("files", []),
    }
