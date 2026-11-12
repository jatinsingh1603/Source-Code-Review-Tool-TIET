# ruff: noqa: PLW2901, PERF401, D102, E501
"""Dataset manager for the evaluation harnesses (#278).

A dataset is a directory of source code plus a ground truth: the vulnerabilities that are really
there, the safe controls next to them, and (for the leakage arm) the secrets, personal data and
business terms that must never reach a model.

Supported layouts, detected from the directory:

* ``kavachbank`` - ``ground-truth/manifest.yaml`` of ``fixtures/kavachbank`` (and the two demo
  projects, which use the same manifest shape);
* ``codekavach-json`` - ``ground-truth.json`` at the dataset root (the generic, documented format);
* ``owasp-benchmark`` - ``expectedresults-*.csv`` next to ``src/main/java/.../BenchmarkTestNNNNN.java``;
* ``juliet`` - files named ``CWE<number>_<name>__<variant>.<ext>`` (every such file is a labelled
  "bad" case at file level; ``*_good*`` names are safe controls).

Datasets are only ever read from local directories; nothing is downloaded here.
"""

import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

import yaml

Kind = Literal["vulnerability", "safe"]
TRUTH_FILE: Final = "ground-truth.json"
MANIFEST: Final = Path("ground-truth") / "manifest.yaml"
NEGATIVES: Final = Path("ground-truth") / "negative_controls.yaml"
TERMS: Final = Path("ground-truth") / "terms.txt"
SOURCE_SUFFIXES: Final = frozenset(
    {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs", ".c", ".cpp", ".kt"}
)
LANGUAGE_BY_SUFFIX: Final = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
    ".kt": "kotlin",
}
_JULIET: Final = re.compile(r"^CWE(\d+)_.*?(?:__)?(.*)\.[A-Za-z]+$")


class DatasetError(ValueError):
    """A dataset could not be found or its ground truth is malformed."""


@dataclass(frozen=True)
class TruthItem:
    """One labelled location. ``line`` 0 means the label holds for the whole file."""

    id: str
    cwe: int
    file: str
    line: int
    kind: Kind = "vulnerability"
    cls: str = ""

    @property
    def language(self) -> str:
        return LANGUAGE_BY_SUFFIX.get(Path(self.file).suffix.lower(), "other")


@dataclass(frozen=True)
class Canary:
    """A value that must never appear in a payload, with the class of data it stands for."""

    value: str
    category: Literal["secret", "pii", "term", "identifier"]
    label: str = ""


@dataclass
class Dataset:
    """A local dataset: its root, labels and canaries."""

    name: str
    root: Path
    layout: str
    truth: list[TruthItem] = field(default_factory=list)
    canaries: list[Canary] = field(default_factory=list)
    synthetic: bool = False
    description: str = ""

    @property
    def vulnerabilities(self) -> list[TruthItem]:
        return [t for t in self.truth if t.kind == "vulnerability"]

    @property
    def controls(self) -> list[TruthItem]:
        return [t for t in self.truth if t.kind == "safe"]

    def source_files(self) -> list[Path]:
        return sorted(
            p
            for p in self.root.rglob("*")
            if p.is_file()
            and p.suffix.lower() in SOURCE_SUFFIXES
            and "ground-truth" not in p.parts
            and "node_modules" not in p.parts
        )

    def limited(self, limit: int | None) -> "Dataset":
        """A view with at most ``limit`` labelled vulnerabilities (and their controls)."""
        if limit is None or limit >= len(self.vulnerabilities):
            return self
        keep = self.vulnerabilities[:limit]
        files = {t.file for t in keep}
        controls = [t for t in self.controls if t.file in files]
        return Dataset(
            self.name,
            self.root,
            self.layout,
            [*keep, *controls],
            self.canaries,
            self.synthetic,
            self.description,
        )


def resolve_dataset(name_or_path: str, *, repo_root: Path | None = None) -> Dataset:
    """Load a dataset by name (a fixture of the checkout) or by directory.

    Raises:
        DatasetError: nothing matches, or the ground truth cannot be read.
    """
    candidate = Path(name_or_path).expanduser()
    if candidate.is_dir():
        return load_dataset(candidate)
    roots = [repo_root] if repo_root else []
    roots += [Path.cwd(), *Path.cwd().parents, Path(__file__).resolve().parents[3]]
    for root in roots:
        for sub in ("fixtures", "datasets", "data/datasets"):
            found = root / sub / name_or_path
            if found.is_dir():
                return load_dataset(found)
    raise DatasetError(f"dataset {name_or_path!r} not found (give a directory or a fixture name)")


def load_dataset(root: Path) -> Dataset:
    """Detect the layout of ``root`` and read its ground truth."""
    root = root.resolve()
    if (root / TRUTH_FILE).is_file():
        return _load_json(root)
    if (root / MANIFEST).is_file():
        return _load_manifest(root)
    if any(root.glob("expectedresults-*.csv")):
        return _load_owasp_benchmark(root)
    if any(_JULIET.match(p.name) for p in root.rglob("CWE*")):
        return _load_juliet(root)
    raise DatasetError(f"no ground truth found in {root} (expected {TRUTH_FILE} or a known layout)")


def _load_json(root: Path) -> Dataset:
    try:
        data = json.loads((root / TRUTH_FILE).read_text(encoding="utf-8"))
        truth = [
            TruthItem(
                id=str(v.get("id", f"V{i}")),
                cwe=int(v["cwe"]),
                file=str(v["file"]),
                line=int(v.get("line", 0)),
                kind="vulnerability",
                cls=str(v.get("class", "")),
            )
            for i, v in enumerate(data.get("vulnerabilities", []), 1)
        ] + [
            TruthItem(
                id=str(v.get("id", f"S{i}")),
                cwe=int(v.get("cwe", 0)),
                file=str(v["file"]),
                line=int(v.get("line", 0)),
                kind="safe",
                cls=str(v.get("class", "")),
            )
            for i, v in enumerate(data.get("negatives", []), 1)
        ]
    except (KeyError, ValueError, TypeError) as error:
        raise DatasetError(f"malformed {TRUTH_FILE}: {error}") from error
    canaries = [Canary(str(t), "term") for t in data.get("terms", [])]
    canaries += [Canary(str(t), "secret") for t in data.get("secrets", [])]
    return Dataset(
        data.get("name", root.name),
        root,
        "codekavach-json",
        truth,
        canaries,
        bool(data.get("synthetic", False)),
        str(data.get("description", "")),
    )


def _load_manifest(root: Path) -> Dataset:
    manifest: dict[str, Any] = yaml.safe_load((root / MANIFEST).read_text(encoding="utf-8")) or {}
    truth = [
        TruthItem(v["id"], int(v["cwe"]), v["file"], int(v["line"]), "vulnerability", v["class"])
        for v in manifest.get("planted_vulnerabilities", [])
    ]
    negatives = root / NEGATIVES
    if negatives.is_file():
        data = yaml.safe_load(negatives.read_text(encoding="utf-8")) or {}
        truth += [
            TruthItem(n["id"], 0, n["file"], int(n["line"]), "safe", n.get("class", ""))
            for n in data.get("negative_controls", [])
        ]
    canaries: list[Canary] = []
    terms = root / TERMS
    if terms.is_file():
        secret_like = re.compile(r"[A-Z0-9/+=_-]{12,}|://|BEGIN |@")
        for line in terms.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                kind: Literal["secret", "term"] = "secret" if secret_like.search(line) else "term"
                canaries.append(Canary(line, kind))
    seed = root / "fixtures" / "seed" / "customers.json"
    if seed.is_file():
        for value in _string_leaves(json.loads(seed.read_text(encoding="utf-8"))):
            if len(value) >= 6:
                canaries.append(Canary(value, "pii"))
    app = manifest.get("application", {})
    return Dataset(
        app.get("name", root.name),
        root,
        "kavachbank",
        truth,
        _dedupe(canaries),
        True,
        str(app.get("description", "")).strip(),
    )


def _string_leaves(node: object) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for v in node.values() for s in _string_leaves(v)]
    if isinstance(node, list):
        return [s for v in node for s in _string_leaves(v)]
    return []


def _dedupe(items: list[Canary]) -> list[Canary]:
    seen: set[str] = set()
    out: list[Canary] = []
    for item in items:
        if item.value not in seen:
            seen.add(item.value)
            out.append(item)
    return out


def _load_owasp_benchmark(root: Path) -> Dataset:
    truth: list[TruthItem] = []
    csv_file = sorted(root.glob("expectedresults-*.csv"))[0]
    sources = {p.stem: p for p in root.rglob("BenchmarkTest*.java")}
    with csv_file.open(encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if not row or row[0].startswith("#") or len(row) < 4:
                continue
            name, category, real, cwe = (c.strip() for c in row[:4])
            source = sources.get(name)
            if source is None or not cwe.isdigit():
                continue
            kind: Kind = "vulnerability" if real.lower() == "true" else "safe"
            truth.append(
                TruthItem(name, int(cwe), str(source.relative_to(root)), 0, kind, category)
            )
    if not truth:
        raise DatasetError(f"{csv_file.name} lists no test case present under {root}")
    return Dataset(root.name, root, "owasp-benchmark", truth, [], False, "OWASP Benchmark layout")


def _load_juliet(root: Path) -> Dataset:
    truth: list[TruthItem] = []
    for path in sorted(root.rglob("CWE*")):
        match = _JULIET.match(path.name)
        if not match or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        kind: Kind = (
            "safe"
            if "good" in path.stem.lower() and "bad" not in path.stem.lower()
            else "vulnerability"
        )
        truth.append(
            TruthItem(path.stem, int(match.group(1)), str(path.relative_to(root)), 0, kind, "")
        )
    return Dataset(root.name, root, "juliet", truth, [], False, "Juliet layout")
