"""Static AST guard for invariant I2 (E02-28): ``codekavach.llm`` sees sanitised data only.

Rules, reported as ``path:line: I2 violation: <rule> <detail>``:

- R1  (allow-list) in ``src/codekavach/llm/``, every name imported from ``codekavach.core.models``
  (or a submodule), and every attribute read on a module alias of it, is in
  ``llm_allowed_names()``. Star imports from it are violations in themselves.
- R1b (deny by name) in ``src/codekavach/llm/``, no identifier equals a raw model name, wherever
  it was imported from (this catches a raw model re-exported by another package). Imports under
  ``if TYPE_CHECKING:`` and string annotations count too.
- R2  ``SanitisedText(...)`` is called only under ``src/codekavach/privacy/``, in
  ``src/codekavach/core/models/text.py`` and under ``tests/``.
- R3  no ``.expose()`` call in ``src/codekavach/llm/``.
- R4  no ``open()``, ``.read_text()`` or ``.read_bytes()`` in ``src/codekavach/llm/`` outside
  ``LLM_FILE_IO_ALLOWLIST``.

The allow-list is derived from each model's ``DATA_CLASSIFICATION``: sanitised and untrusted
models and every enum are allowed, plus the explicit neutral names below. A model that nobody
classified defaults to ``raw`` and is therefore forbidden (fail closed). This is a static
check of names and imports; it cannot prove that a string passed around at run time is clean.
"""

import ast
import enum
import importlib
import inspect
import pkgutil
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

from codekavach.core import models
from codekavach.core.models.base import DataClassification, KavachModel

MODELS_PACKAGE = "codekavach.core.models"
POINTER = "see docs/ARCHITECTURE.md section 6.3"

# Names the LLM layer may use although they are not sanitised models; one reason each.
LLM_NEUTRAL_ALLOWLIST: Mapping[str, str] = {
    "KavachModel": "shared base class; the LLM layer defines its own models on it",
    "VersionedModel": "shared base class of persisted documents",
    "DataClassification": "the LLM layer classifies its own models",
    "SanitisedText": "the wrapper of sanitised text (constructing it is restricted by R2)",
    "TokenCounts": "token numbers only",
    "CweId": "taxonomy identifier type",
    "parse_cwe": "taxonomy identifier parser",
    "format_cwe": "taxonomy identifier formatter",
    "UtcDatetime": "timestamp type",
    "utc_now": "clock",
    "canonical_json": "hashing helper for sanitised documents",
    "sha256_hex": "hashing helper",
    "ModelError": "error type; messages never carry field values",
    "InvalidStatusTransition": "error subclass of ModelError",
    "UnsupportedSchemaVersion": "error subclass of ModelError",
    "MigrationError": "error subclass of ModelError",
    "FingerprintInputError": "error subclass of ModelError",
    "PayloadId": "identifier type",
    "PayloadIdField": "identifier field type",
    "CandidateId": "identifier type",
    "CandidateIdField": "identifier field type",
    "ScanId": "identifier type",
    "ScanIdField": "identifier field type",
    "find_placeholders": "reads placeholder tokens in sanitised text",
    "PLACEHOLDER_PATTERN": "placeholder token syntax",
}
# Files under src/codekavach/llm/ allowed to read files (E23 may add its prompt loader, with a
# written justification in its closing comment). Paths are relative to the repository root.
LLM_FILE_IO_ALLOWLIST: frozenset[str] = frozenset()
RAW_EXTRA_NAMES = frozenset({"RawCode"})


class Zone(enum.Enum):
    """Where a file lives, which decides the rules that apply to it."""

    LLM = "llm"
    PRIVACY = "privacy"
    OTHER_SRC = "other_src"
    TESTS = "tests"


@dataclass(frozen=True)
class Violation:
    """One rule violation at a file position."""

    path: str
    line: int
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: I2 violation: {self.rule} {self.detail} ({POINTER})"


def model_namespace() -> dict[str, object]:
    """Public names of ``codekavach.core.models``: its ``__all__`` and every submodule's classes."""
    table: dict[str, object] = {name: getattr(models, name) for name in models.__all__}
    for info in pkgutil.iter_modules(models.__path__, MODELS_PACKAGE + "."):
        module = importlib.import_module(info.name)
        for name, value in vars(module).items():
            if (
                not name.startswith("_")
                and inspect.isclass(value)
                and value.__module__.startswith(MODELS_PACKAGE)
            ):
                table.setdefault(name, value)
    return table


def submodule_names() -> frozenset[str]:
    """Names of the submodules of ``codekavach.core.models``."""
    return frozenset(info.name for info in pkgutil.iter_modules(models.__path__))


def llm_allowed_names(namespace: Mapping[str, object] | None = None) -> frozenset[str]:
    """Neutral names, sanitised and untrusted models, and enums."""
    allowed = set(LLM_NEUTRAL_ALLOWLIST)
    for name, value in (namespace if namespace is not None else model_namespace()).items():
        if not inspect.isclass(value):
            continue
        if issubclass(value, KavachModel):
            if value.DATA_CLASSIFICATION in {
                DataClassification.SANITISED,
                DataClassification.UNTRUSTED,
            }:
                allowed.add(name)
        elif issubclass(value, enum.Enum):
            allowed.add(name)
    return frozenset(allowed)


def raw_names(namespace: Mapping[str, object] | None = None) -> frozenset[str]:
    """Models classified ``raw`` (the default), plus ``RawCode``; base classes excluded."""
    names = set(RAW_EXTRA_NAMES)
    for name, value in (namespace if namespace is not None else model_namespace()).items():
        if (
            inspect.isclass(value)
            and issubclass(value, KavachModel)
            and value.DATA_CLASSIFICATION is DataClassification.RAW
            and name not in LLM_NEUTRAL_ALLOWLIST
        ):
            names.add(name)
    return frozenset(names)


def _dotted(node: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


class _Checker(ast.NodeVisitor):
    def __init__(
        self,
        filename: str,
        zone: Zone,
        allowed: frozenset[str],
        raw: frozenset[str],
        line_offset: int = 0,
    ) -> None:
        self.filename = filename.replace("\\", "/")
        self.zone = zone
        self.allowed = allowed
        self.raw = raw
        self.submodules = submodule_names()
        self.line_offset = line_offset
        self.aliases: dict[str, str] = {}  # local name -> module path
        self.violations: list[Violation] = []

    # helpers

    def _add(self, node: ast.AST, rule: str, detail: str) -> None:
        line = getattr(node, "lineno", 1) + self.line_offset
        self.violations.append(Violation(self.filename, line, rule, detail))

    @property
    def _llm(self) -> bool:
        return self.zone is Zone.LLM

    def _check_raw(self, node: ast.AST, name: str) -> None:
        if self._llm and name in self.raw:
            self._add(node, "R1b", f"raw model name {name!r} used in codekavach.llm")

    def _check_model_name(self, node: ast.AST, name: str, origin: str) -> None:
        if name not in self.allowed:
            self._add(node, "R1", f"{name!r} from {origin} is not on the LLM allow-list")

    def _annotation(self, node: ast.expr | None) -> None:
        if node is None:
            return
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and self._llm:
            try:
                parsed = ast.parse(node.value, mode="eval")
            except SyntaxError:
                return
            inner = _Checker(
                self.filename, self.zone, self.allowed, self.raw, node.lineno - 1 + self.line_offset
            )
            inner.aliases = self.aliases
            inner.visit(parsed)
            self.violations.extend(inner.violations)

    # imports

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._check_raw(node, alias.name.rsplit(".", 1)[-1])
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                head = alias.name.split(".", 1)[0]
                self.aliases[head] = head

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        from_models = node.level == 0 and (
            module == MODELS_PACKAGE or module.startswith(MODELS_PACKAGE + ".")
        )
        for alias in node.names:
            if alias.name == "*":
                if self._llm and from_models:
                    self._add(node, "R1", f"star import from {module}")
                continue
            self._check_raw(node, alias.name)
            local = alias.asname or alias.name
            if from_models and module == MODELS_PACKAGE and alias.name in self.submodules:
                self.aliases[local] = f"{MODELS_PACKAGE}.{alias.name}"
            elif self._llm and from_models:
                self._check_model_name(node, alias.name, module)
            elif node.level == 0:
                self.aliases[local] = f"{module}.{alias.name}"

    # names and attributes

    def visit_Name(self, node: ast.Name) -> None:
        self._check_raw(node, node.id)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._check_raw(node, node.attr)
        dotted = _dotted(node.value)
        if self._llm and dotted is not None:
            head, _, rest = dotted.partition(".")
            base = self.aliases.get(head)
            if base is not None:
                path = f"{base}.{rest}" if rest else base
                in_models = path == MODELS_PACKAGE or path.startswith(MODELS_PACKAGE + ".")
                if in_models and node.attr not in self.submodules:
                    self._check_model_name(node, node.attr, path)
        self.generic_visit(node)

    # calls

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name == "SanitisedText" and not self._may_construct_sanitised():
            self._add(node, "R2", "SanitisedText constructed outside codekavach.privacy")
        if self._llm:
            if isinstance(func, ast.Attribute) and func.attr == "expose":
                self._add(node, "R3", ".expose() called in codekavach.llm")
            file_io = (isinstance(func, ast.Name) and func.id == "open") or (
                isinstance(func, ast.Attribute) and func.attr in {"read_text", "read_bytes"}
            )
            if file_io and not self._file_io_allowed():
                self._add(node, "R4", f"file read ({name}) in codekavach.llm")
        self.generic_visit(node)

    def _may_construct_sanitised(self) -> bool:
        return self.zone in {Zone.PRIVACY, Zone.TESTS} or self.filename.endswith(
            "src/codekavach/core/models/text.py"
        )

    def _file_io_allowed(self) -> bool:
        return any(self.filename.endswith(path) for path in LLM_FILE_IO_ALLOWLIST)

    # annotations (string annotations are parsed; real ones are visited normally)

    def visit_arg(self, node: ast.arg) -> None:
        self._annotation(node.annotation)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._annotation(node.returns)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._annotation(node.returns)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._annotation(node.annotation)
        self.generic_visit(node)


def find_i2_violations(
    source: str,
    filename: str,
    *,
    zone: Zone,
    namespace: Mapping[str, object] | None = None,
) -> list[Violation]:
    """Check one file's source; a file that does not parse is itself a violation."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as error:
        path = filename.replace("\\", "/")
        return [Violation(path, error.lineno or 1, "parse", "unparseable file")]
    checker = _Checker(filename, zone, llm_allowed_names(namespace), raw_names(namespace))
    checker.visit(tree)
    return sorted(set(checker.violations), key=lambda item: (item.line, item.rule, item.detail))


def zone_of(relative: str) -> Zone:
    """The zone of a repository-relative POSIX path."""
    if relative.startswith("src/codekavach/llm/"):
        return Zone.LLM
    if relative.startswith("src/codekavach/privacy/"):
        return Zone.PRIVACY
    if relative.startswith("tests/"):
        return Zone.TESTS
    return Zone.OTHER_SRC


def iter_checked_files(root: Path) -> Iterator[tuple[Path, str, Zone]]:
    """Python files under ``root/src`` with their relative path and zone."""
    source_root = root / "src"
    for path in sorted(source_root.rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        yield path, relative, zone_of(relative)


def walk_tree(root: Path) -> list[Violation]:
    """Check every Python file under ``root/src`` (tests are exempt from every rule)."""
    violations: list[Violation] = []
    for path, relative, zone in iter_checked_files(root):
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            violations.append(Violation(relative, 1, "parse", "unparseable file"))
            continue
        violations.extend(find_i2_violations(source, relative, zone=zone))
    return violations
