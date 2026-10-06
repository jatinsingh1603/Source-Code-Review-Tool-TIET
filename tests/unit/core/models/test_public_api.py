"""The public API of ``codekavach.core.models`` and its reference page (E02-30)."""

import ast
import importlib
import inspect
import pkgutil
import re
from pathlib import Path

from codekavach.core import models
from codekavach.core.models.base import KavachModel, VersionedModel
from codekavach.core.models.export import EXPORTED_MODELS

PACKAGE = Path(models.__file__).parent
ARCHITECTURE_MODELS = (
    "Finding", "Location", "CodeRegion", "TaintPath", "Evidence", "Candidate", "Scan", "Project",
    "CodeSlice", "SanitisedPayload", "LLMVerdict", "EgressRecord",
)  # fmt: skip
REFERENCE = Path(__file__).resolve().parents[4] / "docs" / "reference" / "domain-model.md"
# KavachModel subclasses defined in the package that are deliberately not re-exported.
PRIVATE: frozenset[str] = frozenset()
BASES = frozenset({KavachModel, VersionedModel})
NETWORK_AND_PROCESS = ("socket", "ssl", "http", "urllib", "requests", "httpx", "aiohttp")
SUBPROCESS_ALLOWED = frozenset({"export.py", "compat.py"})
# String parsing only (scan.py validates repository URLs with urlsplit); no connection.
PURE_PARSING = frozenset({"urllib.parse"})


def defined_models() -> dict[str, type[KavachModel]]:
    found: dict[str, type[KavachModel]] = {}
    for info in pkgutil.iter_modules(models.__path__, f"{models.__name__}."):
        module = importlib.import_module(info.name)
        found.update(
            {
                name: value
                for name, value in vars(module).items()
                if inspect.isclass(value)
                and issubclass(value, KavachModel)
                and value.__module__ == info.name
            }
        )
    return found


def imports_of(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def test_all_is_sorted_unique_and_resolves() -> None:
    assert models.__all__ == sorted(models.__all__)
    assert len(models.__all__) == len(set(models.__all__))
    for name in models.__all__:
        assert getattr(models, name) is not None, name


def test_star_import_exposes_the_architecture_models() -> None:
    namespace: dict[str, object] = {}
    exec("from codekavach.core.models import *", namespace)  # noqa: S102 - the star import itself
    required = set(ARCHITECTURE_MODELS)
    assert required <= set(namespace)


def test_every_model_is_public_or_private() -> None:
    for name, model in defined_models().items():
        assert name in models.__all__ or name in PRIVATE, name
        assert getattr(models, name, model) is model


def test_every_model_declares_its_classification() -> None:
    for name, model in defined_models().items():
        if model in BASES:
            continue
        assert "DATA_CLASSIFICATION" in model.__dict__, f"{name} relies on the raw default"


def test_no_upward_imports() -> None:
    for path in sorted(PACKAGE.glob("*.py")):
        for name in imports_of(path):
            if name.startswith("codekavach"):
                assert name.startswith("codekavach.core.models"), f"{path.name} imports {name}"


def test_no_network_or_process_modules() -> None:
    for path in sorted(PACKAGE.glob("*.py")):
        for name in imports_of(path):
            top = name.split(".")[0]
            if name in PURE_PARSING:
                continue
            assert top not in NETWORK_AND_PROCESS, f"{path.name} imports {name}"
            if top == "subprocess":
                assert path.name in SUBPROCESS_ALLOWED, f"{path.name} imports subprocess"


def section(title_prefix: str) -> str:
    text = REFERENCE.read_text(encoding="utf-8")
    start = text.index(f"## {title_prefix}")
    end = text.find("\n## ", start + 3)
    return text[start : end if end != -1 else len(text)]


def test_reference_has_the_eight_sections() -> None:
    headings = re.findall(r"^## (\d)\. ", REFERENCE.read_text(encoding="utf-8"), re.MULTILINE)
    assert headings == [str(number) for number in range(1, 9)]


def test_mermaid_classes_are_public() -> None:
    block = re.search(r"```mermaid\n(.*?)```", section("1. "), re.DOTALL)
    assert block is not None
    body = block.group(1)
    assert body.startswith("classDiagram")
    names = set(re.findall(r"\b([A-Z][A-Za-z]+)\b", body.split("note", 1)[0]))
    names.discard("Trust")
    assert names, "no class in the diagram"
    assert names <= set(models.__all__), sorted(names - set(models.__all__))


def test_classification_table_matches_the_models() -> None:
    rows = re.findall(r"^\| `(\w+)` \| (\w+) \|$", section("4. "), re.MULTILINE)
    table = dict(rows)
    assert set(table) == {model.__name__ for model in EXPORTED_MODELS}
    for model in EXPORTED_MODELS:
        assert table[model.__name__] == model.DATA_CLASSIFICATION.value, model.__name__
