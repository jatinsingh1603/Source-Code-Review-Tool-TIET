"""Static guard: the core packages spawn no process and deserialise nothing executable (E04-30).

``core.pipeline``, ``core.plugins`` and ``core.store`` handle every artefact of a scan. They must
not import process-spawning or executable-deserialisation modules, nor call ``eval``, ``exec``,
``compile``, ``os.system``, ``os.popen`` or ``os.fork``. Network modules are banned for the whole
package elsewhere (ruff TID251 and the ``i1-single-egress`` contract). Third-party stages loaded
at run time are outside this guard by nature.
"""

import ast
from pathlib import Path

import pytest

import codekavach.core

CORE = Path(codekavach.core.__file__).parent
GUARDED = ("pipeline", "plugins", "store")
FORBIDDEN_MODULES = frozenset(
    {"subprocess", "multiprocessing", "pickle", "cPickle", "marshal", "shelve", "dill", "yaml"}
)
FORBIDDEN_NAMES = frozenset({"eval", "exec", "compile"})
FORBIDDEN_ATTRIBUTES = frozenset({"os.system", "os.popen", "os.fork"})
DYNAMIC_IMPORTS = frozenset({"importlib.import_module", "import_module", "__import__"})


def dotted(node: ast.expr) -> str | None:
    """``a.b.c`` for a name or an attribute chain, else ``None``."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([node.id, *reversed(parts)])


def resolve(node: ast.ImportFrom, package: str) -> str:
    """The absolute module of a from-import; relative ones are resolved against ``package``."""
    if node.level == 0:
        return node.module or ""
    base = package.split(".")
    base = base[: len(base) - (node.level - 1)]
    return ".".join([*base, node.module] if node.module else base)


def is_forbidden(module: str) -> bool:
    return module.split(".", maxsplit=1)[0] in FORBIDDEN_MODULES


def imported_modules(node: ast.AST, package: str) -> list[str]:
    """Every module a node imports, statically or through a constant dynamic import."""
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        module = resolve(node, package)
        return [module, *(f"{module}.{alias.name}" for alias in node.names)]
    if isinstance(node, ast.Call) and dotted(node.func) in DYNAMIC_IMPORTS and node.args:
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return [first.value]
    return []


def problems(source: str, filename: str, package: str) -> list[str]:
    """``file:line: forbidden ...`` for every violation in ``source``."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source, filename=filename)):
        line = getattr(node, "lineno", 0)
        found.extend(
            f"{filename}:{line}: forbidden import {module!r}"
            for module in imported_modules(node, package)
            if is_forbidden(module) or module in FORBIDDEN_ATTRIBUTES
        )
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            bare = isinstance(node.func, ast.Name) and name in FORBIDDEN_NAMES
            if bare or name in FORBIDDEN_ATTRIBUTES:
                found.append(f"{filename}:{line}: forbidden call {name!r}")
    return sorted(set(found))


def package_of(path: Path) -> str:
    relative = path.relative_to(CORE.parent.parent).with_suffix("")
    parts = relative.parts if path.name == "__init__.py" else relative.parts[:-1]
    return ".".join(part for part in parts if part != "__init__")


def guarded_files() -> list[Path]:
    return sorted(path for name in GUARDED for path in (CORE / name).rglob("*.py"))


def test_core_packages_are_clean() -> None:
    files = guarded_files()
    assert len(files) > 20
    assert any("migrations" in path.parts for path in files)
    found = [
        problem
        for path in files
        for problem in problems(
            path.read_text(encoding="utf-8"), path.relative_to(CORE).as_posix(), package_of(path)
        )
    ]
    assert found == []


VIOLATIONS = {
    "import pickle\n": "1: forbidden import 'pickle'",
    "import os\nimport yaml.loader\n": "2: forbidden import 'yaml.loader'",
    "from subprocess import run\n": "1: forbidden import 'subprocess'",
    "from multiprocessing.pool import Pool\n": "1: forbidden import 'multiprocessing.pool'",
    'import importlib\nimportlib.import_module("marshal")\n': "2: forbidden import 'marshal'",
    'from importlib import import_module\nimport_module("shelve")\n': (
        "2: forbidden import 'shelve'"
    ),
    '__import__("dill")\n': "1: forbidden import 'dill'",
    'import os\nos.system("x")\n': "2: forbidden call 'os.system'",
    'import os\n\ndef f() -> None:\n    os.popen("x")\n': "4: forbidden call 'os.popen'",
    "import os\nos.fork()\n": "2: forbidden call 'os.fork'",
    "from os import system\n": "1: forbidden import 'os.system'",
    'eval("1")\n': "1: forbidden call 'eval'",
    'exec("x = 1")\n': "1: forbidden call 'exec'",
    'compile("1", "f", "eval")\n': "1: forbidden call 'compile'",
}


@pytest.mark.parametrize("source", sorted(VIOLATIONS))
def test_synthetic_violations_are_reported(source: str) -> None:
    found = problems(source, "bad.py", "codekavach.core.pipeline")
    assert f"bad.py:{VIOLATIONS[source]}" in found


def test_relative_imports_are_resolved_against_the_package() -> None:
    sibling = "from . import marshal\nfrom .pickle import load\nfrom .. import yaml\n"
    assert problems(sibling, "ok.py", "codekavach.core.store") == []
    assert problems("from . import loader\n", "bad.py", "yaml.constructors") == [
        "bad.py:1: forbidden import 'yaml.constructors'",
        "bad.py:1: forbidden import 'yaml.constructors.loader'",
    ]
    assert problems("from ..pool import Pool\n", "bad.py", "multiprocessing.dummy.x") == [
        "bad.py:1: forbidden import 'multiprocessing.dummy.pool'",
        "bad.py:1: forbidden import 'multiprocessing.dummy.pool.Pool'",
    ]


def test_allowed_constructs_pass() -> None:
    source = (
        "import importlib.metadata\n"
        "import re\n"
        "from importlib.resources import files\n"
        "import importlib\n"
        "PATTERN = re.compile('x')\n"
        "def load(name: str) -> object:\n"
        "    return importlib.import_module(name)\n"
        "class Model:\n"
        "    def compile(self) -> None: ...\n"
        "Model().compile()\n"
    )
    assert problems(source, "ok.py", "codekavach.core.plugins") == []
