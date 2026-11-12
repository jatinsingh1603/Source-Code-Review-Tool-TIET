"""Reachability hint: is the vulnerable package imported by the code? (E19-02)

A hint, never a filter: it informs confidence and the report text, and no finding is dropped
because a package is not imported. Python imports map the distribution name to its import name
(``PyYAML`` to ``yaml``); JavaScript ``require`` and ``import`` specifiers map to the package
root.
"""

import re
from dataclasses import dataclass

from codekavach.analysis.sca.model import Dependency

_PY_ALIASES = {
    "pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4", "scikit-learn": "sklearn",
    "python-dateutil": "dateutil", "pyjwt": "jwt", "opencv-python": "cv2", "attrs": "attr",
    "protobuf": "google.protobuf", "msgpack-python": "msgpack", "psycopg2-binary": "psycopg2",
}  # fmt: skip
_PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w., ]+))", re.MULTILINE)
_JS_IMPORT = re.compile(
    r"""(?:require\(\s*|from\s+|import\s+|import\(\s*)['"]((?:@[\w.-]+/)?[\w.-]+)""", re.MULTILINE
)


@dataclass(frozen=True)
class Reach:
    """``imported`` with the first import site, ``not_imported``, or ``unknown``."""

    status: str
    path: str | None = None
    line: int | None = None


def import_names(dep: Dependency) -> set[str]:
    """The module names ``dep`` is imported under (distribution name mapped to import name)."""
    if dep.ecosystem == "PyPI":
        wanted = _PY_ALIASES.get(dep.name.lower(), dep.name.replace("-", "_"))
        return {wanted, wanted.lower(), dep.name.lower().replace("-", "_")}
    return {dep.name}


def python_modules(text: str) -> set[str]:
    """Top-level module names imported by Python source."""
    found: set[str] = set()
    for m in _PY_IMPORT.finditer(text):
        if m[1]:
            found.add(m[1].split(".")[0])
            found.add(m[1])
        else:
            for part in m[2].split(","):
                token = part.strip().split(" ")[0]
                if token:
                    found.add(token.split(".")[0])
    return found


def js_modules(text: str) -> set[str]:
    """Package names imported or required by JavaScript or TypeScript source."""
    return {m[1] for m in _JS_IMPORT.finditer(text)}


class ReachIndex:
    """Imports of the whole project, queried per dependency."""

    def __init__(self) -> None:
        self._py: dict[str, tuple[str, int]] = {}
        self._js: dict[str, tuple[str, int]] = {}
        self._any = False

    def add_file(self, path: str, language: str, text: str) -> None:
        """Record the imports of one source file."""
        if language == "python":
            self._any = True
            for mod in python_modules(text):
                self._py.setdefault(mod, (path, _line(text, mod.split(".")[-1])))
        elif language in {"javascript", "typescript"}:
            self._any = True
            for mod in js_modules(text):
                self._js.setdefault(mod, (path, _line(text, mod)))

    def reach(self, dep: Dependency) -> Reach:
        """The hint for ``dep``."""
        if dep.ecosystem == "PyPI":
            for name in import_names(dep):
                if name in self._py:
                    return Reach("imported", *self._py[name])
            return Reach("not_imported") if self._py else Reach("unknown")
        if dep.ecosystem == "npm":
            if dep.name in self._js:
                return Reach("imported", *self._js[dep.name])
            return Reach("not_imported") if self._js else Reach("unknown")
        return Reach("unknown")


def _line(text: str, needle: str) -> int:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else 1
