"""A miniature ``codekavach`` package for self-testing the import contracts.

Every internal module named in ``.importlinter`` is created (as a package, or as a plain module
where the real tree has a file of that name), plus the given extra files. Deriving the list from
the configuration means new contracts are covered without editing this helper.
"""

import configparser
import re
from collections.abc import Mapping
from pathlib import Path

REAL_SOURCE = Path(__file__).resolve().parents[2] / "src"
_MODULE = re.compile(r"codekavach(?:\.[A-Za-z_][A-Za-z0-9_]*)*")


def contract_modules(config: Path) -> list[str]:
    """Every ``codekavach...`` name mentioned by the contracts."""
    parser = configparser.ConfigParser()
    parser.read(config, encoding="utf-8")
    names: set[str] = set()
    for section in parser.sections():
        for key in ("source_modules", "forbidden_modules", "ignore_imports"):
            names.update(_MODULE.findall(parser.get(section, key, fallback="")))
    return sorted(names)


def contract_names(config: Path) -> dict[str, str]:
    """Contract id (the part after ``importlinter:contract:``) to its ``name``."""
    parser = configparser.ConfigParser()
    parser.read(config, encoding="utf-8")
    prefix = "importlinter:contract:"
    return {
        section.removeprefix(prefix): parser.get(section, "name")
        for section in parser.sections()
        if section.startswith(prefix)
    }


def _is_plain_module(name: str) -> bool:
    return (REAL_SOURCE / (name.replace(".", "/") + ".py")).is_file()


def _ensure(root: Path, name: str) -> None:
    parts = name.split(".")
    for depth in range(1, len(parts) + 1):
        dotted = ".".join(parts[:depth])
        path = root.joinpath(*parts[:depth])
        if depth == len(parts) and _is_plain_module(dotted):
            path.with_suffix(".py").touch()
            return
        path.mkdir(exist_ok=True)
        (path / "__init__.py").touch()


def build_fake_tree(root: Path, config: Path, extra_files: Mapping[str, str]) -> Path:
    """Create the fake tree under ``root`` and return ``root``."""
    root.mkdir(parents=True, exist_ok=True)
    modules = contract_modules(config)
    if not modules:
        raise AssertionError("no codekavach modules derived from the import contracts")
    for name in ["codekavach", *modules]:
        _ensure(root, name)
    for relative, content in extra_files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in path.relative_to(root).parents:
            if str(parent) not in {".", ""}:
                init = root / parent / "__init__.py"
                if not init.exists():
                    init.touch()
        path.write_text(content, encoding="utf-8")
    return root
