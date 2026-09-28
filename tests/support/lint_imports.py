"""Run import-linter against a fake tree, and prove which ``codekavach`` it analyses."""

import os
import subprocess
import sys
from pathlib import Path


def lint_imports_executable() -> Path:
    """The ``lint-imports`` script of the running environment; missing tooling is an error."""
    scripts = Path(sys.executable).parent
    for name in ("lint-imports", "lint-imports.exe"):
        candidate = scripts / name
        if candidate.is_file():
            return candidate
    raise AssertionError("lint-imports is not installed; sync the dev dependency group")


def tree_environment(tree: Path | None) -> dict[str, str]:
    """A copy of the environment whose ``PYTHONPATH`` puts ``tree`` first."""
    environment = dict(os.environ)
    environment["PYTHONIOENCODING"] = "utf-8"
    environment.pop("PYTHONPATH", None)
    if tree is not None:
        environment["PYTHONPATH"] = str(tree)
    return environment


def analysed_package(tree: Path | None, cwd: Path) -> Path:
    """The ``codekavach`` package that an interpreter started like import-linter would import."""
    completed = subprocess.run(
        [sys.executable, "-c", "import codekavach; print(codekavach.__file__)"],
        cwd=cwd,
        env=tree_environment(tree),
        capture_output=True,
        text=True,
        check=True,
    )
    return Path(completed.stdout.strip()).resolve()


def run_lint_imports(tree: Path, config: Path) -> subprocess.CompletedProcess[str]:
    """Run ``lint-imports`` on ``tree`` after checking that ``tree`` is what gets analysed."""
    package = analysed_package(tree, tree)
    if not package.is_relative_to(tree.resolve()):
        raise AssertionError(f"import-linter would analyse {package}, not the fake tree")
    return subprocess.run(
        [str(lint_imports_executable()), "--config", str(config), "--no-cache"],
        cwd=tree,
        env=tree_environment(tree),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
